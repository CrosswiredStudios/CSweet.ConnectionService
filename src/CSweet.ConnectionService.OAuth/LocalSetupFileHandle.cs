using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace CSweet.ConnectionService;

internal static class LocalSetupFileHandle
{
    public static FileStream Open(string path)
    {
        if (OperatingSystem.IsWindows())
            return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
            throw new PlatformNotSupportedException("Local setup requires supported regular-file validation.");
        // O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC. Nonblocking open prevents
        // a FIFO without a writer from hanging before the descriptor's type is checked.
        var flags = OperatingSystem.IsMacOS() ? 0x4 | 0x100 | 0x1000000 : 0x800 | 0x20000 | 0x80000;
        var descriptor = OpenNative(path, flags);
        if (descriptor < 0) throw new IOException("Cannot open local input file.");
        var handle = new SafeFileHandle((IntPtr)descriptor, ownsHandle: true);
        try
        {
            ushort mode;
            if (OperatingSystem.IsLinux())
            {
                // Linux statx has a fixed UAPI layout across architectures. AT_EMPTY_PATH
                // inspects this descriptor, not a path that could be swapped after open.
                // https://man7.org/linux/man-pages/man2/statx.2.html
                if (Statx(handle, "", 0x1000, 1, out var status) != 0 || (status.Mask & 1) == 0)
                    throw new IOException("Cannot establish local input file type.");
                mode = status.Mode;
            }
            else
            {
                // Darwin's inode64 stat layout: dev_t then mode_t. x64 exposes the
                // explicit inode64 symbol; arm64 uses it as the default fstat ABI.
                // https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h
                DarwinStat status;
                var result = RuntimeInformation.ProcessArchitecture switch
                {
                    Architecture.Arm64 => DarwinFstat(handle, out status),
                    Architecture.X64 => DarwinFstat64(handle, out status),
                    _ => throw new PlatformNotSupportedException("Unsupported Darwin stat ABI.")
                };
                if (result != 0) throw new IOException("Cannot establish local input file type.");
                mode = status.Mode;
            }
            if ((mode & 0xf000) != 0x8000) throw new ArgumentException("Use a regular local file.");
            return new FileStream(handle, FileAccess.Read, 4096, isAsync: false);
        }
        catch { handle.Dispose(); throw; }
    }

    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct LinuxStatx
    {
        [FieldOffset(0)] public uint Mask;
        [FieldOffset(28)] public ushort Mode;
    }
    // Reserve more than the Darwin inode64 structure (144 bytes); only mode is read.
    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct DarwinStat { [FieldOffset(4)] public ushort Mode; }
    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int OpenNative([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags);
    [DllImport("libc", EntryPoint = "statx", SetLastError = true)]
    private static extern int Statx(SafeFileHandle descriptor, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags, uint mask, out LinuxStatx status);
    [DllImport("libc", EntryPoint = "fstat", SetLastError = true)]
    private static extern int DarwinFstat(SafeFileHandle descriptor, out DarwinStat status);
    [DllImport("libc", EntryPoint = "fstat$INODE64", SetLastError = true)]
    private static extern int DarwinFstat64(SafeFileHandle descriptor, out DarwinStat status);
}
