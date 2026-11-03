# Reviewed connector fixtures

`youtube-0.2.1.json` preserves the existing released read/discovery fixture.

`youtube-0.2.2.json` is an exact source copy of `csweet-plugin.json` from
CrosswiredStudios/CSweet.Plugins.Platform.YouTube commit
`f2a802365918f50b7a4454ddcf08e537e0254b1b`. Its upload declaration adds the response
resource pointer `/snippet/channelId`. Media tests approve this candidate only inside
synthetic SQLite fixtures; this does not publish, install or approve it in a live service.
Negative tests explicitly alter their synthetic copy to exercise fail-closed behavior.
