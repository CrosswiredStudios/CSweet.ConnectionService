# Managed connection service contributors

- This is a provider-neutral security service, not an agent runtime. Never load plugin executables,
  add an LLM, return OAuth credentials, or add provider-name conditionals.
- Use published SDK validation and independently reviewed immutable package/profile bindings.
- Deployment signatures prove deployment identity only, never human mutation approval.
- Persist authority changes and content-free events atomically. Bound all inputs and retries.
- Keep proofs, launch handles, OAuth codes/state, credentials and handoffs out of logs/results.
- Version and pack changed public packages. Verify without sibling source references.
- Fake-provider tests do not establish Google acceptance, host integration or complete erasure.
