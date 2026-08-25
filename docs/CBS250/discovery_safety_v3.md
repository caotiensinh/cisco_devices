# CBS250 Discovery Safety Contract v3

## v2.1 status

**RETIRED FOR LIVE DISCOVERY.**

The captured device transcript showed that partial CLI input could survive a help query and be executed by a later synchronization input. Observed effects included an overwrite prompt, a clear-logging confirmation prompt, and a change to active-image selection.

## v3 invariants

1. One help query uses one disposable SSH shell channel.
2. Help syntax ends in literal `?`, never CR/LF.
3. No bytes are sent on that channel after `?`.
4. The channel is destroyed after help text is read.
5. Discovered CLI text is data only.
6. Discovered CLI text never reaches an execution API.
7. Generic execution is exact-allowlist only.
8. `delete`, `clear`, `reload`, `boot`, `copy`, `write`, `configure`, `no`, `shutdown` and other state-changing roots are hard-denied.
9. Global configuration help is opt-in, ephemeral and help-only.
10. Any ambiguity fails closed.

## Architecture separation

Discovery authority is limited to:

```text
identify device
read reviewed inventory
query contextual help
parse syntax
classify risk
produce evidence
```

It has no configuration/write authority.
