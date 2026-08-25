# CBS250 Discovery Safety v3.1

## Purpose

v3.1 extends the investigation-only crawler after live v3 evidence showed that Cisco CBS250 context help can paginate at the root command list. The previous v3 safety invariant is retained: no bytes are sent after a help query's literal `?` marker.

## Why pagination cannot be handled with Space or Enter

Cisco CBS250 CLI displays a `More` prompt for sufficiently long output. Sending a pager navigation key after `?` would violate the crawler's strongest safety invariant and would reintroduce interactive-line state handling.

v3.1 therefore does not navigate the existing pager. It destroys that channel and performs new partial-keyword help queries on new disposable channels.

Examples:

```text
?
  -> More

s?
t?
w?
```

and:

```text
show ?
  -> More

show a?
show b?
show c?
...
```

Each shard is a separate help-only SSH channel and receives zero bytes after `?`.

## One-run `--full-safe`

`--full-safe` collects the maximum safely discoverable grammar in one invocation:

1. reviewed read-only inventory (`show version`, `show system`, `show ip ssh`);
2. privileged EXEC context-help tree;
3. automatic safe pagination sharding;
4. global-configuration context-help tree using ephemeral config-mode entry only;
5. progress/checkpoint evidence;
6. periodic SSH transport recycling and fail-closed channel-open retries.

## Explicit boundary

`--full-safe` is not equivalent to executing every possible CLI path. It deliberately does not instantiate dynamic values or enter configuration submodes that may create or modify state. Examples include arbitrary VLAN IDs, ACL names, interface values, IP addresses, filenames, credentials, and object-creating configuration contexts.

The resulting dataset is therefore the maximum live grammar that can be gathered without granting configuration/write authority.

## Duplicate command wrappers

The CBS `do` command mirrors EXEC-level grammar. v3 live evidence showed this creates a large duplicate subtree. v3.1 records `do` but marks it as a duplicate wrapper and does not recurse through it.

## Safety invariants

- discovered commands are never executed;
- destructive/state-changing roots remain hard-denied in the generic executor;
- every help query uses a disposable shell channel;
- no CR/LF is included in a help query;
- zero bytes are sent after `?`;
- no Space, Enter, Ctrl+C, or synchronization command is sent after `?`;
- unexpected transport/prompt behavior fails closed;
- configuration submode transitions are not authorized.
