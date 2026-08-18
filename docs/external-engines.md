# External engines

An external engine is a Parquet implementation Parquity runs as a subprocess
instead of importing as a Python distribution. It lets implementations that do
not ship a Python provider — .NET, Java, Rust, Go, C++ — participate in the
same writer-by-reader matrix as the built-in providers.

External engines are never in the default matrix. They are configured
explicitly, selected explicitly by name, and their evidence is handled the same
way as evidence from a built-in provider.

## Configure an engine

Parquity reads external engines only from the file named by
`PARQUITY_ENGINES_FILE`. There is no implicit search path: an engine
declaration names a command Parquity will execute with the current user's
authority, so it is opted into deliberately rather than discovered from the
working directory.

```toml
# engines.toml
[engines.engineeredwood]
command = ["/usr/local/bin/engineeredwood-parquity"]

[engines.acme]
command = ["java", "-jar", "/opt/acme/parquity-bridge.jar"]
timeout_seconds = 120
```

```console
export PARQUITY_ENGINES_FILE=engines.toml
parquity engines
```

`command` is an argument vector, never a shell string: Parquity appends the
operation arguments to it and executes it directly, with no shell, no argument
splitting, and no variable expansion. `timeout_seconds` is optional, bounded by
1 through 300, and defaults to 60. It applies to each operation separately.

An engine name must match `[a-z][a-z0-9_-]*`, must be at most 32 characters,
and must not collide with a built-in provider name.

To point a configured name at a different build without editing the file, set
`PARQUITY_ENGINE_<NAME>_COMMAND`, where `<NAME>` is the engine name uppercased
with `-` replaced by `_`. A value that parses as a JSON array of strings
replaces the whole argument vector; any other value is used as a single
executable path, so paths containing spaces need no quoting.

```console
export PARQUITY_ENGINE_ENGINEEREDWOOD_COMMAND=./artifacts/engineeredwood-parquity
```

## Select an engine

External engines are selected by name like any other provider:

```console
parquity check case.json --out check-run \
  --writers pyarrow,engineeredwood \
  --readers pyarrow,duckdb,engineeredwood
```

Selecting an engine whose bridge is missing, unreadable, or failing its
`info` probe is a configuration error that exits 2 before any matrix work. A
requested engine is never dropped silently.

## The bridge contract

A bridge is any executable that answers three operations. The contract identity
is `parquity.bridge.v1`.

Tables cross the boundary as **Arrow IPC file format** — the framed format
written by `pyarrow.ipc.new_file`, not the streaming format. A bridge must
preserve the schema exactly, including field order, field names, nullability,
timestamp units and time zones, and decimal precision and scale. Multiple
record batches are permitted in either direction.

Parquity passes absolute paths. Input files exist and are readable; an output
file's parent directory exists and the bridge creates or replaces the file.

### `info`

```console
$ bridge info
{"protocol":"parquity.bridge.v1","engine":"engineeredwood","version":"0.1.0",
 "directions":["read","write"],
 "writer_profiles":{"compression-gzip":{"Compression":"Gzip"},
                    "row-group-2":{"RowGroupMaxRows":2}}}
```

| Field | Requirement |
|---|---|
| `protocol` | Exactly `parquity.bridge.v1`. |
| `engine` | Must equal the configured name, so a name cannot silently address the wrong binary. |
| `version` | Non-empty. Recorded with every result and compared on replay. |
| `directions` | Non-empty subset of `read` and `write`. |
| `writer_profiles` | Optional. Maps a [writer profile](writer-profiles.md) name to the exact effective options to record. |

Each `writer_profiles` key must be a registered profile name; an absent name is
reported as `UNSUPPORTED` rather than substituted with a default write. Option
values must be booleans, integers, or strings, and they should name the
provider's own public option, not restate the Parquity profile name.

Parquity probes `info` once per process and reuses the result.

### `read`

```console
$ bridge read --parquet IN.parquet --arrow OUT.arrow
{"status":"OK"}
```

### `write`

```console
$ bridge write --arrow IN.arrow --parquet OUT.parquet [--profile NAME]
{"status":"OK"}
```

`--profile` is passed only for a name the bridge declared in `info`.

### Responses and exit codes

Stdout carries exactly one JSON object and nothing else. Diagnostics belong on
stderr; Parquity captures a bounded amount of it and uses it only to explain a
failure. Neither stream may exceed 64 KiB. Stdin is closed.

| Exit | Stdout | Meaning | How Parquity records it |
|---:|---|---|---|
| 0 | `{"status":"OK"}` | The operation succeeded and produced its output file. | Normal result. |
| 1 | `{"status":"ERROR","kind":"...","detail":"..."}` | The implementation tried and failed. | Provider failure — evidence, with `kind` as the diagnostic kind. |
| 2 | `{"status":"ERROR","kind":"...","detail":"..."}` | The bridge rejected Parquity's request: unknown operation, missing argument, undeclared profile. | Protocol error — the run stops. |
| other | any | The process crashed, was killed, or exited without a well-formed response. | Provider failure — evidence, as `ExternalEngineCrash`. |

A bridge that does not answer within its timeout is neither: nothing was observed about
the implementation, so the run stops rather than recording a finding against it.

The split between exit 1 and exit 2 is the point of the contract. Exit 1 says
"this implementation cannot handle these bytes", which is exactly the
observation Parquity exists to record. Exit 2 says "Parquity asked for
something this bridge does not understand", which is a defect in the
integration and must not be filed as evidence about Parquet behavior. A run
that hits exit 2, unparseable stdout, or a missing output file after exit 0
stops loudly rather than recording a finding that names the wrong cause.

`kind` is recorded as the diagnostic kind and contributes to finding identity,
so it should be the implementation's own error class — `ParquetFormatException`,
`ArrowTypeError` — not a generic label. It must be a non-empty identifier of at
most 64 characters.

A timeout is deliberately not a provider failure. Exit 1 means the
implementation answered and said it failed, which is the observation Parquity
records; a timeout means it never answered, so there is nothing to record about
it, and treating the two alike would let a slow machine manufacture findings
against an engine that did nothing wrong. The run stops with
`EXTERNAL_ENGINE_TIMEOUT`, reported against the `timeout_seconds` that fixes it.

A crash is treated as evidence, unlike a timeout: a process that dies on a
particular input has told you something about the implementation.

## Evidence and replay

Evidence records the engine name and the version reported by `info` — the same
two fields, in the same place, as any provider discovered through Python
metadata, so nothing about the run format changes to accommodate an external
engine. The protocol identity is checked at probe time but not stored; a run
that produced evidence necessarily spoke the protocol.

It never records the configured command, which is a local path that would not
survive being shared and could disclose a filesystem layout.

Replay therefore resolves the command from the local configuration and compares
the freshly probed version with the recorded one, reporting version drift the
same way it is reported for a Python provider. Replaying evidence that names an
external engine requires that engine to be configured; it is a configuration
error otherwise, not a smaller matrix.

## Scope

External engines participate in `check`, `fuzz`, and `engines`. They are not
yet available to `scan`, whose reader isolation has its own worker contract.

Parquity does not install, build, or version-manage a bridge. It executes the
command it is given, and it reports what that command does.
