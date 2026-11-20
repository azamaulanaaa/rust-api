# The smolvm sandbox

The checks can run inside a [smolvm](https://smolmachines.com/)
microVM instead of on the host. The microVM runs the same
`scripts/ci.sh` entry point against the live working tree. The
repository is mounted at `/workspace` in the guest. The mount is
read-only. The guest kernel enforces the read-only mount. The
repository is not copied and it is not cloned.

Set `SMOLVM_ADDR` to send the checks to a `smolvm serve` endpoint on
another host. The guest command is the same. See
[Remote mode](#remote-mode).

Set `SMOLVM_ENABLED=1` to require smolvm. The checks then stop when
smolvm cannot run. See [SMOLVM_ENABLED](#smolvm_enabled).

This sandbox is modeled on the
[Throwaway machine](https://smolmachines.com/docs/guides/skills/throwaway-machine)
guide (smolvm v1.34.0, 2026-11-09). Modeled on throwaway-machine.
The checks are trusted static tools, not untrusted code. The guide
wraps untrusted workloads, so it records VM pids and force-kills
them. This sandbox runs trusted, read-only, bounded checks, so it
does not. See [Cancellation and the timeout](#cancellation-and-the-timeout-backstop).

`make ci` runs the checks inside smolvm by default on a host that
can run a machine. The flow was verified on 2026-11-16 on Linux
x86_64 with KVM and smolvm 1.35.1. Read the
[Verification status](#verification-status) section for the
boundary of that verification.

## The model

The sandbox follows the guide's isolation pattern with one change:
the workload here is trusted code.

- Offline by default. The VM runs a baked `.smolmachine` pack from
  the local cache. The pack run asks the registry for nothing.
  Network access happens during the pack build only on the local path.
  The cargo-deny advisories check needs network access in remote mode.
  The offline pack run cannot fetch the RustSec database.
- The repository is mounted with the `:ro` flag. The guest kernel
  refuses writes to it. The checks never write the repository.
- `make smolvm-preflight` reports whether this host can run the
  sandbox. It reads the host and starts no VM.
- `make smolvm-verify` probes the isolation from inside the guest
  and from the host. A run that exits zero proves nothing. The
  verify step checks the claims.
- `SMOLVM_ENABLED=0` forces the host path. The guest sets this value,
  so the checks do not recurse. `SMOLVM_ENABLED=1` requires smolvm and
  stops the run when smolvm is missing. An unset variable or any other
  value selects auto mode. `SMOLVM_GUEST=1` marks a process inside the
  guest. See [SMOLVM_ENABLED](#smolvm_enabled).

## Verification status

Verified on 2026-11-16 on Linux x86_64 with KVM and smolvm 1.35.1:

- `make smolvm-pack` completes. The pack build works. The
  `ci-<key>` stub and the `ci-<key>.smolmachine` sidecar are
  produced.
- `make ci` inside the microVM passes all checks.
- `make smolvm-exec` runs a command inside the guest. The exit
  code propagates.
- `make smolvm-clean` works. It reaps dangling machines and
  removes `.cache/smolvm/`.
- The host is capable of running the microVM. The guest `apt-get`
  step is noninteractive.

Verified live on 2026-11-19 with `smolvm serve` v1.35.4 at
`http://127.0.0.1:5000`:

- The session probe `GET /api/v1/machines/:name/execs` returned 200
  with `{"execs":[]}`. The run used session mode.
- `POST /api/v1/machines/:name/execs` with an `execId`,
  `command`, and `waitSecs` returned 201. The answer carried
  `output` chunks with base64 `data`, `next`, `done`, and `exitCode`.
  A short command finished in the one start request.
- A start that repeated the same `execId` returned 200 with the first
  answer and the first `createdAt`. The command did not run twice.
- `DELETE /api/v1/machines/:name/execs/:exec` returned 204.
- `make smolvm-exec ARGS='echo LIVE-SESSION-OK; exit 7'` ran the full
  remote flow. The init installed apt packages and 13 mise tools. The
  guest output streamed through the session reads. The script exited
  with the guest exit code 7. The machine list was empty after the
  run. The init took 91 seconds on one run and 171 seconds on another.
- A piped local file ran `make smolvm-exec ARGS='sha256sum -'` through
  the numbered stdin frames. The guest hash matched the local hash.
  The input carried one non-UTF-8 byte.
- `SMOLVM_SERVE_SYNC_DIR` uploaded a local directory. A relative link
  inside it stayed a link in the guest. An absolute link became a real
  file with the target content.
- The server ran without `--cache-disk-dir` for these runs. Every
  cache-base call answered 400 with `cache disks are disabled on this
  server; start \`smolvm serve\` with --cache-disk-dir to enable them`.
  The client printed the refused-cache warning and completed each run
  with full provisioning.

Verified live on 2026-11-19 after the server restarted with
`--cache-disk-dir`:

- The create body carried `cacheDisk` with the base
  `smolvm-ci-<sha256-of-the-repository-state>.qcow2` and `mountPath`
  `/cache`. The server refused the create because the base file does
  not exist. The answer was HTTP 400 with `cannot stat cache base (The
  system cannot find the file specified. (os error 2))`.
- The client printed the reason verbatim in the refused-cache warning,
  retried the create without the field, and completed the run with full
  provisioning. The init took 82 seconds. The guest command
  `echo LIVE-MISSING-BASE-OK; exit 3` streamed its output and the
  script exited with the guest exit code 3. The machine list was empty
  after the run.
- A publish on a machine without a cache disk answered HTTP 400 with
  `machine '<name>' has no cache disk`.
- `make smolvm-clean` called `DELETE /api/v1/cache-bases/{base}` for
  both derivable names and printed one `cache_base_removed=<name>` line
  per call. No base existed, so nothing was removed. The 204 answer
  makes the call succeed when the base is absent.
- Conclusion: the serve API cannot create the first cache base. A
  create needs an existing base file, a publish needs an attached cache
  disk, and no route writes the first file into the server's
  `--cache-disk-dir`. This client attaches only the content-keyed base
  name, so a base seeded under another name does not engage the flow.

Verified live on 2026-11-19 after the user seeded the blank base
`smolvm-seed.qcow2` in the server's cache disk directory:

- A create with `cacheDisk` base `smolvm-seed.qcow2` returned 200. The
  answer carried `"cacheDisk":{"base":"smolvm-seed.qcow2",
  "mountPath":"/cache","slot":false}`. The probe machine was deleted.
- A normal `make smolvm-exec` run tried the content base, got the
  `cannot stat cache base` answer, printed one warning that names the
  seed, and created the machine with the seed base. The full init took
  81 seconds.
- The client stopped the machine and published the content base. The
  server answered HTTP 400 with
  `cache disks are not supported on this host`. The client printed the
  status, the message, and one warning, and the run continued.
- The second readiness check after the restart used the exec id
  `<machine>-ready` again. The server answered HTTP 409 with `execId
  '<id>' already ran on this machine and was collected`. The client now
  uses a fresh id for that check. The next run completed with exit
  code 0 and the machine list empty.
- The next run also attached the seed, because no content base exists
  on this host. Its init took 85 seconds. Inside the guest,
  `mise --version` printed `2026.11.9 linux-x64 (2026-11-16)`,
  `which mise` printed `/usr/local/bin/mise`, and `shellcheck --version`
  printed `0.11.0`.
- A raw publish call with the exact spec body on a seed-attached
  machine answered HTTP 400 with
  `cache disks are not supported on this host`. The client is not the
  cause.
- Result: the seed bootstrap works live. The content base and the warm
  init do not work on this Windows host, because it refuses every
  publish. Each run pays full provisioning.

Verified on 2026-11-17 with `smolvm serve` v1.33.0 at
`http://127.0.0.1:5000`:

- `GET /health` and `GET /api/v1/machines` returned 200.
- `POST /api/v1/machines` with this repository's create body returned 200.
- The create body rejects a `smolfile` field with HTTP 422.
- `DELETE /api/v1/machines/:name` returned 200.
- With `SMOLVM_SERVE_IMAGE=bash:latest`, `make smolvm-exec
  ARGS='echo hello-from-remote'` printed the guest output.
- With the same image, `make smolvm-exec ARGS='exit 7'` returned exit
  code 7. The machine list was empty after each run.
- `hello-world` and `bash:latest` pulled and started on this server.
- A create with `debian:stable-slim` returned 200. The machine was not
  started.
- That server has no `/execs` routes. A run against it uses the stream
  and buffered fallback path.

Not verified live:

- A successful cache publish, the content base, the warm init, and the
  init duration gain. The 1.35.4 Windows host attaches the seed base
  and refuses every publish with
  `cache disks are not supported on this host`.
- The full `make smolvm` check run over HTTP. The live runs used
  `make smolvm-exec`, which runs the same remote flow with a guest
  command.
- Remote cleanup of a real base. `make smolvm-clean` and its
  cache-base step ran live, but the host published no base to remove.
- `./smol/verify.sh` (`make smolvm-verify`). The inside and
  outside isolation assertions were not confirmed green on a KVM
  host. Nothing reports `result=isolation_held` yet. The
  network-leak question from a `net=true` build machine stays open
  until the verify passes.
- macOS on Apple Silicon. The implementation exists (the
  `kern.hv_support` detection) but never ran. Treat it as untested.

## Requirements

- Linux x86_64 or aarch64 with KVM at `/dev/kvm`, readable by the
  user. A cloud instance or a VM must expose nested virtualization.
- Or macOS 11 or later on Apple Silicon. smolvm uses the built-in
  hypervisor there. `kern.hv_support` must be `1`. The detection in
  `scripts/ci.sh` and `scripts/smolvm.sh` supports this path. The
  macOS path is untested. See
  [Verification status](#verification-status).
- `smolvm` on `PATH`. Install it with
  `curl -sSL https://smolmachines.com/install.sh | bash`. See the
  [smolvm local documentation](https://smolmachines.com/docs/local).
- `git`, `make`, `sha256sum`, and `bash` on the host.
- For remote mode, a reachable `smolvm serve` endpoint, `curl`, `tar`, and
  a base image prepared on the server. See [Remote mode](#remote-mode).
- Network access in the guest during the pack build. The build
  installs packages with `apt-get` and mise with the mise.run
  script. The checks themselves do not need the network on the
  local pack path. The cargo-deny advisories check needs network
  access to fetch the RustSec database in remote mode.

## How it works

`make ci` calls `scripts/ci.sh`. After the `git` preflight and
before the checks run, `scripts/ci.sh` reads `SMOLVM_ENABLED`:

1. `SMOLVM_ENABLED=0` skips the detection. The script runs the checks
    on the host. The script prints no warning. The microVM sets this
    value in the guest command, so the checks do not recurse.
2. `SMOLVM_ENABLED=1` enforces smolvm. When `SMOLVM_ADDR` has a
    value, the script `exec`s `scripts/smolvm.sh` for the remote path.
    When `smolvm` is on `PATH` and the host accelerator works, it
    `exec`s `scripts/smolvm.sh` for a local microVM. Otherwise it
    prints the enforced-mode error on stderr and exits 3. The checks
    do not run on the host.
3. An unset variable or any other value selects auto mode. When
    `SMOLVM_ADDR` has a value, the script uses the remote path.
    When `smolvm` and the accelerator work, it uses a local microVM.
    Otherwise it prints the loud warning and runs the checks on the
    host.

The accelerator check needs a readable `/dev/kvm` on Linux. On macOS
with Apple Silicon it needs `kern.hv_support=1`.

`scripts/smolvm.sh` does the following:

1. If `SMOLVM_ENABLED=0`, it runs the checks on the host. The
    checks do not recurse.
2. If `SMOLVM_ADDR` has a value, it calls the remote REST
    path. See [Remote mode](#remote-mode). That path is strict.
3. Else it detects `smolvm` and the host accelerator. If either is
    missing and `SMOLVM_ENABLED=1`, it prints the enforced-mode
    error, exits 3, and does not run the checks. If either is missing
    in auto mode, it prints the loud warning and `exec`s the host
    checks with `SMOLVM_ENABLED=0`.
4. It computes the pack cache key. The key is the SHA-256 of the
    `sha256sum` lines of `mise.toml`, every `smol/*.smolfile`,
    `smol/pack-build.sh`, and `smol/init.sh`. The init script holds the
    provisioning steps. A change to it must build a new pack. The key
    also includes `SMOLVM_CPUS` and `SMOLVM_MEMORY_MB` when either
    value differs from its default. A different value builds a
    different pack.
5. It builds the pack when `.cache/smolvm/ci-<key>.smolmachine` is
    missing. It calls `smol/pack-build.sh` for the build.
6. It runs `smolvm machine run --from <pack> --timeout 10m -v
    "$PWD":/workspace:ro -- bash -lc 'cd /workspace &&
    SMOLVM_ENABLED=0 SMOLVM_GUEST=1 bash scripts/ci.sh'`. The VM is
    discarded on exit. No persistent machine is created. The
    `--timeout` value comes from `SMOLVM_TIMEOUT` and defaults to
    `10m`.
7. The exit code of the checks propagates. The exit code of
    `machine run` in foreground mode is used as the exit code of
    `scripts/smolvm.sh`.

The loud warning looks like this:

```text
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!! WARNING: smolvm or the host accelerator is not available.
!! The checks did NOT run in a microVM.
!! The checks run on the HOST instead.
!! Install smolvm and give the host a working accelerator.
!! See docs/smolvm.md for the requirements.
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

The loud warning appears in auto mode only. The scripts print it on
stderr when `make ci` or `make smolvm` runs without a usable smolvm
setup. The warning does not appear in enforced mode. It does not appear
for `SMOLVM_ENABLED=0`. Read the warning when a run feels faster than
expected.

In enforced mode, the scripts print this error on stderr and exit 3:

```text
ERROR: SMOLVM_ENABLED=1 requires smolvm.
smolvm is not on PATH, or the host accelerator is unavailable.
The checks did not run.
Install smolvm on the host.
Give the host a working accelerator.
Alternatively, set SMOLVM_ADDR to use a remote smolvm server.
See docs/smolvm.md for the requirements.
```

Exit code 3 makes CI fail when smolvm is unavailable. The error says
that the checks did not run. Install smolvm and fix the accelerator.
You can also set `SMOLVM_ADDR` for a remote run. Then run the
checks again.

## Remote mode

Set `SMOLVM_ADDR` to run the checks on a remote host. The scripts
call a `smolvm serve` HTTP endpoint with `curl`. The local CLI is not used.
No new runtime is added. The repository is not baked into a machine image.

The client probes the server for the exec session API. A server with the
session endpoints runs every exec in one resumable session and streams a
piped stdin to the guest command. A server without them prints one
warning and uses the stream and buffered paths of the earlier flow. See
[Exec sessions](#exec-sessions).

A server with `--cache-disk-dir` can keep the installed tools in a
published base. The client asks for the disk by default and publishes it
after a cold init. See [Cache disk](#cache-disk). Set
`SMOLVM_SERVE_SYNC_DIR` to send one local directory with the run. See
[Local data upload](#local-data-upload).

`scripts/check-cargo-deny-advisories.sh` fetches the RustSec advisory
database over the network. Remote mode sets `network: true` in the create
body, so the fetch works. The offline local pack path cannot fetch the
database.

### Environment variables

- `SMOLVM_ADDR` sets the server address. Use a full URL such as
  `http://127.0.0.1:8080` or `https://host:8443`. Use a bare `host:port`
  value to get an `http://` prefix. Use a socket path such as
  `/run/smolvm.sock` or a `unix://` value for a Unix socket.
- `SMOLVM_SERVE_TOKEN` is optional. When set, every API call carries an
  `Authorization: Bearer` header. The scripts never print the token value.
- `SMOLVM_SERVE_IMAGE` names the base image for the machine. The default
  value is `debian:stable-slim`. This is the image in
  `smol/base.smolfile`. Set another image when you publish one with the
  tools already installed.
- `SMOLVM_SERVE_TIMEOUT` sets the curl timeout in seconds. The default
  value is `120`. The local path still uses `SMOLVM_TIMEOUT`.
- `SMOLVM_SERVE_RUN_TIMEOUT` sets the total timeout of one remote run
  in seconds. The default is `1800`. The value must be a positive
  integer. The timeout bounds the whole remote run after the staging
  step, including the init exec and the guest command. Each HTTP call
  still uses `SMOLVM_SERVE_TIMEOUT` as its curl max-time.
- `SMOLVM_SERVE_ALLOW_HOSTS` adds an egress allow list to the machine.
  The value is a comma-separated list of hostnames. The default is
  unset. An unset value keeps the create body unchanged. A set value
  adds the `allowedHosts` field to the create body. The scripts stop
  when one entry is empty. See
  [Egress allow list](#egress-allow-list).
- `SMOLVM_SERVE_CACHE` turns the remote cache disk on or off. The
  default is `1`. The value must be `0` or `1`. See
  [Cache disk](#cache-disk).
- `SMOLVM_SERVE_CACHE_SEED` names the blank base that builds a missing
  content base. The default is `smolvm-seed.qcow2`. An empty value
  disables the seed attempt. The value is a bare file name of at most
  128 characters: letters, digits, hyphens, underscores, and the suffix
  `.qcow2`, `.img`, or `.raw`. See [Cache disk](#cache-disk).
- `SMOLVM_SERVE_SYNC_DIR` sends one local directory to the machine in
  addition to the worktree archive. `SMOLVM_SERVE_SYNC_TARGET` names the
  absolute guest path for it. The default is `/workspace`. See
  [Local data upload](#local-data-upload).
- `SMOLVM_CPUS` sets the CPU count of the machine. The default value is
  `1`. The value must be a positive integer.
- `SMOLVM_MEMORY_MB` sets the memory of the machine in MiB. The default
  value is `512`. The value must be a positive integer.

`SMOLVM_CPUS` and `SMOLVM_MEMORY_MB` also set the resources of the local
build machine. The scripts stop when either value is not a positive
integer. A change to either value builds a new pack. Remote mode does
not use the pack, but it sends both values in the create body.

When `SMOLVM_ADDR` is set, the scripts need a reachable server. They
require a successful remote run. They never run the checks or the user
command on the host. If a call fails, they print an error and exit non-zero.

The remote path prints two warnings on stderr. The first warning says
that the local pack cache is not used. The second warning says what the
init script downloads: the tools on every run when the cache is off, or
the tools only when the cache base is missing when the cache is on.
`make smolvm-pack` refuses to run while `SMOLVM_ADDR` has
a value. Unset the variable before you build a local pack.

### API flow

`scripts/smolvm-serve.sh` holds the shared REST calls. Both entry points
source it. One run follows these steps:

1. Check that `curl` and `tar` are on PATH.
2. Resolve the server address into a base URL and curl options.
3. Copy the live working tree to a staging directory. Exclude `.git`
    and `.cache`. Exclude the staging directory and the archive too.
    A temp directory can appear inside the repository. On some hosts
    `/tmp` maps to the repository's `.tmp` directory. The source copy
    must not read the staging directory while the copy writes it.
    That loop never ends. Build a portable `.git` in the staging
    directory. Resolve a worktree pointer to the real git dirs first.
    Copy the common git data and overlay the per-worktree files. Remove
    the pointer files and the worktree list. Check the staged git data
    before any API call. Archive the staging directory. No data comes
    from the local pack cache.
4. Call `GET /health` to check that the server answers.
5. Call `POST /api/v1/machines` with `image` and `network: true` to
    create a machine. The body carries `allowedHosts` when
    `SMOLVM_SERVE_ALLOW_HOSTS` is set. It carries `cacheDisk` when
    `SMOLVM_SERVE_CACHE` is on. A server that refuses the cache disk
    gets one retry without the field.
6. Call `POST /api/v1/machines/<name>/start` to start it.
7. Probe the exec session API. The client calls the read-only list
    route `GET /api/v1/machines/<name>/execs`. A 200 answer turns
    session mode on. A 404 with an empty or non-JSON body turns it off.
    The client prints one warning and uses the fallback flow below. Any
    other answer stops the run with the HTTP status and the server
    message.
8. Call `PUT /api/v1/machines/<name>/files/...` to upload the archive.
    The client measures the archive first. A size above 1 GiB stops the
    run before the call. When `SMOLVM_SERVE_SYNC_DIR` is set, the
    client uploads that directory as a second archive and extracts it
    to a fresh guest directory that it moves into place.
9. Session mode: run the extract exec, the sync extract, the init
    exec, and the guest command through exec sessions. See
    [Exec sessions](#exec-sessions). Init output appears on the console.
    A non-zero `exitCode` stops the run. After a cold init with an
    attached cache disk, the client stops the machine, publishes the
    cache disk, and starts the machine again. See
    [Cache disk](#cache-disk).
10. Fallback mode: call `POST /api/v1/machines/<name>/exec` to extract
    the archive. Call it again to run `bash /workspace/smol/init.sh`.
    Then call `POST /api/v1/machines/<name>/exec/stream` to run the
    guest command. This endpoint returns Server-Sent Events. The client
    prints each output event when it arrives. It reads `exitCode` from
    the exit event. When the stream gives no output and no exit code,
    the client calls `POST /api/v1/machines/<name>/exec` for the same
    command.
11. Call `DELETE /api/v1/machines/<name>` to delete the machine.

Both modes use the same guest command. It is
`cd /workspace && SMOLVM_ENABLED=0 SMOLVM_GUEST=1 bash scripts/ci.sh`.
For `make smolvm-exec` the command runs with the same two variables.

An exec call returns HTTP 200 when the guest command fails. The helper
reads `exitCode` from the response body. A stream call gives the same
value in its exit event. A session gives it in the answer that reports
`done`. The guest exit code becomes the exit code of the script. The
exit trap deletes the machine on every path. The trap also removes the
local archive and the stream state directory.

### Serve API reference

This repository calls the smolvm serve API of two generations. The 0.5.2
spec is the floor: every server that this repository supports answers
those endpoints. The 1.35.4 server adds the `/execs` session family and
the cache-base routes. Its OpenAPI document names the session frame
format. A server may run a different API version. The probe decides what
a run uses.

#### Endpoints that this repository calls

| Method | Path | Purpose | Fields the scripts use |
| --- | --- | --- | --- |
| GET | `/health` | Check the server. | No body. |
| POST | `/api/v1/machines` | Create a machine. | Req: `name`, `image`, `cpus` |
| | | | Req: `memoryMb`, `network`, `cmd` |
| POST | `/api/v1/machines/{name}/start` | Start a machine. | Path: `name` |
| POST | `/api/v1/machines/{id}/exec` | Run a command. | Req: `command` |
| | | | Resp: `exitCode`, `stdout`, `stderr` |
| | | | Resp: `stdoutB64`, `stderrB64` (byte-exact) |
| POST | `/api/v1/machines/{id}/exec/stream` | Stream command output. | |
| | | | Req: `command` |
| | | | Resp: SSE events with `stdout`, `stderr`, `exitCode` |
| PUT | `/api/v1/machines/{id}/files/{path}` | Upload archive. | `id`, `path` |
| | | | Body: `application/octet-stream` |
| POST | `/api/v1/machines/{name}/execs` | Start a session. | Req: `execId` |
| | | | Req: `command` |
| GET | `/api/v1/machines/{name}/execs/{exec}` | Read output. | |
| | | | Query: `after`, `wait` |
| | | | Resp: chunks, `next`, `done` |
| POST | `/api/v1/machines/{name}/execs/{exec}/stdin` | Send a frame. | |
| | | | Req: `seq`, `data`, `eof` |
| DELETE | `/api/v1/machines/{name}/execs/{exec}` | End a session. | |
| POST | `/api/v1/machines/{name}/stop` | Stop the machine. | |
| POST | `/api/v1/machines/{name}/cache-disk/publish` | Publish. | |
| | | | Req: `base` |
| DELETE | `/api/v1/cache-bases/{base}` | Remove one base. | Path: `base` |
| GET | `/api/v1/machines` | List machines. | Read `name` from each item. |
| DELETE | `/api/v1/machines/{name}` | Delete a machine. | Path: `name` |

In the table, `Req` names fields in the request body. `Resp` names fields
in the response body. A `name` or `id` in braces is a path parameter.

The three `/execs` rows are absent from the serve API 0.5.2 spec. They
exist on newer servers only. The probe handles a server without them.

The scripts send `command` as an array of strings. The first item names
the program. The other items are its arguments. The scripts read
`exitCode` as an integer. A value other than 0 stops the run. The upload
sends the worktree archive as an octet-stream body.

#### Exec sessions

A newer server keeps an exec session on the machine. The session belongs
to the machine, not to the connection that started it. A client can drop
off and read the rest later.

The client chooses the `execId` before the first start. The id uses 8
to 64 characters of `A-Z`, `a-z`, `0-9`, `_` and `-`. This repository
builds the id from the machine name and a purpose tag, for example
`smolvm-remote-<pid>-<random>-guest`. A start that repeats an `execId`
returns the session that the first start made. The command does not run
twice. On a retried start the client sends the same `execId`.

The start call is `POST /api/v1/machines/<name>/execs`. The body carries
the `execId`, the `command` array, and `waitSecs`. The wait lets a short
command finish in this one request, because the answer then carries the
output from offset 0. The client sends `waitSecs` from
`SMOLVM_SERVE_TIMEOUT` minus a margin, capped at the server limit of 60
seconds.

Each answer is one `ExecSessionResponse`. The answer carries `output`,
an array of chunks. One chunk names its `stream`, `stdout` or `stderr`,
and carries its bytes base64-encoded in `data`. Stdout and stderr share
one offset space. The output is byte-exact by construction. This path
has no lossy fallback. The answer also carries `next`, the next byte
offset to read, `done`, and after the exit the `exitCode`.

The client reads output with `GET /api/v1/machines/<name>/execs/
<execId>?after=<next>&wait=<seconds>`. The first `next` comes from the
start answer. The `wait` long-polls for output or the exit, so the client
does not sleep between reads. It reads until an answer reports `done`
and takes the exit code from the last answer. It deletes the session
with `DELETE /api/v1/machines/<name>/execs/<execId>` after `done` and on
every failure path.

A failed read retries the same `GET` with the same `after` after one
second. The client stops after three failed reads in a row. It also
stops when `SMOLVM_SERVE_RUN_TIMEOUT` expires. An answer that reports
`lost` output stops the run with an error that names the gap. The reader
fell behind and the server dropped those bytes. The run cannot continue
without them. The session path sends no `timeoutSecs`, so one long init
run no longer hits the single-request cap.

The frame format above follows the serve API of smolvm 1.35.4. It was
read from that server's OpenAPI document and verified live. The 0.5.2
spec does not list the `/execs` routes, so a server of the 0.5.2
generation lacks them. The probe handles that case.

#### Session stdin

A piped local stdin streams to the guest command as numbered frames. The
client starts the guest session with `interactive` set. It reads the
local stdin in chunks of at most 64 KiB. It sends each chunk with
`POST /api/v1/machines/<name>/execs/<execId>/stdin` as `seq` from 1 and
`data` base64-encoded. The last frame carries `eof`. A frame already
applied is acknowledged and ignored, so the client may send the same
`seq` again after a failure. It retries one frame up to three times.
After each frame it reads the session output without a wait, so the
guest output interleaves with the input. The checks path never sends
stdin.

The fallback path has no frames. It sends the whole local stdin as the
one-shot `stdin` string of `ExecRequest`. It stops with an error when
the input is over one MiB or contains a NUL byte.

#### Exec timeout

`ExecRequest.timeoutSecs` sets a server-side timeout in integer
seconds. The fallback path sets this field on every buffered exec call.
The value comes from `SMOLVM_SERVE_TIMEOUT`. That variable sets the
curl client max-time and defaults to 120 seconds. The scripts subtract
5 seconds. They use a floor of 1. They fall back to 115 when the
variable is missing or invalid.

The server timeout must be shorter than the client timeout. The server
then returns a response with an `exitCode` before curl gives up. If both
timeouts are equal, curl can end the call before the server returns the
exit code.

The session path sends no `timeoutSecs`. One session spans many short
HTTP calls, so a single-request cap would cut a long init run. The
whole remote run is bounded by `SMOLVM_SERVE_RUN_TIMEOUT` instead.

#### Upload limit

The serve upload endpoint accepts at most 1 GiB with a `Content-Length`
and at most 100 MiB without one. A larger upload gets HTTP 413. The
client measures the archive before the upload. It stops with an error
that names the limit and the measured size when the archive exceeds
1 GiB. The 413 handling stays for a server that answers the call
anyway.

#### Egress allow list

Set `SMOLVM_SERVE_ALLOW_HOSTS` to add an egress allow list to the
machine. The value is a comma-separated list of hostnames. The scripts
trim one space around each entry. An empty entry, or a value of only
spaces, stops the run with an error. The field `allowedHosts` exists in
the serve API 0.5.2 spec. The server learns the DNS answers for the
allowed names into its egress allow list. Subdomains of an allowed name
are allowed too.

One limit stays. A machine that `serve` starts cannot reach a private,
carrier-NAT or loopback address, even when its allow list names one.
`serve` raises this egress floor for every machine it starts. No allow
list entry lowers it. Lift the floor only with the server-side
environment variables of `serve`. This repository does not try to work
around the floor.

#### Cache disk

Set `SMOLVM_SERVE_CACHE=1` to ask the server for a cache disk. The
default is `1`. Set `0` to turn the feature off. The create body then
gains `cacheDisk` with `mountPath` `/cache` and a base named
`smolvm-ci-<key>.qcow2`. The `<key>` is the same SHA-256 that the local
pack cache uses. A change to `mise.toml`, one `smol/*.smolfile`,
`smol/pack-build.sh`, or `smol/init.sh` names a new base. Base names
are immutable on the server, so one repository state owns one base
name.

The machine reads the base through its own copy-on-write layer mounted
at `/cache`. `smol/init.sh` puts the apt archives, the mise download
cache, the mise data, and the mise binary under `/cache`. The wiring
under `/etc` and `/usr/local/bin` lives on the overlay and is written
again on every run. A machine from a published base reuses the
downloads. The init script prints `smolvm-init-mode=warm` then. A cold
machine prints `smolvm-init-mode=cold` and downloads everything. The
client prints the init duration on every remote run.

The seed base builds the first content base. Seed it once on the
server: create one empty file in the server's cache disk directory. A
blank base is valid; the runtime formats it as ext4 at the mount path.
The default name is `smolvm-seed.qcow2`. On a Windows server, run one
of these commands:

```text
cmd:        type nul > C:\cache\smolvm\smolvm-seed.qcow2
PowerShell: New-Item -ItemType File C:\cache\smolvm\smolvm-seed.qcow2
```

On a POSIX server, run this command:

```text
: > /path/to/cache-dir/smolvm-seed.qcow2
```

Set `SMOLVM_SERVE_CACHE_SEED` to another bare file name. An empty
value turns the seed attempt off. The seed name does not use the
`smolvm-ci-` prefix, so the clean step never deletes it.

The create sequence with caching on:

1. Try the create with the content base `smolvm-ci-<key>.qcow2`.
2. On HTTP 400 with `cannot stat cache base` in the server message,
    try the create once with the seed base. One warning names the seed.
3. When the seed attempt also fails, create once without `cacheDisk`.
    One warning says the run pays full provisioning.
4. On HTTP 400 that says cache disks are disabled, create once
    without `cacheDisk` and name the reason.
5. Any other failure stops the run with the status and the message.

The publish rule: after a successful init, the client publishes the
content base when the machine attached the seed. It stops the machine,
publishes, and starts the machine again. A publish answer of 409 names
a base that exists already. The client treats that answer as success. A
run that attached the content base skips the publish and prints one
`note:` line. A publish that fails another way prints the status and
the message and one warning, and the run continues.

One limit stays: later writes to a published base are not published
again. A provisioning change must change the hash to build a new base.
Edit `mise.toml` or `smol/init.sh` for that.

The clean step: `make smolvm-clean` deletes the cache bases it can
name, `DELETE /api/v1/cache-bases/{base}`. The serve API has no list
route for bases, so only the names derived from the current repository
state are known. Bases of older repository states keep their names.
Remove those by hand on the server. The seed base always stays. When
the seed name matches a derivable name, the client prints one `note:`
line and skips it. See [Verification status](#verification-status).

#### Local data upload

Set `SMOLVM_SERVE_SYNC_DIR` to send one local directory to the machine
in addition to the worktree archive. Set `SMOLVM_SERVE_SYNC_TARGET` to
the absolute guest path for it. The default is `/workspace`. The client
copies the directory, applies the symlink policy below, and uploads the
result as its own archive. The guest extracts it to a fresh directory
and moves it into place, so a stale link in the guest can never be
written through.

The symlink policy:

1. A relative link that stays inside the directory and names an
    existing target is preserved as a link.
2. Any other link that names an existing regular file is replaced with
    a real copy of that file. This covers absolute links and links that
    escape the directory.
3. A link whose target is gone, or is not a regular file, is skipped.
    The client prints one `warning:` line per skipped link.
4. A loop of links stops the run with an error before any API call.

#### Output fields

`stdout` and `stderr` are a lossy UTF-8 view. A non-UTF-8 byte becomes
U+FFFD. The fields `stdoutB64` and `stderrB64` carry the raw bytes as
base64. Those fields are byte-exact. A caller that needs binary-safe
output uses the base64 fields.

A separate issue changed the scripts to print the base64 fields. When the
base64 fields are absent, the scripts print the lossy fields. They also
print a warning on stderr.

#### Unknown fields

`CreateMachineRequest` and `ExecRequest` set `additionalProperties` to
`false`. An unknown field or a mis-cased field gets HTTP 400. The server
does not treat the field as a silent no-op. The create body has no
`smolfile` field. It uses `image`, or `from` for a `.smolmachine` artifact.

The 0.5.2 spec describes unknown fields as HTTP 400. On a live v1.33.0
server, a create body with `smolfile` returned HTTP 422. See
[Verification status](#verification-status). The observed result stays in
that section.

#### Other useful endpoints

The 0.5.2 spec also lists these endpoints. This repository does not call
them. The list below describes the spec only. It makes no promise about a
server implementation.

- `GET /api/v1/machines/{id}/logs?source=workload` streams the workload's
  stdout and stderr.
- `GET /api/v1/machines/{id}/files/{path}` downloads a file as a raw byte
  stream, or lists a directory as `entries` with name, kind, and size.
- `GET /api/v1/machines/{name}/egress-events` lists the egress denials for
  a machine.
- `GET /api/v1/machines/{name}/mounts` lists the host directories mounted
  into a running machine.
- `POST /api/v1/machines/{name}/cache-disk/publish` publishes the cache
  disk of a stopped machine as a new base in the server cache.

### Provision the machine

`smol/init.sh` holds every provisioning step. The local pack build and
the remote run both use this one script. The script installs the
packages with apt-get. It installs mise from mise.run. It runs
`mise install` in `/workspace`. It trusts `/workspace` in git. It adds
the mise shims to the login shell PATH and links them into
`/usr/local/bin`. It prints an `error:` line and exits non-zero when a
step fails.

The script is cache-aware. On a remote machine with a cache disk, the
apt archives, the mise download cache, the mise data, and the mise
binary live under `/cache`. The wiring under `/etc` and
`/usr/local/bin` lives on the overlay and is written again on every
run. The script clears the mise download cache only on the local pack
path. It prints `smolvm-init-mode=warm` when the machine found the
cached mise binary and `smolvm-init-mode=cold` when it must download
everything. A cold init is correct on a cache miss.

The local pack build runs `bash /workspace/smol/init.sh` in the build
machine. The remote run uploads the working tree and runs the same
command in a fresh machine. The upload carries a portable copy of the
git metadata. The checks need the git history for `git rev-parse` and
`git ls-files`. Without it, a check can fail or report a false pass.

A git worktree has a `.git` pointer file. That pointer names a directory
that does not exist in the guest. The client resolves the worktree
pointer on the host before upload. It copies the common git data, then
overlays the per-worktree files. It removes the pointer files and the
worktree list. A normal checkout needs one copy because its git dir is
its common dir. The client checks the staged git data before it calls
the API. The upload leaves out `.cache`, so no data comes from the
local pack cache. Remote mode uses no pack. Without a cache disk it
downloads the tools on every run. With a cache disk it downloads them
only when the base is missing. The create body sets `network: true` so
apt-get and mise.run can reach their endpoints.

The serve API has no pack-create endpoint. It also rejects a `smolfile`
field in the create body with HTTP 422. A create body therefore names an
image. `SMOLVM_SERVE_IMAGE` sets that image. The default is
`debian:stable-slim`, the image in `smol/base.smolfile`. Set another
image when you publish one with the tools already installed.

### Security boundary

`smolvm serve` has no authentication by default. Bind it to loopback or a
protected Unix socket. For a remote host, put it behind an authenticated TLS
proxy. The token is opt-in and the scripts do not print it. Anyone who can
call the API can create machines and run commands. Treat the API as a host
shell. Keep the server and its proxy on a trusted network.

## Offline by default

The pack is a baked artifact built ahead of time. A
`smolvm machine run --from <pack>` run asks the registry for nothing.
The host asks the registry only for `--oci-cache` runs. No step in the
check path passes `--oci-cache`, so the local pack checks run with no
network. The cargo-deny advisories check needs network access to fetch
the RustSec database. Remote mode sets `network: true` for that fetch.
The offline pack path cannot fetch the database.

The pack build is the only step with a network on the local path.
Nothing untrusted runs during the build. The build machine mounts the
repository at `/workspace` with the `:ro` flag and only reads
`mise.toml` from it.

This is materially stronger isolation than a run with egress rules. A
filter on egress depends on the workload's cooperation. No network is
a property of the local pack machine.

## The pack

`make smolvm-pack` builds the pack. The build does the following:

1. Renders `smol/base.smolfile` with the selected resource values. The
    file holds placeholders. The build writes a temporary smolfile with
    the values from `SMOLVM_CPUS` and `SMOLVM_MEMORY_MB`. It creates the
    machine from that file. The repository is mounted at `/workspace`
    with the `:ro` flag.
2. Installs `bash`, `ca-certificates`, `curl`, and `git` with
    `apt-get`.
3. Installs mise to `/usr/local/bin/mise` with the mise.run script.
4. Runs `mise install` in `/workspace`. The tools land in the pack.
5. Runs `mise cache clear` to remove the download cache from the
    pack. The installed tools are not removed.
6. Adds `safe.directory /workspace` to the root git configuration.
7. Adds the mise shims to the login shell PATH through
    `/etc/profile.d/mise.sh`. It also links the shims into
    `/usr/local/bin` so non-login shells find the tools.
8. Stops the machine.
9. Runs `smolvm pack create --from-vm <name> --cpus <cpus> --mem <mem>
    -o .cache/smolvm/ci-<key>`. The `<cpus>` and `<mem>` values come
    from `SMOLVM_CPUS` and `SMOLVM_MEMORY_MB`. On smolvm v1.35.1 the
    `-o` value names the executable stub. The sidecar
    `ci-<key>.smolmachine` is created automatically as
    `<output>.smolmachine`. An `-o` value that ends in `.smolmachine`
    is rejected. `--single-file` does not change this. The stub is
    capped at the selected CPU count and memory size. The caps are not
    reservations.
10. Deletes the build machine.

If a failure happens before the pack create succeeds, the trap
removes the build machine. It stops the machine, deletes it with
`--force --cascade`, and removes possible partial artifacts: the
stub `ci-<key>` and the sidecar `ci-<key>.smolmachine`. The trap is
disarmed when `pack create` succeeds, so the trap never removes a
good pack. If the final machine delete fails after that, the build
machine may dangle, but the pack survives. Use the recovery steps
below in that case. If a provisioning step fails, the build also
prints the guest disk usage before it exits. The output names `/`,
`/root/.cache/mise`, and `/root/.local/share/mise`.

If a build machine ever dangles anyway, `make smolvm-clean` removes
it. The target deletes only the `smolvm-build-*` and `smolvm-run-*`
machines. It then removes `.cache/smolvm/`, which covers the possible
partial artifacts: the stub `ci-<key>` and the sidecar
`ci-<key>.smolmachine`. See [Clean the sandbox](#clean-the-sandbox).

The pack cache key covers `mise.toml`, `smol/pack-build.sh`,
`smol/init.sh`, and every `smol/*.smolfile`. The init script holds the
provisioning steps. Change one of these files and the next
`make smolvm-pack` builds a new pack. The key also covers
`SMOLVM_CPUS` and `SMOLVM_MEMORY_MB` when a value differs from its
default. A pack built for one resource setting is not reused for
another setting. The old pack stays in `.cache/smolvm/` until
`make smolvm-clean` removes it. Remote mode does not use this pack.

The pack does not contain the repository. `pack create --from-vm`
captures the machine disk, and the disk has an empty `/workspace`
from the mount. The checks run against the live working tree on
every run.

`smolvm pack create -o .cache/smolvm/ci-<key>` writes the executable
stub `ci-<key>` and the auto-created sidecar `ci-<key>.smolmachine`.
This repository uses the sidecar through `smolvm machine run --from`.
`scripts/smolvm.sh` checks for the sidecar and runs it.

## Guest disk sizing

The build guest writes to an overlay rootfs. The limits live in
`smol/base.smolfile`. The `overlay` limit caps the writable layer.
The `storage` limit caps the disk. The mise cache, the node runtime,
and the installed tools all live on the overlay.

A pack build can fail near the end of `mise install` with a line
like this:

```text
failed copy: ~/.cache/mise/invocation-downloads/.tmptTmkhE/artifact -> ~/.local/share/mise/downloads/hadolint/2.15.1/.hadolint-linux-x86_64.mise-part
```

The cause is the `overlay` limit. The install downloads node 24,
ten tools, and two npm trees. The cache and the tools together
exceed a 1 GiB overlay. The fix raises `storage` to 2 GiB and
`overlay` to 4 GiB. The pack build also runs `mise cache clear`
after the install. The clear removes the download cache from the
pack. The installed tools stay in the pack.

On 2026-11-16 `make smolvm-pack` completed on Linux x86_64 with
KVM. The pack build works with the 2 GiB `storage` and 4 GiB
`overlay` limits. To check the cache in a pack run:

```bash
smolvm machine run --from .cache/smolvm/ci-<key>.smolmachine \
  -- bash -lc 'du -sh /root/.cache/mise'
```

Expect the output to show an empty or near-empty directory.

The pack cache key includes `smol/init.sh` and every `smol/*.smolfile`.
The bump of `storage` and `overlay` changes that hash. The next
`make smolvm-pack` builds one fresh pack automatically. You do not
need to remove the old pack first.

## Check the isolation

A run that exits zero proves neither the read-only mount nor the
network block. `make smolvm-verify` checks both, in the same shape
as a real run: the cached pack, the repository read-only at
`/workspace`, no network.

The verify step does two halves.

From inside the guest:

1. `touch /workspace/ISOLATION_PROBE` must fail. A success means the
    read-only mount leaked.
2. A TCP connect to `example.com:80` with bash `/dev/tcp` must fail.
    No external probe tool is needed. If the guest bash has no
    `/dev/tcp` support, the step prints `net=no_probe_tool` and fails.
    It does not silently pass.

From the host afterwards:

1. The repository has no `ISOLATION_PROBE` file. If the probe leaked,
    the step deletes the file it created and reports a FAIL.

The step prints key=value lines:

```text
inside_workspace=ok (readonly)
inside_network=ok (blocked)
repo_unchanged=ok
result=isolation_held
```

The step exits 0 when the isolation held. It exits 1 on a FAIL or on
a `result=blocked`. A blocked result means the probe cannot run on
this host: no smolvm, no accelerator, or no pack. On such a host the
step prints its key=value lines and exits 1 instead of crashing.

Run the preflight first, then the verify step, then the microVM:

```bash
make smolvm-preflight
make smolvm-verify
make smolvm
```

As of 2026-11-16 the verify step did not print
`result=isolation_held` on a KVM host. See
[Verification status](#verification-status).

## What a REACHED result means

If the verify step prints `inside_network=FAIL expected=blocked
actual=REACHED` on a host with KVM, the guest reached the network.
That is a failure to report, not a reason to remove the check.

The pack may carry `net=true` from the build machine's Smolfile. A
CLI change can have the same effect. No fix is included here because
no fix was verified. The right response to a REACHED result is:

1. Open an issue on this repository with the full output.
2. Name the smolvm version and the host platform.
3. Propose the fix only with a boot test that shows the probe blocked.

The verify gate is the guardrail. It exists so this condition cannot
pass unnoticed.

## Preflight

`make smolvm-preflight` prints one key=value line per probe. The
last line is `result=ready` or `result=blocked`. The script is
read-only: it starts no VM and writes no smolvm state. The exit code
is 0 when ready, 1 when blocked, 2 on a usage error.

The probe lines:

- `smolvm_installed=yes|no` and `smolvm_version=<version>`.
- `verified_version=1.34.0` and `version_status=match|newer|older|unknown`.
  The guide was verified on v1.34.0. The scripts print
  `version_status` deliberately. Check each flag against your binary.
- `platform=linux-x86_64|linux-aarch64|darwin-aarch64` and
  `accel=kvm|hypervisor_framework`.
- `accel_access=ok|missing|denied`. On Linux the probe tests
  `/dev/kvm`. On macOS it tests `sysctl -n kern.hv_support`; the
  value must be `1`.
- `pack_run=available|unverified|unavailable`. On macOS the printed
  value is `unverified`. The macOS path is untested.
- `planned_mounts=1`, `planned_ports=0`, `devices_requested=1`.
- `device_budget=9` on x86_64 and `device_budget_ok=yes`. A guest
  boots with at most nine devices there, so one mount is always
  inside the budget. On aarch64 `device_budget_ok=not_limiting`.
- `cancel_route=ctrlc`. Ctrl-C on the smolvm CLI ends the VM on
  smolvm v1.20.2 and later.

On a host with no accelerator, the probe prints the failing line,
prints `result=blocked`, and exits 1. That is the correct behavior,
not a bug.

## Cancellation and the timeout backstop

Ctrl-C on the smolvm CLI ends the VM on smolvm v1.20.2 and later.
The sandbox keeps `machine run` in the foreground so that Ctrl-C
reaches the CLI and ends its VM.

`machine run` also gets `--timeout`, default `10m`. Override it with
`SMOLVM_TIMEOUT`. The timeout is a backstop for a hung run.
It is not the normal way to stop a run.

This differs from the guide on purpose. The guide backgrounds the
CLI, records the VM pid in a pid file, and ships a cleanup script
with a `--cancel` mode. That machinery exists for untrusted
workloads: the workload must be force-killed and must not be left
running. The guest here runs trusted, bounded, read-only checks. No
untrusted code runs. `machine run` stays in the foreground, Ctrl-C
ends the VM, and `--timeout` kills a hung run. This sandbox does not
record VM pids and does not ship a reaper. If you adapt this sandbox
to run untrusted code, use the guide's machinery instead.

The guide also collects artifacts from a writable `/out` mount. This
sandbox needs no artifact collection; the checks print their own
results. The guide grants egress with `--allow-host`. This sandbox
grants no egress and publishes no ports, so the device budget is not
a concern.

## Clean the sandbox

`make smolvm-clean` does two things, in this order:

1. It deletes the dangling sandbox machines. Only machines whose names
    match `smolvm-build-*` (a failed or interrupted pack build) or
    `smolvm-run-*` (the older run path) are deleted. The delete runs
    with `--force --cascade`. Machines with every other name stay
    untouched.
2. It removes the `.cache/smolvm/` directory. This removes the
    executable stub and the sidecar `.smolmachine` files.

When `SMOLVM_ADDR` has a value, the target also cleans the server.
It calls `GET /api/v1/machines` and deletes each machine whose name
begins with `smolvm-remote-`. It prints one `deleted=<name>` line per
machine. It does not delete other names. A failed delete prints
`delete_failed=<name>` on stderr and does not stop the run. The client
does not need `jq`. The script parses the JSON with grep and sed. The
token stays out of the output.

The target also removes the remote cache bases it can name. It calls
`DELETE /api/v1/cache-bases/{base}` for the base of the current
repository state and for the base of the default resource values. It
prints one `cache_base_removed=<name>` line per call that succeeds. The
serve API lists no cache bases, so bases of older repository states are
not derivable. Remove those by hand on the server. The seed base always
stays. When the seed name matches a derivable name, the target prints
one `note:` line and never sends the delete.

When `smolvm` is not on `PATH`, the script prints `smolvm=not_found`
and a note that the machine cleanup was skipped. The cache removal
still runs. The exit code is 0. Listing machines reads state. It does
not boot a machine. It is safe on a host with no accelerator.

The script prints one `deleted=<name>` line per deleted machine. It
prints `kept=<N>` with the count of machines with other names. When a
delete fails, it prints `delete_failed=<name>` to stderr and continues
with the next machine. The exit code stays 0. When the cache is
missing, it prints `cache_absent=.cache/smolvm`. When it removed the
cache, it prints `cache_removed=.cache/smolvm`.

The cleanup is idempotent. Run it as often as you want. It never
deletes a machine that has another name. A shared host with other
machines is safe.

## Run a command in the sandbox

`make smolvm-exec` runs one arbitrary command inside the sandbox. The
sandbox shape is the same as the checks: the cached pack (built first
when it is missing, exactly as `scripts/smolvm.sh` builds it), the
repository mounted read-only at `/workspace`, no network on the local
pack path, and a `--timeout` backstop. The cargo-deny advisories check
cannot fetch the RustSec database on this offline path. The timeout
defaults to `10m`. Override it with
`SMOLVM_TIMEOUT`. `SMOLVM_ENABLED=0` and `SMOLVM_GUEST=1` are set for the
command. A `bash scripts/ci.sh` inside it takes the native path.

With `SMOLVM_ADDR` set, the command runs on a remote server. The
remote path prints `exec=<command>` first. It then prints the guest output.
The exit trap deletes the machine. See [Remote mode](#remote-mode).

Give the command as one string in `ARGS`:

```bash
make smolvm-exec ARGS='which mise && mise --version'
```

Or call the script directly:

```bash
scripts/smolvm-exec.sh 'df -h /'
```

The command runs with `bash -lc` with the repository as the working
directory. The command's stdout and stderr are forwarded as-is. The
command's exit code is the exit code of the script.
`make smolvm-exec ARGS='false'` exits non-zero.

There is no host fallback. If `smolvm` is missing or the host
accelerator is unavailable, the script prints the loud warning to
stderr, does not run the command, and exits 1. If `SMOLVM_ADDR` is
set and the server fails, the script prints an error and exits non-zero.
The command is not run on the host under any circumstances. This is on
purpose. A command that must not touch the host never runs by accident.

More examples:

```bash
make smolvm-exec ARGS='df -h /'
make smolvm-exec ARGS='bash scripts/check-shfmt.sh'
make smolvm-exec ARGS='touch /workspace/ISOLATION_PROBE'
```

The last example fails. The mount is read-only.

## Targets

- `make ci` runs the checks. It uses a remote machine when
  `SMOLVM_ADDR` has a value. It uses a local machine when smolvm and
  the accelerator are available. Otherwise it runs on the host with a
  loud warning. With `SMOLVM_ENABLED=1` it exits 3 instead of running the
  checks on the host.
- `make smolvm` runs the checks inside smolvm. It uses the remote path
  when `SMOLVM_ADDR` has a value. Without a usable local setup and
  without a remote address it prints the loud warning in auto mode and
  runs the host checks. With `SMOLVM_ENABLED=1` it prints the error and
  exits 3.
- `make smolvm-pack` builds the cached pack. It exits 0 without
  building when smolvm or the accelerator is missing. It exits non-zero
  when `SMOLVM_ADDR` has a value. Unset the variable first.
- `make smolvm-clean` removes the dangling `smolvm-build-*` and
  `smolvm-run-*` machines. Then it removes `.cache/smolvm/`. With a
  remote address it also deletes `smolvm-remote-*` machines on the
  server. See [Clean the sandbox](#clean-the-sandbox).
- `make smolvm-exec` runs one command inside the sandbox. See
  [Run a command in the sandbox](#run-a-command-in-the-sandbox).
- `make smolvm-preflight` probes the host and prints key=value
  lines. Exits 0 when ready, 1 when blocked.
- `make smolvm-verify` verifies the isolation from inside the guest
  and from the host. Exits 0 when the isolation held, 1 otherwise.
- `make help` lists all targets.

## SMOLVM_ENABLED

`SMOLVM_ENABLED` has three modes:

- `SMOLVM_ENABLED=0` forces the host path. `scripts/ci.sh` skips the
  microVM detection and runs the checks natively. No warning is printed.
  `scripts/smolvm.sh` does the same. The checks never recurse into the
  microVM. This rule also holds in remote mode. The value `0` stops the
  remote call.
- `SMOLVM_ENABLED=1` enforces smolvm. The checks must run in a local
  microVM or on a remote server. When smolvm and the accelerator are
  missing and no remote address exists, the scripts print an error on
  stderr and exit 3. The checks do not run on the host. Install smolvm
  and fix the accelerator. You can also set `SMOLVM_ADDR` for a
  remote run.
- An unset variable or any other value selects auto mode. A remote
  address sends the checks to a server. Without a remote address, smolvm
  with a working accelerator runs the checks in the microVM. Without
  them, the loud warning prints and the checks run on the host.

Run `SMOLVM_ENABLED=0 make ci` to force the host path on a host that
can run the microVM. Run `SMOLVM_ENABLED=1 make ci` to require smolvm.
CI fails with exit code 3 when smolvm cannot run.

The microVM sets `SMOLVM_ENABLED=0` and `SMOLVM_GUEST=1` in the guest
command. `SMOLVM_GUEST=1` marks a process inside the guest. Set these
variables when you debug the guest command. Do not set them on the
host for a normal run.

## Why the pack is built in explicit steps

Provisioning does not use `[dev].init` in the Smolfile. `init` runs
once per machine and its caching rules are not deterministic across
smolvm versions. Each provisioning step runs as a separate
`smolvm machine exec` command. A failed step stops the build with
the exit code of the failing command. The build machine is stopped
and deleted afterwards, even on failure.

## Known limitations and assumptions

These points come from the smolvm documentation and from reading the
CLI reference.

1. The per-run path uses `smolvm machine run --from` with `-v`.
    `machine run` accepts `-v/--volume` and a `[COMMAND]...` argument.
    It is the documented one-shot equivalent of `machine create --from`
    plus `machine start`. Foreground exit-code propagation is the
    documented normal mode. The pack has no
    baked repository. The mount is supplied at run time.
2. `machine create` with a positional `[COMMAND]` sets a persistent
    detached workload. Without a command, the image's ENTRYPOINT/CMD
    runs detached on every start. For packs, the artifact supplies the
    command. `machine run --from` takes the command as an argument, so
    no detached workload is involved.
3. On 2026-11-16 the exit code of `smolvm machine run` in foreground
    mode propagated the guest command exit code on Linux x86_64 with
    KVM. If it does not
    on your version, `make smolvm` needs a check of the guest output
    instead.
4. The `[artifact]` table in `smol/base.smolfile` is documented for
    packs created from a Smolfile. The documentation does not state
    whether it is read for `pack create --from-vm`. The build passes
    `--cpus <cpus> --mem <mem>` as flags as well. The values come from
    `SMOLVM_CPUS` and `SMOLVM_MEMORY_MB`. Both mechanisms cap CPU and
    memory at the same values on purpose. Caps are not reservations.
    Whether the `[artifact]` table is honored for `--from-vm` packs is
    not confirmed.
5. The mise shims are added to `/etc/profile.d/mise.sh` for login
    shells and linked into `/usr/local/bin` for other shells. The
    checks pass inside the guest, so the tools resolve on `bash -lc`,
    which sources `/etc/profile`.
6. `/dev/kvm` exists and is readable is used as the Linux KVM check.
    This does not prove that the kernel allows a VM to start. A host
    in a restricted container can read `/dev/kvm` and still fail to run
    a VM. The loud warning does not cover this case. The preflight
    probe has the same limit.
7. On macOS the detection was extended to `kern.hv_support=1`. The
    macOS path is untested. The v1.24.0 to v1.29.0 `--oci-cache`
    regression (#1819) does not apply to pack `--from` runs.
8. The pack build needs inbound network access to the Debian and
    mise release endpoints. The local pack check runs need no network.
    The cargo-deny advisories check fetches the RustSec database and
    needs network access in remote mode. The guest `apt-get` step is
    noninteractive.
9. The pack may carry `net=true` from the build machine's Smolfile.
    If `make smolvm-verify` prints `inside_network=...actual=REACHED`,
    open an issue. See
    [What a REACHED result means](#what-a-reached-result-means).
10. The `--timeout` backstop kills the guest command after the
    duration. What `machine run` does on a timeout kill is not
    measured.
11. `smolvm machine start` is not documented to block until the
    workload is ready. The build does not rely on `start` returning
    for correctness, but a slow guest can fail the first
    `machine exec` if the agent is not up yet. Retry the build if it
    fails at the first step.

## Git hooks and GitHub Actions

The `pre-commit` and `pre-push` hooks call `scripts/ci.sh` with no
changes. On a host with smolvm and a working accelerator the hooks
now run the checks inside the microVM. This makes each commit build
the pack once on the first run. Later commits reuse
`.cache/smolvm/ci-<key>.smolmachine`.

The GitHub Actions workflow is not changed by this work.
