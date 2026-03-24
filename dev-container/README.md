# dev-container

Sandboxed CLI development container for `stellar-core` and the planned in-tree
DPOR integration. This mirrors the standalone workflow in `~/code/dpor`:
build an image once, run it against the mounted repo, and do all build/test
work inside the container.

## Why a container?

Coding agents and local shell workflows both run arbitrary commands. The
container limits the blast radius: by default it only sees the mounted project
directory plus the bind-mounted agent state directories (`~/.codex` and,
optionally, `~/.claude`). If something goes wrong, `git checkout` restores the
working tree and nothing outside the mounts is touched.

## Quick start

```bash
# 1. Build the image (once, or after Dockerfile changes)
dev-container/build-image.sh

# 2. Run it from the repo root
dev-container/run-container.sh
```

Inside the container you land in `/home/dev/stellar-core` and can build normally:

```bash
git submodule update --init --recursive
./autogen.sh
./configure --enable-tests
make -j"$(nproc)"
```

For a heavier CI-like pass with temporary PostgreSQL:

```bash
./ci-build.sh --use-temp-db --protocol current
```

Once the DPOR integration lands as `external/dpor`, no special container
handling is needed beyond updating submodules:

```bash
git submodule update --init --recursive external/dpor
```

## What's in the image

| Category | Packages / tooling |
|---|---|
| C++ toolchains | `clang-20`, `gcc-14`, `g++-14`, `clang-format-20`, `clangd-20`, `gdb`, `lldb` |
| Build system | `autoconf`, `automake`, `libtool`, `pkg-config`, `cmake`, `ninja-build`, `make` |
| Static analysis | `ccache`, `bear`, `cppcheck`, `iwyu` |
| Databases / tests | `postgresql`, `libpq-dev`, `sqlite3` |
| PDFs / OCR | `pdftotext`, `pdfinfo`, `pdftoppm` via `poppler-utils`, `qpdf`, `mutool`, `tesseract`, `ocrmypdf`, `pdf-extract` |
| Profiling / tracing | `perf`, `valgrind` (`callgrind`, `massif`), `heaptrack`, `google-pprof`, `strace`, `hyperfine` |
| Rust | repo-pinned root toolchain via `install-rust.sh`, `rustfmt`, `clippy`, `rust-src`, `wasm32-unknown-unknown`, `wasm32v1-none`, `cargo-cache`, `cargo-sweep` |
| AI agents | Claude Code (`@anthropic-ai/claude-code`), Codex CLI (`@openai/codex`) |
| Shell / editor | `bash`, `tmux`, `vim`, `fzf`, `ripgrep`, `fd`, `bat`, `jq`, `rsync` |
| Networking | `curl`, `wget`, `openssh-client` |

The image runs as a non-root `dev` user (UID/GID matched to the host). The
default launcher keeps `no-new-privileges` enabled, so privileged commands such
as `sudo` only work in modes that explicitly drop it, such as `--debug` or
`--debug-full`.

By default the environment uses `clang-20`:

```bash
echo "$CC"   # clang-20
echo "$CXX"  # clang++-20
```

Switch to GCC in the container if you want parity with the other CI lane:

```bash
export CC=gcc
export CXX=g++
./ci-build.sh --use-temp-db --protocol current
```

## Git identity

On startup, `run-container.sh` reads `user.name` and `user.email` from your
host global Git config and applies them inside the container. No other host Git
config is imported.

## Agent login

The launcher bind-mounts `~/.codex` into the container so Codex auth persists
across runs. If you also want Claude Code, pass `--mount-claude-dir` and log in
inside the container:

```bash
codex auth
claude login
```

## Debug modes

For CPU sampling with `perf` and similar profiling tools that need
`perf_event_open` and relaxed seccomp rules:

```bash
dev-container/run-container.sh --profile
```

This adds `CAP_PERFMON`, `CAP_SYS_PTRACE`, and disables seccomp/apparmor
filtering without going fully privileged. It still keeps
`no-new-privileges` enabled.

For GDB, LLDB, `strace`, or sanitizer workflows that need ptrace support:

```bash
dev-container/run-container.sh --debug
```

For fully privileged debugging (ASLR disabled, unrestricted ptrace):

```bash
dev-container/run-container.sh --debug-full
```

The default mode keeps the hardened baseline enabled. `--profile`, `--debug`,
and `--debug-full` are mutually exclusive. If `perf` still reports permission
errors in `--profile`, the host kernel's `perf_event_paranoid` setting is
stricter than the container caps allow; use `--debug-full` or adjust the host
sysctl.

## Profiling workflows

These are the most useful tools for DPOR exploration and state-space profiling
against `stellar-core`:

```bash
# Replace <command> with the DPOR driver or focused stellar-core test you want to study.

# End-to-end CPU sampling with call stacks
perf record --call-graph dwarf -- <command>
perf report

# Repeatable wall-clock benchmarking for regression checks
hyperfine --warmup 1 '<command>'

# Allocation hot spots from graph cloning / execution snapshot churn
heaptrack <command>
heaptrack_print heaptrack.*.gz | less

# Deterministic callgraph and heap-growth views
valgrind --tool=callgrind <command>
callgrind_annotate callgrind.out.* | less
valgrind --tool=massif <command>
ms_print massif.out.* | less
```

`stellar-core` also has existing Tracy instrumentation and helper scripts under
`scripts/README.md`. For instrumented traces, configure with
`--enable-tracy --enable-tracy-capture --enable-tracy-csvexport`, then use the
built `tracy-capture` / `tracy-csvexport` tools from the build tree.

## PDF extraction workflows

The image includes both low-level PDF tools and a single convenience wrapper
for agents:

```bash
# Extract text to stdout, falling back to OCR if the PDF is scanned
pdf-extract docs/software/core-data-flow.pdf | less

# Write extracted text to a file
pdf-extract paper.pdf paper.txt

# Force OCR even if the PDF already has an embedded text layer
pdf-extract --ocr paper.pdf paper-ocr.txt

# Force OCR on a scanned PDF and keep a sidecar text file
ocrmypdf --skip-text --language eng --sidecar paper.txt scan.pdf scan-ocr.pdf

# Inspect metadata or page count
pdfinfo paper.pdf

# Normalize / validate a damaged or odd PDF before extraction
qpdf --check paper.pdf
qpdf --decrypt paper.pdf normalized.pdf
```

`pdf-extract` first tries embedded text with `pdftotext`, falls back to
`mutool` for some PDFs that Poppler handles poorly, and then rasterizes pages
with `pdftoppm` and OCRs them with `tesseract`.

## Hardening

The default container adds a few restrictions on top of standard Docker
isolation:

| Measure | Flag | Effect |
|---|---|---|
| Drop capabilities | `--cap-drop=ALL` | Removes default Linux capabilities |
| No new privileges | `--security-opt=no-new-privileges` | Blocks setuid/setgid escalation |
| PID limit | `--pids-limit=1024` | Prevents runaway process trees |
| Memory limit | `--memory=32g` | Caps memory usage during builds/tests |

`--profile`, `--debug`, and `--debug-full` selectively relax these
restrictions.

## Options

```text
dev-container/run-container.sh [tag] [options] [-- command...]
```

| Option | Description |
|---|---|
| `tag` | Docker image tag (default: `stellar-core-dev`) |
| `--name NAME` | Custom container name (default: `dev-<project>`) |
| `--profile` | Enable `perf`-friendly profiling mode with `CAP_PERFMON` and relaxed seccomp/apparmor |
| `--debug` | Add `SYS_PTRACE` and disable seccomp/apparmor |
| `--debug-full` | Privileged mode with ASLR and ptrace scope disabled |
| `--persist` | Keep the stopped container instead of removing it |
| `--mount-claude-dir` | Bind-mount `~/.claude` into the container |
| `-- command...` | Override the default shell |

If you use `--persist`, reconnect later with `docker start -ai <container>`.

## Rebuilding

```bash
# normal rebuild
dev-container/build-image.sh

# force a full rebuild
dev-container/build-image.sh --no-cache
```

If you use an alternate Ubuntu mirror, set `APT_MIRROR` before building:

```bash
APT_MIRROR=mirror://mirrors.ubuntu.com/mirrors.txt dev-container/build-image.sh
```

## Files

| File | Purpose |
|---|---|
| `Dockerfile` | Image definition |
| `build-image.sh` | Build the image with host UID/GID |
| `run-container.sh` | Launch the container with the repo + agent state mounted |
| `pdf-extract.sh` | Convenience wrapper for PDF text extraction with OCR fallback |
| `perf-wrapper.sh` | Resolves the real installed `perf` binary inside Ubuntu containers |
| `tmux.conf` | tmux defaults (vim keys, OSC52 clipboard, 256-color) |
| `osc52-tmux` | Clipboard helper for tmux over SSH/containers |
| `project-title.sh` | Sets the terminal title to the project name |
