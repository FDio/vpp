# AGENTS.md — Working on this VPP tree

This file is for AI coding agents (and humans) who know nothing about this
project. It describes what the repository is, how it is built, how it is
tested, and the conventions that changes are expected to follow.

---

## 1. Project overview

This is **FD.io VPP (Vector Packet Processing)**, the open-source version of
Cisco's VPP technology: a high-performance, production-quality packet
processing stack that runs on commodity CPUs. It is the dataplane framework
behind the FD.io project, licensed under **Apache-2.0**.

VPP processes packets as a **directed graph of forwarding nodes**. Each node
receives a *frame* of buffers (vector) and processes them in a tight loop,
which enables prefetching, pipelining, and SIMD. Multiple worker threads run
replicas of the graph, with ingress-hashed packet steering.

**This checkout is a fork.** The important remotes:

| Remote     | URL                          | Meaning                                  |
| ---------- | ---------------------------- | ---------------------------------------- |
| `origin`   | `git@github.com:sunoaki/vpp.git` | This fork (the one being developed here) |
| `upstream` | `git@github.com:FDio/vpp.git`    | Canonical upstream FD.io VPP             |

- The current branch is `master`.
- `master` is **60 commits ahead of `upstream/master`**. These commits are
  hardening/fix work (see "Fork-specific context" below), not upstream changes.
- Version string comes from `src/scripts/version` / `git describe`; as of this
  writing it is `v26.10-rc0-489-gbc8310875`.
- Project metadata lives in `INFO.yaml`; the project PTL and committer list are
  there and in `MAINTAINERS`.

Upstream project resources (useful when a change may need to go upstream):
Gerrit `gerrit.fd.io` (`project=vpp`, see `.gitreview`), GitHub issues at
`https://github.com/fdio/vpp/issues`, mailing list `vpp-dev@lists.fd.io`.

---

## 2. Repository layout

| Path                 | Contents                                                                 |
| -------------------- | ------------------------------------------------------------------------ |
| `src/vppinfra`       | Core infrastructure library: vectors, pools, hashes/bihash, bitmaps, time, format/unformat, allocators, SIMD helpers |
| `src/svm`            | Shared virtual memory allocation library (used for API shared memory)     |
| `src/vlib`           | Vector processing library: buffer & graph-node management, threads, CLI, counters, tracing, event logger |
| `src/vlibmemory`     | Shared-memory / API memory management (client & server sides)             |
| `src/vlibapi`        | Binary API library                                                       |
| `src/vnet`           | The network stack: L2/L3/L4 nodes, interfaces, FIB, features, sessions    |
| `src/vpp`            | The `vpp` application container (links everything), `vppctl`, `vpe.api`   |
| `src/vpp-api`        | API client bindings: C (`client/`), C++/C (`vapi/`), Python (`python/vpp_papi`), Lua |
| `src/vat`, `src/vat2`| API test programs / vat2 plugin framework                                 |
| `src/vcl`            | VPP Communications Library and LD_PRELOAD shim (`vppcom`, `vcl_ldpreload`) |
| `src/plugins`        | ~99 bundled dataplane plugins (see below)                                 |
| `src/drivers`        | Built-in device drivers (armada, atlantic, iavf, ige, octeon)             |
| `src/crypto_engines` | Crypto backends: `ipsecmb`, `native`, `openssl`                           |
| `src/tools`          | `vppapigen` (API compiler), `g2`, `perftool`, `appimage`                  |
| `src/scripts`        | Version/utility scripts, including `src/scripts/version`                  |
| `src/cmake`          | CMake rule/function definitions and `platform/*.cmake` CPU tuning files   |
| `test`               | Python unit/functional test harness (`VppTestCase`) + `test/asf` + `test/hs-test` |
| `test/hs-test`       | Go/Ginkgo host-stack end-to-end test framework (Docker topologies)        |
| `extras`             | Packaging (`deb`, `rpm`, `snap`), Vagrant, emacs plugin generator, libmemif, config tools, kube-test |
| `docs`               | Sphinx documentation tree (`.rst`/`.md`, symlinks into `src/`)            |
| `build-data`         | Build metadata: `packages/*.mk`, `platforms/*.mk`                         |
| `build-root`         | Build output directory (generated; largely gitignored)                    |
| `build`, `build-data`, `build-root` | See build system section                                  |

`README.md` documents the directory layout in the project's own words.
`MAINTAINERS` is authoritative for who owns a component and for the feature-id
vocabulary used by commit-message checks.

### The plugins directory

`src/plugins` contains ~99 subdirectories, each a shared object
(`<name>_plugin.so`) built from its own `CMakeLists.txt`. There is no central
registration list: `src/plugins/CMakeLists.txt` globs `*/CMakeLists.txt` and
adds each subdirectory, and each plugin calls `add_vpp_plugin(<name> ...)`.
Plugin selection can be constrained at configure time with
`-DVPP_PLUGINS=<comma list>` or `-DVPP_EXCLUDED_PLUGINS=<comma list>`.

Representative plugins: `acl`, `nat`, `ipsec`, `dpdk`, `rdma`, `memif`,
`linux-cp`, `gre`, `quic`, `http_static`, `srv6-*`, `lisp`, `flowprobe`,
`sfdp*`, `lacp`, `bonding`, `pppoe`, `gtpu`, `map`, `nsh`, `vhost`,
`af_packet`, `af_xdp`, `netmap`.

Note that not every protocol/feature is a plugin: `session`, `tls`, `tcp`,
`udp`, `vxlan`, `ipsec`, `fib`, `ip`, `ip6` and others live in `src/vnet`,
while `src/plugins` holds the separately-loadable `.so` modules.

---

## 3. Technology stack

- **Language:** C (C11-style, GNU extensions). Some C++ in `src/vpp-api/vapi`
  (`vapi.hpp`, `vapi_cpp_test.cpp`) and `src/plugins/*/` C++ usages.
- **Test/aux languages:** Python 3 (functional test harness, docs, tooling),
  Go (hs-test, kube-test), shell.
- **Build system:** top-level GNU `Makefile` → `build-root/Makefile` →
  **CMake (>= 3.19) generating Ninja** build files. The legacy autotools-style
  build is gone; `make bootstrap` is a no-op.
- **Compilers:** Clang (preferred/default when `CC=cc`) or GCC, both **>= 9.0.0**.
  The build is compiled with `-Werror` in practice, so warnings are failures.
- **External dependencies:** built into `build/external` (DPDK `26.07`,
  rdma-core `64.0`, ipsec-mb, quicly, libcbor, xdp-tools, daq, octeon-roc).
  `build/optional` holds optional deps. See `build/external/packages/*.mk`.
- **Docs:** Sphinx (`docs/`, `docs/Makefile`, `docs/conf.py`), reStructuredText
  and Markdown, with `sphinxcontrib-spelling`.
- **Multi-architecture:** performance-critical nodes are compiled once per CPU
  variant (e.g. `x86_64_v3`, `avx2`, `avx512`, `neoverse-*`), and the best
  variant is selected at runtime. Platform tuning files live in
  `src/cmake/platform/` (`icelake-server`, `sapphirerapids`, `emeraldrapids`,
  `neoverse-n1/n2/v2`, `octeon9/10`, `cn913x`).

---

## 4. Build system and commands

All commands are run from the repository root. `make` with no target prints
the target list (`make help` is the same).

### One-time setup

```bash
make install-dep            # install distro build dependencies (sudo)
make install-ext-deps       # build/install DPDK, rdma-core, etc. into build/external
make install-opt-deps       # optional dependencies (not always needed)
```

`make install-dep` also runs
`git config commit.template .git_commit_template.txt`.

### Build

```bash
make build                  # debug binaries -> build-root/build-vpp_debug-native
make build-release          # release binaries -> build-root/build-vpp-native
make rebuild                # wipe + build (debug)
make rebuild-release        # wipe + build (release)
make wipe                   # remove debug build products
```

Outputs land in `build-root/`:
`build-vpp-native/` (release), `build-vpp_debug-native/` (debug),
`build-vpp_gcov-native/` (coverage), and matching `install-vpp-*` trees.

### Incremental C compilation (much faster than a full `make build`)

The CMake/Ninja tree is directly usable:

```bash
ninja -C build-root/build-vpp_debug-native/vpp <target>
# e.g. a single plugin:
ninja -C build-root/build-vpp_debug-native/vpp lib/x86_64-linux-gnu/vpp_plugins/gre_plugin.so
```

`make compdb` regenerates `compile_commands.json` at the repo root (used by
clangd/IDEs; gitignored).

### Run / debug the binary

```bash
make run                    # run debug vpp (needs sudo for hugepages/NIC access)
make run-release            # run release vpp
make debug                  # run debug vpp under gdb
make debug-release          # run release vpp under gdb
make run-vat                # run the vpp-api-test tool
```

Useful make arguments: `V=1` (verbose build), `STARTUP_CONF=<path>`,
`STARTUP_DIR=<path>`, `GDB=<path>`, `PLATFORM=<name>`, `DPDK_CONFIG=<...>`
(e.g. `"no-pci"`), `SAMPLE_PLUGIN=yes`, `DISABLED_PLUGINS=<list>`.
`src/vpp/conf/startup.conf` is the reference startup configuration
(`unix`, `api-trace`, `api-segment`, `socksvr`, `cpu`, `dpdk`, ... stanzas).

### Alternative: the `configure` script

`./configure` is an experimental, standalone CMake driver for out-of-tree or
cross builds (`--build-type`, `--platform`, `--arch`, `--plugins`, `--drivers`,
`--crypto-engines`, `--minimal`, `--native-only`, `--sanitize mem`, ...).
Consult its `--help` before changing it; the comment asks to check with the
maintainer first.

### Sanitizers

CMake option `-DVPP_ENABLE_SANITIZE_ADDR=ON` enables AddressSanitizer; the
default ASAN options are set in `src/CMakeLists.txt`. The test harness exports
`ASAN_OPTIONS` from `test/Makefile`.

---

## 5. Code organization and conventions

### Layer boundaries

`vppinfra` → `svm` → `vlib` → `vlibmemory`/`vlibapi` → `vnet` → `vpp`.
Keep dependencies pointing downward. `src/CMakeLists.txt` lists `SUBDIRS` in
that order ("order matters"). Plugins link against the core libraries; core
code must not depend on plugins.

### Plugin structure (the dominant unit of new code)

A plugin directory typically contains:

```
CMakeLists.txt      # add_vpp_plugin(...)
plugin.c            # VLIB_PLUGIN_REGISTER() { .version = VPP_BUILD_VER, .description = ... }
FEATURE.yaml        # machine-readable feature metadata (required, schema-validated)
<name>.api          # binary API definitions (if the plugin has an API)
<name>_api.c        # API message handlers (generated header + manual handlers)
<name>.h            # plugin-internal header
node.c              # graph node dispatch functions
<name>.c            # main/init/CLI
error.def           # error-string definitions, included via foreach_<name>_error
```

Example — `src/plugins/gre/CMakeLists.txt`:

```cmake
add_vpp_plugin(gre
  SOURCES gre.c node.c gre_api.c interface.c pg.c plugin.c
  MULTIARCH_SOURCES node.c gre.c
  INSTALL_HEADERS gre.h error.def
  API_FILES gre.api
)
```

`add_vpp_plugin` (defined in `src/cmake/plugin.cmake`) supports:
`SOURCES`, `MULTIARCH_SOURCES`, `MULTIARCH_FORCE_ON`, `API_FILES`,
`API_TEST_SOURCES`, `VAT_AUTO_TEST`, `INSTALL_HEADERS`, `LINK_LIBRARIES`,
`LINK_FLAGS`, `COMPONENT`, `DEV_COMPONENT`, `SUPPORTED_OS_LIST`.
It installs the plugin to `<libdir>/vpp_plugins` and any API test plugin to
`vpp_api_test_plugins` / `vat2_plugins`.

A generator exists for new plugins:
`cd src/plugins && ../../extras/emacs/make-plugin.sh`. After adding a plugin
directory you generally just rebuild; no other file needs editing (the glob
picks it up). See `docs/developer/plugindoc/add_plugin.rst`.

### Feature metadata (`FEATURE.yaml`)

Every plugin/component should ship a `FEATURE.yaml` (105 exist). It is
validated against a JSON schema by `extras/scripts/fts.py`:

- `name`, `description`, `features` (list), `state` ∈
  {production, experimental, development},
  `properties` ⊆ {API, CLI, STATS, MULTITHREAD}, `maintainer` (string or list).

Validate with `make checkfeaturelist`; dump the list with `make featurelist`.

### Multi-architecture nodes

Follow `docs/developer/corearchitecture/multiarch/nodefns.rst`:

- Declare the node function with `VLIB_NODE_FN (<node_name>)`, and the function
  name **must** match the graph node name.
- Bracket the single copies of `VLIB_REGISTER_NODE`, error strings, and trace
  format functions in `#ifndef CLIB_MARCH_VARIANT ... #endif`.
- **Never** set the `.function` member of `VLIB_REGISTER_NODE`; the multiarch
  constructor selects it at runtime.
- Mark the body inline with `always_inline` (not `static inline`), or the
  compiler will not emit per-variant copies.
- List the file under `MULTIARCH_SOURCES` in `CMakeLists.txt`.

### Binary API (`.api` files)

The API is defined in a custom IDL and compiled by `src/tools/vppapigen`. See
`docs/interfacing/binapi/vpp_api_language.rst`. Key points:

- `option version = "X.Y.Z";` at the top of each `.api` file.
- Request/reply naming conventions: `<name>` / `<name>_reply`;
  dump/detail: `<name>_dump` / `<name>_details`; events: `want_*` +
  `service { rpc ... events ... }`.
- Every request carries `u32 client_index; u32 context;`.
- `autoreply` is shorthand for a reply containing only `retval`.
- API message CRCs are part of the wire contract. `make checkstyle-api`
  (`extras/scripts/crcchecker.py --check-patchset`) rejects incompatible
  changes to APIs with semantic version >= 1.0.0. If an API change is
  intentional, the CRC must be deliberately updated and the change discussed
  (the checker's failure message points at the API change process).
- Generated JSON/header artifacts are produced by
  `make json-api-files`, `make go-api-files`.

### License headers

New files must contain an `SPDX-License-Identifier:` line (checked by
`make checkstyle` for added `*.c`, `*.h`, `*.cmake`, `*.py`, `CMakeLists.txt`).
The tree is migrating from the long Apache-2.0 boilerplate to the short SPDX
form (thousands of files already use `/* SPDX-License-Identifier: Apache-2.0
* Copyright (c) ... */`). New code should use the SPDX form.

### Coding style (C)

- `.clang-format` is authoritative: **GNU base style, tabs (`UseTab: Always`),
  column limit 100, 2-space continuation indent**, `SpaceAfterCStyleCast: true`,
  includes not sorted. Minimum `clang-format` version is 11.
- `.clang-tidy` enables `misc-*`, `bugprone-*` (minus swappable-params and
  reserved-identifier), `performance-*`, `clang-analyzer-*` (minus
  `valist.Uninitialized`).
- `make checkstyle` (via `extras/scripts/checkstyle.sh`) checks the **most
  recent commit** (`CHECKSTYLE_COMMIT=HEAD~N` to override) and fails on:
  trailing whitespace, Emacs indentation-control comments on modified lines,
  missing SPDX in new files, the deprecated
  `fd.io coding-style-patch-verification` footer, and clang-format diffs.
- `make fixstyle` applies clang-format to the current commit's diff.
- The expected clang-format major version is set per OS in the top-level
  `Makefile` (`CLANG_FORMAT_VER`, e.g. 11, 15, 19). A mismatch makes
  `checkstyle` fail with a version error.
- Avoid Emacs indentation-control comments in new or modified code. Note that
  `checkstyle.sh` detects them by grepping added lines for the literal marker,
  so even a comment *quoting* the marker trips the check.

### Python style

Python under `test/` (and repo-wide) is formatted with **black**, target
`py39`: `make checkstyle-python` / `make fixstyle-python`. The test harness
installs its own pinned toolchain in a virtualenv.

### Go style

`test/hs-test` and `extras/kube-test` are checked with `goimports`
(`v0.39.0`): `make checkstyle-go` / `make fixstyle-go`. Go modules are
`fd.io/hs-test` (go 1.26.5) and the kube-test module.

### Commit messages (enforced)

Format is described in `.git_commit_template.txt` and enforced by
`extras/scripts/check_commit_msg.sh` (`make checkstyle-commit`):

- Subject: `<feature-name>: <subject>`, max ~50 chars, lowercase, imperative,
  no trailing period. `feature-name` **must be a feature id present in
  `MAINTAINERS`** (the `I:` lines). Commits spanning multiple components
  should be split.
- Body explains *why*, wrapped ~72 chars, with a `Type:` line whose value is
  one of: `feature`, `fix`, `refactor`, `improvement`, `style`, `docs`,
  `test`, `make`, `ci`.
- Optional `Ticket:`, `Fixes:`, `Change-Id:`, `Signed-off-by:` lines.

Example subject lines from this tree: `linux-cp: drop nexthops on deleted
interfaces`, `fib: guard attached export against bad fib index`,
`build: make deb version vary per commit`.

### Documentation style

Docs live as `.rst`/`.md` next to the code in `src/` (and `test/`, `extras/`)
and are **symlinked** into `docs/`. `extras/scripts/check_documentation.sh`
verifies that every doc file is either linked from `docs/` or listed in
`docs/docsignore`. Build with `make docs`, clean with `make docs-clean`, spell
check with `make docs-spell`; output is `build-root/docs/html/index.html`.

---

## 6. Testing

There are three test systems. "Over 1,000 unit test vectors" are referenced in
`docs/developer/build-run-debug/testing_vpp.rst`.

### 6.1 Python functional tests (`test/`) — the primary harness

Built on Python `unittest` + **Scapy** for packet construction/inspection.

- Base classes: `test/framework.py::VppTestCase` (packet-generator/scapy tests)
  and `test/asfframework.py::VppAsfTestCase` ("A Scapy Free" tests under
  `test/asf/`, which use VPP's own packet generator without Scapy).
- Lifecycle: `setUpClass` → `setUp` → `test_<name>` → `tearDown` →
  `tearDownClass`. Each test class gets its own temporary directory
  (`/tmp/vpp-unittest-<ClassName>-XXXXXX`) and shared-memory prefix, so tests
  are isolated; each directory holds `log.txt`, `pg*_in.pcap`, `pg*_out.pcap`.
- Object model helpers live in `test/vpp_*.py` (e.g. `vpp_gre_interface.py`,
  `vpp_ip_route.py`); assertions use `unittest` assert methods plus
  `self.statistics` counters.
- Dependencies are pinned: `test/requirements.txt` (source) is compiled into
  `test/requirements-3.txt` (hash-pinned lockfile). The venv is created at
  `build-root/test/venv`, using `uv` when available and falling back to
  pip/pip-tools. `test/patches/scapy-<version>/*.patch` are applied to Scapy
  after install.
- Tests can run in parallel; each suite is a forked process.

Commands (run from the repo root):

```bash
make test                        # build vpp + run basic functional tests
make test-debug                  # same, against the debug image
make test-all                    # basic + extended tests (EXTENDED_TESTS=1)
make retest                      # run tests without rebuilding vpp
make TEST=test_gre test          # one file
make TEST=gre test               # 'test_' prefix omitted
make TEST='gre.TestGRE.test_gre' test   # file.class.method, wildcards allowed
make TEST_JOBS=auto test         # parallel processes
make test-list TEST=...          # show which tests the filter selects, no run
make test-help                   # full list of test targets and variables
make test-shell                  # interactive shell with the test env activated
make test-start-vpp-in-gdb       # start a vpp for DEBUG=attach
make test-wipe                   # clean temp files/venvs
```

Important test variables: `V=[0|1|2]` (verbosity), `TEST_JOBS=[n|auto]`,
`MAX_VPP_CPUS`, `FAILFAST`, `TIMEOUT` (default 600s), `RETRIES`, `STEP`,
`SANITY`, `EXTENDED_TESTS`, `VARIANT=<march>` (test a specific multiarch
variant, e.g. `skx`), `RND_SEED`, `CACHE_OUTPUT`, `USE_SMT`, `SKIP_TESTS`,
`DEBUG=<core|gdb|gdbserver|attach>`.

Failed tests are copied to `/tmp/vpp-failed-unittests/` and, in CI, archived.

When adding a test for a feature, look for an existing `test/test_<feature>.py`
and mirror its structure; plugin tests commonly skip themselves when the
plugin is excluded (`config.excluded_plugins`).

### 6.2 Host-stack end-to-end tests (`test/hs-test`) — Go + Ginkgo + Docker

End-to-end tests for the host stack that need multiple VPP instances, network
namespaces, and external tools. Written in Go with Ginkgo; topology is built
with Docker and `ip`. Requires root and a sane `kernel.core_pattern` (no pipe,
otherwise core dumps are not detected). See `test/hs-test/README.rst`.

```bash
make -C test/hs-test build        # build test infra / docker images
make -C test/hs-test test         # run tests
make -C test/hs-test test-debug   # run against debug VPP image
make -C test/hs-test list-tests
make -C test/hs-test test TEST=MyTest
make -C test/hs-test test PARALLEL=4 PERSIST=true V=2
make cleanup-hst                  # remove containers/namespaces from last run
```

Suites are grouped by topology and run in parallel; `RUN_ID` isolates
concurrent runs on one checkout.

### 6.3 C unit tests

- `src/vppinfra/test/test_*.c` are standalone C unit tests, built only when
  `-DVPP_BUILD_VPPINFRA_TESTS=ON`. They are registered via `add_vpp_test` in
  `src/vppinfra/CMakeLists.txt`.
- Individual components have in-tree tests, e.g. `src/vnet/interface_test.c`,
  `src/vpp-api/client/test.c`, and per-plugin API test plugins
  (`API_TEST_SOURCES`).
- `src/tools/vppapigen/test_vppapigen.py` tests the API generator and is run by
  `make verify`.

### 6.4 Coverage and "make verify"

```bash
make test-cov            # gcov build + tests + lcov HTML report
make test-cov-both       # merge Python + Go (hs-test) coverage
make test-cov-build / test-cov-prep / test-cov-post   # phased coverage
make test-cov-hs         # host-stack tests with coverage
make cov-merge           # merge + genhtml the lcov traces
```

Report output: `build-root/test-coverage-merged/html/index.html`. Details in
`docs/developer/build-run-debug/code_coverage.rst`.

`make verify` runs `pkg-verify` (build packages + sample-plugin + libmemif),
then `vppapigen` tests and `make test` — only on Ubuntu 22.04
(`MAKE_VERIFY_GATE_OS`).

### 6.5 CI

CI is GitHub Actions under `.github/workflows/`. This fork keeps exactly two
workflows, both on GitHub-hosted runners:

- `pr-verify.yml` — runs on `pull_request` against `master`. Two jobs:
  - `style` (no build): `make checkfeaturelist`, `make checkstyle` over the
    whole pull request, `make checkstyle-api`, `make checkstyle-python`, and
    `extras/scripts/check_commit_msg.sh` for every non-merge commit in the PR.
  - `build and test`: installs dependencies, builds VPP debug with `-Werror`
    under ccache, derives a focused `TEST=<name>` filter from the changed paths
    (falling back to the `ip4` smoke suite), and runs `make test-debug`.
- `build-deb-trixie.yml` — builds Debian 13 (Trixie) DEB packages on push to
  `master` (and can publish a GitHub Release).

Both jobs run inside a `debian:trixie` container, which matters for the shell:
a container job gets `sh` (dash in this image) for `run:` steps unless the job
sets `defaults: run: shell: bash`, and dash rejects the bash parameter
expansions used by the test-filter step.

The upstream FD.io workflows are **not** present here. They targeted FD.io's
self-hosted Nomad runners and consumed `fdio/*` actions plus AWS secrets, none
of which exist on this fork, so they sat queued forever; they were deleted.
Do not reintroduce a `self-hosted` runner target, an `fdio/` action, or an AWS
secret into a workflow.

The test filter only ever emits a name for which `test/test_<name>.py` exists
exactly, because the runner resolves a bare filter to that file name and
matches it literally — a name with no module selects nothing and fails the job
instead of falling back. For `src/plugins/<pkg>/<sub>/...` the subdirectory is
tried first, so `src/plugins/nat/nat64/nat64_db.c` selects `nat64`.

Reusable composite actions still live in `.github/actions/` (`vpp-build`,
`vpp-make-test`, `vpp-install-deps`, `vpp-install-ext-deps`,
`vpp-docker-runtime-setup`), but the two workflows above do not currently use
them.

Dependabot is configured for `github-actions` only, with PRs disabled
(`open-pull-requests-limit: 0`).

Note that `lsp_diagnostics` and similar tools that resolve paths against their
own working directory cannot see this repository, so compilation and formatting
are verified by CI and by `extras/scripts/checkstyle.sh` run locally with the
pinned `CLANG_FORMAT_VER=19`, which is hunk-scoped.

Run the local equivalents of the CI gates before considering a change done:

```bash
make checkstyle            # C formatting + feature list
make checkstyle-commit     # commit message (feature id + Type:)
make checkstyle-python     # black
make checkstyle-api        # API CRC compatibility
make checkstyle-go         # goimports
make test-checkstyle       # Python + Go test-code style
make docs-spell            # Sphinx spelling
```

---

## 7. Security considerations

The project has an explicit security policy in `SECURITY.md`; the summary below
is not a substitute for reading it.

- **Report vulnerabilities privately** to `security@lists.fd.io`. Do not open a
  public issue for a security bug. The full process is in
  `docs/aboutvpp/security/tsc_vulnerability_management_v2.rst`; past advisories
  are in `docs/aboutvpp/security/security_advisories.rst`.
- **What counts as a security bug:** a bug exploitable through the
  **dataplane** — i.e. triggered by crafted packets arriving on an interface
  and processed by the forwarding graph, with no prior privileged access.
  Examples: a crafted packet that crashes VPP (DoS) or achieves RCE; any
  memory-safety flaw reachable from normal packet processing.
- **What does NOT count:** bugs reachable only through the **binary API** or
  the debug CLI (`vppctl`). Those interfaces are *trusted* — the caller is
  assumed to be in the same administrative trust domain as VPP. Such bugs
  should still be fixed, but through the normal public bug process.
- Concretely for agents: when auditing or modifying dataplane code, treat
  packet-derived lengths/indices/offsets as untrusted and validate them. When a
  crash requires an API/CLI precondition, it is a regular bug, not a CVE.
- The debug CLI (`vppctl`) and the API socket are privileged interfaces:
  `unix { cli-listen /run/vpp/cli.sock ... }` in the startup config controls
  access, and the `api-segment`/`unix` stanzas set the `gid` used to restrict
  socket permissions.
- VPP runs as a privileged process using hugepages and (for DPDK) kernel
  drivers such as `uio_pci_generic`; see `docs/gettingstarted/running/`.

---

## 8. Packaging and deployment

```bash
make pkg-deb          # build DEB packages
make pkg-deb-debug    # debug DEB packages
make pkg-rpm          # build RPM packages (depends on `make dist`)
make pkg-srpm         # source RPM
make pkg-snap         # build SNAP package
make pkg-verify       # full package build: vpp + sample-plugin + libmemif + pkg-$(PKG)
```

- Package flavor is auto-detected from `/etc/os-release`: `deb` (Ubuntu, Debian,
  LinuxMint), `rpm` (RHEL, CentOS, Fedora, openSUSE-Leap, Rocky, AlmaLinux,
  Anolis, Kylin), `pkg` (FreeBSD).
- `make dist` produces `build-root/vpp-<version>.tar.xz`.
- Debian packaging metadata is under `build-root/deb/debian/` and
  `extras/deb/`; RPM under `extras/rpm/`; snap under `extras/snap/`.
- On install, VPP creates a `vpp` user/group, a systemd unit
  (`vpp.service`), hugepage sysctls (`/etc/sysctl.d/80-vpp.conf`), and a
  default `/etc/vpp/startup.conf`. Add users who need `vppctl` to the `vpp`
  group (`usermod -a -G vpp <user>`). See `docs/gettingstarted/running/`.
- `extras/vagrant/build.sh` bootstraps dependencies, builds and installs VPP on
  a Linux host; `extras/vagrant/` has a Vagrant VM for development.
- `extras/vpp_config/` is a Python tool for generating `startup.conf` for a
  given set of NICs; `extras/scripts/` contains operational helpers
  (`pci-nic-bind`, `lsnet`, `vfctl`, `vpp-review`, ...).

Version numbering: `src/scripts/version` derives the version from
`git describe --long --match "v*"`, with fallbacks for repos without tags. In
this fork the deb workflow synthesises versions of the form
`0.0.0-release+<timestamp>~g<sha>` so that rebuilt packages sort strictly above
earlier builds (see commits `7ee6487a3` and `bc8310875`); this matters because
an unchanged version string makes apt skip the new package and can leave
mismatched shared libraries installed.

---

## 9. Fork-specific context (important for this checkout)

The commits on `master` beyond `upstream/master` are largely **defensive
hardening and crash fixes** to dataplane and control-plane paths, plus build/CI
work. Areas touched: `linux-cp` (netlink error recovery, interface liveness
validation), `fib` (bad index guards, attached-export), `gre`, `teib`,
`vlib` buffer/handoff cleanup, `svm` mapping/fifo rollback, `session` fifo
migration, `rdma`, `cnat`, `nat`, `memif`, `flowprobe`, `dpdk` (incl. Huawei
Hi1822/hinic PMD handling), `vhost`, `tls`, `timer`/`tw_timer`, `vapi` message
size bounds, `http`/`http_static` parsing, `iavf` TX placeholders, `sfdp`, and
`.github/workflows` (the unrunnable FD.io workflows removed, a GitHub-hosted
pull-request verification workflow added, Debian 13 DEB build kept).

Practical implications:

- Fixes here often validate indices/handles derived from external input
  (netlink, API, packets) before use. Match that style: prefer explicit
  validation and a graceful skip/drop over dereferencing.
- The tree is kept mergeable with upstream. Prefer minimal, upstreamable
  changes; avoid introducing fork-only abstractions into core code.
- Commit subjects still use upstream feature ids from `MAINTAINERS`, and
  `Type: fix` is used on bug fixes.
- `.omo/` and `.sisyphus/` are **local agent workspace metadata**
  (`run-continuation/`, handoff notes, patches). They are gitignored
  (`.gitignore`: "Agent workspace metadata") and are not part of the product —
  do not treat their contents as project documentation or commit them.
- `.codegraph` is a symlink to a local code-index cache; also not part of the
  project.

---

## 10. Quick reference

```bash
# Build
make install-dep && make install-ext-deps
make build                                   # debug
make build-release                           # release
ninja -C build-root/build-vpp_debug-native/vpp <target>   # incremental

# Run
make run                                     # debug binary
make debug                                   # debug under gdb

# Test
make test                                    # python functional tests
make TEST=gre test                           # filtered
make TEST_JOBS=auto test                     # parallel
make test-all                                # + extended
make -C test/hs-test test                    # host-stack e2e (Go/Ginkgo)
make test-cov                                # coverage report
make test-help                               # all options

# Style / gates
make checkstyle                              # clang-format on last commit
make fixstyle                                # auto-format last commit
make checkstyle-commit                       # commit message
make checkstyle-python                       # black
make checkstyle-api                          # API CRC compatibility
make checkstyle-go                           # goimports
make checkfeaturelist                        # FEATURE.yaml schema

# Docs
make docs                                    # -> build-root/docs/html/index.html
make docs-clean
```

Ground rules for agents working in this tree:

1. Read `MAINTAINERS` for the owning maintainer and the correct feature id
   before writing a commit message.
2. Keep changes scoped to one component per commit (`feature-name:` prefix).
3. New C files get an `SPDX-License-Identifier` header; formatting is
   clang-format with tabs and a 100-column limit.
4. Treat packet-derived data as untrusted; validate indices, lengths, and
   handles before use.
5. Add or extend tests under `test/` (Python) or `test/hs-test` (Go) when
   behavior changes, and run the relevant `make test TEST=...` and style
   gates before finishing.
6. Update `FEATURE.yaml` and the `.api` version/CRC when a plugin's feature set
   or API changes.
