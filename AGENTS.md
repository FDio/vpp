# Working on This VPP Tree

## Project Overview

FD.io VPP (Vector Packet Processing) is an Apache-2.0 licensed, extensible
packet-processing framework providing switch/router functionality on commodity
CPUs. Source code and project documentation are primarily English.

The dataplane processes frames of packet buffers through a directed graph of
nodes. `vlib` provides graph dispatch, buffers, threads, CLI, tracing, and counters;
`vnet` implements networking on that framework. There is one main thread and
optional worker threads, with CPU placement configured at startup. Performance
critical node implementations can be compiled for multiple CPU variants; runtime
selection chooses an appropriate implementation.

The runtime is the `vpp` executable plus shared libraries and loadable plugins.
Operators configure it through startup configuration, the CLI (`vppctl`), and the
binary API. API bindings and VCL expose interfaces to external applications.

Use `INFO.yaml` for project contacts and issue tracking, and `MAINTAINERS` for
component owners, file patterns, and commit feature identifiers. Obtain current
branch, remotes, version, and divergence from Git rather than assuming a fixed
checkout state. `src/scripts/version` reads `src/scripts/.version` when present,
otherwise uses `git describe --long --match "v*"`.

## Source and Configuration Map

| Path | Responsibility |
| --- | --- |
| `src/vppinfra` | Core containers, allocation, formatting, hashes, time, and SIMD helpers |
| `src/svm` | Shared virtual memory and FIFO infrastructure |
| `src/vlib` | Packet graph execution, buffer management, threads, CLI, and diagnostics |
| `src/vlibapi`, `src/vlibmemory` | Binary API support and transport/memory infrastructure |
| `src/vnet` | Interfaces, forwarding tables, L2/L3 protocols, sessions, TCP/UDP, and TLS |
| `src/vpp` | Main application, configuration, CLI client, API integration, and statistics |
| `src/plugins` | Loadable features and device integrations, including GRE, VXLAN, NAT, ACL, DPDK, and linux-cp |
| `src/drivers`, `src/crypto_engines` | Device drivers and crypto backends |
| `src/vcl` | VPP Communications Library and preload support |
| `src/vpp-api` | API client libraries and language bindings, including C/C++ and Python |
| `src/vat`, `src/vat2` | API test clients and test plugin infrastructure |
| `src/tools/vppapigen` | Compiler and generators for the binary API language |
| `src/examples` | Example applications and plugins |
| `test` | Python functional harness, helpers, and feature suites |
| `test/hs-test` | Go/Ginkgo host-stack integration tests using Docker |
| `extras/kube-test` | Go/Ginkgo Kubernetes/CalicoVPP test infrastructure |
| `extras` | Packaging, operational scripts, development helpers, and integrations |
| `docs` | Sphinx documentation and generation scripts |
| `build`, `build-data` | Dependency recipes, platform metadata, and build orchestration |
| `build-root` | Build orchestration files plus generated build/install/test/package outputs |

Key configuration files and entry points:

- Root `Makefile`: public build, run, test, style, documentation, and packaging
  targets; distribution-specific dependencies and formatter selection.
- `build-root/Makefile`, `build-data/packages/vpp.mk`, and
  `build-data/platforms/`: build orchestration and CMake invocation.
- `src/CMakeLists.txt`: CMake project, compiler/build options, ordered source
  subdirectories, sanitizer settings, and installation layout.
- `src/cmake/`: plugin/library/API/driver helpers and CPU platform definitions.
- `build/external/packages/` and `build/optional/`: external and optional
  dependency build recipes. Consult recipes for current dependency versions.
- `src/vpp/conf/startup.conf`: reference runtime configuration, including `unix`,
  API tracing, sockets, CPU workers, buffers, DPDK, plugins, and statistics.
- `.clang-format`, `.clang-tidy`: C formatting and static-analysis configuration.
- `test/Makefile`, `test/requirements.txt`, `test/requirements-3.txt`: test
  environment and Python dependency source/hash-pinned lockfile.
- `src/vpp-api/python/pyproject.toml` and `setup.py`: setuptools packaging for
  `vpp_papi`; this is not a root Python application project.
- `test/hs-test/go.mod`, `extras/kube-test/go.mod`: separate Go modules with their
  own Go versions and dependency sets.
- `docs/conf.py`, `docs/Makefile`: Sphinx configuration and documentation build.
- `.github/workflows/`: pull-request verification and Debian package publishing.
- `.git_commit_template.txt`, `MAINTAINERS`, `SECURITY.md`: contribution and
  security rules.

There is no root `package.json`, `Cargo.toml`, or `pyproject.toml`. The main build
is C with GNU extensions; C++ also appears in API clients and some components.
Python, shell, and Go support tooling, tests, and documentation.

## Build and Run

Run commands from the repository root unless a command explicitly uses `-C`.
`make` or `make help` lists supported targets. The build requires Bash and uses
Make to invoke CMake with Ninja. CMake requires at least 3.19; the source declares
Clang/GCC 9.0.0 as minimum supported compiler versions and warns about older
compilers. The root Makefile prefers Clang when `CC` is the default `cc`.
Configured build types add `-Werror -Wall`; release uses `-O3`, debug uses `-O0`
and `CLIB_DEBUG`. Full VPP source builds are configured for Linux and FreeBSD;
the Darwin CMake path builds `vppinfra` only.

```bash
make install-dep              # Installs OS packages with sudo; sets Git commit template
make install-ext-deps         # Builds/installs external dependency package
make install-opt-deps         # Optional dependency package, when needed
make build                    # Debug build and install tree
make build-release            # Release build and install tree
make compdb                   # Generate root compile_commands.json for tooling
```

Debug outputs use `build-root/build-vpp_debug-native/vpp` and
`build-root/install-vpp_debug-native/vpp`; release outputs use the corresponding
`vpp-native` paths. Existing configured trees support focused incremental builds:

```bash
ninja -C build-root/build-vpp_debug-native/vpp gre_plugin
make run STARTUP_CONF=/absolute/path/startup.conf
make run-release STARTUP_CONF=/absolute/path/startup.conf
make debug STARTUP_CONF=/absolute/path/startup.conf
```

Run/debug Make targets use `sudo -E` by default. With no startup file, the root
Makefile supplies an interactive minimal configuration and defaults DPDK to
`no-pci`. Runtime configuration can enable hardware access and allocate shared
memory or hugepages; inspect the reference startup configuration before changing
host networking. `STARTUP_DIR`, `DISABLED_PLUGINS`, `DPDK_CONFIG`, `PLATFORM`, and
`V=1` are supported Make controls.

Pass additional CMake settings using `VPP_EXTRA_CMAKE_ARGS`. For example,
`-DVPP_ENABLE_SANITIZE_ADDR=ON` enables AddressSanitizer. Plugin build selection
uses `VPP_PLUGINS` or `VPP_EXCLUDED_PLUGINS`; runtime disabling uses the startup
`plugins` stanza or `DISABLED_PLUGINS`.

`./configure` is an experimental standalone CMake/Ninja driver for out-of-tree,
minimal, and cross builds. Read its source/help before using it; its header asks
contributors to consult the maintainer before changing it. Its `--wipe` option
executes `git clean -fdx` with only `startup.*` excluded. Use existing incremental
build trees for normal edits; wipe/rebuild targets remove build and test state.

## Component Development

`src/CMakeLists.txt` builds foundational libraries before networking, application,
and plugin code. Keep core dependencies independent of plugins. Use the existing
component's CMake helper and neighboring code as the implementation pattern.

Plugins are discovered through `src/plugins/CMakeLists.txt` and declare targets
with `add_vpp_plugin` from `src/cmake/plugin.cmake`. A plugin commonly has source
and header files, `plugin.c` registration, `FEATURE.yaml`, optional `.api` files,
API handlers, graph nodes, and error definitions. `src/plugins/gre/CMakeLists.txt`
is a compact example of `SOURCES`, `MULTIARCH_SOURCES`, `INSTALL_HEADERS`, and
`API_FILES`. Plugin libraries are installed under the configured library directory
in `vpp_plugins`.

For multiarch node changes, read
`docs/developer/corearchitecture/multiarch/nodefns.rst`. Use `VLIB_NODE_FN`, keep
single-copy registration/formatting data behind `#ifndef CLIB_MARCH_VARIANT`,
leave registration `.function` assignment to runtime selection, and use
`always_inline` for inline dispatch bodies. Multiarch files belong in both the
component sources and `MULTIARCH_SOURCES`.

For binary API changes, read
`docs/interfacing/binapi/vpp_api_language.rst` and the neighboring `.api` files.
Edit API definitions and generators rather than generated headers. Semantic
versions and message CRCs are compatibility contracts; `make checkstyle-api`
checks incompatible changes. `make json-api-files`, `make json-api-files-debug`,
and `make go-api-files` provide generation entry points. Keep feature metadata
consistent with actual capabilities and validate it with `make checkfeaturelist`.

## Style and Documentation

- Follow `.clang-format`: GNU base style, tabs, 100-column limit, two-space
  continuation indent, and unsorted includes. The minimum formatter configuration
  version is 11; `CLANG_FORMAT_VER` is selected by the root Makefile for the OS
  (19 for Debian 13). Use the configured formatter, not an arbitrary local major.
- Add SPDX license identifiers to new source/build files. The style script also
  rejects trailing whitespace and added legacy Emacs indentation-control markers.
- `make checkstyle` includes feature validation and invokes
  `extras/scripts/checkstyle.sh`; the default comparison is the latest commit,
  with `CHECKSTYLE_COMMIT` available to select a different comparison. Inspect
  the script when checking uncommitted work so the intended diff is covered.
- Python uses Black with target `py39`: `make checkstyle-python` and
  `make fixstyle-python`. These operate through the test virtual environment.
- Go uses each module's Makefile formatter target. `make checkstyle-go` checks
  both modules; host-stack tests currently use goimports v0.39.0 and kube-test
  uses v0.35.0. Follow `go.mod` for each module's language/toolchain requirements.
- Use a lowercase imperative commit subject `<feature-id>: <subject>` with a
  maximum of 50 characters, and a body explaining why with a `Type:` field.
  Select the identifier from `MAINTAINERS`; consult `.git_commit_template.txt`
  and run `make checkstyle-commit` for commit validation.

Documentation is reStructuredText and Markdown, including component-local files
linked into `docs`. When adding component documentation, inspect
`extras/scripts/check_documentation.sh` and `docs/docsignore` for inclusion rules.
`make docs` builds HTML in `build-root/docs/html`; `make docs-spell` checks
spelling. The Sphinx build uses warnings-as-errors. Update affected documentation
and feature metadata when behavior changes.

## Testing and Verification

### Python Functional Tests

`test/framework.py` provides `VppTestCase` for packet-generator/Scapy tests;
`test/asfframework.py` provides the Scapy-free base used under `test/asf`.
`test/vpp_*.py` contains API-backed object helpers. Extend the relevant existing
feature suite and preserve plugin exclusion handling.

```bash
make TEST=gre test-debug                    # Builds and tests the debug image
make TEST=gre test                          # Builds and tests the release image
make TEST=gre retest-debug                  # Uses existing debug build
make TEST='bfd.BFDAPITestCase.test_add_bfd' test-debug
make TEST_JOBS=auto test-debug
make test-all                              # Includes extended tests
make TEST=gre test-list                     # Lists selection; may build/setup dependencies
make test-help                             # All filters and environment controls
```

Simple filters select exact `test_<name>.py` modules; advanced filters use
`file.class.method` with shell-style wildcards, and comma-separated filters are
supported. Confirm selection before interpreting an empty run as success.

The harness manages `build-root/test/venv`, preferring `uv` when available and
otherwise using pip/pip-tools. It installs the API binding editable and applies
`test/patches/scapy-*` patches. Dependency inputs and the hash-pinned lockfile
must be maintained together; `make test-refresh-deps` regenerates dependencies.

Useful controls include `TEST_JOBS`, `MAX_VPP_CPUS`, `VPP_WORKER_COUNT`,
`USE_SMT`, `TIMEOUT`, `RETRIES`, `RND_SEED`, `SKIP_TESTS`, `DEBUG`, and `VARIANT`.
The harness needs adequate CPUs and shared memory. Tests leave temporary logs,
packet captures, and failure artifacts under `/tmp/vpp-unittest-*` and
`/tmp/vpp-failed-unittests/`. Test setup/reset targets remove prior harness state;
retain needed failure evidence before another run.

### Host-Stack, Kubernetes, and C Tests

```bash
make -C test/hs-test build
make -C test/hs-test TEST=MyTest test-debug
make -C test/hs-test list-tests
make -C test/hs-test RUN_ID=my-run PARALLEL=auto test
make -C test/hs-test RUN_ID=my-run cleanup-hst
```

Host-stack tests use Ginkgo/Gomega, Docker containers, and network namespaces.
They require privileged container capabilities, Docker access, and suitable
`kernel.core_pattern` configuration. Read `test/hs-test/README.rst` before
running them. `RUN_ID` isolates container names and cleanup; `TIMEOUT` here is in
minutes, unlike the Python harness's seconds. `MW_PARALLEL=true` requires
`PARALLEL=auto`. Logs and generated state are under `/tmp/hst` and the suite's
`summary` directory.

Kubernetes integration lives separately in `extras/kube-test`; consult its
Makefile and documentation for `test-kind`, `test-kind-debug`, and `test-bm` and
required cluster setup. These commands can change containers, pods, and namespaces.

C/component tests include `src/vppinfra/test`, API client tests, and plugin test
libraries. Inspect the owning `CMakeLists.txt` for test selection and options such
as `VPP_BUILD_VPPINFRA_TESTS`. The API compiler has
`src/tools/vppapigen/test_vppapigen.py`.

Coverage targets include `make test-cov`, `make test-cov-hs`, and
`make test-cov-both`; merged HTML is under
`build-root/test-coverage-merged/html`. Coverage uses GCC/gcov and lcov.
`make verify` performs package verification first; its subsequent API-generator
and functional-test phase is OS-gated by `MAKE_VERIFY_GATE_OS`, defaulting to
Ubuntu 22.04. A successful invocation on another OS does not prove those tests ran.

### CI Gates

`.github/workflows/pr-verify.yml` runs on pull requests to `master`, on
GitHub-hosted Ubuntu runners inside Debian Trixie containers. The style job checks
feature metadata, C style, API compatibility, Python style, and author commit
messages. The build job builds debug VPP with ccache and runs focused Python
suites inferred from changed paths, falling back to `ip4`. It uses the local
`vpp-docker-runtime-setup` action and provisions shared memory for the harness.
The jobs explicitly use Bash for container scripts.

Run focused tests and relevant style checks for the changed component. API
compatibility checks require a clean tracked worktree. Root `make checkstyle-all`
combines commit, C, Python, spelling, and Go checks; API checking is a separate
target. Record the commands actually executed and any skipped or blocked checks.

## Packaging and Deployment

```bash
make pkg-deb                  # Release Debian packages in build-root
make pkg-deb-debug            # Debug Debian packages
make pkg-rpm                  # RPM packages; creates source archive first
make pkg-srpm                 # Source RPM
make pkg-snap                 # Snap build
make dist                     # Source archive under build-root
```

Packaging rules are in `src/pkg`, `extras/deb`, `extras/rpm`, and `extras/snap`.
`make pkg-verify` also builds the sample plugin and libmemif and wipes build
products; it is broader than an incremental validation command.

`.github/workflows/build-deb-trixie.yml` builds Debian 13 packages on pushes to
`master` and manual dispatch. It uploads `build-root/*.deb` and can publish a
prerelease on manual request. The workflow checks out the triggering commit and
supplies a timestamp/commit-count/hash version when no VPP release tag is
reachable. Preserve package version ordering when changing this logic so package
managers recognize new builds.

The runtime configuration reference is `src/vpp/conf/startup.conf`; packaged
installations use `/etc/vpp/startup.conf`. Consult packaging files and
`docs/gettingstarted/running` before altering service setup, user/group access,
hugepage configuration, or device bindings. `extras/vagrant/build.sh` is a
build-and-install helper with host-level effects, not a read-only project check.

## Security and Workspace Boundaries

Follow `SECURITY.md`: report packet-triggered vulnerabilities privately to
`security@lists.fd.io`. Dataplane memory-safety bugs reachable through crafted
network packets without privileged access fall within that policy. Binary API
and CLI callers are trusted operators; bugs requiring that access follow the
normal bug process under the current policy.

Validate packet-derived lengths, offsets, and indices before dereferencing or
copying. Preserve socket permissions and configured group access for CLI/API
interfaces. Inspect startup, test, and deployment commands before actions that
change host networking or require elevated privileges.

Generated build trees, install trees, virtual environments, API artifacts, caches,
and test logs are not substitutes for source changes. `.omo/` and `.sisyphus/`
are ignored local agent metadata; `.codegraph` is local indexing support. Keep
product documentation and patches independent of these local workspaces.
