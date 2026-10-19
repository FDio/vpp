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

## Validation Policy

CI validates; a session on this tree edits. Work here produces a committed,
reviewable diff. Compiling the tree, installing its dependencies, and running its
test suites happen in the pull-request pipeline once the branch is pushed, and a
pipeline run is the evidence for any statement that a change compiles or passes a
suite. Packages are built separately, by a workflow triggered on pushes to `master`
and on manual request.

Work expected inside a session, none of which compiles C:

- Read source, `MAINTAINERS`, `INFO.yaml`, `docs/`, and `.github/workflows/`.
- Edit source and inspect the result with `git diff`, `git diff --stat`, and
  `git show`.
- Run over your own work the checks that need no compiler: `extras/scripts/
  checkstyle.sh` (formatting, trailing whitespace, SPDX header, INDENT-ON/OFF
  over a commit range), `extras/scripts/check_commit_msg.sh`,
  `extras/scripts/fts.py --validate --all`,
  `extras/scripts/crcchecker.py --check-patchset` on a clean tree, which compares
  the latest commit against its parent, and a Python syntax parse such as
  `python3 -c 'import ast,sys; ast.parse(open(sys.argv[1]).read())' <file>`.
- Read the CI configuration to predict which jobs and suites a change triggers.

Steps reserved for CI or a maintainer environment, and left out of a session:

- Compilation of any kind: `make build`, `make build-release`, `make compdb`,
  `ninja -C build-root/...`, `./configure`, and single-file compiler runs such as
  `-fsyntax-only`.
- Dependency installation and environment setup: `make install-dep`,
  `make install-ext-deps`, `make install-opt-deps`, `make test-dep`, and creating
  `build-root/test/venv`.
- Test execution: `make test*` and `make retest*` for the Python functional
  harness, `make -C test/hs-test ...`, `extras/kube-test` targets, the coverage
  targets, and the built `vpp` binary.
- Packaging: `make pkg-*`, `make dist`, `make verify`, and `make pkg-verify`.

A compiler-free check runs in a session once its tools are already installed — the C
style check needs the matching `clang-format-19` and a `clang-format-diff` helper,
and `fts.py` needs PyYAML and `python3-jsonschema` — and waits for the pipeline
otherwise; the documentation build has no pipeline job, so without its toolchain it
is left unrun. Installing a missing tool is itself a pipeline step.

State a change as building or as passing a suite only after the run that covers it —
the pipeline job, or a maintainer's — reports success; until then describe it as
unverified.

### What PR verification runs

`.github/workflows/pr-verify.yml` runs on pull requests to `master`, on
GitHub-hosted Ubuntu runners inside Debian Trixie containers, with Bash as the
container shell, and has two jobs:

- `style` installs the checkstyle dependencies and runs `make checkfeaturelist`,
  `make checkstyle`, `make checkstyle-api`, `make checkstyle-python`, and
  `extras/scripts/check_commit_msg.sh` on every non-merge commit of the pull
  request. It sets `CLANG_FORMAT_VER=19`, matching the value the root Makefile
  selects for Debian 13. `checkstyle-api` runs before the Python check because
  `crcchecker.py` refuses to run against a dirty working tree.
- `build-test` installs the build dependencies, builds debug VPP with ccache, then
  runs `make TEST_JOBS=auto RETRIES=2 TEST="<suite>" test-debug` for up to three
  suites derived from the changed paths, falling back to `ip4` when no suite
  derives. The `vpp-docker-runtime-setup` action remounts `/dev/shm` and sets
  `LOG_DIR=build-root/test-logs`.

PR verification does not cover Go formatting, documentation spelling and rendering,
release builds, coverage, host-stack and Kubernetes suites, or package builds.

## Build Reference

The commands and paths below describe how the tree is built and laid out, and which
of them the pipeline runs. They are reference for editing build files and CMake
declarations, not a procedure to run locally.

Run commands from the repository root unless a command explicitly uses `-C`.
`make` or `make help` lists supported targets. The build requires Bash and uses
Make to invoke CMake with Ninja. CMake requires at least 3.19; the source declares
Clang/GCC 9.0.0 as minimum supported compiler versions and warns about older
compilers. The root Makefile prefers Clang when `CC` is the default `cc`.
Configured build types add `-Werror -Wall`; release uses `-O3`, debug uses `-O0`
and `CLIB_DEBUG`. Full VPP source builds are configured for Linux and FreeBSD;
the Darwin CMake path builds `vppinfra` only.

Build commands (the `build-test` job runs `make install-dep` and `make build`;
the rest are maintainer references):

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
`vpp-native` paths. A configured tree supports a focused incremental build through a
single Ninja target, which a maintainer uses instead of rebuilding the whole tree:

```bash
ninja -C build-root/build-vpp_debug-native/vpp gre_plugin
```

Run/debug targets execute the built binary; they use `sudo -E` by default and
belong to a maintainer with a built image, not to a session on this tree. With no
startup file, the root Makefile supplies an interactive minimal configuration and
defaults DPDK to `no-pci`. Runtime configuration can enable hardware access and
allocate shared memory or hugepages; inspect the reference startup configuration
before changing host networking. `STARTUP_DIR`, `DISABLED_PLUGINS`, `DPDK_CONFIG`,
`PLATFORM`, and `V=1` are supported Make controls.

```bash
make run STARTUP_CONF=/absolute/path/startup.conf
make run-release STARTUP_CONF=/absolute/path/startup.conf
make debug STARTUP_CONF=/absolute/path/startup.conf
```

Pass additional CMake settings using `VPP_EXTRA_CMAKE_ARGS`. For example,
`-DVPP_ENABLE_SANITIZE_ADDR=ON` enables AddressSanitizer. Plugin build selection
uses `VPP_PLUGINS` or `VPP_EXCLUDED_PLUGINS`; runtime disabling uses the startup
`plugins` stanza or `DISABLED_PLUGINS`. The `build-test` job passes
`-DCMAKE_C_COMPILER_LAUNCHER=ccache` and `-DCMAKE_CXX_COMPILER_LAUNCHER=ccache`
through that variable and builds with ccache.

`./configure` is an experimental standalone CMake/Ninja driver for out-of-tree,
minimal, and cross builds. Read its source/help before changing it; its header asks
contributors to consult the maintainer. Its `--wipe` option executes
`git clean -fdx` with only `startup.*` excluded. Build trees are cache and output,
never a source of truth; wipe and rebuild targets remove build and test state.

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
versions and message CRCs are compatibility contracts, and the `style` job runs
`make checkstyle-api` over the change. The same check runs in a session as
`extras/scripts/crcchecker.py --check-patchset`, which reads the `.api` files
without compiling and compares the latest commit against its parent, so commit
before running it and keep the tree clean. Keep feature metadata consistent with
actual capabilities and validate it with `extras/scripts/fts.py --validate --all`.

API JSON and Go binding regeneration writes into the build-root install tree, so it
is a maintainer step like the other non-gated targets: `make json-api-files`,
`make json-api-files-debug`, and `make go-api-files`. Change the inputs those
generators read, and leave the generated trees to them.

## Style and Documentation

- Follow `.clang-format`: GNU base style, tabs, 100-column limit, two-space
  continuation indent, and unsorted includes. The minimum formatter configuration
  version is 11; `CLANG_FORMAT_VER` is selected by the root Makefile for the OS
  (19 for Debian 13). Use the configured formatter, not an arbitrary local major.
- Add SPDX license identifiers to new source/build files. The style checks also
  reject trailing whitespace and added legacy Emacs indentation-control markers.
- Check your own diff before committing: `extras/scripts/checkstyle.sh` reports the
  formatting, whitespace, and SPDX problems the `style` job would report, and
  honors `CHECKSTYLE_COMMIT`, which defaults to the latest commit.
- Python formatting is Black with target `py39`, checked in the `style` job by
  `make checkstyle-python`, which operates through the test virtual environment and
  has no local equivalent without dependency installation.
- Go uses each module's Makefile formatter target; `make checkstyle-go` checks both
  modules but is not part of PR verification. Host-stack tests currently use
  goimports v0.39.0 and kube-test uses v0.35.0. Follow `go.mod` for each module's
  language/toolchain requirements.
- Use a lowercase imperative commit subject `<feature-id>: <subject>` with a
  maximum of 50 characters, and a body explaining why with a `Type:` field. Select
  the identifier from `MAINTAINERS` (`I:` lines) and the type from
  `feature fix refactor improvement style docs test make ci`. Consult
  `.git_commit_template.txt` and run `extras/scripts/check_commit_msg.sh`, which is
  the same script the `style` job runs.

Documentation is reStructuredText and Markdown, including component-local files
linked into `docs`. When adding component documentation, inspect
`extras/scripts/check_documentation.sh` and `docs/docsignore` for inclusion rules.
The Sphinx build (`make docs`, HTML under `build-root/docs/html`, warnings as
errors) and the spelling check (`make docs-spell`) run from a session once the
documentation toolchain is already installed; they write under `build-root/docs`
and PR verification runs neither, so keep documentation edits consistent with the
sources they describe and with neighboring documents.

## Test Suites

The Python functional suites described here run in the pipeline; host-stack,
Kubernetes, coverage, and C tests without a selected Python wrapper are maintainer
steps. The `build-test` job selects suites from changed source paths using the
rules below; confirm the emitted filters before interpreting a pipeline result.

### Python Functional Tests

`test/framework.py` provides `VppTestCase` for packet-generator/Scapy tests;
`test/asfframework.py` provides the Scapy-free base used under `test/asf`.
`test/vpp_*.py` contains API-backed object helpers. Extend the relevant existing
feature suite and preserve plugin exclusion handling.

The `build-test` job invokes the harness with a filter derived from the changed
paths:

```bash
make TEST_JOBS=auto RETRIES=2 TEST='bfd.BFDAPITestCase.test_add_bfd' test-debug
```

Simple filters select exact `test_<name>.py` modules; advanced filters use
`file.class.method` with shell-style wildcards, and comma-separated filters are
supported. For source-derived candidates, `src/plugins/<pkg>/<sub>/...` tries
`<sub>` then `<pkg>`; `src/vnet/<name>/...` uses `<name>`. Hyphens become
underscores, and the exact module must exist under `test/` or `test/asf/`.
Candidates whose exact test module also changed take priority; remaining candidates
follow alphabetically, with duplicates removed and at most three suites selected.
Test-only changes add no candidate. With no source-derived candidate, including
changes confined to `src/vppinfra`, `src/svm`, or `src/vlib`, the job uses `ip4`.
The ASF `fib` suite invokes `test fib`, which runs the C FIB unit tests.

Harness controls such as `TEST_JOBS`, `MAX_VPP_CPUS`, `VPP_WORKER_COUNT`, `USE_SMT`,
`TIMEOUT`, `RETRIES`, `RND_SEED`, `SKIP_TESTS`, `DEBUG`, and `VARIANT` exist for the
pipeline and for a maintainer running the harness directly; a session reading or
editing the suites has no use for them. The harness needs adequate CPUs and shared
memory, manages `build-root/test/venv` itself, installs the API binding editable,
and applies `test/patches/scapy-*` patches. Dependency inputs in
`test/requirements.txt` and the hash-pinned lockfile `test/requirements-3.txt` are
maintained together, and `make test-refresh-deps` regenerates the lockfile from a
maintainer environment. Tests leave temporary logs, packet captures, and failure
artifacts under `/tmp/vpp-unittest-*` and `/tmp/vpp-failed-unittests/`; the run
summary appears in the job console, and `build-root/test-logs` holds only the
runtime-setup log.

### Host-Stack, Kubernetes, and C Tests

Host-stack tests (`test/hs-test`) use Ginkgo/Gomega, Docker containers, and network
namespaces, and require privileged container capabilities, Docker access, and
suitable `kernel.core_pattern` configuration. Read `test/hs-test/README.rst` before
changing them. `RUN_ID` isolates container names and cleanup; `TIMEOUT` is in
minutes there, unlike the Python harness's seconds; `MW_PARALLEL=true` requires
`PARALLEL=auto`. Generated state is under `/tmp/hst` and the suite's `summary`
directory. Maintainer commands, for reference:

```bash
make -C test/hs-test build
make -C test/hs-test TEST=MyTest test-debug
make -C test/hs-test list-tests
make -C test/hs-test RUN_ID=my-run PARALLEL=auto test
make -C test/hs-test RUN_ID=my-run cleanup-hst
```

Kubernetes integration lives separately in `extras/kube-test`; consult its Makefile
and documentation for `test-kind`, `test-kind-debug`, and `test-bm` and the required
cluster setup. These commands change containers, pods, and namespaces, and they run
in a maintainer environment rather than a session.

C/component tests include `src/vppinfra/test`, API client tests, and plugin test
libraries; they need a compiled tree, so they are maintainer steps. Inspect the
owning `CMakeLists.txt` for test selection and options such as
`VPP_BUILD_VPPINFRA_TESTS`. The API compiler has
`src/tools/vppapigen/test_vppapigen.py`, which runs under the test environment.

### Coverage and Package Verification

Coverage targets (`make test-cov`, `make test-cov-hs`, `make test-cov-both`) need a
GCC/gcov build and lcov; merged HTML is under
`build-root/test-coverage-merged/html`. `make verify` performs package verification
first, and its subsequent API-generator and functional-test phase is OS-gated by
`MAKE_VERIFY_GATE_OS`, defaulting to Ubuntu 22.04; a successful invocation on
another OS does not prove those tests ran. Both are maintainer commands.

For checks outside PR verification, report their actual execution status and the
evidence for any result; describe checks that did not run as unverified.

## Packaging and Deployment

Packages are built by `.github/workflows/build-deb-trixie.yml`, which builds Debian
13 packages on pushes to `master` and on manual dispatch, uploads
`build-root/*.deb`, and can publish a prerelease on manual request. The workflow
checks out the triggering commit and supplies a timestamp/commit-count/hash version
when no VPP release tag is reachable; preserve package version ordering when
changing that logic so package managers recognize new builds.

Maintainer package targets, for reference:

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
products; it is broader than any incremental validation.

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
