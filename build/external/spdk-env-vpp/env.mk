# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cisco and/or its affiliates.

# SPDK's libraries are built independently of their environment implementation.
# The VPP plugin supplies the spdk_env_* symbols when the final shared object is
# linked, so the external SPDK build has no DPDK dependency.
ENV_CFLAGS =
ENV_CXXFLAGS =
ENV_LIBS =
ENV_LINKER_ARGS =
ENV_DEPLIBS =
