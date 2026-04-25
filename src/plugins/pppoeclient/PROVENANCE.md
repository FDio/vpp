SPDX-FileCopyrightText: Copyright (c) 2026 Hi-Jiajun.
SPDX-License-Identifier: Apache-2.0

Origin and lineage
- This plugin (src/plugins/pppoeclient) began as a port of the PPPoE
  client state machine published by RaydoNetworks at
  https://github.com/raydonetworks/vpp-pppoeclient (Apache-2.0).
- The upstream project targeted an older VPP tree. The current sources
  have been adapted for the in-tree VPP plugin interface, reworked for
  the pppox control-plane bridge added in this branch, and extended
  with new CLI / API surface, diagnostics, and regression tests.

Per-file copyright headers
- Files originally derived from RaydoNetworks retain their original
  "Copyright (c) 2017 RaydoNetworks." line alongside the
  "Copyright (c) 2026 Hi-Jiajun." line. Both are licensed under the
  SPDX identifier "Apache-2.0" recorded at the top of each file.
- Files authored entirely in this branch carry only the Hi-Jiajun
  copyright line, still under Apache-2.0.

Similarity snapshot (2026-04-25, coarse text-diff)
- pppoeclient.h : ~0.535 overlap with upstream
- pppoeclient.c : ~0.195
- node.c        : ~0.220
- pppox/pppox.c : ~0.319 (compiled into pppoeclient_plugin.so)
- pppox/node.c  : ~0.539
These are rough byte-overlap measurements, not line-accurate counts.
They are here to document that the lineage is not negligible but also
that core behavior has diverged materially.

Local adaptations (non-exhaustive)
- Full PPPoE discovery state machine (PADI/PADO/PADR/PADS/PADT) with
  Host-Uniq-less fallback matching on (AC MAC, AC-Name, service-name,
  cookie).
- Per-client control-history ring with dump and summary APIs, filtered
  CLI (show pppoe client summary / history / debug), and orphan-history
  bookkeeping for unmatched discovery packets.
- Cool-down and exponential backoff for auth-failure-driven restarts.
- pppox integration so discovery handoff, CHAP/PAP failure propagation,
  and PPP control-plane state are coordinated with the imported pppd
  sources (see src/plugins/pppoeclient/pppox/pppd/README.import).

Licensing
The pppoeclient plugin itself is covered by Apache-2.0. Per-file
licensing for the imported pppd sources under
src/plugins/pppoeclient/pppox/pppd is declared in each source file via
SPDX-License-Identifier headers (Apache-2.0, BSD-4.3TAHOE,
BSD-Attribution-HPND-disclaimer, Mackerras-3-Clause,
Mackerras-3-Clause-acknowledgment, RSA-MD, Sun-PPP). Full license texts
for these SPDX identifiers are available at https://spdx.org/licenses/.

Review expectations
- When changing files carrying the RaydoNetworks copyright line, keep
  the header intact so the lineage stays discoverable.
- Do not strip the "Copyright (c) 2017 RaydoNetworks." line from files
  that still contain substantial upstream structure.
- New files introduced on top of this codebase are free to carry only
  the Hi-Jiajun copyright line.
