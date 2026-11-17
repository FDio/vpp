SPDX-FileCopyrightText: Copyright (c) 2026 Jiajun Liang.
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
  "Copyright (c) 2026 Jiajun Liang." line. Both are licensed under the
  SPDX identifier "Apache-2.0" recorded at the top of each file.
- Files authored entirely in this branch carry only the Jiajun Liang
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
  cookie) and O(1) VLAN dispatch table for exact sub-interfaces plus
  default/wildcard sub-interface support.
- Single-step client creation and option configuration, per-client
  control-history ring with dump API, filtered CLI diagnostics
  (`show pppoe client summary / history / debug`), and orphan-history
  bookkeeping for unmatched discovery packets.
- Configurable rediscovery cooldown and exponential backoff with optional
  jitter for auth-failure-driven restarts.
- pppox integration in a single unified `pppoeclient_plugin.so` module so
  discovery handoff, CHAP/PAP failure propagation, and PPP control-plane
  state are coordinated directly with the trimmed imported pppd sources
  (see `src/plugins/pppoeclient/pppox/pppd/README.import`).

Licensing
The pppoeclient plugin itself is covered by `Apache-2.0`. Unused third-party
files (`ccp.*`, `ecp.*`, `eap.h`, `options.c`, `md5.*`, `slcompress.h`,
`vjcompress.h`, `ppp-comp.h`) were removed. Per-file licensing for the
remaining imported pppd sources under `src/plugins/pppoeclient/pppox/pppd`
is declared in each file via SPDX-License-Identifier headers:
- `Apache-2.0` (`sys-vpp.c`, `sys-vpp.h`)
- `BSD-Attribution-HPND-disclaimer` (`auth.c`, `fsm.c`, `fsm.h`, `if_ppp.h`,
  `ipcp.c`, `ipcp.h`, `ipv6cp.c`, `ipv6cp.h`, `lcp.c`, `lcp.h`, `magic.c`,
  `magic.h`, `pathnames.h`, `pppd.h`, `upap.c`, `upap.h`)
- `Mackerras-3-Clause-acknowledgment` (`auth.c`, `chap-md5.c`, `chap-md5.h`,
  `chap-new.c`, `chap-new.h`, `ppp_defs.h`, `pppio.h`, `utils.c`)
- `Mackerras-3-Clause` (`ppp_defs.h`, `pppio.h`)

Full license texts for these SPDX identifiers are available at
https://spdx.org/licenses/. Verbatim third-party copyright and license
notices from the imported pppd sources follow below so this directory is
self-contained:

---
Carnegie Mellon University (`BSD-Attribution-HPND-disclaimer`):

Copyright (c) 1984-2000 Carnegie Mellon University. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in
   the documentation and/or other materials provided with the
   distribution.

3. The name "Carnegie Mellon University" must not be used to
   endorse or promote products derived from this software without
   prior written permission. For permission or any legal
   details, please contact
     Office of Technology Transfer
     Carnegie Mellon University
     5000 Forbes Avenue
     Pittsburgh, PA  15213-3890
     (412) 268-4387, fax: (412) 268-7395
     tech-transfer@andrew.cmu.edu

4. Redistributions of any form whatsoever must retain the following
   acknowledgment:
   "This product includes software developed by Computing Services
    at Carnegie Mellon University (http://www.cmu.edu/computing/)."

CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

---
Paul Mackerras (`Mackerras-3-Clause-acknowledgment` / `Mackerras-3-Clause`):

Copyright (c) 1984-2003 Paul Mackerras. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in
   the documentation and/or other materials provided with the
   distribution. (Included in Mackerras-3-Clause files such as
   ppp_defs.h and pppio.h.)

3. The name(s) of the authors of this software must not be used to
   endorse or promote products derived from this software without
   prior written permission.

4. Redistributions of any form whatsoever must retain the following
   acknowledgment:
   "This product includes software developed by Paul Mackerras
    <paulus@samba.org>".

THE AUTHORS OF THIS SOFTWARE DISCLAIM ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS, IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

Review expectations
- When changing files carrying the RaydoNetworks copyright line, keep
  the header intact so the lineage stays discoverable.
- Do not strip the "Copyright (c) 2017 RaydoNetworks." line from files
  that still contain substantial upstream structure.
- New files introduced on top of this codebase are free to carry only
  the Jiajun Liang copyright line.
