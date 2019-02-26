# Copyright (c) 2018 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

add_vpp_plugin(nat
  SOURCES
  nat.c
  nat_api.c
  in2out.c
  in2out_ed.c
  out2in.c
  out2in_ed.c
  nat_ipfix_logging.c
  nat_det.c
  nat_det_in2out.c
  nat_det_out2in.c
  nat_reass.c
  nat_dpo.c
  nat44_cli.c
  nat44_handoff.c
  nat44_hairpinning.c
  nat44_classify.c
  nat64.c
  nat64_cli.c
  nat64_in2out.c
  nat64_out2in.c
  nat64_db.c
  dslite_dpo.c
  dslite.c
  dslite_in2out.c
  dslite_out2in.c
  dslite_cli.c
  dslite_ce_encap.c
  dslite_ce_decap.c
  nat66.c
  nat66_cli.c
  nat66_in2out.c
  nat66_out2in.c
  nat_affinity.c
  nat_format.c
  nat_syslog.c
  nat_ha.c

  MULTIARCH_SOURCES
  dslite_ce_decap.c
  dslite_ce_encap.c
  dslite_in2out.c
  dslite_out2in.c
  in2out.c
  in2out_ed.c
  nat44_classify.c
  nat44_hairpinning.c
  nat44_handoff.c
  nat64_in2out.c
  nat64_out2in.c
  nat66_in2out.c
  nat66_out2in.c
  nat_det_in2out.c
  nat_det_out2in.c
  out2in.c
  out2in_ed.c

  API_FILES
  nat.api

  API_TEST_SOURCES
  nat_test.c

  INSTALL_HEADERS
  nat_all_api_h.h
  nat_msg_enum.h
)
