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

add_vpp_plugin(filter
  SOURCES
  filter_api.c
  filter_buffer.c
  filter_chain.c
  filter_feature.c
  filter_feature_node.c
  filter_hook.c
  filter_list.c
  filter_match.c
  filter_match_all.c
  filter_match_all_node.c
  filter_match_ip.c
  filter_match_ip_node.c
  filter_match_l4.c
  filter_match_l4_node.c
  filter_match_mark.c
  filter_match_mark_node.c
  filter_rule.c
  filter_table.c
  filter_target.c
  filter_target_accept.c
  filter_target_accept_node.c
  filter_target_drop.c
  filter_target_goto.c
  filter_target_goto_node.c
  filter_target_jump.c
  filter_target_jump_node.c
  filter_target_mark.c
  filter_target_mark_node.c
  filter_target_return.c
  filter_target_return_node.c
  filter_target_terminate.c
  filter_target_terminate_node.c
  filter_test.c
  filter_types.c

  API_FILES
  filter.api

  INSTALL_HEADERS
  filter_all_api_h.h
  filter_msg_enum.h
)
