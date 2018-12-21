/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "vom/gbp_contract_cmds.hpp"
#include "vom/api_types.hpp"

namespace VOM {
namespace gbp_contract_cmds {

create_cmd::create_cmd(HW::item<bool>& item,
                       epg_id_t src_epg_id,
                       epg_id_t dst_epg_id,
                       const handle_t& acl,
                       const gbp_contract::gbp_rules_t& gbp_rules,
                       const gbp_contract::ethertype_set_t& allowed_ethertypes)
  : rpc_cmd(item)
  , m_src_epg_id(src_epg_id)
  , m_dst_epg_id(dst_epg_id)
  , m_acl(acl)
  , m_gbp_rules(gbp_rules)
  , m_allowed_ethertypes(allowed_ethertypes)
{
}

bool
create_cmd::operator==(const create_cmd& other) const
{
  return ((m_acl == other.m_acl) && (m_src_epg_id == other.m_src_epg_id) &&
          (m_dst_epg_id == other.m_dst_epg_id) &&
          (m_gbp_rules == other.m_gbp_rules) &&
          (m_allowed_ethertypes == other.m_allowed_ethertypes));
}

rc_t
create_cmd::issue(connection& con)
{
  size_t n_rules = m_gbp_rules.size();
  size_t n_et_rules = 0;

  msg_t req(con.ctx(), n_rules, n_et_rules, std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_add = 1;
  payload.contract.acl_index = m_acl.value();
  payload.contract.src_epg = m_src_epg_id;
  payload.contract.dst_epg = m_dst_epg_id;

  uint32_t ii = 0;
  payload.contract.n_rules = n_rules;

  for (auto rule : m_gbp_rules) {
    if (rule.action() == gbp_rule::action_t::REDIRECT)
      payload.contract.rules[ii].action = GBP_API_RULE_REDIRECT;
    else if (rule.action() == gbp_rule::action_t::PERMIT)
      payload.contract.rules[ii].action = GBP_API_RULE_PERMIT;
    else
      payload.contract.rules[ii].action = GBP_API_RULE_DENY;

    if (rule.nhs().hash_mode() == gbp_rule::hash_mode_t::SYMMETRIC)
      payload.contract.rules[ii].nh_set.hash_mode = GBP_API_HASH_MODE_SYMMETRIC;
    else if (rule.nhs().hash_mode() == gbp_rule::hash_mode_t::SRC_IP)
      payload.contract.rules[ii].nh_set.hash_mode = GBP_API_HASH_MODE_SRC_IP;
    else
      payload.contract.rules[ii].nh_set.hash_mode = GBP_API_HASH_MODE_DST_IP;

    const gbp_rule::next_hops_t& next_hops = rule.nhs().next_hops();
    uint8_t jj = 0, nh_size = (next_hops.size() > 8) ? 8 : next_hops.size();

    payload.contract.rules[ii].nh_set.n_nhs = nh_size;
    for (auto nh : next_hops) {
      to_api(nh.getIp(), payload.contract.rules[ii].nh_set.nhs[jj].ip);
      to_api(nh.getMac(), payload.contract.rules[ii].nh_set.nhs[jj].mac);
      payload.contract.rules[ii].nh_set.nhs[jj].bd_id = nh.getBdId();
      payload.contract.rules[ii].nh_set.nhs[jj].rd_id = nh.getRdId();
      jj++;
    }
    ++ii;
  }

  u8* data;
  u16* et;

  data = (((u8*)&payload.contract.n_ether_types) +
          (sizeof(payload.contract.rules[0]) * payload.contract.n_rules));
  *data = m_allowed_ethertypes.size();
  et = (u16*)(++data);
  ii = 0;
  for (auto tt : m_allowed_ethertypes) {
    et[ii] = tt.value();
    ii++;
  }

  VAPI_CALL(req.execute());

  return (wait());
}

std::string
create_cmd::to_string() const
{
  std::ostringstream s;
  s << "gbp-contract-create: " << m_hw_item.to_string()
    << " src-epg-id:" << m_src_epg_id << " dst-epg-id:" << m_dst_epg_id
    << " acl:" << m_acl;

  return (s.str());
}

delete_cmd::delete_cmd(HW::item<bool>& item,
                       epg_id_t src_epg_id,
                       epg_id_t dst_epg_id)
  : rpc_cmd(item)
  , m_src_epg_id(src_epg_id)
  , m_dst_epg_id(dst_epg_id)
{
}

bool
delete_cmd::operator==(const delete_cmd& other) const
{
  return ((m_src_epg_id == other.m_src_epg_id) &&
          (m_dst_epg_id == other.m_dst_epg_id));
}

rc_t
delete_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), 0, 0, std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_add = 0;
  payload.contract.acl_index = ~0;
  payload.contract.src_epg = m_src_epg_id;
  payload.contract.dst_epg = m_dst_epg_id;

  VAPI_CALL(req.execute());

  return (wait());
}

std::string
delete_cmd::to_string() const
{
  std::ostringstream s;
  s << "gbp-contract-delete: " << m_hw_item.to_string()
    << " src-epg-id:" << m_src_epg_id << " dst-epg-id:" << m_dst_epg_id;

  return (s.str());
}

bool
dump_cmd::operator==(const dump_cmd& other) const
{
  return (true);
}

rc_t
dump_cmd::issue(connection& con)
{
  m_dump.reset(new msg_t(con.ctx(), std::ref(*this)));

  VAPI_CALL(m_dump->execute());

  wait();

  return rc_t::OK;
}

std::string
dump_cmd::to_string() const
{
  return ("gbp-contract-dump");
}

}; // namespace gbp_contract_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
