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

#include "vom/gbp_contract.hpp"
#include "vom/gbp_contract_cmds.hpp"
#include "vom/singular_db_funcs.hpp"

namespace VOM {

singular_db<gbp_contract::key_t, gbp_contract> gbp_contract::m_db;

gbp_contract::event_handler gbp_contract::m_evh;

gbp_contract::gbp_contract(epg_id_t src_epg_id,
                           epg_id_t dst_epg_id,
                           const ACL::l3_list& acl)
  : m_hw(false)
  , m_src_epg_id(src_epg_id)
  , m_dst_epg_id(dst_epg_id)
  , m_acl(acl.singular())
{}

gbp_contract::gbp_contract(const gbp_contract& gbpc)
  : m_hw(gbpc.m_hw)
  , m_src_epg_id(gbpc.m_src_epg_id)
  , m_dst_epg_id(gbpc.m_dst_epg_id)
  , m_acl(gbpc.m_acl)
{}

gbp_contract::~gbp_contract()
{
  sweep();

  // not in the DB anymore.
  m_db.release(key(), this);
}

const gbp_contract::key_t
gbp_contract::key() const
{
  return (std::make_pair(m_src_epg_id, m_dst_epg_id));
}

bool
gbp_contract::operator==(const gbp_contract& gbpc) const
{
  return ((key() == gbpc.key()) && (m_acl->handle() == gbpc.m_acl->handle()));
}

void
gbp_contract::sweep()
{
  if (m_hw) {
    HW::enqueue(
      new gbp_contract_cmds::delete_cmd(m_hw, m_src_epg_id, m_dst_epg_id));
  }
  HW::write();
}

void
gbp_contract::replay()
{
  if (m_hw) {
    HW::enqueue(new gbp_contract_cmds::create_cmd(
      m_hw, m_src_epg_id, m_dst_epg_id, m_acl->handle()));
  }
}

std::string
gbp_contract::to_string() const
{
  std::ostringstream s;
  s << "gbp-contract:[{" << m_src_epg_id << ", " << m_dst_epg_id << "}, "
    << m_acl->to_string() << "]";

  return (s.str());
}

void
gbp_contract::set_gbp_rules(gbp_contract::gbp_rules_t& gbp_rules) const
{
  m_gbp_rules = gbp_rules;
}

void
gbp_contract::update(const gbp_contract& r)
{
  /*
   * create the table if it is not yet created
   */
  if (rc_t::OK != m_hw.rc()) {
    HW::enqueue(new gbp_contract_cmds::create_cmd(
      m_hw, m_src_epg_id, m_dst_epg_id, m_acl->handle()));
  }
}

std::shared_ptr<gbp_contract>
gbp_contract::find_or_add(const gbp_contract& temp)
{
  return (m_db.find_or_add(temp.key(), temp));
}

std::shared_ptr<gbp_contract>
gbp_contract::find(const key_t& k)
{
  return (m_db.find(k));
}

std::shared_ptr<gbp_contract>
gbp_contract::singular() const
{
  return find_or_add(*this);
}

void
gbp_contract::dump(std::ostream& os)
{
  db_dump(m_db, os);
}

gbp_contract::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "gbp-contract" }, "GBP Contract", this);
}

void
gbp_contract::event_handler::handle_replay()
{
  m_db.replay();
}

void
gbp_contract::event_handler::handle_populate(const client_db::key_t& key)
{
  std::shared_ptr<gbp_contract_cmds::dump_cmd> cmd =
    std::make_shared<gbp_contract_cmds::dump_cmd>();

  HW::enqueue(cmd);
  HW::write();

  for (auto& record : *cmd) {
    auto& payload = record.get_payload();

    std::shared_ptr<ACL::l3_list> acl =
      ACL::l3_list::find(payload.contract.acl_index);

    if (acl) {
      gbp_contract gbpc(
        payload.contract.src_epg, payload.contract.dst_epg, *acl);
      OM::commit(key, gbpc);

      VOM_LOG(log_level_t::DEBUG) << "read: " << gbpc.to_string();
    }
  }
}

dependency_t
gbp_contract::event_handler::order() const
{
  return (dependency_t::ENTRY);
}

void
gbp_contract::event_handler::show(std::ostream& os)
{
  db_dump(m_db, os);
}

std::ostream&
operator<<(std::ostream& os, const gbp_contract::key_t& key)
{
  os << "{ " << key.first << "," << key.second << "}";

  return (os);
}

} // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
