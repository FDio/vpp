/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include "vom/qos_record.hpp"
#include "vom/api_types.hpp"
#include "vom/qos_record_cmds.hpp"
#include "vom/qos_types_api.hpp"
#include "vom/singular_db_funcs.hpp"

namespace VOM {
namespace QoS {

singular_db<record::key_t, record> record::m_db;

record::event_handler record::m_evh;

record::record(const interface& itf, const source_t& src)
  : m_config(false)
  , m_itf(itf.singular())
  , m_src(src)
{
}

record::record(const record& r)
  : m_config(r.m_config)
  , m_itf(r.m_itf)
  , m_src(r.m_src)
{
}

record::~record()
{
  sweep();
  m_db.release(key(), this);
}

const record::key_t
record::key() const
{
  return (std::make_pair(m_itf->key(), m_src));
}

bool
record::operator==(const record& r) const
{
  return (key() == r.key());
}

void
record::sweep()
{
  if (m_config) {
    HW::enqueue(new record_cmds::delete_cmd(m_config, m_itf->handle(), m_src));
  }
  HW::write();
}

void
record::replay()
{
  if (m_config) {
    HW::enqueue(new record_cmds::create_cmd(m_config, m_itf->handle(), m_src));
  }
}

std::string
record::to_string() const
{
  std::ostringstream s;
  s << "qos-record:[" << m_itf->to_string() << ", src:" << m_src.to_string();

  return (s.str());
}

void
record::update(const record& r)
{
  if (rc_t::OK != m_config.rc()) {
    HW::enqueue(new record_cmds::create_cmd(m_config, m_itf->handle(), m_src));
  }
}

std::shared_ptr<record>
record::find_or_add(const record& temp)
{
  return (m_db.find_or_add(temp.key(), temp));
}

std::shared_ptr<record>
record::find(const key_t& k)
{
  return (m_db.find(k));
}

std::shared_ptr<record>
record::singular() const
{
  return find_or_add(*this);
}

void
record::dump(std::ostream& os)
{
  db_dump(m_db, os);
}

record::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "qos-record" }, "QoS Record", this);
}

void
record::event_handler::handle_replay()
{
  m_db.replay();
}

void
record::event_handler::handle_populate(const client_db::key_t& key)
{
  std::shared_ptr<record_cmds::dump_cmd> cmd =
    std::make_shared<record_cmds::dump_cmd>();

  HW::enqueue(cmd);
  HW::write();

  for (auto& rr : *cmd) {
    auto& payload = rr.get_payload();

    std::shared_ptr<interface> itf =
      interface::find(payload.record.sw_if_index);

    VOM_LOG(log_level_t::DEBUG) << "data: " << payload.record.sw_if_index;

    if (itf) {
      record qr(*itf, from_api(payload.record.input_source));
      OM::commit(key, qr);

      VOM_LOG(log_level_t::DEBUG) << "read: " << qr.to_string();
    } else {
      VOM_LOG(log_level_t::ERROR) << "no interface:"
                                  << payload.record.sw_if_index;
    }
  }
}

dependency_t
record::event_handler::order() const
{
  return (dependency_t::ENTRY);
}

void
record::event_handler::show(std::ostream& os)
{
  db_dump(m_db, os);
}

}; // namespace QoS

std::ostream&
operator<<(std::ostream& os, const QoS::record::key_t& key)
{
  os << key.first << "," << key.second;

  return os;
}

}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
