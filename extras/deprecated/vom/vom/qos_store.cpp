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

#include "vom/qos_store.hpp"
#include "vom/api_types.hpp"
#include "vom/qos_store_cmds.hpp"
#include "vom/qos_types_api.hpp"
#include "vom/singular_db_funcs.hpp"

namespace VOM {
namespace QoS {

singular_db<store::key_t, store> store::m_db;

store::event_handler store::m_evh;

store::store(const interface& itf, const source_t& src, bits_t value)
  : m_config(false)
  , m_itf(itf.singular())
  , m_src(src)
  , m_value(value)
{
}

store::store(const store& s)
  : m_config(s.m_config)
  , m_itf(s.m_itf)
  , m_src(s.m_src)
  , m_value(s.m_value)
{
}

store::~store()
{
  sweep();
  m_db.release(key(), this);
}

const store::key_t
store::key() const
{
  return (std::make_pair(m_itf->key(), m_src));
}

bool
store::operator==(const store& r) const
{
  return (key() == r.key());
}

void
store::sweep()
{
  if (m_config) {
    HW::enqueue(new store_cmds::delete_cmd(m_config, m_itf->handle(), m_src));
  }
  HW::write();
}

void
store::replay()
{
  if (m_config) {
    HW::enqueue(
      new store_cmds::create_cmd(m_config, m_itf->handle(), m_src, m_value));
  }
}

std::string
store::to_string() const
{
  std::ostringstream s;
  s << "qos-store:[" << m_itf->to_string() << ", src:" << m_src.to_string()
    << ", value:" << static_cast<int>(m_value);

  return (s.str());
}

void
store::update(const store& r)
{
  if (rc_t::OK != m_config.rc()) {
    HW::enqueue(
      new store_cmds::create_cmd(m_config, m_itf->handle(), m_src, m_value));
  }
}

std::shared_ptr<store>
store::find_or_add(const store& temp)
{
  return (m_db.find_or_add(temp.key(), temp));
}

std::shared_ptr<store>
store::find(const key_t& k)
{
  return (m_db.find(k));
}

std::shared_ptr<store>
store::singular() const
{
  return find_or_add(*this);
}

void
store::dump(std::ostream& os)
{
  db_dump(m_db, os);
}

store::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "qos-store" }, "QoS Store", this);
}

void
store::event_handler::handle_replay()
{
  m_db.replay();
}

void
store::event_handler::handle_populate(const client_db::key_t& key)
{
  std::shared_ptr<store_cmds::dump_cmd> cmd =
    std::make_shared<store_cmds::dump_cmd>();

  HW::enqueue(cmd);
  HW::write();

  for (auto& rr : *cmd) {
    auto& payload = rr.get_payload();

    std::shared_ptr<interface> itf = interface::find(payload.store.sw_if_index);

    VOM_LOG(log_level_t::DEBUG) << "data: " << payload.store.sw_if_index;

    if (itf) {
      store qr(*itf, from_api(payload.store.input_source), payload.store.value);
      OM::commit(key, qr);

      VOM_LOG(log_level_t::DEBUG) << "read: " << qr.to_string();
    } else {
      VOM_LOG(log_level_t::ERROR) << "no interface:"
                                  << payload.store.sw_if_index;
    }
  }
}

dependency_t
store::event_handler::order() const
{
  return (dependency_t::ENTRY);
}

void
store::event_handler::show(std::ostream& os)
{
  db_dump(m_db, os);
}

}; // namespace QoS

}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
