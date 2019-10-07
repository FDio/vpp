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

#include "vom/qos_mark.hpp"
#include "vom/api_types.hpp"
#include "vom/qos_mark_cmds.hpp"
#include "vom/qos_types_api.hpp"
#include "vom/singular_db_funcs.hpp"

namespace VOM {
namespace QoS {

singular_db<mark::key_t, mark> mark::m_db;

mark::event_handler mark::m_evh;

mark::mark(const interface& itf, const map& m, const source_t& src)
  : m_config(false)
  , m_itf(itf.singular())
  , m_map(m.singular())
  , m_src(src)
{
}

mark::mark(const mark& m)
  : m_config(m.m_config)
  , m_itf(m.m_itf)
  , m_map(m.m_map)
  , m_src(m.m_src)
{
}

mark::~mark()
{
  sweep();
  m_db.release(key(), this);
}

const mark::key_t
mark::key() const
{
  return (std::make_pair(m_itf->key(), m_src));
}

bool
mark::operator==(const mark& m) const
{
  return (key() == m.key() && m_map->id() == m.m_map->id());
}

void
mark::sweep()
{
  if (m_config) {
    HW::enqueue(new mark_cmds::delete_cmd(m_config, m_itf->handle(), m_src));
  }
  HW::write();
}

void
mark::replay()
{
  if (m_config) {
    HW::enqueue(
      new mark_cmds::create_cmd(m_config, m_itf->handle(), m_map->id(), m_src));
  }
}

std::string
mark::to_string() const
{
  std::ostringstream s;
  s << "qos-mark:[" << m_itf->to_string() << ", map:" << m_map->id()
    << ", src:" << m_src.to_string();

  return (s.str());
}

void
mark::update(const mark& r)
{
  if (rc_t::OK != m_config.rc()) {
    HW::enqueue(
      new mark_cmds::create_cmd(m_config, m_itf->handle(), m_map->id(), m_src));
  }
}

std::shared_ptr<mark>
mark::find_or_add(const mark& temp)
{
  return (m_db.find_or_add(temp.key(), temp));
}

std::shared_ptr<mark>
mark::find(const key_t& k)
{
  return (m_db.find(k));
}

std::shared_ptr<mark>
mark::singular() const
{
  return find_or_add(*this);
}

void
mark::dump(std::ostream& os)
{
  db_dump(m_db, os);
}

mark::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "qos-mark" }, "QoS Mark", this);
}

void
mark::event_handler::handle_replay()
{
  m_db.replay();
}

void
mark::event_handler::handle_populate(const client_db::key_t& key)
{
  std::shared_ptr<mark_cmds::dump_cmd> cmd =
    std::make_shared<mark_cmds::dump_cmd>();

  HW::enqueue(cmd);
  HW::write();

  for (auto& rr : *cmd) {
    auto& payload = rr.get_payload();

    std::shared_ptr<interface> itf = interface::find(payload.mark.sw_if_index);
    std::shared_ptr<map> map = map::find(payload.mark.map_id);

    VOM_LOG(log_level_t::DEBUG) << "data: " << payload.mark.sw_if_index;

    if (itf && map) {
      mark qm(*itf, *map, from_api(payload.mark.output_source));
      OM::commit(key, qm);

      VOM_LOG(log_level_t::DEBUG) << "read: " << qm.to_string();
    } else {
      VOM_LOG(log_level_t::ERROR)
        << "no interface or map:" << payload.mark.sw_if_index << ", "
        << payload.mark.map_id;
    }
  }
}

dependency_t
mark::event_handler::order() const
{
  return (dependency_t::ENTRY);
}

void
mark::event_handler::show(std::ostream& os)
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
