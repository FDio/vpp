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

#include "vom/qos_map.hpp"
#include "vom/api_types.hpp"
#include "vom/qos_map_cmds.hpp"
#include "vom/qos_types_api.hpp"
#include "vom/singular_db_funcs.hpp"

namespace VOM {
namespace QoS {

singular_db<map::key_t, map> map::m_db;

map::event_handler map::m_evh;

map::map(uint32_t id, const outputs_t& o)
  : m_config(false)
  , m_id(id)
  , m_outputs(o)
{
}

map::map(const map& r)
  : m_config(r.m_config)
  , m_id(r.m_id)
  , m_outputs(r.m_outputs)
{
}

map::~map()
{
  sweep();
  m_db.release(key(), this);
}

const map::key_t
map::key() const
{
  return m_id;
}

const uint32_t
map::id() const
{
  return m_id;
}

bool
map::operator==(const map& m) const
{
  return (key() == m.key() && m_outputs == m.m_outputs);
}

void
map::sweep()
{
  if (m_config) {
    HW::enqueue(new map_cmds::delete_cmd(m_config, m_id));
  }
  HW::write();
}

void
map::replay()
{
  if (m_config) {
    HW::enqueue(new map_cmds::create_cmd(m_config, m_id, m_outputs));
  }
}

std::string
map::to_string() const
{
  std::ostringstream s;
  s << "qos-map:" << (int)m_id;

  return (s.str());
}

void
map::update(const map& m)
{
  m_outputs = m.m_outputs;

  if (rc_t::OK != m_config.rc()) {
    HW::enqueue(new map_cmds::create_cmd(m_config, m_id, m_outputs));
  }
}

std::shared_ptr<map>
map::find_or_add(const map& temp)
{
  return (m_db.find_or_add(temp.key(), temp));
}

std::shared_ptr<map>
map::find(const key_t& k)
{
  return (m_db.find(k));
}

std::shared_ptr<map>
map::singular() const
{
  return find_or_add(*this);
}

void
map::dump(std::ostream& os)
{
  db_dump(m_db, os);
}

map::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "qos-map" }, "QoS Map", this);
}

void
map::event_handler::handle_replay()
{
  m_db.replay();
}

static const map::outputs_t
from_api(vapi_type_qos_egress_map_row rows[4])
{
  map::outputs_t o;

  for (uint32_t ii = 0; ii < 4; ii++) {
    std::copy(std::begin(rows[ii].outputs), std::end(rows[ii].outputs),
              o[ii].begin());
  }

  return o;
}

void
map::event_handler::handle_populate(const client_db::key_t& key)
{
  std::shared_ptr<map_cmds::dump_cmd> cmd =
    std::make_shared<map_cmds::dump_cmd>();

  HW::enqueue(cmd);
  HW::write();

  for (auto& rr : *cmd) {
    auto& payload = rr.get_payload();

    map qr(payload.map.id, from_api(payload.map.rows));
    OM::commit(key, qr);
  }
}

dependency_t
map::event_handler::order() const
{
  return (dependency_t::TABLE);
}

void
map::event_handler::show(std::ostream& os)
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
