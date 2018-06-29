/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include "vom/l2_xconnect.hpp"
#include "vom/l2_xconnect_cmds.hpp"
#include "vom/singular_db_funcs.hpp"

namespace VOM {
/**
 * A DB of all the L2 x-connect Configs
 */
singular_db<l2_xconnect::key_t, l2_xconnect> l2_xconnect::m_db;

l2_xconnect::event_handler l2_xconnect::m_evh;

/**
 * Construct a new object matching the desried state
 */
l2_xconnect::l2_xconnect(const interface& east_itf, const interface& west_itf)
  : m_east_itf(east_itf.singular())
  , m_west_itf(west_itf.singular())
  , m_xconnect_east(0)
  , m_xconnect_west(0)
{
}

l2_xconnect::l2_xconnect(const l2_xconnect& o)
  : m_east_itf(o.m_east_itf)
  , m_west_itf(o.m_west_itf)
  , m_xconnect_east(o.m_xconnect_east)
  , m_xconnect_west(o.m_xconnect_west)
{
}

const l2_xconnect::key_t
l2_xconnect::key() const
{
  if (m_east_itf->name() < m_west_itf->name())
    return (std::make_pair(m_east_itf->key(), m_west_itf->key()));
  return (std::make_pair(m_west_itf->key(), m_east_itf->key()));
}

bool
l2_xconnect::operator==(const l2_xconnect& l) const
{
  return ((*m_east_itf == *l.m_east_itf) && (*m_west_itf == *l.m_west_itf));
}

std::shared_ptr<l2_xconnect>
l2_xconnect::find(const key_t& key)
{
  return (m_db.find(key));
}

void
l2_xconnect::sweep()
{
  if (m_xconnect_east && m_xconnect_west &&
      handle_t::INVALID != m_east_itf->handle() &&
      handle_t::INVALID != m_west_itf->handle()) {
    HW::enqueue(new l2_xconnect_cmds::unbind_cmd(
      m_xconnect_east, m_east_itf->handle(), m_west_itf->handle()));
    HW::enqueue(new l2_xconnect_cmds::unbind_cmd(
      m_xconnect_west, m_west_itf->handle(), m_east_itf->handle()));
  }

  HW::write();
}

void
l2_xconnect::replay()
{
  if (m_xconnect_east && m_xconnect_west &&
      handle_t::INVALID != m_east_itf->handle() &&
      handle_t::INVALID != m_west_itf->handle()) {
    HW::enqueue(new l2_xconnect_cmds::bind_cmd(
      m_xconnect_east, m_east_itf->handle(), m_west_itf->handle()));
    HW::enqueue(new l2_xconnect_cmds::bind_cmd(
      m_xconnect_west, m_west_itf->handle(), m_east_itf->handle()));
  }
}

l2_xconnect::~l2_xconnect()
{
  sweep();

  // not in the DB anymore.
  m_db.release(key(), this);
}

std::string
l2_xconnect::to_string() const
{
  std::ostringstream s;
  s << "L2-xconnect:[" << m_east_itf->to_string() << " "
    << m_west_itf->to_string() << " " << m_xconnect_east.to_string() << " "
    << m_xconnect_west.to_string() << "]";

  return (s.str());
}

void
l2_xconnect::update(const l2_xconnect& desired)
{
  /*
   * the desired state is always that the interface should be created
   */
  if (rc_t::OK != m_xconnect_east.rc() && rc_t::OK != m_xconnect_west.rc()) {
    HW::enqueue(new l2_xconnect_cmds::bind_cmd(
      m_xconnect_east, m_east_itf->handle(), m_west_itf->handle()));
    HW::enqueue(new l2_xconnect_cmds::bind_cmd(
      m_xconnect_west, m_west_itf->handle(), m_east_itf->handle()));
  }
}

std::shared_ptr<l2_xconnect>
l2_xconnect::find_or_add(const l2_xconnect& temp)
{
  return (m_db.find_or_add(temp.key(), temp));
}

std::shared_ptr<l2_xconnect>
l2_xconnect::singular() const
{
  return find_or_add(*this);
}

void
l2_xconnect::dump(std::ostream& os)
{
  db_dump(m_db, os);
}

l2_xconnect::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "l2-xconnect" }, "L2 xconnects", this);
}

void
l2_xconnect::event_handler::handle_replay()
{
  m_db.replay();
}

void
l2_xconnect::event_handler::handle_populate(const client_db::key_t& key)
{
  /**
   * This needs to be done here
   */
  std::shared_ptr<l2_xconnect_cmds::dump_cmd> cmd =
    std::make_shared<l2_xconnect_cmds::dump_cmd>();

  HW::enqueue(cmd);
  HW::write();

  for (auto& x_record : *cmd) {
    auto& payload = x_record.get_payload();

    VOM_LOG(log_level_t::DEBUG) << "l2-xconnect dump: "
                                << " east-itf: " << payload.rx_sw_if_index
                                << " west-itf: " << payload.tx_sw_if_index;

    std::shared_ptr<interface> east_itf =
      interface::find(payload.rx_sw_if_index);
    std::shared_ptr<interface> west_itf =
      interface::find(payload.tx_sw_if_index);

    if (east_itf && west_itf) {
      if (east_itf->name() > west_itf->name())
        continue;
      l2_xconnect l2_xc(*east_itf, *west_itf);
      OM::commit(key, l2_xc);
    }
  }
}

dependency_t
l2_xconnect::event_handler::order() const
{
  return (dependency_t::BINDING);
}

void
l2_xconnect::event_handler::show(std::ostream& os)
{
  db_dump(m_db, os);
}
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
