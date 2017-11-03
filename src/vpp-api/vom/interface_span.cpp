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

#include "vom/interface_span.hpp"
#include "vom/interface_span_cmds.hpp"

namespace VOM {
/**
 * A DB of all interface_span config
 */
singular_db<interface_span::key_type_t, interface_span> interface_span::m_db;

interface_span::event_handler interface_span::m_evh;

interface_span::interface_span(const interface& itf_from,
                               const interface& itf_to,
                               interface_span::state_t state)
  : m_itf_from(itf_from.singular())
  , m_itf_to(itf_to.singular())
  , m_state(state)
  , m_config(true)
{
}

interface_span::interface_span(const interface_span& o)
  : m_itf_from(o.m_itf_from)
  , m_itf_to(o.m_itf_to)
  , m_state(o.m_state)
  , m_config(o.m_config)
{
}

interface_span::~interface_span()
{
  sweep();

  // not in the DB anymore.
  m_db.release(make_pair(m_itf_from->key(), m_itf_to->key()), this);
}

void
interface_span::sweep()
{
  if (m_config) {
    HW::enqueue(new interface_span_cmds::unconfig_cmd(
      m_config, m_itf_from->handle(), m_itf_to->handle()));
  }
  HW::write();
}

void
interface_span::dump(std::ostream& os)
{
  m_db.dump(os);
}

void
interface_span::replay()
{
  if (m_config) {
    HW::enqueue(new interface_span_cmds::config_cmd(
      m_config, m_itf_from->handle(), m_itf_to->handle(), m_state));
  }
}

std::string
interface_span::to_string() const
{
  std::ostringstream s;
  s << "Itf Span-config:"
    << " itf-from:" << m_itf_from->to_string()
    << " itf-to:" << m_itf_to->to_string() << " state:" << m_state.to_string();

  return (s.str());
}

void
interface_span::update(const interface_span& desired)
{
  if (!m_config) {
    HW::enqueue(new interface_span_cmds::config_cmd(
      m_config, m_itf_from->handle(), m_itf_to->handle(), m_state));
  }
}

std::ostream&
operator<<(std::ostream& os, const interface_span::key_type_t& key)
{
  os << "[" << key.first << ", " << key.second << "]";

  return (os);
}

std::shared_ptr<interface_span>
interface_span::find_or_add(const interface_span& temp)
{
  return (m_db.find_or_add(
    make_pair(temp.m_itf_from->key(), temp.m_itf_to->key()), temp));
}

std::shared_ptr<interface_span>
interface_span::singular() const
{
  return find_or_add(*this);
}

interface_span::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "itf-span" }, "interface span configurations",
                            this);
}

void
interface_span::event_handler::handle_replay()
{
  m_db.replay();
}

void
interface_span::event_handler::handle_populate(const client_db::key_t& key)
{
  std::shared_ptr<interface_span_cmds::dump_cmd> cmd(
    new interface_span_cmds::dump_cmd());

  HW::enqueue(cmd);
  HW::write();

  for (auto& record : *cmd) {
    auto& payload = record.get_payload();

    std::shared_ptr<interface> itf_from =
      interface::find(payload.sw_if_index_from);
    std::shared_ptr<interface> itf_to = interface::find(payload.sw_if_index_to);

    interface_span itf_span(*itf_from, *itf_to,
                            state_t::from_int(payload.state));

    VOM_LOG(log_level_t::DEBUG) << "span-dump: " << itf_from->to_string()
                                << itf_to->to_string()
                                << state_t::from_int(payload.state).to_string();

    /*
 * Write each of the discovered interfaces into the OM,
 * but disable the HW Command q whilst we do, so that no
 * commands are sent to VPP
 */
    OM::commit(key, itf_span);
  }
}

dependency_t
interface_span::event_handler::order() const
{
  return (dependency_t::BINDING);
}

void
interface_span::event_handler::show(std::ostream& os)
{
  m_db.dump(os);
}

const interface_span::state_t interface_span::state_t::DISABLED(0, "disable");
const interface_span::state_t interface_span::state_t::RX_ENABLED(1,
                                                                  "rx-enable");
const interface_span::state_t interface_span::state_t::TX_ENABLED(2,
                                                                  "tx-enable");
const interface_span::state_t interface_span::state_t::TX_RX_ENABLED(
  3,
  "tx-rx-enable");

interface_span::state_t::state_t(int v, const std::string& s)
  : enum_base<interface_span::state_t>(v, s)
{
}

interface_span::state_t
interface_span::state_t::from_int(uint8_t i)
{
  switch (i) {
    case 0:
      return interface_span::state_t::DISABLED;
      break;
    case 1:
      return interface_span::state_t::RX_ENABLED;
      break;
    case 2:
      return interface_span::state_t::TX_ENABLED;
      break;
    case 3:
    default:
      break;
  }

  return interface_span::state_t::TX_RX_ENABLED;
}
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
