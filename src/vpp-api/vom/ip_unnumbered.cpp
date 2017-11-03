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

#include "vom/ip_unnumbered.hpp"
#include "vom/ip_unnumbered_cmds.hpp"

namespace VOM {
/**
 * A DB of all LLDP configs
 */
singular_db<ip_unnumbered::key_t, ip_unnumbered> ip_unnumbered::m_db;

ip_unnumbered::event_handler ip_unnumbered::m_evh;

ip_unnumbered::ip_unnumbered(const interface& itf, const interface& l3_itf)
  : m_itf(itf.singular())
  , m_l3_itf(l3_itf.singular())
{
}

ip_unnumbered::ip_unnumbered(const ip_unnumbered& o)
  : m_itf(o.m_itf)
  , m_l3_itf(o.m_l3_itf)
  , m_config(o.m_config)
{
}

ip_unnumbered::~ip_unnumbered()
{
  sweep();

  // not in the DB anymore.
  m_db.release(m_itf->key(), this);
}

void
ip_unnumbered::sweep()
{
  if (m_config) {
    HW::enqueue(new ip_unnumbered_cmds::unconfig_cmd(m_config, m_itf->handle(),
                                                     m_l3_itf->handle()));
  }
  HW::write();
}

void
ip_unnumbered::dump(std::ostream& os)
{
  m_db.dump(os);
}

void
ip_unnumbered::replay()
{
  if (m_config) {
    HW::enqueue(new ip_unnumbered_cmds::config_cmd(m_config, m_itf->handle(),
                                                   m_l3_itf->handle()));
  }
}

std::string
ip_unnumbered::to_string() const
{
  std::ostringstream s;
  s << "IP Unnumbered-config:"
    << " itf:" << m_itf->to_string() << " l3-itf:" << m_l3_itf->to_string();

  return (s.str());
}

void
ip_unnumbered::update(const ip_unnumbered& desired)
{
  if (!m_config) {
    HW::enqueue(new ip_unnumbered_cmds::config_cmd(m_config, m_itf->handle(),
                                                   m_l3_itf->handle()));
  }
}

std::shared_ptr<ip_unnumbered>
ip_unnumbered::find_or_add(const ip_unnumbered& temp)
{
  return (m_db.find_or_add(temp.m_itf->key(), temp));
}

std::shared_ptr<ip_unnumbered>
ip_unnumbered::singular() const
{
  return find_or_add(*this);
}

ip_unnumbered::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "ip-un" }, "IP unnumbered configurations", this);
}

void
ip_unnumbered::event_handler::handle_replay()
{
  m_db.replay();
}

void
ip_unnumbered::event_handler::handle_populate(const client_db::key_t& key)
{
  // VPP provides no dump for IP unnumbered
}

dependency_t
ip_unnumbered::event_handler::order() const
{
  return (dependency_t::BINDING);
}

void
ip_unnumbered::event_handler::show(std::ostream& os)
{
  m_db.dump(os);
}
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
