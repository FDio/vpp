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

#include "vom/arp_proxy_binding.hpp"
#include "vom/arp_proxy_binding_cmds.hpp"

namespace VOM {

/**
 * A DB of all ARP proxy bindings configs
 */
singular_db<interface::key_t, arp_proxy_binding> arp_proxy_binding::m_db;

arp_proxy_binding::event_handler arp_proxy_binding::m_evh;

arp_proxy_binding::arp_proxy_binding(const interface& itf,
                                     const arp_proxy_config& proxy_cfg)
  : m_itf(itf.singular())
  , m_arp_proxy_cfg(proxy_cfg.singular())
  , m_binding(true)
{
}

arp_proxy_binding::arp_proxy_binding(const arp_proxy_binding& o)
  : m_itf(o.m_itf)
  , m_arp_proxy_cfg(o.m_arp_proxy_cfg)
  , m_binding(o.m_binding)
{
}

arp_proxy_binding::~arp_proxy_binding()
{
  sweep();

  // not in the DB anymore.
  m_db.release(m_itf->key(), this);
}

void
arp_proxy_binding::sweep()
{
  if (m_binding) {
    HW::enqueue(
      new arp_proxy_binding_cmds::unbind_cmd(m_binding, m_itf->handle()));
  }
  HW::write();
}

void
arp_proxy_binding::dump(std::ostream& os)
{
  m_db.dump(os);
}

void
arp_proxy_binding::replay()
{
  if (m_binding) {
    HW::enqueue(
      new arp_proxy_binding_cmds::bind_cmd(m_binding, m_itf->handle()));
  }
}

std::string
arp_proxy_binding::to_string() const
{
  std::ostringstream s;
  s << "ArpProxy-binding: " << m_itf->to_string();

  return (s.str());
}

void
arp_proxy_binding::update(const arp_proxy_binding& desired)
{
  /*
 * the desired state is always that the interface should be created
 */
  if (!m_binding) {
    HW::enqueue(
      new arp_proxy_binding_cmds::bind_cmd(m_binding, m_itf->handle()));
  }
}

std::shared_ptr<arp_proxy_binding>
arp_proxy_binding::find_or_add(const arp_proxy_binding& temp)
{
  return (m_db.find_or_add(temp.m_itf->key(), temp));
}

std::shared_ptr<arp_proxy_binding>
arp_proxy_binding::singular() const
{
  return find_or_add(*this);
}

arp_proxy_binding::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "arp-proxy" }, "ARP proxy bindings", this);
}

void
arp_proxy_binding::event_handler::handle_replay()
{
  m_db.replay();
}

void
arp_proxy_binding::event_handler::handle_populate(const client_db::key_t& key)
{
  // FIXME
}

dependency_t
arp_proxy_binding::event_handler::order() const
{
  return (dependency_t::BINDING);
}

void
arp_proxy_binding::event_handler::show(std::ostream& os)
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
