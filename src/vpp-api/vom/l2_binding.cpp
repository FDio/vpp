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

#include "vom/l2_binding.hpp"
#include "vom/l2_binding_cmds.hpp"

namespace VOM {
/**
 * A DB of all the L2 Configs
 */
singular_db<l2_binding::key_t, l2_binding> l2_binding::m_db;

l2_binding::event_handler l2_binding::m_evh;

/*
 * Make sure these are in sync with the smae enum in VPP
 */
const l2_binding::l2_vtr_op_t l2_binding::l2_vtr_op_t::L2_VTR_DISABLED(
  0,
  "disabled");
const l2_binding::l2_vtr_op_t l2_binding::l2_vtr_op_t::L2_VTR_PUSH_1(1,
                                                                     "push-1");
const l2_binding::l2_vtr_op_t l2_binding::l2_vtr_op_t::L2_VTR_PUSH_2(2,
                                                                     "push-2");
const l2_binding::l2_vtr_op_t l2_binding::l2_vtr_op_t::L2_VTR_POP_1(3, "pop-1");
const l2_binding::l2_vtr_op_t l2_binding::l2_vtr_op_t::L2_VTR_POP_2(4, "pop-2");
const l2_binding::l2_vtr_op_t l2_binding::l2_vtr_op_t::L2_VTR_TRANSLATE_1_1(
  5,
  "translate-1-1");
const l2_binding::l2_vtr_op_t l2_binding::l2_vtr_op_t::L2_VTR_TRANSLATE_1_2(
  6,
  "translate-1-2");
const l2_binding::l2_vtr_op_t l2_binding::l2_vtr_op_t::L2_VTR_TRANSLATE_2_1(
  7,
  "translate-2-1");
const l2_binding::l2_vtr_op_t l2_binding::l2_vtr_op_t::L2_VTR_TRANSLATE_2_2(
  5,
  "translate-2-2");

l2_binding::l2_vtr_op_t::l2_vtr_op_t(int v, const std::string s)
  : enum_base<l2_binding::l2_vtr_op_t>(v, s)
{
}

/**
 * Construct a new object matching the desried state
 */
l2_binding::l2_binding(const interface& itf, const bridge_domain& bd)
  : m_itf(itf.singular())
  , m_bd(bd.singular())
  , m_binding(0)
  , m_vtr_op(l2_vtr_op_t::L2_VTR_DISABLED, rc_t::UNSET)
  , m_vtr_op_tag(0)
{
}

l2_binding::l2_binding(const l2_binding& o)
  : m_itf(o.m_itf)
  , m_bd(o.m_bd)
  , m_binding(0)
  , m_vtr_op(o.m_vtr_op)
  , m_vtr_op_tag(o.m_vtr_op_tag)
{
}

const l2_binding::key_t&
l2_binding::key() const
{
  return (m_itf->key());
}

bool
l2_binding::operator==(const l2_binding& l) const
{
  return ((*m_itf == *l.m_itf) && (*m_bd == *l.m_bd));
}

std::shared_ptr<l2_binding>
l2_binding::find(const key_t& key)
{
  return (m_db.find(key));
}

void
l2_binding::sweep()
{
  if (m_binding && handle_t::INVALID != m_itf->handle()) {
    HW::enqueue(
      new l2_binding_cmds::unbind_cmd(m_binding, m_itf->handle(), m_bd->id(),
                                      interface::type_t::BVI == m_itf->type()));
  }

  // no need to undo the VTR operation.
  HW::write();
}

void
l2_binding::replay()
{
  if (m_binding && handle_t::INVALID != m_itf->handle()) {
    HW::enqueue(
      new l2_binding_cmds::bind_cmd(m_binding, m_itf->handle(), m_bd->id(),
                                    interface::type_t::BVI == m_itf->type()));
  }

  if (m_vtr_op && handle_t::INVALID != m_itf->handle()) {
    HW::enqueue(new l2_binding_cmds::set_vtr_op_cmd(m_vtr_op, m_itf->handle(),
                                                    m_vtr_op_tag));
  }
}

l2_binding::~l2_binding()
{
  sweep();

  // not in the DB anymore.
  m_db.release(m_itf->key(), this);
}

std::string
l2_binding::to_string() const
{
  std::ostringstream s;
  s << "L2-binding:[" << m_itf->to_string() << " " << m_bd->to_string() << " "
    << m_binding.to_string() << "]";

  return (s.str());
}

void
l2_binding::set(const l2_vtr_op_t& op, uint16_t tag)
{
  assert(rc_t::UNSET == m_vtr_op.rc());
  m_vtr_op.set(rc_t::NOOP);
  m_vtr_op.update(op);
  m_vtr_op_tag = tag;
}

void
l2_binding::update(const l2_binding& desired)
{
  /*
   * the desired state is always that the interface should be created
   */
  if (rc_t::OK != m_binding.rc()) {
    HW::enqueue(
      new l2_binding_cmds::bind_cmd(m_binding, m_itf->handle(), m_bd->id(),
                                    interface::type_t::BVI == m_itf->type()));
  } else if (!(*m_bd == *desired.m_bd)) {
    /*
     * re-binding to a different BD. do unbind, bind.
     */
    HW::enqueue(
      new l2_binding_cmds::unbind_cmd(m_binding, m_itf->handle(), m_bd->id(),
                                      interface::type_t::BVI == m_itf->type()));
    m_bd = desired.m_bd;
    HW::enqueue(
      new l2_binding_cmds::bind_cmd(m_binding, m_itf->handle(), m_bd->id(),
                                    interface::type_t::BVI == m_itf->type()));
  }

  /*
   * set the VTR operation if request
   */
  if (m_vtr_op.update(desired.m_vtr_op)) {
    HW::enqueue(new l2_binding_cmds::set_vtr_op_cmd(m_vtr_op, m_itf->handle(),
                                                    m_vtr_op_tag));
  }
}

std::shared_ptr<l2_binding>
l2_binding::find_or_add(const l2_binding& temp)
{
  return (m_db.find_or_add(temp.m_itf->key(), temp));
}

std::shared_ptr<l2_binding>
l2_binding::singular() const
{
  return find_or_add(*this);
}

void
l2_binding::dump(std::ostream& os)
{
  m_db.dump(os);
}

l2_binding::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "l2" }, "L2 bindings", this);
}

void
l2_binding::event_handler::handle_replay()
{
  m_db.replay();
}

void
l2_binding::event_handler::handle_populate(const client_db::key_t& key)
{
  /**
   * This is done while populating the bridge-domain
   */
}

dependency_t
l2_binding::event_handler::order() const
{
  return (dependency_t::BINDING);
}

void
l2_binding::event_handler::show(std::ostream& os)
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
