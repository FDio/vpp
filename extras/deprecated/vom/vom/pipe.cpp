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

#include "vom/pipe.hpp"
#include "vom/interface_factory.hpp"
#include "vom/pipe_cmds.hpp"
#include "vom/singular_db_funcs.hpp"

namespace VOM {

typedef enum end_t_ {
  EAST = 0,
  WEST,
} end_t;
#define N_ENDS (WEST + 1)

pipe::event_handler pipe::m_evh;

static const std::string
pipe_mk_name(uint32_t instance)
{
  return ("pipe" + std::to_string(instance));
}

/**
 * Construct a new object matching the desried state
 */
pipe::pipe(uint32_t instance, admin_state_t state)
  : interface(pipe_mk_name(instance), type_t::PIPE, state)
  , m_instance(instance)
{
}

pipe::~pipe()
{
  sweep();
  release();
}

pipe::pipe(const pipe& o)
  : interface(o)
  , m_instance(o.m_instance)
{
}

std::string
pipe::to_string(void) const
{
  std::ostringstream s;

  s << "[pipe: " << interface::to_string() << " instance:" << m_instance
    << " ends:[" << m_hdl_pair.rc().to_string() << " "
    << m_hdl_pair.data().first << ", " << m_hdl_pair.data().second << "]]";

  return (s.str());
}

std::queue<cmd*>&
pipe::mk_create_cmd(std::queue<cmd*>& q)
{
  q.push(new pipe_cmds::create_cmd(m_hdl, m_name, m_instance, m_hdl_pair));

  return (q);
}

std::queue<cmd*>&
pipe::mk_delete_cmd(std::queue<cmd*>& q)
{
  q.push(new pipe_cmds::delete_cmd(m_hdl, m_hdl_pair));

  return (q);
}

std::shared_ptr<pipe>
pipe::singular() const
{
  return std::dynamic_pointer_cast<pipe>(singular_i());
}

std::shared_ptr<interface>
pipe::singular_i() const
{
  return m_db.find_or_add(key(), *this);
}

std::shared_ptr<pipe>
pipe::find(const key_t& k)
{
  return std::dynamic_pointer_cast<pipe>(m_db.find(k));
}

std::shared_ptr<interface>
pipe::west()
{
  if (!m_ends[WEST]) {
    if (rc_t::OK == m_hdl_pair.rc()) {
      m_ends[WEST] = pipe_end(*this, WEST).singular();
      m_ends[WEST]->set(m_hdl_pair.data().first);
    }
  }

  return (m_ends[WEST]);
}

std::shared_ptr<interface>
pipe::east()
{
  if (!m_ends[EAST]) {
    if (rc_t::OK == m_hdl_pair.rc()) {
      m_ends[EAST] = pipe_end(*this, EAST).singular();
      m_ends[EAST]->set(m_hdl_pair.data().first);
    }
  }

  return (m_ends[EAST]);
}

pipe::pipe_end::pipe_end(const pipe& p, uint8_t id)
  : interface(p.name() + "." + std::to_string(id),
              interface::type_t::PIPE_END,
              interface::admin_state_t::UP)
  , m_pipe(p.singular())
{
}

std::queue<cmd*>&
pipe::pipe_end::mk_create_cmd(std::queue<cmd*>& q)
{
  return (q);
}

std::queue<cmd*>&
pipe::pipe_end::mk_delete_cmd(std::queue<cmd*>& q)
{
  return (q);
}

void
pipe::set_ends(const handle_pair_t& p)
{
  if (handle_t::INVALID != p.first && handle_t::INVALID != p.second) {
    m_hdl_pair = { p, rc_t::OK };
  } else {
    m_hdl_pair = { p, rc_t::INVALID };
  }
}

pipe::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "pipe" }, "pipes", this);
}

void
pipe::event_handler::handle_replay()
{
  // m_db.replay();
}

void
pipe::event_handler::handle_populate(const client_db::key_t& key)
{
  std::shared_ptr<pipe_cmds::dump_cmd> cmd =
    std::make_shared<pipe_cmds::dump_cmd>();

  HW::enqueue(cmd);
  HW::write();

  for (auto& record : *cmd) {
    std::shared_ptr<pipe> sp;

    sp = interface_factory::new_pipe_interface(record.get_payload());

    VOM_LOG(log_level_t::DEBUG) << " pipe-dump: " << sp->to_string();
    OM::commit(key, *sp);
  }
}

dependency_t
pipe::event_handler::order() const
{
  return (dependency_t::VIRTUAL_INTERFACE);
}

void
pipe::event_handler::show(std::ostream& os)
{
  db_dump(m_db, os);
}

}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
