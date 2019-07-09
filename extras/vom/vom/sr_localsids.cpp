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

#include "vom/sr_localsids.hpp"
#include "vom/sr_localsids_cmds.hpp"
#include "vom/singular_db_funcs.hpp"

using std::make_shared;

namespace VOM {
singular_db<localsid::key_t, localsid> localsid::m_db;

const localsid::sr_behavior_t localsid::sr_behavior_t::UNKNOWN(13, "Unknown");
const localsid::sr_behavior_t localsid::sr_behavior_t::END(1, "End");
const localsid::sr_behavior_t localsid::sr_behavior_t::END_X(2, "End.X");
const localsid::sr_behavior_t localsid::sr_behavior_t::END_T(3, "End.T");
const localsid::sr_behavior_t localsid::sr_behavior_t::END_DX2(5, "End.DX2");
const localsid::sr_behavior_t localsid::sr_behavior_t::END_DX6(6, "End.DX6");
const localsid::sr_behavior_t localsid::sr_behavior_t::END_DX4(7, "End.DX4");
const localsid::sr_behavior_t localsid::sr_behavior_t::END_DT6(8, "End.DT6");
const localsid::sr_behavior_t localsid::sr_behavior_t::END_DT4(9, "End.DT4");

localsid::sr_behavior_t
localsid::sr_behavior_t::from_int(int v)
{
  if (v == 1)
    return localsid::sr_behavior_t::END;
  else if (v == 2)
    return localsid::sr_behavior_t::END_X;
  else if (v == 3)
    return localsid::sr_behavior_t::END_T;
  else if (v == 5)
    return localsid::sr_behavior_t::END_DX2;
  else if (v == 6)
    return localsid::sr_behavior_t::END_DX6;
  else if (v == 7)
    return localsid::sr_behavior_t::END_DX4;
  else if (v == 8)
    return localsid::sr_behavior_t::END_DT6;
  else if (v == 9)
    return localsid::sr_behavior_t::END_DT4;

  return localsid::sr_behavior_t::UNKNOWN;
}

localsid::localsid(const sr_behavior_t &be,
                   const boost::asio::ip::address_v6 &sid)
  : m_hw(false)
  , m_behavior(be)
  , m_localsid(sid)
  , m_intf(nullptr)
  , m_rd(nullptr)
  , m_nh()
{
}

localsid::localsid(const sr_behavior_t &be,
                   const boost::asio::ip::address_v6 &sid,
                   const interface &intf)
  : m_hw(false)
  , m_behavior(be)
  , m_localsid(sid)
  , m_intf(intf.singular())
  , m_rd(route_domain::get_default())
  , m_nh()
{
}

localsid::localsid(const sr_behavior_t &be,
                   const boost::asio::ip::address_v6 &sid,
                   const route_domain &rd)
  : m_hw(false)
  , m_behavior(be)
  , m_localsid(sid)
  , m_intf(nullptr)
  , m_rd(rd.singular())
  , m_nh()
{
}

localsid::localsid(const sr_behavior_t &be,
                   const boost::asio::ip::address_v6 &sid,
                   const route::path &path)
  : m_hw(false)
  , m_behavior(be)
  , m_localsid(sid)
  , m_intf(path.itf())
  , m_rd(route_domain::get_default())
  , m_nh(path.nh())
{
}

localsid::localsid(const localsid &l)
  : m_hw(l.m_hw)
  , m_behavior(l.m_behavior)
  , m_localsid(l.m_localsid)
  , m_intf(l.m_intf)
  , m_rd(l.m_rd)
  , m_nh(l.m_nh)
{
}

localsid::~localsid()
{
  sweep();
  release();
}

localsid::sr_behavior_t::sr_behavior_t(int v, const std::string& s)
  : enum_base<localsid::sr_behavior_t>(v, s)
{
}

const localsid::key_t&
localsid::key() const
{
  return (m_localsid);
}

void
localsid::dump(std::ostream& os)
{
  db_dump(m_db, os);
}

std::queue<cmd*>&
localsid::mk_create_cmd(std::queue<cmd*>& q)
{
  if (m_behavior == sr_behavior_t::END) {
    q.push(new sr_localsids_cmds::create_cmd(m_hw, m_behavior, m_localsid));
  } else if (m_behavior == sr_behavior_t::END_X) {
    if (m_intf)
      q.push(new sr_localsids_cmds::create_cmd(m_hw, m_behavior, m_localsid,
                                               m_nh, m_intf->handle()));
    else
      q.push(new sr_localsids_cmds::create_cmd(m_hw, m_behavior, m_localsid,
                                               m_nh));
  } else if (m_behavior == sr_behavior_t::END_DX2) {
    if (m_intf)
      q.push(new sr_localsids_cmds::create_cmd(m_hw, m_behavior, m_localsid,
                                               m_intf->handle()));
  } else if (m_behavior == sr_behavior_t::END_DT4) {
    if (m_rd)
      q.push(new sr_localsids_cmds::create_cmd(m_hw, m_behavior, m_localsid,
                                               m_rd->table_id()));
  } else if (m_behavior == sr_behavior_t::END_DT6) {
    if (m_rd)
      q.push(new sr_localsids_cmds::create_cmd(m_hw, m_behavior, m_localsid,
                                               m_rd->table_id()));
  } else if (m_behavior == sr_behavior_t::END_DX4) {
    if (m_intf)
      q.push(new sr_localsids_cmds::create_cmd(m_hw, m_behavior, m_localsid,
                                               m_nh, m_intf->handle()));
    else
      q.push(new sr_localsids_cmds::create_cmd(m_hw, m_behavior, m_localsid,
                                               m_nh));
  } else if (m_behavior == sr_behavior_t::END_DX6) {
    if (m_intf)
      q.push(new sr_localsids_cmds::create_cmd(m_hw, m_behavior, m_localsid,
                                               m_nh, m_intf->handle()));
    else
      q.push(new sr_localsids_cmds::create_cmd(m_hw, m_behavior, m_localsid,
                                               m_nh));
  } else {
      VOM_LOG(log_level_t::WARNING) << "Unsupported behavior";
  }

  return (q);
}

void
localsid::sweep()
{
  if (m_hw) {
    HW::enqueue(new sr_localsids_cmds::delete_cmd(m_hw, m_localsid));
  }
  HW::write();
}

void
localsid::update(const localsid& obj)
{
  if (rc_t::OK != m_hw.rc()) {
    std::queue<cmd*> cmds;
    HW::enqueue(mk_create_cmd(cmds));
  }
}

void
localsid::release()
{
  m_db.release(key(), this);
}

std::string
localsid::to_string() const
{
  std::ostringstream s;
  s << "sr-localsid:["
    << "behavior:" << m_behavior.to_string() << ", "
    << "localsid:" << m_localsid
    << "]";

  return (s.str());
}

void
localsid::replay()
{
  if (m_hw) {
    std::queue<cmd*> cmds;
    HW::enqueue(mk_create_cmd(cmds));
  }
}

std::shared_ptr<localsid>
localsid::find_or_add(const localsid &temp)
{
  return (m_db.find_or_add(temp.key(), temp));
}

std::shared_ptr<localsid>
localsid::singular() const
{
  return find_or_add(*this);
}

localsid::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "sr-localsid" }, "SRv6 Localsid", this);
}

void
localsid::event_handler::handle_populate(const client_db::key_t& key)
{
  std::shared_ptr<localsid> l;
  std::shared_ptr<sr_localsids_cmds::dump_cmd> cmd =
    std::make_shared<sr_localsids_cmds::dump_cmd>();

  HW::enqueue(cmd);
  HW::write();

  for (auto& record : *cmd) {

    auto& payload = record.get_payload();

    sr_behavior_t be = sr_behavior_t::from_int(payload.behavior);
    boost::asio::ip::address_v6 sid = from_bytes(0, payload.addr.addr).to_v6();
    std::shared_ptr<interface> intf =
      interface::find(payload.xconnect_iface_or_vrf_table);
    std::shared_ptr<route_domain> rd = route_domain::find(payload.fib_table);
    boost::asio::ip::address_v4 nh4 =
      from_bytes(0, payload.xconnect_nh_addr4).to_v4();
    boost::asio::ip::address_v6 nh6 =
      from_bytes(0, payload.xconnect_nh_addr6).to_v6();

    if (be == sr_behavior_t::END) {
      l = make_shared<localsid>(be, sid);
    } else if (be == sr_behavior_t::END_X) {
      if (intf) {
        route::path path(nh6, *intf);
        l = make_shared<localsid>(be, sid, path);
      } else {
        route::path path(*route_domain::get_default(), nh6);
        l = make_shared<localsid>(be, sid, path);
      }
    } else if (be == sr_behavior_t::END_DX2) {
      if (!intf)
        continue;
      l = make_shared<localsid>(be, sid, *intf);
    } else if (be == sr_behavior_t::END_T) {
      if (!rd)
        continue;
      l = make_shared<localsid>(be, sid, *rd);
    } else if (be == sr_behavior_t::END_DT4) {
      if (!rd)
        continue;
      l = make_shared<localsid>(be, sid, *rd);
    } else if (be == sr_behavior_t::END_DT6) {
      if (!rd)
        continue;
      l = make_shared<localsid>(be, sid, *rd);
    } else if (be == sr_behavior_t::END_DX4) {
      if (intf) {
        route::path path(nh4, *intf);
        l = make_shared<localsid>(be, sid, path);
      } else {
        route::path path(*route_domain::get_default(), nh4);
        l = make_shared<localsid>(be, sid, path);
      }
    } else if (be == sr_behavior_t::END_DX6) {
      if (intf) {
        route::path path(nh6, *intf);
        l = make_shared<localsid>(be, sid, path);
      } else {
        route::path path(*route_domain::get_default(), nh6);
        l = make_shared<localsid>(be, sid, path);
      }
    } else {
      continue;
    }

    OM::commit(key, *l);
  }
}

void
localsid::event_handler::handle_replay()
{
  m_db.replay();
}

void
localsid::event_handler::show(std::ostream& os)
{
  db_dump(m_db, os);
}

dependency_t
localsid::event_handler::order() const
{
  return (dependency_t::ENTRY);
}

std::shared_ptr<localsid>
localsid::find(const key_t& k)
{
  return (m_db.find(k));
}

};
