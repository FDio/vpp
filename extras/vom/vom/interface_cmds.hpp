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

#ifndef __VOM_INTERFACE_CMDS_H__
#define __VOM_INTERFACE_CMDS_H__

#include <vapi/vapi.hpp>

#include "vom/dump_cmd.hpp"
#include "vom/event_cmd.hpp"
#include "vom/interface.hpp"
#include "vom/rpc_cmd.hpp"

#include <vapi/af_packet.api.vapi.hpp>
#include <vapi/interface.api.vapi.hpp>
#include <vapi/l2.api.vapi.hpp>
#include <vapi/vhost_user.api.vapi.hpp>
#include <vapi/vpe.api.vapi.hpp>

namespace VOM {

namespace interface_cmds {
/**
 * Factory method to construct a new interface from the VPP record
 */
std::unique_ptr<interface> new_interface(
  const vapi_payload_sw_interface_details& vd);

/**
 * A command class to create bvi interfaces in VPP
 */
class bvi_create_cmd : public interface::create_cmd<vapi::Bvi_create>
{
public:
  /**
   * Constructor taking the HW::item to update
   * and the name of the interface to create
   */
  bvi_create_cmd(HW::item<handle_t>& item, const std::string& name);
  ~bvi_create_cmd() = default;

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);

  /**
 * convert to string format for debug purposes
 */
  std::string to_string() const;
};

/**
 * A command class to create Loopback interfaces in VPP
 */
class loopback_create_cmd : public interface::create_cmd<vapi::Create_loopback>
{
public:
  /**
   * Constructor taking the HW::item to update
   * and the name of the interface to create
   */
  loopback_create_cmd(HW::item<handle_t>& item, const std::string& name);
  ~loopback_create_cmd() = default;

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);

  /**
 * convert to string format for debug purposes
 */
  std::string to_string() const;
};

/**
 * A command class to create af_packet interfaces in VPP
 */
class af_packet_create_cmd
  : public interface::create_cmd<vapi::Af_packet_create>
{
public:
  /**
   * Constructor taking the HW::item to update
   * and the name of the interface to create
   */
  af_packet_create_cmd(HW::item<handle_t>& item, const std::string& name);
  ~af_packet_create_cmd() = default;
  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);
  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;
};

/**
 * A functor class that creates an interface
 */
class vhost_create_cmd
  : public interface::create_cmd<vapi::Create_vhost_user_if>
{
public:
  vhost_create_cmd(HW::item<handle_t>& item,
                   const std::string& name,
                   const std::string& tag);

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);
  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

private:
  const std::string m_tag;
};

/**
 * A command class to delete bvi interfaces in VPP
 */
class bvi_delete_cmd : public interface::delete_cmd<vapi::Bvi_delete>
{
public:
  /**
   * Constructor taking the HW::item to update
   */
  bvi_delete_cmd(HW::item<handle_t>& item);

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);
  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;
};

/**
 * A command class to delete loopback interfaces in VPP
 */
class loopback_delete_cmd : public interface::delete_cmd<vapi::Delete_loopback>
{
public:
  /**
   * Constructor taking the HW::item to update
   */
  loopback_delete_cmd(HW::item<handle_t>& item);

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);
  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;
};

/**
 * A command class to delete af-packet interfaces in VPP
 */
class af_packet_delete_cmd
  : public interface::delete_cmd<vapi::Af_packet_delete>
{
public:
  /**
   * Constructor taking the HW::item to update
   * and the name of the interface to delete
   */
  af_packet_delete_cmd(HW::item<handle_t>& item, const std::string& name);

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);
  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;
};

/**
 * A functor class that deletes a Vhost interface
 */
class vhost_delete_cmd
  : public interface::delete_cmd<vapi::Delete_vhost_user_if>
{
public:
  vhost_delete_cmd(HW::item<handle_t>& item, const std::string& name);

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);
  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;
};

/**
 * A command class to set tag on interfaces
 */
class set_tag
  : public rpc_cmd<HW::item<handle_t>, vapi::Sw_interface_tag_add_del>
{
public:
  /**
   * Constructor taking the HW::item to update
   */
  set_tag(HW::item<handle_t>& item, const std::string& name);

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Comparison operator - only used for UT
   */
  bool operator==(const set_tag& i) const;

private:
  /**
   * The tag to add
   */
  const std::string m_name;
};

/**
 * A cmd class that changes the admin state
 */
class state_change_cmd : public rpc_cmd<HW::item<interface::admin_state_t>,
                                        vapi::Sw_interface_set_flags>
{
public:
  /**
   * Constructor taking the HW::item to update
   * and the name handle of the interface whose state is to change
   */
  state_change_cmd(HW::item<interface::admin_state_t>& s,
                   const HW::item<handle_t>& h);

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);
  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Comparison operator - only used for UT
   */
  bool operator==(const state_change_cmd& i) const;

private:
  /**
   * the handle of the interface to update
   */
  const HW::item<handle_t>& m_hdl;
};

/**
 * A command class that binds an interface to an L3 table
 */
class set_table_cmd
  : public rpc_cmd<HW::item<route::table_id_t>, vapi::Sw_interface_set_table>
{
public:
  /**
   * Constructor taking the HW::item to update
   * and the name handle of the interface whose table is to change
   */
  set_table_cmd(HW::item<route::table_id_t>& item,
                const l3_proto_t& proto,
                const HW::item<handle_t>& h);

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Comparison operator - only used for UT
   */
  bool operator==(const set_table_cmd& i) const;

private:
  /**
   * the handle of the interface to update
   */
  const HW::item<handle_t>& m_hdl;

  /**
   * The L3 protocol of the table
   */
  l3_proto_t m_proto;
};

/**
 * A command class that changes the MAC address on an interface
 */
class set_mac_cmd
  : public rpc_cmd<HW::item<l2_address_t>, vapi::Sw_interface_set_mac_address>
{
public:
  /**
   * Constructor taking the HW::item to update
   * and the handle of the interface
   */
  set_mac_cmd(HW::item<l2_address_t>& item, const HW::item<handle_t>& h);

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Comparison operator - only used for UT
   */
  bool operator==(const set_mac_cmd& i) const;

private:
  /**
   * the handle of the interface to update
   */
  const HW::item<handle_t>& m_hdl;
};

/**
 * A command class that enables detailed stats collection on an interface
 */
class collect_detail_stats_change_cmd
  : public rpc_cmd<HW::item<interface::stats_type_t>,
                   vapi::Collect_detailed_interface_stats>
{
public:
  /**
   * Constructor taking the HW::item to update
   * and the handle of the interface
   */
  collect_detail_stats_change_cmd(HW::item<interface::stats_type_t>& item,
                                  const handle_t& h,
                                  bool enable);

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Comparison operator - only used for UT
   */
  bool operator==(const collect_detail_stats_change_cmd& i) const;

private:
  /**
   * the handle of the interface to update
   */
  const handle_t& m_hdl;

  /**
   * enable or disable the detailed stats collection
   */
  bool m_enable;
};

/**
 * A command class represents our desire to recieve interface events
 */
class events_cmd
  : public event_cmd<vapi::Want_interface_events, vapi::Sw_interface_event>
{
public:
  /**
   * Constructor taking the listner to notify
   */
  events_cmd(interface::event_listener& el);

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);

  /**
   * Retires the command - unsubscribe from the events.
   */
  void retire(connection& con);

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Comparison operator - only used for UT
   */
  bool operator==(const events_cmd& i) const;

  /**
   * Called when it's time to poke the listeners
   */
  void notify();

private:
  /**
   * The listeners to notify when data/events arrive
   */
  interface::event_listener& m_listener;
};

/**
 * A cmd class that Dumps all the Vpp interfaces
 */
class dump_cmd : public VOM::dump_cmd<vapi::Sw_interface_dump>
{
public:
  /**
   * Default Constructor
   */
  dump_cmd();

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);
  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Comparison operator - only used for UT
   */
  bool operator==(const dump_cmd& i) const;
};

/**
 * A cmd class that Dumps all the Vpp Interfaces
 */
class vhost_dump_cmd : public VOM::dump_cmd<vapi::Sw_interface_vhost_user_dump>
{
public:
  /**
   * Default Constructor
   */
  vhost_dump_cmd();

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);
  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Comparison operator - only used for UT
   */
  bool operator==(const vhost_dump_cmd& i) const;
};

/**
 * A cmd class that Dumps all the Vpp interfaces
 */
class af_packet_dump_cmd : public VOM::dump_cmd<vapi::Af_packet_dump>
{
public:
  /**
   * Default Constructor
   */
  af_packet_dump_cmd() = default;

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);
  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Comparison operator - only used for UT
   */
  bool operator==(const af_packet_dump_cmd& i) const;
};
};
};
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
#endif
