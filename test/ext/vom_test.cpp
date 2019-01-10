/*
 * Test suite for class VppOM
 *
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
#define BOOST_TEST_MODULE "VPP OBJECT MODEL"
#define BOOST_TEST_DYN_LINK

#include <boost/test/unit_test.hpp>
#include <boost/assign/list_inserter.hpp>


#include <iostream>
#include <deque>

#include "vom/om.hpp"
#include "vom/interface.hpp"
#include "vom/interface_cmds.hpp"
#include "vom/bond_interface_cmds.hpp"
#include "vom/bond_group_binding.hpp"
#include "vom/bond_group_binding_cmds.hpp"
#include "vom/l2_binding.hpp"
#include "vom/l2_binding_cmds.hpp"
#include "vom/l2_xconnect.hpp"
#include "vom/l2_xconnect_cmds.hpp"
#include "vom/l3_binding.hpp"
#include "vom/l3_binding_cmds.hpp"
#include "vom/bridge_domain.hpp"
#include "vom/bridge_domain_entry.hpp"
#include "vom/bridge_domain_arp_entry.hpp"
#include "vom/bridge_domain_cmds.hpp"
#include "vom/bridge_domain_entry_cmds.hpp"
#include "vom/bridge_domain_arp_entry_cmds.hpp"
#include "vom/prefix.hpp"
#include "vom/route.hpp"
#include "vom/route_cmds.hpp"
#include "vom/mroute_cmds.hpp"
#include "vom/route_domain.hpp"
#include "vom/route_domain_cmds.hpp"
#include "vom/vxlan_tunnel.hpp"
#include "vom/vxlan_tunnel_cmds.hpp"
#include "vom/sub_interface.hpp"
#include "vom/sub_interface_cmds.hpp"
#include "vom/acl_ethertype.hpp"
#include "vom/acl_ethertype_cmds.hpp"
#include "vom/acl_list.hpp"
#include "vom/acl_binding.hpp"
#include "vom/acl_list_cmds.hpp"
#include "vom/acl_binding_cmds.hpp"
#include "vom/acl_l3_rule.hpp"
#include "vom/acl_l2_rule.hpp"
#include "vom/arp_proxy_config.hpp"
#include "vom/arp_proxy_binding.hpp"
#include "vom/arp_proxy_config_cmds.hpp"
#include "vom/arp_proxy_binding_cmds.hpp"
#include "vom/igmp_binding.hpp"
#include "vom/igmp_binding_cmds.hpp"
#include "vom/igmp_listen.hpp"
#include "vom/igmp_listen_cmds.hpp"
#include "vom/ip_punt_redirect.hpp"
#include "vom/ip_punt_redirect_cmds.hpp"
#include "vom/ip_unnumbered.hpp"
#include "vom/ip_unnumbered_cmds.hpp"
#include "vom/interface_ip6_nd.hpp"
#include "vom/interface_span.hpp"
#include "vom/interface_span_cmds.hpp"
#include "vom/neighbour.hpp"
#include "vom/neighbour_cmds.hpp"
#include "vom/nat_static.hpp"
#include "vom/nat_static_cmds.hpp"
#include "vom/nat_binding.hpp"
#include "vom/nat_binding_cmds.hpp"
#include "vom/pipe.hpp"
#include "vom/pipe_cmds.hpp"

using namespace boost;
using namespace VOM;

/**
 * An expectation exception
 */
class ExpException
{
public:
    ExpException(unsigned int number)
    {
        // a neat place to add a break point
        std::cout << "  ExpException here: " << number << std::endl;
    }
};

class MockListener : public interface::event_listener,
                     public interface::stat_listener
{
    void handle_interface_stat(const interface& itf)
    {
    }
    void handle_interface_event(std::vector<VOM::interface::event> events)
    {
    }
};

class MockCmdQ : public HW::cmd_q
{
public:
    MockCmdQ():
        m_strict_order(true)
    {
    }
    virtual ~MockCmdQ()
    {
    }
    void expect(cmd *f)
    {
        m_exp_queue.push_back(f);
    }
    void enqueue(cmd *f)
    {
        m_act_queue.push_back(f);
    }
    void enqueue(std::queue<cmd*> &cmds)
    {
        while (cmds.size())
        {
            m_act_queue.push_back(cmds.front());
            cmds.pop();
        }
    }
    void enqueue(std::shared_ptr<cmd> f)
    {
        m_act_queue.push_back(f.get());
    }

    void dequeue(cmd *f)
    {
    }

    void dequeue(std::shared_ptr<cmd> cmd)
    {
    }

    void strict_order(bool on)
    {
        m_strict_order = on;
    }

    bool is_empty()
    {
        return ((0 == m_exp_queue.size()) &&
                (0 == m_act_queue.size()));
    }

    rc_t write()
    {
        cmd *f_exp, *f_act;
        rc_t rc = rc_t::OK;

        while (m_act_queue.size())
        {
            bool matched = false;
            auto it_exp = m_exp_queue.begin();
            auto it_act = m_act_queue.begin();

            f_act = *it_act;

            std::cout << " Act: " << f_act->to_string() << std::endl;
            while (it_exp != m_exp_queue.end())
            {
                f_exp = *it_exp;
                try
                {
                    std::cout << "  Exp: " << f_exp->to_string() << std::endl;

                    if (typeid(*f_exp) != typeid(*f_act))
                    {
                        throw ExpException(1);
                    }

                    if (typeid(*f_exp) == typeid(interface_cmds::af_packet_create_cmd))
                    {
                        rc = handle_derived<interface_cmds::af_packet_create_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(interface_cmds::loopback_create_cmd))
                    {
                        rc = handle_derived<interface_cmds::loopback_create_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(interface_cmds::vhost_create_cmd))
                    {
                        rc = handle_derived<interface_cmds::vhost_create_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(bond_interface_cmds::create_cmd))
                    {
                       rc = handle_derived<bond_interface_cmds::create_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(interface_cmds::loopback_delete_cmd))
                    {
                        rc = handle_derived<interface_cmds::loopback_delete_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(interface_cmds::af_packet_delete_cmd))
                    {
                        rc = handle_derived<interface_cmds::af_packet_delete_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(interface_cmds::vhost_delete_cmd))
                    {
                       rc = handle_derived<interface_cmds::vhost_delete_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(bond_interface_cmds::delete_cmd))
                    {
                       rc = handle_derived<bond_interface_cmds::delete_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(interface_cmds::state_change_cmd))
                    {
                        rc = handle_derived<interface_cmds::state_change_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(interface_cmds::set_table_cmd))
                    {
                        rc = handle_derived<interface_cmds::set_table_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(interface_cmds::set_mac_cmd))
                    {
                        rc = handle_derived<interface_cmds::set_mac_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(interface_cmds::set_tag))
                    {
                        rc = handle_derived<interface_cmds::set_tag>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(bond_group_binding_cmds::bind_cmd))
                    {
                       rc = handle_derived<bond_group_binding_cmds::bind_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(bond_group_binding_cmds::unbind_cmd))
                    {
                       rc = handle_derived<bond_group_binding_cmds::unbind_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(route_domain_cmds::create_cmd))
                    {
			rc = handle_derived<route_domain_cmds::create_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(route_domain_cmds::delete_cmd))
                    {
                        rc = handle_derived<route_domain_cmds::delete_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(route::ip_route_cmds::update_cmd))
                    {
			rc = handle_derived<route::ip_route_cmds::update_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(route::ip_route_cmds::delete_cmd))
                    {
                        rc = handle_derived<route::ip_route_cmds::delete_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(route::ip_mroute_cmds::update_cmd))
                    {
			rc = handle_derived<route::ip_mroute_cmds::update_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(route::ip_mroute_cmds::delete_cmd))
                    {
                        rc = handle_derived<route::ip_mroute_cmds::delete_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(neighbour_cmds::create_cmd))
                    {
			rc = handle_derived<neighbour_cmds::create_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(neighbour_cmds::delete_cmd))
                    {
                        rc = handle_derived<neighbour_cmds::delete_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(l3_binding_cmds::bind_cmd))
                    {
                        rc = handle_derived<l3_binding_cmds::bind_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(l3_binding_cmds::unbind_cmd))
                    {
                        rc = handle_derived<l3_binding_cmds::unbind_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(bridge_domain_cmds::create_cmd))
                    {
                        rc = handle_derived<bridge_domain_cmds::create_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(bridge_domain_cmds::delete_cmd))
                    {
                        rc = handle_derived<bridge_domain_cmds::delete_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(bridge_domain_entry_cmds::create_cmd))
                    {
                        rc = handle_derived<bridge_domain_entry_cmds::create_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(bridge_domain_entry_cmds::delete_cmd))
                    {
                        rc = handle_derived<bridge_domain_entry_cmds::delete_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(bridge_domain_arp_entry_cmds::create_cmd))
                    {
                        rc = handle_derived<bridge_domain_arp_entry_cmds::create_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(bridge_domain_arp_entry_cmds::delete_cmd))
                    {
                        rc = handle_derived<bridge_domain_arp_entry_cmds::delete_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(l2_binding_cmds::bind_cmd))
                    {
                        rc = handle_derived<l2_binding_cmds::bind_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(l2_binding_cmds::unbind_cmd))
                    {
                        rc = handle_derived<l2_binding_cmds::unbind_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(l2_binding_cmds::set_vtr_op_cmd))
                    {
                        rc = handle_derived<l2_binding_cmds::set_vtr_op_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(l2_xconnect_cmds::bind_cmd))
                    {
                        rc = handle_derived<l2_xconnect_cmds::bind_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(l2_xconnect_cmds::unbind_cmd))
                    {
                        rc = handle_derived<l2_xconnect_cmds::unbind_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(vxlan_tunnel_cmds::create_cmd))
                    {
                        rc = handle_derived<vxlan_tunnel_cmds::create_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(vxlan_tunnel_cmds::delete_cmd))
                    {
                        rc = handle_derived<vxlan_tunnel_cmds::delete_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(sub_interface_cmds::create_cmd))
                    {
                        rc = handle_derived<sub_interface_cmds::create_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(sub_interface_cmds::delete_cmd))
                    {
                        rc = handle_derived<sub_interface_cmds::delete_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(ACL::acl_ethertype_cmds::bind_cmd))
                    {
                        rc = handle_derived<ACL::acl_ethertype_cmds::bind_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(ACL::acl_ethertype_cmds::unbind_cmd))
                    {
                        rc = handle_derived<ACL::acl_ethertype_cmds::unbind_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(ACL::list_cmds::l3_update_cmd))
                    {
                        rc = handle_derived<ACL::list_cmds::l3_update_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(ACL::list_cmds::l3_delete_cmd))
                    {
                        rc = handle_derived<ACL::list_cmds::l3_delete_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(ACL::binding_cmds::l3_bind_cmd))
                    {
                        rc = handle_derived<ACL::binding_cmds::l3_bind_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(ACL::binding_cmds::l3_unbind_cmd))
                    {
                        rc = handle_derived<ACL::binding_cmds::l3_unbind_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(ACL::list_cmds::l2_update_cmd))
                    {
                        rc = handle_derived<ACL::list_cmds::l2_update_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(ACL::list_cmds::l2_delete_cmd))
                    {
                        rc = handle_derived<ACL::list_cmds::l2_delete_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(ACL::binding_cmds::l2_bind_cmd))
                    {
                        rc = handle_derived<ACL::binding_cmds::l2_bind_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(ACL::binding_cmds::l2_unbind_cmd))
                    {
                        rc = handle_derived<ACL::binding_cmds::l2_unbind_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(arp_proxy_binding_cmds::bind_cmd))
                    {
                        rc = handle_derived<arp_proxy_binding_cmds::bind_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(arp_proxy_binding_cmds::unbind_cmd))
                    {
                        rc = handle_derived<arp_proxy_binding_cmds::unbind_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(arp_proxy_config_cmds::config_cmd))
                    {
                        rc = handle_derived<arp_proxy_config_cmds::config_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(arp_proxy_config_cmds::unconfig_cmd))
                    {
                        rc = handle_derived<arp_proxy_config_cmds::unconfig_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(igmp_binding_cmds::bind_cmd))
                    {
                        rc = handle_derived<igmp_binding_cmds::bind_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(igmp_binding_cmds::unbind_cmd))
                    {
                        rc = handle_derived<igmp_binding_cmds::unbind_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(igmp_listen_cmds::listen_cmd))
                    {
                        rc = handle_derived<igmp_listen_cmds::listen_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(igmp_listen_cmds::unlisten_cmd))
                    {
                        rc = handle_derived<igmp_listen_cmds::unlisten_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(ip_punt_redirect_cmds::config_cmd))
                    {
                        rc = handle_derived<ip_punt_redirect_cmds::config_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(ip_punt_redirect_cmds::unconfig_cmd))
                    {
                        rc = handle_derived<ip_punt_redirect_cmds::unconfig_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(ip_unnumbered_cmds::config_cmd))
                    {
                        rc = handle_derived<ip_unnumbered_cmds::config_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(ip_unnumbered_cmds::unconfig_cmd))
                    {
                        rc = handle_derived<ip_unnumbered_cmds::unconfig_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(ip6nd_ra_config::config_cmd))
                    {
                        rc = handle_derived<ip6nd_ra_config::config_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(ip6nd_ra_config::unconfig_cmd))
                    {
                        rc = handle_derived<ip6nd_ra_config::unconfig_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(ip6nd_ra_prefix::config_cmd))
                    {
                        rc = handle_derived<ip6nd_ra_prefix::config_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(ip6nd_ra_prefix::unconfig_cmd))
                    {
                        rc = handle_derived<ip6nd_ra_prefix::unconfig_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(interface_span_cmds::config_cmd))
                    {
                        rc = handle_derived<interface_span_cmds::config_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(interface_span_cmds::unconfig_cmd))
                    {
                        rc = handle_derived<interface_span_cmds::unconfig_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(nat_static_cmds::create_44_cmd))
                    {
                        rc = handle_derived<nat_static_cmds::create_44_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(nat_static_cmds::delete_44_cmd))
                    {
                        rc = handle_derived<nat_static_cmds::delete_44_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(nat_binding_cmds::bind_44_input_cmd))
                    {
                        rc = handle_derived<nat_binding_cmds::bind_44_input_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(nat_binding_cmds::unbind_44_input_cmd))
                    {
                        rc = handle_derived<nat_binding_cmds::unbind_44_input_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(interface_cmds::events_cmd))
                    {
                        rc = handle_derived<interface_cmds::events_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(pipe_cmds::create_cmd))
                    {
                        rc = handle_derived<pipe_cmds::create_cmd>(f_exp, f_act);
                    }
                    else if (typeid(*f_exp) == typeid(pipe_cmds::delete_cmd))
                    {
                        rc = handle_derived<pipe_cmds::delete_cmd>(f_exp, f_act);
                    }
                    else
                    {
                        throw ExpException(2);
                    }

                    // if we get here then we found the match.
                    m_exp_queue.erase(it_exp);
                    m_act_queue.erase(it_act);
                    delete f_exp;
                    delete f_act;

                    // return any injected failures to the agent
                    if (rc_t::OK != rc && rc_t::NOOP != rc)
                    {
                        return (rc);
                    }

                    matched = true;
                    break;
                }
                catch (ExpException &e)
                {
                    // The expected and actual do not match
                    if (m_strict_order)
                    {
                        // in strict ordering mode this is fatal, so rethrow
                        throw e;
                    }
                    else
                    {
                        // move the iterator onto the next in the expected list and
                        // check for a match
                        ++it_exp;
                    }
                }
            }

            if (!matched)
                throw ExpException(3);
        }

        return (rc);
    }
private:

    template <typename T>
    rc_t handle_derived(const cmd *f_exp, cmd *f_act)
    {
        const T *i_exp;
        T *i_act;

        i_exp = dynamic_cast<const T*>(f_exp);
        i_act = dynamic_cast<T*>(f_act);
        if (!(*i_exp == *i_act))
        {
            throw ExpException(4);
        }
        // pass the data and return code to the agent
        i_act->item() = i_exp->item();

        return (i_act->item().rc());
    }

    // The Q to push the expectations on
    std::deque<cmd*> m_exp_queue;

    // the queue to push the actual events on
    std::deque<cmd*> m_act_queue;

    // control whether the expected queue is strictly ordered.
    bool m_strict_order;
};

class VppInit {
public:
    std::string name;
    MockCmdQ *f;

    VppInit()
        : name("vpp-ut"),
          f(new MockCmdQ())
    {
        HW::init(f);
        OM::init();
        logger().set(log_level_t::DEBUG);
    }

    ~VppInit() {
        delete f;
    }
};

BOOST_AUTO_TEST_SUITE(vom)

#define TRY_CHECK_RC(stmt)                    \
{                                             \
    try {                                     \
        BOOST_CHECK(rc_t::OK == stmt);        \
    }                                         \
    catch (ExpException &e)                   \
    {                                         \
        BOOST_CHECK(false);                   \
    }                                         \
    BOOST_CHECK(vi.f->is_empty());            \
}

#define TRY_CHECK(stmt)                       \
{                                             \
    try {                                     \
        stmt;                                 \
    }                                         \
    catch (ExpException &e)                   \
    {                                         \
        BOOST_CHECK(false);                   \
    }                                         \
    BOOST_CHECK(vi.f->is_empty());            \
}

#define ADD_EXPECT(stmt)                      \
    vi.f->expect(new stmt)

#define STRICT_ORDER_OFF()                        \
    vi.f->strict_order(false)

BOOST_AUTO_TEST_CASE(test_interface) {
    VppInit vi;
    const std::string go = "GeorgeOrwell";
    const std::string js = "JohnSteinbeck";
    rc_t rc = rc_t::OK;

    /*
     * George creates and deletes the interface
     */
    std::string itf1_name = "afpacket1";
    interface itf1(itf1_name,
                   interface::type_t::AFPACKET,
                   interface::admin_state_t::UP);

    /*
     * set the expectation for a afpacket interface create.
     *  2 is the interface handle VPP [mock] assigns
     */
    HW::item<handle_t> hw_ifh(2, rc_t::OK);
    ADD_EXPECT(interface_cmds::af_packet_create_cmd(hw_ifh, itf1_name));

    HW::item<interface::admin_state_t> hw_as_up(interface::admin_state_t::UP, rc_t::OK);
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_ifh));

    TRY_CHECK_RC(OM::write(go, itf1));

    HW::item<interface::admin_state_t> hw_as_down(interface::admin_state_t::DOWN, rc_t::OK);
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_ifh));
    ADD_EXPECT(interface_cmds::af_packet_delete_cmd(hw_ifh, itf1_name));

    TRY_CHECK(OM::remove(go));

    /*
     * George creates the interface, then John brings it down.
     * George's remove is a no-op, sice John also owns the interface
     */
    interface itf1b(itf1_name,
                    interface::type_t::AFPACKET,
                    interface::admin_state_t::DOWN);

    ADD_EXPECT(interface_cmds::af_packet_create_cmd(hw_ifh, itf1_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_ifh));
    TRY_CHECK_RC(OM::write(go, itf1));

    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_ifh));
    TRY_CHECK_RC(OM::write(js, itf1b));

    TRY_CHECK(OM::remove(go));

    ADD_EXPECT(interface_cmds::af_packet_delete_cmd(hw_ifh, itf1_name));
    TRY_CHECK(OM::remove(js));

    /*
     * George adds an interface, then we flush all of Geroge's state
     */
    ADD_EXPECT(interface_cmds::af_packet_create_cmd(hw_ifh, itf1_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_ifh));
    TRY_CHECK_RC(OM::write(go, itf1));

    TRY_CHECK(OM::mark(go));

    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_ifh));
    ADD_EXPECT(interface_cmds::af_packet_delete_cmd(hw_ifh, itf1_name));
    TRY_CHECK(OM::sweep(go));

    /*
     * George adds an interface. mark stale. update the same interface. sweep
     * and expect no delete
     */
    ADD_EXPECT(interface_cmds::af_packet_create_cmd(hw_ifh, itf1_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_ifh));
    TRY_CHECK_RC(OM::write(go, itf1b));

    TRY_CHECK(OM::mark(go));

    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_ifh));
    TRY_CHECK_RC(OM::write(go, itf1));

    TRY_CHECK(OM::sweep(go));

    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_ifh));
    ADD_EXPECT(interface_cmds::af_packet_delete_cmd(hw_ifh, itf1_name));
    TRY_CHECK(OM::remove(go));

    /*
     * George adds an insterface, then we mark that state. Add a second interface
     * an flush the first that is now stale.
     */
    ADD_EXPECT(interface_cmds::af_packet_create_cmd(hw_ifh, itf1_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_ifh));
    TRY_CHECK_RC(OM::write(go, itf1));

    TRY_CHECK(OM::mark(go));

    std::string itf2_name = "afpacket2";
    std::string itf2_tag = "uuid-of-afpacket2-interface";
    interface itf2(itf2_name,
                   interface::type_t::AFPACKET,
                   interface::admin_state_t::UP,
                   itf2_tag);
    HW::item<handle_t> hw_ifh2(3, rc_t::OK);

    ADD_EXPECT(interface_cmds::af_packet_create_cmd(hw_ifh2, itf2_name));
    ADD_EXPECT(interface_cmds::set_tag(hw_ifh2, itf2_tag));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_ifh2));
    TRY_CHECK_RC(OM::write(go, itf2));

    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_ifh));
    ADD_EXPECT(interface_cmds::af_packet_delete_cmd(hw_ifh, itf1_name));
    TRY_CHECK(OM::sweep(go));

    TRY_CHECK(OM::mark(go));

    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_ifh2));
    ADD_EXPECT(interface_cmds::af_packet_delete_cmd(hw_ifh2, itf2_name));
    TRY_CHECK(OM::sweep(go));


    std::string itf3_name = "/PATH/TO/vhost_user1.sock";
    std::string itf3_tag = "uuid-of-vhost_user1-interface";
    interface itf3(itf3_name,
                   interface::type_t::VHOST,
                   interface::admin_state_t::UP,
                   itf3_tag);
    HW::item<handle_t> hw_ifh3(4, rc_t::OK);

    ADD_EXPECT(interface_cmds::vhost_create_cmd(hw_ifh3, itf3_name, itf3_tag));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_ifh3));
    TRY_CHECK_RC(OM::write(go, itf3));

    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_ifh3));
    ADD_EXPECT(interface_cmds::vhost_delete_cmd(hw_ifh3, itf3_name));
    TRY_CHECK(OM::remove(go));
}

BOOST_AUTO_TEST_CASE(test_bvi) {
    VppInit vi;
    const std::string ernest = "ErnestHemmingway";
    const std::string graham = "GrahamGreene";
    rc_t rc = rc_t::OK;
    l3_binding *l3;

    HW::item<interface::admin_state_t> hw_as_up(interface::admin_state_t::UP,
                                                rc_t::OK);
    HW::item<interface::admin_state_t> hw_as_down(interface::admin_state_t::DOWN,
                                                  rc_t::OK);

    /*
     * Enrest creates a BVI with address 10.10.10.10/24
     */
    route::prefix_t pfx_10("10.10.10.10", 24);

    const std::string bvi_name = "bvi1";
    interface itf(bvi_name,
                  interface::type_t::BVI,
                  interface::admin_state_t::UP);
    HW::item<handle_t> hw_ifh(4, rc_t::OK);
    HW::item<route::prefix_t> hw_pfx_10(pfx_10, rc_t::OK);

    ADD_EXPECT(interface_cmds::loopback_create_cmd(hw_ifh, bvi_name));
    ADD_EXPECT(interface_cmds::set_tag(hw_ifh, bvi_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_ifh));
    TRY_CHECK_RC(OM::write(ernest, itf));

    l3 = new l3_binding(itf, pfx_10);
    HW::item<bool> hw_l3_bind(true, rc_t::OK);
    HW::item<bool> hw_l3_unbind(false, rc_t::OK);
    ADD_EXPECT(l3_binding_cmds::bind_cmd(hw_l3_bind, hw_ifh.data(), pfx_10));
    TRY_CHECK_RC(OM::write(ernest, *l3));

    // change the MAC address on the BVI
    interface itf_new_mac(bvi_name,
                          interface::type_t::BVI,
                          interface::admin_state_t::UP);
    l2_address_t l2_addr({0,1,2,3,4,5});
    HW::item<l2_address_t> hw_mac(l2_addr, rc_t::OK);
    itf_new_mac.set(l2_addr);
    ADD_EXPECT(interface_cmds::set_mac_cmd(hw_mac, hw_ifh));
    TRY_CHECK_RC(OM::write(ernest, itf_new_mac));

    // create/write the interface to the OM again but with an unset MAC
    // this should not generate a MAC address update
    TRY_CHECK_RC(OM::write(ernest, itf));

    // change the MAC address on the BVI - again
    interface itf_new_mac2(bvi_name,
                           interface::type_t::BVI,
                           interface::admin_state_t::UP);
    l2_address_t l2_addr2({0,1,2,3,4,6});
    HW::item<l2_address_t> hw_mac2(l2_addr2, rc_t::OK);
    itf_new_mac2.set(l2_addr2);
    ADD_EXPECT(interface_cmds::set_mac_cmd(hw_mac2, hw_ifh));
    TRY_CHECK_RC(OM::write(ernest, itf_new_mac2));

    delete l3;
    ADD_EXPECT(l3_binding_cmds::unbind_cmd(hw_l3_unbind, hw_ifh.data(), pfx_10));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_ifh));
    ADD_EXPECT(interface_cmds::loopback_delete_cmd(hw_ifh));
    TRY_CHECK(OM::remove(ernest));

    /*
     * Graham creates a BVI with address 10.10.10.10/24 in Routing Domain
     */
    route_domain rd(1);
    HW::item<bool> hw_rd4_create(true, rc_t::OK);
    HW::item<bool> hw_rd4_delete(false, rc_t::OK);
    HW::item<bool> hw_rd6_create(true, rc_t::OK);
    HW::item<bool> hw_rd6_delete(false, rc_t::OK);
    HW::item<route::table_id_t> hw_rd4_bind(1, rc_t::OK);
    HW::item<route::table_id_t> hw_rd4_unbind(route::DEFAULT_TABLE, rc_t::OK);
    HW::item<route::table_id_t> hw_rd6_bind(1, rc_t::OK);
    HW::item<route::table_id_t> hw_rd6_unbind(route::DEFAULT_TABLE, rc_t::OK);
    ADD_EXPECT(route_domain_cmds::create_cmd(hw_rd4_create, l3_proto_t::IPV4, 1));
    ADD_EXPECT(route_domain_cmds::create_cmd(hw_rd6_create, l3_proto_t::IPV6, 1));
    TRY_CHECK_RC(OM::write(graham, rd));

    const std::string bvi2_name = "bvi2";
    interface *itf2 = new interface(bvi2_name,
                                    interface::type_t::BVI,
                                    interface::admin_state_t::UP,
                                    rd);
    HW::item<handle_t> hw_ifh2(5, rc_t::OK);

    ADD_EXPECT(interface_cmds::loopback_create_cmd(hw_ifh2, bvi2_name));
    ADD_EXPECT(interface_cmds::set_tag(hw_ifh2, bvi2_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_ifh2));
    ADD_EXPECT(interface_cmds::set_table_cmd(hw_rd4_bind, l3_proto_t::IPV4, hw_ifh2));
    ADD_EXPECT(interface_cmds::set_table_cmd(hw_rd6_bind, l3_proto_t::IPV6, hw_ifh2));

    TRY_CHECK_RC(OM::write(graham, *itf2));

    l3 = new l3_binding(*itf2, pfx_10);
    ADD_EXPECT(l3_binding_cmds::bind_cmd(hw_l3_bind, hw_ifh2.data(), pfx_10));
    TRY_CHECK_RC(OM::write(graham, *l3));

    delete l3;
    delete itf2;

    ADD_EXPECT(l3_binding_cmds::unbind_cmd(hw_l3_unbind, hw_ifh2.data(), pfx_10));
    ADD_EXPECT(interface_cmds::set_table_cmd(hw_rd4_unbind, l3_proto_t::IPV4, hw_ifh2));
    ADD_EXPECT(interface_cmds::set_table_cmd(hw_rd6_unbind, l3_proto_t::IPV6, hw_ifh2));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_ifh2));
    ADD_EXPECT(interface_cmds::loopback_delete_cmd(hw_ifh2));
    ADD_EXPECT(route_domain_cmds::delete_cmd(hw_rd4_delete, l3_proto_t::IPV4, 1));
    ADD_EXPECT(route_domain_cmds::delete_cmd(hw_rd6_delete, l3_proto_t::IPV6, 1));
    TRY_CHECK(OM::remove(graham));
}

BOOST_AUTO_TEST_CASE(test_bond) {
    VppInit vi;
    const std::string cb = "CarolBerg";
    rc_t rc = rc_t::OK;

    /*
     * creates the interfaces
     */
    std::string itf1_name = "afpacket1";
    interface itf1(itf1_name,
                   interface::type_t::AFPACKET,
                   interface::admin_state_t::UP);

    HW::item<handle_t> hw_ifh(2, rc_t::OK);
    ADD_EXPECT(interface_cmds::af_packet_create_cmd(hw_ifh, itf1_name));

    HW::item<interface::admin_state_t> hw_as_up(interface::admin_state_t::UP, rc_t::OK);
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_ifh));

    TRY_CHECK_RC(OM::write(cb, itf1));

    std::string itf2_name = "afpacket2";
    interface itf2(itf2_name,
                   interface::type_t::AFPACKET,
                   interface::admin_state_t::UP);


    HW::item<handle_t> hw_ifh2(4, rc_t::OK);
    ADD_EXPECT(interface_cmds::af_packet_create_cmd(hw_ifh2, itf2_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_ifh2));

    TRY_CHECK_RC(OM::write(cb, itf2));

    std::string bond_name = "bond";
    bond_interface bond_itf(bond_name, interface::admin_state_t::UP,
                                 bond_interface::mode_t::LACP);

    HW::item<handle_t> hw_ifh3(6, rc_t::OK);
    ADD_EXPECT(bond_interface_cmds::create_cmd(hw_ifh3, bond_name,
      bond_interface::mode_t::LACP, bond_interface::lb_t::L2, l2_address_t::ZERO));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_ifh3));

    TRY_CHECK_RC(OM::write(cb, bond_itf));

    bond_member *bm1 = new bond_member(itf1, bond_member::mode_t::ACTIVE,
                                         bond_member::rate_t::SLOW);
    bond_member *bm2 = new bond_member(itf2, bond_member::mode_t::ACTIVE,
                                         bond_member::rate_t::SLOW);
    bond_group_binding *bgb = new bond_group_binding(bond_itf, {*bm1, *bm2});

    HW::item<bool> bond_hw_bind(true, rc_t::OK);
    ADD_EXPECT(bond_group_binding_cmds::bind_cmd(bond_hw_bind, hw_ifh3.data(), *bm1));
    ADD_EXPECT(bond_group_binding_cmds::bind_cmd(bond_hw_bind, hw_ifh3.data(), *bm2));

    TRY_CHECK_RC(OM::write(cb, *bgb));

    delete bgb;
    delete bm2;
    delete bm1;

    STRICT_ORDER_OFF();
    HW::item<interface::admin_state_t> hw_as_down(interface::admin_state_t::DOWN, rc_t::OK);
    ADD_EXPECT(bond_group_binding_cmds::unbind_cmd(bond_hw_bind, hw_ifh.data()));
    ADD_EXPECT(bond_group_binding_cmds::unbind_cmd(bond_hw_bind, hw_ifh2.data()));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_ifh2));
    ADD_EXPECT(interface_cmds::af_packet_delete_cmd(hw_ifh2, itf2_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_ifh3));
    ADD_EXPECT(bond_interface_cmds::delete_cmd(hw_ifh3));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_ifh));
    ADD_EXPECT(interface_cmds::af_packet_delete_cmd(hw_ifh, itf1_name));

    TRY_CHECK(OM::remove(cb));
}

BOOST_AUTO_TEST_CASE(test_bridge) {
    VppInit vi;
    const std::string franz = "FranzKafka";
    const std::string dante = "Dante";
    const std::string jkr = "jkrowling";
    rc_t rc = rc_t::OK;

    /*
     * Franz creates an interface, Bridge-domain, then binds the two
     */

    // interface create
    std::string itf1_name = "afpacket1";
    interface itf1(itf1_name,
                   interface::type_t::AFPACKET,
                   interface::admin_state_t::UP);

    HW::item<handle_t> hw_ifh(3, rc_t::OK);
    HW::item<interface::admin_state_t> hw_as_up(interface::admin_state_t::UP,
                                                rc_t::OK);
    ADD_EXPECT(interface_cmds::af_packet_create_cmd(hw_ifh, itf1_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_ifh));

    TRY_CHECK_RC(OM::write(franz, itf1));

    // bridge-domain create
    bridge_domain bd1(33);

    HW::item<uint32_t> hw_bd(33, rc_t::OK);
    ADD_EXPECT(bridge_domain_cmds::create_cmd(hw_bd,
                                              bridge_domain::learning_mode_t::ON,
                                              bridge_domain::arp_term_mode_t::ON,
                                              bridge_domain::flood_mode_t::ON,
                                              bridge_domain::mac_age_mode_t::OFF));

    TRY_CHECK_RC(OM::write(franz, bd1));

    // L2-interface create and bind
    // this needs to be delete'd before the flush below, since it too maintains
    // references to the BD and Interface
    l2_binding *l2itf = new l2_binding(itf1, bd1);
    HW::item<bool> hw_l2_bind(true, rc_t::OK);

    ADD_EXPECT(l2_binding_cmds::bind_cmd(hw_l2_bind,
                                         hw_ifh.data(),
                                         hw_bd.data(),
                                         l2_binding::l2_port_type_t::L2_PORT_TYPE_NORMAL));
    TRY_CHECK_RC(OM::write(franz, *l2itf));

    /*
     * Dante adds an interface to the same BD
     */
    std::string itf2_name = "afpacket2";
    interface itf2(itf2_name,
                   interface::type_t::AFPACKET,
                   interface::admin_state_t::UP);

    HW::item<handle_t> hw_ifh2(4, rc_t::OK);
    ADD_EXPECT(interface_cmds::af_packet_create_cmd(hw_ifh2, itf2_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_ifh2));
    TRY_CHECK_RC(OM::write(dante, itf2));

    // BD add is a no-op since it exists
    TRY_CHECK_RC(OM::write(dante, bd1));

    l2_binding *l2itf2 = new l2_binding(itf2, bd1);
    HW::item<l2_binding::l2_vtr_op_t> hw_set_vtr(l2_binding::l2_vtr_op_t::L2_VTR_POP_1, rc_t::OK);
    l2itf2->set(l2_binding::l2_vtr_op_t::L2_VTR_POP_1, 68);

    ADD_EXPECT(l2_binding_cmds::bind_cmd(hw_l2_bind,
                                         hw_ifh2.data(),
                                         hw_bd.data(),
                                         l2_binding::l2_port_type_t::L2_PORT_TYPE_NORMAL));
    ADD_EXPECT(l2_binding_cmds::set_vtr_op_cmd(hw_set_vtr, hw_ifh2.data(), 68));
    TRY_CHECK_RC(OM::write(dante, *l2itf2));

    // Add some static entries to the bridge-domain
    HW::item<bool> hw_be1(true, rc_t::OK);
    mac_address_t mac1({0,1,2,3,4,5});
    bridge_domain_entry *be1 = new bridge_domain_entry(bd1, mac1, itf2);
    ADD_EXPECT(bridge_domain_entry_cmds::create_cmd(hw_be1, mac1, bd1.id(), hw_ifh2.data(),
		                                    false));
    TRY_CHECK_RC(OM::write(dante, *be1));

    // Add some entries to the bridge-domain ARP termination table
    HW::item<bool> hw_bea1(true, rc_t::OK);
    boost::asio::ip::address ip1 = boost::asio::ip::address::from_string("10.10.10.10");

    bridge_domain_arp_entry *bea1 = new bridge_domain_arp_entry(bd1, ip1, mac1);
    ADD_EXPECT(bridge_domain_arp_entry_cmds::create_cmd(hw_be1, bd1.id(), mac1, ip1));
    TRY_CHECK_RC(OM::write(dante, *bea1));

    // flush Franz's state
    delete l2itf;
    HW::item<interface::admin_state_t> hw_as_down(interface::admin_state_t::DOWN,
                                                  rc_t::OK);
    ADD_EXPECT(l2_binding_cmds::unbind_cmd(hw_l2_bind,
                                           hw_ifh.data(),
                                           hw_bd.data(),
                                           l2_binding::l2_port_type_t::L2_PORT_TYPE_NORMAL));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_ifh));
    ADD_EXPECT(interface_cmds::af_packet_delete_cmd(hw_ifh, itf1_name));
    TRY_CHECK(OM::remove(franz));

    // flush Dante's state - the order the interface and BD are deleted
    // is an uncontrollable artifact of the C++ object destruction.
    delete l2itf2;
    delete be1;
    delete bea1;
    STRICT_ORDER_OFF();
    ADD_EXPECT(bridge_domain_arp_entry_cmds::delete_cmd(hw_be1, bd1.id(), mac1, ip1));
    ADD_EXPECT(bridge_domain_entry_cmds::delete_cmd(hw_be1, mac1, bd1.id(), false));
    ADD_EXPECT(l2_binding_cmds::unbind_cmd(hw_l2_bind,
                                           hw_ifh2.data(),
                                           hw_bd.data(),
                                           l2_binding::l2_port_type_t::L2_PORT_TYPE_NORMAL));

    ADD_EXPECT(bridge_domain_cmds::delete_cmd(hw_bd));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_ifh2));
    ADD_EXPECT(interface_cmds::af_packet_delete_cmd(hw_ifh2, itf2_name));
    TRY_CHECK(OM::remove(dante));

    // test the BVI entry in l2fib
    bridge_domain bd2(99);

    HW::item<uint32_t> hw_bd2(99, rc_t::OK);
    ADD_EXPECT(bridge_domain_cmds::create_cmd(hw_bd2,
                                              bridge_domain::learning_mode_t::ON,
                                              bridge_domain::arp_term_mode_t::ON,
                                              bridge_domain::flood_mode_t::ON,
                                              bridge_domain::mac_age_mode_t::OFF));

    TRY_CHECK_RC(OM::write(jkr, bd2));

    std::string itf3_name = "bvi";
    interface itf3(itf3_name,
                   interface::type_t::BVI,
                   interface::admin_state_t::UP);

    HW::item<handle_t> hw_ifh3(5, rc_t::OK);
    ADD_EXPECT(interface_cmds::loopback_create_cmd(hw_ifh3, itf3_name));
    ADD_EXPECT(interface_cmds::set_tag(hw_ifh3, itf3_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_ifh3));
    TRY_CHECK_RC(OM::write(jkr, itf3));

    l2_binding *l2itf3 = new l2_binding(itf3, bd2);
    ADD_EXPECT(l2_binding_cmds::bind_cmd(hw_l2_bind,
                                         hw_ifh3.data(),
                                         hw_bd2.data(),
                                         l2_binding::l2_port_type_t::L2_PORT_TYPE_BVI));
    TRY_CHECK_RC(OM::write(jkr, *l2itf3));

    HW::item<bool> hw_be2(true, rc_t::OK);
    mac_address_t mac2({0,1,2,3,4,5});
    bridge_domain_entry *be2 = new bridge_domain_entry(bd2, mac2, itf3);
    ADD_EXPECT(bridge_domain_entry_cmds::create_cmd(hw_be2, mac2, bd2.id(), hw_ifh3.data(), true));
    TRY_CHECK_RC(OM::write(jkr, *be2));

    delete l2itf3;
    delete be2;
    STRICT_ORDER_OFF();
    ADD_EXPECT(l2_binding_cmds::unbind_cmd(hw_l2_bind,
                                           hw_ifh3.data(),
                                           hw_bd2.data(),
                                           l2_binding::l2_port_type_t::L2_PORT_TYPE_BVI));
    ADD_EXPECT(bridge_domain_entry_cmds::delete_cmd(hw_be2, mac2, bd2.id(), true));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_ifh3));
    ADD_EXPECT(interface_cmds::loopback_delete_cmd(hw_ifh3));
    ADD_EXPECT(bridge_domain_cmds::delete_cmd(hw_bd2));
    TRY_CHECK(OM::remove(jkr));
}

BOOST_AUTO_TEST_CASE(test_l2_xconnect) {
    VppInit vi;
    const std::string nicholas = "NicholasAbercrombie";
    rc_t rc = rc_t::OK;

    /*
     * Interface 1
     */
    std::string itf1_name = "host1";
    interface itf1(itf1_name,
                   interface::type_t::AFPACKET,
                   interface::admin_state_t::UP);
    HW::item<handle_t> hw_ifh(2, rc_t::OK);
    HW::item<interface::admin_state_t> hw_as_up(interface::admin_state_t::UP, rc_t::OK);
    ADD_EXPECT(interface_cmds::af_packet_create_cmd(hw_ifh, itf1_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_ifh));
    TRY_CHECK_RC(OM::write(nicholas, itf1));

    /*
     * Interface 2
     */
    std::string itf2_name = "host2";
    interface itf2(itf2_name,
                   interface::type_t::AFPACKET,
                   interface::admin_state_t::UP);

    HW::item<handle_t> hw_ifh2(4, rc_t::OK);
    ADD_EXPECT(interface_cmds::af_packet_create_cmd(hw_ifh2, itf2_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_ifh2));
    TRY_CHECK_RC(OM::write(nicholas, itf2));

    l2_xconnect *l2_xconn = new l2_xconnect(itf1, itf2);
    HW::item<bool> xconnect_east(true, rc_t::OK);
    HW::item<bool> xconnect_west(true, rc_t::OK);
    HW::item<bool> xconnect_east_unbind(false, rc_t::OK);
    HW::item<bool> xconnect_west_unbind(false, rc_t::OK);
    ADD_EXPECT(l2_xconnect_cmds::bind_cmd(xconnect_east, hw_ifh.data(), hw_ifh2.data()));
    ADD_EXPECT(l2_xconnect_cmds::bind_cmd(xconnect_west, hw_ifh2.data(), hw_ifh.data()));
    TRY_CHECK_RC(OM::write(nicholas, *l2_xconn));

    delete l2_xconn;

    HW::item<interface::admin_state_t> hw_as_down(interface::admin_state_t::DOWN, rc_t::OK);
    STRICT_ORDER_OFF();
    ADD_EXPECT(l2_xconnect_cmds::unbind_cmd(xconnect_east_unbind, hw_ifh.data(), hw_ifh2.data()));
    ADD_EXPECT(l2_xconnect_cmds::unbind_cmd(xconnect_west_unbind, hw_ifh2.data(), hw_ifh.data()));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_ifh2));
    ADD_EXPECT(interface_cmds::af_packet_delete_cmd(hw_ifh2, itf2_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_ifh));
    ADD_EXPECT(interface_cmds::af_packet_delete_cmd(hw_ifh, itf1_name));

    TRY_CHECK(OM::remove(nicholas));
}

BOOST_AUTO_TEST_CASE(test_vxlan) {
    VppInit vi;
    const std::string franz = "FranzKafka";
    rc_t rc = rc_t::OK;

    /*
     * Franz creates an interface, Bridge-domain, then binds the two
     */

    // VXLAN create
    vxlan_tunnel::endpoint_t ep(boost::asio::ip::address::from_string("10.10.10.10"),
                                boost::asio::ip::address::from_string("10.10.10.11"),
                                322);

    vxlan_tunnel vxt(ep.src, ep.dst, ep.vni);

    HW::item<handle_t> hw_vxt(3, rc_t::OK);
    ADD_EXPECT(vxlan_tunnel_cmds::create_cmd(hw_vxt, "don't-care", ep,
                                             handle_t::INVALID));

    TRY_CHECK_RC(OM::write(franz, vxt));

    // bridge-domain create
    bridge_domain bd1(33, bridge_domain::learning_mode_t::OFF,
                      bridge_domain::arp_term_mode_t::OFF,
                      bridge_domain::flood_mode_t::OFF,
                      bridge_domain::mac_age_mode_t::ON);

    HW::item<uint32_t> hw_bd(33, rc_t::OK);
    ADD_EXPECT(bridge_domain_cmds::create_cmd(hw_bd,
                                              bridge_domain::learning_mode_t::OFF,
                                              bridge_domain::arp_term_mode_t::OFF,
                                              bridge_domain::flood_mode_t::OFF,
                                              bridge_domain::mac_age_mode_t::ON));

    TRY_CHECK_RC(OM::write(franz, bd1));

    // L2-interface create and bind
    // this needs to be delete'd before the flush below, since it too maintains
    // references to the BD and Interface
    l2_binding *l2itf = new l2_binding(vxt, bd1);
    HW::item<bool> hw_l2_bind(true, rc_t::OK);

    ADD_EXPECT(l2_binding_cmds::bind_cmd(hw_l2_bind,
                                         hw_vxt.data(),
                                         hw_bd.data(),
                                         l2_binding::l2_port_type_t::L2_PORT_TYPE_NORMAL));
    TRY_CHECK_RC(OM::write(franz, *l2itf));

    // flush Franz's state
    delete l2itf;
    HW::item<handle_t> hw_vxtdel(3, rc_t::NOOP);
    STRICT_ORDER_OFF();
    ADD_EXPECT(l2_binding_cmds::unbind_cmd(hw_l2_bind,
                                           hw_vxt.data(),
                                           hw_bd.data(),
                                           l2_binding::l2_port_type_t::L2_PORT_TYPE_NORMAL));
    ADD_EXPECT(bridge_domain_cmds::delete_cmd(hw_bd));
    ADD_EXPECT(vxlan_tunnel_cmds::delete_cmd(hw_vxtdel, ep));
    TRY_CHECK(OM::remove(franz));
}

BOOST_AUTO_TEST_CASE(test_vlan) {
    VppInit vi;
    const std::string noam = "NoamChomsky";
    rc_t rc = rc_t::OK;

    std::string itf1_name = "host1";
    interface itf1(itf1_name,
                   interface::type_t::AFPACKET,
                   interface::admin_state_t::UP);

    HW::item<handle_t> hw_ifh(2, rc_t::OK);
    ADD_EXPECT(interface_cmds::af_packet_create_cmd(hw_ifh, itf1_name));

    HW::item<interface::admin_state_t> hw_as_up(interface::admin_state_t::UP, rc_t::OK);
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_ifh));

    TRY_CHECK_RC(OM::write(noam, itf1));

    sub_interface *vl33 = new sub_interface(itf1,
                                            interface::admin_state_t::UP,
                                            33);

    HW::item<handle_t> hw_vl33(3, rc_t::OK);
    ADD_EXPECT(sub_interface_cmds::create_cmd(hw_vl33, itf1_name+".33", hw_ifh.data(), 33));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_vl33));

    TRY_CHECK_RC(OM::write(noam, *vl33));

    delete vl33;
    HW::item<interface::admin_state_t> hw_as_down(interface::admin_state_t::DOWN, rc_t::OK);
    HW::item<handle_t> hw_vl33_down(3, rc_t::NOOP);
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_vl33));
    ADD_EXPECT(sub_interface_cmds::delete_cmd(hw_vl33_down));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_ifh));
    ADD_EXPECT(interface_cmds::af_packet_delete_cmd(hw_ifh, itf1_name));

    TRY_CHECK(OM::remove(noam));
}

BOOST_AUTO_TEST_CASE(test_acl) {
    VppInit vi;
    const std::string fyodor = "FyodorDostoyevsky";
    const std::string leo = "LeoTolstoy";
    rc_t rc = rc_t::OK;

    /*
     * Fyodor adds an ACL in the input direction
     */
    std::string itf1_name = "host1";
    interface itf1(itf1_name,
                   interface::type_t::AFPACKET,
                   interface::admin_state_t::UP);
    HW::item<handle_t> hw_ifh(2, rc_t::OK);
    HW::item<interface::admin_state_t> hw_as_up(interface::admin_state_t::UP, rc_t::OK);
    ADD_EXPECT(interface_cmds::af_packet_create_cmd(hw_ifh, itf1_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_ifh));
    TRY_CHECK_RC(OM::write(fyodor, itf1));

    ACL::ethertype_rule_t e1(ethertype_t::ARP, direction_t::INPUT);
    ACL::ethertype_rule_t e2(ethertype_t::ARP, direction_t::OUTPUT);
    ACL::ethertype_rule_t e3(ethertype_t::IPV4, direction_t::INPUT);
    ACL::acl_ethertype::ethertype_rules_t l_e = {e1, e2, e3};
    ACL::acl_ethertype *a_e = new ACL::acl_ethertype(itf1, l_e);
    HW::item<bool> ae_binding(true, rc_t::OK);
    ADD_EXPECT(ACL::acl_ethertype_cmds::bind_cmd(ae_binding, hw_ifh.data(), l_e));
    TRY_CHECK_RC(OM::write(fyodor, *a_e));

    route::prefix_t src("10.10.10.10", 32);
    ACL::l3_rule r1(10, ACL::action_t::PERMIT, src, route::prefix_t::ZERO);
    ACL::l3_rule r2(20, ACL::action_t::DENY, route::prefix_t::ZERO, route::prefix_t::ZERO);

    std::string acl_name = "acl1";
    ACL::l3_list acl1(acl_name);
    acl1.insert(r2);
    acl1.insert(r1);
    ACL::l3_list::rules_t rules = {r1, r2};

    HW::item<handle_t> hw_acl(2, rc_t::OK);
    ADD_EXPECT(ACL::list_cmds::l3_update_cmd(hw_acl, acl_name, rules));
    TRY_CHECK_RC(OM::write(fyodor, acl1));

    ACL::l3_rule r3(30, ACL::action_t::PERMIT, route::prefix_t::ZERO, route::prefix_t::ZERO);
    ACL::l3_list acl2(acl_name);
    acl2.insert(r3);
    ACL::l3_list::rules_t rules2 = {r3};
    ADD_EXPECT(ACL::list_cmds::l3_update_cmd(hw_acl, acl_name, rules2));
    TRY_CHECK_RC(OM::write(fyodor, acl2));

    ACL::l3_binding *l3b = new ACL::l3_binding(direction_t::INPUT, itf1, acl1);
    HW::item<bool> hw_binding(true, rc_t::OK);
    ADD_EXPECT(ACL::binding_cmds::l3_bind_cmd(hw_binding, direction_t::INPUT,
                                         hw_ifh.data(), hw_acl.data()));
    TRY_CHECK_RC(OM::write(fyodor, *l3b));

    /**
     * Leo adds an L2 ACL in the output direction
     */
    TRY_CHECK_RC(OM::write(leo, itf1));

    std::string l2_acl_name = "l2_acl1";
    mac_address_t mac({0x0, 0x0, 0x1, 0x2, 0x3, 0x4});
    mac_address_t mac_mask({0xff, 0xff, 0xff, 0x0, 0x0, 0x0});
    ACL::l2_rule l2_r1(10, ACL::action_t::PERMIT, src, mac, mac_mask);
    ACL::l2_rule l2_r2(20, ACL::action_t::DENY, src, {}, {});

    ACL::l2_list l2_acl(l2_acl_name);
    l2_acl.insert(l2_r2);
    l2_acl.insert(l2_r1);

    ACL::l2_list::rules_t l2_rules = {l2_r1, l2_r2};

    HW::item<handle_t> l2_hw_acl(3, rc_t::OK);
    ADD_EXPECT(ACL::list_cmds::l2_update_cmd(l2_hw_acl, l2_acl_name, l2_rules));
    TRY_CHECK_RC(OM::write(leo, l2_acl));

    ACL::l2_binding *l2b = new ACL::l2_binding(direction_t::OUTPUT, itf1, l2_acl);
    HW::item<bool> l2_hw_binding(true, rc_t::OK);
    ADD_EXPECT(ACL::binding_cmds::l2_bind_cmd(l2_hw_binding, direction_t::OUTPUT,
                                       hw_ifh.data(), l2_hw_acl.data()));
    TRY_CHECK_RC(OM::write(leo, *l2b));

    delete l2b;
    ADD_EXPECT(ACL::binding_cmds::l2_unbind_cmd(l2_hw_binding, direction_t::OUTPUT,
                                                hw_ifh.data(), l2_hw_acl.data()));
    ADD_EXPECT(ACL::list_cmds::l2_delete_cmd(l2_hw_acl));
    TRY_CHECK(OM::remove(leo));

    delete l3b;
    delete a_e;
    HW::item<interface::admin_state_t> hw_as_down(interface::admin_state_t::DOWN,
                                                  rc_t::OK);
    STRICT_ORDER_OFF();
    ADD_EXPECT(ACL::binding_cmds::l3_unbind_cmd(hw_binding, direction_t::INPUT,
                                         hw_ifh.data(), hw_acl.data()));
    ADD_EXPECT(ACL::list_cmds::l3_delete_cmd(hw_acl));
    ADD_EXPECT(ACL::acl_ethertype_cmds::unbind_cmd(ae_binding, hw_ifh.data()));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_ifh));
    ADD_EXPECT(interface_cmds::af_packet_delete_cmd(hw_ifh, itf1_name));

    TRY_CHECK(OM::remove(fyodor));
}

BOOST_AUTO_TEST_CASE(test_igmp) {
    VppInit vi;
    const std::string Isaiah = "IsaiahBerlin";
    rc_t rc = rc_t::OK;

    boost::asio::ip::address_v4 gaddr = boost::asio::ip::address_v4::from_string("232.0.0.1");
    boost::asio::ip::address_v4 saddr1 = boost::asio::ip::address_v4::from_string("192.168.0.20");
    boost::asio::ip::address_v4 saddr2 = boost::asio::ip::address_v4::from_string("192.168.0.30");

    std::string itf3_name = "host3";
    interface itf3(itf3_name,
                   interface::type_t::AFPACKET,
                   interface::admin_state_t::UP);
    HW::item<handle_t> hw_ifh(2, rc_t::OK);
    HW::item<interface::admin_state_t> hw_as_up(interface::admin_state_t::UP, rc_t::OK);
    ADD_EXPECT(interface_cmds::af_packet_create_cmd(hw_ifh, itf3_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_ifh));
    TRY_CHECK_RC(OM::write(Isaiah, itf3));

    igmp_binding *ib = new igmp_binding(itf3);
    HW::item<bool> hw_binding(true, rc_t::OK);
    ADD_EXPECT(igmp_binding_cmds::bind_cmd(hw_binding, hw_ifh.data()));
    TRY_CHECK_RC(OM::write(Isaiah, *ib));

    igmp_listen::src_addrs_t saddrs = {saddr1, saddr2};

    igmp_listen *il = new igmp_listen(*ib, gaddr, saddrs);
    HW::item<bool> hw_as_listen(true, rc_t::OK);
    ADD_EXPECT(igmp_listen_cmds::listen_cmd(hw_as_listen, hw_ifh.data(), gaddr, saddrs));
    TRY_CHECK_RC(OM::write(Isaiah, *il));

    delete il;
    delete ib;

    HW::item<interface::admin_state_t> hw_as_down(interface::admin_state_t::DOWN,
                                                  rc_t::OK);
    STRICT_ORDER_OFF();
    ADD_EXPECT(igmp_listen_cmds::unlisten_cmd(hw_as_listen, hw_ifh.data(), gaddr));
    ADD_EXPECT(igmp_binding_cmds::unbind_cmd(hw_binding, hw_ifh.data()));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_ifh));
    ADD_EXPECT(interface_cmds::af_packet_delete_cmd(hw_ifh, itf3_name));

    TRY_CHECK(OM::remove(Isaiah));
}

BOOST_AUTO_TEST_CASE(test_arp_proxy) {
    VppInit vi;
    const std::string kurt = "KurtVonnegut";
    rc_t rc = rc_t::OK;

    asio::ip::address_v4 low  = asio::ip::address_v4::from_string("10.0.0.0");
    asio::ip::address_v4 high = asio::ip::address_v4::from_string("10.0.0.255");

    arp_proxy_config ap(low, high);
    HW::item<bool> hw_ap_cfg(true, rc_t::OK);
    ADD_EXPECT(arp_proxy_config_cmds::config_cmd(hw_ap_cfg, low, high));
    TRY_CHECK_RC(OM::write(kurt, ap));

    std::string itf3_name = "host3";
    interface itf3(itf3_name,
                   interface::type_t::AFPACKET,
                   interface::admin_state_t::UP);
    HW::item<handle_t> hw_ifh(2, rc_t::OK);
    HW::item<interface::admin_state_t> hw_as_up(interface::admin_state_t::UP, rc_t::OK);
    ADD_EXPECT(interface_cmds::af_packet_create_cmd(hw_ifh, itf3_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_ifh));
    TRY_CHECK_RC(OM::write(kurt, itf3));

    arp_proxy_binding *apb = new arp_proxy_binding(itf3);
    HW::item<bool> hw_binding(true, rc_t::OK);
    ADD_EXPECT(arp_proxy_binding_cmds::bind_cmd(hw_binding, hw_ifh.data()));
    TRY_CHECK_RC(OM::write(kurt, *apb));

    delete apb;

    HW::item<interface::admin_state_t> hw_as_down(interface::admin_state_t::DOWN,
                                                  rc_t::OK);
    STRICT_ORDER_OFF();
    ADD_EXPECT(arp_proxy_binding_cmds::unbind_cmd(hw_binding, hw_ifh.data()));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_ifh));
    ADD_EXPECT(interface_cmds::af_packet_delete_cmd(hw_ifh, itf3_name));
    ADD_EXPECT(arp_proxy_config_cmds::unconfig_cmd(hw_ap_cfg, low, high));

    TRY_CHECK(OM::remove(kurt));
}

BOOST_AUTO_TEST_CASE(test_ip_punt_redirect) {
    VppInit vi;
    const std::string eliot = "EliotReed";
    rc_t rc = rc_t::OK;

    /*
     * Interface 1 is the tx interface
     */
    std::string itf1_name = "tx-itf";
    interface itf1(itf1_name,
                   interface::type_t::AFPACKET,
                   interface::admin_state_t::UP);
    HW::item<handle_t> hw_ifh(2, rc_t::OK);
    HW::item<interface::admin_state_t> hw_as_up(interface::admin_state_t::UP, rc_t::OK);
    ADD_EXPECT(interface_cmds::af_packet_create_cmd(hw_ifh, itf1_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_ifh));
    TRY_CHECK_RC(OM::write(eliot, itf1));

    boost::asio::ip::address addr = boost::asio::ip::address::from_string("192.168.0.20");

    /*
     * Interface 2 is the rx interface
     */
    std::string itf2_name = "rx-itf";
    interface itf2(itf2_name,
                   interface::type_t::AFPACKET,
                   interface::admin_state_t::UP);

    HW::item<handle_t> hw_ifh2(4, rc_t::OK);
    ADD_EXPECT(interface_cmds::af_packet_create_cmd(hw_ifh2, itf2_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_ifh2));
    TRY_CHECK_RC(OM::write(eliot, itf2));

    ip_punt_redirect *ip_punt = new ip_punt_redirect(itf2, itf1, addr);
    HW::item<bool> hw_ip_cfg(true, rc_t::OK);
    HW::item<bool> hw_ip_uncfg(false, rc_t::OK);
    ADD_EXPECT(ip_punt_redirect_cmds::config_cmd(hw_ip_cfg, hw_ifh2.data(), hw_ifh.data(), addr));
    TRY_CHECK_RC(OM::write(eliot, *ip_punt));

    delete ip_punt;

    HW::item<interface::admin_state_t> hw_as_down(interface::admin_state_t::DOWN, rc_t::OK);
    STRICT_ORDER_OFF();
    ADD_EXPECT(ip_punt_redirect_cmds::unconfig_cmd(hw_ip_uncfg, hw_ifh2.data(), hw_ifh.data(), addr));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_ifh));
    ADD_EXPECT(interface_cmds::af_packet_delete_cmd(hw_ifh, itf1_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_ifh2));
    ADD_EXPECT(interface_cmds::af_packet_delete_cmd(hw_ifh2, itf2_name));

    TRY_CHECK(OM::remove(eliot));
}

BOOST_AUTO_TEST_CASE(test_ip_unnumbered) {
    VppInit vi;
    const std::string eric = "EricAmbler";
    rc_t rc = rc_t::OK;

    /*
     * Interface 1 has the L3 address
     */
    std::string itf1_name = "host1";
    interface itf1(itf1_name,
                   interface::type_t::AFPACKET,
                   interface::admin_state_t::UP);
    HW::item<handle_t> hw_ifh(2, rc_t::OK);
    HW::item<interface::admin_state_t> hw_as_up(interface::admin_state_t::UP, rc_t::OK);
    ADD_EXPECT(interface_cmds::af_packet_create_cmd(hw_ifh, itf1_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_ifh));
    TRY_CHECK_RC(OM::write(eric, itf1));

    route::prefix_t pfx_10("10.10.10.10", 24);
    l3_binding *l3 = new l3_binding(itf1, pfx_10);
    HW::item<bool> hw_l3_bind(true, rc_t::OK);
    HW::item<bool> hw_l3_unbind(false, rc_t::OK);
    ADD_EXPECT(l3_binding_cmds::bind_cmd(hw_l3_bind, hw_ifh.data(), pfx_10));
    TRY_CHECK_RC(OM::write(eric, *l3));

    /*
     * Interface 2 is unnumbered
     */
    std::string itf2_name = "host2";
    interface itf2(itf2_name,
                   interface::type_t::AFPACKET,
                   interface::admin_state_t::UP);

    HW::item<handle_t> hw_ifh2(4, rc_t::OK);
    ADD_EXPECT(interface_cmds::af_packet_create_cmd(hw_ifh2, itf2_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_ifh2));
    TRY_CHECK_RC(OM::write(eric, itf2));

    ip_unnumbered *ipun = new ip_unnumbered(itf2, itf1);
    HW::item<bool> hw_ip_cfg(true, rc_t::OK);
    HW::item<bool> hw_ip_uncfg(false, rc_t::OK);
    ADD_EXPECT(ip_unnumbered_cmds::config_cmd(hw_ip_cfg, hw_ifh2.data(), hw_ifh.data()));
    TRY_CHECK_RC(OM::write(eric, *ipun));

    delete l3;
    delete ipun;

    HW::item<interface::admin_state_t> hw_as_down(interface::admin_state_t::DOWN, rc_t::OK);
    STRICT_ORDER_OFF();
    ADD_EXPECT(ip_unnumbered_cmds::unconfig_cmd(hw_ip_uncfg, hw_ifh2.data(), hw_ifh.data()));
    ADD_EXPECT(l3_binding_cmds::unbind_cmd(hw_l3_unbind, hw_ifh.data(), pfx_10));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_ifh2));
    ADD_EXPECT(interface_cmds::af_packet_delete_cmd(hw_ifh2, itf2_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_ifh));
    ADD_EXPECT(interface_cmds::af_packet_delete_cmd(hw_ifh, itf1_name));

    TRY_CHECK(OM::remove(eric));
}

BOOST_AUTO_TEST_CASE(test_ip6nd) {
    VppInit vi;
    const std::string paulo = "PauloCoelho";
    rc_t rc = rc_t::OK;

    /*
     * ra config
     */
    std::string itf_name = "host_ip6nd";
    interface itf(itf_name,
                   interface::type_t::AFPACKET,
                   interface::admin_state_t::UP);
    HW::item<handle_t> hw_ifh(3, rc_t::OK);
    HW::item<interface::admin_state_t> hw_as_up(interface::admin_state_t::UP, rc_t::OK);
    ADD_EXPECT(interface_cmds::af_packet_create_cmd(hw_ifh, itf_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_ifh));
    TRY_CHECK_RC(OM::write(paulo, itf));

    route::prefix_t pfx_10("fd8f:69d8:c12c:ca62::3", 128);
    l3_binding *l3 = new l3_binding(itf, pfx_10);
    HW::item<bool> hw_l3_bind(true, rc_t::OK);
    HW::item<bool> hw_l3_unbind(false, rc_t::OK);
    ADD_EXPECT(l3_binding_cmds::bind_cmd(hw_l3_bind, hw_ifh.data(), pfx_10));
    TRY_CHECK_RC(OM::write(paulo, *l3));

    ra_config ra(0, 1, 0, 4);
    ip6nd_ra_config *ip6ra = new ip6nd_ra_config(itf, ra);
    HW::item<bool> hw_ip6nd_ra_config_config(true, rc_t::OK);
    HW::item<bool> hw_ip6nd_ra_config_unconfig(false, rc_t::OK);
    ADD_EXPECT(ip6nd_ra_config::config_cmd(hw_ip6nd_ra_config_config, hw_ifh.data(), ra));
    TRY_CHECK_RC(OM::write(paulo, *ip6ra));

    /*
     * ra prefix
     */
    ra_prefix ra_pfx(pfx_10, 0, 0, 2592000, 604800);
    ip6nd_ra_prefix *ip6pfx = new ip6nd_ra_prefix(itf, ra_pfx);
    HW::item<bool> hw_ip6nd_ra_prefix_config(true, rc_t::OK);
    HW::item<bool> hw_ip6nd_ra_prefix_unconfig(false, rc_t::OK);
    ADD_EXPECT(ip6nd_ra_prefix::config_cmd(hw_ip6nd_ra_prefix_config, hw_ifh.data(), ra_pfx));
    TRY_CHECK_RC(OM::write(paulo, *ip6pfx));

    delete ip6pfx;

    ADD_EXPECT(ip6nd_ra_prefix::unconfig_cmd(hw_ip6nd_ra_prefix_unconfig, hw_ifh.data(), ra_pfx));

    delete ip6ra;
    delete l3;

    HW::item<interface::admin_state_t> hw_as_down(interface::admin_state_t::DOWN, rc_t::OK);

    STRICT_ORDER_OFF();
    ADD_EXPECT(ip6nd_ra_config::unconfig_cmd(hw_ip6nd_ra_config_unconfig, hw_ifh.data(), ra));
    ADD_EXPECT(l3_binding_cmds::unbind_cmd(hw_l3_unbind, hw_ifh.data(), pfx_10));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_ifh));
    ADD_EXPECT(interface_cmds::af_packet_delete_cmd(hw_ifh, itf_name));

    TRY_CHECK(OM::remove(paulo));
}

BOOST_AUTO_TEST_CASE(test_interface_span) {
    VppInit vi;
    const std::string elif = "ElifShafak";
    rc_t rc = rc_t::OK;

    /*
     * Interface 1 to be mirrored
     */
    std::string itf1_name = "port-from";
    interface itf1(itf1_name,
                   interface::type_t::AFPACKET,
                   interface::admin_state_t::UP);
    HW::item<handle_t> hw_ifh(2, rc_t::OK);
    HW::item<interface::admin_state_t> hw_as_up(interface::admin_state_t::UP, rc_t::OK);
    ADD_EXPECT(interface_cmds::af_packet_create_cmd(hw_ifh, itf1_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_ifh));
    TRY_CHECK_RC(OM::write(elif, itf1));

    /*
     * Interface 2 where traffic is mirrored
     */
    std::string itf2_name = "port-to";
    interface itf2(itf2_name,
                   interface::type_t::AFPACKET,
                   interface::admin_state_t::UP);

    HW::item<handle_t> hw_ifh2(4, rc_t::OK);
    HW::item<interface::admin_state_t> hw_as_up2(interface::admin_state_t::UP, rc_t::OK);

    ADD_EXPECT(interface_cmds::af_packet_create_cmd(hw_ifh2, itf2_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up2, hw_ifh2));
    TRY_CHECK_RC(OM::write(elif, itf2));

    interface_span *itf_span = new interface_span(itf1, itf2, interface_span::state_t::TX_RX_ENABLED);
    HW::item<bool> hw_is_cfg(true, rc_t::OK);
    HW::item<bool> hw_is_uncfg(true, rc_t::OK);
    ADD_EXPECT(interface_span_cmds::config_cmd(hw_is_cfg, hw_ifh.data(), hw_ifh2.data(), interface_span::state_t::TX_RX_ENABLED));
    TRY_CHECK_RC(OM::write(elif, *itf_span));

    HW::item<interface::admin_state_t> hw_as_down(interface::admin_state_t::DOWN, rc_t::OK);
    HW::item<interface::admin_state_t> hw_as_down2(interface::admin_state_t::DOWN, rc_t::OK);

    delete itf_span;
    STRICT_ORDER_OFF();
    ADD_EXPECT(interface_span_cmds::unconfig_cmd(hw_is_uncfg, hw_ifh.data(), hw_ifh2.data()));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_ifh));
    ADD_EXPECT(interface_cmds::af_packet_delete_cmd(hw_ifh, itf1_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down2, hw_ifh2));
    ADD_EXPECT(interface_cmds::af_packet_delete_cmd(hw_ifh2, itf2_name));

    TRY_CHECK(OM::remove(elif));
}

BOOST_AUTO_TEST_CASE(test_routing) {
    VppInit vi;
    const std::string ian = "IanFleming";
    rc_t rc = rc_t::OK;

    /*
     * non-default route domain
     */
    route_domain rd4(1);
    HW::item<bool> hw_rd4_create(true, rc_t::OK);
    HW::item<bool> hw_rd4_delete(false, rc_t::OK);
    HW::item<bool> hw_rd6_create(true, rc_t::OK);
    HW::item<bool> hw_rd6_delete(false, rc_t::OK);
    HW::item<route::table_id_t> hw_rd4_bind(1, rc_t::OK);
    HW::item<route::table_id_t> hw_rd4_unbind(route::DEFAULT_TABLE, rc_t::OK);
    HW::item<route::table_id_t> hw_rd6_bind(1, rc_t::OK);
    HW::item<route::table_id_t> hw_rd7_unbind(route::DEFAULT_TABLE, rc_t::OK);
    ADD_EXPECT(route_domain_cmds::create_cmd(hw_rd4_create, l3_proto_t::IPV4, 1));
    ADD_EXPECT(route_domain_cmds::create_cmd(hw_rd6_create, l3_proto_t::IPV6, 1));
    TRY_CHECK_RC(OM::write(ian, rd4));

    /*
     * a couple of interfaces
     */
    std::string itf1_name = "af1";
    interface itf1(itf1_name,
                   interface::type_t::AFPACKET,
                   interface::admin_state_t::UP);
    HW::item<handle_t> hw_ifh(2, rc_t::OK);
    HW::item<interface::admin_state_t> hw_as_up(interface::admin_state_t::UP, rc_t::OK);
    HW::item<interface::admin_state_t> hw_as_down(interface::admin_state_t::DOWN, rc_t::OK);
    ADD_EXPECT(interface_cmds::af_packet_create_cmd(hw_ifh, itf1_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_ifh));
    TRY_CHECK_RC(OM::write(ian, itf1));

    std::string itf2_name = "af2";
    interface *itf2 = new interface(itf2_name,
                                    interface::type_t::AFPACKET,
                                    interface::admin_state_t::UP,
                                    rd4);

    HW::item<handle_t> hw_ifh2(4, rc_t::OK);
    HW::item<interface::admin_state_t> hw_as_up2(interface::admin_state_t::UP, rc_t::OK);
    HW::item<interface::admin_state_t> hw_as_down2(interface::admin_state_t::DOWN, rc_t::OK);
    ADD_EXPECT(interface_cmds::af_packet_create_cmd(hw_ifh2, itf2_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up2, hw_ifh2));
    ADD_EXPECT(interface_cmds::set_table_cmd(hw_rd4_bind, l3_proto_t::IPV4, hw_ifh2));
    ADD_EXPECT(interface_cmds::set_table_cmd(hw_rd6_bind, l3_proto_t::IPV6, hw_ifh2));
    TRY_CHECK_RC(OM::write(ian, *itf2));

    /*
     * prefix on each interface
     */
    route::prefix_t pfx_10("10.10.10.10", 24);
    l3_binding *l3_10 = new l3_binding(itf1, pfx_10);
    HW::item<bool> hw_l3_10_bind(true, rc_t::OK);
    HW::item<bool> hw_l3_10_unbind(false, rc_t::OK);
    ADD_EXPECT(l3_binding_cmds::bind_cmd(hw_l3_10_bind, hw_ifh.data(), pfx_10));
    TRY_CHECK_RC(OM::write(ian, *l3_10));
    route::prefix_t pfx_11("11.11.11.11", 24);
    l3_binding *l3_11 = new l3_binding(*itf2, pfx_11);
    HW::item<bool> hw_l3_11_bind(true, rc_t::OK);
    HW::item<bool> hw_l3_11_unbind(false, rc_t::OK);
    ADD_EXPECT(l3_binding_cmds::bind_cmd(hw_l3_11_bind, hw_ifh2.data(), pfx_11));
    TRY_CHECK_RC(OM::write(ian, *l3_11));

    /*
     * A route via interface 1 in the default table
     */
    route::prefix_t pfx_5("5.5.5.5", 32);
    boost::asio::ip::address nh_9 = boost::asio::ip::address::from_string("10.10.10.9");
    route::path *path_9 = new route::path(nh_9, itf1);
    boost::asio::ip::address nh_10 = boost::asio::ip::address::from_string("10.10.10.11");
    route::path *path_10 = new route::path(nh_10, itf1);
    route::ip_route *route_5 = new route::ip_route(pfx_5);
    route_5->add(*path_10);
    route_5->add(*path_9);
    HW::item<bool> hw_route_5(true, rc_t::OK);
    ADD_EXPECT(route::ip_route_cmds::update_cmd(hw_route_5, 0, pfx_5, *path_9));
    ADD_EXPECT(route::ip_route_cmds::update_cmd(hw_route_5, 0, pfx_5, *path_10));
    TRY_CHECK_RC(OM::write(ian, *route_5));

    route_5->remove(*path_9);
    ADD_EXPECT(route::ip_route_cmds::delete_cmd(hw_route_5, 0, pfx_5, *path_9));
    TRY_CHECK_RC(OM::write(ian, *route_5));

    delete path_9;

    /*
     * A route via interface 2 in the non-default table
     */
    boost::asio::ip::address nh_11 = boost::asio::ip::address::from_string("11.11.11.10");
    route::path *path_11 = new route::path(nh_11, *itf2);
    boost::asio::ip::address nh_12 = boost::asio::ip::address::from_string("11.11.11.12");
    route::path *path_12 = new route::path(nh_12, *itf2);
    route::ip_route *route_5_2 = new route::ip_route(rd4, pfx_5);
    route_5_2->add(*path_11);
    HW::item<bool> hw_route_5_2(true, rc_t::OK);
    ADD_EXPECT(route::ip_route_cmds::update_cmd(hw_route_5_2, 1, pfx_5, *path_11));
    TRY_CHECK_RC(OM::write(ian, *route_5_2));

    route_5_2->add(*path_12);
    ADD_EXPECT(route::ip_route_cmds::update_cmd(hw_route_5_2, 1, pfx_5, *path_12));
    TRY_CHECK_RC(OM::write(ian, *route_5_2));

    /*
     * An ARP entry for the neighbour on itf1
     */
    HW::item<bool> hw_neighbour(true, rc_t::OK);
    mac_address_t mac_n({0,1,2,4,5,6});
    neighbour *ne = new neighbour(itf1, nh_10, mac_n);
    ADD_EXPECT(neighbour_cmds::create_cmd(hw_neighbour, hw_ifh.data(), mac_n, nh_10));
    TRY_CHECK_RC(OM::write(ian, *ne));

    /*
     * A DVR route
     */
    route::prefix_t pfx_6("6.6.6.6", 32);
    route::path *path_l2 = new route::path(*itf2, nh_proto_t::ETHERNET);
    route::ip_route *route_dvr = new route::ip_route(pfx_6);
    route_dvr->add(*path_l2);
    HW::item<bool> hw_route_dvr(true, rc_t::OK);
    ADD_EXPECT(route::ip_route_cmds::update_cmd(hw_route_dvr, 0, pfx_6, *path_l2));
    TRY_CHECK_RC(OM::write(ian, *route_dvr));

    /*
     * a multicast route
     */
    route::mprefix_t mpfx_4(boost::asio::ip::address::from_string("232.1.1.1"), 32);
    route::ip_mroute *mroute_4 = new route::ip_mroute(mpfx_4);

    route::path *mp1 = new route::path(itf1, nh_proto_t::IPV4);
    route::path *mp2 = new route::path(*itf2, nh_proto_t::IPV4);
    mroute_4->add(*mp1, route::itf_flags_t::FORWARD);
    mroute_4->add(*mp1, route::itf_flags_t::ACCEPT);
    mroute_4->add(*mp2, route::itf_flags_t::FORWARD);
    HW::item<bool> hw_mroute_4(true, rc_t::OK);
    ADD_EXPECT(route::ip_mroute_cmds::update_cmd(hw_mroute_4, 0, mpfx_4,
                                                 *mp1, route::itf_flags_t::FORWARD));
    ADD_EXPECT(route::ip_mroute_cmds::update_cmd(hw_mroute_4, 0, mpfx_4,
                                                 *mp2, route::itf_flags_t::FORWARD));
    ADD_EXPECT(route::ip_mroute_cmds::update_cmd(hw_mroute_4, 0, mpfx_4,
                                                 *mp1, route::itf_flags_t::ACCEPT));
    TRY_CHECK_RC(OM::write(ian, *mroute_4));

    STRICT_ORDER_OFF();
    // delete the stack objects that hold references to others
    // so the OM::remove is the call that removes the last reference
    delete l3_11;
    delete l3_10;
    delete itf2;
    delete route_5;
    delete route_5_2;
    delete route_dvr;
    delete ne;
    delete mroute_4;

    ADD_EXPECT(route::ip_mroute_cmds::delete_cmd(hw_mroute_4, 0, mpfx_4,
                                                 *mp1, route::itf_flags_t::FORWARD));
    ADD_EXPECT(route::ip_mroute_cmds::delete_cmd(hw_mroute_4, 0, mpfx_4,
                                                 *mp2, route::itf_flags_t::FORWARD));
    ADD_EXPECT(route::ip_mroute_cmds::delete_cmd(hw_mroute_4, 0, mpfx_4,
                                                 *mp1, route::itf_flags_t::ACCEPT));

    delete mp1;
    delete mp2;

    ADD_EXPECT(neighbour_cmds::delete_cmd(hw_neighbour, hw_ifh.data(), mac_n, nh_10));
    ADD_EXPECT(route::ip_route_cmds::delete_cmd(hw_route_dvr, 0, pfx_6, *path_l2));
    ADD_EXPECT(route::ip_route_cmds::delete_cmd(hw_route_5_2, 1, pfx_5, *path_11));
    ADD_EXPECT(route::ip_route_cmds::delete_cmd(hw_route_5_2, 1, pfx_5, *path_12));
    ADD_EXPECT(route::ip_route_cmds::delete_cmd(hw_route_5, 0, pfx_5, *path_10));

    delete path_10;
    delete path_11;
    delete path_12;
    delete path_l2;

    ADD_EXPECT(l3_binding_cmds::unbind_cmd(hw_l3_10_unbind, hw_ifh.data(), pfx_10));
    ADD_EXPECT(l3_binding_cmds::unbind_cmd(hw_l3_11_unbind, hw_ifh2.data(), pfx_11));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_ifh));
    ADD_EXPECT(interface_cmds::af_packet_delete_cmd(hw_ifh, itf1_name));
    ADD_EXPECT(interface_cmds::set_table_cmd(hw_rd4_unbind, l3_proto_t::IPV4, hw_ifh2));
    ADD_EXPECT(interface_cmds::set_table_cmd(hw_rd4_unbind, l3_proto_t::IPV6, hw_ifh2));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down2, hw_ifh2));
    ADD_EXPECT(interface_cmds::af_packet_delete_cmd(hw_ifh2, itf2_name));
    ADD_EXPECT(route_domain_cmds::delete_cmd(hw_rd4_delete, l3_proto_t::IPV4, 1));
    ADD_EXPECT(route_domain_cmds::delete_cmd(hw_rd6_delete, l3_proto_t::IPV6, 1));

    TRY_CHECK(OM::remove(ian));
}

BOOST_AUTO_TEST_CASE(test_nat) {
    VppInit vi;
    const std::string gs = "GeorgeSimenon";
    rc_t rc = rc_t::OK;

    /*
     * Inside Interface
     */
    std::string itf_in_name = "inside";
    interface itf_in(itf_in_name,
                     interface::type_t::AFPACKET,
                     interface::admin_state_t::UP);
    HW::item<handle_t> hw_ifh(2, rc_t::OK);
    HW::item<interface::admin_state_t> hw_as_up(interface::admin_state_t::UP, rc_t::OK);
    HW::item<interface::admin_state_t> hw_as_down(interface::admin_state_t::DOWN, rc_t::OK);
    ADD_EXPECT(interface_cmds::af_packet_create_cmd(hw_ifh, itf_in_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_ifh));
    TRY_CHECK_RC(OM::write(gs, itf_in));

    /*
     * outside
     */
    std::string itf_out_name = "port-to";
    interface itf_out(itf_out_name,
                   interface::type_t::AFPACKET,
                   interface::admin_state_t::UP);

    HW::item<handle_t> hw_ifh2(4, rc_t::OK);
    HW::item<interface::admin_state_t> hw_as_up2(interface::admin_state_t::UP, rc_t::OK);
    HW::item<interface::admin_state_t> hw_as_down2(interface::admin_state_t::DOWN, rc_t::OK);

    ADD_EXPECT(interface_cmds::af_packet_create_cmd(hw_ifh2, itf_out_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up2, hw_ifh2));
    TRY_CHECK_RC(OM::write(gs, itf_out));

    /*
     * A NAT static mapping
     */
    boost::asio::ip::address in_addr = boost::asio::ip::address::from_string("10.0.0.1");
    boost::asio::ip::address_v4 out_addr = boost::asio::ip::address_v4::from_string("1.1.1.1");

    nat_static ns(in_addr, out_addr);
    HW::item<bool> hw_ns(true, rc_t::OK);

    ADD_EXPECT(nat_static_cmds::create_44_cmd(hw_ns, 0, in_addr.to_v4(), out_addr));
    TRY_CHECK_RC(OM::write(gs, ns));

    /*
     * bind nat inside and out
     */
    nat_binding *nb_in = new nat_binding(itf_in,
                                         direction_t::INPUT,
                                         l3_proto_t::IPV4,
                                         nat_binding::zone_t::INSIDE);
    HW::item<bool> hw_nb_in(true, rc_t::OK);

    ADD_EXPECT(nat_binding_cmds::bind_44_input_cmd(hw_nb_in,
                                                   hw_ifh.data().value(),
                                                   nat_binding::zone_t::INSIDE));
    TRY_CHECK_RC(OM::write(gs, *nb_in));

    nat_binding *nb_out = new nat_binding(itf_out,
                                          direction_t::INPUT,
                                          l3_proto_t::IPV4,
                                          nat_binding::zone_t::OUTSIDE);
    HW::item<bool> hw_nb_out(true, rc_t::OK);

    ADD_EXPECT(nat_binding_cmds::bind_44_input_cmd(hw_nb_out,
                                                   hw_ifh2.data().value(),
                                                   nat_binding::zone_t::OUTSIDE));
    TRY_CHECK_RC(OM::write(gs, *nb_out));


    STRICT_ORDER_OFF();
    delete nb_in;
    delete nb_out;
    ADD_EXPECT(nat_binding_cmds::unbind_44_input_cmd(hw_nb_in,
                                                     hw_ifh.data().value(),
                                                     nat_binding::zone_t::INSIDE));
    ADD_EXPECT(nat_binding_cmds::unbind_44_input_cmd(hw_nb_out,
                                                     hw_ifh2.data().value(),
                                                     nat_binding::zone_t::OUTSIDE));
    ADD_EXPECT(nat_static_cmds::delete_44_cmd(hw_ns, 0, in_addr.to_v4(), out_addr));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_ifh));
    ADD_EXPECT(interface_cmds::af_packet_delete_cmd(hw_ifh, itf_in_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down2, hw_ifh2));
    ADD_EXPECT(interface_cmds::af_packet_delete_cmd(hw_ifh2, itf_out_name));

    TRY_CHECK(OM::remove(gs));
}

BOOST_AUTO_TEST_CASE(test_interface_events) {
    VppInit vi;
    MockListener ml;

    HW::item<bool> hw_want(true, rc_t::OK);

    ADD_EXPECT(interface_cmds::events_cmd(ml));
    cmd* itf = new interface_cmds::events_cmd(ml);

    HW::enqueue(itf);
    HW::write();
}

BOOST_AUTO_TEST_CASE(test_interface_route_domain_change) {
    VppInit vi;
    const std::string rene = "ReneGoscinny";
    rc_t rc = rc_t::OK;

    /*
     * Create an interface with two IP addresses
     */
    std::string itf1_name = "host1";
    interface itf1(itf1_name,
                   interface::type_t::AFPACKET,
                   interface::admin_state_t::UP);
    HW::item<handle_t> hw_ifh1(2, rc_t::OK);
    HW::item<interface::admin_state_t> hw_as_up(interface::admin_state_t::UP, rc_t::OK);
    HW::item<interface::admin_state_t> hw_as_down(interface::admin_state_t::DOWN, rc_t::OK);
    ADD_EXPECT(interface_cmds::af_packet_create_cmd(hw_ifh1, itf1_name));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_ifh1));
    TRY_CHECK_RC(OM::write(rene, itf1));

    route::prefix_t pfx_10("10.10.10.10", 24);
    l3_binding *l3_1 = new l3_binding(itf1, pfx_10);
    HW::item<bool> hw_l3_bind1(true, rc_t::OK);
    HW::item<bool> hw_l3_unbind1(false, rc_t::OK);
    ADD_EXPECT(l3_binding_cmds::bind_cmd(hw_l3_bind1, hw_ifh1.data(), pfx_10));
    TRY_CHECK_RC(OM::write(rene, *l3_1));

    route::prefix_t pfx_11("10.10.11.11", 24);
    l3_binding *l3_2 = new l3_binding(itf1, pfx_11);
    HW::item<bool> hw_l3_bind2(true, rc_t::OK);
    HW::item<bool> hw_l3_unbind2(false, rc_t::OK);
    ADD_EXPECT(l3_binding_cmds::bind_cmd(hw_l3_bind2, hw_ifh1.data(), pfx_11));
    TRY_CHECK_RC(OM::write(rene, *l3_2));

    route_domain rd(1);
    HW::item<bool> hw_rd_create(true, rc_t::OK);
    HW::item<bool> hw_rd_delete(false, rc_t::OK);
    HW::item<route::table_id_t> hw_rd_bind(1, rc_t::OK);
    HW::item<route::table_id_t> hw_rd_unbind(route::DEFAULT_TABLE, rc_t::OK);
    ADD_EXPECT(route_domain_cmds::create_cmd(hw_rd_create, l3_proto_t::IPV4, 1));
    ADD_EXPECT(route_domain_cmds::create_cmd(hw_rd_create, l3_proto_t::IPV6, 1));
    TRY_CHECK_RC(OM::write(rene, rd));

    /*
     * update the interface to change to a new route-domain
     * expect that the l3-bindings are removed and readded.
     */
    interface *itf2 = new interface(itf1_name,
                                    interface::type_t::AFPACKET,
                                    interface::admin_state_t::UP,
                                    rd);
    ADD_EXPECT(l3_binding_cmds::unbind_cmd(hw_l3_unbind1, hw_ifh1.data(), pfx_10));
    ADD_EXPECT(l3_binding_cmds::unbind_cmd(hw_l3_unbind2, hw_ifh1.data(), pfx_11));
    ADD_EXPECT(interface_cmds::set_table_cmd(hw_rd_bind, l3_proto_t::IPV4, hw_ifh1));
    ADD_EXPECT(interface_cmds::set_table_cmd(hw_rd_bind, l3_proto_t::IPV6, hw_ifh1));
    ADD_EXPECT(l3_binding_cmds::bind_cmd(hw_l3_bind1, hw_ifh1.data(), pfx_10));
    ADD_EXPECT(l3_binding_cmds::bind_cmd(hw_l3_bind2, hw_ifh1.data(), pfx_11));
    TRY_CHECK_RC(OM::write(rene, *itf2));

    /*
     * mve the interface back to the default route-domain
     */
    interface itf3(itf1_name,
                   interface::type_t::AFPACKET,
                   interface::admin_state_t::UP);
    ADD_EXPECT(l3_binding_cmds::unbind_cmd(hw_l3_unbind1, hw_ifh1.data(), pfx_10));
    ADD_EXPECT(l3_binding_cmds::unbind_cmd(hw_l3_unbind2, hw_ifh1.data(), pfx_11));
    ADD_EXPECT(interface_cmds::set_table_cmd(hw_rd_unbind, l3_proto_t::IPV4, hw_ifh1));
    ADD_EXPECT(interface_cmds::set_table_cmd(hw_rd_unbind, l3_proto_t::IPV6, hw_ifh1));
    ADD_EXPECT(l3_binding_cmds::bind_cmd(hw_l3_bind1, hw_ifh1.data(), pfx_10));
    ADD_EXPECT(l3_binding_cmds::bind_cmd(hw_l3_bind2, hw_ifh1.data(), pfx_11));
    TRY_CHECK_RC(OM::write(rene, itf3));

    delete l3_1;
    delete l3_2;
    delete itf2;

    STRICT_ORDER_OFF();
    ADD_EXPECT(l3_binding_cmds::unbind_cmd(hw_l3_unbind1, hw_ifh1.data(), pfx_10));
    ADD_EXPECT(l3_binding_cmds::unbind_cmd(hw_l3_unbind2, hw_ifh1.data(), pfx_11));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_ifh1));
    ADD_EXPECT(interface_cmds::af_packet_delete_cmd(hw_ifh1, itf1_name));
    ADD_EXPECT(route_domain_cmds::delete_cmd(hw_rd_delete, l3_proto_t::IPV4, 1));
    ADD_EXPECT(route_domain_cmds::delete_cmd(hw_rd_delete, l3_proto_t::IPV6, 1));

    TRY_CHECK(OM::remove(rene));
}

BOOST_AUTO_TEST_CASE(test_prefixes) {
    route::prefix_t p6_s_16(boost::asio::ip::address::from_string("2001::"), 16);

    BOOST_CHECK(p6_s_16.mask() == boost::asio::ip::address::from_string("ffff::"));

    route::prefix_t p6_s_17(boost::asio::ip::address::from_string("2001:ff00::"), 17);

    BOOST_CHECK(p6_s_17.mask() == boost::asio::ip::address::from_string("ffff:8000::"));
    BOOST_CHECK(p6_s_17.low().address() == boost::asio::ip::address::from_string("2001:8000::"));

    route::prefix_t p6_s_15(boost::asio::ip::address::from_string("2001:ff00::"), 15);
    BOOST_CHECK(p6_s_15.mask() == boost::asio::ip::address::from_string("fffe::"));
    BOOST_CHECK(p6_s_15.low().address() == boost::asio::ip::address::from_string("2000::"));

    route::prefix_t p4_s_16(boost::asio::ip::address::from_string("192.168.0.0"), 16);

    BOOST_CHECK(p4_s_16.mask() == boost::asio::ip::address::from_string("255.255.0.0"));

    route::prefix_t p4_s_17(boost::asio::ip::address::from_string("192.168.127.0"), 17);

    BOOST_CHECK(p4_s_17.mask() == boost::asio::ip::address::from_string("255.255.128.0"));
    BOOST_CHECK(p4_s_17.low().address() == boost::asio::ip::address::from_string("192.168.0.0"));
    BOOST_CHECK(p4_s_17.high().address() == boost::asio::ip::address::from_string("192.168.127.255"));

    route::prefix_t p4_s_15(boost::asio::ip::address::from_string("192.168.255.255"), 15);

    BOOST_CHECK(p4_s_15.mask() == boost::asio::ip::address::from_string("255.254.0.0"));
    BOOST_CHECK(p4_s_15.low().address() == boost::asio::ip::address::from_string("192.168.0.0"));
    BOOST_CHECK(p4_s_15.high().address() == boost::asio::ip::address::from_string("192.169.255.255"));

    route::prefix_t p4_s_32(boost::asio::ip::address::from_string("192.168.1.1"), 32);

    BOOST_CHECK(p4_s_32.mask() == boost::asio::ip::address::from_string("255.255.255.255"));
    BOOST_CHECK(p4_s_32.low().address() == boost::asio::ip::address::from_string("192.168.1.1"));
    BOOST_CHECK(p4_s_32.high().address() == boost::asio::ip::address::from_string("192.168.1.1"));

}

BOOST_AUTO_TEST_CASE(test_pipes) {
    VppInit vi;
    const std::string gk = "GKChesterton";

    const std::string pipe_name_1 = "pipe1";
    VOM::pipe pipe1(1, interface::admin_state_t::UP);
    HW::item<handle_t> hw_hdl(4, rc_t::OK);
    HW::item<pipe::handle_pair_t> hw_hdl_pair(std::make_pair(5,6), rc_t::OK);

    HW::item<interface::admin_state_t> hw_as_up(interface::admin_state_t::UP,
                                                rc_t::OK);
    HW::item<interface::admin_state_t> hw_as_down(interface::admin_state_t::DOWN,
                                                  rc_t::OK);
    ADD_EXPECT(pipe_cmds::create_cmd(hw_hdl, pipe_name_1, 1, hw_hdl_pair));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_up, hw_hdl));
    TRY_CHECK_RC(OM::write(gk, pipe1));

    pipe1.set_ends(hw_hdl_pair.data());

    // put each end of the pipe in a BD
    bridge_domain bd1(33, bridge_domain::learning_mode_t::OFF,
                      bridge_domain::arp_term_mode_t::OFF,
                      bridge_domain::flood_mode_t::OFF,
                      bridge_domain::mac_age_mode_t::ON);

    HW::item<uint32_t> hw_bd(33, rc_t::OK);
    ADD_EXPECT(bridge_domain_cmds::create_cmd(hw_bd,
                                              bridge_domain::learning_mode_t::OFF,
                                              bridge_domain::arp_term_mode_t::OFF,
                                              bridge_domain::flood_mode_t::OFF,
                                              bridge_domain::mac_age_mode_t::ON));

    TRY_CHECK_RC(OM::write(gk, bd1));

    l2_binding *l2_1 = new l2_binding(*pipe1.east(), bd1);
    HW::item<bool> hw_l2_1_bind(true, rc_t::OK);

    ADD_EXPECT(l2_binding_cmds::bind_cmd(hw_l2_1_bind,
                                         pipe1.east()->handle(),
                                         hw_bd.data(),
                                         l2_binding::l2_port_type_t::L2_PORT_TYPE_NORMAL));
    TRY_CHECK_RC(OM::write(gk, *l2_1));

    l2_binding *l2_2 = new l2_binding(*pipe1.west(), bd1);
    HW::item<bool> hw_l2_2_bind(true, rc_t::OK);

    ADD_EXPECT(l2_binding_cmds::bind_cmd(hw_l2_2_bind,
                                         pipe1.west()->handle(),
                                         hw_bd.data(),
                                         l2_binding::l2_port_type_t::L2_PORT_TYPE_NORMAL));
    TRY_CHECK_RC(OM::write(gk, *l2_2));

    STRICT_ORDER_OFF();

    delete l2_1;
    delete l2_2;
    ADD_EXPECT(l2_binding_cmds::unbind_cmd(hw_l2_1_bind,
                                           pipe1.east()->handle(),
                                           hw_bd.data(),
                                           l2_binding::l2_port_type_t::L2_PORT_TYPE_NORMAL));
    ADD_EXPECT(l2_binding_cmds::unbind_cmd(hw_l2_1_bind,
                                           pipe1.west()->handle(),
                                           hw_bd.data(),
                                           l2_binding::l2_port_type_t::L2_PORT_TYPE_NORMAL));
    ADD_EXPECT(interface_cmds::state_change_cmd(hw_as_down, hw_hdl));
    ADD_EXPECT(pipe_cmds::delete_cmd(hw_hdl, hw_hdl_pair));
    ADD_EXPECT(bridge_domain_cmds::delete_cmd(hw_bd));
    TRY_CHECK(OM::remove(gk));
}

BOOST_AUTO_TEST_SUITE_END()
