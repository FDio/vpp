#ifndef __VOM_NAT_BINDING_CMDS_H__
#define __VOM_NAT_BINDING_CMDS_H__

#include "vom/nat_binding.hpp"
#include "vom/rpc_cmd.hpp"
#include "vom/dump_cmd.hpp"

#include <vapi/nat.api.vapi.hpp>

namespace VOM {
namespace nat_binding_cmds {
/**
 * A functor class that binds L2 configuration to an interface
 */
class bind_44_input_cmd
    : public rpc_cmd<HW::item<bool>,
                     rc_t,
                     vapi::Nat44_interface_add_del_feature>
{
public:
    /**
     * Constructor
     */
    bind_44_input_cmd(HW::item<bool>& item,
                      const handle_t& itf,
                      const nat_binding::zone_t& zone);

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
    bool operator==(const bind_44_input_cmd& i) const;

private:
    /**
     * The interface to bind
     */
    const handle_t m_itf;

    /**
     * The zone the interface is in
     */
    const nat_binding::zone_t m_zone;
};

/**
 * A cmd class that Unbinds L2 configuration from an interface
 */
class unbind_44_input_cmd
    : public rpc_cmd<HW::item<bool>,
                     rc_t,
                     vapi::Nat44_interface_add_del_feature>
{
public:
    /**
     * Constructor
     */
    unbind_44_input_cmd(HW::item<bool>& item,
                        const handle_t& itf,
                        const nat_binding::zone_t& zone);

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
    bool operator==(const unbind_44_input_cmd& i) const;

private:
    /**
     * The interface to bind
     */
    const handle_t m_itf;

    /**
     * The zone the interface is in
     */
    const nat_binding::zone_t m_zone;
};

/**
 * A cmd class that Dumps all the nat_statics
 */
class dump_44_cmd : public dump_cmd<vapi::Nat44_interface_dump>
{
public:
    /**
     * Constructor
     */
    dump_44_cmd();
    dump_44_cmd(const dump_44_cmd& d);

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
    bool operator==(const dump_44_cmd& i) const;

private:
    /**
     * HW reutrn code
     */
    HW::item<bool> item;
};
};
};

#endif
