/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __VOM_SUB_INTERFACE_H__
#define __VOM_SUB_INTERFACE_H__

#include "vom/interface.hpp"

namespace VOM
{
    /**
     * A Sub-interface. e.g. a VLAN sub-interface on an Ethernet interface
     */
    class sub_interface : public interface
    {
        /*
         * Typedef for VLAN ID
         */
        typedef uint16_t vlan_id_t;

      public:
        /**
         * Construct a new object matching the desried state
         */
        sub_interface(const interface &parent,
                      admin_state_t state,
                      vlan_id_t vlan);
        /**
         * Destructor
         */
        ~sub_interface();
        /**
         * Copy Constructor
         */
        sub_interface(const sub_interface &o);

        /**
         * Return the matching 'singular instance' of the sub-interface
         */
        std::shared_ptr<sub_interface> singular() const;

        /**
         * A functor class that creates an interface
         */
        class create_cmd : public interface::create_cmd<vapi::Create_vlan_subif>
        {
          public:
            /**
             * Cstrunctor taking the reference to the parent
             * and the sub-interface's VLAN
             */
            create_cmd(HW::item<handle_t> &item,
                       const std::string &name,
                       const handle_t &parent,
                       uint16_t vlan);

            /**
             * Issue the command to VPP/HW
             */
            rc_t issue(connection &con);

            /**
             * convert to string format for debug purposes
             */
            std::string to_string() const;

            /**
             * Comparison operator - only used for UT
             */
            bool operator==(const create_cmd &i) const;

          private:
            /**
             * Refernece to the parents handle
             */
            const handle_t &m_parent;

            /**
             * The VLAN of the sub-interface
             */
            uint16_t m_vlan;
        };

        /**
         * A cmd class that Delete an interface
         */
        class delete_cmd : public interface::delete_cmd<vapi::Delete_subif>
        {
          public:
            /**
             * Constructor
             */
            delete_cmd(HW::item<handle_t> &item);

            /**
             * Issue the command to VPP/HW
             */
            rc_t issue(connection &con);

            /**
             * convert to string format for debug purposes
             */
            std::string to_string() const;

            /**
             * Comparison operator - only used for UT
             */
            bool operator==(const delete_cmd &i) const;
        };

      private:
        /**
         * Construct with handle
         */
        sub_interface(const handle_t &handle,
                      const interface &parent,
                      admin_state_t state,
                      vlan_id_t vlan);
        /**
         * The interface class can construct interfaces with handles
         */
        friend class interface;

        /**
         * Return the matching 'instance' of the sub-interface
         *  over-ride from the base class
         */
        std::shared_ptr<interface> singular_i() const;

        /**
         * Virtual functions to construct an interface create commands.
         */
        virtual std::queue<cmd *> &mk_create_cmd(std::queue<cmd *> &cmds);

        /**
         * Virtual functions to construct an interface delete commands.
         */
        virtual std::queue<cmd *> &mk_delete_cmd(std::queue<cmd *> &cmds);

        /**
         * From the name of the parent and the vlan,
         * construct the sub-interface's name
         */
        static std::string mk_name(const interface &parent,
                                   vlan_id_t vlan);

        /**
         * Refernece conter lock on the parent
         */
        const std::shared_ptr<interface> m_parent;

        /**
         * VLAN ID
         */
        vlan_id_t m_vlan;
    };
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
