/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Include file for Vppconnection
 *
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __VOM_CONNECTION_H__
#define __VOM_CONNECTION_H__

#include <mutex>
#include <string>

#include <vapi/vapi.hpp>

namespace VOM
{
    /**
     * A representation of the connection to VPP
     */
    class connection
    {
      public:
        /**
         * Constructor
         */
        connection();
        /**
         * Destructor
         */
        ~connection();

        /**
         * Blocking [re]connect call - always eventually succeeds, or the
         * universe expires. Not much this system can do without one.
         */
        void connect();

        /**
         * Blocking disconnect
         */
        void disconnect();

        /**
         * Retrun the VAPI context the commands will use
         */
        vapi::Connection &ctx();

      private:
        /**
         * The VAPI connection context
         */
        vapi::Connection m_vapi_conn;

        /**
         * The name of this application
         */
        const std::string m_app_name;
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
