/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include "vom/connection.hpp"

using namespace VOM;

connection::connection()
  : m_app_name("vpp-OM")
{
}

connection::~connection()
{
    disconnect();
}

void connection::disconnect()
{
    m_vapi_conn.disconnect();
}

void connection::connect()
{
    vapi_error_e rv;

    do
    {
        rv = m_vapi_conn.connect(m_app_name.c_str(),
                                 NULL,  //m_api_prefix.c_str(),
                                 128,
                                 128);
    } while (VAPI_OK != rv);
}

vapi::Connection &connection::ctx()
{
    return (m_vapi_conn);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
