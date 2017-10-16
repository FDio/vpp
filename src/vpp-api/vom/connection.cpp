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

#include "vom/connection.hpp"

namespace VOM {
connection::connection()
  : m_app_name("vpp-OM")
{
}

connection::~connection()
{
  disconnect();
}

void
connection::disconnect()
{
  m_vapi_conn.disconnect();
}

void
connection::connect()
{
  vapi_error_e rv;

  do {
    rv = m_vapi_conn.connect(m_app_name.c_str(),
                             NULL, // m_api_prefix.c_str(),
                             128, 128);
  } while (VAPI_OK != rv);
}

vapi::Connection&
connection::ctx()
{
  return (m_vapi_conn);
}
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
