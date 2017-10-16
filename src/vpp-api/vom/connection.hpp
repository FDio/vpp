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

#ifndef __VOM_CONNECTION_H__
#define __VOM_CONNECTION_H__

#include <string>

#include <vapi/vapi.hpp>

namespace VOM {
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
  vapi::Connection& ctx();

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
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
