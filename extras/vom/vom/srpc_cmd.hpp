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

#ifndef __VOM_SRPC_CMD_H__
#define __VOM_SRPC_CMD_H__

#include "vom/hw.hpp"
#include "vom/rpc_cmd.hpp"

namespace VOM {
template <typename MSG>
class srpc_cmd : public rpc_cmd<HW::item<handle_t>, MSG>
{
public:
  /**
   * convenient typedef
   */
  typedef MSG msg_t;

  /**
   * Constructor taking the HW item that will be updated by the command
   */
  srpc_cmd(HW::item<handle_t>& item)
    : rpc_cmd<HW::item<handle_t>, MSG>(item)
  {
  }

  /**
   * Desructor
   */
  virtual ~srpc_cmd() {}

  virtual vapi_error_e operator()(MSG& reply)
  {
    int stats_index = reply.get_response().get_payload().stats_index;
    int retval = reply.get_response().get_payload().retval;

    VOM_LOG(log_level_t::DEBUG) << this->to_string() << " " << retval;

    rc_t rc = rc_t::from_vpp_retval(retval);
    handle_t handle = handle_t::INVALID;

    if (rc_t::OK == rc) {
      handle = stats_index;
    }

    this->fulfill(HW::item<handle_t>(handle, rc));

    return (VAPI_OK);
  }
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
