/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef __VOM_STAT_CLASS_H__
#define __VOM_STAT_CLASS_H__

#include "vom/interface.hpp"
#include "vom/stat_client.hpp"

namespace VOM {

class stat_class
{
public:
  stat_class();
  ~stat_class();

  void register_stat_listener(handle_t h, interface::stat_listener& sl);
  void unregister_stat_listener(handle_t handle);

protected:
  /**
   * Notify the command that data from VPP has been scraped and been stored.
   * The command should now inform its clients/listeners.
   */
  virtual void notify() = 0;

private:
  static std::map<handle_t, interface::stat_listener&> m_stat_listeners;
  counter_t m_rx;
  counter_t m_tx;
  stat_counter_t m_rx_error;
  stat_counter_t m_tx_error;
  stat_counter_t m_rx_unicast;
  stat_counter_t m_tx_unicast;
  stat_counter_t m_rx_multicast;
  stat_counter_t m_tx_multicast;
  stat_counter_t m_rx_broadcast;
  stat_counter_t m_tx_broadcast;
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
