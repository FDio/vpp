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

#include "vom/stat_reader.hpp"

namespace VOM {

stat_client* stat_reader::m_client;

stat_reader::stat_reader()
{
  m_client = new stat_client();
  m_client->stat_client_connect();
  m_client->stat_client_ls();
}

stat_reader::~stat_reader()
{
  delete m_client;
}

void
stat_reader::register_stat_listener(uint32_t index)
{
  m_stat_listeners.insert(index);
}

void
stat_reader::unregister_stat_listener(uint32_t index)
{
  m_stat_listeners.erase(index);
}

void
stat_reader::get_stats(uint32_t index)
{
  stat_client::stat_data_vec_t sd = m_client->stat_client_dump();
  for (auto& sde : sd) {
    counter_t count = {.packets = 0, .bytes = 0 };
    switch (sde.get_stat_segment_type()) {
      case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
      case STAT_DIR_TYPE_ERROR_INDEX:
      case STAT_DIR_TYPE_SCALAR_INDEX:
        break;

      case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
        for (int k = 0; k < m_client->stat_client_vec_len(
                              sde.get_stat_segment_combined_counter_data());
             k++) {
          count.packets +=
            sde.get_stat_segment_combined_counter_data()[k][index].packets;
          count.bytes +=
            sde.get_stat_segment_combined_counter_data()[k][index].bytes;
        }
        std::cout << "[" << index << "] " << count.packets << " packets "
                  << count.bytes << " bytes " << sde.get_stat_segment_name()
                  << std::endl;
        break;

      default:;
    }
  }
}

} // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
