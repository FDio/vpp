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
#include "vom/interface.hpp"

namespace VOM {

stat_reader::stat_indexes_t stat_reader::m_stat_itf_indexes;

stat_reader::stat_reader()
  : m_client()
{
}

stat_reader::stat_reader(stat_client sc)
  : m_client(sc)
{
}

stat_reader::~stat_reader()
{
}

int
stat_reader::connect()
{
  return m_client.connect();
}

void
stat_reader::disconnect()
{
  m_client.disconnect();
}

void
stat_reader::registers(const interface& intf)
{
  m_stat_itf_indexes.insert(intf.handle_i().value());
}

void
stat_reader::unregisters(const interface& intf)
{
  m_stat_itf_indexes.erase(intf.handle_i().value());
}

void
stat_reader::read()
{
  std::set<std::shared_ptr<interface>> itfs_w_stats;
  const stat_client::stat_data_vec_t& sd = m_client.dump();

  for (auto& sde : sd) {
    std::string name;

    if (sde.name().empty())
      continue;

    name = sde.name();

    if (name.find("/if") != std::string::npos)
      name.erase(0, 4);

    switch (sde.type()) {
      case STAT_DIR_TYPE_ERROR_INDEX:
      case STAT_DIR_TYPE_SCALAR_INDEX:
      case STAT_DIR_TYPE_NAME_VECTOR:
      case STAT_DIR_TYPE_ILLEGAL:
        break;

      case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE: {
        uint64_t** data;

        data = sde.get_stat_segment_simple_counter_data();

        for (auto& i : m_stat_itf_indexes) {
          counter_t count;

          for (int k = 0; k < m_client.vec_len(data); k++) {
            count.packets += data[k][i];
          }

          std::shared_ptr<interface> itf = interface::find(i);
          if (itf) {
            itf->set(count, name);
            itfs_w_stats.insert(itf);
          }
        }
        break;
      }

      case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED: {
        vlib_counter_t** data;

        data = sde.get_stat_segment_combined_counter_data();

        for (auto& i : m_stat_itf_indexes) {
          counter_t count;

          for (int k = 0; k < m_client.vec_len(data); k++) {
            count.packets += data[k][i].packets;
            count.bytes += data[k][i].bytes;
          }

          std::shared_ptr<interface> itf = interface::find(i);
          if (itf) {
            itf->set(count, name);
            itfs_w_stats.insert(itf);
          }
        }
        break;
      }
    }
  }
  for (auto itf : itfs_w_stats) {
    itf->publish_stats();
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
