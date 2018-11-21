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

#include "vom/stat_client.hpp"

namespace VOM {

stat_client::stat_data_t::stat_data_t()
  : m_name("")
  , m_type(STAT_DIR_TYPE_ILLEGAL)
{
}

stat_client::stat_data_t::stat_data_t(stat_segment_data_t* stat_seg_data)
  : m_name(stat_seg_data->name)
  , m_type(stat_seg_data->type)
{
  switch (m_type) {
    case STAT_DIR_TYPE_SCALAR_INDEX:
      m_scalar_value = stat_seg_data->scalar_value;
      break;
    case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
      m_simple_counter_vec = stat_seg_data->simple_counter_vec;
      break;
    case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
      m_combined_counter_vec =
        reinterpret_cast<counter_t**>(stat_seg_data->combined_counter_vec);
      break;
    case STAT_DIR_TYPE_ERROR_INDEX:
      m_error_Value = stat_seg_data->error_value;
      break;
    case STAT_DIR_TYPE_ILLEGAL:
      break;
  }
}

const std::string&
stat_client::stat_data_t::get_stat_segment_name(void) const
{
  return m_name;
}

const stat_directory_type_t&
stat_client::stat_data_t::get_stat_segment_type(void) const
{
  return m_type;
}

double
stat_client::stat_data_t::get_stat_segment_scalar_data(void)
{
  return m_scalar_value;
}
uint64_t
stat_client::stat_data_t::get_stat_segment_error_data(void)
{
  return m_error_Value;
}
uint64_t**
stat_client::stat_data_t::get_stat_segment_simple_counter_data(void)
{
  return m_simple_counter_vec;
}
counter_t**
stat_client::stat_data_t::get_stat_segment_combined_counter_data(void)
{
  return m_combined_counter_vec;
}

stat_client::stat_client(std::string& socket_name)
  : m_socket_name(socket_name)
  , m_patterns()
{
  m_patterns.push_back("/if");
}

stat_client::stat_client(std::vector<std::string>& pattern)
  : m_socket_name("/run/vpp/stats.sock")
  , m_patterns(pattern)
{
}

stat_client::stat_client(std::string socket_name,
                         std::vector<std::string> patterns)
  : m_socket_name(socket_name)
  , m_patterns(patterns)
{
}

stat_client::stat_client()
  : m_socket_name("/run/vpp/stats.sock")
  , m_patterns()
{
  m_patterns.push_back("/if");
}

stat_client::~stat_client()
{
  stat_segment_vec_free(m_counter_vec);
  stat_client_data_free();
  if (m_stat_connect)
    stat_segment_disconnect();
}

stat_client::stat_client(const stat_client& o)
  : m_socket_name(o.m_socket_name)
  , m_patterns(o.m_patterns)
{
}

int
stat_client::stat_client_connect()
{
  if (stat_segment_connect(const_cast<char*>(m_socket_name.c_str())) == 0)
    m_stat_connect = 1;
  return m_stat_connect;
}

void
stat_client::stat_client_disconnect()
{
  if (m_stat_connect)
    stat_segment_disconnect();
}

int
stat_client::stat_client_vec_len(void* vec)
{
  return stat_segment_vec_len(vec);
}

void
stat_client::stat_client_vec_free(void* vec)
{
  stat_segment_vec_free(vec);
}

void
stat_client::stat_client_ls(void)
{
  uint8_t** string_vec;
  for (auto pattern : m_patterns) {
    string_vec = stat_segment_string_vector(string_vec,
                                            const_cast<char*>(pattern.c_str()));
  }
  m_counter_vec = stat_segment_ls(string_vec);
  stat_segment_vec_free(string_vec);
}

stat_client::stat_data_vec_t&
stat_client::stat_client_dump(void)
{
  stat_segment_data_t* ssd;
  stat_segment_data_free(m_stat_seg_data);
  if (m_stat_data.size()) {
    m_stat_data.clear();
  }
  ssd = stat_segment_dump(m_counter_vec);
  if (!ssd) {
    stat_client_ls();
    return m_stat_data;
  }
  m_stat_seg_data = ssd;
  for (int i = 0; i < stat_segment_vec_len(ssd); i++) {
    stat_data_t sd(&ssd[i]);
    m_stat_data.push_back(sd);
  }
  return m_stat_data;
}

stat_client::stat_data_vec_t&
stat_client::stat_client_dump_entry(uint32_t index)
{
  stat_segment_data_t* ssd;
  stat_segment_data_free(m_stat_seg_data);
  if (m_stat_data.size()) {
    m_stat_data.clear();
  }
  ssd = stat_segment_dump_entry(index);
  if (!ssd) {
    stat_client_ls();
    return m_stat_data;
  }
  m_stat_seg_data = ssd;
  for (int i = 0; i < stat_segment_vec_len(ssd); i++) {
    stat_data_t sd(&ssd[i]);
    m_stat_data.push_back(sd);
  }
  return m_stat_data;
}

void
stat_client::stat_client_data_free(void)
{
  stat_segment_data_free(m_stat_seg_data);
}

double
stat_client::stat_client_heartbeat(void)
{
  return stat_segment_heartbeat();
}

std::string
stat_client::stat_client_index_to_name(uint32_t index)
{
  return stat_segment_index_to_name(index);
}

} // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
