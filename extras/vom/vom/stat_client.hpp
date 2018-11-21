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

#ifndef __VOM_STAT_CLIENT_H__
#define __VOM_STAT_CLIENT_H__

#include <boost/asio.hpp>
#include <boost/thread/thread.hpp>
#include <iostream>
#include <string>
#include <vector>

#ifdef __cplusplus
extern "C"
{
#endif

#include <vpp-api/client/stat_client.h>
#ifdef __cplusplus
}
#endif

#include "vom/timer.hpp"

namespace VOM {

typedef struct
{
  uint64_t packets;
  uint64_t bytes;
} counter_t;

typedef uint64_t stat_counter_t;
/**
 * A representation of a stat client in VPP
 */
class stat_client
{
public:
  typedef struct
  {
    uint64_t packets;
    uint64_t bytes;
  } counter_t;

  struct stat_data_t
  {
    stat_data_t()
      : m_stat_seg_data(NULL)
      , m_name("")
      , m_type(STAT_DIR_TYPE_ILLEGAL)
    {}

    stat_data_t(stat_segment_data_t* stat_seg_data)
      : m_stat_seg_data(stat_seg_data)
      , m_name(stat_seg_data->name)
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
          m_combined_counter_vec = reinterpret_cast<stat_client::counter_t**>(
            stat_seg_data->combined_counter_vec);
          break;
        case STAT_DIR_TYPE_ERROR_INDEX:
          m_error_Value = stat_seg_data->error_value;
          break;
        case STAT_DIR_TYPE_ILLEGAL:
          break;
      }
    }

    stat_segment_data_t* get_stat_segment_data_ptr(void) const
    {
      return m_stat_seg_data;
    }

    const std::string& get_stat_segment_name(void) const { return m_name; }

    const stat_directory_type_t& get_stat_segment_type(void) const
    {
      return m_type;
    }

  private:
    stat_segment_data_t* m_stat_seg_data;
    const std::string m_name;
    const stat_directory_type_t m_type;
    union
    {
      double m_scalar_value;
      uint64_t m_error_Value;
      uint64_t** m_simple_counter_vec;
      counter_t** m_combined_counter_vec;
    };
  };

  stat_client(std::string& socket_name)
    : m_socket_name(socket_name)
    , m_patterns()
  {
    m_patterns.push_back("/if");
  }

  stat_client(std::vector<std::string>& pattern)
    : m_socket_name("/run/vpp/stats.sock")
    , m_patterns(pattern)
  {}

  stat_client(std::string socket_name, std::vector<std::string> patterns)
    : m_socket_name(socket_name)
    , m_patterns(patterns)
  {}

  stat_client()
    : m_socket_name("/run/vpp/stats.sock")
    , m_patterns()
  {
    m_patterns.push_back("/if");
  }

  ~stat_client()
  {
    stat_client_disconnect();
    stat_client_data_free();
  }

  stat_client(const stat_client& o)
    : m_socket_name(o.m_socket_name)
    , m_patterns(o.m_patterns)
  {}

  int stat_client_connect()
  {
    boost::asio::io_service io;
    m_t.reset(new timer(io));
    m_t->set(true);
    m_th.reset(
      new boost::thread(boost::bind(&boost::asio::io_service::run, &io)));
    io.run();
    return stat_segment_connect(const_cast<char*>(m_socket_name.c_str()));
  }

  void stat_client_disconnect()
  {
    m_t->set(false);
    if (m_th->joinable())
      m_th->join();
    m_th.reset();
    m_t.reset();
    stat_segment_disconnect();
  }

  int stat_client_vec_len(void* vec) { return stat_segment_vec_len(vec); }

  void stat_client_vec_free(void* vec) { stat_segment_vec_free(vec); }

  void stat_client_ls(void)
  {
    std::vector<char*> cstrings;
    cstrings.reserve(m_patterns.size());
    for (size_t i = 0; i < m_patterns.size(); ++i)
      cstrings.push_back(const_cast<char*>(m_patterns[i].c_str()));
    m_counter_vec = stat_segment_ls(reinterpret_cast<uint8_t**>(&cstrings[0]));
  }

  void stat_client_dump(void)
  {
    stat_segment_data_t* ssd;
    ssd = stat_segment_dump(m_counter_vec);
    if (m_data)
      stat_client_data_free();
    m_data.reset(new stat_data_t(ssd));
  }

  void stat_client_dump_entry(uint32_t index)
  {
    stat_segment_data_t* ssd;
    ssd = stat_segment_dump_entry(index);
    if (m_data)
      stat_client_data_free();
    m_data.reset(new stat_data_t(ssd));
  }

  void stat_client_data_free(void)
  {
    stat_segment_data_free(m_data->get_stat_segment_data_ptr());
  }

  double stat_client_heartbeat(void) { return stat_segment_heartbeat(); }

  std::string stat_client_index_to_name(uint32_t index)
  {
    return stat_segment_index_to_name(index);
  }

private:
  std::string m_socket_name;
  std::vector<std::string> m_patterns;
  uint32_t* m_counter_vec;
  std::shared_ptr<stat_data_t> m_data;
  std::shared_ptr<VOM::timer> m_t;
  std::shared_ptr<boost::thread> m_th;
};
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
