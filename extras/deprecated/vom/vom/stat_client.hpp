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

#include <iostream>
#include <string>
#include <vector>

extern "C" {
#include <vpp-api/client/stat_client.h>
}

namespace VOM {

/**
 * A representation of a stat client in VPP
 */
class stat_client
{
public:
  /**
   * stat data representation
   */
  struct stat_data_t
  {
    /**
     * stat data custom constructor
     */
    stat_data_t(const stat_segment_data_t& stat_seg_data);

    /**
     * get name of stat
     */
    const std::string& name() const;

    /**
     * get type of stat
     */
    const stat_directory_type_t& type() const;

    /**
     * Get pointer to actual data
     */
    double get_stat_segment_scalar_data() const;
    uint64_t* get_stat_segment_error_data() const;
    uint64_t** get_stat_segment_simple_counter_data() const;
    vlib_counter_t** get_stat_segment_combined_counter_data() const;

  private:
    /**
     * name of stat data
     */
    const std::string m_name;

    /**
     * type of stat data
     */
    const stat_directory_type_t m_type;

    /**
     * union of pointers to actual stat data
     */
    union
    {
      double m_scalar_value;
      counter_t* m_error_vec;
      counter_t** m_simple_counter_vec;
      vlib_counter_t** m_combined_counter_vec;
    };
  };

  /**
   * vector of stat_data_t
   */
  typedef std::vector<stat_data_t> stat_data_vec_t;

  /**
   * Stat Client constructor with custom socket name
   */
  stat_client(std::string& socket_name);

  /**
   * Stat Client constructor with custom vector of patterns
   */
  stat_client(std::vector<std::string>& pattern);

  /**
   * Stat Client constructor with custom socket name and vector of patterns
   */
  stat_client(std::string socket_name, std::vector<std::string> patterns);

  /**
   * Stat Client constructor
   */
  stat_client();

  /**
   * Stat Client destructor
   */
  ~stat_client();

  /**
   * Stat Client copy constructor
   */
  stat_client(const stat_client& o);

  /**
   * Connect to stat segment
   */
  int connect();

  /**
   * Disconnect to stat segment
   */
  void disconnect();

  /**
   * dump all the stats for given pattern
   */
  const stat_data_vec_t& dump();

  /**
   * dump stats for given index in stat directory
   */
  const stat_data_vec_t& dump_entry(uint32_t index);

  /**
   * Get vector length of VPP style vector
   */
  int vec_len(void* vec);

  double heartbeat();

  /**
   * get index to name of stat
   */
  std::string index_to_name(uint32_t index);

private:
  /**
   * Free VPP style vector
   */
  void vec_free(void* vec);

  /**
   * Free stat segment data
   */
  void data_free();

  /**
   * ls on the stat directory using given pattern
   */
  void ls();

  /**
   * socket name
   */
  std::string m_socket_name;

  /**
   * vector of patterns for stats
   */
  std::vector<std::string> m_patterns;

  /**
   * connection bit
   */
  bool m_stat_connect;

  /**
   * Pointer to VPP style vector of stat indexes
   */
  uint32_t* m_counter_vec;

  /**
   * Pointer to stat segment
   */
  stat_segment_data_t* m_stat_seg_data;

  /**
   * Vector of stat data
   */
  stat_data_vec_t m_stat_data;
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
