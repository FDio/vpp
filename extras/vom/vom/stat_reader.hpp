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

#ifndef __VOM_STAT_READER_H__
#define __VOM_STAT_READER_H__

#include "vom/enum_base.hpp"
#include "vom/stat_client.hpp"
#include <set>

namespace VOM {

class interface;

/**
 * Stat reader: single interface to get stats
 */
class stat_reader
{
public:

  struct stats_type_t : public enum_base<stats_type_t>
  {
    const static stats_type_t NONE;
    const static stats_type_t INTERFACE;

  private:
    stats_type_t(int v, const std::string& s);
  };

  /**
   * typedef of stat_indexes
   */
  typedef std::set<uint32_t> stat_indexes_t;

  /**
   * Default Constructor
   */
  stat_reader();

  /**
   * Constructor
   */
  stat_reader(stat_client sc);

  /**
   * Destructor
   */
  ~stat_reader();

  /**
   * get stat indexes
   */
  const stat_indexes_t& get(const stats_type_t) const;

  /**
   * connection to stat object
   */
  virtual int connect();

  /**
   * disconnect to stat object
   */
  virtual void disconnect();

  /**
   * read stats for registered objects from stat_segment
   * and set those stats to respective objects
   */
  virtual void read();

private:
  /**
   * friend to interface class to call stat_register and
   * stat_unregister methods
   */
  friend class interface;

  /**
   * Register objects to get stats for
   */
  static void registers(const interface& itf);

  /**
   * Unregister objects
   */
  static void unregisters(const interface& itf);

  /**
   * stat_client object
   */
  stat_client m_client;

  /**
   * stat index empty
   */
  const stat_indexes_t m_stat_index_empty;

  /**
   * static pointer to set of registered interfaces
   */
  static stat_indexes_t m_stat_itf_indexes;
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
