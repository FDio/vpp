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
  /**
   * Default Constructor
   */
  stat_reader();

  /**
   * Destructor
   */
  ~stat_reader();

  /**
    * read stats for registered objects from stat_segment
    * and set those stats to respective objects
    */
  static void read();

private:
  /**
   * friend to interface class to call stat_register and
   * stat_unregister methods
   */
  friend class interface;

  /**
   * Register objects to get stats for
   */
  static void stat_register(const interface& itf);

  /**
   * Unregister objects
   */
  static void stat_unregister(const interface& itf);

  /**
   * typedef of stat_indexes
   */
  typedef std::set<uint32_t> stat_indexes_t;

  /**
   * static pointer to stat_client
   */
  static stat_client* m_client;

  /**
   * static pointer to set of registered interfaces
   */
  static stat_indexes_t* m_stat_itf_indexes;
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
