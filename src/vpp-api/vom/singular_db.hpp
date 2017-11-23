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

#ifndef __VOM_INST_DB_H__
#define __VOM_INST_DB_H__

#include <memory>
#include <ostream>

#include "vom/logger.hpp"

namespace VOM {
/**
 * A Database to store the unique 'singular' instances of a single object
 * type.
 * The instances are stored as weak pointers. So the DB does not own these
 * objects, they are owned by object in the client_db.
 */
template <typename KEY, typename OBJ>
class singular_db
{
public:
  /**
   * Constructor
   */
  singular_db() {}

  /**
   * Iterator
   */
  typedef
    typename std::map<KEY, std::weak_ptr<OBJ>>::const_iterator const_iterator;

  /**
   * Get iterator to the beginning of the DB
   */
  const_iterator cbegin() { return m_map.cbegin(); }

  /**
   * Get iterator to the beginning of the DB
   */
  const_iterator cend() { return m_map.cend(); }

  /**
   * Find or add the object to the store.
   * The object passed is deisred state. A new instance will be copy
   * constructed from it. This function is templatised on the object type
   * passed, which may be drrived from, the object type stored. this
   * prevents slicing during the make_shared construction.
   */
  template <typename DERIVED>
  std::shared_ptr<OBJ> find_or_add(const KEY& key, const DERIVED& obj)
  {
    auto search = m_map.find(key);

    if (search == m_map.end()) {
      std::shared_ptr<OBJ> sp = std::make_shared<DERIVED>(obj);

      m_map[key] = sp;

      VOM_LOG(log_level_t::DEBUG) << *sp;
      return (sp);
    }

    return (search->second.lock());
  }

  /**
   * Find the object to the store.
   */
  std::shared_ptr<OBJ> find(const KEY& key)
  {
    auto search = m_map.find(key);

    if (search == m_map.end()) {
      std::shared_ptr<OBJ> sp(NULL);

      return (sp);
    }

    return (search->second.lock());
  }

  /**
   * Release the object from the DB store, if it's the one we have stored
   */
  void release(const KEY& key, const OBJ* obj)
  {
    auto search = m_map.find(key);

    if (search != m_map.end()) {
      if (search->second.expired()) {
        m_map.erase(key);
      } else {
        std::shared_ptr<OBJ> sp = m_map[key].lock();

        if (sp.get() == obj) {
          m_map.erase(key);
        }
      }
    }
  }

  /**
   * Find the object to the store.
   */
  void add(const KEY& key, std::shared_ptr<OBJ> sp) { m_map[key] = sp; }

  /**
   * Print each of the object in the DB into the stream provided
   */
  void dump(std::ostream& os)
  {
    for (auto entry : m_map) {
      os << "key: " << entry.first << std::endl;
      os << "  " << entry.second.lock()->to_string() << std::endl;
    }
  }

  /**
   * Populate VPP from current state, on VPP restart
   */
  void replay()
  {
    for (auto entry : m_map) {
      entry.second.lock()->replay();
    }
  }

private:
  /**
   * the map of objects against their key
   */
  std::map<const KEY, std::weak_ptr<OBJ>> m_map;
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
