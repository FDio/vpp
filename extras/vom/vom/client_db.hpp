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

#ifndef __VOM_KEY_DB_H__
#define __VOM_KEY_DB_H__

#include <map>
#include <set>

#include "vom/object_base.hpp"

namespace VOM {
/**
 * A convenitent typedef for set of objects owned.
 *  A set of shared pointers. This is how the reference counting
 *  of an object in the model it managed. Once all these shared ptr
 *  and hence references are gone, the object is deleted and any state
 *  in VPP is removed.
 */
typedef std::set<object_ref> object_ref_list;

/**
 * A DB storing the objects that each owner/key owns.
 *  Each object is reference counter by each key that owns it. When
 * no more references exist the object is destroyed.
 */
class client_db
{
public:
  /**
   * In the opflex world each entity is known by a URI which can be
   * converted
   * into a string. We use the string type, since it allows us to keep
   * this VPP
   * specific code independent of opflex types. I might consider making
   * this
   * a template parameter one day...
   */
  typedef const std::string key_t;

  /**
   * Find the objects owned by the key
   */
  object_ref_list& find(const key_t& k);

  /**
   * flush, i.e. un-reference, all objects owned by the key
   */
  void flush(const key_t& k);

  /**
   * Print each of the object in the DB into the stream provided
   */
  void dump(const key_t& key, std::ostream& os);

  /**
   * Print each KEY
   */
  void dump(std::ostream& os);

private:
  /**
   * A map of keys versus the object they reference
   */
  std::map<key_t, object_ref_list> m_objs;
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
