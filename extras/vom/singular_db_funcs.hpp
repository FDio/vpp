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

#ifndef __VOM_INST_DB_FUNCS_H__
#define __VOM_INST_DB_FUNCS_H__

#include <ostream>

#include "singular_db.hpp"

/**
 * A set of helper function to iterate over objects in the DB.
 * These functions are delcared not as DB member functions so that
 * the template instatiation of the DB does not require the definitions
 * of the functions used to be declared.
 */
namespace VOM {
/**
 * Print each of the objects in the DB into the stream provided
 */
template <typename DB>
void
db_dump(const DB& db, std::ostream& os)
{
  for (const auto entry : db) {
    os << "key: " << entry.first << std::endl;
    os << "  " << entry.second.lock()->to_string() << std::endl;
  }
}
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
