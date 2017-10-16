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

#include "vom/client_db.hpp"

namespace VOM {
object_ref_list&
client_db::find(const client_db::key_t& k)
{
  return (m_objs[k]);
}

void
client_db::flush(const client_db::key_t& k)
{
  m_objs.erase(m_objs.find(k));
}

void
client_db::dump(const key_t& key, std::ostream& os)
{
  object_ref_list& orlist = find(key);

  for (auto entry : orlist) {
    os << "  " << entry.obj()->to_string() << std::endl;
  }
}

void
client_db::dump(std::ostream& os)
{
  for (auto entry : m_objs) {
    os << "  key:[" << entry.first << "]" << std::endl;
  }
}
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
