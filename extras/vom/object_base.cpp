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

#include "vom/object_base.hpp"

namespace VOM {
object_ref::object_ref(std::shared_ptr<object_base> obj)
  : m_obj(obj)
  , m_state(OBJECT_STATE_NONE)
{
}

bool
object_ref::operator<(const object_ref& other) const
{
  return (m_obj.get() < other.m_obj.get());
}

std::shared_ptr<object_base>
object_ref::obj() const
{
  return (m_obj);
}

void
object_ref::mark() const
{
  m_state = OBJECT_STATE_STALE;
}

void
object_ref::clear() const
{
  m_state = OBJECT_STATE_NONE;
}

bool
object_ref::stale() const
{
  return (m_state == OBJECT_STATE_STALE);
}

std::ostream&
operator<<(std::ostream& os, const object_base& o)
{
  os << o.to_string();

  return (os);
}
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
