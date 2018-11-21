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

#include "vom/stat_class.hpp"

namespace VOM {

stat_class::stat_class() {}

stat_class::~stat_class() {}

void
stat_class::register_stat_listener(handle_t h, interface::stat_listener& sl)
{
  m_stat_listeners.insert(
    std::pair<handle_t, interface::stat_listener&>(h, sl));
}

void
stat_class::unregister_stat_listener(handle_t h)
{
  m_stat_listeners.erase(h);
}

void
stat_class::notify()
{}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
}
