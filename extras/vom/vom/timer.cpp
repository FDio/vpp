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

#include "vom/timer.hpp"

using boost::asio::deadline_timer;

namespace VOM {

timer::timer(boost::asio::io_service& io, long sec)
  : m_timer(io, boost::posix_time::seconds(sec))
  , m_sec(sec)
  , m_poll(0)
{
  // m_timer.async_wait(boost::bind(&timer::timed_poll, this));
}

timer::~timer()
{
  m_timer.cancel();
}

void
timer::set(bool off)
{
  m_poll = off;
}

void
timer::timed_poll(stat_data_t* (*f)(uint32_t), uint32_t index, stat_data_t* st)
{
  if (m_poll) {
    st = f(index);
    m_timer.expires_from_now(boost::posix_time::seconds(m_sec));
    m_timer.async_wait(boost::bind(&timer::timed_poll, this, f, index, st));
  }
}
} // namespace

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
