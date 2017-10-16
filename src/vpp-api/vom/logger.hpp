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

#ifndef __VOM_LOGGER_H__
#define __VOM_LOGGER_H__

#include <boost/log/sources/logger.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/trivial.hpp>

using levels = boost::log::trivial::severity_level;

namespace VOM
{
    /**
     * We use the boost logging library.
     * the expectation is the client configures the sinks as it desires
     */
    typedef boost::log::sources::severity_logger_mt<boost::log::trivial::severity_level> log_t;

    /**
     * Return a log object into which VPP objects can write
     */
    log_t &logger();
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
