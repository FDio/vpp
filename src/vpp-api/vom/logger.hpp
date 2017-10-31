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

#include <fstream>
#include <iostream>

#include "vom/enum_base.hpp"

namespace VOM {
struct log_level_t : enum_base<log_level_t>
{
  const static log_level_t CRITICAL;
  const static log_level_t ERROR;
  const static log_level_t WARNING;
  const static log_level_t INFO;
  const static log_level_t DEBUG;

private:
  /**
   * Private constructor taking the value and the string name
   */
  log_level_t(int v, const std::string& s);
};

/**
 * Ideally we'd use the boost logger but that is not prevelent
 * in many distros. So something simple here instead.
 */
class log_t
{
public:
  /**
   * Construct a logger
   */
  log_t();

  /**
   * Return the stream
   */
  std::ostream& stream(const char* file, int line);

  /**
   * The configured level
   */
  const log_level_t& level() const;

  /**
   * set the logging level
   */
  void set(const log_level_t& level);

  /**
   * set a file to receive the logging data
   */
  void set(const std::string& ofile);

private:
  /**
   * the configured logging level
   */
  log_level_t m_level;

  /**
   * Opened file for debugging
   */
  std::ofstream m_file_stream;

  /**
   * Pointer to the output stream
   */
  std::ostream* m_o_stream;
};

/**
 * Return a log object into which VPP objects can write
 */
log_t& logger();

#define VOM_LOG(lvl)                                                           \
  if (lvl >= logger().level())                                                 \
  logger().stream(__FILE__, __LINE__)
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
