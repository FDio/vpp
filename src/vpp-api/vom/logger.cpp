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

#include <chrono>
#include <ctime>
#include <vector>

#include <boost/algorithm/string.hpp>

#include "vom/logger.hpp"

namespace VOM {
const log_level_t log_level_t::CRITICAL(4, "critical");
const log_level_t log_level_t::ERROR(3, "error");
const log_level_t log_level_t::WARNING(2, "warning");
const log_level_t log_level_t::INFO(1, "info");
const log_level_t log_level_t::DEBUG(0, "debug");

log_level_t::log_level_t(int v, const std::string& s)
  : enum_base<log_level_t>(v, s)
{
}

static log_t slog;

log_t&
logger()
{
  return slog;
}

log_t::log_t()
  : m_level(log_level_t::ERROR)
  , m_handler(new cout_handler())
{
}

void
log_t::set(const log_level_t& level)
{
  m_level = level;
}

void
log_t::set(handler* h)
{
  m_handler = h;
}

void
log_t::write(const std::string& file,
             const int line,
             const std::string& function,
             const log_level_t& level,
             const std::string& message)
{
  m_handler->handle_message(file, line, function, level, message);
}

/**
 * The configured level
 */
const log_level_t&
log_t::level() const
{
  return (m_level);
}

static std::string
get_filename(const std::string& file)
{
  std::vector<std::string> dirs;
  boost::split(dirs, file, boost::is_any_of("/"));

  return dirs.back();
}

log_t::entry::entry(const char* file,
                    const char* function,
                    int line,
                    const log_level_t& level)
  : m_file(get_filename(file))
  , m_function(function)
  , m_level(level)
  , m_line(line)
{
}

log_t::entry::~entry()
{
  logger().write(m_file, m_line, m_function, m_level, m_stream.str());
}

std::stringstream&
log_t::entry::stream()
{
  return (m_stream);
}

static std::string
get_timestamp()
{
  auto end = std::chrono::system_clock::now();
  auto end_time = std::chrono::system_clock::to_time_t(end);

  /*
   * put-time is not support in gcc in 4.8
   * so we play this dance with ctime
   */
  std::string display = std::ctime(&end_time);
  display.pop_back();

  return (display);
}

file_handler::file_handler(const std::string& ofile)
{
  m_file_stream.open(ofile);
}

file_handler::~file_handler()
{
  m_file_stream.close();
}

void
file_handler::handle_message(const std::string& file,
                             const int line,
                             const std::string& function,
                             const log_level_t& level,
                             const std::string& message)
{
  m_file_stream << get_timestamp();
  m_file_stream << " [" << level.to_string() << "]" << file << ":" << line
                << " " << function << "() " << message << std::endl;
}

void
cout_handler::handle_message(const std::string& file,
                             const int line,
                             const std::string& function,
                             const log_level_t& level,
                             const std::string& message)
{
  std::cout << get_timestamp();
  std::cout << " [" << level.to_string() << "]" << file << ":" << line << " "
            << function << "() " << message << std::endl;
}

}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
