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
#include <sstream>

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

  /*
   * not allowed to construct
   */
  log_level_t() = delete;
};

/**
 * Ideally we'd use the boost logger but that is not prevelent
 * in many distros. So something simple here instead.
 */
class log_t
{
public:
  /**
   *
   */
  class handler
  {
  public:
    /**
   * Default Constructor
   */
    handler() = default;

    /**
     * Default Destructor
     */
    virtual ~handler() = default;

    /**
     * Handle a log message
     */
    virtual void handle_message(const std::string& file,
                                const int line,
                                const std::string& function,
                                const log_level_t& level,
                                const std::string& message) = 0;
  };

  /**
   * Construct a logger
   */
  log_t(handler* h);
  log_t();

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
  void set(handler* h);

  /**
   * An entry in the log
   */
  class entry
  {
  public:
    entry(const char* file,
          const char* function,
          int line,
          const log_level_t& level);
    ~entry();

    std::stringstream& stream();

  private:
    const std::string m_file;
    const std::string m_function;
    const log_level_t m_level;
    const int m_line;

    std::stringstream m_stream;
  };
  /**
   * Register a log handler to receive the log output
   */
  void register_handler(handler& h);

private:
  void write(const std::string& file,
             const int line,
             const std::string& function,
             const log_level_t& level,
             const std::string& message);

  /**
   * the configured logging level
   */
  log_level_t m_level;

  /**
   * Pointer to a registered handler. Null if no handler registerd
   */
  handler* m_handler;
};

class file_handler : public log_t::handler
{
public:
  file_handler(const std::string& ofile);
  ~file_handler();

  virtual void handle_message(const std::string& file,
                              const int line,
                              const std::string& function,
                              const log_level_t& level,
                              const std::string& message);

private:
  /**
   * Opened file for debugging
   */
  std::ofstream m_file_stream;
};

class cout_handler : public log_t::handler
{
public:
  cout_handler() = default;
  ~cout_handler() = default;
  virtual void handle_message(const std::string& file,
                              const int line,
                              const std::string& function,
                              const log_level_t& level,
                              const std::string& message);
};

/**
 * Return a log object into which VPP objects can write
 */
log_t& logger();

#define VOM_LOG(lvl)                                                           \
  if (lvl >= logger().level())                                                 \
  log_t::entry(__FILE__, __FUNCTION__, __LINE__, lvl).stream()
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
