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

#ifndef __VOM_INSPECT_H__
#define __VOM_INSPECT_H__

#include <deque>
#include <map>
#include <memory>
#include <ostream>
#include <string>
#include <vector>

namespace VOM {
/**
 * A means to inspect the state VPP has built, in total, and per-client
 */
class inspect
{
public:
  /**
   * Constructor
   */
  inspect() = default;

  /**
   * Destructor to tidyup socket resources
   */
  ~inspect() = default;

  /**
   * handle input from the requester
   *
   * @param input command
   * @param output output
   */
  void handle_input(const std::string& input, std::ostream& output);

  /**
   * inspect command handler Handler
   */
  class command_handler
  {
  public:
    command_handler() = default;
    virtual ~command_handler() = default;

    /**
     * Show each object
     */
    virtual void show(std::ostream& os) = 0;
  };

  /**
   * Register a command handler for inspection
   */
  static void register_handler(const std::vector<std::string>& cmds,
                               const std::string& help,
                               command_handler* ch);

private:
  /**
   * command handler list
   */
  static std::unique_ptr<std::map<std::string, command_handler*>>
    m_cmd_handlers;
  /**
   * help handler list
   */
  static std::unique_ptr<
    std::deque<std::pair<std::vector<std::string>, std::string>>>
    m_help_handlers;
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
