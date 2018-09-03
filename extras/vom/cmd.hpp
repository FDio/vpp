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

#ifndef __VOM_CMD_H__
#define __VOM_CMD_H__

#include <string>

#include "vom/types.hpp"

namespace VOM {
/**
 * Forward declaration of the connection class
 */
class connection;

/**
 * A representation of a method call to VPP
 */
class cmd
{
public:
  /**
   * Default constructor
   */
  cmd() {}
  /**
   * Virtual destructor
   */
  virtual ~cmd() {}

  /**
   * Issue the command to VPP/HW
   */
  virtual rc_t issue(connection& con) = 0;

  /**
   * Retire/cancel a long running command
   */
  virtual void retire(connection& con) = 0;

  /**
   * Invoked on a Command when the HW queue is disabled to indicate
   * that the commnad can be considered successful
   */
  virtual void succeeded() = 0;

  /**
   * convert to string format for debug purposes
   */
  virtual std::string to_string() const = 0;
};

/**
 * Free ostream function to print a command
 */
std::ostream& operator<<(std::ostream& os, const cmd& cmd);
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
