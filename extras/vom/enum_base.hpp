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

#ifndef __VOM_ENUM_H__
#define __VOM_ENUM_H__

#include <string>

namespace VOM {
/**
 * A template base class for all enum types.
 * This enum type exists to associate an enum value with a string for
 * display/debug purposes.
 * Concrete enum types use the CRTP. Derived classes thus inherit this
 * base's function, but are not polymorphic.
 */
template <typename T>
class enum_base
{
public:
  /**
   * convert to string format for debug purposes
   */
  const std::string& to_string() const { return (m_desc); }

  /**
   * Comparison operator
   */
  bool operator==(const enum_base& e) const { return (e.m_value == m_value); }

  /**
   * Assignment
   */
  enum_base& operator=(const enum_base& e)
  {
    m_value = e.m_value;
    m_desc = e.m_desc;

    return (*this);
  }

  /**
   * Comparison operator
   */
  bool operator!=(const enum_base& e) const { return (e.m_value != m_value); }

  /**
   * integer conversion operator
   */
  operator int() const { return (m_value); }

  /**
   * Return the value of the enum - same as integer conversion
   */
  int value() const { return (m_value); }

protected:
  /**
   * Constructor of an enum - takes value and string description
   */
  enum_base(int value, const std::string desc)
    : m_value(value)
    , m_desc(desc)
  {
  }

  /**
   * Constructor
   */
  virtual ~enum_base() {}

private:
  /**
   * Integer value of the enum
   */
  int m_value;

  /**
   * String description
   */
  std::string m_desc;
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
