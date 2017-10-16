/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __VOM_ENUM_H__
#define __VOM_ENUM_H__

#include <string>

namespace VOM
{
    /**
     * Atemplate base class for all enum types.
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
        const std::string &to_string() const
        {
            return (m_desc);
        }

        /**
         * Comparison operator
         */
        bool operator==(const enum_base &e) const
        {
            return (e.m_value == m_value);
        }

        /**
         * Assignemet
         */
        enum_base &operator=(const enum_base &e)
        {
            m_value = e.m_value;
            m_desc = e.m_desc;

            return (*this);
        }

        /**
         * Comparison operator
         */
        bool operator!=(const enum_base &e) const
        {
            return (e.m_value != m_value);
        }

        /**
         * integer conversion operator
         */
        constexpr operator int() const
        {
            return (m_value);
        }

        /**
         * Return the value of the enum - same as integer conversion
         */
        constexpr int value() const
        {
            return (m_value);
        }

      protected:
        /**
         * Constructor of an enum - takes value and string description
         */
        constexpr enum_base(int value,
                            const std::string desc)
          : m_value(value), m_desc(desc)
        {
        }

        /**
         * Constructor
         */
        virtual ~enum_base()
        {
        }

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
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
