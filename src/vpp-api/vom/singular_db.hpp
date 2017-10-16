/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __VOM_INST_DB_H__
#define __VOM_INST_DB_H__

#include <memory>
#include <ostream>

namespace VOM
{
    /**
     * A Database to store the unique 'singular' instances of a single object type.
     * The instances are stored as weak pointers. So the DB does not own these
     * objects, they are owned by object in the client_db.
     */
    template <typename KEY, typename OBJ>
    class singular_db
    {
      public:
        /**
         * Constructor
         */
        singular_db()
        {
        }

        /**
         * Iterator
         */
        typedef typename std::map<KEY, std::weak_ptr<OBJ>>::const_iterator const_iterator;

        /**
         * Get iterator to the beginning of the DB
         */
        const_iterator cbegin()
        {
            return m_map.cbegin();
        }

        /**
         * Get iterator to the beginning of the DB
         */
        const_iterator cend()
        {
            return m_map.cend();
        }

        /**
         * Find or add the object to the store.
         * The object passed is deisred state. A new instance will be copy
         * constructed from it. This function is templatised on the object type
         * passed, which may be drrived from, the object type stored. this
         * prevents slicing during the make_shared construction.
         */
        template <typename DERIVED>
        std::shared_ptr<OBJ> find_or_add(const KEY &key, const DERIVED &obj)
        {
            auto search = m_map.find(key);

            if (search == m_map.end())
            {
                std::shared_ptr<OBJ> sp = std::make_shared<DERIVED>(obj);

                m_map[key] = sp;

                BOOST_LOG_SEV(logger(), levels::debug) << *sp;
                return (sp);
            }

            return (search->second.lock());
        }

        /**
         * Find the object to the store.
         */
        std::shared_ptr<OBJ> find(const KEY &key)
        {
            auto search = m_map.find(key);

            if (search == m_map.end())
            {
                std::shared_ptr<OBJ> sp(NULL);

                return (sp);
            }

            return (search->second.lock());
        }

        /**
         * Release the object from the DB store, if it's the one we have stored
         */
        void release(const KEY &key, const OBJ *obj)
        {
            auto search = m_map.find(key);

            if (search != m_map.end())
            {
                if (search->second.expired())
                {
                    m_map.erase(key);
                }
                else
                {
                    std::shared_ptr<OBJ> sp = m_map[key].lock();

                    if (sp.get() == obj)
                    {
                        m_map.erase(key);
                    }
                }
            }
        }

        /**
         * Find the object to the store.
         */
        void add(const KEY &key, std::shared_ptr<OBJ> sp)
        {
            m_map[key] = sp;
        }

        /**
         * Print each of the object in the DB into the stream provided
         */
        void dump(std::ostream &os)
        {
            for (auto entry : m_map)
            {
                os << "key: " << entry.first << std::endl;
                os << "  " << entry.second.lock()->to_string() << std::endl;
            }
        }

        /**
         * Populate VPP from current state, on VPP restart
         */
        void replay()
        {
            for (auto entry : m_map)
            {
                entry.second.lock()->replay();
            }
        }

      private:
        /**
         * the map of objects against their key
         */
        std::map<KEY, std::weak_ptr<OBJ>> m_map;
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
