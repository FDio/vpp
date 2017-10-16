/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <boost/algorithm/string.hpp>
#include <cassert>
#include <string>
#include <vector>

#include "vom/inspect.hpp"
#include "vom/logger.hpp"
#include "vom/om.hpp"

using namespace VOM;

std::unique_ptr<std::map<std::string, inspect::command_handler *>> inspect::m_cmd_handlers;

std::unique_ptr<std::deque<std::pair<std::vector<std::string>, std::string>>> inspect::m_help_handlers;

void inspect::handle_input(const std::string &message,
                           std::ostream &output)
{
    if (message.length())
    {
        if (message.find("help") != std::string::npos)
        {
            output << "Command Options: " << std::endl;
            output << "  keys              - Show all keys owning objects" << std::endl;
            output << "  key:XXX           - Show all object referenced by key XXX" << std::endl;
            output << "  all               - Show All objects" << std::endl;
            output << "Individual object_base Types:" << std::endl;

            for (auto h : *m_help_handlers)
            {
                output << "  {";

                for (auto s : h.first)
                {
                    output << s << " ";
                }
                output << "} - \t";
                output << h.second;
                output << std::endl;
            }
        }
        else if (message.find("keys") != std::string::npos)
        {
            OM::dump(output);
        }
        else if (message.find("key") != std::string::npos)
        {
            std::vector<std::string> results;
            boost::split(results, message, boost::is_any_of(":\n"));

            OM::dump(results[1], output);
        }
        else if (message.find("all") != std::string::npos)
        {
            /*
             * get the unique set of handlers, then invoke each
             */
            std::set<command_handler *> hdlrs;
            for (auto h : *m_cmd_handlers)
            {
                hdlrs.insert(h.second);
            }
            for (auto h : hdlrs)
            {
                h->show(output);
            }
        }
        else
        {
            auto it = m_cmd_handlers->find(message);

            if (it != m_cmd_handlers->end())
            {
                it->second->show(output);
            }
            else
            {
                output << "Unknown Command: " << message << std::endl;
            }
        }
    }
}

void inspect::register_handler(const std::vector<std::string> &cmds,
                               const std::string &help,
                               command_handler *handler)
{
    if (!m_cmd_handlers)
    {
        m_cmd_handlers.reset(new std::map<std::string, command_handler *>);
        m_help_handlers.reset(new std::deque<std::pair<std::vector<std::string>,
                                                       std::string>>);
    }

    for (auto cmd : cmds)
    {
        (*m_cmd_handlers)[cmd] = handler;
    }
    m_help_handlers->push_front(std::make_pair(cmds, help));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
