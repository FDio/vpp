/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include "vom/cmd.hpp"

using namespace VOM;

/**
 * Free ostream function to print a command
 */
std::ostream &VOM::operator<<(std::ostream &os, const cmd &cmd)
{
    os << cmd.to_string();

    return (os);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
