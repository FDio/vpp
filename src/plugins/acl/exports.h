/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#ifndef included_acl_exports_h
#define included_acl_exports_h

/*
 * This file contains the declarations for external consumption,
 * along with the necessary dependent includes.
 */

#define ACL_PLUGIN_EXTERNAL_EXPORTS

#include <vlib/unix/plugin.h>

#include "acl.h"
#include "fa_node.h"
#include "public_inlines.h"

#endif /* included_acl_exports_h */
