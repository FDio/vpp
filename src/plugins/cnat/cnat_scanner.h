/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#ifndef __CNAT_SCANNER_H__
#define __CNAT_SCANNER_H__

#include <vnet/ip/ip.h>

/* delay in seconds between two scans of session/clients tables */
extern f64 cnat_scanner_timeout;

#endif
