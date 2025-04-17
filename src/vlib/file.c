/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <limits.h>

clib_file_main_t file_main;

