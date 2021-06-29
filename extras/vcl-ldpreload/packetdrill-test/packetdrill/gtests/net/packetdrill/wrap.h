/*
 * Copyright 2013 Google Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */
/*
 * Wrappers for making L3-independent syscalls.
 */

#ifndef __WRAP_H__
#define __WRAP_H__

#include "config.h"
#include "types.h"

extern int wrap_socket (enum ip_version_t ip_version, int type);
extern u16 wrap_bind_listen (int fd, enum ip_version_t ip_version, u16 port);

#endif /* __WRAP_H__ */
