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

#ifndef included_linux_syscall_h
#define included_linux_syscall_h

#include <unistd.h>
#include <sys/syscall.h>

static inline long
set_mempolicy (int mode, const unsigned long *nodemask, unsigned long maxnode)
{
  return syscall (__NR_set_mempolicy, mode, nodemask, maxnode);
}

static inline int
get_mempolicy (int *mode, unsigned long *nodemask, unsigned long maxnode,
	       void *addr, unsigned long flags)
{
  return syscall (__NR_get_mempolicy, mode, nodemask, maxnode, addr, flags);
}

static inline long
move_pages (int pid, unsigned long count, void **pages, const int *nodes,
	    int *status, int flags)
{
  return syscall (__NR_move_pages, pid, count, pages, nodes, status, flags);
}

static inline int
memfd_create (const char *name, unsigned int flags)
{
  return syscall (__NR_memfd_create, name, flags);
}

#endif /* included_linux_syscall_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
