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

#ifndef __NR_memfd_create
#if defined __x86_64__
#define __NR_memfd_create 319
#elif defined __arm__
#define __NR_memfd_create 385
#elif defined __aarch64__
#define __NR_memfd_create 279
#else
#error "__NR_memfd_create unknown for this architecture"
#endif
#endif

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

#ifndef F_LINUX_SPECIFIC_BASE
#define F_LINUX_SPECIFIC_BASE 1024
#endif
#define MFD_ALLOW_SEALING       0x0002U
#define F_ADD_SEALS (F_LINUX_SPECIFIC_BASE + 9)
#define F_GET_SEALS (F_LINUX_SPECIFIC_BASE + 10)

#define F_SEAL_SEAL     0x0001	/* prevent further seals from being set */
#define F_SEAL_SHRINK   0x0002	/* prevent file from shrinking */
#define F_SEAL_GROW     0x0004	/* prevent file from growing */
#define F_SEAL_WRITE    0x0008	/* prevent writes */


#endif /* included_linux_syscall_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
