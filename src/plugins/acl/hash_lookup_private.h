/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Cisco and/or its affiliates.
 */

#define ACL_HASH_LOOKUP_DEBUG 0

#if ACL_HASH_LOOKUP_DEBUG == 1
#define DBG0(...) clib_warning(__VA_ARGS__)
#define DBG(...)
#define DBG_UNIX_LOG(...)
#elif ACL_HASH_LOOKUP_DEBUG == 2
#define DBG0(...) clib_warning(__VA_ARGS__)
#define DBG(...) do { void *prevheap = clib_mem_set_heap (vlib_global_main.heap_base); vlib_cli_output(&vlib_global_main, __VA_ARGS__); clib_mem_set_heap (prevheap); } while (0)
#define DBG_UNIX_LOG(...) clib_unix_warning(__VA_ARGS__)
#else
#define DBG0(...)
#define DBG(...)
#define DBG_UNIX_LOG(...)
#endif

