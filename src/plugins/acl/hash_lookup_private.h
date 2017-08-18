/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */

#define ACL_HASH_LOOKUP_DEBUG 0

#if ACL_HASH_LOOKUP_DEBUG == 1
#define DBG0(...) clib_warning(__VA_ARGS__)
#define DBG(...)
#define DBG_UNIX_LOG(...)
#elif ACL_HASH_LOOKUP_DEBUG == 2
#define DBG0(...) clib_warning(__VA_ARGS__)
#define DBG(...) clib_warning(__VA_ARGS__)
#define DBG_UNIX_LOG(...) clib_unix_warning(__VA_ARGS__)
#else
#define DBG0(...)
#define DBG(...)
#define DBG_UNIX_LOG(...)
#endif

