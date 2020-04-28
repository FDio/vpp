/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef __LCP_LOG_H__
#define __LCP_LOG_H__

#include <stdio.h>
#include <assert.h>

#define LCP_DBG(_c, _args...)                         \
  printf("DBG: %ld:%ld:%s:%d: " _c "\n", pthread_self(), time(NULL), __FILE__, __LINE__, ##_args);
#define LCP_INFO(_c, _args...)                         \
  printf("INFO: %s:%d: " _c "\n", __FILE__, __LINE__, ##_args);
#define LCP_ERROR(_c, _args...)                         \
  printf("ERROR: %s:%d: " _c "\n", __FILE__, __LINE__, ##_args);

#define LCP_ASSERT(_c) assert(_c);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
