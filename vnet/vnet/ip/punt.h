/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

/**
 * @file
 * @brief Definitions for punt infrastructure.
 */
#ifndef included_punt_h
#define included_punt_h

typedef enum
{
#define punt_error(n,s) PUNT_ERROR_##n,
#include <vnet/ip/punt_error.def>
#undef punt_error
  PUNT_N_ERROR,
} punt_error_t;


clib_error_t *vnet_punt_add_del (vlib_main_t * vm, u8 ipv,
				 u8 protocol, u16 port, int is_add);

#endif /* included_punt_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
