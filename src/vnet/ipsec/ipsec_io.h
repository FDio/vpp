/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#ifndef __IPSEC_IO_H__
#define __IPSEC_IO_H__

#define foreach_ipsec_output_next  \
  _ (DROP, "error-drop")

#define _(v, s) IPSEC_OUTPUT_NEXT_##v,
typedef enum
{
  foreach_ipsec_output_next
#undef _
    IPSEC_OUTPUT_N_NEXT,
} ipsec_output_next_t;

#define foreach_ipsec_input_next   \
  _ (PUNT, "punt-dispatch")        \
  _ (DROP, "error-drop")

#define _(v, s) IPSEC_INPUT_NEXT_##v,
typedef enum
{
  foreach_ipsec_input_next
#undef _
    IPSEC_INPUT_N_NEXT,
} ipsec_input_next_t;


typedef struct
{
  u32 spd_index;
} ip4_ipsec_config_t;

typedef struct
{
  u32 spd_index;
} ip6_ipsec_config_t;

#endif /* __IPSEC_IO_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
