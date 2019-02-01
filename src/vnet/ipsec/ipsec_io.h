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

#define IPSEC_FLAG_IPSEC_GRE_TUNNEL (1 << 0)

#define foreach_ipsec_output_next  \
  _ (DROP, "error-drop")           \
  _ (ESP4_ENCRYPT, "esp4-encrypt") \
  _ (AH4_ENCRYPT, "ah4-encrypt")   \
  _ (ESP6_ENCRYPT, "esp6-encrypt") \
  _ (AH6_ENCRYPT, "ah6-encrypt")

#define _(v, s) IPSEC_OUTPUT_NEXT_##v,
typedef enum
{
  foreach_ipsec_output_next
#undef _
    IPSEC_OUTPUT_N_NEXT,
} ipsec_output_next_t;

#define foreach_ipsec_input_next   \
  _ (DROP, "error-drop")           \
  _ (ESP4_DECRYPT, "esp4-decrypt") \
  _ (AH4_DECRYPT, "ah4-decrypt")   \
  _ (ESP6_DECRYPT, "esp6-decrypt") \
  _ (AH6_DECRYPT, "ah6-decrypt")

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
