/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#ifndef __IP_FLOW_HASH_H__
#define __IP_FLOW_HASH_H__

/** Default: 5-tuple + flowlabel without the "reverse" bit */
#define IP_FLOW_HASH_DEFAULT (0x9F)

#define foreach_flow_hash_bit_v1                                              \
  _ (src, IP_FLOW_HASH_SRC_ADDR)                                              \
  _ (dst, IP_FLOW_HASH_DST_ADDR)                                              \
  _ (sport, IP_FLOW_HASH_SRC_PORT)                                            \
  _ (dport, IP_FLOW_HASH_DST_PORT)                                            \
  _ (proto, IP_FLOW_HASH_PROTO)                                               \
  _ (reverse, IP_FLOW_HASH_REVERSE_SRC_DST)                                   \
  _ (symmetric, IP_FLOW_HASH_SYMMETRIC)

#define foreach_flow_hash_bit                                                 \
  _ (src, 0, IP_FLOW_HASH_SRC_ADDR)                                           \
  _ (dst, 1, IP_FLOW_HASH_DST_ADDR)                                           \
  _ (sport, 2, IP_FLOW_HASH_SRC_PORT)                                         \
  _ (dport, 3, IP_FLOW_HASH_DST_PORT)                                         \
  _ (proto, 4, IP_FLOW_HASH_PROTO)                                            \
  _ (reverse, 5, IP_FLOW_HASH_REVERSE_SRC_DST)                                \
  _ (symmetric, 6, IP_FLOW_HASH_SYMMETRIC)                                    \
  _ (flowlabel, 7, IP_FLOW_HASH_FL)

/**
 * A flow hash configuration is a mask of the flow hash options
 */
typedef enum flow_hash_config_t_
{
#define _(a, b, c) c = (1 << b),
  foreach_flow_hash_bit
#undef _
} flow_hash_config_t;

#endif /* __IP_TYPES_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
