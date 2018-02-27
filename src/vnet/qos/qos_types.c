/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

/**
 * QoS tyeps
 */

#include <vnet/qos/qos_types.h>

static const char *qos_source_names[] = QOS_SOURCE_NAMES;

u8 *
format_qos_source (u8 * s, va_list * args)
{
  int qs = va_arg (*args, int);

  return (format (s, "%s", qos_source_names[qs]));
}

uword
unformat_qos_source (unformat_input_t * input, va_list * args)
{
  int *qs = va_arg (*args, int *);

  if (unformat (input, "ip"))
    *qs = QOS_SOURCE_IP;
  else if (unformat (input, "mpls"))
    *qs = QOS_SOURCE_MPLS;
  else if (unformat (input, "ext"))
    *qs = QOS_SOURCE_EXT;
  else if (unformat (input, "vlan"))
    *qs = QOS_SOURCE_VLAN;
  else
    return 0;

  return 1;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
