/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

/**
 * QoS types
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
