/*
 * Copyright (c) 2011-2016 Cisco and/or its affiliates.
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
#ifndef __included_lldp_protocol_h__
#define __included_lldp_protocol_h__
/**
 * @file
 * @brief LLDP protocol declarations
 */
#include <vnet/srp/packet.h>

/*
 * optional TLV codes.
 */
#define foreach_lldp_optional_tlv_type(F) \
  F (4, port_desc, "Port Description")    \
  F (5, sys_name, "System name")          \
  F (6, sys_desc, "System Description")   \
  F (7, sys_caps, "System Capabilities")  \
  F (8, mgmt_addr, "Management Address")  \
  F (127, org_spec, "Organizationally Specific TLV")

/*
 * all TLV codes.
 */
#define foreach_lldp_tlv_type(F)  \
  F (0, pdu_end, "End of LLDPDU") \
  F (1, chassis_id, "Chassis ID") \
  F (2, port_id, "Port ID")       \
  F (3, ttl, "Time To Live")      \
  foreach_lldp_optional_tlv_type (F)

#define LLDP_TLV_NAME(t) LLDP_TLV_##t

typedef enum
{
#define F(n, t, s) LLDP_TLV_NAME (t) = n,
  foreach_lldp_tlv_type (F)
#undef F
} lldp_tlv_code_t;

struct lldp_tlv_head
{
  u8 byte1;			/* contains TLV code in the upper 7 bits + MSB of length */
  u8 byte2;			/* contains the lower bits of length */
};

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  struct lldp_tlv_head head;
  u8 v[0];
}) lldp_tlv_t;
/* *INDENT-ON* */

lldp_tlv_code_t lldp_tlv_get_code (const lldp_tlv_t * tlv);
void lldp_tlv_set_code (lldp_tlv_t * tlv, lldp_tlv_code_t code);
u16 lldp_tlv_get_length (const lldp_tlv_t * tlv);
void lldp_tlv_set_length (lldp_tlv_t * tlv, u16 length);

#define foreach_chassis_id_subtype(F)      \
  F (0, reserved, "Reserved")              \
  F (1, chassis_comp, "Chassis component") \
  F (2, intf_alias, "Interface alias")     \
  F (3, port_comp, "Port component")       \
  F (4, mac_addr, "MAC address")           \
  F (5, net_addr, "Network address")       \
  F (6, intf_name, "Interface name")       \
  F (7, local, "Locally assigned")

#define LLDP_CHASS_ID_SUBTYPE_NAME(t) LLDP_CHASS_ID_SUBTYPE_##t
#define LLDP_MIN_CHASS_ID_LEN (1)
#define LLDP_MAX_CHASS_ID_LEN (255)

typedef enum
{
#define F(n, t, s) LLDP_CHASS_ID_SUBTYPE_NAME (t) = n,
  foreach_chassis_id_subtype (F)
#undef F
} lldp_chassis_id_subtype_t;

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  struct lldp_tlv_head head;
  u8 subtype;
  u8 id[0];
}) lldp_chassis_id_tlv_t;
/* *INDENT-ON* */

#define foreach_port_id_subtype(F)            \
  F (0, reserved, "Reserved")                 \
  F (1, intf_alias, "Interface alias")        \
  F (2, port_comp, "Port component")          \
  F (3, mac_addr, "MAC address")              \
  F (4, net_addr, "Network address")          \
  F (5, intf_name, "Interface name")          \
  F (6, agent_circuit_id, "Agent circuit ID") \
  F (7, local, "Locally assigned")

#define LLDP_PORT_ID_SUBTYPE_NAME(t) LLDP_PORT_ID_SUBTYPE_##t
#define LLDP_MIN_PORT_ID_LEN (1)
#define LLDP_MAX_PORT_ID_LEN (255)

typedef enum
{
#define F(n, t, s) LLDP_PORT_ID_SUBTYPE_NAME (t) = n,
  foreach_port_id_subtype (F)
#undef F
} lldp_port_id_subtype_t;

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  struct lldp_tlv_head head;
  u8 subtype;
  u8 id[0];
}) lldp_port_id_tlv_t;

typedef CLIB_PACKED (struct {
  struct lldp_tlv_head head;
  u16 ttl;
}) lldp_ttl_tlv_t;
/* *INDENT-ON* */

#endif /* __included_lldp_protocol_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
