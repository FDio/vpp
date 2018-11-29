/*
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
 */
/**
 * @file
 * @brief NAT syslog logging
 */

#ifndef __included_nat_syslog_h__
#define __included_nat_syslog_h__

#include <nat/nat.h>

void nat_syslog_nat44_apmadd (u32 ssubix, u32 sfibix, ip4_address_t * isaddr,
			      u16 isport, ip4_address_t * xsaddr, u16 xsport,
			      snat_protocol_t proto);

void nat_syslog_nat44_apmdel (u32 ssubix, u32 sfibix, ip4_address_t * isaddr,
			      u16 isport, ip4_address_t * xsaddr, u16 xsport,
			      snat_protocol_t proto);

void
nat_syslog_dslite_apmadd (u32 ssubix, ip6_address_t * sv6enc,
			  ip4_address_t * isaddr, u16 isport,
			  ip4_address_t * xsaddr, u16 xsport,
			  snat_protocol_t proto);

void
nat_syslog_dslite_apmdel (u32 ssubix, ip6_address_t * sv6enc,
			  ip4_address_t * isaddr, u16 isport,
			  ip4_address_t * xsaddr, u16 xsport,
			  snat_protocol_t proto);

void nat_syslog_nat44_sadd (u32 ssubix, u32 sfibix, ip4_address_t * isaddr,
			    u16 isport, ip4_address_t * idaddr, u16 idport,
			    ip4_address_t * xsaddr, u16 xsport,
			    ip4_address_t * xdaddr, u16 xdport,
			    snat_protocol_t proto, u8 is_twicenat);

void nat_syslog_nat44_sdel (u32 ssubix, u32 sfibix, ip4_address_t * isaddr,
			    u16 isport, ip4_address_t * idaddr, u16 idport,
			    ip4_address_t * xsaddr, u16 xsport,
			    ip4_address_t * xdaddr, u16 xdport,
			    snat_protocol_t proto, u8 is_twicenat);

void nat_syslog_nat64_sadd (u32 sfibix, ip6_address_t * isaddr, u16 isport,
			    ip4_address_t * xsaddr, u16 xsport,
			    ip4_address_t * xdaddr, u16 xdport,
			    snat_protocol_t proto);

void nat_syslog_nat64_sdel (u32 sfibix, ip6_address_t * isaddr, u16 isport,
			    ip4_address_t * xsaddr, u16 xsport,
			    ip4_address_t * xdaddr, u16 xdport,
			    snat_protocol_t proto);

#endif /* __included_nat_syslog_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
