/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

/**
 * @file
 * @brief NAT syslog logging
 */
#ifndef __included_nat_syslog_h__
#define __included_nat_syslog_h__

#include <nat/lib/lib.h>
#include <nat/lib/nat_proto.h>

void nat_syslog_nat44_apmadd (u32 ssubix, u32 sfibix, ip4_address_t * isaddr,
			      u16 isport, ip4_address_t * xsaddr, u16 xsport,
			      nat_protocol_t proto);

void nat_syslog_nat44_apmdel (u32 ssubix, u32 sfibix, ip4_address_t * isaddr,
			      u16 isport, ip4_address_t * xsaddr, u16 xsport,
			      nat_protocol_t proto);

void
nat_syslog_dslite_apmadd (u32 ssubix, ip6_address_t * sv6enc,
			  ip4_address_t * isaddr, u16 isport,
			  ip4_address_t * xsaddr, u16 xsport,
			  nat_protocol_t proto);

void
nat_syslog_dslite_apmdel (u32 ssubix, ip6_address_t * sv6enc,
			  ip4_address_t * isaddr, u16 isport,
			  ip4_address_t * xsaddr, u16 xsport,
			  nat_protocol_t proto);

void nat_syslog_nat64_sadd (u32 sfibix, ip6_address_t * isaddr, u16 isport,
			    ip4_address_t * xsaddr, u16 xsport,
			    ip4_address_t * xdaddr, u16 xdport,
			    nat_protocol_t proto);

void nat_syslog_nat64_sdel (u32 sfibix, ip6_address_t * isaddr, u16 isport,
			    ip4_address_t * xsaddr, u16 xsport,
			    ip4_address_t * xdaddr, u16 xdport,
			    nat_protocol_t proto);

#endif /* __included_nat_syslog_h__ */
