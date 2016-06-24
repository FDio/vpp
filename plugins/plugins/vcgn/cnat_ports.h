/* 
 *------------------------------------------------------------------
 * cnat_ports.h - port database definitions
 *
 * Copyright (c) 2007-2013 Cisco and/or its affiliates.
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

#ifndef __CNAT_PORTS_H__
#define __CNAT_PORTS_H__

#include "platform_common.h"
#include "cnat_bulk_port_defs.h"

#define PORTS_PER_ADDR 65536 

#define CNAT_INSTS PLATFORM_CNAT_INSTS 

#define BITS_PER_INST (PORTS_PER_ADDR)

/*
 * Ensure that atleast few 4 bit ports are available for RTSP
 * in case we want to map 4 digit inside ports to 4 digit outside ports
 */
#define MIN_STATIC_PORT_RANGE_FOR_RTSP (9900)

extern u8 my_instance_number;

/*
 * Now it is a 1-to-1 mapping between bit and port values
 */
static inline u16 bit2port (u32 bit)
{
    return bit;
}

static inline uword port2bit (u16 port)
{
    return port;
}

/*
 * Port bitmap structure
 * THIS structure is not used to be REMOVED....
 */


typedef struct {
    u32 ipv4_address;           /* native bit order */
    u16 vrf;
    u16 pad;
    u32 threshold_crossed;
    uword bm[(BITS_PER_INST + BITS(uword)-1)/BITS(uword)];
} cnat_portmap_t;

//cnat_portmap_t *cnat_portmap;


typedef struct {
    u32 inuse;
    u32 delete_time;
    u32 ipv4_address;           /* native bit order */
    u32 last_sent_timestamp;
    uword bm[(BITS_PER_INST + BITS(uword)-1)/BITS(uword)];
    u32 dyn_full;
    u32 private_ip_users_count; /* number of private ip's(subscribers) to this
			   public ip */
} cnat_portmap_v2_t;


typedef enum {
    PORT_SINGLE=0,
    PORT_PAIR=1,
    PORT_S_EVEN=2,
    PORT_S_ODD=3,
} port_pair_t;

typedef enum {
    PORT_TYPE_DYNAMIC=0,
    PORT_TYPE_STATIC=1,
    PORT_TYPE_RTSP=2,
} port_type_t;


typedef enum {
    PORT_ALLOC_ANY=1,
    PORT_ALLOC_DIRECTED=2,
} port_alloc_t;

#define PORT_PROBE_LIMIT 20


/* 
 * randq1
 * Linear congruential random number generator with
 * extensively studied properties. See Numerical Recipes in C
 * 2nd Ed. page 284. Known to behave according to the test vector
 * supplied in the text, on X86 and Octeon.
 */
static inline u32 randq1 (u32 prev)
{
    return (1664525L*prev + 1013904223L);
}

cnat_errno_t
cnat_static_port_alloc_v2(
                  cnat_portmap_v2_t    *pm,
                  port_alloc_t          atype,
                  port_pair_t           pair_type,
                  u32                  i_ipv4_address,
                  u16                  i_port,
                  u32                  *index,
                  u32                  *o_ipv4_address,
                  u16                  *o_port,
                  u16                   static_port_range
#ifndef NO_BULK_LOGGING
                  , bulk_alloc_size_t    bulk_size,
                  int *nfv9_log_req
#endif /* NO_BULK_LOGGING */
		  , u16                   ip_n_to_1
                );

cnat_errno_t
cnat_mapped_static_port_alloc_v2 (
                     cnat_portmap_v2_t    *pm,
                     port_alloc_t         atype,
                     u32                  *index,
                     u32                   ipv4_address,
                     u16                   port
#ifndef NO_BULK_LOGGING
                     , int *nfv9_log_req,
                     bulk_alloc_size_t bulk_size
#endif 
		     , u16                   ip_n_to_1
                     );

cnat_errno_t
cnat_dynamic_port_alloc_v2(
                  cnat_portmap_v2_t *pm,
                  port_alloc_t       atype,
                  port_pair_t        pair_type,
                  u32               *index,
                  u32               *o_ipv4_address,
                  u16               *o_port,
                  u16               static_port_range
#ifndef NO_BULK_LOGGING
                    , bulk_alloc_size_t bulk_size,
                    int *nfv9_log_req
#endif
                  , u16                ip_n_to_1,
                  u32               *rseed_ip
                  );


cnat_errno_t
cnat_dynamic_port_alloc_rtsp (
                  cnat_portmap_v2_t *pm,
                  port_alloc_t       atype,
                  port_pair_t        pair_type,
                  u16                start_range,
                  u16                end_range,
                  u32               *index,
                  u32               *o_ipv4_address,
                  u16               *o_port
#ifndef NO_BULK_LOGGING
                    , bulk_alloc_size_t bulk_size,
                    int *nfv9_log_req
#endif
                  , u32               *rseed_ip
                  );

void cnat_port_free_v2(
                  cnat_portmap_v2_t *pm,
                  int                index, 
                  port_pair_t        ptype,
		  u16                base_port,
                  u16               static_port_range);

void cnat_portmap_dump_v2(cnat_portmap_v2_t *pm,
                          u16 print_limit);



cnat_errno_t
nat64_static_port_alloc (
                 cnat_portmap_v2_t    *pm,
                 port_alloc_t          atype,
                 port_pair_t           pair_type,
                 u32                   *i_ipv6_address,
                 u16                   i_port,
                 u32                  *index,
                 u32                  *o_ipv4_address,
                 u16                  *o_port);



#endif /* __CNAT_PORTS_H__ */
