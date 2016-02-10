/* 
 *------------------------------------------------------------------
 * cnat_show.c - translation database definitions
 *
 * Copyright (c) 2007-2014 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/hash.h>
#include <vppinfra/pool.h>
#include <vppinfra/clib.h>

#include "cnat_db.h"
#include "cnat_config.h"
#include "cnat_global.h"
#include "cnat_logging.h"
#include "spp_ctx.h"
#include "spp_timers.h"
#include "platform_common.h"
#include "cnat_syslog.h"
#include "cnat_v4_pptp_alg.h"
#include "platform_common.h"

#ifndef TOBE_PORTED
/* The following variable is in cnat_config_msg_handler.c which
 * is to be ported later.. if required
 */
u32 total_address_pool_allocated = 0;
#endif

#ifndef NO_BULK_LOGGING
#define CNAT_MY_VRFMAP_PRINT \
PLATFORM_DEBUG_PRINT("i-uidx 0x%x o-uidx 0x%x i-vrfid 0x%x o-vrfid 0x%x\n" \
       "status %d  del time 0x%x tcp mss 0x%x pm list 0x%x\n" \
       "bulk size %d\n" \
       "ip n:1 %d\n" \
       "NFV9 template index 0x%x\n" \
       "SYSLOG template index 0x%x\n" \
       "Netflow Session Logging %d \n" \
       "Syslog Session Logging %d \n" \
       "PCP Server 0x%x, Port %u \n", \
       my_vrfmap->i_vrf, my_vrfmap->o_vrf, my_vrfmap->i_vrf_id, \
       my_vrfmap->o_vrf_id, my_vrfmap->status, my_vrfmap->delete_time, \
       my_vrfmap->tcp_mss, my_vrfmap->portmap_list, \
       BULKSIZE_FROM_VRFMAP(my_vrfmap), \
       my_vrfmap->ip_n_to_1, \
       my_vrfmap->nfv9_logging_index, \
       my_vrfmap->syslog_logging_index,\
       my_vrfmap->nf_logging_policy, \
       my_vrfmap->syslog_logging_policy, \
       my_vrfmap->pcp_server_addr, \
       my_vrfmap->pcp_server_port); 
#else
#define CNAT_MY_VRFMAP_PRINT \
PLATFORM_DEBUG_PRINT("i-uidx 0x%x o-uidx 0x%x i-vrfid 0x%x o-vrfid 0x%x\n" \
       "status %d  del time 0x%x tcp mss 0x%x pm list 0x%x\n" \
       "NFV9 template index 0x%x\n ip n:1 %d\n", \
       my_vrfmap->i_vrf, my_vrfmap->o_vrf, my_vrfmap->i_vrf_id, \
       my_vrfmap->o_vrf_id, my_vrfmap->status, my_vrfmap->delete_time, \
       my_vrfmap->tcp_mss, my_vrfmap->portmap_list, \
       my_vrfmap->nfv9_logging_index, my_vrfmap->ip_n_to_1);
#endif  /* NO_BULK_LOGGING */

#define CNAT_MY_LOGGING_INFO_PRINT \
do { \
    cnat_syslog_logging_info_t *my_syslog_info = 0; \
    PLATFORM_DEBUG_PRINT("SYSLOG config: \n"); \
    pool_foreach (my_syslog_info, cnat_syslog_logging_info_pool, ({ \
        if (my_syslog_info->i_vrf == my_vrfmap->i_vrf) {  \
            PLATFORM_DEBUG_PRINT(" \
            ipv4[0x%x], port[%u], hostname[%s]\n", \
            my_syslog_info->ipv4_address, my_syslog_info->port, \
            my_syslog_info->header_hostname); \
        break; \
        } \
    })); \
}while (0) \
;


void printf_ipv4(u32 ad)
{
    u8 a __attribute__((unused)), b __attribute__((unused)), 
        c __attribute__((unused)), d __attribute__((unused));

    a = ad>>24;
    b = (ad>>16) & 0xFF;
    c = (ad>>8) & 0xFF;
    d = (ad>>0) & 0xFF;

    PLATFORM_DEBUG_PRINT("%d.%d.%d.%d", a, b, c, d);
}
void cnat_main_db_entry_dump (cnat_main_db_entry_t *db)
{
    PLATFORM_DEBUG_PRINT("Main DB entry at %p, index %ld dst_ip %x\n",
            db, db - cnat_main_db, db->dst_ipv4);
    /* only dump hash next index if it's non EMPTY */
    if (db->out2in_hash.next != EMPTY || db->in2out_hash.next != EMPTY)
    PLATFORM_DEBUG_PRINT("out2in hash %u, in2out hash %u\n", 
            db->out2in_hash.next,
            db->in2out_hash.next);
    PLATFORM_DEBUG_PRINT("out2in key ipv4 0x%08X, port 0x%04X (%5d), vrf %d, protocol %s\n",
            db->out2in_key.k.ipv4,
            db->out2in_key.k.port,
            db->out2in_key.k.port,
            db->out2in_key.k.vrf & CNAT_VRF_MASK,
            (db->out2in_key.k.vrf & CNAT_PRO_MASK) == CNAT_UDP ? "UDP" :
            ((db->in2out_key.k.vrf & CNAT_PRO_MASK) == CNAT_TCP ? "TCP" :
             ((db->in2out_key.k.vrf & CNAT_PRO_MASK) == CNAT_ICMP ? "ICMP" : "PPTP ALG")));

    PLATFORM_DEBUG_PRINT("in2out key ipv4 0x%08X, port 0x%04X (%5d), vrf %d, protocol %s\n",
            db->in2out_key.k.ipv4,
            db->in2out_key.k.port,
            db->in2out_key.k.port,
            db->in2out_key.k.vrf & CNAT_VRF_MASK,
            (db->in2out_key.k.vrf & CNAT_PRO_MASK) == CNAT_UDP ? "UDP" :
            ((db->in2out_key.k.vrf & CNAT_PRO_MASK) == CNAT_TCP ? "TCP" : 
             ((db->in2out_key.k.vrf & CNAT_PRO_MASK) == CNAT_ICMP ? "ICMP" : "UNKNOWN")));

    PLATFORM_DEBUG_PRINT("user %d, user ports (nxt) %d (prev) %d, vrfmap_index 0x%x\n",
            db->user_index, db->user_ports.next, db->user_ports.prev,
            db->vrfmap_index);
    PLATFORM_DEBUG_PRINT("timeout %d \n", db->timeout);
    PLATFORM_DEBUG_PRINT("flags 0x%x ", db->flags);

    if (db->flags & CNAT_DB_FLAG_TCP_ACTIVE) {
        PLATFORM_DEBUG_PRINT(" TCP_ACTIVE ");
    } else if (db->flags & CNAT_DB_FLAG_UDP_ACTIVE) {
        PLATFORM_DEBUG_PRINT(" UDP_ACTIVE ");
    } else if (db->flags & CNAT_DB_FLAG_STATIC_PORT) {
        PLATFORM_DEBUG_PRINT(" STATIC_PORT ");
    }

    PLATFORM_DEBUG_PRINT(" ALG dlt0 0x%02X dlt1 0x%02X\n", db->alg.alg_dlt[0], db->alg.alg_dlt[1]);
    PLATFORM_DEBUG_PRINT("\n");

    PLATFORM_DEBUG_PRINT("out2in_pkts: %u\n", db->out2in_pkts);
    PLATFORM_DEBUG_PRINT("in2out_pkts: %u\n", db->in2out_pkts);
    PLATFORM_DEBUG_PRINT("entry_expires: %u  current time: %u\n", db->entry_expires, cnat_current_time);
    PLATFORM_DEBUG_PRINT("-------------------------\n");
}

void cnat_user_db_entry_dump (cnat_user_db_entry_t *up)
{
    u32 db_entry_index, first_db_entry_index;
    cnat_main_db_entry_t *ep;

    PLATFORM_DEBUG_PRINT("User DB entry at %p, index %ld\n",
            up, up - cnat_user_db);
    PLATFORM_DEBUG_PRINT("translation list head index %u, %u translations portmapindex 0x%x\n",
            up->translation_list_head_index, 
            up->ntranslations, up->portmap_index);
    PLATFORM_DEBUG_PRINT("source ipv4 0x%x, source port 0x%x, vrf %d\n",
            up->key.k.ipv4, 
            up->key.k.port,
            up->key.k.vrf);
    first_db_entry_index = db_entry_index = up->translation_list_head_index;
    if (first_db_entry_index != EMPTY) {
        PLATFORM_DEBUG_PRINT("Port translation list:\n");
        do {
            PLATFORM_DEBUG_PRINT("  [%d]\n", db_entry_index);
            ep = cnat_main_db + db_entry_index;
            db_entry_index = ep->user_ports.next;
        } while (first_db_entry_index != db_entry_index);
    } else {
        PLATFORM_DEBUG_PRINT("WARNING: empty translation list!\n");
    }
    PLATFORM_DEBUG_PRINT("-------------------------\n");
}

void cnat_user_db_entry_dump_summary (cnat_user_db_entry_t *up)
{
    u32 db_entry_index, first_db_entry_index;
    u32 total_entries = 0;

    PLATFORM_DEBUG_PRINT("User DB entry at %p, index %ld\n",
            up, up - cnat_user_db);
    PLATFORM_DEBUG_PRINT("translation list head index %u, %u translations portmapindex 0x%x\n",
            up->translation_list_head_index, 
            up->ntranslations, up->portmap_index);
    PLATFORM_DEBUG_PRINT("source ipv4 0x%x, source port 0x%x, vrf %d\n",
            up->key.k.ipv4, 
            up->key.k.port,
            up->key.k.vrf);
    first_db_entry_index = db_entry_index = up->translation_list_head_index;
    if (first_db_entry_index != EMPTY) {
        PLATFORM_DEBUG_PRINT("Port translation list:\n");
        do {
	    total_entries++;
        } while (first_db_entry_index != db_entry_index);
        PLATFORM_DEBUG_PRINT("TOTAL_ENTRIES: %d\n", total_entries);
    } else {
        PLATFORM_DEBUG_PRINT("WARNING: empty translation list!\n");
    }
    PLATFORM_DEBUG_PRINT("-------------------------\n");
}

/* for internal development and UT only */
void cnat_db_dump_main_by_index (int argc, unsigned long *argv)
{
    u32 index, i, len;
    u32 active_count, scan_count;

    if (argc != 1) {
        PLATFORM_DEBUG_PRINT("invalid input %d\n", argc);
        return;
    } 

    index = argv[0];        

    len = vec_len(cnat_main_db);

    active_count = pool_elts(cnat_main_db);

    if (index >= active_count) {
        PLATFORM_DEBUG_PRINT("Index %u >= total active entries %u\n", index, active_count);
        return;
    }

    scan_count = 0;
    for (i=0; i< len; i++) {
        if(pool_is_free_index(cnat_main_db, i)) continue;

        if (index == scan_count) {
            cnat_main_db_entry_dump(cnat_main_db + i);
            break;
        }
        scan_count++;
    }
}

void cnat_db_dump_main (int argc, unsigned long *argv)
{
    cnat_main_db_entry_t *db;
   
    pool_foreach(db, cnat_main_db, ({
        cnat_main_db_entry_dump(db);
    }));
}

void cnat_db_dump_main_summary (int argc, unsigned long *argv)
{
    cnat_main_db_entry_t *db;
    u32 num_entries = 0;
   
    pool_foreach(db, cnat_main_db, ({
        num_entries++;
    }));

    PLATFORM_DEBUG_PRINT("\nNum main entries %d\n", num_entries);
}

void cnat_db_dump_user (int argc, unsigned long *argv)
{
    cnat_user_db_entry_t *up;

    pool_foreach(up, cnat_user_db, ({
        cnat_user_db_entry_dump(up);
    }));
}

void cnat_db_dump_user_summary (int argc, unsigned long *argv)
{
    cnat_user_db_entry_t *up;

    pool_foreach(up, cnat_user_db, ({
        cnat_user_db_entry_dump_summary(up);
    }));
}

void cnat_db_dump_hashes (int argc, unsigned long *argv)
{
    int i;

    PLATFORM_DEBUG_PRINT("Main DB out2in hash:\n");
    for (i = 0; i < vec_len(cnat_out2in_hash); i++) {
        if (cnat_out2in_hash[i].next != EMPTY) {
            PLATFORM_DEBUG_PRINT("[%d]: %u\n", i, cnat_out2in_hash[i].next);
        }
    }
    PLATFORM_DEBUG_PRINT("Main DB in2out hash:\n");
    for (i = 0; i < vec_len(cnat_in2out_hash); i++) {
        if (cnat_in2out_hash[i].next != EMPTY) {
            PLATFORM_DEBUG_PRINT("[%d]: %u\n", i, cnat_in2out_hash[i].next);
        }
    }

    PLATFORM_DEBUG_PRINT("User hash:\n");
    for (i = 0; i < vec_len(cnat_user_hash); i++) {
        if (cnat_user_hash[i].next != EMPTY) {
            PLATFORM_DEBUG_PRINT("[%d]: %u\n", i, cnat_user_hash[i].next);
        }
    }
    PLATFORM_DEBUG_PRINT("-------------------------\n");
}


#ifdef OLD_VRFMAP

void cnat_db_dump_cdb (int argc, unsigned long *argv)
{
    int k;
    int verbose=0;
    int all = 0;

    if (argc > 0) {
        verbose = 1;
    }

    if (argc > 1) {
        all = 1;
    }

    PLATFORM_DEBUG_PRINT ("%d vrfmap vectors  \n", vec_len(cnat_portmap_by_vrf));

    for (k = 0; k < vec_len(cnat_portmap_by_vrf); k++) {
        PLATFORM_DEBUG_PRINT("index%d: status %d i_vrf 0x%x o_vrf 0x%x\n", k,
               cnat_portmap_by_vrf[k].status, 
               cnat_portmap_by_vrf[k].i_vrf,
               cnat_portmap_by_vrf[k].o_vrf);
        cnat_db_dump_address_portmap(verbose, all,
                                     cnat_portmaps[k],
                                     cnat_portmaps_inuse[k]);
    }
}

void cnat_db_dump_i_vrf (int argc, unsigned long *argv)
{
    u32 k;
    u32 vrf =0;
    int verbose=0;
    int all = 0;

    if (!argc) {
        PLATFORM_DEBUG_PRINT("need vrf input ,return\n");
        return;
    }

    if (argc > 0) {
         vrf = argv[0];
    }
   
    if (argc > 1) {
        verbose = 1;
    }

    if (argc > 2) {
        all = 1;
    }

    PLATFORM_DEBUG_PRINT ("%d vrfmap vectors  \n", vec_len(cnat_portmap_by_vrf));

    for (k = 0; k < vec_len(cnat_portmap_by_vrf); k++) {
        if (cnat_portmap_by_vrf[k].i_vrf == vrf) {
            PLATFORM_DEBUG_PRINT("%d:  i_vrf 0x%x o_vrf 0x%x\n", k,
               cnat_portmap_by_vrf[k].i_vrf,
               cnat_portmap_by_vrf[k].o_vrf);
            cnat_db_dump_address_portmap(verbose, all,
                                     cnat_portmaps[k],
                                     cnat_portmaps_inuse[k]);
            return;
        }
    }
    PLATFORM_DEBUG_PRINT("not found\n");
}

void cnat_db_dump_o_vrf (int argc, unsigned long *argv)
{
    u32 k;
    int verbose=0;
    int all = 0;
    u32 vrf =0;

    if (!argc) {
        PLATFORM_DEBUG_PRINT("need vrf input ,return\n");
        return;
    }

    if (argc > 0) {
         vrf = argv[0];
    }

    if (argc > 1) {
        verbose = 1;
    }

    if (argc > 2) {
        all = 1;
    }

    PLATFORM_DEBUG_PRINT ("%d vrfmap vectors  \n", vec_len(cnat_portmap_by_vrf));

    for (k = 0; k < vec_len(cnat_portmap_by_vrf); k++) {
        if (cnat_portmap_by_vrf[k].o_vrf == vrf) {
            PLATFORM_DEBUG_PRINT("index%d: status %d i_vrf 0x%x o_vrf 0x%x\n", k,
               cnat_portmap_by_vrf[k].status,
               cnat_portmap_by_vrf[k].i_vrf,
               cnat_portmap_by_vrf[k].o_vrf);
            cnat_db_dump_address_portmap(verbose, all,
                                     cnat_portmaps[k],
                                     cnat_portmaps_inuse[k]);
            return;
        }
    }
    PLATFORM_DEBUG_PRINT("not found\n");
}
#endif

#ifdef TOBE_PORTED
/* This does not seem to be used */
void cnat_db_mem_usage_cmd (int argc, unsigned long *argv)
{
    pool_header_t * p;
    _VEC *_v;
    u32 bitmap_bytes=0, free_indices_bytes=0, vec_bytes=0, total_bytes=0;

    if (cnat_main_db) {
        p = pool_header(cnat_main_db);
        if (p->free_bitmap) {
            _v = _vec_find(p->free_bitmap);
            bitmap_bytes = _v->alen;
        } else {
            bitmap_bytes = 0;
        }
        if (p->free_indices) {
            _v = _vec_find(p->free_indices);
            free_indices_bytes = _v->alen;
        } else {
            free_indices_bytes = 0;
        }
        _v = _vec_find(cnat_main_db);
        vec_bytes = _v->alen;
    } else {
        vec_bytes = 0;
    }
    
    total_bytes = bitmap_bytes + free_indices_bytes + vec_bytes;

    PLATFORM_DEBUG_PRINT ("Main DB: %d total bytes, %d bitmap, %d indices, %d vec\n", 
            total_bytes, bitmap_bytes, free_indices_bytes, vec_bytes);
    PLATFORM_DEBUG_PRINT ("  vector length %d\n", vec_len(cnat_main_db));

    if (cnat_user_db) {
        p = pool_header(cnat_user_db);
        if (p->free_bitmap) {
            _v = _vec_find(p->free_bitmap);
            bitmap_bytes = _v->alen;
        } else {
            bitmap_bytes = 0;
        }
        if (p->free_indices) {
            _v = _vec_find(p->free_indices);
            free_indices_bytes = _v->alen;
        } else {
            free_indices_bytes = 0;
        }
        _v = _vec_find(cnat_user_db);
        vec_bytes = _v->alen;
    } else {
        vec_bytes = 0;
    }
    
    total_bytes = bitmap_bytes + free_indices_bytes + vec_bytes;

    PLATFORM_DEBUG_PRINT ("User DB: %d total bytes, %d bitmap, %d indices, %d vec\n", 
            total_bytes, bitmap_bytes, free_indices_bytes, vec_bytes);
    PLATFORM_DEBUG_PRINT ("  vector length %d\n", vec_len(cnat_user_db));

    _v = _vec_find(cnat_out2in_hash);
    PLATFORM_DEBUG_PRINT("out2in hash: %d total bytes\n", _v->alen);

    _v = _vec_find(cnat_in2out_hash);
    PLATFORM_DEBUG_PRINT("in2out hash: %d total bytes\n", _v->alen);
}
#endif

static void print_server_ip_address (vlib_main_t *vm, u32 ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;	
    vlib_cli_output(vm, "\tIP Address   : %d.%d.%d.%d\n", bytes[0], bytes[1], bytes[2], bytes[3]);
}

void cnat_nfv9_show_collector (vlib_main_t *vm, cnat_nfv9_logging_info_t *my_nfv9_logging_info)
{
    nfv9_server_info_t *server =  nfv9_server_info_pool +
        my_nfv9_logging_info->server_index;
#if 0
    vlib_cli_output(vm,"\tVRF - 0x%x - %s\n", my_nfv9_logging_info->i_vrf,
           my_nfv9_logging_info->deleted?"DELETED":"ACTIVE");
#endif
    print_server_ip_address(vm, clib_net_to_host_u32(server->ipv4_address)); 
    vlib_cli_output(vm,"\tPort         : %d\n", server->port);
    vlib_cli_output(vm,"\tTimeout      : %d\n", server->timeout_rate);
    vlib_cli_output(vm,"\tRefresh Rate : %d\n", server->refresh_rate);
    vlib_cli_output(vm,"\tMax Pkt Size : %d\n", my_nfv9_logging_info->max_length_minus_max_record_size);
    
    return;
}

void cnat_db_dump_policy (int argc, unsigned long *argv) 
{

    PLATFORM_CNAT_DB_DUMP_POLICY_PRINT();

    if (cnat_nfv9_global_info.cnat_nfv9_init_done) {
	if (cnat_nfv9_global_info.cnat_nfv9_global_collector_index != EMPTY) {
	    cnat_nfv9_logging_info_t *my_nfv9_logging_info;
            nfv9_server_info_t *server __attribute__((unused));

	    my_nfv9_logging_info = cnat_nfv9_logging_info_pool +
			cnat_nfv9_global_info.cnat_nfv9_global_collector_index;
            server =  nfv9_server_info_pool + 
                my_nfv9_logging_info->server_index;

	    PLATFORM_DEBUG_PRINT("NFv9 logging ip 0x%x port 0x%x refresh-rate %d timeout %d\n",
		   server->ipv4_address,
		   server->port,
		   server->refresh_rate,
		   server->timeout_rate);
	    PLATFORM_DEBUG_PRINT("NFv9 path_mtu = %d\n", 
		   my_nfv9_logging_info->max_length_minus_max_record_size);
	} else {
	    PLATFORM_DEBUG_PRINT("NFv9 global logging is not configured\n");
	}
    } else {
	PLATFORM_DEBUG_PRINT("NFv9 LOGGING is not configured\n");
    }
           
}

#ifdef OLD_VRFMAP
void cnat_show_cdb (int verbose)
{
    int k, l, i;
    for (i = 0; i < vec_len(cnat_portmap_by_vrf); i++) {
        PLATFORM_DEBUG_PRINT("i_vrf %d : o_vrf %d\n",
                cnat_portmap_by_vrf[i].i_vrf,
                cnat_portmap_by_vrf[i].o_vrf);
    }

    PLATFORM_DEBUG_PRINT("port limit %d\n", cnat_main_db_max_ports_per_user);

    PLATFORM_DEBUG_PRINT ("%d portmap vectors\n", vec_len(cnat_portmaps));

    for (k = 0; k < vec_len(cnat_portmaps); k++) {
        cnat_portmap_t *pm;
        u16 *inuse;
        pm = cnat_portmaps[k];
        inuse = cnat_portmaps_inuse[k];
        for (l = 0; l < vec_len(pm); l++) {
            if (inuse[l] || verbose ) {
                u32 net_address;
                net_address =
                    spp_host_to_net_byte_order_32((pm+l)->ipv4_address);
                printf_ipv4(net_address);
                PLATFORM_DEBUG_PRINT (": %d inuse\n", inuse[l]);
                if (verbose && inuse[l]) {
                    cnat_portmap_dump (pm+l, inuse+l);
                }
            }
        }
    }
}
#endif



/* v2 show command */
void cnat_show_address_portmap_sumary (cnat_portmap_v2_t *pm)
{
    cnat_portmap_v2_t *my_pm =0;
    u32 first_address = 0; 
    u32 second_address = 0;
    u32 last_address = 0;
    u32 i, pm_len;

    if ((pm_len = vec_len(pm))) {
	PLATFORM_DEBUG_PRINT("%d portmap in this list 0x%lx\n", 
                             pm_len, (u32)pm);
        for (i = 0; i < pm_len; i++) {
	    my_pm = pm + i;
	    if (!first_address) {
	        first_address = my_pm->ipv4_address;
	    } else if (!second_address) {
	        second_address = my_pm->ipv4_address;
	    }
            last_address = my_pm->ipv4_address;
        }

	if (first_address) {
	    PLATFORM_DEBUG_PRINT("1. 0x%08x", first_address);
	}
	if (second_address) {
	    PLATFORM_DEBUG_PRINT(", 2. 0x%08x", second_address);
	}

	if ((last_address != first_address) && 
	    (last_address != second_address)) {
	    PLATFORM_DEBUG_PRINT(",  .....,  %d. 0x%08x", pm_len, last_address);
	}
	PLATFORM_DEBUG_PRINT("\n");
    } else {
	PLATFORM_DEBUG_PRINT("ZERO POOL ADDRESSES in this list 0x%x \n", (u32)pm);
    }
}


void cnat_show_address_portmap (int verbose, int all, 
                                cnat_portmap_v2_t *pm, u16 port_limit)
{
    cnat_portmap_v2_t *my_pm =0;
    u32 i, pm_len;

    pm_len = vec_len(pm);
    if (!all) {
	cnat_show_address_portmap_sumary(pm);
    } else {
        PLATFORM_DEBUG_PRINT("%d portmap in this list 0x%x \n", pm_len, (u32)pm);
    }

    for (i = 0; i < pm_len; i++) {

	my_pm = pm + i;
        if (all) {
            PLATFORM_DEBUG_PRINT("pm:0x%x ip address:0x%x del_time 0x%x inuse:%d\n",
            (u32)my_pm, my_pm->ipv4_address, my_pm->delete_time, my_pm->inuse);
        } else if (my_pm->inuse) {
            PLATFORM_DEBUG_PRINT("pm:0x%x ip address:0x%x inuse:%d\n",
            (u32)my_pm, my_pm->ipv4_address, my_pm->inuse); 
        }

        if (verbose && (my_pm->inuse)) {
            if(PREDICT_FALSE(!port_limit)) {
               cnat_portmap_dump_v2 (my_pm, cnat_main_db_max_ports_per_user);
            }
            else {
              cnat_portmap_dump_v2 (my_pm, port_limit);
            }
        }
    }

    PLATFORM_DEBUG_PRINT("\n");
}


void cnat_show_cdb_v2 (int verbose, int all)
{
    cnat_vrfmap_t *my_vrfmap = 0;
    cnat_portmap_v2_t *pm =0;
    PLATFORM_DEBUG_PRINT("port limit %d\n", cnat_main_db_max_ports_per_user);
    PLATFORM_DEBUG_PRINT("total address pool allocated %d\n", total_address_pool_allocated);
    PLATFORM_DEBUG_PRINT("icmp rate limit %d (per core %d)\n",
        cnat_main_db_icmp_rate_limit, cnat_main_db_icmp_rate_limit_core);
    PLATFORM_DEBUG_PRINT("dynamic port range start %d\n", cnat_static_port_range);
    if (pptp_cfg.enable == PPTP_DISABLED) {
        PLATFORM_DEBUG_PRINT("PPTP alg disabled \n");
    } else {
        PLATFORM_DEBUG_PRINT("PPTP alg enabled \n");
    }

    if (ftp_alg_enabled) {
        PLATFORM_DEBUG_PRINT("FTP alg enabled\n");
    } else {
        PLATFORM_DEBUG_PRINT("FTP alg disabled\n");
    }

    pool_foreach (my_vrfmap, cnat_map_by_vrf, ({
        CNAT_MY_VRFMAP_PRINT
        CNAT_MY_LOGGING_INFO_PRINT
        PLATFORM_DEBUG_PRINT("per vrf port limit %d\n", my_vrfmap->port_limit);
        pm = my_vrfmap->portmap_list;
        cnat_show_address_portmap(verbose, all, pm, my_vrfmap->port_limit);

    }));
}


void cnat_show_cdb_command_v2(int argc, unsigned long *argv)
{
    int verbose=0;
    int all = 0;

    if (argc > 0) {
        verbose = 1;
    }

    if (argc > 1) {
        all = 1;
    }

    cnat_show_cdb_v2(verbose, all);
}

void cnat_show_ivrf_command_v2 (int argc, unsigned long *argv)
{
    u32 vrf =0;
    int verbose=0;
    int all = 0;
    cnat_vrfmap_t *my_vrfmap = 0;
    cnat_portmap_v2_t *pm =0;

    if (!argc) {
        PLATFORM_DEBUG_PRINT("need vrf input ,return\n");
        return;
    }
    if (argc > 0) {
         vrf = argv[0];
    }
    if (argc > 1) {
        verbose = 1;
    }
    if (argc > 2) {
        all = 1;
    }
    PLATFORM_DEBUG_PRINT ("%lld vrfmap vectors  \n", pool_elts(cnat_map_by_vrf));
    pool_foreach (my_vrfmap, cnat_map_by_vrf, ({
        if (my_vrfmap->i_vrf == vrf) {
            CNAT_MY_VRFMAP_PRINT
            pm = my_vrfmap->portmap_list;
            cnat_show_address_portmap(verbose, all, pm,my_vrfmap->port_limit);
            return;
        }
    }));
    PLATFORM_DEBUG_PRINT("not found\n");
}

void cnat_show_ovrf_command_v2 (int argc, unsigned long *argv)
{
    u32 not_found =1;
    u32 vrf =0;
    int verbose=0;
    int all = 0;
    cnat_vrfmap_t *my_vrfmap = 0;
    cnat_portmap_v2_t *pm =0;

    if (!argc) {
        PLATFORM_DEBUG_PRINT("need vrf input ,return\n");
        return;
    }
    if (argc > 0) {
         vrf = argv[0];
    }
    if (argc > 1) {
        verbose = 1;
    }
    if (argc > 2) {
        all = 1;
    }
    PLATFORM_DEBUG_PRINT("%d vrfmap vectors  \n", pool_elts(cnat_map_by_vrf));
    pool_foreach (my_vrfmap, cnat_map_by_vrf, ({
        if (my_vrfmap->o_vrf == vrf) {
            CNAT_MY_VRFMAP_PRINT
            pm = my_vrfmap->portmap_list;
            cnat_show_address_portmap(verbose, all, pm,my_vrfmap->port_limit);
            not_found = 0; 
        }
    }));
    if (not_found) {
        PLATFORM_DEBUG_PRINT("not found\n");
    }
}

void cnat_timeout_db_entry_dump (cnat_timeout_db_entry_t *up)
{
    u32 db_entry_index __attribute__((unused)), 
        first_db_entry_index __attribute__((unused));

    PLATFORM_DEBUG_PRINT("Timeout DB entry at index %ld\n", up - cnat_timeout_db);
    PLATFORM_DEBUG_PRINT("Desnt key 0x%16llx\n", up->t_key.timeout_key.key64);
    PLATFORM_DEBUG_PRINT("Timeout value %d\n", up->t_key.timeout_value);
    PLATFORM_DEBUG_PRINT("Hash Next  0x%x\n", up->t_hash.next);

}

void cnat_db_dump_timeout ()
{
    cnat_timeout_db_entry_t *up;
    pool_header_t     *h;
    u32 used __attribute__((unused)), free __attribute__((unused));

    h = pool_header(cnat_timeout_db);
    free = vec_len(h->free_indices);
    used = (vec_len(cnat_timeout_db) - free);

    PLATFORM_DEBUG_PRINT("Timeout DB Free %d, Used %d\n",free, used);

    pool_foreach(up, cnat_timeout_db, ({
        cnat_timeout_db_entry_dump(up);
    }));
}

