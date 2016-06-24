/* 
 *------------------------------------------------------------------
 * cnat_util.c - cnat helpers 
 *
 * Copyright (c) 2009-2014 Cisco and/or its affiliates.
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
#include <vppinfra/error.h>

#include "tcp_header_definitions.h"

#if 0
void spp_api_cnat_v4_config_dummy_t_handler
(spp_api_cnat_v4_config_dummy_t *mp);

void spp_api_cnat_v4_config_dummy_max_t_handler
(spp_api_cnat_v4_config_dummy_max_t *mp);

void spp_api_cnat_v4_config_icmp_timeout_t_handler
(spp_api_cnat_v4_config_icmp_timeout_t *mp);

void spp_api_cnat_clear_db_request_t_handler 
(spp_api_cnat_clear_db_request_t *mp);

void spp_api_cnat_v4_debug_global_t_handler
(spp_api_cnat_v4_debug_global_t *mp);

void spp_api_cnat_v4_show_outside_entry_req_t_handler
(spp_api_cnat_v4_show_outside_entry_req_t *mp);

void spp_api_cnat_v4_show_inside_entry_req_t_handler
(spp_api_cnat_v4_show_inside_entry_req_t *mp);

void spp_api_cnat_show_statistics_summary_req_t_handler
(spp_api_cnat_show_statistics_summary_req_t *mp);

void cnat_db_create_db_entries_cmd (int argc, unsigned long *argv)
{
    int i, j ;
    int nusers = 3000;

    cnat_db_key_bucket_t key_info;
    cnat_main_db_entry_t *db;
    cnat_gen_icmp_info info;
    cnat_key_t dest_info_dummy;

    memset(&dest_info_dummy, 0, sizeof(cnat_key_t));
    printf ("Create %d users, 100 translations each...\n", nusers);

    for (i = 0; i < nusers; i++) {
        for (j = 0; j < 100; j++) {

            key_info.k.k.vrf = CNAT_TCP | (1 & CNAT_VRF_MASK);
            key_info.k.k.ipv4  = 0x0c000001+i;
            key_info.k.k.port  = 1024+j;

            db = cnat_get_main_db_entry_v2(&key_info, PORT_SINGLE,
                PORT_TYPE_DYNAMIC, &info, &dest_info_dummy);

            if (db == 0) {
                 printf ("OOPS: cnat_main_db_create failed users %d trans %d\n", i, j);
                 return; /*jli*/
            }
          
            db->entry_expires = cnat_current_time;

        }
    }
}

void db_test_clear (int argc, unsigned long *argv)
{
    spp_api_cnat_clear_db_request_t mp;

    mp.wildcard = argv[0];
    mp.protocol = argv[1];
    mp.port_num = argv[2];
    mp.inside_vrf = argv[3];
    mp.ip_addr = argv[4];
    spp_api_cnat_clear_db_request_t_handler(&mp);
}

/* test code*/
void cnat_db_test_show (int argc, unsigned long *argv)
{

    spp_api_cnat_v4_show_inside_entry_req_t mp1[2000];
    spp_api_cnat_v4_show_outside_entry_req_t mp2[30000];

    if (argc > 1) {
        if (argc != 7) {
	    printf("Usage: db test show dec((which)) dec((vrf)) dec((proto)) dec((ip)) dec((start_port)) dec((end_port)) dec((flags))\n");
	    return;
	}

	mp1[0].vrf_id = argv[1];
	mp1[0].protocol = argv[2];;
	mp1[0].ipv4_addr =  argv[3];
	mp1[0].start_port = argv[4];
	mp1[0].end_port =  argv[5];
	mp1[0].flags = argv[6];
	mp1[0].all_entries = 0;

    if (argv[0] == 1) {
	     spp_api_cnat_v4_show_inside_entry_req_t_handler (&(mp1[0]));
	} else {
	     spp_api_cnat_v4_show_outside_entry_req_t_handler (&(mp2[0]));
	}

	return;
    } else {
	printf("inside entries \n");
	mp1[0].ipv4_addr =  0x016994CA;
	mp1[0].vrf_id = 1;
	mp1[0].all_entries = 0;
	mp1[0].start_port = 32765;
	mp1[0].end_port =  65535;
	mp1[0].protocol = 2;
	mp1[0].flags = 3;

       spp_api_cnat_v4_show_inside_entry_req_t_handler (&(mp1[0]));

	mp2[0].ipv4_addr =  0x640200c1;
	mp2[0].vrf_id = 0;
	mp2[0].start_port = 1025;
	mp2[0].end_port = 62235;
	mp2[0].protocol = 2;
	mp2[0].flags = 3;

	spp_api_cnat_v4_show_outside_entry_req_t_handler (&(mp2[0]));
    }

#if 1
    {
    spp_api_cnat_stats_node_mapping_t mp3[20000];
    spp_api_cnat_stats_counter_mapping_t mp4[20000];
    spp_api_cnat_stats_counter_values_t mp5[23000];

    mp3[0].rc = 0;
    spp_api_cnat_stats_node_mapping_t_handler (&mp3);
    mp4[0].rc = 0;
    spp_api_cnat_stats_counter_mapping_t_handler (&mp4);

    mp5[0].flag = 1;
    spp_api_cnat_stats_counter_values_t_handler(&mp5);
    }
#endif

#if 0
    mp1.ipv4_addr = 0x0A010102;
    mp1.vrf_id = 1;
    mp1.all_entries = 1;
    mp1.protocol = 1;

    spp_api_cnat_v4_show_inside_entry_req_t_handler (&mp1);


    mp1.ipv4_addr = 0x0A010103;
    mp1.vrf_id = 1;
    mp1.all_entries = 1;
    mp1.protocol = 2;

    spp_api_cnat_v4_show_inside_entry_req_t_handler (&mp1);

    mp6[0].inside_vrf_id = 1; 
    mp6[0].start_ipv4_address = 0x64020001;
    mp6[0].end_ipv4_address = 0x64020101;
    mp6[0].free_addr = 0;
    mp6[0].flags = CNAT_TRANSLATION_ENTRY_STATIC;

    spp_api_cnat_v4_show_freeUsed_entry_req_t_handler(&mp6);
  
#endif
    printf("returned here");

    return;
}



void cnat_db_clear_all_entries (int argc, unsigned long *argv)
{
    cnat_main_db_entry_t * db;
    u32 index;

    pool_header_t * p = vec_header(cnat_main_db, sizeof(pool_header_t) );

    for(index = 0; index < vec_len(cnat_main_db); index++) {

        if ( !clib_bitmap_get(p->free_bitmap, index)) {

            db = cnat_main_db + index;
            cnat_delete_main_db_entry_v2(db);

        }
    }
    
}


void spp_log_cmd (int argc, unsigned long *argv)
{
    u16 num_traces;
    u16 error_code;
    u16 num_args;
    u32 arg[7];
    u8 i;

    num_traces = argv[0];

    for (i = 0; i < num_traces; i++) {
        error_code = argv[1 + 4*i];
        num_args = argv[2 + 4*i];
        arg[0] = argv[3 + 4*i];
        arg[1] = argv[4 + 4*i];

        spp_printf(error_code, num_args, arg);
    }
}


void cnat_db_create_random_entries (int argc, unsigned long *argv)
{

     platform_cnat_db_create_random_entries();
}

#define MAX_DEPTH 10

void show_user_db_hash_chain_len() {

    u32 max_len, len, n, i, max_idx, index, used;
    cnat_user_db_entry_t * udb;
    u32 hash_depth[MAX_DEPTH];

    memset(hash_depth, 0, sizeof(u32)*MAX_DEPTH);

    n = vec_len(cnat_user_hash);

    used = 0;
    max_len = 0;
    for(i=0;i<n;i++) {

        index = cnat_user_hash[i].next;

        len = 0;
        if (index != EMPTY) used++;

        while (index != EMPTY) {
            len++ ;
            udb = cnat_user_db + index;
            index = udb->user_hash.next;
        }

        if(len < (MAX_DEPTH-1) ) {
            hash_depth[len]++;
        } else {
            hash_depth[MAX_DEPTH-1]++;
        }

        if (max_len < len) {
            max_len = len;
            max_idx = cnat_user_hash[i].next;
         }
    }

    printf("Max user db hash length %u, total buckets %u used %u\n",
           max_len, n, used);

    for( i=1; i<(MAX_DEPTH - 1); i++) {
        printf("Hash chain len  %02d, entries count %d\n", i, hash_depth[i]);
    }

    printf("Hash chain len >%02d, entries count %d\n",
           MAX_DEPTH-1, hash_depth[MAX_DEPTH-1]);

}

void show_main_db_hash_chain_len() {

    u32 max_len, len, n, i, max_idx, index, used;
    cnat_main_db_entry_t * db;
    u32 hash_depth[MAX_DEPTH];

    memset(hash_depth, 0, sizeof(u32)*MAX_DEPTH);

    n = vec_len(cnat_in2out_hash);

    used = 0;
    max_len = 0;
    for(i=0;i<n;i++) {

        index = cnat_in2out_hash[i].next;

        len = 0;
        if (index != EMPTY) used++;

        while (index != EMPTY) {
            len++ ;
            db = cnat_main_db + index;
            index = db->in2out_hash.next;
        }

        if(len < (MAX_DEPTH-1) ) {
            hash_depth[len]++;
        } else {
            hash_depth[MAX_DEPTH-1]++;
        }

        if (max_len < len) { 
            max_len = len;  
            max_idx = cnat_in2out_hash[i].next;
         }
    }

    printf("Max main db I2O hash length %u, total buckets %u used %u\n", 
           max_len, n, used);

    for( i=1; i<(MAX_DEPTH - 1); i++) {
        printf("Hash chain len  %02d, entries count %d\n", i, hash_depth[i]);
    }

    printf("Hash chain len >%02d, entries count %d\n",
           MAX_DEPTH-1, hash_depth[MAX_DEPTH-1]);


    memset(hash_depth, 0, sizeof(u32)*MAX_DEPTH);

    n = vec_len(cnat_out2in_hash);
    used = 0;
    max_len = 0;

    for(i=0;i<n;i++) {

       index = cnat_out2in_hash[i].next;
       len = 0;

       if (index != EMPTY) used++;

       while (index != EMPTY) {
           len++ ;
           db = cnat_main_db + index;
           index = db->out2in_hash.next;
       }

        if(len < (MAX_DEPTH-1) ) {
            hash_depth[len]++;
        } else {
            hash_depth[MAX_DEPTH-1]++;
        }

        if (max_len < len) {
            max_len = len;
            max_idx = cnat_in2out_hash[i].next;
         }
    }

    printf("Max main db O2I hash length %u, total buckets %u used %u\n",
           max_len, n, used);

    for( i=1; i<(MAX_DEPTH - 1); i++) {
        printf("Hash chain len  %02d, entries count %d\n", i, hash_depth[i]);
    }

    printf("Hash chain len >%02d, entries count %d\n", 
           MAX_DEPTH-1, hash_depth[MAX_DEPTH-1]);


}

u32 db_free_entry (void * p) {

    pool_header_t * h;
    u32 free;

    h = pool_header(p);

    free = p == 0 ? 0: vec_len(h->free_indices);

    return free;
}

void cnat_db_summary (int argc, unsigned long *argv) {

    PLATFORM_DEBUG_PRINT("\n-----------------------------------------");
    PLATFORM_DEBUG_PRINT("\nSummary DB");
    PLATFORM_DEBUG_PRINT("\n-----------------------------------------\n");
    u32 count1, count2, i;
#ifndef NO_NAT64_DEF
    extern void nat64_session_db_summary();
#endif
    /* main db active entry count*/
    count1 = vec_len(cnat_main_db);
    count2 = db_free_entry(cnat_main_db);

    PLATFORM_DEBUG_PRINT("main db entries:  total %u, active %u, free %u\n", count1, count1 - count2, count2);

    /* user db active entry count */
    count1 = vec_len(cnat_user_db);
    count2 = db_free_entry(cnat_user_db);

    PLATFORM_DEBUG_PRINT("user db entries:  total %u, active %u, free %u\n", count1, count1 - count2, count2);


    /* user db active entry count */
#ifndef NO_NAT64_DEF
    nat64_session_db_summary();
#endif

    /* main db hash i2o o2i usage count */
    count1  = 0;
    count2  = 0;

    for (i=0; i< CNAT_MAIN_HASH_SIZE; i++) {

        if(cnat_in2out_hash[i].next != ~0) count1++;
        if(cnat_out2in_hash[i].next != ~0) count2++;

    }

    PLATFORM_DEBUG_PRINT("main hash in2out: total %6u, used %u (%.2f%%)\n", 
            CNAT_MAIN_HASH_SIZE, count1,
            (100.0*count1)/CNAT_MAIN_HASH_SIZE);

    PLATFORM_DEBUG_PRINT("main hash out2in: total %6u, used %u (%.2f%%)\n", 
            CNAT_MAIN_HASH_SIZE, count2,
            (100.0 * count1)/CNAT_MAIN_HASH_SIZE);

    /* use db hashing usage count */

    count1  = 0;    

    for (i=0; i< CNAT_USER_HASH_SIZE; i++) {
        if(cnat_user_hash[i].next != ~0) count1++;
    }

    PLATFORM_DEBUG_PRINT("user db hash:     total %6u, used %u (%.2f%%)\n", 
            CNAT_USER_HASH_SIZE, count1,
            (100.0*count1)/CNAT_USER_HASH_SIZE);

   PLATFORM_DEBUG_PRINT("\nNull pointer exceptions:\n");
   PLATFORM_DEBUG_PRINT("packet_pool: null enq   : %10u, null deq  : %10u\n",null_enq_pkt, null_deq_pkt);
   PLATFORM_DEBUG_PRINT("ctx_pool   : null enq   : %10u, null deq  : %10u\n",null_enq_ctx, null_deq_ctx);
   PLATFORM_DEBUG_PRINT("wqe_pool   : null enq   : %10u, null deq  : %10u\n",null_enq_wqe, null_deq_wqe);

   PLATFORM_DEBUG_PRINT("\nReceived Packet Errors on SPI:\n");
   PLATFORM_DEBUG_PRINT("rcv_pkt_errs: %10u\n",rcv_pkt_errs);

   PLATFORM_DEBUG_PRINT("\nctx/sf allocation failure errors: \n");
#ifndef CGN_PERF_SCALE_DEBUG
   PLATFORM_DEBUG_PRINT("Warning: collection of error counts <with timestamp> is disabled.\n");
   PLATFORM_DEBUG_PRINT("sf alloc errors: %10u, ctx alloc errors: %10u\n",sf_alloc_errs,ctx_alloc_errs);
#else
   for(i=0;i<COUNTER_BUFFER_SIZE;i++)
       PLATFORM_DEBUG_PRINT("<%2d>Timestamp <sec>: %10u, sf errors: %10u, ctx errors: %10u\n",\
	       i,err_cnt_arr[i].timestamp,\
               err_cnt_arr[i].sf_error_counter, \
               err_cnt_arr[i].ctx_error_counter);
#endif
}

void cnat_db_hash_summary (int argc, unsigned long *argv) {

    show_main_db_hash_chain_len();

    show_user_db_hash_chain_len();
}

/*
 * cnat_port_alloc
 * This function is now deprecated...
 *
 */
#ifdef LB_PORT
int cnat_port_alloc (cnat_portmap_t *cnat_portmap, u16 *portmap_inuse,
                     int cnat_instance,
                     port_alloc_t atype, port_pair_t ptype,
                     int *index, u32 *ipv4_address, u16 *base_port)
#else
int cnat_port_alloc (cnat_portmap_t *cnat_portmap, u16 *portmap_inuse,
                     port_alloc_t atype, port_pair_t ptype,
                     int *index, u32 *ipv4_address, u16 *base_port)
#endif
{

    return (0);
}

/*
 * cnat_port_free
 * This function is now deprecated...
 *
 */
#ifdef LB_PORT
void cnat_port_free (cnat_portmap_t *cnat_portmap, u16 *portmap_inuse,
                     int instance, int index, port_pair_t ptype, u16 base_port)
#else
void cnat_port_free (cnat_portmap_t *cnat_portmap, u16 *portmap_inuse,
                     int index, port_pair_t ptype, u16 base_port)
#endif
{
}

void spp_api_cnat_port_allocate_t_handler(spp_api_cnat_port_allocate_t *mp)
{
    int i, j, k1, k2;
    int pm_index;
    u32 ipv4_address;
    u16 aport;
    int rv;
    char *out1, *out2, *out_f;
    port_alloc_t pt1, pt2;
    cnat_portmap_t *pm = 0;
    u16 *pm_inuse = 0;
    u32 *firstp =0;
    u32 nr_ports =0;
    u32 nodd_ports = 0;
    u32 neven_ports = 0;
#ifdef LB_PORT
    u32 my_instance = 1;
#endif
    char out_r[12] = "allocated-r";
    char out_o[12] = "allocated-o";
    char out_e[12] = "allocated-e";


    /*
     * this command is run after db create portmap
     * vrf is hardcode to 1
     */

    /* Already have a portmap vector for this VRF? */
    for (i = 0; i < vec_len(cnat_portmap_indices_by_vrf); i++) {
        if (cnat_portmap_indices_by_vrf[i] == mp->vrf) {
            pm = cnat_portmaps[i];
            pm_inuse = cnat_portmaps_inuse[i];
            goto found_portmaps;
        }
    }

    printf("need to run db create portmaps first 0x%d\n",
            vec_len(cnat_portmap_indices_by_vrf));
    return;

found_portmaps:
    nr_ports = mp->nr_ports;
    nodd_ports = mp->nodd_ports;
    neven_ports = mp->neven_ports;

    if ((nr_ports + nodd_ports + neven_ports ) > (PORTS_PER_ADDR)) {
        printf("invalid port# nr_ports %d + odd %d + even %d "
               "should be less than 200 \n", nr_ports, nodd_ports, neven_ports);
        return;
    }

    /*
     * first port
     */
    firstp = nr_ports ? (&nr_ports) : (nodd_ports ? (&nodd_ports) : (&neven_ports));
    if (!(*firstp)) {
        printf("invalid port# nr_ports %d  odd %d  even %d ",
               nr_ports, nodd_ports, neven_ports);
    }
    out_f = nr_ports ? out_r : (nodd_ports ? out_o : out_e);

#ifdef LB_PORT
    rv = cnat_port_alloc (pm, pm_inuse, my_instance,
                          PORT_ALLOC_ANY, PORT_S_ODD,
                          &pm_index, &ipv4_address, &aport);
#else
    rv = cnat_port_alloc (pm, pm_inuse,
                          PORT_ALLOC_ANY, PORT_S_ODD,
                          &pm_index, &ipv4_address, &aport);
#endif

    if (!rv) {
        printf("failed-o\n");
        return;
    }
    printf("%s %8d %10x %8d\n", out_f,
            pm_index, ipv4_address, aport);

    (*firstp)--;

    for (i=0; i < nr_ports; i++) {
#ifdef LB_PORT
        rv = cnat_port_alloc (pm, pm_inuse, my_instance,
                              PORT_ALLOC_DIRECTED, PORT_SINGLE,
                              &pm_index, &ipv4_address, &aport);
#else
        rv = cnat_port_alloc (pm, pm_inuse,
                              PORT_ALLOC_DIRECTED, PORT_SINGLE,
                              &pm_index, &ipv4_address, &aport);
#endif
        if (rv) {
            printf("%s %8d %10x %8d\n", out_r,
                   pm_index, ipv4_address, aport);
        } else {
            printf("%s failed\n", out_r);
            return;
        }
    }

    if (nodd_ports > neven_ports) {
        k1 = nodd_ports;
        k2 = neven_ports;
        pt1 = PORT_S_ODD;
        pt2 = PORT_S_EVEN;
        out1 = out_o;
        out2 = out_e;
    } else {
        k1= neven_ports;
        pt1 = PORT_S_EVEN;
        k2 = nodd_ports;
        pt2 = PORT_S_ODD;
        out1 = out_e;
        out2 = out_o;
    }

    j = 0;
    for (i=0; i < k1; i++) {
#ifdef LB_PORT
        rv = cnat_port_alloc (pm, pm_inuse, my_instance,
                                  PORT_ALLOC_DIRECTED, pt1,
                                  &pm_index, &ipv4_address, &aport);
#else
        rv = cnat_port_alloc (pm, pm_inuse,
                                  PORT_ALLOC_DIRECTED, pt1,
                                  &pm_index, &ipv4_address, &aport);
#endif
        if (rv) {
            printf("%s %8d %10x %8d\n", out1,
                   pm_index, ipv4_address, aport);
        } else {
            printf("%s failed\n", out1);
            return;
        }

        if (j < k2) {
#ifdef LB_PORT
            rv = cnat_port_alloc (pm, pm_inuse, my_instance,
                                  PORT_ALLOC_DIRECTED, pt2,
                                  &pm_index, &ipv4_address, &aport);
#else
            rv = cnat_port_alloc (pm, pm_inuse,
                                  PORT_ALLOC_DIRECTED, pt2,
                                  &pm_index, &ipv4_address, &aport);
#endif

            if (rv) {
                printf("%s %8d %10x %8d\n", out2,
                   pm_index, ipv4_address, aport);
                j++;
            } else {
                printf("%s failed\n", __FUNCTION__);
                return;
           }
        }
    }
}

void cnat_db_summary_stats (int argc, unsigned long *argv)
{
    spp_api_cnat_show_statistics_summary_req_t mp[50000];

    spp_api_cnat_show_statistics_summary_req_t_handler(&(mp[0]));
}

void cnat_debug_global_test  (int argc, unsigned long *argv)
{
    spp_api_cnat_v4_debug_global_t *mp;
    spp_api_cnat_v4_config_dummy_t mp1;
    spp_api_cnat_v4_config_icmp_timeout_t mp2[10];

    mp = spp_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof (*mp));


    mp->_spp_msg_id = SPP_API_CNAT_V4_DEBUG_GLOBAL;
    mp->debug_flag  = argv[0];

    platform_send_msg(mp);

     mp2[0].default_value = 3;

     spp_api_cnat_v4_config_dummy_t_handler(&mp1);
     spp_api_cnat_v4_config_icmp_timeout_t_handler(&(mp2[0]));
}

void cnat_debug_inside_test  (int argc, unsigned long *argv)
{

    spp_api_cnat_v4_debug_in2out_private_addr_t *mp;

    mp = spp_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof (*mp));


    mp->_spp_msg_id = SPP_API_CNAT_V4_DEBUG_IN2OUT_PRIVATE_ADDR;

    mp->start_addr = spp_host_to_net_byte_order_32(argv[0]);
    mp->end_addr = spp_host_to_net_byte_order_32(argv[1]);
    mp->i_vrf = spp_host_to_net_byte_order_16(argv[2]);
    mp->debug_flag = spp_host_to_net_byte_order_32(argv[3]);

    platform_send_msg(mp);
}

void cnat_config_ports_user (int argc, unsigned long *argv)
{
    spp_api_cnat_v4_config_port_limit_t *mp;

    mp = spp_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof (*mp));


    mp->_spp_msg_id = SPP_API_CNAT_V4_CONFIG_PORT_LIMIT;

    mp->port_limit = spp_host_to_net_byte_order_16(argv[0]);

    platform_send_msg(mp);

}

void cnat_debug_outside_test  (int argc, unsigned long *argv)
{

    spp_api_cnat_v4_debug_out2in_public_addr_t *mp;

    mp = spp_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof (*mp));


    mp->_spp_msg_id = SPP_API_CNAT_V4_DEBUG_OUT2IN_PUBLIC_ADDR;

    mp->start_addr = spp_host_to_net_byte_order_32(argv[0]);
    mp->end_addr = spp_host_to_net_byte_order_32(argv[1]);
    mp->o_vrf = spp_host_to_net_byte_order_16(argv[2]);
    mp->debug_flag = spp_host_to_net_byte_order_32(argv[3]);

    platform_send_msg(mp);
}

void cnat_debug_udp_dump (int argc, unsigned long *argv)
{

    spp_api_cnat_p2mp_debug_request_t *mp;

    mp = spp_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof (*mp));


    mp->_spp_msg_id = SPP_API_CNAT_P2MP_DEBUG_REQUEST;
    mp->dump_type = 
        spp_host_to_net_byte_order_16(CNAT_DEBUG_GENERIC_COMMAND_DEBUG_FLAGS);

    if (spp_host_to_net_byte_order_32(argv[0]) == 1) {
        mp->param[0] = spp_host_to_net_byte_order_32(
	                   CNAT_DEBUG_FLAG_UDP_INSIDE_PACKET_DUMP);
    } else {
        mp->param[0] = spp_host_to_net_byte_order_32(
	                   CNAT_DEBUG_FLAG_UDP_OUTSIDE_PACKET_DUMP);
    }
    mp->param[1] = spp_host_to_net_byte_order_32(argv[1]);
    
    platform_send_msg(mp);



}

void cnat_debug_udp_crc (int argc, unsigned long *argv)
{
    spp_api_cnat_p2mp_debug_request_t *mp;

    mp = spp_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof (*mp));


    mp->_spp_msg_id = SPP_API_CNAT_P2MP_DEBUG_REQUEST;
    mp->dump_type = 
        spp_host_to_net_byte_order_16(CNAT_DEBUG_GENERIC_COMMAND_DEBUG_FLAGS);

    if (spp_host_to_net_byte_order_32(argv[0]) == 1) {
        mp->param[0] = spp_host_to_net_byte_order_32(
	                   CNAT_DEBUG_FLAG_UDP_INSIDE_CHECKSUM_MODIFY);
    } else {
        mp->param[0] = spp_host_to_net_byte_order_32(
	                   CNAT_DEBUG_FLAG_UDP_OUTSIDE_CHECKSUM_MODIFY);
    }
    mp->param[1] = spp_host_to_net_byte_order_32(argv[1]);
    
    platform_send_msg(mp);

}

void cnat_db_allocate_port_cmd (int argc, unsigned long *argv)
{
    spp_api_cnat_port_allocate_t *mp;


    if (!argc) {
        printf("no port# defined\n");
        return;
    }

    if ( argc < 3) {
         printf("no port# defined\n");
        return;
    }

    if ((argc == 3) && (argv[0] == 0) && (argv[1] == 0) && (argv[2] == 0)) {
         printf("no port# defined\n");
        return;
    }

    mp = spp_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof (*mp));


    mp->_spp_msg_id = SPP_API_CNAT_PORT_ALLOCATE;
    mp->nr_ports =  argv[0];
    mp->nodd_ports = argv[1];
    mp->neven_ports = argv[2];
    mp->vrf = 1;

    platform_send_msg(mp);
}


void spp_api_cnat_port_clear_t_handler(spp_api_cnat_port_clear_t *mp)
{
    u32 i;
    cnat_portmap_t *pm = 0;
    u16 *pm_inuse = 0;
#ifdef LB_PORT
    u32 my_instance = 1;
#endif


    /*
     * this command is run after db create port
     * vrf is hardcode to 1
     */

    /* Already have a portmap vector for this VRF? */
    for (i = 0; i < vec_len(cnat_portmap_indices_by_vrf); i++) {
        if (cnat_portmap_indices_by_vrf[i] == mp->vrf) {
            pm = cnat_portmaps[i];
            pm_inuse = cnat_portmaps_inuse[i];
            goto found_portmaps;
        }
    }

    printf("portmap is not created 0x%d\n",
            vec_len(cnat_portmap_indices_by_vrf));
    return;

found_portmaps:
    if (mp->pm_index >= vec_len(pm)) {
        printf("invalid port_index 0x%d >=  0x%d\n",
               mp->pm_index, vec_len(pm));
         return;
    }

#ifdef LB_PORT
    cnat_port_free(pm, pm_inuse, my_instance,
                   mp->pm_index, PORT_SINGLE, mp->port);
#else
    cnat_port_free(pm, pm_inuse,
                   mp->pm_index, PORT_SINGLE, mp->port);
#endif
    printf("\n pm_index %d port %d is deleted\n", mp->pm_index, mp->port);
}



void cnat_db_clear_port_cmd (int argc, unsigned long *argv)
{
    spp_api_cnat_port_clear_t *mp;

    if (!argc) {
        printf("no port# defined\n");
        return;
    }

    if ( argc < 2 ) {
         printf("no port# defined\n");
        return;
    }

    if (argc > 2) {
         printf("too many port# defined\n");
        return;
    }

    mp = spp_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof (*mp));


    mp->_spp_msg_id = SPP_API_CNAT_PORT_CLEAR;
    mp->pm_index =  argv[0];
    mp->port = argv[1];
    mp->vrf = 1;

    platform_send_msg(mp);
}


void spp_api_cnat_v4_add_vrf_map_t_handler
(spp_api_cnat_v4_add_vrf_map_t *mp);

void spp_api_cnat_v4_del_vrf_map_t_handler
(spp_api_cnat_v4_del_vrf_map_t *mp);

void spp_api_cnat_v4_add_static_port_t_handler
(spp_api_cnat_v4_add_static_port_t *mp);

void spp_api_cnat_v4_del_static_port_t_handler
(spp_api_cnat_v4_del_static_port_t *mp);


void cnat_db_create_vrfmap_cmd (int argc, unsigned long *argv)
{
    spp_api_cnat_v4_add_vrf_map_t *mp;

    if ((argc != 4)) { 
        printf("need right input\n");
        return;
    }

    mp = spp_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof (*mp));
    mp->_spp_msg_id = SPP_API_CNAT_V4_ADD_VRF_MAP;
    mp->i_vrf = spp_host_to_net_byte_order_16(argv[0]);
    mp->o_vrf = spp_host_to_net_byte_order_16(argv[1]);
    mp->start_addr[0] = spp_host_to_net_byte_order_32(argv[2]);
    mp->end_addr[0] = spp_host_to_net_byte_order_32(argv[3]);

    /*
     * Some hardcoded values for the vrf ids
     */
    mp->i_vrf_id = spp_host_to_net_byte_order_32(0x00000100 | mp->i_vrf);
    mp->o_vrf_id = spp_host_to_net_byte_order_32(0x00000200 | mp->o_vrf);

    platform_send_msg(mp);
}


void cnat_db_delete_vrfmap_cmd (int argc, unsigned long *argv)
{
    spp_api_cnat_v4_del_vrf_map_t *mp;

    if (argc != 4) { 
        printf("need right input\n");
        return;
    }

    mp = spp_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof (*mp));
    mp->_spp_msg_id = SPP_API_CNAT_V4_DEL_VRF_MAP;
    mp->i_vrf = spp_host_to_net_byte_order_16(argv[0]);
    mp->start_addr[0] = spp_host_to_net_byte_order_32(argv[2]);
    mp->end_addr[0] = spp_host_to_net_byte_order_32(argv[3]);

    platform_send_msg(mp);
}

void cnat_db_add_svi_cmd (int argc, unsigned long *argv)
{
    spp_api_cnat_config_svi_params_t *mp;

    if (argc != 3)  {
        printf("need right input\n");
        return;
    }

   
    mp = spp_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof (*mp));
    mp->_spp_msg_id = SPP_API_CNAT_CONFIG_SVI_PARAMS;
    mp->uidb_index = spp_host_to_net_byte_order_16(argv[1]);
    mp->svi_ipv4_addr = spp_host_to_net_byte_order_32(argv[2]);
    platform_send_msg(mp);
    return;
}



void spp_api_cnat_port_create_t_handler(spp_api_cnat_port_create_t *mp)
{
    int i, j, k1, k2;
    int my_index;
    u32 ipv4_address;
    u16 aport;
    u32 pm_len =0;
    cnat_errno_t rv;
    u16   i_vrf;
    char *out1, *out2, *out_f;
    port_alloc_t pt1, pt2;
    cnat_vrfmap_t  *my_vrfmap;
    cnat_portmap_v2_t *pm = 0;
    u32 *firstp =0;
    u32 nr_ports =0;
    u32 nodd_ports = 0;
    u32 neven_ports = 0;
#ifdef LB_PORT
    u32 my_instance = 1;
#endif
    char out_r[12] = "allocated-r";
    char out_o[12] = "allocated-o";
    char out_e[12] = "allocated-e";
#ifndef NO_BULK_LOGGING
    int nfv9_log_req;
#endif

    nr_ports = mp->nr_ports;
    nodd_ports = mp->nodd_ports;
    neven_ports = mp->neven_ports;
    i_vrf = mp->vrf;

    /*
     * this command is run after db create vrfmap
     * or using vrf id in init function
     */
    /* Already have a portmap vector for this VRF? */
    pool_foreach (my_vrfmap, cnat_map_by_vrf, ({
        if ((my_vrfmap->status == S_RUN) &&
            (my_vrfmap->i_vrf == i_vrf)) {
            pm = my_vrfmap->portmap_list;
            pm_len = vec_len(pm);
            if (pm_len) { 
                goto found_portmaps;
            }
        }
    }));

    printf("need to run db create vrfmaps first for this vrf0x%d\n", pm_len);
    return;

found_portmaps:

    if ((nr_ports + nodd_ports + neven_ports ) > (PORTS_PER_ADDR)) {
        printf("invalid port# nr_ports %d + odd %d + even %d "
               "should be less than 200 \n", nr_ports, nodd_ports, neven_ports);
        return;
    }

    /*
     * first port
     */
    firstp = nr_ports ? (&nr_ports) : (nodd_ports ? (&nodd_ports) : (&neven_ports));
    if (!(*firstp)) {
        printf("invalid port# nr_ports %d  odd %d  even %d ",
               nr_ports, nodd_ports, neven_ports);
    }
    out_f = nr_ports ? out_r : (nodd_ports ? out_o : out_e);

    rv = cnat_dynamic_port_alloc_v2 (pm,  PORT_ALLOC_ANY, PORT_S_ODD,
                          &my_index, &ipv4_address, &aport, 
                          cnat_static_port_range
#ifndef NO_BULK_LOGGING
                          , BULKSIZE_FROM_VRFMAP(my_vrfmap), 
                          &nfv9_log_req
#endif
                          , 0,
                          &(my_vrfmap->rseed_ip)
                          );

    if (rv != CNAT_SUCCESS) {
        printf("failed-o\n");
        return;
    }
    printf("%s %8d %10x %8d\n", out_f,
            my_index, ipv4_address, aport);

    (*firstp)--;

    for (i=0; i < nr_ports; i++) {
        rv = cnat_dynamic_port_alloc_v2 (pm, PORT_ALLOC_DIRECTED, PORT_SINGLE, 
                          &my_index, &ipv4_address, &aport,
                          cnat_static_port_range
#ifndef NO_BULK_LOGGING
                          , BULKSIZE_FROM_VRFMAP(my_vrfmap), 
                          &nfv9_log_req
#endif
                          , 0,
                          &(my_vrfmap->rseed_ip)
                          );

        if (rv == CNAT_SUCCESS) {
            printf("%s %8d %10x %8d\n", out_r,
                   my_index, ipv4_address, aport);
        } else {
            printf("%s failed\n", __FUNCTION__);
            return;
        }
    } 
 
    if (nodd_ports > neven_ports) {
        k1 = nodd_ports;
        k2 = neven_ports;
        pt1 = PORT_S_ODD;
        pt2 = PORT_S_EVEN;
        out1 = out_o;
        out2 = out_e;
    } else {
        k1= neven_ports;
        pt1 = PORT_S_EVEN;
        k2 = nodd_ports;
        pt2 = PORT_S_ODD;
        out1 = out_e;
        out2 = out_o;
    }

    j = 0;
    for (i=0; i < k1; i++) {
        rv = cnat_dynamic_port_alloc_v2 (pm, PORT_ALLOC_DIRECTED, pt1, 
                          &my_index, &ipv4_address, &aport,
                          cnat_static_port_range
#ifndef NO_BULK_LOGGING
                          , BULKSIZE_FROM_VRFMAP(my_vrfmap), 
                          &nfv9_log_req
#endif
                          , 0,
                          &(my_vrfmap->rseed_ip)
                          );

        if (rv == CNAT_SUCCESS) {
            printf("%s %8d %10x %8d\n", out1,
                   my_index, ipv4_address, aport);
        } else {
            printf("%s failed\n", __FUNCTION__);
            return;
        }

        if (j < k2) {
            rv = cnat_dynamic_port_alloc_v2 (pm, PORT_ALLOC_DIRECTED, pt2,
                          &my_index, &ipv4_address, &aport,
                          cnat_static_port_range
#ifndef NO_BULK_LOGGING
                          , BULKSIZE_FROM_VRFMAP(my_vrfmap), 
                          &nfv9_log_req
#endif
                          , 0,
                          &(my_vrfmap->rseed_ip)
                          );
            
            if (rv == CNAT_SUCCESS) {
                printf("%s %8d %10x %8d\n", out2,
                   my_index, ipv4_address, aport);
                j++;
            } else {
                printf("%s failed\n", __FUNCTION__);
            return;
                return;
           }
        }
    }
}


void cnat_db_create_port_cmd (int argc, unsigned long *argv)
{
    spp_api_cnat_port_create_t *mp;

    if (argc != 4) {
        printf("no proper input defined\n");
        return;
    }
 
    if ((argv[0] == 0) && (argv[1] == 0) && (argv[2] == 0)) {
         printf("no port# defined\n");
        return;
    }

    mp = spp_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof (*mp));


    mp->_spp_msg_id = SPP_API_CNAT_PORT_CREATE;
    mp->nr_ports =  argv[0];
    mp->nodd_ports = argv[1];
    mp->neven_ports = argv[2];
    mp->vrf = argv[3];

    platform_send_msg(mp);
}

void spp_api_cnat_port_delete_t_handler(spp_api_cnat_port_delete_t *mp)
{
    u32 pm_len;
    cnat_vrfmap_t  *my_vrfmap;
    cnat_portmap_v2_t *pm = 0;

    u32 my_index, my_port;
    u16 i_vrf;
#ifdef LB_PORT
    u32 my_instance = 1;
#endif

    my_index = mp->pm_index;
    my_port = mp->port;
    i_vrf = mp->vrf;

    /*
     * this command is run after db create port
     */
    pool_foreach (my_vrfmap, cnat_map_by_vrf, ({
        if (my_vrfmap->i_vrf == i_vrf) {
            pm = my_vrfmap->portmap_list;
            pm_len = vec_len(pm);
            if (pm_len)  {
                goto found_portmaps;
            }
        }
    }));

    printf("portmap is not created 0x%d\n",
            vec_len(cnat_portmap_indices_by_vrf));
    return;

found_portmaps:
    if (my_index >= pm_len) {
        printf("invalid port_index 0x%d >=  0x%d\n",
               my_index, pm_len);
         return;
    }

#ifdef LB_PORT
    cnat_port_free_v2(pm, my_instance,
                    my_index, PORT_SINGLE, mp->port,cnat_static_port_range);
#else 
    cnat_port_free_v2(pm, my_index, PORT_SINGLE, mp->port,cnat_static_port_range);
#endif
    printf("\n pm_index %d port %d is deleted\n", mp->pm_index, mp->port);
}

void cnat_db_delete_port_cmd (int argc, unsigned long *argv)
{
    spp_api_cnat_port_clear_t *mp;

    if (argc != 3) {
        printf("no proper input defined\n");
        return;
    }

    mp = spp_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof (*mp));


    mp->_spp_msg_id = SPP_API_CNAT_PORT_DELETE;
    mp->pm_index =  argv[0];
    mp->port = argv[1];
    mp->vrf = argv[2];
    platform_send_msg(mp);
}

void cnat_db_create_static_fwd_cmd (int argc, unsigned long *argv)
{
    spp_api_cnat_v4_add_static_port_t *mp;

    if (argc != 4)  {
        printf("need right input\n");
        return;
    }

    mp = spp_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof (*mp));
    mp->_spp_msg_id = SPP_API_CNAT_V4_ADD_STATIC_PORT;
    mp->i_vrf = spp_host_to_net_byte_order_16(argv[0]);
    mp->i_ip = spp_host_to_net_byte_order_32(argv[1]);
    mp->i_port = spp_host_to_net_byte_order_16(argv[2]);
    mp->proto = argv[3];

    platform_send_msg(mp);
    return;
}

void cnat_db_create_static_fwd_stby_cmd (int argc, unsigned long *argv)
{
    spp_api_cnat_v4_add_static_port_t *mp;

    if (argc != 7)  {
        printf("need right input\n");
        return;
    }

    mp = spp_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof (*mp));
    mp->_spp_msg_id = SPP_API_CNAT_V4_ADD_STATIC_PORT;
    mp->i_vrf = spp_host_to_net_byte_order_16(argv[0]);
    mp->i_ip = spp_host_to_net_byte_order_32(argv[1]);
    mp->i_port = spp_host_to_net_byte_order_16(argv[2]);
    mp->proto = argv[3];
    mp->o_vrf_id = spp_host_to_net_byte_order_32(argv[4]);
    mp->o_ip = spp_host_to_net_byte_order_32(argv[5]);
    mp->o_port = spp_host_to_net_byte_order_16(argv[6]);

printf("\ni_vrf %d, ip 0x%x, port %d, o_ip, port %d", mp->i_vrf, mp->i_ip, mp->i_port, mp->o_ip, mp->o_port);

    platform_send_msg(mp);
    return;
}

void cnat_db_delete_static_fwd_cmd (int argc, unsigned long *argv)
{
    spp_api_cnat_v4_del_static_port_t *mp;

    if (argc != 3)  {
        printf("need right input\n");
        return;
    }
    
    mp = spp_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof (*mp));
    mp->_spp_msg_id = SPP_API_CNAT_V4_DEL_STATIC_PORT;
    mp->i_vrf = spp_host_to_net_byte_order_16(argv[0]);
    mp->i_ip = spp_host_to_net_byte_order_32(argv[1]);
    mp->i_port = spp_host_to_net_byte_order_16(argv[2]);

    platform_send_msg(mp);
    return;
}

void cnat_nfv9_create_cmd (int argc, unsigned long *argv)
{
    spp_api_cnat_v4_config_nfv9_logging_t *mp;

    if (argc < 3) {
        printf("nfv9 create i_vrf ip_addr port [refresh_rate] [timeout] [mtu]");
        return;
    }

    mp = spp_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof (*mp));
    mp->_spp_msg_id = SPP_API_CNAT_V4_CONFIG_NFV9_LOGGING;
    mp->enable = 1;
    mp->i_vrf = spp_host_to_net_byte_order_16(argv[0]);

    mp->ipv4_address = spp_host_to_net_byte_order_32(argv[1]);
    mp->port = spp_host_to_net_byte_order_16(argv[2]);

    if (argc > 3) {
	mp->refresh_rate = spp_host_to_net_byte_order_16(argv[3]);
	mp->timeout_rate = spp_host_to_net_byte_order_16(argv[4]);
	mp->path_mtu = spp_host_to_net_byte_order_16(argv[5]);
    } else {
	mp->refresh_rate = spp_host_to_net_byte_order_16(1000);
	mp->timeout_rate = spp_host_to_net_byte_order_16(30);
	mp->path_mtu = spp_host_to_net_byte_order_16(1500);
    }
   platform_send_msg(mp);
}

void cnat_delete_cgn (int argc, unsigned long *argv)
{
    void *mp_send;
    spp_api_cnat_del_cgn_t *mp;
    u32 mp_size;

    mp_size = sizeof(spp_api_cnat_del_cgn_t);

    mp = spp_msg_api_alloc(mp_size);
    memset(mp, 0, mp_size);

    mp->_spp_msg_id = SPP_API_CNAT_DEL_CGN;

    mp_send = mp;

    platform_send_msg(mp);
}

void cnat_debug_global_all (int argc, unsigned long *argv)
{
    spp_api_cnat_v4_debug_global_t *mp;

    mp = spp_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof (*mp));

    mp->_spp_msg_id = SPP_API_CNAT_V4_DEBUG_GLOBAL;
    mp->debug_flag  = CNAT_DEBUG_GLOBAL_ALL;

    platform_send_msg(mp);
}

void cnat_debug_global_none (int argc, unsigned long *argv)
{
    spp_api_cnat_v4_debug_global_t *mp;

    mp = spp_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof (*mp));

    mp->_spp_msg_id = SPP_API_CNAT_V4_DEBUG_GLOBAL;
    mp->debug_flag  = CNAT_DEBUG_NONE;

    platform_send_msg(mp);
}


void cnat_bulk_cmd (int argc, unsigned long *argv)
{
    void *mp_send;

    if (argc < 1) {
	printf("\nargc = %d", argc);
        printf("\n1. bulk cmd [0=static-port, 1=bulk_vrf, 2=policy_knob]");
        return;
    }


    switch (argv[0]) {
        case 0:
	{
	    spp_api_cnat_v4_bulk_add_delete_static_port_t *mp;
	    spp_api_cnat_v4_add_static_port_t *mp_sp;
	    u32 mp_size = 
	            sizeof(spp_api_cnat_v4_bulk_add_delete_static_port_t) +
	                  (sizeof(spp_api_cnat_v4_add_static_port_t))*2;

	    mp = spp_msg_api_alloc(mp_size);
	    memset(mp, 0, mp_size);

	    mp->_spp_msg_id = SPP_API_CNAT_V4_BULK_ADD_DELETE_STATIC_PORT;

	    mp->num_static_port_entries = spp_host_to_net_byte_order_32(3);

	    mp_sp = (spp_api_cnat_v4_add_static_port_t *) &(mp->pad2);

	    mp_sp->_spp_msg_id = spp_host_to_net_byte_order_16(
				SPP_API_CNAT_V4_ADD_STATIC_PORT);
	    mp_sp->proto = 2;
	    mp_sp->i_vrf = spp_host_to_net_byte_order_16(0x1);
	    mp_sp->i_ip = spp_host_to_net_byte_order_32(0x11111111);
	    mp_sp->i_port = spp_host_to_net_byte_order_16(0x7777);

	    mp_sp++;


	    mp_sp->_spp_msg_id = spp_host_to_net_byte_order_16(
				SPP_API_CNAT_V4_ADD_STATIC_PORT);
	    mp_sp->proto = 1;
	    mp_sp->i_vrf = spp_host_to_net_byte_order_16(0x1);
	    mp_sp->i_ip = spp_host_to_net_byte_order_32(0x22222222);
	    mp_sp->i_port = spp_host_to_net_byte_order_16(0x6666);

	    mp_sp++;


	    mp_sp->_spp_msg_id = spp_host_to_net_byte_order_16(
				SPP_API_CNAT_V4_ADD_STATIC_PORT);
	    mp_sp->proto = 1;
	    mp_sp->i_vrf = spp_host_to_net_byte_order_16(0x1);
	    mp_sp->i_ip = spp_host_to_net_byte_order_32(0x33333333);
	    mp_sp->i_port = spp_host_to_net_byte_order_16(0x5555);

	    mp_send = mp;

	}
	break;

	case 1:
	{
	    spp_api_cnat_v4_bulk_vrf_map_t *mp;
	    spp_api_cnat_v4_single_vrf_map_req *mp_sp;

	    u32 mp_size = sizeof(spp_api_cnat_v4_bulk_vrf_map_t) +
	                  (sizeof(spp_api_cnat_v4_single_vrf_map_req))*2;

	    mp = spp_msg_api_alloc(mp_size);
	    memset(mp, 0, mp_size);

	    mp->_spp_msg_id = SPP_API_CNAT_V4_BULK_VRF_MAP;

	    mp->num_vrfmap_entries = spp_host_to_net_byte_order_32(3);

	    mp_sp = (spp_api_cnat_v4_single_vrf_map_req *)
	                &(mp->vrf_policy_enable);

	    mp_sp->i_vrf_id = spp_host_to_net_byte_order_32(0xe0000001);
	    mp_sp->o_vrf_id = spp_host_to_net_byte_order_32(0xe0000000);
	    mp_sp->i_vrf = spp_host_to_net_byte_order_16(0x1);
	    mp_sp->o_vrf = spp_host_to_net_byte_order_16(0x0);
	    mp_sp->start_addr = spp_host_to_net_byte_order_32(0x11111100);
	    mp_sp->end_addr = spp_host_to_net_byte_order_32(0x111111ff);
	    mp_sp->vrf_policy_enable = spp_host_to_net_byte_order_16(0x3);
	    mp_sp->tcp_mss_value = spp_host_to_net_byte_order_16(0x111);
	    mp_sp->vrf_nfv9_logging_ipv4_address = spp_host_to_net_byte_order_32(0x11000001);
	    mp_sp->vrf_nfv9_logging_udp_port = spp_host_to_net_byte_order_16(0x1001);
	    mp_sp->vrf_nfv9_refresh_rate = spp_host_to_net_byte_order_16(0x100);
	    mp_sp->vrf_nfv9_timeout_rate = spp_host_to_net_byte_order_16(0x10);
	    mp_sp->vrf_nfv9_path_mtu = spp_host_to_net_byte_order_16(0x100);

	    mp_sp++;

	    mp_sp->i_vrf_id = spp_host_to_net_byte_order_32(0xe0000002);
	    mp_sp->o_vrf_id = spp_host_to_net_byte_order_32(0xe0000000);
	    mp_sp->i_vrf = spp_host_to_net_byte_order_16(0x2);
	    mp_sp->o_vrf = spp_host_to_net_byte_order_16(0x0);
	    mp_sp->start_addr = spp_host_to_net_byte_order_32(0x22220000);
	    mp_sp->end_addr = spp_host_to_net_byte_order_32(0x2222ffff);
	    mp_sp->vrf_policy_enable = spp_host_to_net_byte_order_16(0x1);
	    mp_sp->tcp_mss_value = spp_host_to_net_byte_order_16(0x222);
	    mp_sp->vrf_nfv9_logging_ipv4_address = spp_host_to_net_byte_order_32(0x22000002);
	    mp_sp->vrf_nfv9_logging_udp_port = spp_host_to_net_byte_order_16(0x2002);
	    mp_sp->vrf_nfv9_refresh_rate = spp_host_to_net_byte_order_16(0x200);
	    mp_sp->vrf_nfv9_timeout_rate = spp_host_to_net_byte_order_16(0x20);
	    mp_sp->vrf_nfv9_path_mtu = spp_host_to_net_byte_order_16(0x200);

	    mp_sp++;

	    mp_sp->i_vrf_id = spp_host_to_net_byte_order_32(0xe0000003);
	    mp_sp->o_vrf_id = spp_host_to_net_byte_order_32(0xe0000007);
	    mp_sp->i_vrf = spp_host_to_net_byte_order_16(0x3);
	    mp_sp->o_vrf = spp_host_to_net_byte_order_16(0x7);
	    mp_sp->start_addr = spp_host_to_net_byte_order_32(0x33333000);
	    mp_sp->end_addr = spp_host_to_net_byte_order_32(0x33333fff);
	    mp_sp->vrf_policy_enable = spp_host_to_net_byte_order_16(0x1);
	    mp_sp->tcp_mss_value = spp_host_to_net_byte_order_16(0x333);
	    mp_sp->vrf_nfv9_logging_ipv4_address = spp_host_to_net_byte_order_32(0x33000003);
	    mp_sp->vrf_nfv9_logging_udp_port = spp_host_to_net_byte_order_16(0x3003);
	    mp_sp->vrf_nfv9_refresh_rate = spp_host_to_net_byte_order_16(0x300);
	    mp_sp->vrf_nfv9_timeout_rate = spp_host_to_net_byte_order_16(0x30);
	    mp_sp->vrf_nfv9_path_mtu = spp_host_to_net_byte_order_16(0x300);

	    mp_send = mp;
	}
	break;

	case 2:
	{
	    spp_api_cnat_v4_bulk_policy_knob_t *mp;

	    u32 mp_size = 
	        sizeof(spp_api_cnat_v4_bulk_policy_knob_t) +
	        (sizeof(spp_api_cnat_v4_single_vrf_map_req))*2;

	    mp = spp_msg_api_alloc(mp_size);
	    memset(mp, 0, mp_size);

	    mp->_spp_msg_id = SPP_API_CNAT_V4_BULK_POLICY_KNOB;

	    mp->port_limit = spp_host_to_net_byte_order_16(345);
	    mp->icmp_timeout = spp_host_to_net_byte_order_16(300);
	    mp->udp_init_timeout = spp_host_to_net_byte_order_16(175);
	    mp->udp_act_timeout = spp_host_to_net_byte_order_16(133);
	    mp->tcp_init_timeout = spp_host_to_net_byte_order_16(222);
	    mp->tcp_act_timeout = spp_host_to_net_byte_order_16(2345);

	    mp->nat_policy_enable = spp_host_to_net_byte_order_32(0x7);

	    mp->global_nfv9_logging_ipv4_address = spp_host_to_net_byte_order_32(0x77777777);
	    mp->global_nfv9_logging_udp_port = spp_host_to_net_byte_order_16(0x7007);
	    mp->global_nfv9_refresh_rate = spp_host_to_net_byte_order_16(0x700);
	    mp->global_nfv9_timeout_rate = spp_host_to_net_byte_order_16(0x70);
	    mp->global_nfv9_path_mtu = spp_host_to_net_byte_order_16(0x700);

	    mp_send = mp;
	}
	break;


	default:
	   printf("\nargv[2] = %d", argv[2]);
	   printf("\n2. bulk cmd [0=static-port, 1=bulk_vrf, 2=policy_knob+bulk_vrf]");
	   return;

    }
    platform_send_msg(mp_send);
}

void cnat_nfv9_delete_cmd (int argc, unsigned long *argv)
{
    spp_api_cnat_v4_config_nfv9_logging_t *mp;

    if (argc != 1) {
        printf("nfv9 delete i_vrf ");
        return;
    }

    mp = spp_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof (*mp));
    mp->_spp_msg_id = SPP_API_CNAT_V4_CONFIG_NFV9_LOGGING;
    mp->enable = 0;
    mp->i_vrf = spp_host_to_net_byte_order_16(argv[0]);
    platform_send_msg(mp);
}

void cnat_generic_cmd (int argc, unsigned long *argv)
{
    spp_api_cnat_generic_command_request_t *mp;

    if (argc != 9) {
        printf("generic command core type p1 p2 p3 p4 p5 p6 p7 ");
        return;
    }

    /*
     * Allocate a large buffer for message req and resp structure
     */
    mp = spp_msg_api_alloc (MAX_DEBUG_BUFFER_SIZE);
    memset(mp, 0, MAX_DEBUG_BUFFER_SIZE);
    mp->_spp_msg_id = SPP_API_CNAT_GENERIC_COMMAND_REQUEST;
    mp->core_num = argv[0];
    mp->params[0] = spp_host_to_net_byte_order_32(argv[1]);
    mp->params[1] = spp_host_to_net_byte_order_32(argv[2]);
    mp->params[2] = spp_host_to_net_byte_order_32(argv[3]);
    mp->params[3] = spp_host_to_net_byte_order_32(argv[4]);
    mp->params[4] = spp_host_to_net_byte_order_32(argv[5]);
    mp->params[5] = spp_host_to_net_byte_order_32(argv[6]);
    mp->params[6] = spp_host_to_net_byte_order_32(argv[7]);
    mp->params[7] = spp_host_to_net_byte_order_32(argv[8]);
    platform_send_msg(mp);
}

u32 icmp_sent_timestamps; /* 32 KB array per core */
u8 v4_pkt_count = 0;

cnat_icmp_msg_t icmp_msg_gen_allowed ()
{
#ifdef DISABLE_ICMP_THROTTLE_FOR_DEBUG_PURPOSE
    return CNAT_ICMP_MSG;
#else
    u32 current_timestamp;
    spp_node_main_vector_t *nmv;
    u32 updated_timestamp;

    v4_pkt_count ++;
        
    nmv = spp_get_node_main_vectorized_inline();

    current_timestamp = nmv->ticks / nmv->ticks_per_second;
    
    PLATFORM_UPDATE_TIMESTAMP
    if (PREDICT_FALSE(icmp_sent_timestamps != updated_timestamp)) {
        v4_pkt_count = 1;
        /* update timestamp */
        icmp_sent_timestamps = updated_timestamp;
    } 
    if (PREDICT_TRUE(v4_pkt_count <= cnat_main_db_icmp_rate_limit_core)) {
            return CNAT_ICMP_MSG;
    } else {
            return CNAT_NO_ICMP_MSG;
    }
#endif
}

u32 v6_icmp_sent_timestamps; /* 32 KB array per core */
u8 v6_pkt_count = 0;

cnat_icmp_msg_t v6_icmp_msg_gen_allowed ()
{
#ifdef DISABLE_ICMP_THROTTLE_FOR_DEBUG_PURPOSE
    return CNAT_ICMP_MSG;
#else
    u32 current_timestamp;
    spp_node_main_vector_t *nmv;
    u32 updated_timestamp;

    nmv = spp_get_node_main_vectorized_inline();

    current_timestamp = nmv->ticks / nmv->ticks_per_second;
    PLATFORM_UPDATE_TIMESTAMP
    v6_pkt_count ++;

    if (PREDICT_FALSE(v6_icmp_sent_timestamps != updated_timestamp)) {
        v6_pkt_count = 1;
        /* update timestamp */
        v6_icmp_sent_timestamps = updated_timestamp;
    }
    if (PREDICT_TRUE(v6_pkt_count <= cnat_main_db_icmp_rate_limit_core)) {
            return CNAT_ICMP_MSG;
    } else {
            return CNAT_NO_ICMP_MSG;
    }
#endif
}

u32 v4_udp_crc_zero_timestamps; 
u32 v4_udp_crc_zero_pkt_count = 0;
int v4_crc_zero_udp_allowed ()
{
    PLATFORM_V4_CRC_ZERO_UDP_ALLOWED
    /* Currently not supported for Brahmos. we need to take care of this */
   spp_node_main_vector_t *nmv;
   u32 hash_value, current_timestamp;

    nmv = spp_get_node_main_vectorized_inline();

     current_timestamp = nmv->ticks / nmv->ticks_per_second;
    v4_udp_crc_zero_pkt_count++;
    if (PREDICT_FALSE(v4_udp_crc_zero_timestamps != current_timestamp)) {
        v4_udp_crc_zero_pkt_count = 1;
        v4_udp_crc_zero_timestamps = current_timestamp;
     }
    if (PREDICT_TRUE(v4_udp_crc_zero_pkt_count <= 
                crc_zero_udp_rate_limit_core)) {
        return 1;
    } else {
        return 0;
    }
}

/*
 * ipv4_decr_ttl_n_calc_csum()
 * - It decrements the TTL and calculates the incremental IPv4 checksum
 */

ALWAYS_INLINE(
void ipv4_decr_ttl_n_calc_csum(ipv4_header *ipv4))
{
    u32 checksum;
    u16 old;

    old = ntohs(*(u16 *)&ipv4->ttl);

    /* Decrement TTL */
    ipv4->ttl--;

    /* Calculate incremental checksum */
    checksum = old + (~ntohs(*(u16 *)&ipv4->ttl) & 0xFFFF);
    checksum += ntohs(ipv4->checksum);
    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    ipv4->checksum = htons(checksum + (checksum >> 16));
}

ALWAYS_INLINE(
void calc_ipv4_checksum (ipv4_header *ipv4))
{
    u16 *data = (u16 *) ipv4;
    u32 checksum = 0;

    checksum = crc_calc(ipv4);

    /* Now produce the 1's complement */
    ipv4->checksum = spp_host_to_net_byte_order_16(((u16) (~(u16)checksum)));
}

ALWAYS_INLINE(
void calc_v4_icmp_checksum (icmp_v4_t *icmp, int ipv4_payload_size))
{
    u16 *data = (u16 *) icmp;
    int num_hwords = (ipv4_payload_size)/2;
    u32 checksum = 0;

    icmp->checksum = 0;
    if (PREDICT_FALSE((ipv4_payload_size%2) != 0)) {
        num_hwords += 1; 
        /* Append 0's in the last octet */
        *((u8 *)data + ipv4_payload_size) = 0;
    }
    while (num_hwords) {
        checksum += (u32)spp_net_to_host_byte_order_16(data++);
        num_hwords--;
    }

    /* Add in the carry of the original sum */
    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    /* Add in the carry of the final sum */
    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    /* Now produce the 1's complement */
    icmp->checksum = spp_host_to_net_byte_order_16(((u16) (~(u16)checksum)));
}

ALWAYS_INLINE(
void calc_v6_icmp_checksum (ipv6_header_t *ipv6, u16 ip_payload_size))
{
    u16 *data;
    u16 *data1;
    int i;
    icmp_v6_t *icmp;
    int num_hwords = (ip_payload_size)/2;
    u32 checksum = 0;
    pseudo_v6_header_t pseudo_header;

    icmp = (icmp_v6_t *) ((u8 *)ipv6 + IPV6_HDR_LEN);
    data = (u16 *) icmp;
    icmp->checksum = 0;

#if 1
    if (PREDICT_FALSE((ip_payload_size%2) != 0)) {
        num_hwords += 1;
        /* Append 0's in the last octet */
        *((u8 *)data + ip_payload_size) = 0;
    }
#endif

    /* construct the pseudo header */

    pseudo_header.src_addr[0] = ipv6->src_addr[0];
    pseudo_header.src_addr[1] = ipv6->src_addr[1];
    pseudo_header.src_addr[2] = ipv6->src_addr[2];
    pseudo_header.src_addr[3] = ipv6->src_addr[3];
    pseudo_header.dst_addr[0] = ipv6->dst_addr[0];
    pseudo_header.dst_addr[1] = ipv6->dst_addr[1];
    pseudo_header.dst_addr[2] = ipv6->dst_addr[2];
    pseudo_header.dst_addr[3] = ipv6->dst_addr[3];
    pseudo_header.payload_length = spp_host_to_net_byte_order_16(ip_payload_size);
    pseudo_header.next_header = spp_host_to_net_byte_order_16(ipv6->next_header);

    data1 = (u16 *) &pseudo_header;

    /* sizeof(pseudo_v6_header_t) = 36 */
    for (i = 0; i < 18; i++) {
       checksum += (u32)spp_net_to_host_byte_order_16(data1++);
    }

checksum_calc:

    if (PREDICT_TRUE(num_hwords)) {
        checksum += (u32)spp_net_to_host_byte_order_16(data);
        num_hwords--;
        data++;
        goto checksum_calc;
    }
            
    /* Add in the carry of the original sum */
    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    /* Add in the carry of the final sum */
    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    /* Now produce the 1's complement */
    icmp->checksum = spp_host_to_net_byte_order_16(((u16) (~(u16)checksum)));
}

void icmp_error_generate_v6 (spp_ctx_t *ctx, u8 icmp_type,
                              u8 icmp_code, u16 uidb_index) {

    u16          ip_hdr_len, ip_payload_size;
    u32         *src_p, * dst_p;
    icmp_v6_t   *icmp;
    int          i;
    ipv6_header_t *ip_old, *ip_new;
    u16         icmp_payload_len;
    
    /*
     * As per RFC 2463, we limit the maximum size of generated ICMPv6 message to     * 1280. And hence if the packet is bigger than 1280, then it needs to be
     * truncated. Also, if the packet had multiple chained buffers, we need to
     * free all chained buffers, except the first one.
     */
    free_all_but_first_chained_buffers(ctx);

    ip_hdr_len      = IPV6_HDR_LEN;
    /* offset to ip payload */
    
    ip_old = (ipv6_header_t *)PLATFORM_CTX_CURRENT_HDR;
    ip_new = (ipv6_header_t *) ((u8 *) PLATFORM_CTX_CURRENT_HDR - ICMPV6_ERR_SIZE);
    icmp   = (icmp_v6_t*) ( (u8*)ip_new + ip_hdr_len);
 
     icmp_payload_len = ip_hdr_len + 
         spp_net_to_host_byte_order_16(&(ip_old->payload_length)) ;

     ip_payload_size = ICMPV6_HDR_SIZE + icmp_payload_len;
    /*
     * There is no easy way to predict this case as the probablity that the IPv6
     * pkt is big depends on the type of traffic.  Let us optimize the big
     * pkt case as it involves more processing
     * 
     * If the pkt size exceeds IPV6_MIN_PATH_MTU truncate it to IPV6_MIN_PATH_MTU
     */
     if (PREDICT_TRUE((ip_payload_size + ip_hdr_len) > IPV6_MIN_PATH_MTU)) {
         ip_payload_size = IPV6_MIN_PATH_MTU - ip_hdr_len;
     }

   /* Following ICMP op has to be after ip header being copied */
    icmp->type       = icmp_type;
    icmp->code       = icmp_code;
    
    ip_new->version_trafficclass_flowlabel = spp_host_to_net_byte_order_32(
                                              VERSION_TRAFFICCLASS_FLOWLABEL);
    ip_new->payload_length        = spp_host_to_net_byte_order_16(ip_payload_size);
    ip_new->next_header           = IPV6_PROTO_ICMPV6;
    ip_new->hop_limit             = 64;
    ip_new->dst_addr[0]           = ip_old->src_addr[0];
    ip_new->dst_addr[1]           = ip_old->src_addr[1];
    ip_new->dst_addr[2]           = ip_old->src_addr[2];
    ip_new->dst_addr[3]           = ip_old->src_addr[3];
    
    ip_new->src_addr[0]           = 
      spp_host_to_net_byte_order_32(svi_params_array[uidb_index].ipv6_addr[0]);
    ip_new->src_addr[1]           =
      spp_host_to_net_byte_order_32(svi_params_array[uidb_index].ipv6_addr[1]);
    ip_new->src_addr[2]           = 
      spp_host_to_net_byte_order_32(svi_params_array[uidb_index].ipv6_addr[2]);
    ip_new->src_addr[3]           = 
      spp_host_to_net_byte_order_32(svi_params_array[uidb_index].ipv6_addr[3]);
   /* calc checksum for icmp */

    calc_v6_icmp_checksum(ip_new, ip_payload_size);
#if 0
    printf("Flow = 0x%x\n", ip_new->version_trafficclass_flowlabel);
    printf("Hoplimit = 0x%x\n", ip_new->hop_limit);
    printf("Length= 0x%x\n", ip_new->payload_length);
    printf("Next header = 0x%x\n", ip_new->next_header);
    printf("Src add0 = 0x%x\n", ip_new->src_addr[0]);
    printf("Src add1 = 0x%x\n", ip_new->src_addr[1]);
    printf("Src add2 = 0x%x\n", ip_new->src_addr[2]);
    printf("Src add3 = 0x%x\n", ip_new->src_addr[3]);
    printf("Dst add0 = 0x%x\n", ip_new->dst_addr[0]);
    printf("Dst add1 = 0x%x\n", ip_new->dst_addr[1]);
    printf("Dst add2 = 0x%x\n", ip_new->dst_addr[2]);
    printf("Dst add3 = 0x%x\n", ip_new->dst_addr[3]);
    printf("Icmp type = 0x%x\n", icmp->type);
    printf("Icmp code = 0x%x\n", icmp->code);

    printf("\n\nICMP packet:\n");
    for (i = 0; i < 10; i ++) {
        printf("0x%x " , *((u8 *)icmp + i));
        if ((i%16) == 15) {
            printf("\n");
        }
    }
#endif

    ctx->current_header -= ICMPV6_ERR_SIZE;
    ctx->current_length = ip_payload_size + ip_hdr_len; 
    PLATFORM_CNAT_SET_TX_VRF(ctx,uidb_index);
}

void icmp_error_generate_v2 (ipv4_header *ip, u8 icmp_type,
                          u8 icmp_code, u16 mtu, u32 src_ip)
{

    u16          ip_hdr_len, ip_payload_size;
    u32         *src_p, * dst_p;
    icmp_v4_t   *icmp;

    ip_hdr_len  = (ip->version_hdr_len_words & 0xf) << 2;   /* offset to ip payload */
    icmp        = (icmp_v4_t*) ( (u8*)ip + ip_hdr_len);
    ip_payload_size = sizeof(icmp_v4_t) + ip_hdr_len +
        ICMP_UNREACHABLE_IP_PAYLOAD_SIZE;

    src_p = (u32*)
            ((u8*)ip + ip_hdr_len + ICMP_UNREACHABLE_IP_PAYLOAD_SIZE - 4);
    dst_p = (u32*) ((u8*)src_p + sizeof(ipv4_header) +
                     sizeof(icmp_v4_t));

    while(src_p >= (u32*)ip)  *dst_p-- = *src_p--;

   /* Following ICMP op has to be after ip header being copied */
    icmp->type       = icmp_type;
    icmp->code       = icmp_code;
    icmp->identifier = 0;
    icmp->sequence   = 0;
    if(PREDICT_FALSE(mtu != 0)) {
        icmp->sequence   = spp_host_to_net_byte_order_16(mtu); 
    }


   /* build icmp header, keep original tos, identification values */
    ip->version_hdr_len_words = 0x45;
    ip->total_len_bytes       = sizeof(ipv4_header) + ip_payload_size;
    ip->total_len_bytes       = spp_host_to_net_byte_order_16(ip->total_len_bytes);
    ip->frag_flags_offset     = 0;
    ip->ttl                   = 64;
    ip->protocol              = ICMP_PROT;
    ip->checksum              = 0;
    ip->dest_addr             = ip->src_addr;
    ip->src_addr              = spp_host_to_net_byte_order_32(src_ip);

   /* calc checksum for ip and icmp */

    calc_ipv4_checksum(ip);
    calc_v4_icmp_checksum( (icmp_v4_t *) ((u8*) ip + sizeof(ipv4_header)),
                        ip_payload_size);
}

void icmp_error_generate (ipv4_header *ip, u8 icmp_type, 
                          u8 icmp_code, u16 uidb_index) {
 
    u16          ip_hdr_len, ip_payload_size;
    u32         *src_p, * dst_p;
    icmp_v4_t   *icmp;
    
    ip_hdr_len  = (ip->version_hdr_len_words & 0xf) << 2;   /* offset to ip payload */
    icmp        = (icmp_v4_t*) ( (u8*)ip + ip_hdr_len);
    ip_payload_size = sizeof(icmp_v4_t) + ip_hdr_len +
        ICMP_UNREACHABLE_IP_PAYLOAD_SIZE;

    src_p = (u32*)
            ((u8*)ip + ip_hdr_len + ICMP_UNREACHABLE_IP_PAYLOAD_SIZE - 4);
    dst_p = (u32*) ((u8*)src_p + sizeof(ipv4_header) +
                     sizeof(icmp_v4_t));

    while(src_p >= (u32*)ip)  *dst_p-- = *src_p--;

   /* Following ICMP op has to be after ip header being copied */
    icmp->type       = icmp_type;
    icmp->code       = icmp_code;
    icmp->identifier = 0;
    icmp->sequence   = 0;


   /* build icmp header, keep original tos, identification values */
    ip->version_hdr_len_words = 0x45;
    ip->total_len_bytes       = sizeof(ipv4_header) + ip_payload_size;
    ip->total_len_bytes       = spp_host_to_net_byte_order_16(ip->total_len_bytes);
    ip->frag_flags_offset     = 0;
    ip->ttl                   = 64;
    ip->protocol              = ICMP_PROT;
    ip->checksum              = 0;
    ip->dest_addr             = ip->src_addr;

    ip->src_addr              = spp_host_to_net_byte_order_32(svi_params_array[uidb_index].ipv4_addr);

   /* calc checksum for ip and icmp */

    calc_ipv4_checksum(ip);
    calc_v4_icmp_checksum( (icmp_v4_t *) ((u8*) ip + sizeof(ipv4_header)),
                        ip_payload_size);
#if 0 
    printf("version_hdr_len_words = 0x%x\n", ip->version_hdr_len_words);
    printf("total_len_bytes = 0x%x\n", ip->total_len_bytes);
    printf("Frag = 0x%x\n", ip->frag_flags_offset);
    printf("ttl = 0x%x\n", ip->ttl);
    printf("Protocol = 0x%x\n", ip->protocol);
    printf("checksum = 0x%x\n", ip->checksum);
    printf("Dest addr = 0x%x\n", ip->dest_addr);
    printf("Src addr  = 0x%x\n", ip->src_addr);
    printf("Icmp type = 0x%x\n", icmp->type);
    printf("Icmp code = 0x%x\n", icmp->code);
#endif

}

int icmpv4_generate_with_throttling_v2 (spp_ctx_t *ctx, ipv4_header *ipv4, 
                                     int icmp_type, int icmp_code, 
                                     u16 mtu, u32 src_ip)
{
    u16          ip_hdr_len;
    icmp_v4_t   *icmp;
    u16 rx_uidb_index = ctx->ru.rx.uidb_index;
    if (icmp_msg_gen_allowed()) { 
        free_all_but_first_chained_buffers(ctx);
        icmp_error_generate_v2(ipv4, icmp_type, icmp_code, mtu, src_ip);
        ctx->current_length = (u16)
            ((u8*)ctx->current_header - ctx->packet_data) +
            spp_net_to_host_byte_order_16(&ipv4->total_len_bytes);
        PLATFORM_CNAT_SET_TX_VRF(ctx,rx_uidb_index);
        return 1;
    } else {
        return 0;
    }
}

int icmpv4_generate_with_throttling (spp_ctx_t *ctx, ipv4_header *ipv4, 
                                     u16 rx_uidb_index)
{
    int icmp_type;
    int icmp_code;
    
    if (icmp_msg_gen_allowed()) {
        /* ICMP error would be small, so one buffer is enough. Clear the other */
        free_all_but_first_chained_buffers(ctx);

        icmp_type = ICMPV4_TIMEEXCEEDED;
        icmp_code = ICMPV4_TIMTTL;
        icmp_error_generate(ipv4, icmp_type, icmp_code, rx_uidb_index);
        ctx->current_length = (u16)
            ((u8*)ctx->current_header - ctx->packet_data) +
            spp_net_to_host_byte_order_16(&ipv4->total_len_bytes);
        PLATFORM_CNAT_SET_TX_VRF(ctx,rx_uidb_index);
        return 1;
    } else {
        return 0;
    }
}

int icmpv4_generate_with_throttling_v1 (spp_ctx_t *ctx, ipv4_header *ipv4, 
                                     u16 rx_uidb_index, u32 type, u32 code)
{
    if (icmp_msg_gen_allowed()) {
        /* ICMP error would be small, so one buffer is enough. Clear the other */
        free_all_but_first_chained_buffers(ctx);

        icmp_error_generate(ipv4, type, code, rx_uidb_index);
        ctx->current_length = (u16)
            ((u8*)ctx->current_header - ctx->packet_data) +
            spp_net_to_host_byte_order_16(&ipv4->total_len_bytes);
        PLATFORM_CNAT_SET_TX_VRF(ctx,rx_uidb_index);
        return 1;
    } else {
        return 0;
    }
}

    
int icmpv6_generate_with_throttling (spp_ctx_t *ctx, ipv6_header_t *ipv6,
                                     u16 rx_uidb_index)
{
    int icmp_type;
    int icmp_code;

    if (v6_icmp_msg_gen_allowed()) {
        icmp_type = ICMPV6_TIMEEXCEEDED;
        icmp_code = ICMPV6_TIMTTL;
        icmp_error_generate_v6(ctx, icmp_type, icmp_code, rx_uidb_index);
        return 1;
    } else {
        return 0;
    }
}

int icmpv6_generate_with_throttling_v1 (spp_ctx_t *ctx, ipv6_header_t *ipv6,
                                     u16 rx_uidb_index, u32 type, u32 code)
{

    if (v6_icmp_msg_gen_allowed()) {
        icmp_error_generate_v6(ctx, type, code, rx_uidb_index);
        return 1;
    } else {
        return 0;
    }
}
#endif 

void calculate_window_scale(tcp_hdr_type *tcp_header, u8 *scale) {
    
    u8 check_options = 0;

    *scale = 0;
    check_options = ((tcp_header->flags & TCP_FLAG_SYN) &&
                    (((tcp_header->hdr_len>>4) << 2) > sizeof(tcp_hdr_type)));
    
    if (PREDICT_FALSE(check_options)) {
         u8 *options_ptr = tcp_findoption(tcp_header, TCP_OPTION_WINDOW_SCALE);

	 /*
          * TCP option field: | kind 1B | len 1B | value 2B|
          *     where kind != [0, 1]
          */
	 if (PREDICT_TRUE(options_ptr && 
	                 (options_ptr[1] == TCP_OPTION_WINDOW_SCALE))) {
	     u8 *ptr  = (u8*)(options_ptr + 2);
	     *scale    = *ptr;

	     if(PREDICT_FALSE(*scale >= 14)) {
	         *scale = 14;
	     }

	     return;
	 }
    }	 
}	     

#if 0
ALWAYS_INLINE(
void cnat_log_nat44_tcp_seq_mismatch(
                   cnat_main_db_entry_t *db,
                   cnat_vrfmap_t *vrfmap))
{
     /* As of now, Netflow does not require this to be logged
      * So only syslog
      */
      if(PREDICT_TRUE(db->flags & CNAT_TAC_SEQ_MISMATCH)) {
              /* Already logged ..*/
          return;
      }
     /* else, set the flag and call the log API */

     db->flags = db->flags | CNAT_TAC_SEQ_MISMATCH;
				  
     cnat_syslog_nat44_tcp_seq_mismatch(db, vrfmap);
}
	 
				    
static int cnat_util_init (void *notused)
{
    /* run SPP_API_CNAT_PORTMAP_CREATE first*/
    spp_msg_api_set_handler(SPP_API_CNAT_PORT_ALLOCATE,
                            spp_api_cnat_port_allocate_t_handler);


    spp_msg_api_set_handler(SPP_API_CNAT_PORT_CLEAR,
                            spp_api_cnat_port_clear_t_handler);

    /* run vrfmap config first */
    spp_msg_api_set_handler(SPP_API_CNAT_PORT_CREATE,
                            spp_api_cnat_port_create_t_handler);

    spp_msg_api_set_handler(SPP_API_CNAT_PORT_DELETE,
                            spp_api_cnat_port_delete_t_handler);
    return 0;
}

void
print_ipv6_pkt (ipv6_header_t *ip)
{
    u32 i, total_len, l4_len=0;

    u8 *pkt = (u8 *) ip;

    total_len = spp_net_to_host_byte_order_16(&ip->payload_length);

    /* we rarely need to debug > 200 bytes of packet */
    if(total_len > 200) {
	total_len = 200;
    }

    printf("\n======== PRINTING PKT START======\n");
    printf("======== IPv6 PAYLOAD LEN %d ===========\n", total_len);
    for (i=0; i < 40; i++) {
       printf(" %02X ", *(pkt + i));
       if(i%16==15)
	   printf("\n");
    }
    
    if (ip->next_header == IPV6_PROTO_TCP) {
	printf("\n======== TCP HEADER =================\n");
	l4_len = 20;
    }
    else if (ip->next_header == IPV6_PROTO_UDP) {
	printf("\n======== UDP HEADER =================\n");
	l4_len = 8;
    }
    else if (ip->next_header == IPV6_PROTO_ICMPV6) {
	printf("\n======== ICMP HEADER =================\n");
	l4_len = 8;
    }

    for (i=40; i < (l4_len + 40); i++) {
       printf(" %02X ", *(pkt + i));
    }

    printf("\n======== LAYER4 PAYLOAD ===================\n");
    for (i=(l4_len + 40); i < total_len; i++) {
       printf(" %02X ", *(pkt + i));
       if(i%16==15)
	   printf("\n");
    }

    printf("\n======== PRINTING PKT END =======\n");
}



PLATFORM_SPP_INIT_FUNCTION(cnat_util_init);
#endif
