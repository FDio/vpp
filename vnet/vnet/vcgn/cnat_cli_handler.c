/* *------------------------------------------------------------------
 * cnat_cli_handler.c - CLI handler definitions
 *
 * Copyright (c) 2007-2015 Cisco and/or its affiliates.
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

#include "cnat_db.h"
#include "cnat_config.h"
#include "cnat_global.h"
#include "cnat_cli.h"
#include "cnat_logging.h"
#include "cnat_syslog.h"
#include "cnat_config_api.h"
#include "cnat_show_api.h"
#include "cnat_show_response.h"

#include <arpa/inet.h>

u32 show_debug_level = 0;

u32
cnat_get_vrfmap_nfv9_logging_index (u32 i_vrf_id)
{
    cnat_nfv9_logging_info_t *my_nfv9_logging_info = 0;
    u32 logging_index = EMPTY;

    /*
     * Start with global logging index if available
     */
    if (cnat_nfv9_global_info.cnat_nfv9_init_done) {
        logging_index = cnat_nfv9_global_info.cnat_nfv9_global_collector_index;

        pool_foreach (my_nfv9_logging_info, cnat_nfv9_logging_info_pool, ({
            if (my_nfv9_logging_info->i_vrf_id == i_vrf_id) {
                logging_index = my_nfv9_logging_info -
                                    cnat_nfv9_logging_info_pool;
                break;
            }
        }));
    }
    return (logging_index);
}

u32
cnat_get_vrfmap_syslog_logging_index (u32 i_vrf_id)
{
    cnat_syslog_logging_info_t *my_syslog_info = NULL;
    u32 logging_index = EMPTY;

    /*
     * Start with global logging index if available
     */
    if(PREDICT_TRUE(cnat_syslog_global_info.cnat_syslog_init_done)) {

        pool_foreach (my_syslog_info, cnat_syslog_logging_info_pool, ({
            if (my_syslog_info->i_vrf_id == i_vrf_id) {
            logging_index = my_syslog_info -
                                    cnat_syslog_logging_info_pool;
                break;
            }
        }));
    }
    return (logging_index);
}

void
cnat_set_vrf_params_with_default(cnat_vrfmap_t *my_vrfmap, u32 i_vrf, u32 i_vrf_id)
{

    my_vrfmap->status   = S_WAO;

    my_vrfmap->i_vrf    = i_vrf;
    my_vrfmap->i_vrf_id = i_vrf_id;

    my_vrfmap->o_vrf    = INVALID_UIDX;
    my_vrfmap->o_vrf_id = INVALID_VRFID;

#ifndef NO_BULK_LOGGING
    BULKSIZE_FROM_VRFMAP(my_vrfmap) = BULK_ALLOC_SIZE_NONE;
#endif /* #ifndef NO_BULK_LOGGING */
    my_vrfmap->tcp_mss  = V4_TCP_MSS_NOT_CONFIGURED_VALUE;
    my_vrfmap->frag_tout = CNAT_IPV4_FRAG_TIMEOUT_DEF;
    my_vrfmap->port_limit = V4_DEF_VRF_MAX_PORTS;
    my_vrfmap->nfv9_logging_index =
        cnat_get_vrfmap_nfv9_logging_index(i_vrf_id);
    my_vrfmap->syslog_logging_index =
        cnat_get_vrfmap_syslog_logging_index(i_vrf_id);

     /* Copy logging policy from nfv9 info. */
    if(my_vrfmap->nfv9_logging_index != EMPTY) {
        cnat_nfv9_logging_info_t *nfv9_logging_info =
            cnat_nfv9_logging_info_pool + my_vrfmap->nfv9_logging_index;
        my_vrfmap->nf_logging_policy = nfv9_logging_info->logging_policy;
    }
    if(my_vrfmap->syslog_logging_index != EMPTY) {
        cnat_syslog_logging_info_t *syslog_logging_info =
            cnat_syslog_logging_info_pool + my_vrfmap->syslog_logging_index;
        my_vrfmap->syslog_logging_policy = syslog_logging_info->logging_policy;
    }
    #if 0
    printf("Initializing params in cnat_set_vrf_params_with_default\n"
                                  "my_vrfmap->status = %u\n"
                                  "my_vrfmap->tcp_mss = %u\n"
                                  "my_vrfmap->i_vrf   = %u\n"
                                  "my_vrfmap->i_vrf_id = %u\n"
                                  "my_vrfmap->o_vrf    = %u\n"
                                  "my_vrfmap->o_vrf_id = %u\n"
                                  "my_vrfmap->bulk_size = %u\n"
                                  "my_vrfmap->nfv9_logging_index = %u\n"
                                  "my_vrfmap->syslog_logging_index = %u\n"
                                  "my_vrfmap->frag_tout = %u\n"
                                  "my_vrfmap->port_limit = %u\n"
                                  "my_vrfmap->nf_logging_policy = %u\n"
                                  "my_vrfmap->syslog_logging_policy = %u\n",
                                   my_vrfmap->status,
                                   my_vrfmap->tcp_mss,
                                   my_vrfmap->i_vrf,
                                   my_vrfmap->i_vrf_id,
                                   my_vrfmap->o_vrf,
                                   my_vrfmap->o_vrf_id,
                                   my_vrfmap->bulk_size,
                                   my_vrfmap->nfv9_logging_index,
                                   my_vrfmap->syslog_logging_index,
                                   my_vrfmap->frag_tout,
                                   my_vrfmap->port_limit,
                                   my_vrfmap->nf_logging_policy,
                                   my_vrfmap->syslog_logging_policy);
    #endif /* if 0 */
}

/* config command handlers */
void cnat_nat44_add_vrf_map_t_handler(spp_api_cnat_v4_add_vrf_map_t *mp,
                            vlib_main_t *vm)
{
    void cnat_table_entry_fill_map(u32 start_addr, u32 end_addr,
                                   cnat_portmap_v2_t **port_map_holder);
    u32 start_addr, end_addr;
    u32 pm_len __attribute__((unused));
    cnat_vrfmap_t       *my_vrfmap = 0;
    cnat_portmap_v2_t   *pm = 0;
    u16   i_vrf, o_vrf;
    u32   ivrf_id, ovrf_id; 
    u16   my_vrfmap_index;
    u8    i = 0;

    start_addr = mp->start_addr[0]; 
    end_addr   = mp->end_addr[0];
    i_vrf      = mp->i_vrf; 
    o_vrf      = mp->o_vrf;
    ovrf_id    = mp->o_vrf_id;
    ivrf_id    = mp->i_vrf_id;

#if DEBUG_NOT_COMMENTED
    vlib_cli_output(vm, "%s: saddr[0x%x], eaddr[0x%x], i_vrf[0x%x], o_vrf[0x%x], "
           "ovrf_id[0x%x], ivrf_id[0x%x]\n", __func__, start_addr, end_addr,
            i_vrf, o_vrf, ovrf_id, ivrf_id);
#endif
    if (start_addr > end_addr) {
    	vlib_cli_output(vm, "Add VRF Map failed start addr 0x%x > end addr 0x%x\n", 
						start_addr, end_addr);
	return;
    }
    if ((end_addr - start_addr) > CNAT_MAX_ADDR_POOL_SIZE) {
        vlib_cli_output(vm, "Add VRF Map failed start addr 0x%x - end addr "
			"0x%x range > 65536\n", start_addr, end_addr);
        return;
    }	
    my_vrfmap_index = vrf_map_array[i_vrf];

    if (my_vrfmap_index != VRF_MAP_ENTRY_EMPTY) {

        my_vrfmap = cnat_map_by_vrf + my_vrfmap_index;

        my_vrfmap->o_vrf = o_vrf;
        my_vrfmap->i_vrf_id = ivrf_id;
        my_vrfmap->o_vrf_id = ovrf_id;
    } else {
        /*
         * first time add 
         */
        pool_get(cnat_map_by_vrf, my_vrfmap);
        memset(my_vrfmap, 0, sizeof(*my_vrfmap));
        /* waiting for outside vrf */
        cnat_set_vrf_params_with_default(my_vrfmap, i_vrf, ivrf_id);
        my_vrfmap->i_vrf = i_vrf;
        my_vrfmap->o_vrf = o_vrf;
        my_vrfmap->i_vrf_id = ivrf_id;
        my_vrfmap->o_vrf_id = ovrf_id;
#ifndef NO_BULK_LOGGING
        BULKSIZE_FROM_VRFMAP(my_vrfmap) = BULK_ALLOC_SIZE_NONE;
#endif /* #ifndef NO_BULK_LOGGING */

        my_vrfmap->tcp_mss = V4_TCP_MSS_NOT_CONFIGURED_VALUE;
        my_vrfmap->status = S_WA;
        my_vrfmap->frag_tout = 0; /* currently setting it to 0 */
        my_vrfmap->port_limit = V4_DEF_VRF_MAX_PORTS;
        vrf_map_array[i_vrf] = (my_vrfmap - cnat_map_by_vrf);
    }
    pm = my_vrfmap->portmap_list;
    pm_len = vec_len(pm);
    for(i=0; i < 1 ; i++) {
        start_addr = mp->start_addr[i];
        end_addr   = mp->end_addr[i];
        if((start_addr == 0) || (end_addr == 0))
            break;
        
        cnat_table_entry_fill_map(start_addr, end_addr,
                           &(my_vrfmap->portmap_list));
    }
    my_vrfmap->status = S_RUN;
    vlib_cli_output(vm, "Address Pool Config Successful !!\n");
    return;
}

void cnat_nat44_set_protocol_timeout_value(u16 active, 
          u16 init, u8 *proto, u8 reset, vlib_main_t *vm)
{
    if (!strncmp((char *) proto, "tcp", 3)) {
        tcp_initial_setup_timeout = (reset) ? V4_DEF_TCP_IS_TO : init;
        tcp_active_timeout = (reset) ? V4_DEF_TCP_AS_TO : active;

    } else if (!strncmp((char *) proto, "udp", 3)) {
        udp_init_session_timeout = (reset) ? V4_DEF_UDP_IS_TO : init;
        udp_act_session_timeout = (reset) ? V4_DEF_UDP_AS_TO : active;

    } else if (!strncmp((char *) proto, "icmp", 4)) {
        icmp_session_timeout = (reset) ? V4_DEF_ICMP_S_TO : active;

    } else {
        vlib_cli_output(vm, "Error !! Unsupported protocol %s\n", proto);
    }
    return; 
}




/* Show command handlers */
void cnat_nat44_handle_show_stats(vlib_main_t *vm)
{
    pool_header_t     *h;
    u32               used, free;
    cnat_vrfmap_t     *my_vrfmap =0;
    cnat_portmap_v2_t *pm =0, *my_pm = 0;
    u32 i, pm_len;
    struct in_addr ip;
    void cnat_nfv9_show_collector 
        (vlib_main_t *vm, cnat_nfv9_logging_info_t *my_nfv9_logging_info);

    /* active translations */
    h = pool_header(cnat_main_db);
    free = vec_len(h->free_indices);
    used = vec_len(cnat_main_db) - free;

    vlib_cli_output(vm, "vCGN NAT44 Statistics :\n");
    vlib_cli_output(vm, "\tActive Translations : %u\n", 
            NAT44_COMMON_STATS.active_translations);
    vlib_cli_output(vm, "\tTotal free translation entries : %u\n", free);
    vlib_cli_output(vm, "\tTotal used translation entries : %u\n", used);
    vlib_cli_output(vm, "\ti2o drops due to port limit exceeded : %lu\n", 
            in2out_drops_port_limit_exceeded);
    vlib_cli_output(vm, "\ti2o drops due to system limit reached : %lu\n", 
            in2out_drops_system_limit_reached);
    vlib_cli_output(vm, "\ti2o drops due to resource depletion : %lu\n", 
            in2out_drops_resource_depletion);
    vlib_cli_output(vm, "\to2i drops due to no translations : %lu\n", 
            NAT44_COMMON_STATS.no_translation_entry_drops);

    vlib_cli_output(vm, "\tPool address usage:\n");
    vlib_cli_output(vm, "\t-------------------------------------------------\n");
    vlib_cli_output(vm, "\tExternal Address \tPorts Used\n");
    vlib_cli_output(vm, "\t-------------------------------------------------\n");

    used = 0;
    pool_foreach (my_vrfmap, cnat_map_by_vrf, ({
                pm = my_vrfmap->portmap_list;
                pm_len = vec_len(pm);
                for (i = 0; i < pm_len; i++) {
                my_pm = pm + i;
                if (my_pm->inuse) {
                used++;
                /* maximum of 200 addresses to be returned */
                if (used <= 200) {
                ip.s_addr = ntohl(my_pm->ipv4_address);    
                vlib_cli_output(vm, "\t%s   \t\t%u\n", inet_ntoa(ip), my_pm->inuse);
                }
                }
                }
                }));
    return;
}

void cnat_nat44_handle_show_config(vlib_main_t *vm)
{
    cnat_vrfmap_t * my_vrfmap;
    cnat_portmap_v2_t *pm = 0;
    cnat_portmap_v2_t *my_pm = 0;
    u32 pm_len;
    struct in_addr ip_addr;
    u8  status_str[20]; 
    cnat_nfv9_logging_info_t *my_nfv9_logging_info, 
        *global_nfv9_logging_info = 0;

    vnet_hw_interface_t * hw;
    dpdk_main_t * dm = &dpdk_main;

    void cnat_nfv9_show_collector 
        (vlib_main_t *vm, cnat_nfv9_logging_info_t *my_nfv9_logging_info);

    vlib_cli_output(vm, "vCGN NAT44 Config:\n");
    vlib_cli_output(vm, "\tPort Limit : %u\n", cnat_main_db_max_ports_per_user);
    vlib_cli_output(vm, "\ttotal address pool : %u\n", total_address_pool_allocated);
    vlib_cli_output(vm, "\tdynamic port start range : %u\n", cnat_static_port_range);

    pool_foreach(my_vrfmap, cnat_map_by_vrf, ({
                hw = vnet_get_hw_interface (dm->vnet_main, my_vrfmap->i_vrf);
                vlib_cli_output(vm, "\tInside Interface  : %s\n", hw->name);
                hw = vnet_get_hw_interface (dm->vnet_main, my_vrfmap->o_vrf);
                vlib_cli_output(vm, "\tOutside Interface : %s\n", hw->name);

                memset(status_str, 0x00, sizeof(status_str));
                switch(my_vrfmap->status) {
                case S_WAO: memcpy(status_str, "S_WAO", 5); break;
                case S_WA:  memcpy(status_str, "S_WA",  4); break;
                case S_WO:  memcpy(status_str, "S_WO",  4); break;
                case S_RUN: memcpy(status_str, "ONLINE", 6); break;
                case S_DEL: memcpy(status_str, "S_DEL", 5); break;
                default: memcpy(status_str, "Invalid state", 13); 

                } 
                vlib_cli_output(vm, 
                              "\tAddress pool map table status : %s\n", status_str);

                pm = my_vrfmap->portmap_list;
                pm_len = vec_len(pm);
                my_pm = pm;
                ip_addr.s_addr = clib_net_to_host_u32(my_pm->ipv4_address);
                vlib_cli_output(vm, 
                             "\tStart Address : %s\n", inet_ntoa(ip_addr));
                my_pm = pm + (pm_len - 1);
                ip_addr.s_addr = clib_net_to_host_u32(my_pm->ipv4_address);
                vlib_cli_output(vm, 
                               "\tEnd Address : %s\n", inet_ntoa(ip_addr));

    }));
    vlib_cli_output(vm, 
            "\ttcp init timeout    : %u sec\n", tcp_initial_setup_timeout);
    vlib_cli_output(vm, 
            "\ttcp active timeout  : %u sec\n", tcp_active_timeout);
    vlib_cli_output(vm, 
            "\tudp init timeout    : %u sec\n", udp_init_session_timeout);
    vlib_cli_output(vm, 
            "\tudp active timeout  : %u sec\n", udp_act_session_timeout);
    vlib_cli_output(vm, 
            "\ticmp session timeout: %u sec\n", icmp_session_timeout);

#if 0
    if (cnat_nfv9_global_info.cnat_nfv9_global_collector_index != EMPTY) {
        vlib_cli_output(vm,"\nGloabal NFV9 Collector :");
        global_nfv9_logging_info = cnat_nfv9_logging_info_pool +
            cnat_nfv9_global_info.cnat_nfv9_global_collector_index;
        cnat_nfv9_show_collector(vm, global_nfv9_logging_info);
    }
#endif

    vlib_cli_output(vm, "\nNFV9 Collector :");
    if (cnat_nfv9_logging_info_pool !=NULL) { 
        pool_foreach (my_nfv9_logging_info, cnat_nfv9_logging_info_pool, ({
            if (my_nfv9_logging_info != global_nfv9_logging_info) {
                cnat_nfv9_show_collector(vm, my_nfv9_logging_info);
                vlib_cli_output(vm, "\n");
            }
        }));
    } else {
        vlib_cli_output(vm, "\n");
    }

    return;
}

/*
 * Check if the request flag matches the entry flags and
 * if so return "1"
 *
 * entry_flag_ptr is an output parameter - it returns the flags
 * corresponding to the translation entry
 */
static u8 cnat_v4_show_verify_display_entry (
                                        u16                  request_flag,
					cnat_main_db_entry_t *db,
					u16                  *entry_flag_ptr)
{
    u8  display_entry = 0;

    /*
     * This should never happen
     */
    if (!entry_flag_ptr) {
        return (display_entry);
    }

    *entry_flag_ptr = 0;

    if ((db->flags & CNAT_DB_FLAG_STATIC_PORT)
        &&(db->flags & CNAT_DB_FLAG_ALG_ENTRY)) {
        *entry_flag_ptr |= CNAT_TRANSLATION_ENTRY_STATIC;
        *entry_flag_ptr |= CNAT_TRANSLATION_ENTRY_ALG;
    } else if (db->flags & CNAT_DB_FLAG_STATIC_PORT) {
	*entry_flag_ptr |= CNAT_TRANSLATION_ENTRY_STATIC;
    } else if ((db->flags & CNAT_DB_FLAG_ALG_ENTRY) || 
        (db->flags & CNAT_DB_FLAG_PPTP_GRE_ENTRY)) {
	*entry_flag_ptr |= CNAT_TRANSLATION_ENTRY_ALG;
    } else if (db->flags & CNAT_DB_FLAG_PCPI) {
        *entry_flag_ptr |= CNAT_TRANSLATION_ENTRY_PCPI_DYNAMIC;
    } else if (db->flags & CNAT_DB_FLAG_PCPE) {
        *entry_flag_ptr |= CNAT_TRANSLATION_ENTRY_PCPE_DYNAMIC; 
    } else {
        *entry_flag_ptr |= CNAT_TRANSLATION_ENTRY_DYNAMIC;
    } 
   
    if (request_flag == CNAT_TRANSLATION_ENTRY_ALL) {
	display_entry = 1;
    } else {
	/*
	 * Check if the request_flag is STATIC or ALG
	 * and the entry is STATIC or ALG as well
	 */
	if ((request_flag & CNAT_TRANSLATION_ENTRY_STATIC) &&
	    (*entry_flag_ptr & CNAT_TRANSLATION_ENTRY_STATIC)) {
	    display_entry = 1;
	}

	if ((request_flag & CNAT_TRANSLATION_ENTRY_ALG) &&
	    (*entry_flag_ptr & CNAT_TRANSLATION_ENTRY_ALG)) {
	    display_entry = 1;
	}

        if ((request_flag & CNAT_TRANSLATION_ENTRY_PCPI_DYNAMIC) &&
            (*entry_flag_ptr & CNAT_TRANSLATION_ENTRY_PCPI_DYNAMIC)) {
            display_entry = 1;
        }

        if ((request_flag & CNAT_TRANSLATION_ENTRY_PCPE_DYNAMIC) &&
            (*entry_flag_ptr & CNAT_TRANSLATION_ENTRY_PCPE_DYNAMIC)) {
            display_entry = 1;
        }

	/*
	 * For dynamic entry case, check if flags field is 0
	 */
	if ((request_flag & CNAT_TRANSLATION_ENTRY_DYNAMIC) && 
	    (*entry_flag_ptr & CNAT_TRANSLATION_ENTRY_DYNAMIC)) {
	    display_entry = 1;
	}
    }

    if (PREDICT_FALSE(show_debug_level > 2)) {
	PLATFORM_DEBUG_PRINT("Entry (0x%x, %d) -> (0x%x, %d) request_flag 0x%x, entry_flag 0x%x, display_entry %d\n", db->in2out_key.k.ipv4, db->in2out_key.k.port, db->out2in_key.k.ipv4, db->out2in_key.k.port, request_flag, *entry_flag_ptr, display_entry);
    }

    return (display_entry);
}
void cnat_v4_show_inside_entry_req_t_handler
(spp_api_cnat_v4_show_inside_entry_req_t *mp, vlib_main_t * vm)
{
    cnat_user_db_entry_t *udb = NULL;
    cnat_main_db_entry_t *db = NULL;
    cnat_db_key_bucket_t u_ki, ki;
    u64 a, b, c;
    u32 index;
    u16 start_port, end_port, port;
    u16 request_flag = 0;
    u16 entry_flag   = 0;
    u8  num_entries = 0;
    u8 proto, all;
    u8 done = 0;
    cnat_v4_show_translation_entry *entry_list; 
    cnat_v4_show_translation_entry entry[PLATFORM_MAX_TRANSLATION_ENTRIES];
    u8 display_entry;
    u8 flag_str[11];
    vnet_hw_interface_t * hw;
    dpdk_main_t * dm = &dpdk_main;

    ki.k.k.ipv4 = mp->ipv4_addr;
    ki.k.k.vrf = mp->vrf_id;
    start_port = mp->start_port;
    end_port = mp->end_port;
#if DEBUG
    vlib_cli_output(vm, "## proto %d, inside-addr 0x%x, start_port %u, "
                "end_port %u, vrf 0x%x, flag 0x%x\n",
                mp->protocol, 
                mp->ipv4_addr,
                mp->start_port,
                mp->end_port,
                mp->vrf_id,
                mp->flags);
#endif

    proto = mp->protocol;
    ki.k.k.vrf |= ((u16)proto << CNAT_PRO_SHIFT);

    all = mp->all_entries;  /* for no port range case */
    request_flag = mp->flags; /* for all, alg, static entries case */
    entry_list = entry; 

    /* 
     * check if the address is belonging to this core
     */
        

    /*
     * first we check if the user exists in the udb, if he is not then
     * it does not make sense to check the main db for translations
     */
    u_ki.k.k.vrf = ki.k.k.vrf & CNAT_VRF_MASK;
    u_ki.k.k.ipv4 = ki.k.k.ipv4;
    u_ki.k.k.port = 0;

    if (PREDICT_FALSE(show_debug_level > 0)) {
        vlib_cli_output(vm, "\nI_TRANS_CORE %d: IPv4 0x%x, VRF 0x%x, "
                "start_port %d, end_port %d", 
                my_instance_number, ki.k.k.ipv4, 
                ki.k.k.vrf, start_port, end_port);
    }

    udb = cnat_user_db_lookup_entry(&u_ki);
    if (!udb) {
        if (PREDICT_FALSE(show_debug_level > 0)) {
            vlib_cli_output(vm, "\nReturning %d entries", 
                    num_entries); 
        }
        return;
    }

    if (all) {
    #if 0
	if (PREDICT_FALSE(show_debug_level > 0)) {
	    PLATFORM_DEBUG_PRINT("\nI_TRANS: Printing ALL\n");
	}

        /* 
         * get the head of list of translation entries for that user 
         * from the user db 
         */
        head = udb->translation_list_head_index;
        db = cnat_main_db + head;

        while (num_entries < PLATFORM_MAX_TRANSLATION_ENTRIES) {

            if (((db->in2out_key.k.vrf & CNAT_PRO_MASK) >> CNAT_PRO_SHIFT)
                                                            != proto) {
                goto next_entry;
            }

            display_entry = 
	        spp_api_cnat_v4_show_verify_display_entry(request_flag, db,
		                                          &entry_flag);

            if (display_entry) {
                entry_list->ipv4_addr = 
                    spp_host_to_net_byte_order_32(db->out2in_key.k.ipv4);
                entry_list->cnat_port = 
                    spp_host_to_net_byte_order_16(db->out2in_key.k.port);
                entry_list->src_port = 
                    spp_host_to_net_byte_order_16(db->in2out_key.k.port);   

                entry_list->protocol = proto;

                /* incase of gre - in2out is not accounted */
                if(proto != CNAT_PPTP) {
                    
                    entry_list->in2out_packets =
                       spp_host_to_net_byte_order_32(db->in2out_pkts);
                } else {
                    entry_list->in2out_packets = 0;
                }
                entry_list->out2in_packets =
                    spp_host_to_net_byte_order_32(db->out2in_pkts);

                entry_list->flags = 
                    spp_host_to_net_byte_order_16(entry_flag);

                num_entries++;
                entry_list = entry_list + 1;
            }
next_entry: 
            db = cnat_main_db + db->user_ports.next;
            /*
             * its a circular list, so if we have reached the head again
             * all the entries for that user have been read
             */
            if (db == (cnat_main_db + head)) { 
                break;
            }
        }
        resp->num_entries = num_entries;
    #endif /* if 0 */
    } else {
        if (PREDICT_FALSE(show_debug_level > 0)) {
            vlib_cli_output(vm, "\nI_TRANS: Printing range %d .. %d\n",
                    start_port, end_port);
        }
        /*
         * port range is specified so for each port calculate the hash and
         * check if the entry is present in main db
         */
        port = start_port;
        done = 0;
        while ((!done) && (num_entries < PLATFORM_MAX_TRANSLATION_ENTRIES)) {

            ki.k.k.port = port;
            if (port >= end_port) {
                done = 1;
            } else {
                port++;
            }
            CNAT_V4_GET_HASH(ki.k.key64,
                    ki.bucket,
                    CNAT_MAIN_HASH_MASK);
            index = cnat_in2out_hash[ki.bucket].next;
            if (PREDICT_TRUE(index == EMPTY)) {
                continue;
            }

            do {
                db = cnat_main_db + index;
                if (db->in2out_key.key64 == ki.k.key64) {
                    break;
                }
                index = db->in2out_hash.next;
            } while (index != EMPTY);

            if (index == EMPTY) {
                continue;
            } else {

                display_entry = 
                    cnat_v4_show_verify_display_entry(request_flag, db,
                            &entry_flag);
                if (display_entry) {

                    entry_list->ipv4_addr =
                        clib_host_to_net_u32(db->out2in_key.k.ipv4);
                    entry_list->cnat_port =
                        clib_host_to_net_u16(db->out2in_key.k.port);
                    entry_list->src_port =
                        clib_host_to_net_u16(db->in2out_key.k.port);

                    entry_list->protocol = proto;
                    entry_list->nsessions = db->nsessions; 
		    entry_list->flags = ((db->flags & CNAT_DB_FLAG_TCP_ACTIVE) ||
				     	 (db->flags & CNAT_DB_FLAG_UDP_ACTIVE)) ? 1:0;
                    /* incase of gre - in2out is not accounted */
                    if(proto != CNAT_PPTP) {
                        entry_list->in2out_packets =
                            clib_host_to_net_u32(db->in2out_pkts);
                    } else {
                        entry_list->in2out_packets = 0;
                    }

                    entry_list->out2in_packets =
                        clib_host_to_net_u32(db->out2in_pkts);
               
                    if (PREDICT_FALSE(show_debug_level > 3)) {
                        vlib_cli_output(vm, "\n1. Entry: Addr 0x%x, port %d, num_entries %d",
                                clib_net_to_host_u32(entry_list->ipv4_addr), 
                                clib_net_to_host_u16(entry_list->cnat_port), 
                                num_entries);
                    } 

                    entry_list = entry_list + 1;
                    num_entries++;
                } 
            } /* if (index == EMPTY) */
        } /* while() */
    }

    if (PREDICT_FALSE(show_debug_level > 0)) {
        if (num_entries) {
            vlib_cli_output(vm, "\nReturning %d entries\n", 
                    num_entries); 
        }
    }

    entry_list = entry;
    u8 i = 0;
    struct in_addr ip;
    u8 proto_str[10];
    u8 transl_str[10];
    memset(proto_str, 0x00, 10);
    memset(transl_str, 0x00, 10);

    if      (proto == 1) strncpy((char *)proto_str, "udp", 3);
    else if (proto == 2) strncpy((char *)proto_str, "tcp", 3);
    else if (proto == 3) strncpy((char *)proto_str, "icmp", 4);
    else                 strncpy((char *)proto_str, "unknown", 7);

    if (request_flag == 0x04) strncpy((char *)transl_str, "Dynamic", 7);
    else strncpy((char *)transl_str, "Unknown", 7); /* currently we are not supporting static/alg entries */

    ip.s_addr = clib_net_to_host_u32(u_ki.k.k.ipv4);
    hw = vnet_get_hw_interface (dm->vnet_main, u_ki.k.k.vrf);

    vlib_cli_output (vm, "Inside-translation details\n");
    vlib_cli_output (vm, "--------------------------\n");

    vlib_cli_output (vm, "Inside interface       : %s\n", hw->name);
    vlib_cli_output (vm, "Inside address         : %s\n", inet_ntoa(ip));
    vlib_cli_output (vm, "Start port             : %u\n", start_port);
    vlib_cli_output (vm, "End port               : %u\n", end_port);

    vlib_cli_output (vm, "--------------------------------------------------------------------------------------"
            "-----------------------\n");
    vlib_cli_output (vm, "Outside          Protocol  Inside      Outside    Translation"
            "      I2O       O2I       	   Flag      Num\n");
    vlib_cli_output (vm, "Address                    Src Port    Src Port   Type       "
            "      Pkts      Pkts                    Sessions\n");
    vlib_cli_output (vm, "--------------------------------------------------------------------------------------"
            "-----------------------\n");

    while ((num_entries) && (entry_list) && (i < 50)) {

        ip.s_addr = entry_list->ipv4_addr;
	memset(flag_str,0x00,11);
        if((proto == 1) || (proto == 2)) {
          if(entry_list->flags == 1) {
            strncpy((char *)flag_str,"Active",6);
          }
          else {
            strncpy((char *) flag_str,"Non Active",10);
          }
        } else {
	    strncpy((char *) flag_str, "NA", 2);
	} 
        vlib_cli_output(vm, "%s %10s %11u %12u %13s %10u %10u %14s %6u\n",
                inet_ntoa(ip), proto_str,
                clib_net_to_host_u16(entry_list->src_port),
                clib_net_to_host_u16(entry_list->cnat_port),
                transl_str, 
                clib_net_to_host_u32(entry_list->in2out_packets), 
                clib_net_to_host_u32(entry_list->out2in_packets),
                flag_str, 
                entry_list->nsessions);
        entry_list++;
        num_entries--; i++;
    }

    return; 
}

void cnat_v4_show_outside_entry_req_t_handler
(spp_api_cnat_v4_show_outside_entry_req_t *mp, vlib_main_t *vm)
{
    cnat_main_db_entry_t *db = NULL;
    cnat_db_key_bucket_t ko;
    u64 a, b, c;
    u32 index;
    u16 start_port, end_port, port;
    u16 request_flag = 0;
    u16 entry_flag   = 0;
    u8  num_entries = 0;
    u8 proto;
    cnat_v4_show_translation_entry *entry_list;
    cnat_v4_show_translation_entry entry[PLATFORM_MAX_TRANSLATION_ENTRIES];
    u8 done = 0;
    u8 display_entry;
    u8 flag_str[11];
    vnet_hw_interface_t * hw;
    dpdk_main_t * dm = &dpdk_main;

    ko.k.k.ipv4 = mp->ipv4_addr;
    ko.k.k.vrf = mp->vrf_id;
    start_port = mp->start_port;
    end_port = mp->end_port;

    proto = mp->protocol;
    request_flag = mp->flags;

    ko.k.k.vrf |= ((u16)proto << CNAT_PRO_SHIFT);

    entry_list = entry;

    if (PREDICT_FALSE(show_debug_level > 0)) {
        vlib_cli_output(vm, "\nO_TRANS_CORE %d: IPv4 0x%x, VRF 0x%x, "
                        "start_port %d, end_port %d", my_instance_number, 
                        ko.k.k.ipv4, ko.k.k.vrf, start_port, end_port);
    }

    /*
     * for each ip and port combination we need to scan the main db 
     * and check if the entry is present in main db
     */
    port = start_port;
    done = 0;
    while ((!done) && (num_entries < PLATFORM_MAX_TRANSLATION_ENTRIES)) {
        ko.k.k.port = port;

	/*
	 * If we have reached the end_port, we are DONE
	 */
	if (port >= end_port) {
	    done = 1;
	} else {
	    port++;
	}

        CNAT_V4_GET_HASH(ko.k.key64,
                ko.bucket,
                CNAT_MAIN_HASH_MASK);

        index = cnat_out2in_hash[ko.bucket].next;
        if (PREDICT_TRUE(index == EMPTY)) {
            continue;
        }

        do {
            db = cnat_main_db + index;
            if (db->out2in_key.key64 == ko.k.key64) {
                break;
            }
            index = db->out2in_hash.next;
        } while (index != EMPTY);

        if (index == EMPTY) {
            continue;
        } else {
            display_entry = 
	        cnat_v4_show_verify_display_entry(request_flag, db,
		                                          &entry_flag);

            if (display_entry) {
                entry_list->ipv4_addr =
                    clib_host_to_net_u32(db->in2out_key.k.ipv4);
                entry_list->cnat_port =
                    clib_host_to_net_u16(db->out2in_key.k.port);
                entry_list->src_port =
                    clib_host_to_net_u16(db->in2out_key.k.port);
                entry_list->protocol = proto;
                entry_list->nsessions = db->nsessions;
                entry_list->flags = ((db->flags & CNAT_DB_FLAG_TCP_ACTIVE) || 
				     (db->flags & CNAT_DB_FLAG_UDP_ACTIVE)) ? 1:0;
                /* incase of gre - in2out is not accounted */
                if(proto != CNAT_PPTP) {
                   entry_list->in2out_packets =
                    clib_host_to_net_u32(db->in2out_pkts);
                } else {
                   entry_list->in2out_packets = 0 ;
                }
                entry_list->out2in_packets =
                    clib_host_to_net_u32(db->out2in_pkts);
                #if 0
                entry_list->flags =
                    clib_host_to_net_u16(entry_flag); 
                #endif
                entry_list = entry_list + 1;
                num_entries++;
            }
        }
    }
    
    if (num_entries == 0) {
        /* No point proceeding further */
        return;
    }

    if (PREDICT_FALSE(show_debug_level > 0)) {
        if (num_entries) {
            vlib_cli_output(vm, "\nO_TRANS: Core %d returning %d entries", 
                    num_entries); 
        }
    }

	entry_list = entry;
	u8 i = 0;
    struct in_addr ip;
    u8 proto_str[10];
    u8 transl_str[10];
    memset(proto_str, 0x00, 10);
    memset(transl_str, 0x00, 10);

    if      (proto == 1) strncpy((char *) proto_str, "udp", 3);
    else if (proto == 2) strncpy((char *) proto_str, "tcp", 3);
    else if (proto == 3) strncpy((char *) proto_str, "icmp", 4);
    else                 strncpy((char *) proto_str, "unknown", 7);

    if (request_flag == 0x04) strncpy((char *) transl_str, "Dynamic", 7);
    else strncpy((char *)transl_str, "Unknown", 7); /* currently we are not supporting static/alg entries */

    ip.s_addr = clib_net_to_host_u32(ko.k.k.ipv4);
    hw = vnet_get_hw_interface (dm->vnet_main, (ko.k.k.vrf & CNAT_VRF_MASK));

    vlib_cli_output (vm, "Outside-translation details\n");
    vlib_cli_output (vm, "--------------------------\n");

    vlib_cli_output (vm, "Outside interface       : %s\n", hw->name);
    vlib_cli_output (vm, "Outside address         : %s\n", inet_ntoa(ip));
    vlib_cli_output (vm, "Start port              : %u\n", start_port);
    vlib_cli_output (vm, "End port                : %u\n", end_port);

    vlib_cli_output (vm, "--------------------------------------------------------------------------------------"
            "-----------------------\n");
    vlib_cli_output (vm, "Inside           Protocol  Outside     Inside     Translation"
            "      I2O       O2I       Flag          Num\n");
    vlib_cli_output (vm, "Address                    Dst Port    Dst Port   Type       "
            "      Pkts      Pkts                    Sessions\n");
    vlib_cli_output (vm, "--------------------------------------------------------------------------------------"
            "-----------------------\n");

	while ((num_entries) && (entry_list) && (i < 50)) {
        ip.s_addr = entry_list->ipv4_addr;
	memset(flag_str,0x00,11);
        if((proto == 1) || (proto == 2)) {
          if(entry_list->flags == 1) {
            strncpy((char *) flag_str,"Active",6);
          }
          else {
            strncpy((char *) flag_str,"Non Active",10);
          }
        } else {
	    strncpy((char *) flag_str, "NA", 2);
	} 
        vlib_cli_output(vm, "%s %10s %11u %12u %13s %10u %10u %14s %6u\n",
                inet_ntoa(ip), proto_str,
                clib_net_to_host_u16(entry_list->cnat_port),
                clib_net_to_host_u16(entry_list->src_port),
                transl_str, 
                clib_net_to_host_u32(entry_list->in2out_packets), 
                clib_net_to_host_u32(entry_list->out2in_packets),
                flag_str,
                entry_list->nsessions);
        entry_list++;
        num_entries--; i++;

	}
    return;
}
