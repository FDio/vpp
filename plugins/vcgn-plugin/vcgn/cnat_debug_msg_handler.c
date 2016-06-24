/* 
 *------------------------------------------------------------------
 * cnat_debug_msg_handler.c - debug command
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

#include <vlib/vlib.h>
#include <vnet/vnet.h>

#include "cnat_cli.h"

u32 global_debug_flag = CNAT_DEBUG_NONE;
u16 debug_i_vrf = CNAT_DEBUG_NONE;
u32 debug_i_flag = CNAT_DEBUG_NONE;
u32 debug_i_addr_start = CNAT_DEBUG_NONE;
u32 debug_i_addr_end = CNAT_DEBUG_NONE;

u16 debug_o_vrf = CNAT_DEBUG_NONE;
u32 debug_o_flag = CNAT_DEBUG_NONE;
u32 debug_o_addr_start = CNAT_DEBUG_NONE;
u32 debug_o_addr_end = CNAT_DEBUG_NONE;

u32 udp_inside_checksum_disable    = 0;
u32 udp_outside_checksum_disable   = 0;
u32 udp_inside_packet_dump_enable  = 0;
u32 udp_outside_packet_dump_enable = 0;

u32 tcp_logging_enable_flag        = 0;

u32 icmp_debug_flag                = 0;
u32 frag_debug_flag                = 0;

u32 nfv9_logging_debug_flag        = 0;
u32 syslog_debug_flag              = 0; 

u32 summary_stats_debug_flag       = 0;

/*
 * By defaut we set the config debug level to 1
 */
u32 config_debug_level             = 1;

#ifdef TOBE_PORTED
extern void show_bulk_port_stats();
extern void clear_bulk_port_stats();
extern void show_bulk_port_allocation(u16 in_vrfid, u32 inside_ip);
extern void set_bulk_size_to_all_vrfs(int bulk_size);

u32 *cnat_debug_addr_list;

extern int global_pd_dbg_lvl;
extern int global_pi_dbg_lvl;
extern int global_l2_dbg_lvl;
extern u32  cnat_pptp_debug_flag;
extern u32  cnat_pcp_debug_flag;

void spp_api_cnat_get_cgn_db_summary
(spp_api_cnat_generic_command_request_t *);

void spp_api_cnat_v4_debug_dummy_t_handler
(spp_api_cnat_v4_debug_dummy_t *mp) 
{
    u32 arr[] = { DEBUG_DUMMY };
    spp_printf(CNAT_DUMMY_HANDLER_HIT, 1, arr);
    if(global_pd_dbg_lvl) {
        PLATFORM_DEBUG_PRINT("\n invalid debug command received: message id is 0\n");
    }
    mp->rc = CNAT_ERR_INVALID_MSG_ID;

}

void spp_api_cnat_v4_debug_dummy_max_t_handler
(spp_api_cnat_v4_debug_dummy_max_t *mp)
{
    u32 arr[] = { DEBUG_DUMMY_MAX };
    spp_printf(CNAT_DUMMY_HANDLER_HIT, 1, arr);
    if(global_pd_dbg_lvl) {
        PLATFORM_DEBUG_PRINT("\n invalid debug command received: message id is out of range\n");
    }
    mp->rc = CNAT_ERR_INVALID_MSG_ID;

}


void spp_api_cnat_v4_debug_global_t_handler
(spp_api_cnat_v4_debug_global_t *mp) 
{
    if ((mp->debug_flag == CNAT_DEBUG_GLOBAL_ERR) ||
        (mp->debug_flag == CNAT_DEBUG_GLOBAL_ALL) ||
        (mp->debug_flag == CNAT_DEBUG_NONE)) { 
        mp->rc = CNAT_SUCCESS;
        global_debug_flag = mp->debug_flag;
        return;
    }

    mp->rc = CNAT_ERR_PARSER;
    if(global_pd_dbg_lvl) {
        PLATFORM_DEBUG_PRINT("invalid global debug flag %x\n",
            mp->debug_flag);
    }
    return;
}

void spp_node_print_cnat_counters()
{
    if (cnat_global_counters.nfv9_downstream_constipation_count) {
        PLATFORM_DEBUG_PRINT("\nNF downstream constipation count: %llu\n",
                cnat_global_counters.nfv9_downstream_constipation_count);
    }

    if (xlat_global_counters.v4_to_v6_frag_invalid_uidb_drop_count  ||
        xlat_global_counters.v6_to_v4_frag_invalid_uidb_drop_count  ||
        xlat_global_counters.v4_to_v6_icmp_invalid_uidb_drop_count  ||
        xlat_global_counters.v6_to_v4_icmp_invalid_uidb_drop_count  ||
        xlat_global_counters.v4_to_v6_tcp_invalid_uidb_drop_count   ||
        xlat_global_counters.v6_to_v4_tcp_invalid_uidb_drop_count   ||
        xlat_global_counters.v4_to_v6_udp_invalid_uidb_drop_count   ||
        xlat_global_counters.v6_to_v4_udp_invalid_uidb_drop_count   ||
        xlat_global_counters.v4_to_v6_udp_crc_zero_invalid_uidb_drop_count) {

        PLATFORM_DEBUG_PRINT("\nMy_instance %d: v4_to_v6 frag invalid uidb drop count %lld",
               my_instance_number,
               xlat_global_counters.v4_to_v6_frag_invalid_uidb_drop_count);

        PLATFORM_DEBUG_PRINT("\nMy_instance %d: v6_to_v4 frag invalid uidb drop count %lld",
               my_instance_number,
               xlat_global_counters.v6_to_v4_frag_invalid_uidb_drop_count);

        PLATFORM_DEBUG_PRINT("\nMy_instance %d: v4_to_v6 icmp invalid uidb drop count %lld",
               my_instance_number,
               xlat_global_counters.v4_to_v6_icmp_invalid_uidb_drop_count);

        PLATFORM_DEBUG_PRINT("\nMy_instance %d: v6_to_v4 icmp invalid uidb drop count %lld",
               my_instance_number,
               xlat_global_counters.v6_to_v4_icmp_invalid_uidb_drop_count);

        PLATFORM_DEBUG_PRINT("\nMy_instance %d: v4_to_v6 tcp invalid uidb drop count %lld",
               my_instance_number,
               xlat_global_counters.v4_to_v6_tcp_invalid_uidb_drop_count);

        PLATFORM_DEBUG_PRINT("\nMy_instance %d: v6_to_v4 tcp invalid uidb drop count %lld",
               my_instance_number,
               xlat_global_counters.v6_to_v4_tcp_invalid_uidb_drop_count);

        PLATFORM_DEBUG_PRINT("\nMy_instance %d: v4_to_v6 udp invalid uidb drop count %lld",
               my_instance_number,
               xlat_global_counters.v4_to_v6_udp_invalid_uidb_drop_count);

        PLATFORM_DEBUG_PRINT("\nMy_instance %d: v6_to_v4 udp invalid uidb drop count %lld",
               my_instance_number,
               xlat_global_counters.v6_to_v4_udp_invalid_uidb_drop_count);

        PLATFORM_DEBUG_PRINT("\nMy_instance %d: v4_to_v6 udp crc0 invld uidb drop count %lld",
          my_instance_number,
          xlat_global_counters.v4_to_v6_udp_crc_zero_invalid_uidb_drop_count);

        PLATFORM_DEBUG_PRINT("\n");
    }
    

}

void spp_log_p2mp_req(spp_api_cnat_p2mp_debug_request_t *mp)
{
    u8 i = 0;
    u32 num_rec = spp_net_to_host_byte_order_32(&mp->param[i++]);
    u32 err_c_num_args;

    while (num_rec--) {
        u8 j = 0;
        u16 err_c;
        u16 num_args;
        u32 argv[32];

        err_c_num_args = spp_net_to_host_byte_order_32(&mp->param[i++]);
        err_c = (err_c_num_args >> 16) & 0xFFFF;
        num_args = err_c_num_args & 0xFFFF;

        num_args = (num_args <= 32) ? num_args : 32;
        while (j < num_args) {
                argv[j++] = spp_net_to_host_byte_order_32(&mp->param[i++]);
        }

        i += ((num_args - 32) > 0) ? (num_args - 32) : 0;
        spp_printf(err_c, num_args, argv);
    }
}

void  nat64_debug_addr_pool_add_del()
{
  cnat_portmap_v2_t *my_pm = NULL;
  cnat_portmap_v2_t *pm = NULL;
  u32 len, i, pm_len;

    PLATFORM_DEBUG_PRINT("\n sizeof port_map =%d\n", sizeof( cnat_portmap_v2_t));
  len = 10;
  PLATFORM_DEBUG_PRINT("\n adding 10 entries in vector 1-10\n ");
  vec_add2(pm, my_pm, len);
  pm = my_pm;

   PLATFORM_DEBUG_PRINT(" pm =%p  , my_pm = %p\n", pm, my_pm); 
  for(i=0;i<len;i++){
    my_pm->ipv4_address = i+1;
    my_pm++;
  }
   PLATFORM_DEBUG_PRINT(" pm =%p  , my_pm = %p\n", pm, my_pm); 
   
  pm_len = vec_len(pm);
  PLATFORM_DEBUG_PRINT("\n printing vector contents : vec_len = %d \n", pm_len);
  my_pm = pm;
  for(i=0;i<pm_len ; i++)
  {
    PLATFORM_DEBUG_PRINT(" %d ,",my_pm->ipv4_address);
    my_pm++;
  }
   PLATFORM_DEBUG_PRINT(" pm =%p  , my_pm = %p\n", pm, my_pm); 

  PLATFORM_DEBUG_PRINT("\n adding 5 entries in vector 11-15\n ");
  len = 5;
  vec_add2(pm, my_pm, len);

   PLATFORM_DEBUG_PRINT(" pm =%p  , my_pm = %p\n", pm, my_pm); 
  for(i=0;i<len;i++) {
    my_pm->ipv4_address = 11+i;
    my_pm++;
  }
   
   PLATFORM_DEBUG_PRINT(" pm =%p  , my_pm = %p\n", pm, my_pm); 
  pm_len = vec_len(pm);
  PLATFORM_DEBUG_PRINT("\n printing vector contents : vec_len = %d \n", pm_len);
  my_pm = pm;
  for(i=0;i<pm_len ; i++)
  {
    PLATFORM_DEBUG_PRINT(" %d ,",my_pm->ipv4_address);
    my_pm++;
  }
   PLATFORM_DEBUG_PRINT(" pm =%p  , my_pm = %p\n", pm, my_pm); 

  PLATFORM_DEBUG_PRINT("\n adding 6 entries in vector 16-21\n ");
  len = 6;
  vec_add2(pm, my_pm, len);
   PLATFORM_DEBUG_PRINT(" pm =%p  , my_pm = %p\n", pm, my_pm); 
  for(i=0;i<len;i++) {
    my_pm->ipv4_address = 16+i;
    my_pm++;
  }

   PLATFORM_DEBUG_PRINT(" pm =%p  , my_pm = %p\n", pm, my_pm); 
  pm_len = vec_len(pm);
  PLATFORM_DEBUG_PRINT("\n printing vector contents : vec_len = %d \n", pm_len);
  my_pm = pm;
  for(i=0;i<pm_len ; i++)
  {
    PLATFORM_DEBUG_PRINT(" %d ,",my_pm->ipv4_address);
    my_pm++;
  }

   PLATFORM_DEBUG_PRINT(" pm =%p  , my_pm = %p\n", pm, my_pm); 
  PLATFORM_DEBUG_PRINT("\nDeleting 7 entries starting from entry value=8\n");
  pm_len = vec_len(pm);
  my_pm = pm;
   PLATFORM_DEBUG_PRINT(" pm_len =%d\n", pm_len);
  for(i=0;i<pm_len;i++)
  {
    if(my_pm->ipv4_address == 8){
          PLATFORM_DEBUG_PRINT("\n match found brraeaking..\n");
       break;
      } 
     my_pm++;
  }

   PLATFORM_DEBUG_PRINT(" pm =%p  , my_pm = %p i= %d\n", pm, my_pm, i); 
//  vec_delete(pm, 7, my_pm);
  vec_delete(pm, 7, i);
   PLATFORM_DEBUG_PRINT(" pm =%p  , my_pm = %p\n", pm, my_pm); 

  PLATFORM_DEBUG_PRINT(" printing entries aftr deletion from 8-14\n");
  pm_len = vec_len(pm);
  PLATFORM_DEBUG_PRINT("\n printing vector contents : vec_len = %d \n", pm_len);
  my_pm = pm;
  for(i=0;i<pm_len ; i++)
  {
    PLATFORM_DEBUG_PRINT(" %d ,",my_pm->ipv4_address);
    my_pm++;
  }


   PLATFORM_DEBUG_PRINT(" pm =%p  , my_pm = %p\n", pm, my_pm); 

  PLATFORM_DEBUG_PRINT("\nadding deleted items again 8-14\n");
  len =7;
  vec_add2(pm, my_pm, len);

   PLATFORM_DEBUG_PRINT(" pm =%p  , my_pm = %p\n", pm, my_pm); 
  for(i=0;i<len;i++) {
    my_pm->ipv4_address = 8+i;
    my_pm++;
  }

   PLATFORM_DEBUG_PRINT(" pm =%p  , my_pm = %p\n", pm, my_pm); 
  pm_len = vec_len(pm);
  PLATFORM_DEBUG_PRINT("\n printing vector contents : vec_len = %d \n", pm_len);
  my_pm = pm;
  for(i=0;i<pm_len ; i++)
  {
    PLATFORM_DEBUG_PRINT(" %d ,",my_pm->ipv4_address);
    my_pm++;
  }
   PLATFORM_DEBUG_PRINT(" pm =%p  , my_pm = %p\n", pm, my_pm); 
  PLATFORM_DEBUG_PRINT("\n");
}


void uidb_mapping_dump_timeout() {

   u32 i;
 
    PLATFORM_DEBUG_PRINT("\nCGSE uidb mapping table \n"); 
    for(i = 0;i < 30;i++) {
        PLATFORM_DEBUG_PRINT("%d  ",*(cgse_uidb_index_cgse_id_mapping_ptr + i));
    }

}

void nat64_debug_dump_info(u32 debug_value)
{

  switch(debug_value) {

  case 1 :
          bib_add_v6_entry1();
  break;

  case 2 :
         bib_add_v6_entry2();
  break;

  case 3 :
        bib_add_v6_entry1_new();
  break;

  case 4 :
        bib_add_v6_entry1_new_static();
  break;

  case 5 :
        bib_add_v6_entry3();
  break;

  case 6 :
        bib_add_v6_entry_new2();
  break;

  case 7 :
        nat64_fill_table_entry();
  break;

  case 10 :
        nat64_db_dump_main();
  break;

  case 11 :
        nat64_db_dump_user();
  break;

  case 12 :
        nat64_db_dump_session();
  break;

  case 13 :
        nat64_dump_table();
  break;

  case 14 :
        bib_del_v6_entry1_static();
  break;

  case 15 :
    nat64_debug_addr_pool_add_del(); 
  break;

  case 16 :
        nat64_db_dump_timeout(0);
  break;

  case 17 :
        uidb_mapping_dump_timeout();
  break;

  default : break;
  }
}


void cnat_debug_flags_set (spp_api_cnat_p2mp_debug_request_t *mp)
{
    u32 debug_variable = spp_net_to_host_byte_order_32(&mp->param[0]);
    u32 debug_value    = spp_net_to_host_byte_order_32(&mp->param[1]);

    cnat_key_t t_key;

    switch (debug_variable) {

        case CNAT_DEBUG_FLAG_UDP_INSIDE_CHECKSUM_DISABLE:
            udp_inside_checksum_disable = debug_value;
            PLATFORM_DEBUG_PRINT("\nudp_inside_checksum_disable set to %d\n", debug_value);
            break;

        case CNAT_DEBUG_FLAG_UDP_OUTSIDE_CHECKSUM_DISABLE:
            udp_outside_checksum_disable = debug_value;
            PLATFORM_DEBUG_PRINT("\nudp_outside_checksum_disable set to %d\n", debug_value);
            break;

        case CNAT_DEBUG_FLAG_UDP_OUTSIDE_PKT_DUMP_ENABLE:
            udp_outside_packet_dump_enable = debug_value;
            PLATFORM_DEBUG_PRINT("\nudp_outside_packet_dump_enable set to %d\n", debug_value);
            break;

        case CNAT_DEBUG_FLAG_UDP_INSIDE_PKT_DUMP_ENABLE:
            udp_inside_packet_dump_enable = debug_value;
            PLATFORM_DEBUG_PRINT("\nudp_inside_packet_dump_enable set to %d\n", debug_value);
            break;

        case CNAT_DEBUG_FLAG_ICMP_PKT_DUMP_ENABLE:
            icmp_debug_flag = debug_value;
            PLATFORM_DEBUG_PRINT("\nicmp_debug_flag set to %d\n", debug_value);
            break;

        case CNAT_DEBUG_FLAG_FRAG_PKT_DUMP_ENABLE:
            frag_debug_flag = debug_value;
            PLATFORM_DEBUG_PRINT("\nfrag_debug_flag set to %d\n", debug_value);
            break;

        case CNAT_DEBUG_FLAG_XLAT_CONFIG_DEBUG_ENABLE:
            xlat_config_debug_level = debug_value;
            PLATFORM_DEBUG_PRINT("\nxlat_config_debug_level set to %d\n", debug_value);
            break;

        case CNAT_DEBUG_FLAG_NAT64_CONFIG_DEBUG_ENABLE:
            nat64_config_debug_level = debug_value;
            PLATFORM_DEBUG_PRINT("\nnat64_config_debug_level set to %d\n", debug_value);
            nat64_debug_dump_info(debug_value);
            break;

        case CNAT_DEBUG_FLAG_NAT64_DATA_PATH_DEBUG_ENABLE:
            nat64_data_path_debug_level = debug_value;
            PLATFORM_DEBUG_PRINT("\nnat64_data_path_debug_level set to %d\n", debug_value);
            break;

        case CNAT_DEBUG_FLAG_DSLITE_CONFIG_DEBUG_ENABLE:
            ds_lite_config_debug_level = debug_value;
            PLATFORM_DEBUG_PRINT("\nds_lite_config_debug_level set to %d\n", debug_value);
            break;

        case CNAT_DEBUG_FLAG_XLAT_DATA_PATH_DEBUG_ENABLE:
            xlat_data_path_debug_level = debug_value;
            PLATFORM_DEBUG_PRINT("\nxlat_data_path_debug_level set to %d\n", debug_value);
            break;

        case CNAT_DEBUG_FLAG_CONFIG_DEBUG_ENABLE:
            config_debug_level = debug_value;

            PLATFORM_DEBUG_PRINT("\nconfig_debug_level set to %d\n", debug_value);
            break;

        case CNAT_DEBUG_FLAG_CONFIG_PPTP_ENABLE:
            cnat_pptp_debug_flag = debug_value;

            if(debug_value == 0) {
              pptp_dump_counters();
            }

            PLATFORM_DEBUG_PRINT("\ncnat_pptp_debug_level set to %d\n", debug_value);
            break;

        case CNAT_DEBUG_FLAG_CONFIG_PCP_ENABLE:
            cnat_pcp_debug_flag = debug_value;

            if(debug_value == 0) {
              pcp_dump_counters();
            }
            PLATFORM_DEBUG_PRINT("\ncnat_pcp_debug_level set to %d\n", debug_value);
              break;
  
        case CNAT_DEBUG_FLAG_GLOBAL_DEBUG_ALL_ENABLE:
            global_debug_flag = debug_value;
            PLATFORM_DEBUG_PRINT("\nglobal_debug_flag set to %d\n", debug_value);
            break;

        case CNAT_DEBUG_FLAG_SUMMARY_STATS_DEBUG_ENABLE:
            summary_stats_debug_flag = debug_value;
            PLATFORM_DEBUG_PRINT("\nsummary_stats_debug_flag set to %d\n", debug_value);
            break;

        case CNAT_DEBUG_FLAG_SHOW_DEBUG_ENABLE:
            show_debug_level = debug_value;
            PLATFORM_DEBUG_PRINT("\nshow_debug_level set to %d\n", debug_value);
            break;

        case CNAT_DEBUG_FLAG_TCP_LOGGING_ENABLE:
            tcp_debug_logging_enable_disable(debug_value);
            break;
        case CNAT_DEBUG_FLAG_V6RD_DATA_PATH_DEBUG_ENABLE:
            v6rd_data_path_debug_level = debug_value;
            PLATFORM_DEBUG_PRINT("\nv6rd_data_path_debug_level set to %d\n", debug_value);
            break;
        case CNAT_DEBUG_FLAG_V6RD_CONFIG_DEBUG_ENABLE:
            v6rd_config_debug_level = debug_value;
            PLATFORM_DEBUG_PRINT("\nv6rd_config_debug_level set to %d\n", debug_value);
            break;
         case CNAT_DEBUG_FLAG_V6RD_DEFRAG_DEBUG_ENABLE:
             /* set debug atleast to 1, so that critical errors are always
              * enabled
              */
             v6rd_defrag_debug_level = debug_value ? debug_value : 1;
             PLATFORM_DEBUG_PRINT("\nv6rd_config_debug_level set to %d\n", debug_value);
             break;


        case CNAT_DEBUG_SET_STATIC_PORT_RANGE:
	    PLATFORM_DEBUG_PRINT("\nChange Static Port Range from %d --> %d\n",
	           cnat_static_port_range, debug_value);
	    cnat_static_port_range = debug_value;
            break;

        case CNAT_DEBUG_FLAG_DSLITE_DP_ENABLE:
            PLATFORM_DEBUG_PRINT("\n Changing dslite debug flag from %d --> %d\n",
                   dslite_debug_level, debug_value);
            dslite_debug_level = debug_value;
            break;

        case CNAT_DEBUG_FLAG_NFV9_LOGGING_DUMP_ENABLE:
            nfv9_logging_debug_flag = debug_value;
            PLATFORM_DEBUG_PRINT("\nnfv9_logging_debug_flag set to %d\n", debug_value);
            break;

        case CNAT_DEBUG_FLAG_SYSLOG_LOGGING_DUMP_ENABLE:
            syslog_debug_flag = debug_value;
            PLATFORM_DEBUG_PRINT("\nsyslog_debug_flag set to %d\n", debug_value);
            break;

        case CNAT_DEBUG_FLAG_MAPE_CONFIG_DEBUG_ENABLE:
            mape_config_debug_level = debug_value;
            PLATFORM_DEBUG_PRINT("\nmape_config_debug_level set to %d\n", debug_value);
            break;

        case CNAT_DEBUG_FLAG_MAPE_DATA_PATH_DEBUG_ENABLE:
            mape_data_path_debug_level = debug_value;
            PLATFORM_DEBUG_PRINT("\nmape_data_path_debug_level set to %d\n", debug_value);
            break;

        case CNAT_DEBUG_FLAGS_DUMP:
	default:
	{
	    PLATFORM_DEBUG_PRINT("\nCurrent values of Debug Variables\n");
	    PLATFORM_DEBUG_PRINT("\nTo modify an item chose its index and provide the value\n");
	    PLATFORM_DEBUG_PRINT("\n%d: udp_inside_checksum_disable %d\n", 
	           CNAT_DEBUG_FLAG_UDP_INSIDE_CHECKSUM_DISABLE,
		   udp_inside_checksum_disable);
	    PLATFORM_DEBUG_PRINT("%d: udp_outside_checksum_disable %d\n", 
		   CNAT_DEBUG_FLAG_UDP_OUTSIDE_CHECKSUM_DISABLE,
	           udp_outside_checksum_disable);
	    PLATFORM_DEBUG_PRINT("%d: udp_inside_packet_dump_enable %d\n", 
		   CNAT_DEBUG_FLAG_UDP_OUTSIDE_PKT_DUMP_ENABLE,
	           udp_inside_packet_dump_enable);
	    PLATFORM_DEBUG_PRINT("%d: udp_outside_packet_dump_enable %d\n", 
		   CNAT_DEBUG_FLAG_UDP_INSIDE_PKT_DUMP_ENABLE,
	           udp_outside_packet_dump_enable);
	    PLATFORM_DEBUG_PRINT("%d: icmp_debug_flag %d\n",
	           CNAT_DEBUG_FLAG_ICMP_PKT_DUMP_ENABLE,
	           icmp_debug_flag);
	    PLATFORM_DEBUG_PRINT("%d: frag_debug_flag %d\n",
		   CNAT_DEBUG_FLAG_FRAG_PKT_DUMP_ENABLE,
	           frag_debug_flag);
	    PLATFORM_DEBUG_PRINT("%d: config_debug_level %d\n",
	           CNAT_DEBUG_FLAG_CONFIG_DEBUG_ENABLE,
	           config_debug_level);
	    PLATFORM_DEBUG_PRINT("%d: global_debug_flag %d\n",
		   CNAT_DEBUG_FLAG_GLOBAL_DEBUG_ALL_ENABLE,
	           global_debug_flag);
	    PLATFORM_DEBUG_PRINT("%d: summary_stats_debug_flag %d\n",
		   CNAT_DEBUG_FLAG_SUMMARY_STATS_DEBUG_ENABLE,
	           summary_stats_debug_flag);
	    PLATFORM_DEBUG_PRINT("%d: show_debug_level %d\n",
	           CNAT_DEBUG_FLAG_SHOW_DEBUG_ENABLE,
	           show_debug_level);
	    PLATFORM_DEBUG_PRINT("%d: xlat_config_debug_level %d\n",
	           CNAT_DEBUG_FLAG_XLAT_CONFIG_DEBUG_ENABLE,
	           xlat_config_debug_level);
	    PLATFORM_DEBUG_PRINT("%d: xlat_data_path_debug_level %d\n",
	           CNAT_DEBUG_FLAG_XLAT_DATA_PATH_DEBUG_ENABLE,
	           xlat_data_path_debug_level);
	    PLATFORM_DEBUG_PRINT("%d: tcp_logging_enable_flag %d\n",
	           CNAT_DEBUG_FLAG_TCP_LOGGING_ENABLE,
	           tcp_logging_enable_flag);
	    PLATFORM_DEBUG_PRINT("    tcp_logging_enable_options DISABLE %d, ENABLE %d, PKT_DUMP %d, SUMMARY_DUMP %d\n",
	           TCP_LOGGING_DISABLE, TCP_LOGGING_ENABLE,
	           TCP_LOGGING_PACKET_DUMP, TCP_LOGGING_SUMMARY_DUMP);
       PLATFORM_DEBUG_PRINT("%d: nfv9_logging_debug_flag %d\n",
               CNAT_DEBUG_FLAG_NFV9_LOGGING_DUMP_ENABLE,
               nfv9_logging_debug_flag);
       PLATFORM_DEBUG_PRINT("%d: syslog_debug_flag %d\n",
               CNAT_DEBUG_FLAG_SYSLOG_LOGGING_DUMP_ENABLE,
               syslog_debug_flag);
	    PLATFORM_DEBUG_PRINT("%d: cnat_static_port_range %d\n",
	           CNAT_DEBUG_SET_STATIC_PORT_RANGE,
	           cnat_static_port_range);
	    PLATFORM_DEBUG_PRINT("%d: v6rd_data_path_debug_level %d\n",
	           CNAT_DEBUG_FLAG_V6RD_DATA_PATH_DEBUG_ENABLE,
	           v6rd_data_path_debug_level);
	    PLATFORM_DEBUG_PRINT("%d: v6rd_config_debug_level %d\n",
	           CNAT_DEBUG_FLAG_V6RD_CONFIG_DEBUG_ENABLE,
	           v6rd_config_debug_level);
	    PLATFORM_DEBUG_PRINT("%d: v6rd_defrag_debug_level %d\n",
	           CNAT_DEBUG_FLAG_V6RD_DEFRAG_DEBUG_ENABLE,
	           v6rd_defrag_debug_level);
	    PLATFORM_DEBUG_PRINT("%d: nat64_stful_debug %d\n",
	           CNAT_DEBUG_FLAG_NAT64_CONFIG_DEBUG_ENABLE,
	           nat64_config_debug_level);
	    PLATFORM_DEBUG_PRINT("%d: nat64_data_path_debug_level %d\n",
	           CNAT_DEBUG_FLAG_NAT64_DATA_PATH_DEBUG_ENABLE,
	           nat64_data_path_debug_level);
	    PLATFORM_DEBUG_PRINT("%d: dslite_debug_level %d\n",
	           CNAT_DEBUG_FLAG_DSLITE_DP_ENABLE,
	           dslite_debug_level);
	    PLATFORM_DEBUG_PRINT("%d: ds_lite_config_debug_level %d\n",
	           CNAT_DEBUG_FLAG_DSLITE_CONFIG_DEBUG_ENABLE,
	           ds_lite_config_debug_level);
            PLATFORM_DEBUG_PRINT("%d: mape_config_debug_level %d\n",
                   CNAT_DEBUG_FLAG_MAPE_CONFIG_DEBUG_ENABLE,
                   mape_config_debug_level);
            PLATFORM_DEBUG_PRINT("%d: mape_data_path_debug_level %d\n",
                   CNAT_DEBUG_FLAG_MAPE_DATA_PATH_DEBUG_ENABLE,
                   mape_data_path_debug_level);
	}
	break;
    }
}

extern void dump_cnat_frag_stats(void);

void spp_api_cnat_p2mp_debug_request_t_handler
(spp_api_cnat_p2mp_debug_request_t *mp)
{
    u16 command_type;

/*
    if (mp->core_num != my_instance_number) {
        mp->rc = CNAT_NOT_THIS_CORE;
    return;
    }
*/

    command_type = spp_net_to_host_byte_order_16(&mp->dump_type);
    PLATFORM_DEBUG_PRINT("-->> Core%d: Received debug msg ... cmd type: %d\n",
        my_instance_number, command_type);

    switch (command_type) {

    case CNAT_DEBUG_GENERIC_COMMAND_DUMP_POLICY:
        PLATFORM_DEBUG_PRINT("Core%d: policy\n", my_instance_number);
        cnat_db_dump_policy();
        break;

    case CNAT_DEBUG_GENERIC_COMMAND_DUMP_MAIN_DB:
        PLATFORM_DEBUG_PRINT("Core%d: Main db\n", my_instance_number);
        cnat_db_dump_main();
        break;

    case CNAT_DEBUG_GENERIC_COMMAND_DUMP_MAIN_DB_SUMMARY:
        PLATFORM_DEBUG_PRINT("Core%d: Main db Summary\n", my_instance_number);
        cnat_db_dump_main_summary();
        break;

    case CNAT_DEBUG_GENERIC_COMMAND_DUMP_USER_DB:
        PLATFORM_DEBUG_PRINT("Core%d: User db\n", my_instance_number);
        cnat_db_dump_user();
        break;

    case CNAT_DEBUG_GENERIC_COMMAND_DUMP_USER_DB_SUMMARY:
        PLATFORM_DEBUG_PRINT("Core%d: User db Summary\n", my_instance_number);
        cnat_db_dump_user_summary();
        break;

    case CNAT_DEBUG_GENERIC_COMMAND_DUMP_HASHES_DB:
        PLATFORM_DEBUG_PRINT("Core%d: Hashes db\n", my_instance_number);
        cnat_db_dump_hashes();
        break;

    case CNAT_DEBUG_GENERIC_COMMAND_DUMP_VRF_MAP:
        PLATFORM_DEBUG_PRINT("Core%d: Vrf map \n", my_instance_number);
        cnat_db_dump_portmaps();
        break;

    case CNAT_DEBUG_GENERIC_COMMAND_DUMP_SUMMARY_DB:
        PLATFORM_DEBUG_PRINT("Core%d: dump summary DB \n", my_instance_number);
        cnat_db_summary();
        break;
    
    case CNAT_DEBUG_GENERIC_COMMAND_DUMP_STATS:
        PLATFORM_DEBUG_PRINT("Core%d: dump stats \n", my_instance_number);
        spp_node_print_stats(1, NULL);         
        break;

    /* Currently does same as clear node ctr, may change */
    case CNAT_DEBUG_GENERIC_COMMAND_CLEAR_STATS:
        PLATFORM_DEBUG_PRINT("Core%d: clear stats \n", my_instance_number);
        spp_node_clear_stats();
        break;

    case CNAT_DEBUG_SPP_LOG:
        PLATFORM_DEBUG_PRINT("Core%d: SPP LOG \n", my_instance_number);
        spp_log_p2mp_req(mp);
        break;

    case CNAT_DEBUG_GENERIC_COMMAND_DUMP_NODE_COUNTER:
        PLATFORM_DEBUG_PRINT("Core%d: NODE Counter dump \n", my_instance_number);
        spp_node_print_counters();
        break;

    case CNAT_DEBUG_GENERIC_COMMAND_CLEAR_NODE_COUNTER:
        PLATFORM_DEBUG_PRINT("Core%d: clear node counter \n", my_instance_number);
        spp_node_clear_stats();
        break;
 
    case CNAT_DEBUG_GENERIC_COMMAND_DUMP_CNAT_COUNTER:
        PLATFORM_DEBUG_PRINT("Core%d: CNAT Counter dump \n", my_instance_number);
        spp_node_print_cnat_counters();
        break;

    case CNAT_DEBUG_GENERIC_COMMAND_DUMP_VA:
        PLATFORM_DEBUG_PRINT("Core%d: VA dump \n", my_instance_number);
        {
            int argc = 1;
            u32 arg[2] = {spp_net_to_host_byte_order_32(&mp->param[0]), 0};

            cnat_va_dump(argc, arg);
        }
        break;

    case CNAT_DEBUG_GENERIC_COMMAND_SHOW_CONFIG:
        PLATFORM_DEBUG_PRINT("Core%d: Show config dump \n", my_instance_number);
        {
            int argc = 0;
            unsigned long arg[3];

            if (arg[argc++] = spp_net_to_host_byte_order_32(&mp->param[0])) {
                if (arg[argc++] = spp_net_to_host_byte_order_32(&mp->param[1])) {
                    ;
                } else {
                    argc--;
                }
            }

            cnat_show_cdb_command_v2(argc, arg);
/*
            xlat_show_config();
            cnat_alg_show();
*/
            v6rd_show_config();
            dslite_show_config();
	    nat64_dump_table();
            mape_show_config();
        }
        break;
       
    case CNAT_DEBUG_GENERIC_COMMAND_SHOW_NFV9:
        PLATFORM_DEBUG_PRINT("Core%d: NFv9 dump \n", my_instance_number);
        #if 0 /* Currently not calling this */
        cnat_nfv9_show_cmd();
        #endif
        break;

    case CNAT_DEBUG_GENERIC_COMMAND_SHOW_IVRF:
        PLATFORM_DEBUG_PRINT("Core%d: IVRF dump \n", my_instance_number);
        {
            int argc = 0;
            unsigned long arg[3];

            if (arg[argc++] = spp_net_to_host_byte_order_32(&mp->param[0])) {
                if (arg[argc++] = spp_net_to_host_byte_order_32(&mp->param[1])) {
                    if (arg[argc++] = spp_net_to_host_byte_order_32(&mp->param[2])) {
                        ;
                    } else {
                        argc--;
                    }
                } else {
                    argc--;
                }
            }


            PLATFORM_DEBUG_PRINT("VRF: %d \n", spp_net_to_host_byte_order_32(&mp->param[0]));
            PLATFORM_DEBUG_PRINT("2nd arg: %d \n",
                  spp_net_to_host_byte_order_32(&mp->param[1]));
            
            cnat_show_ivrf_command_v2(argc, arg);
        } 
        break;

    case CNAT_DEBUG_GENERIC_COMMAND_SHOW_OVRF:
        PLATFORM_DEBUG_PRINT("Core%d: OVRF dump \n", my_instance_number);
        {
            int argc = 0;
            unsigned long arg[3];
            if (arg[argc++] = spp_net_to_host_byte_order_32(&mp->param[0])) { 
                if (arg[argc++] = spp_net_to_host_byte_order_32(&mp->param[1])) {
                    if (arg[argc++] = spp_net_to_host_byte_order_32(&mp->param[2])) {
                        ;
                    } else {
                        argc--;
                    }
                } else {
                    argc--;
                }
            }

            PLATFORM_DEBUG_PRINT("VRF: %d \n", spp_net_to_host_byte_order_32(&mp->param[0]));
            PLATFORM_DEBUG_PRINT("2nd arg: %d \n",
                  spp_net_to_host_byte_order_32(&mp->param[1]));

            cnat_show_ovrf_command_v2(argc, arg);
        }
        break;

    case CNAT_DEBUG_GENERIC_COMMAND_DEBUG_OPTIONS: 
        PLATFORM_DEBUG_PRINT("Core%d: Debug option dump \n", my_instance_number);
        { 
            global_pd_dbg_lvl = 0;
            global_pi_dbg_lvl = 0;
            global_l2_dbg_lvl = 0;

            global_pd_dbg_lvl =
                  spp_net_to_host_byte_order_32(&mp->param[0]);
            global_pi_dbg_lvl = 
                  spp_net_to_host_byte_order_32(&mp->param[1]);
            global_l2_dbg_lvl = 
                  spp_net_to_host_byte_order_32(&mp->param[2]);

            PLATFORM_DEBUG_PRINT("global_pd_dbg_lvl: %d, global_pi_dbg_lvl: %d, global_l2_dbg_lvl: %d\n",
                global_pd_dbg_lvl, global_pi_dbg_lvl, global_l2_dbg_lvl);
        }
        break;

    case CNAT_DEBUG_GENERIC_COMMAND_DUMP_DEBUG_LEVELS:
        PLATFORM_DEBUG_PRINT("Core%d: PD Debug level: %d \n", my_instance_number, global_pd_dbg_lvl);
        PLATFORM_DEBUG_PRINT("Core%d: PI Debug level: %d \n", my_instance_number, global_pi_dbg_lvl);
        PLATFORM_DEBUG_PRINT("Core%d: L2 Debug level: %d \n", my_instance_number, global_l2_dbg_lvl);
        break;

    case CNAT_DEBUG_GENERIC_COMMAND_DEBUG_FLAGS:
        PLATFORM_DEBUG_PRINT("Core%d: Debug flags \n", my_instance_number);
        cnat_debug_flags_set(mp);
        break;

    case CNAT_READ_TEMP_SENSORS:
         PLATFORM_INIT_TEMP_SENSORS();
         PLATFORM_READ_CPU_SENSORS(TEMPERATURE_SENSOR_TEST_MODE);
         break;

    case CNAT_BLOCK_OCTEON_SENSOR_READ:

         PLATFORM_SET_TEMP_READ_BLOCK(temperature_read_blocked , mp);
#ifdef TARGET_RODDICK
        temperature_read_blocked = 
              spp_net_to_host_byte_order_32(&mp->param[0]);
#endif
        break;

    case CNAT_DEBUG_TIMEOUT_DB_SUMMARY:
        cnat_db_dump_timeout();
        break;

    /* This option has to be removed later */
    case CNAT_DEBUG_SET_BULK_SIZE:
        PLATFORM_DEBUG_PRINT("\nSetting bulk size to %d\n",
            spp_net_to_host_byte_order_32(&mp->param[0]));
        set_bulk_size_to_all_vrfs(
            spp_net_to_host_byte_order_32(&mp->param[0]));
        break;

    case CNAT_DEBUG_SHOW_BULK_STAT:
        show_bulk_port_stats();
        break;

    case CNAT_DEBUG_CLEAR_BULK_STAT:
        clear_bulk_port_stats();
        break;

    case CNAT_DEBUG_SHOW_BULK_ALLOC:
        {
            u16 in_vrfid = spp_net_to_host_byte_order_32(&mp->param[0]);
            u32 inside_ip = spp_net_to_host_byte_order_32(&mp->param[1]);
            show_bulk_port_allocation(in_vrfid, inside_ip);
        }
        break;

    case CNAT_DEBUG_NAT44_IN2OUT_FRAG_STATS:
         dump_cnat_frag_stats();
         break;

    default:
        mp->rc = CNAT_ERR_INVALID_MSG_ID;
        break;
    }

    mp->rc = CNAT_SUCCESS;
    return;
}


void spp_api_cnat_v4_debug_in2out_private_addr_t_handler
(spp_api_cnat_v4_debug_in2out_private_addr_t *mp)
{
    u16   i_vrf;
    u32   debug_flag;
    u32 start_addr, end_addr;


    start_addr =
        spp_net_to_host_byte_order_32(&mp->start_addr);
    end_addr =
        spp_net_to_host_byte_order_32(&mp->end_addr);
    i_vrf =
        spp_net_to_host_byte_order_16(&mp->i_vrf);
    debug_flag =
        spp_net_to_host_byte_order_32(&mp->debug_flag);

    if ((i_vrf > MAX_UIDX) || (start_addr > end_addr) ||
        ((debug_flag != CNAT_DEBUG_NONE) && 
         ((debug_flag & CNAT_DEBUG_ALL) == CNAT_DEBUG_NONE))) { 
        mp->rc = CNAT_ERR_PARSER;
        PLATFORM_DEBUG_PRINT("invalid debug ivrf 0x%x flag 0x%x "
               "start addr 0x%x end addr 0x%x\n",
                 i_vrf, debug_flag,
                 start_addr, end_addr);
        return;
    }

    PLATFORM_DEBUG_PRINT("debug ivrf 0x%x flag 0x%x "
           "start addr 0x%x end addr 0x%x\n",
           i_vrf, debug_flag, 
           start_addr, end_addr);

    mp->rc = CNAT_SUCCESS;
    debug_i_vrf = i_vrf;
    debug_i_flag = debug_flag;
    debug_i_addr_start = start_addr;
    debug_i_addr_end = end_addr;

}

void spp_api_cnat_v4_debug_out2in_public_addr_t_handler
(spp_api_cnat_v4_debug_out2in_public_addr_t *mp)
{
    u16   o_vrf;
    u32   debug_flag;
    u32 start_addr, end_addr;

    start_addr =
        spp_net_to_host_byte_order_32(&mp->start_addr);
    end_addr =
        spp_net_to_host_byte_order_32(&mp->end_addr);
    o_vrf =
        spp_net_to_host_byte_order_16(&mp->o_vrf);
    debug_flag =
        spp_net_to_host_byte_order_32(&mp->debug_flag);

    if ((o_vrf > MAX_UIDX) || (start_addr > end_addr) ||
        ((debug_flag != CNAT_DEBUG_NONE) &&
         ((debug_flag & CNAT_DEBUG_ALL) == CNAT_DEBUG_NONE))) {
        mp->rc = CNAT_ERR_PARSER;
        PLATFORM_DEBUG_PRINT("invalid debug ovrf 0x%x flag 0x%x "
               "start addr 0x%x end addr 0x%x\n",
                 o_vrf, debug_flag,
                 start_addr, end_addr);
        return;
    }

    mp->rc = CNAT_SUCCESS;
    debug_o_vrf = o_vrf;
    debug_o_flag = debug_flag;
    debug_o_addr_start = start_addr;
    debug_o_addr_end = end_addr;

   PLATFORM_DEBUG_PRINT(" o2i debug currently is not supported\n"); 
}

void nat64_reset_session_expiry(nat64_bib_entry_t *db) 
{
    NAT64_STFUL_DEBUG_PRINT(3, " invoking nat64_clean_bib_db_entry\n " );
    nat64_clean_bib_db_entry(db);
    NAT64_STFUL_DEBUG_PRINT(3, "done with clean_bib_db_entry\n " );
}

void spp_api_nat64_clear_db_request_t_handler
(spp_api_nat64_clear_db_request_t *mp) 
{
    u16 port, proto, flag;
    u32 index;
    u32 i;
    nat64_bib_entry_t* db;
    nat64_v6_key_t ki;
    nat64_table_entry_t *my_nat64_table_db_ptr;
    u16 nat64_id;

    NAT64_STFUL_FUNC_ENTER;
    NAT64_STFUL_DEBUG_DUMP_MSG(mp);

    nat64_id = spp_net_to_host_byte_order_16(&mp->nat64_id);
    my_nat64_table_db_ptr = nat64_table_ptr + nat64_id;

    port = spp_net_to_host_byte_order_16(&mp->port_num);
    proto = mp->protocol;

    ki.vrf = nat64_id;
    ki.vrf |= ((u16)proto << CNAT_PRO_SHIFT);

    for(i =0 ; i< 4 ; i++) 
       ki.ipv6[i] = spp_net_to_host_byte_order_32(&mp->ip_addr[i]);

    ki.port = port;

    flag = mp->flags;

    mp->rc = CNAT_SUCCESS;

    NAT64_STFUL_DEBUG_PRINT(3, "\n Nat64_id = %d, port =%d, \
                                proto =%d, flags=0x%08X",\
                             nat64_id, port, proto, flag);
          
    NAT64_STFUL_DEBUG_PRINT(3, "\n IPv6 Addr = %08X :  %08X: %08X:  %08X",\
           ki.ipv6[0],  ki.ipv6[1],  ki.ipv6[2],  ki.ipv6[3]); 

    if (flag == CNAT_DB_CLEAR_SPECIFIC) {
        NAT64_STFUL_DEBUG_PRINT(3, "\n clear specific \n");

        db = nat64_bib_db_lookup_entry(&ki); 
        if (db == NULL) {
            NAT64_STFUL_DEBUG_PRINT(3, "\n clear specific - not present\n");
            mp->rc = CNAT_NOT_FOUND_ANY;
            return;
        }

        if( !(db->flags & CNAT_DB_NAT64_FLAG) ||
              (db->nat64_inst_id != nat64_id))
               return;


         nat64_reset_session_expiry(db);
         return;
    }

    pool_header_t *p  = pool_header(nat64_bib_db);
  
    for(index = 0; index < vec_len(nat64_bib_db); index++) {

        /* check is it nat44, if yes skip , do it n nat44 as well */

        if (PREDICT_FALSE(!clib_bitmap_get(p->free_bitmap, index))) {
            db = nat64_bib_db + index;

            if( !(db->flags & CNAT_DB_NAT64_FLAG) || 
                 (db->nat64_inst_id != nat64_id)) 
                   continue;
        
            if (flag == CNAT_DB_CLEAR_ALL) {
                nat64_reset_session_expiry(db);
                continue;
            }
           
            if (flag & CNAT_DB_CLEAR_ADDR) {
                if ((db->v6_in_key.ipv6[0] != ki.ipv6[0]) ||
                    (db->v6_in_key.ipv6[1] != ki.ipv6[1]) ||
                    (db->v6_in_key.ipv6[2] != ki.ipv6[2]) ||
                    (db->v6_in_key.ipv6[3] != ki.ipv6[3])){
                     NAT64_STFUL_DEBUG_PRINT(3, "\n%s:%d\n", __FUNCTION__, \
                                              __LINE__ );
                    continue;
                }
            }
             
            if (flag & CNAT_DB_CLEAR_PROTO) {
                if (((db->v6_in_key.vrf  & CNAT_PRO_MASK) >> CNAT_PRO_SHIFT)
                                                            != proto) {
                   NAT64_STFUL_DEBUG_PRINT(3, "\n%s:%d\n", __FUNCTION__, \
                                              __LINE__ );
                    continue;
                }
            }

            if (flag & CNAT_DB_CLEAR_PORT) {
                if (db->v6_in_key.port  != port) {
                   NAT64_STFUL_DEBUG_PRINT(3, "\n%s:%d\n", __FUNCTION__, \
                                              __LINE__ );
                    continue;
               }
            }
 
            NAT64_STFUL_DEBUG_PRINT(3, "\n%s:%d\n", __FUNCTION__, \
                                              __LINE__ );
            /*
             * Delete if the db entry matches and it is not a
             */
            nat64_reset_session_expiry(db);
        }
    }
}

void inline cnat_clear_session_db(cnat_main_db_entry_t *db)
{
    if(PREDICT_FALSE(db->nsessions > 1)) {
        u32 session_index = db->session_head_index;
        cnat_session_entry_t *sdb;
        do {
            sdb = cnat_session_db + session_index;
            if(PREDICT_FALSE(!sdb)) {
                //TO DO: Debug msg?
                break;
            }
            sdb->entry_expires = 0;
            session_index = sdb->main_list.next;
        } while(session_index != db->session_head_index
                && db->session_head_index != EMPTY);
    }
    return;
}

#ifdef CGSE_DS_LITE
extern dslite_table_entry_t dslite_table_array[];

void spp_api_ds_lite_clear_db_request_t_handler
(spp_api_ds_lite_clear_db_request_t *mp) 
{
    u16 port, proto, flag;
    u32 index;
    u32 i;
    cnat_main_db_entry_t *db;
    cnat_user_db_entry_t  *udb;
    dslite_key_t ki;
    dslite_table_entry_t *my_table_db_ptr;
    u16 id;
    u16 i_vrf;


    id = spp_net_to_host_byte_order_16(&mp->ds_lite_id);
    id = DS_LITE_CONFIG_TO_ARRAY_ID(id);

    my_table_db_ptr = &dslite_table_array[id];
    i_vrf = my_table_db_ptr->i_vrf;

    port = spp_net_to_host_byte_order_16(&mp->port_num);
    proto = mp->protocol;

    ki.ipv4_key.k.vrf = i_vrf;
    ki.ipv4_key.k.vrf |= ((u16)proto << CNAT_PRO_SHIFT);

    for(i =0 ; i< 4 ; i++) 
       ki.ipv6[i] = spp_net_to_host_byte_order_32(&mp->ip_addr[i]);

    ki.ipv4_key.k.port = port;

    flag = mp->flags;

    mp->rc = CNAT_SUCCESS;

    DSLITE_PRINTF(3, "\n dslite id = %d, port =%d" 
                             "proto =%d, flags=0x%08X",\
                             id, port, proto, flag);
          
    DSLITE_PRINTF(3, "\n IPv6 Addr = %08X :  %08X: %08X:  %08X",\
           ki.ipv6[0],  ki.ipv6[1],  ki.ipv6[2],  ki.ipv6[3]); 

    if (flag == CNAT_DB_CLEAR_SPECIFIC) {
        DSLITE_PRINTF(3, "\n Clear specific NOT supported for DS Lite \n");
        return;
    }

    pool_header_t *p  = pool_header(cnat_main_db);
  
    for(index = 0; index < vec_len(cnat_main_db); index++) {

        /* check is it dslite entry, if not skip */

        if (PREDICT_FALSE(!clib_bitmap_get(p->free_bitmap, index))) {
            db = cnat_main_db + index;

            if( !(db->flags & CNAT_DB_DSLITE_FLAG) || 
                 ((db->in2out_key.k.vrf & CNAT_VRF_MASK) != i_vrf) ||
                 (db->flags & CNAT_DB_FLAG_STATIC_PORT)) {
                   continue;
            }
        
            if (flag == CNAT_DB_CLEAR_ALL) {
             
             /* 
              * Make the entry time as very old (0), and wait
              * for a timeout to auto-expire the entry.
              */
                db->entry_expires = 0;
                /* Handle sessions as well.. */
                cnat_clear_session_db(db);
                continue;
            }
           
            if (flag & CNAT_DB_CLEAR_ADDR) {
                udb = cnat_user_db + db->user_index;
                if(PREDICT_FALSE(!udb)) {
                    continue;
                }
                if ((udb->ipv6[0] != ki.ipv6[0]) ||
                    (udb->ipv6[1] != ki.ipv6[1]) ||
                    (udb->ipv6[2] != ki.ipv6[2]) ||
                    (udb->ipv6[3] != ki.ipv6[3])) {
                    continue;
                }
            }
             
            if (flag & CNAT_DB_CLEAR_PROTO) {
                if (((db->in2out_key.k.vrf & CNAT_PRO_MASK) >> CNAT_PRO_SHIFT)
                                                            != proto) {
                    continue;
                }
            }

            if (flag & CNAT_DB_CLEAR_PORT) {
                if (db->in2out_key.k.port  != port) {
                    continue;
               }
            }
 
            /*
             * Mark for expiry in the next round of DB scan
             */
            db->entry_expires = 0;
            /* Handle sessions as well.. */
            cnat_clear_session_db(db);
        }
    }
}
#endif /* #ifdef CGSE_DS_LITE */

void spp_api_cnat_clear_db_request_t_handler 
(spp_api_cnat_clear_db_request_t *mp) 
{
    u16 i_vrf, port, proto, flag;
    u32 ip_addr, index;
    u64 a,b,c;
    cnat_main_db_entry_t * db;
    cnat_db_key_bucket_t ki;

#if defined(TARGET_LINUX_UDVR) || defined(CNAT_PG) 
    i_vrf = mp->inside_vrf;
    ip_addr = mp->ip_addr;
    port = mp->port_num;
    proto = mp->protocol;
#else
    i_vrf = spp_net_to_host_byte_order_16(&mp->inside_vrf);
    ip_addr = spp_net_to_host_byte_order_32(&mp->ip_addr);
    port = spp_net_to_host_byte_order_16(&mp->port_num);
    proto = spp_net_to_host_byte_order_16(&mp->protocol);
#endif


    
    ki.k.k.vrf = i_vrf;
    ki.k.k.vrf |= ((u16)proto << CNAT_PRO_SHIFT);
    ki.k.k.ipv4 = ip_addr;
    ki.k.k.port = port;

    flag = mp->wildcard;

    mp->rc = CNAT_SUCCESS;

    if (flag == CNAT_DB_CLEAR_SPECIFIC) {
        CNAT_V4_GET_HASH(ki.k.key64,
                    ki.bucket,
                    CNAT_MAIN_HASH_MASK);
        index = cnat_in2out_hash[ki.bucket].next;
        if (PREDICT_TRUE(index == EMPTY)) {
            mp->rc = CNAT_NOT_FOUND_ANY;
            return;
        }

        do {
            db = cnat_main_db + index;

	    /*
	     * Delete if the db entry matches and it is not a
	     * STATIC port entry
	     */
            if ((db->in2out_key.key64 == ki.k.key64) &&
                !(db->flags & CNAT_DB_FLAG_STATIC_PORT) &&
                !(db->flags & CNAT_DB_NAT64_FLAG) &&
                !(db->flags & CNAT_DB_DSLITE_FLAG)) {
             
             /* 
              * Make the entry time as very old (0), and wait
              * for a timeout to auto-expire the entry.
              */
                db->entry_expires = 0;
                /* Handle sessions as well.. */
                cnat_clear_session_db(db);
		return;
            }
            index = db->in2out_hash.next;
        } while (index != EMPTY);

         mp->rc = CNAT_NOT_FOUND_ANY;       
         return;
    }

    pool_header_t *p  = vec_header(cnat_main_db, sizeof(pool_header_t));

    for(index = 0; index < vec_len(cnat_main_db); index++) {

        if (PREDICT_TRUE(!clib_bitmap_get(p->free_bitmap, index))) {
            db = cnat_main_db + index;
           
            if(PREDICT_FALSE(db->flags & CNAT_DB_NAT64_FLAG)) {
                continue;
            } 

            if(PREDICT_FALSE(db->flags & CNAT_DB_DSLITE_FLAG)) {
                continue;
            }

            if (flag == CNAT_DB_CLEAR_ALL) {
                if (!(db->flags & CNAT_DB_FLAG_STATIC_PORT)) {
                    db->entry_expires = 0;
                    /* Handle sessions as well.. */
                    cnat_clear_session_db(db);
		}
                continue;
            }
           
            if (flag & CNAT_DB_CLEAR_VRF) {
                if (((db->in2out_key.k.vrf & CNAT_VRF_MASK) != i_vrf)) {
                    continue; 
                }
            }
            
            if (flag & CNAT_DB_CLEAR_ADDR) {
                if ((db->in2out_key.k.ipv4 != ip_addr)) {
                    continue;
                }
            }
             
            if (flag & CNAT_DB_CLEAR_PROTO) {
                if (((db->in2out_key.k.vrf  & CNAT_PRO_MASK) >> CNAT_PRO_SHIFT)
                                                            != proto) {
                    continue;
                }
            }

            if (flag & CNAT_DB_CLEAR_PORT) {
                if (db->in2out_key.k.port  != port) {
                    continue;
               }
            }
 
	    /*
	     * Delete if the db entry matches and it is not a
	     * STATIC port entry
	     */
	    if (!(db->flags & CNAT_DB_FLAG_STATIC_PORT)) {
            db->entry_expires = 0;
            /* Handle sessions as well.. */
            cnat_clear_session_db(db);
       	    }
        }    
    }
}

void
spp_api_cnat_generic_command_debug (cnat_generic_command_resp *mp_resp)
{
#ifdef SHOW_DEBUG
    u32 i, j;

    i = spp_net_to_host_byte_order_32(&(mp_resp->num_bytes));

    PLATFORM_DEBUG_PRINT("\nNum_Bytes %d\n", i);

    for (j = 0; j < i; j++) {
        PLATFORM_DEBUG_PRINT("0x%02X ", mp_resp->raw_data[j]);
	if ((j % 16) == 15) {
	    PLATFORM_DEBUG_PRINT("\n");
	}
    }
#endif
}

/*
 * The following commands implements command to dump the
 *    user-db information 
 *    port-map information
 *      for a give user source IP address
 *
 * The format of the output is:
 *   Word 0: Address of udb
 *   Word 1: udb->translation_list_head_index
 *   Word 2: 
 *     Bytes 0..1: udb->ntranslations
 *     Bytes 2..2: udb->icmp_msg_coung
 *     Bytes 3..3: udb->unused
 *   Word 3: udb->portmap_index
 *   Word 4: udb->key.k.ipv4
 *   Word 5: 
 *     Bytes 0..1: udb->key.k.port = 0
 *     Bytes 2..3: udb->key.k.vrf
 *   Word 6: udb->user_hash
 *   Word 7: Address of my_pm 
 *   Word 8: my_pm->status
 *   Word 9: my_pm->inuse
 *   Word A: my_pm->delete_time
 *   Word B: my_pm->ipv4_address
 */
void spp_api_cnat_generic_command_user_db_pm
(spp_api_cnat_generic_command_request_t *mp) 
{
    u32 i;
    cnat_db_key_bucket_t u_ki;
    u16 my_vrfmap_index;
    u32 *result_array;
    cnat_generic_command_resp *mp_resp;
    cnat_user_db_entry_t *udb;
    cnat_user_db_entry_t *mp_udb;
    cnat_vrfmap_t *my_vrfmap;
    cnat_portmap_v2_t *pm;
    cnat_portmap_v2_t *my_pm;

    /*
     * Request structure is used to send the response
     */
    mp_resp = (cnat_generic_command_resp *) mp;

    u_ki.k.k.vrf  = spp_net_to_host_byte_order_32(&mp->params[1]);
    u_ki.k.k.ipv4 = spp_net_to_host_byte_order_32(&mp->params[2]);
    u_ki.k.k.port = 0;

    udb = cnat_user_db_lookup_entry(&u_ki);

    if (!udb) {
	mp_resp->num_bytes = spp_host_to_net_byte_order_32(0);
	goto no_udb_found;
    }

    result_array = (u32 *) (&(mp_resp->raw_data[0]));

    i = 0;
    result_array[i++] = spp_host_to_net_byte_order_32((u32) udb);

    mp_udb = (cnat_user_db_entry_t *) &(result_array[i]);

    /*
     * Align the entry to the next 4 byte boundary
     */
    i = i + ((sizeof(cnat_user_db_entry_t)+3)/4);

    /*
     * Fill in the UDB information
     */
    mp_udb->translation_list_head_index =
        spp_host_to_net_byte_order_32(udb->translation_list_head_index);
    mp_udb->ntranslations =
        spp_host_to_net_byte_order_16(udb->ntranslations);
    mp_udb->icmp_msg_count = udb->icmp_msg_count;
    mp_udb->flags = udb->flags;
    mp_udb->portmap_index =
        spp_host_to_net_byte_order_32(udb->portmap_index);
    mp_udb->key.k.ipv4 =
        spp_host_to_net_byte_order_32(udb->key.k.ipv4);
    mp_udb->key.k.port =
        spp_host_to_net_byte_order_16(udb->key.k.port);
    mp_udb->key.k.vrf =
        spp_host_to_net_byte_order_16(udb->key.k.vrf);
    mp_udb->user_hash.next =
        spp_host_to_net_byte_order_32(udb->user_hash.next);

    my_vrfmap_index = vrf_map_array[u_ki.k.k.vrf];
    my_vrfmap = cnat_map_by_vrf + my_vrfmap_index;
    pm = my_vrfmap->portmap_list;
    my_pm = pm + udb->portmap_index;

    /*
     * Fill in the port_map information
     */
    result_array[i++] = spp_host_to_net_byte_order_32((u32) my_pm);
    result_array[i++] = spp_host_to_net_byte_order_32(my_pm->inuse);
    result_array[i++] = spp_host_to_net_byte_order_32(my_pm->delete_time);
    result_array[i++] = spp_host_to_net_byte_order_32(my_pm->ipv4_address);

    mp_resp->num_bytes = spp_host_to_net_byte_order_32(i*4);

no_udb_found:
    spp_api_cnat_generic_command_debug(mp_resp);
}

/*
 * The following commands implements command to dump the
 * DB usage stats for 
 *    main-db
 *    user-db
 *    in2out hash
 *    out2in hash
 *
 * The format of the output is:
 *   Word 0: Main-DB - Total
 *   Word 1: Main-DB - Active
 *   Word 2: Main-DB - Free
 *   Word 3: User-DB - Total
 *   Word 4: User-DB - Active
 *   Word 5: User-DB - Free
 *   Word 6: Hash In2Out - Size
 *   Word 7: Hash In2Out - Used
 *   Word 8: Hash In2Out - Used Percentage
 *   Word 9: Hash Out2In - Size
 *   Word A: Hash Out2In - Used
 *   Word B: Hash Out2In - Used Percentage
 */
void spp_api_cnat_generic_command_db_summary 
(spp_api_cnat_generic_command_request_t *mp) 
{
    u32 count1, count2, count3;
    u32 i = 0;
    u32 k = 0;
    cnat_generic_command_resp *mp_resp;
    u32 *result_array;

    /*
     * Request structure is used to send the response
     */
    mp_resp = (cnat_generic_command_resp *) mp;
    result_array = (u32 *) (&(mp_resp->raw_data[0]));

    /*
     * Find entries free and used in main-db
     */
    count1 = vec_len(cnat_main_db);
    count2 = db_free_entry(cnat_main_db);
    count3 = count1 - count2;

    *(result_array + i++) = spp_host_to_net_byte_order_32(count1);
    *(result_array + i++) = spp_host_to_net_byte_order_32(count3);
    *(result_array + i++) = spp_host_to_net_byte_order_32(count2);

    /*
     * Find entries free and used in user-db
     */
    count1 = vec_len(cnat_user_db);
    count2 = db_free_entry(cnat_user_db);
    count3 = count1 - count2;

    *(result_array + i++) = spp_host_to_net_byte_order_32(count1);
    *(result_array + i++) = spp_host_to_net_byte_order_32(count3);
    *(result_array + i++) = spp_host_to_net_byte_order_32(count2);

    /*
     * Find entries used in in2out and out2in hash tables
     * and percentage utilization.
     */
    count1 = count2 = 0;
    for (k = 0; k < CNAT_MAIN_HASH_SIZE; k++) {
        if(cnat_in2out_hash[k].next != ~0) count1++;
        if(cnat_out2in_hash[k].next != ~0) count2++;

    }

    count3 = count1*100/CNAT_MAIN_HASH_SIZE;

    *(result_array + i++) = spp_host_to_net_byte_order_32(CNAT_MAIN_HASH_SIZE);
    *(result_array + i++) = spp_host_to_net_byte_order_32(count1);
    *(result_array + i++) = spp_host_to_net_byte_order_32(count3);

    count3 = count2*100/CNAT_MAIN_HASH_SIZE;

    *(result_array + i++) = spp_host_to_net_byte_order_32(CNAT_MAIN_HASH_SIZE);
    *(result_array + i++) = spp_host_to_net_byte_order_32(count2);
    *(result_array + i++) = spp_host_to_net_byte_order_32(count3);

    mp_resp->num_bytes = spp_host_to_net_byte_order_32(i*4);

    spp_api_cnat_generic_command_debug(mp_resp);
}

/*
 * The following commands implements generic commands such as:
 *
 * Command 1:
 *  Reads num_bytes octets from a start_locn
 *  generic command <core_num> <cmd_type=1> <start_locn> <num_bytes> 0 0 0 0 0
 *
 * Command 2:
 *  Writes upto 8  octets from a start_locn
 *  generic command <core_num> <cmd_type=2> <start_locn> <num_bytes> 0 0 0 0 0
 *
 * Command 3:
 *  Dump the db summary stats
 *  generic command <core_num> <cmd_type=3>
 *
 * Command 4:
 *  Dump the user db entry
 *  generic command <core_num> <cmd_type=4> <vrf_id> <src_ip_addr>
 *
 * The following structures are referenced by this command:
 *     typedef struct _spp_api_cnat_generic_command_request {
 *         u16 _spp_msg_id;
 *         u8 rc;
 *         u8 core_num;
 *         u32 params[8];
 *     } spp_api_cnat_generic_command_request_t;
 *
 *     typedef struct {
 *         u16 spp_msg_id;
 *         u8  rc;
 *         u8  core;
 *         u32 num_bytes;
 *         u8  raw_data[0];
 *     } cnat_generic_command_resp;
 *
 */
void spp_api_cnat_generic_command_request_t_handler 
(spp_api_cnat_generic_command_request_t *mp) 
{
    cnat_generic_command_resp *resp_ptr;
    u32 command_type, start_locn, num_bytes;

    command_type = spp_net_to_host_byte_order_32(&mp->params[0]);
    resp_ptr     = (cnat_generic_command_resp *) mp;

    switch (command_type) {
        case CNAT_DEBUG_GENERIC_COMMAND_READ_MEM:
	    start_locn = spp_net_to_host_byte_order_32(&mp->params[1]);
	    num_bytes  = spp_net_to_host_byte_order_32(&mp->params[2]);
	    clib_memcpy(&(resp_ptr->raw_data[0]), (u8 *) start_locn, num_bytes);
	    resp_ptr->num_bytes = spp_host_to_net_byte_order_32(num_bytes);

#ifdef SHOW_DEBUG
            {
	        u32 i;

	        for (i = 0; i < num_bytes; i++) {
		    PLATFORM_DEBUG_PRINT("0x%02X ", resp_ptr->raw_data[i]);
		    if ((i % 16) == 15) {
		        PLATFORM_DEBUG_PRINT("\n");
		    }
		}
	    }
#endif
	    break;

        case CNAT_DEBUG_GENERIC_COMMAND_WRITE_MEM:
	    start_locn = spp_net_to_host_byte_order_32(&mp->params[1]);
	    num_bytes  = spp_net_to_host_byte_order_32(&mp->params[2]);

	    if (num_bytes > sizeof(u64)) {
	        mp->rc = CNAT_ERR_INVALID_MSG_SIZE;
		return;
	    }

	    clib_memcpy((u8 *) start_locn, &(mp->params[3]), num_bytes);
	    resp_ptr->num_bytes = 0;
	    break;

        case CNAT_DEBUG_GENERIC_COMMAND_DB_SUMMARY:
	    spp_api_cnat_generic_command_db_summary(mp);
	    break;

        case CNAT_DEBUG_GENERIC_COMMAND_USER_DB_PM:
	    spp_api_cnat_generic_command_user_db_pm(mp);
	    break;

        case CNAT_DEBUG_GET_CGN_DB_SUMMARY:
            spp_api_cnat_get_cgn_db_summary(mp);
            break; 

        default:
	    mp->rc = CNAT_ERR_INVALID_MSG_ID;
	    break;
    }
}


static int cnat_debug_init (void *notused)
{
    spp_msg_api_set_handler(SPP_API_CNAT_V4_DEBUG_DUMMY,
                            spp_api_cnat_v4_debug_dummy_t_handler);

    spp_msg_api_set_handler(SPP_API_CNAT_V4_DEBUG_DUMMY_MAX,
                            spp_api_cnat_v4_debug_dummy_max_t_handler);

    spp_msg_api_set_handler(SPP_API_CNAT_V4_DEBUG_GLOBAL,
                            spp_api_cnat_v4_debug_global_t_handler);

    spp_msg_api_set_handler(SPP_API_CNAT_V4_DEBUG_IN2OUT_PRIVATE_ADDR,
                           spp_api_cnat_v4_debug_in2out_private_addr_t_handler);

    spp_msg_api_set_handler(SPP_API_CNAT_V4_DEBUG_OUT2IN_PUBLIC_ADDR,
                            spp_api_cnat_v4_debug_out2in_public_addr_t_handler);

    spp_msg_api_set_handler(SPP_API_CNAT_CLEAR_DB_REQUEST, 
                            spp_api_cnat_clear_db_request_t_handler);

    spp_msg_api_set_handler(SPP_API_CNAT_GENERIC_COMMAND_REQUEST,
                            spp_api_cnat_generic_command_request_t_handler);

    spp_msg_api_set_handler(SPP_API_CNAT_P2MP_DEBUG_REQUEST,
                            spp_api_cnat_p2mp_debug_request_t_handler);

    spp_msg_api_set_handler(SPP_API_NAT64_CLEAR_DB_REQUEST,
                            spp_api_nat64_clear_db_request_t_handler);

    spp_msg_api_set_handler(SPP_API_DS_LITE_CLEAR_DB_REQUEST,
                            spp_api_ds_lite_clear_db_request_t_handler);

    return 0;
}

/*
************************
* spp_api_cnat_get_cgn_db_summary
* This is for finding out the per core CPU users and utilization
************************
*/

void spp_api_cnat_get_cgn_db_summary
(spp_api_cnat_generic_command_request_t *mp)
{
    u32 total_db_entries, total_free_entries, used_entries;
    u32 i = 0;
    cnat_generic_command_resp *mp_resp;
    u32 *result_array;

    /*
     * Request structure is used to send the response
     */
    mp_resp = (cnat_generic_command_resp *) mp;
    result_array = (u32 *) (&(mp_resp->raw_data[0]));

    /*
     * Find entries free and used in main-db
     */
    total_db_entries = vec_len(cnat_main_db);
    total_free_entries = db_free_entry(cnat_main_db);
    used_entries = total_db_entries - total_free_entries;

    *(result_array + i++) = spp_host_to_net_byte_order_32(total_db_entries);
    *(result_array + i++) = spp_host_to_net_byte_order_32(used_entries);
    *(result_array + i++) = spp_host_to_net_byte_order_32(total_free_entries);

    /*
     * Find entries free and used in user-db
     */
    total_db_entries = vec_len(cnat_user_db);
    total_free_entries = db_free_entry(cnat_user_db);
    used_entries = total_db_entries - total_free_entries;

    *(result_array + i++) = spp_host_to_net_byte_order_32(total_db_entries);
    *(result_array + i++) = spp_host_to_net_byte_order_32(used_entries);
    *(result_array + i++) = spp_host_to_net_byte_order_32(total_free_entries);

    mp_resp->num_bytes = spp_host_to_net_byte_order_32(i*sizeof(u32));
}

SPP_INIT_FUNCTION(cnat_debug_init);
#endif /* TOBE_PORTED */
