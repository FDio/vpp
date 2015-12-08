/* 
 *------------------------------------------------------------------
 * cnat_config.c - configuration definitions
 *
 * Copyright (c) 2007-2012 Cisco and/or its affiliates.
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
#include "cnat_config.h"
#include "cnat_cli.h"
#include "cnat_v4_pptp_alg.h"
#include "platform_common.h"

/* session timeout */

u16 tcp_initial_setup_timeout = V4_DEF_TCP_IS_TO;     /* sec */ 
u16 tcp_active_timeout = V4_DEF_TCP_AS_TO;           /* sec */ 
u16 udp_init_session_timeout = V4_DEF_UDP_IS_TO;       /* 30 sec */
u16 udp_act_session_timeout = V4_DEF_UDP_AS_TO;       /* 2 min */
u16 icmp_session_timeout = V4_DEF_ICMP_S_TO;           /* 60 sec */

cnat_pptp_config_t  pptp_cfg = 
    { 
       .enable  = PPTP_DISABLED,
       .timeout = PPTP_GRE_TIMEOUT 
    } ;

/* This flag is used as indication of timeout related config
 * changes and hence db needs to be updated
 */
u8  timeout_dirty_flag = 0;

/* mapping refresh direction, 
 * 1 inbound and outbound refresh 
 */
u8 mapping_refresh_both_direction = V4_DEF_ENABLE;

u16 cnat_main_db_max_ports_per_user = V4_DEF_MAX_PORTS;

u32 cnat_main_db_icmp_rate_limit = DEF_RATE_LIMIT;
u32 cnat_main_db_icmp_rate_limit_core = DEF_RATE_LIMIT_CORE;
u32 crc_zero_udp_rate_limit_core = RATE_LIMIT_UDP_CORE;
u16 cnat_static_port_range = CNAT_DEF_STATIC_PORT_RANGE;


/*
 * ftp alg enable
 */
u8 ftp_alg_enabled = V4_DEF_DISABLE;
u16 rtsp_alg_port_num = 0;

/*
 * load balancing debug mode
 */
u8 lb_debug_enable = V4_DEF_DISABLE;


/* good or evil mode 
 * 0 endpoint-independnet filter, good mode
 * 1 address depedent filter, evil mode
 */
u8 address_dependent_filtering = V4_DEF_DISABLE;

u16 per_user_icmp_msg_limit = ICMP_MSG_RATE_LIMIT;

u16 config_delete_timeout = V4_CONFIG_DELETE_TO;

