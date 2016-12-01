/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#ifndef PLUGINS_IOAM_PLUGIN_IOAM_ANALYSE_IP6_IOAM_ANALYSE_NODE_H_
#define PLUGINS_IOAM_PLUGIN_IOAM_ANALYSE_IP6_IOAM_ANALYSE_NODE_H_

#include <ioam/analyse/ioam_analyse.h>
#include <vnet/ip/ip6_hop_by_hop.h>

/** @brief IP6-iOAM analyser main structure.
    @note cache aligned.
*/
typedef struct
{
  /** Array of function pointer to analyse each hop-by-hop option. */
  int (*analyse_hbh_handler[MAX_IP6_HBH_OPTION]) (u32 flow_id,
						  ip6_hop_by_hop_option_t *
						  opt, u16 len);

  /** This contains the aggregated data from the time VPP started analysing. */
  ioam_analyser_data_t *aggregated_data;

} ip6_ioam_analyser_main_t;

extern ip6_ioam_analyser_main_t ioam_analyser_main;

extern vlib_node_registration_t analyse_node_local;
extern vlib_node_registration_t analyse_node_remote;

void ip6_ioam_analyse_register_handlers (void);

void ip6_ioam_analyse_unregister_handlers (void);

clib_error_t *ip6_ioam_analyse_init (vlib_main_t * vm);

inline static ioam_analyser_data_t *
ioam_analyse_get_data_from_flow_id (u32 flow_id)
{
  if (flow_id >= vec_len (ioam_analyser_main.aggregated_data))
    return NULL;

  if (ioam_analyser_main.aggregated_data[flow_id].is_free)
    ioam_analyser_main.aggregated_data[flow_id].is_free = 0;

  return (ioam_analyser_main.aggregated_data + flow_id);
}

#endif /* PLUGINS_IOAM_PLUGIN_IOAM_ANALYSE_IP6_IOAM_ANALYSE_NODE_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
