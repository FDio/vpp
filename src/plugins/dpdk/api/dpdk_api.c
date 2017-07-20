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
#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/bitmap.h>

#include <vnet/ethernet/ethernet.h>
#include <dpdk/device/dpdk.h>
#include <vlib/pci/pci.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <string.h>
#include <fcntl.h>

#include <dpdk/device/dpdk_priv.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <dpdk/api/dpdk_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <dpdk/api/dpdk_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <dpdk/api/dpdk_all_api_h.h>
#undef vl_endianfun

#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)

/* Get the API version number. */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <dpdk/api/dpdk_all_api_h.h>
#undef vl_api_version

/* Macro to finish up custom dump fns */
#define FINISH                                  \
    vec_add1 (s, 0);                            \
    vl_print (handle, (char *)s);               \
    vec_free (s);                               \
    return handle;

#include <vlibapi/api_helper_macros.h>

static void
  vl_api_sw_interface_set_dpdk_hqos_pipe_t_handler
  (vl_api_sw_interface_set_dpdk_hqos_pipe_t * mp)
{
  vl_api_sw_interface_set_dpdk_hqos_pipe_reply_t *rmp;
  int rv = 0;

  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd;

  u32 sw_if_index = ntohl (mp->sw_if_index);
  u32 subport = ntohl (mp->subport);
  u32 pipe = ntohl (mp->pipe);
  u32 profile = ntohl (mp->profile);
  vnet_hw_interface_t *hw;

  VALIDATE_SW_IF_INDEX (mp);

  /* hw_if & dpdk device */
  hw = vnet_get_sup_hw_interface (dm->vnet_main, sw_if_index);

  xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  rv = rte_sched_pipe_config (xd->hqos_ht->hqos, subport, pipe, profile);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_DPDK_HQOS_PIPE_REPLY);
}

static void *vl_api_sw_interface_set_dpdk_hqos_pipe_t_print
  (vl_api_sw_interface_set_dpdk_hqos_pipe_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_set_dpdk_hqos_pipe ");

  s = format (s, "sw_if_index %u ", ntohl (mp->sw_if_index));

  s = format (s, "subport %u  pipe %u  profile %u ",
	      ntohl (mp->subport), ntohl (mp->pipe), ntohl (mp->profile));

  FINISH;
}

static void
  vl_api_sw_interface_set_dpdk_hqos_subport_t_handler
  (vl_api_sw_interface_set_dpdk_hqos_subport_t * mp)
{
  vl_api_sw_interface_set_dpdk_hqos_subport_reply_t *rmp;
  int rv = 0;

  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd;
  struct rte_sched_subport_params p;

  u32 sw_if_index = ntohl (mp->sw_if_index);
  u32 subport = ntohl (mp->subport);
  p.tb_rate = ntohl (mp->tb_rate);
  p.tb_size = ntohl (mp->tb_size);
  p.tc_rate[0] = ntohl (mp->tc_rate[0]);
  p.tc_rate[1] = ntohl (mp->tc_rate[1]);
  p.tc_rate[2] = ntohl (mp->tc_rate[2]);
  p.tc_rate[3] = ntohl (mp->tc_rate[3]);
  p.tc_period = ntohl (mp->tc_period);

  vnet_hw_interface_t *hw;

  VALIDATE_SW_IF_INDEX (mp);

  /* hw_if & dpdk device */
  hw = vnet_get_sup_hw_interface (dm->vnet_main, sw_if_index);

  xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  rv = rte_sched_subport_config (xd->hqos_ht->hqos, subport, &p);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_DPDK_HQOS_SUBPORT_REPLY);
}

static void *vl_api_sw_interface_set_dpdk_hqos_subport_t_print
  (vl_api_sw_interface_set_dpdk_hqos_subport_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_set_dpdk_hqos_subport ");

  s = format (s, "sw_if_index %u ", ntohl (mp->sw_if_index));

  s =
    format (s,
	    "subport %u  rate %u  bkt_size %u  tc0 %u tc1 %u tc2 %u tc3 %u period %u",
	    ntohl (mp->subport), ntohl (mp->tb_rate), ntohl (mp->tb_size),
	    ntohl (mp->tc_rate[0]), ntohl (mp->tc_rate[1]),
	    ntohl (mp->tc_rate[2]), ntohl (mp->tc_rate[3]),
	    ntohl (mp->tc_period));

  FINISH;
}

static void
  vl_api_sw_interface_set_dpdk_hqos_tctbl_t_handler
  (vl_api_sw_interface_set_dpdk_hqos_tctbl_t * mp)
{
  vl_api_sw_interface_set_dpdk_hqos_tctbl_reply_t *rmp;
  int rv = 0;

  dpdk_main_t *dm = &dpdk_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  dpdk_device_t *xd;

  u32 sw_if_index = ntohl (mp->sw_if_index);
  u32 entry = ntohl (mp->entry);
  u32 tc = ntohl (mp->tc);
  u32 queue = ntohl (mp->queue);
  u32 val, i;

  vnet_hw_interface_t *hw;

  VALIDATE_SW_IF_INDEX (mp);

  /* hw_if & dpdk device */
  hw = vnet_get_sup_hw_interface (dm->vnet_main, sw_if_index);

  xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  if (tc >= RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE)
    {
      clib_warning ("invalid traffic class !!");
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }
  if (queue >= RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS)
    {
      clib_warning ("invalid queue !!");
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  /* Detect the set of worker threads */
  uword *p = hash_get_mem (tm->thread_registrations_by_name, "workers");

  if (p == 0)
    {
      clib_warning ("worker thread registration AWOL !!");
      rv = VNET_API_ERROR_INVALID_VALUE_2;
      goto done;
    }

  vlib_thread_registration_t *tr = (vlib_thread_registration_t *) p[0];
  int worker_thread_first = tr->first_index;
  int worker_thread_count = tr->count;

  val = tc * RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS + queue;
  for (i = 0; i < worker_thread_count; i++)
    xd->hqos_wt[worker_thread_first + i].hqos_tc_table[entry] = val;

  BAD_SW_IF_INDEX_LABEL;
done:

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_DPDK_HQOS_TCTBL_REPLY);
}

static void *vl_api_sw_interface_set_dpdk_hqos_tctbl_t_print
  (vl_api_sw_interface_set_dpdk_hqos_tctbl_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: sw_interface_set_dpdk_hqos_tctbl ");

  s = format (s, "sw_if_index %u ", ntohl (mp->sw_if_index));

  s = format (s, "entry %u  tc %u  queue %u",
	      ntohl (mp->entry), ntohl (mp->tc), ntohl (mp->queue));

  FINISH;
}

#define foreach_dpdk_plugin_api_msg                                       \
_(SW_INTERFACE_SET_DPDK_HQOS_PIPE, sw_interface_set_dpdk_hqos_pipe)       \
_(SW_INTERFACE_SET_DPDK_HQOS_SUBPORT, sw_interface_set_dpdk_hqos_subport) \
_(SW_INTERFACE_SET_DPDK_HQOS_TCTBL, sw_interface_set_dpdk_hqos_tctbl)

/* Set up the API message handling tables */
static clib_error_t *
dpdk_plugin_api_hookup (vlib_main_t * vm)
{
  dpdk_main_t *dm __attribute__ ((unused)) = &dpdk_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + dm->msg_id_base),     \
                           #n,          \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_dpdk_plugin_api_msg;
#undef _
  return 0;
}

#define vl_msg_name_crc_list
#include <dpdk/api/dpdk_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (dpdk_main_t * dm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + dm->msg_id_base);
  foreach_vl_msg_name_crc_dpdk;
#undef _
}

//  TODO
/*
static void plugin_custom_dump_configure (dpdk_main_t * dm)
{
#define _(n,f) dm->api_main->msg_print_handlers \
  [VL_API_##n + dm->msg_id_base]                \
    = (void *) vl_api_##f##_t_print;
  foreach_dpdk_plugin_api_msg;
#undef _
}
*/
/* force linker to link functions used by vlib and declared weak */

static clib_error_t *
dpdk_api_init (vlib_main_t * vm)
{
  dpdk_main_t *dm = &dpdk_main;
  clib_error_t *error = 0;

  /* init CLI */
  if ((error = vlib_call_init_function (vm, dpdk_init)))
    return error;

  u8 *name;
  name = format (0, "dpdk_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  dm->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);
  vec_free (name);

  error = dpdk_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (dm, &api_main);

//  TODO
//  plugin_custom_dump_configure (dm);

  return error;
}

VLIB_INIT_FUNCTION (dpdk_api_init);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
