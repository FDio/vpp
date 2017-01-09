/*
 *------------------------------------------------------------------
 * dpdk_api.c - dpdk interface api
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vlibmemory/api.h>

#if DPDK > 0
#include <vnet/devices/dpdk/dpdk.h>
#endif

#include <vnet/vnet_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vnet/vnet_all_api_h.h>
#undef vl_printfun

#include <vlibapi/api_helper_macros.h>

#define foreach_vpe_api_msg                                               \
_(SW_INTERFACE_SET_DPDK_HQOS_PIPE, sw_interface_set_dpdk_hqos_pipe)       \
_(SW_INTERFACE_SET_DPDK_HQOS_SUBPORT, sw_interface_set_dpdk_hqos_subport) \
_(SW_INTERFACE_SET_DPDK_HQOS_TCTBL, sw_interface_set_dpdk_hqos_tctbl)

static void
  vl_api_sw_interface_set_dpdk_hqos_pipe_t_handler
  (vl_api_sw_interface_set_dpdk_hqos_pipe_t * mp)
{
  vl_api_sw_interface_set_dpdk_hqos_pipe_reply_t *rmp;
  int rv = 0;

#if DPDK > 0
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
#else
  clib_warning ("setting HQoS pipe parameters without DPDK not implemented");
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif /* DPDK */

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_DPDK_HQOS_PIPE_REPLY);
}

static void
  vl_api_sw_interface_set_dpdk_hqos_subport_t_handler
  (vl_api_sw_interface_set_dpdk_hqos_subport_t * mp)
{
  vl_api_sw_interface_set_dpdk_hqos_subport_reply_t *rmp;
  int rv = 0;

#if DPDK > 0
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
#else
  clib_warning
    ("setting HQoS subport parameters without DPDK not implemented");
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif /* DPDK */

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_DPDK_HQOS_SUBPORT_REPLY);
}

static void
  vl_api_sw_interface_set_dpdk_hqos_tctbl_t_handler
  (vl_api_sw_interface_set_dpdk_hqos_tctbl_t * mp)
{
  vl_api_sw_interface_set_dpdk_hqos_tctbl_reply_t *rmp;
  int rv = 0;

#if DPDK > 0
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
#else
  clib_warning ("setting HQoS DSCP table entry without DPDK not implemented");
  rv = VNET_API_ERROR_UNIMPLEMENTED;
#endif /* DPDK */

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_DPDK_HQOS_TCTBL_REPLY);
}

/*
 * dpdk_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has alread mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */
#define vl_msg_name_crc_list
#include <vnet/vnet_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_dpdk;
#undef _
}

static clib_error_t *
dpdk_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (dpdk_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
