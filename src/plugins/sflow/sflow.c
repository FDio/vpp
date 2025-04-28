/*
 * Copyright (c) 2024 InMon Corp.
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
#include <vnet/plugin/plugin.h>
#include <sflow/sflow.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

#include <sflow/sflow.api_enum.h>
#include <sflow/sflow.api_types.h>
#include <sflow/sflow_dlapi.h>

#include <vpp-api/client/stat_client.h>
#include <vlib/stats/stats.h>

#define REPLY_MSG_ID_BASE smp->msg_id_base
#include <vlibapi/api_helper_macros.h>

sflow_main_t sflow_main;
vlib_log_class_t sflow_logger;

static void
sflow_stat_segment_client_init (void)
{
  stat_client_main_t *scm = &stat_client_main;
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  uword size;

  size = sm->memory_size ? sm->memory_size : STAT_SEGMENT_DEFAULT_SIZE;
  scm->memory_size = size;
  scm->shared_header = sm->shared_header;
  scm->directory_vector =
    stat_segment_adjust (scm, (void *) scm->shared_header->directory_vector);
}

static void
update_counter_vector_simple (stat_segment_data_t *res,
			      sflow_counters_t *ifCtrs, u32 hw_if_index)
{
  for (int th = 0; th < vec_len (res->simple_counter_vec); th++)
    {
      for (int intf = 0; intf < vec_len (res->simple_counter_vec[th]); intf++)
	{
	  if (intf == hw_if_index)
	    {
	      u64 count = res->simple_counter_vec[th][intf];
	      if (count)
		{
		  if (strcmp (res->name, "/if/rx-error") == 0)
		    ifCtrs->rx.errs += count;
		  else if (strcmp (res->name, "/if/tx-error") == 0)
		    ifCtrs->tx.errs += count;
		  else if (strcmp (res->name, "/if/drops") == 0)
		    ifCtrs->tx.drps += count;
		  else if (strcmp (res->name, "/if/rx-miss") == 0 ||
			   strcmp (res->name, "/if/rx-no-buf") == 0)
		    ifCtrs->rx.drps += count;
		}
	    }
	}
    }
}

static void
update_counter_vector_combined (stat_segment_data_t *res,
				sflow_counters_t *ifCtrs, u32 hw_if_index)
{
  for (int th = 0; th < vec_len (res->simple_counter_vec); th++)
    {
      for (int intf = 0; intf < vec_len (res->combined_counter_vec[th]);
	   intf++)
	{
	  if (intf == hw_if_index)
	    {
	      u64 pkts = res->combined_counter_vec[th][intf].packets;
	      u64 byts = res->combined_counter_vec[th][intf].bytes;
	      if (pkts || byts)
		{
		  if (strcmp (res->name, "/if/rx") == 0)
		    {
		      ifCtrs->rx.pkts += pkts;
		      ifCtrs->rx.byts += byts;
		    }
		  else if (strcmp (res->name, "/if/tx") == 0)
		    {
		      ifCtrs->tx.byts += byts;
		      ifCtrs->tx.pkts += pkts;
		    }
		  // TODO: do multicasts include broadcasts, or are they
		  // counted separately? (test with traffic)
		  else if (strcmp (res->name, "/if/rx-multicast") == 0)
		    ifCtrs->rx.m_pkts += pkts;
		  else if (strcmp (res->name, "/if/tx-multicast") == 0)
		    ifCtrs->tx.m_pkts += pkts;
		  else if (strcmp (res->name, "/if/rx-broadcast") == 0)
		    ifCtrs->rx.b_pkts += pkts;
		  else if (strcmp (res->name, "/if/tx-broadcast") == 0)
		    ifCtrs->tx.b_pkts += pkts;
		}
	    }
	}
    }
}

static int
startsWith (u8 *str, char *prefix)
{
  if (str && prefix)
    {
      int len1 = vec_len (str);
      int len2 = strlen (prefix);
      if (len1 >= len2)
	{
	  return (memcmp (str, prefix, len2) == 0);
	}
    }
  return false;
}

static void
update_counters (sflow_main_t *smp, sflow_per_interface_data_t *sfif)
{
  vnet_sw_interface_t *sw =
    vnet_get_sw_interface (smp->vnet_main, sfif->sw_if_index);
  vnet_hw_interface_t *hw =
    vnet_get_hw_interface (smp->vnet_main, sfif->hw_if_index);
  // This gives us a list of stat integers
  u32 *stats = stat_segment_ls (NULL);
  stat_segment_data_t *res = NULL;
  // read vector of stat_segment_data_t objects
retry:
  res = stat_segment_dump (stats);
  if (res == NULL)
    {
      /* Memory layout has changed */
      if (stats)
	vec_free (stats);
      stats = stat_segment_ls (NULL);
      goto retry;
    }
  sflow_counters_t ifCtrs = {};
  // and accumulate the (per-thread) entries for this interface
  for (int ii = 0; ii < vec_len (res); ii++)
    {
      switch (res[ii].type)
	{
	case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
	  update_counter_vector_simple (&res[ii], &ifCtrs, sfif->hw_if_index);
	  break;
	case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
	  update_counter_vector_combined (&res[ii], &ifCtrs,
					  sfif->hw_if_index);
	  break;
	case STAT_DIR_TYPE_SCALAR_INDEX:
	case STAT_DIR_TYPE_NAME_VECTOR:
	case STAT_DIR_TYPE_EMPTY:
	default:
	  break;
	}
    }
  stat_segment_data_free (res);
  vec_free (stats);
  // send the structure via netlink
  SFLOWUS *ust = &smp->sflow_usersock;
  SFLOWUS_set_msg_type (ust, SFLOW_VPP_MSG_IF_COUNTERS);
  SFLOWUS_set_attr (ust, SFLOW_VPP_ATTR_PORTNAME, hw->name,
		    vec_len (hw->name));
  SFLOWUS_set_attr_int (ust, SFLOW_VPP_ATTR_IFINDEX, sfif->sw_if_index);

  if (smp->lcp_itf_pair_get_vif_index_by_phy)
    {
      sfif->linux_if_index =
	(*smp->lcp_itf_pair_get_vif_index_by_phy) (sfif->sw_if_index);
    }

  if (sfif->linux_if_index != INDEX_INVALID)
    {
      // We know the corresponding Linux ifIndex for this interface, so include
      // that here.
      SFLOWUS_set_attr_int (ust, SFLOW_VPP_ATTR_OSINDEX, sfif->linux_if_index);
    }

  // Report consistent with vpp-snmp-agent
  u64 ifSpeed = (hw->link_speed == ~0) ? 0 : ((u64)hw->link_speed * 1000);
  if (startsWith (hw->name, "loop") || startsWith (hw->name, "tap"))
    ifSpeed = 1e9;

  u32 ifType = startsWith (hw->name, "loop") ? 24 // softwareLoopback
					       :
					       6; // ethernetCsmacd

  u32 ifDirection = (hw->flags & VNET_HW_INTERFACE_FLAG_HALF_DUPLEX) ?
		      2 // half-duplex
		      :
		      1; // full-duplex

  u32 operUp = (hw->flags & VNET_HW_INTERFACE_FLAG_LINK_UP) ? 1 : 0;
  u32 adminUp = (sw->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ? 1 : 0;

  SFLOWUS_set_attr_int (ust, SFLOW_VPP_ATTR_IFSPEED, ifSpeed);
  SFLOWUS_set_attr_int (ust, SFLOW_VPP_ATTR_IFTYPE, ifType);
  SFLOWUS_set_attr_int (ust, SFLOW_VPP_ATTR_IFDIRECTION, ifDirection);
  SFLOWUS_set_attr_int (ust, SFLOW_VPP_ATTR_OPER_UP, operUp);
  SFLOWUS_set_attr_int (ust, SFLOW_VPP_ATTR_ADMIN_UP, adminUp);
  SFLOWUS_set_attr_int (ust, SFLOW_VPP_ATTR_RX_OCTETS, ifCtrs.rx.byts);
  SFLOWUS_set_attr_int (ust, SFLOW_VPP_ATTR_TX_OCTETS, ifCtrs.tx.byts);
  SFLOWUS_set_attr_int (ust, SFLOW_VPP_ATTR_RX_PKTS, ifCtrs.rx.pkts);
  SFLOWUS_set_attr_int (ust, SFLOW_VPP_ATTR_TX_PKTS, ifCtrs.tx.pkts);
  SFLOWUS_set_attr_int (ust, SFLOW_VPP_ATTR_RX_MCASTS, ifCtrs.rx.m_pkts);
  SFLOWUS_set_attr_int (ust, SFLOW_VPP_ATTR_TX_MCASTS, ifCtrs.tx.m_pkts);
  SFLOWUS_set_attr_int (ust, SFLOW_VPP_ATTR_RX_BCASTS, ifCtrs.rx.b_pkts);
  SFLOWUS_set_attr_int (ust, SFLOW_VPP_ATTR_TX_BCASTS, ifCtrs.tx.b_pkts);
  SFLOWUS_set_attr_int (ust, SFLOW_VPP_ATTR_RX_ERRORS, ifCtrs.rx.errs);
  SFLOWUS_set_attr_int (ust, SFLOW_VPP_ATTR_TX_ERRORS, ifCtrs.tx.errs);
  SFLOWUS_set_attr_int (ust, SFLOW_VPP_ATTR_RX_DISCARDS, ifCtrs.rx.drps);
  SFLOWUS_set_attr_int (ust, SFLOW_VPP_ATTR_TX_DISCARDS, ifCtrs.tx.drps);
  SFLOWUS_set_attr (ust, SFLOW_VPP_ATTR_HW_ADDRESS, hw->hw_address,
		    vec_len (hw->hw_address));
  smp->unixsock_seq++;
  SFLOWUS_set_attr_int (ust, SFLOW_VPP_ATTR_SEQ, smp->unixsock_seq);
  if (SFLOWUS_send (ust) < 0)
    smp->csample_send_drops++;
  smp->csample_send++;
}

static u32
total_drops (sflow_main_t *smp)
{
  // sum sendmsg and worker-fifo drops
  u32 all_drops = smp->psample_send_drops;
  for (clib_thread_index_t thread_index = 0; thread_index < smp->total_threads;
       thread_index++)
    {
      sflow_per_thread_data_t *sfwk =
	vec_elt_at_index (smp->per_thread_data, thread_index);
      all_drops += sfwk->drop;
    }
  return all_drops;
}

static void
send_sampling_status_info (sflow_main_t *smp)
{
  SFLOWUS *ust = &smp->sflow_usersock;
  u32 all_pipeline_drops = total_drops (smp);
  SFLOWUS_set_msg_type (ust, SFLOW_VPP_MSG_STATUS);
  SFLOWUS_set_attr_int (ust, SFLOW_VPP_ATTR_UPTIME_S, smp->now_mono_S);
  SFLOWUS_set_attr_int (ust, SFLOW_VPP_ATTR_DROPS, all_pipeline_drops);
  ++smp->unixsock_seq;
  SFLOWUS_set_attr_int (ust, SFLOW_VPP_ATTR_SEQ, smp->unixsock_seq);
  SFLOWUS_send (ust);
}

static int
counter_polling_check (sflow_main_t *smp)
{
  // see if we should poll one or more interfaces
  int polled = 0;
  for (int ii = 0; ii < vec_len (smp->per_interface_data); ii++)
    {
      sflow_per_interface_data_t *sfif =
	vec_elt_at_index (smp->per_interface_data, ii);
      if (sfif && sfif->sflow_enabled &&
	  (sfif->polled == 0 // always send the first time
	   || (smp->now_mono_S % smp->pollingS) ==
		(sfif->hw_if_index % smp->pollingS)))
	{
	  update_counters (smp, sfif);
	  sfif->polled++;
	  polled++;
	}
    }
  return polled;
}

static void
lowercase_and_replace_white (char *str, int len, char replace)
{
  if (str)
    for (int ii = 0; ii < len; ii++)
      {
	if (isspace (str[ii]))
	  str[ii] = replace;
	else
	  str[ii] = tolower (str[ii]);
      }
}

static int
compose_trap_str (char *buf, int buf_len, char *str, int str_len)
{
  int prefix_len = strlen (SFLOW_TRAP_PREFIX);
  int max_cont_len = buf_len - prefix_len - 1;
  int cont_len = (str_len > max_cont_len) ? max_cont_len : str_len;
  clib_memcpy_fast (buf, SFLOW_TRAP_PREFIX, prefix_len);
  clib_memcpy_fast (buf + prefix_len, str, cont_len);
  lowercase_and_replace_white (buf + prefix_len, cont_len, SFLOW_TRAP_WHITE);
  buf[prefix_len + cont_len] = '\0';
  return prefix_len + cont_len;
}

static int
send_packet_sample (vlib_main_t *vm, sflow_main_t *smp, sflow_sample_t *sample)
{
  if (sample->header_bytes > smp->headerB)
    {
      // We get here if header-bytes setting is reduced dynamically
      // and a sample that was in the FIFO appears with a larger
      // header.
      return 0;
    }
  SFLOWPS *pst = &smp->sflow_psample;
  u32 ps_group, seqNo;
  switch (sample->sample_type)
    {
    case SFLOW_SAMPLETYPE_INGRESS:
      ps_group = SFLOW_VPP_PSAMPLE_GROUP_INGRESS;
      seqNo = ++smp->psample_seq_ingress;
      break;
    case SFLOW_SAMPLETYPE_EGRESS:
      ps_group = SFLOW_VPP_PSAMPLE_GROUP_EGRESS;
      seqNo = ++smp->psample_seq_egress;
      break;
    default:
      return 0;
    }
  // TODO: is it always ethernet? (affects ifType counter as well)
  u16 header_protocol = 1; /* ethernet */
  SFLOWPS_set_attr_int (pst, SFLOWPS_PSAMPLE_ATTR_SAMPLE_GROUP, ps_group);
  SFLOWPS_set_attr_int (pst, SFLOWPS_PSAMPLE_ATTR_IIFINDEX,
			sample->input_if_index);
  SFLOWPS_set_attr_int (pst, SFLOWPS_PSAMPLE_ATTR_OIFINDEX,
			sample->output_if_index);
  SFLOWPS_set_attr_int (pst, SFLOWPS_PSAMPLE_ATTR_ORIGSIZE,
			sample->sampled_packet_size);
  SFLOWPS_set_attr_int (pst, SFLOWPS_PSAMPLE_ATTR_GROUP_SEQ, seqNo);
  SFLOWPS_set_attr_int (pst, SFLOWPS_PSAMPLE_ATTR_SAMPLE_RATE,
			sample->samplingN);
  SFLOWPS_set_attr (pst, SFLOWPS_PSAMPLE_ATTR_DATA, sample->header,
		    sample->header_bytes);
  SFLOWPS_set_attr_int (pst, SFLOWPS_PSAMPLE_ATTR_PROTO, header_protocol);
  if (SFLOWPS_send (pst) < 0)
    return -1;
  return 1;
}

static int
send_discard_sample (vlib_main_t *vm, sflow_main_t *smp,
		     sflow_sample_t *sample)
{
  SFLOWDM *dmt = &smp->sflow_dropmon;
  if (sample->header_bytes > smp->headerB)
    {
      // We get here if header-bytes setting is reduced dynamically
      // and a sample that was in the FIFO appears with a larger
      // header.
      return 0;
    }
  if (sample->sample_type != SFLOW_SAMPLETYPE_DISCARD)
    {
      SFLOW_ERR ("send_discard_sample sample-sample_type=%u",
		 sample->sample_type);
      return 0;
    }
  vlib_error_main_t *em = &vm->error_main;
  if (sample->drop_reason >= vec_len (em->counters_heap))
    return 0;
  if (sample->drop_reason >= vec_len (vm->node_main.node_by_error))
    return 0;
  u32 err_node_idx = vm->node_main.node_by_error[sample->drop_reason];
  // Are all the ones we want classed as errors, or might some be WARN or INFO?
  // if (err->severity == VL_COUNTER_SEVERITY_ERROR)
  // set TRAP_GROUP_NAME to "vpp_<node>"
  char trap_grp[SFLOW_MAX_TRAP_LEN];
  char trap[SFLOW_MAX_TRAP_LEN];
  vlib_node_t *n = vlib_get_node (vm, err_node_idx);
  int trap_grp_len = compose_trap_str (trap_grp, SFLOW_MAX_TRAP_LEN,
				       (char *) n->name, vec_len (n->name));
  // set TRAP_NAME to "vpp_<error>"
  vlib_error_desc_t *err = &em->counters_heap[sample->drop_reason];
  int err_name_len = clib_strnlen (err->name, SFLOW_MAX_TRAP_LEN);
  int trap_len =
    compose_trap_str (trap, SFLOW_MAX_TRAP_LEN, err->name, err_name_len);
  // populate the netlink attributes
  u16 origin = NET_DM_ORIGIN_SW;
  SFLOWDM_set_attr_int (dmt, NET_DM_ATTR_ORIGIN, origin);
  // include NUL termination char in netlink strings.
  SFLOWDM_set_attr (dmt, NET_DM_ATTR_HW_TRAP_GROUP_NAME, trap_grp,
		    trap_grp_len + 1);
  SFLOWDM_set_attr (dmt, NET_DM_ATTR_HW_TRAP_NAME, trap, trap_len + 1);
  SFLOWDM_set_attr_int (dmt, NET_DM_ATTR_ORIG_LEN,
			sample->sampled_packet_size);
  SFLOWDM_set_attr_int (dmt, NET_DM_ATTR_TRUNC_LEN, sample->header_bytes);
  // TODO: read from header? (really just needs to be non-zero for hsflowd)
  u16 proto = 0x0800;
  SFLOWDM_set_attr_int (dmt, NET_DM_ATTR_PROTO, proto);
  SFLOWDM_set_attr_int (dmt, NET_DM_ATTR_IN_PORT, sample->input_if_index);
  SFLOWDM_set_attr (dmt, NET_DM_ATTR_PAYLOAD, sample->header,
		    sample->header_bytes);
  if (SFLOWDM_send (dmt) < 0)
    return -1;
  return 1;
}

static u32
read_worker_fifos (vlib_main_t *vm, sflow_main_t *smp)
{
  // Our maximum samples/sec is approximately:
  // (SFLOW_READ_BATCH * smp->total_threads) / SFLOW_POLL_WAIT_S
  // but it may also be affected by SFLOW_FIFO_DEPTH
  // and whether vlib_process_wait_for_event_or_clock() really waits for
  // SFLOW_POLL_WAIT_S every time.
  // If there are too many samples then dropping them as early as possible
  // (and as randomly as possible) is preferred, so SFLOW_FIFO_DEPTH should not
  // be any bigger than it strictly needs to be. If there is a system
  // bottleneck it could be in the PSAMPLE netlink channel, the hsflowd
  // encoder, the UDP stack, the network path, the collector, or a faraway
  // application. Any kind of "clipping" will result in systematic bias so we
  // try to make this fair even when it's running hot. For example, we'll
  // round-robin the thread FIFO dequeues here to make sure we give them equal
  // access to the PSAMPLE channel. Another factor in sizing SFLOW_FIFO_DEPTH
  // is to ensure that we can absorb a short-term line-rate burst without
  // dropping samples. This implies a deeper FIFO. In fact it looks like this
  // requirement ends up being the dominant one. A value of SFLOW_FIFO_DEPTH
  // that will absorb an n-second line-rate burst may well result in the max
  // sustainable samples/sec being higher than we really need. But it's not a
  // serious problem because the samples are packed into UDP datagrams and the
  // network or collector can drop those anywhere they need to. The protocol is
  // designed to be tolerant to random packet-loss in transit. For example, 1%
  // loss should just make it look like the sampling-rate setting was 1:10100
  // instead of 1:10000.
  u32 batch = 0;
  for (; batch < SFLOW_READ_BATCH; batch++)
    {
      u32 psample_found = 0, dropmon_found = 0;
      u32 psample_send = 0, psample_send_fail = 0;
      u32 dropmon_send = 0, dropmon_send_fail = 0;
      for (clib_thread_index_t thread_index = 0;
	   thread_index < smp->total_threads; thread_index++)
	{
	  sflow_per_thread_data_t *sfwk =
	    vec_elt_at_index (smp->per_thread_data, thread_index);
	  sflow_sample_t sample;
	  if (sflow_fifo_dequeue (&sfwk->fifo, &sample))
	    {
	      psample_found++;
	      int sent = send_packet_sample (vm, smp, &sample);
	      if (sent == 1)
		psample_send++;
	      if (sent == -1)
		psample_send_fail++;
	    }
	  if (sflow_drop_fifo_dequeue (&sfwk->drop_fifo, &sample))
	    {
	      dropmon_found++;
	      int sent = send_discard_sample (vm, smp, &sample);
	      if (sent == 1)
		dropmon_send++;
	      if (sent == -1)
		dropmon_send_fail++;
	    }
	}
      if (psample_found == 0 && dropmon_found == 0)
	{
	  // nothing found on FIFOs this time through, so terminate batch early
	  break;
	}
      else
	{
	  if (psample_send > 0)
	    {
	      vlib_node_increment_counter (smp->vlib_main, sflow_node.index,
					   SFLOW_ERROR_PSAMPLE_SEND,
					   psample_send);
	      smp->psample_send += psample_send;
	    }
	  if (psample_send_fail > 0)
	    {
	      vlib_node_increment_counter (smp->vlib_main, sflow_node.index,
					   SFLOW_ERROR_PSAMPLE_SEND_FAIL,
					   psample_send_fail);
	      smp->psample_send_drops += psample_send_fail;
	    }
	  if (dropmon_send > 0)
	    {
	      vlib_node_increment_counter (smp->vlib_main, sflow_node.index,
					   SFLOW_ERROR_DROPMON_SEND,
					   dropmon_send);
	      smp->dropmon_send += dropmon_send;
	    }
	  if (dropmon_send_fail > 0)
	    {
	      vlib_node_increment_counter (smp->vlib_main, sflow_node.index,
					   SFLOW_ERROR_DROPMON_SEND_FAIL,
					   dropmon_send_fail);
	      smp->dropmon_send_drops += dropmon_send_fail;
	    }
	}
    }
  return batch;
}

static void
read_node_counters (sflow_main_t *smp, sflow_err_ctrs_t *ctrs)
{
  for (u32 ec = 0; ec < SFLOW_N_ERROR; ec++)
    ctrs->counters[ec] = 0;
  for (clib_thread_index_t thread_index = 0; thread_index < smp->total_threads;
       thread_index++)
    {
      sflow_per_thread_data_t *sfwk =
	vec_elt_at_index (smp->per_thread_data, thread_index);
      ctrs->counters[SFLOW_ERROR_PROCESSED] += sfwk->pool;
      ctrs->counters[SFLOW_ERROR_SAMPLED] += sfwk->smpl;
      ctrs->counters[SFLOW_ERROR_DROPPED] += sfwk->drop;
      ctrs->counters[SFLOW_ERROR_DIPROCESSED] += sfwk->dsmp;
      ctrs->counters[SFLOW_ERROR_DIDROPPED] += sfwk->ddrp;
    }
}

static void
update_node_cntr (sflow_main_t *smp, sflow_err_ctrs_t *prev,
		  sflow_err_ctrs_t *latest, sflow_error_t ee)
{
  u32 delta = latest->counters[ee] - prev->counters[ee];
  vlib_node_increment_counter (smp->vlib_main, sflow_node.index, ee, delta);
}

static void
update_node_counters (sflow_main_t *smp, sflow_err_ctrs_t *prev,
		      sflow_err_ctrs_t *latest)
{
  // TODO: is it OK to assess all counters against sflow_node or do we
  // need to distinguish sflow_drop_node and sflow_egress_node?
  update_node_cntr (smp, prev, latest, SFLOW_ERROR_PROCESSED);
  update_node_cntr (smp, prev, latest, SFLOW_ERROR_SAMPLED);
  update_node_cntr (smp, prev, latest, SFLOW_ERROR_DROPPED);
  update_node_cntr (smp, prev, latest, SFLOW_ERROR_DIPROCESSED);
  update_node_cntr (smp, prev, latest, SFLOW_ERROR_DIDROPPED);
  *prev = *latest; // latch for next time
}

static uword
sflow_process_samples (vlib_main_t *vm, vlib_node_runtime_t *node,
		       vlib_frame_t *frame)
{
  sflow_main_t *smp = &sflow_main;
  clib_time_t ctm;
  clib_time_init (&ctm);

  sflow_err_ctrs_t prev = {};
  read_node_counters (smp, &prev);

  while (1)
    {

      // We don't have anything for the main loop to edge-trigger on, so
      // we are just asking to be called back regularly.  More regularly
      // if sFlow is actually enabled...
      f64 poll_wait_S = smp->running ? SFLOW_POLL_WAIT_S : 1.0;
      vlib_process_wait_for_event_or_clock (vm, poll_wait_S);
      if (!smp->running)
	{
	  // Nothing to do. Just yield again.
	  continue;
	}

      // PSAMPLE channel may need extra step (e.g. to learn family_id)
      // before it is ready to send
      EnumSFLOWNLState psState = SFLOWPS_state (&smp->sflow_psample);
      if (psState != SFLOWNL_STATE_READY)
	{
	  SFLOWPS_open_step (&smp->sflow_psample);
	}

      // DROPMON channel may need extra step (e.g. to learn family_id)
      // before it is ready to send
      EnumSFLOWNLState dmState = SFLOWDM_state (&smp->sflow_dropmon);
      if (dmState != SFLOWNL_STATE_READY)
	{
	  SFLOWDM_open_step (&smp->sflow_dropmon);
	}

      // What we want is a monotonic, per-second clock. This seems to do it
      // because it is based on the CPU clock.
      f64 tnow = clib_time_now (&ctm);
      u32 tnow_S = (u32) tnow;
      if (tnow_S != smp->now_mono_S)
	{
	  // second rollover
	  smp->now_mono_S = tnow_S;
	  // send status info
	  send_sampling_status_info (smp);
	  // poll counters for interfaces that are due
	  counter_polling_check (smp);
	}
      // process samples from workers
      read_worker_fifos (vm, smp);

      // and sync the global counters
      sflow_err_ctrs_t latest = {};
      read_node_counters (smp, &latest);
      update_node_counters (smp, &prev, &latest);
    }
  return 0;
}

VLIB_REGISTER_NODE (sflow_process_samples_node, static) = {
  .function = sflow_process_samples,
  .name = "sflow-process-samples",
  .type = VLIB_NODE_TYPE_PROCESS,
  .process_log2_n_stack_bytes = 17,
};

static void
sflow_set_worker_sampling_state (sflow_main_t *smp)
{
  /* set up (or reset) sampling context for each thread */
  vlib_thread_main_t *tm = &vlib_thread_main;
  smp->total_threads = 1 + tm->n_threads;
  vec_validate (smp->per_thread_data, smp->total_threads);
  for (clib_thread_index_t thread_index = 0; thread_index < smp->total_threads;
       thread_index++)
    {
      sflow_per_thread_data_t *sfwk =
	vec_elt_at_index (smp->per_thread_data, thread_index);
      if (sfwk->smpN != smp->samplingN)
	{
	  sfwk->smpN = smp->samplingN;
	  sfwk->seed = thread_index;
	  sfwk->skip = sflow_next_random_skip (sfwk);
	  SFLOW_DBG (
	    "sflowset_worker_sampling_state: samplingN=%u thread=%u skip=%u",
	    smp->samplingN, thread_index, sfwk->skip);
	}
    }
}

static void
sflow_sampling_start (sflow_main_t *smp)
{
  SFLOW_INFO ("sflow_sampling_start");

  smp->running = 1;
  // Reset this clock so that the per-second netlink status updates
  // will communicate a restart to hsflowd.  This helps to distinguish:
  // (1) vpp restarted with sFlow off => no status updates (went quiet)
  // (2) vpp restarted with default sFlow => status updates (starting again
  // from 0)
  smp->now_mono_S = 0;

  // reset sequence numbers to indicated discontinuity
  smp->psample_seq_ingress = 0;
  smp->psample_seq_egress = 0;
  smp->psample_send = 0;
  smp->psample_send_drops = 0;
  smp->csample_send = 0;
  smp->csample_send_drops = 0;
  smp->dropmon_send = 0;
  smp->dropmon_send_drops = 0;

  /* open PSAMPLE netlink channel for writing packet samples */
  SFLOWPS_init (&smp->sflow_psample);
  SFLOWPS_open (&smp->sflow_psample);
  /* open USERSOCK netlink channel for writing counters */
  SFLOWUS_init (&smp->sflow_usersock);
  SFLOWUS_open (&smp->sflow_usersock);
  /* open DROPMON netlink channel for writing discard events */
  SFLOWDM_init (&smp->sflow_dropmon);
  SFLOWDM_open (&smp->sflow_dropmon);
  /* set up (or reset) sampling context for each thread */
  sflow_set_worker_sampling_state (smp);
}

static void
sflow_sampling_stop (sflow_main_t *smp)
{
  SFLOW_INFO ("sflow_sampling_stop");
  smp->running = 0;
  SFLOWPS_close (&smp->sflow_psample);
  SFLOWUS_close (&smp->sflow_usersock);
  SFLOWDM_close (&smp->sflow_dropmon);
}

static void
sflow_sampling_start_stop (sflow_main_t *smp)
{
  int run =
    ((smp->samplingN != 0 && smp->interfacesEnabled != 0) || smp->dropM);
  if (run != smp->running)
    {
      if (run)
	sflow_sampling_start (smp);
      else
	sflow_sampling_stop (smp);
    }
}

int
sflow_sampling_rate (sflow_main_t *smp, u32 samplingN)
{
  // TODO: this might be the right place to enforce the
  // "2 significant" figures constraint so that per-interface
  // sampling-rate settings can use HCF+sub-sampling efficiently.

  if (smp->running && smp->samplingN && samplingN)
    {
      // dynamic change of sampling rate
      smp->samplingN = samplingN;
      sflow_set_worker_sampling_state (smp);
    }
  else
    {
      // potential on/off change
      smp->samplingN = samplingN;
      sflow_sampling_start_stop (smp);
    }
  return 0;
}

int
sflow_polling_interval (sflow_main_t *smp, u32 pollingS)
{
  smp->pollingS = pollingS;
  return 0;
}

int
sflow_header_bytes (sflow_main_t *smp, u32 headerB)
{
  u32 hdrB = headerB;
  // first round up to nearest multiple of SFLOW_HEADER_BYTES_STEP
  // (which helps to make worker thread memcpy faster)
  hdrB = ((hdrB + SFLOW_HEADER_BYTES_STEP - 1) / SFLOW_HEADER_BYTES_STEP) *
	 SFLOW_HEADER_BYTES_STEP;
  // then check max/min
  if (hdrB < SFLOW_MIN_HEADER_BYTES)
    hdrB = SFLOW_MIN_HEADER_BYTES;
  if (hdrB > SFLOW_MAX_HEADER_BYTES)
    hdrB = SFLOW_MAX_HEADER_BYTES;
  if (hdrB != headerB)
    SFLOW_WARN ("header_bytes rounded from %u to %u\n", headerB, hdrB);
  smp->headerB = hdrB;
  return 0;
}

void
sflow_enable_disable_interface (sflow_main_t *smp,
				sflow_per_interface_data_t *sfif)
{
  bool ingress_on =
    sfif->sflow_enabled && ((smp->samplingD & SFLOW_DIRN_INGRESS) != 0);
  bool egress_on =
    sfif->sflow_enabled && ((smp->samplingD & SFLOW_DIRN_EGRESS) != 0);
  bool drop_on = sfif->sflow_enabled && smp->dropM;
  bool ingress_enabled = (vnet_feature_is_enabled ("device-input", "sflow",
						   sfif->sw_if_index) == 1);
  bool egress_enabled =
    (vnet_feature_is_enabled ("interface-output", "sflow-egress",
			      sfif->sw_if_index) == 1);
  bool drop_enabled = (vnet_feature_is_enabled ("error-drop", "sflow-drop",
						sfif->sw_if_index) == 1);

  if (ingress_on != ingress_enabled)
    vnet_feature_enable_disable ("device-input", "sflow", sfif->sw_if_index,
				 ingress_on, 0, 0);
  if (egress_on != egress_enabled)
    vnet_feature_enable_disable ("interface-output", "sflow-egress",
				 sfif->sw_if_index, egress_on, 0, 0);
  if (drop_on != drop_enabled)
    vnet_feature_enable_disable ("error-drop", "sflow-drop", sfif->sw_if_index,
				 smp->dropM, 0, 0);
}

void
sflow_enable_disable_all (sflow_main_t *smp)
{
  for (int ii = 0; ii < vec_len (smp->per_interface_data); ii++)
    {
      sflow_per_interface_data_t *sfif =
	vec_elt_at_index (smp->per_interface_data, ii);
      if (sfif && sfif->sflow_enabled)
	sflow_enable_disable_interface (smp, sfif);
    }
}

int
sflow_direction (sflow_main_t *smp, u32 samplingD)
{
  if (samplingD != smp->samplingD)
    {
      // direction changed - tell all active interfaces.
      smp->samplingD = samplingD;
      sflow_enable_disable_all (smp);
    }
  return 0;
}

int
sflow_drop_monitoring (sflow_main_t *smp, u32 dropM)
{
  if (dropM != smp->dropM)
    {
      // drop-monitoring changed.
      smp->dropM = dropM;
      // Tell all active interfaces.
      sflow_enable_disable_all (smp);
    }
  return 0;
}

int
sflow_enable_disable (sflow_main_t *smp, u32 sw_if_index, int enable_disable)
{
  vnet_sw_interface_t *sw;

  /* Utterly wrong? */
  if (pool_is_free_index (smp->vnet_main->interface_main.sw_interfaces,
			  sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (smp->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  // note: vnet_interface_main_t has "fast lookup table" called
  // he_if_index_by_sw_if_index.
  SFLOW_DBG ("sw_if_index=%u, sup_sw_if_index=%u, hw_if_index=%u\n",
	     sw->sw_if_index, sw->sup_sw_if_index, sw->hw_if_index);

  // note: vnet_hw_interface_t has uword *bond_info
  // (where 0=>none, ~0 => slave, other=>ptr to bitmap of slaves)

  vec_validate (smp->per_interface_data, sw->hw_if_index);
  sflow_per_interface_data_t *sfif =
    vec_elt_at_index (smp->per_interface_data, sw->hw_if_index);
  if (enable_disable == sfif->sflow_enabled)
    {
      // redundant enable or disable
      return VNET_API_ERROR_VALUE_EXIST;
    }
  else
    {
      // OK, turn it on/off
      sfif->sw_if_index = sw_if_index;
      sfif->hw_if_index = sw->hw_if_index;
      sfif->polled = 0;
      sfif->sflow_enabled = enable_disable;
      sflow_enable_disable_interface (smp, sfif);
      smp->interfacesEnabled += (enable_disable) ? 1 : -1;
    }

  sflow_sampling_start_stop (smp);
  return 0;
}

static clib_error_t *
sflow_sampling_rate_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  sflow_main_t *smp = &sflow_main;
  u32 sampling_N = ~0;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%u", &sampling_N))
	;
      else
	break;
    }

  if (sampling_N == ~0)
    return clib_error_return (0, "Please specify a sampling rate...");

  rv = sflow_sampling_rate (smp, sampling_N);

  switch (rv)
    {
    case 0:
      break;
    default:
      return clib_error_return (0, "sflow_enable_disable returned %d", rv);
    }
  return 0;
}

static clib_error_t *
sflow_polling_interval_command_fn (vlib_main_t *vm, unformat_input_t *input,
				   vlib_cli_command_t *cmd)
{
  sflow_main_t *smp = &sflow_main;
  u32 polling_S = ~0;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%u", &polling_S))
	;
      else
	break;
    }

  if (polling_S == ~0)
    return clib_error_return (0, "Please specify a polling interval...");

  rv = sflow_polling_interval (smp, polling_S);

  switch (rv)
    {
    case 0:
      break;
    default:
      return clib_error_return (0, "sflow_polling_interval returned %d", rv);
    }
  return 0;
}

static clib_error_t *
sflow_header_bytes_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  sflow_main_t *smp = &sflow_main;
  u32 header_B = ~0;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%u", &header_B))
	;
      else
	break;
    }

  if (header_B == ~0)
    return clib_error_return (0, "Please specify a header bytes limit...");

  rv = sflow_header_bytes (smp, header_B);

  switch (rv)
    {
    case 0:
      break;
    default:
      return clib_error_return (0, "sflow_header_bytes returned %d", rv);
    }
  return 0;
}

static clib_error_t *
sflow_direction_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  sflow_main_t *smp = &sflow_main;
  u32 sampling_D = ~0;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "rx"))
	sampling_D = SFLOW_DIRN_INGRESS;
      else if (unformat (input, "tx"))
	sampling_D = SFLOW_DIRN_EGRESS;
      else if (unformat (input, "both"))
	sampling_D = SFLOW_DIRN_BOTH;
      else
	break;
    }

  if (sampling_D == ~0)
    return clib_error_return (
      0, "Please specify a sampling direction (rx|tx|both)...");

  rv = sflow_direction (smp, sampling_D);

  switch (rv)
    {
    case 0:
      break;
    default:
      return clib_error_return (0, "sflow_direction returned %d", rv);
    }
  return 0;
}

static clib_error_t *
sflow_drop_monitoring_command_fn (vlib_main_t *vm, unformat_input_t *input,
				  vlib_cli_command_t *cmd)
{
  sflow_main_t *smp = &sflow_main;
  u32 drop_M = 1;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	drop_M = 0;
      else if (unformat (input, "enable"))
	drop_M = 1;
      else
	break;
    }

  rv = sflow_drop_monitoring (smp, drop_M);

  switch (rv)
    {
    case 0:
      break;
    default:
      return clib_error_return (0, "sflow_drop_monitoring returned %d", rv);
    }
  return 0;
}

static clib_error_t *
sflow_enable_disable_command_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  sflow_main_t *smp = &sflow_main;
  u32 sw_if_index = ~0;
  int enable_disable = 1;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable_disable = 0;
      else if (unformat (input, "enable"))
	enable_disable = 1;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
			 smp->vnet_main, &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  rv = sflow_enable_disable (smp, sw_if_index, enable_disable);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return (
	0, "Invalid interface, only works on physical ports");
      break;

    case VNET_API_ERROR_UNIMPLEMENTED:
      return clib_error_return (0,
				"Device driver doesn't support redirection");
      break;

    default:
      return clib_error_return (0, "sflow_enable_disable returned %d", rv);
    }
  return 0;
}

static const char *
sflow_direction_str (u32 direction)
{
  switch (direction)
    {
    case SFLOW_DIRN_INGRESS:
      return "rx";
    case SFLOW_DIRN_EGRESS:
      return "tx";
    case SFLOW_DIRN_BOTH:
      return "both";
    }
  return "none";
}

static clib_error_t *
show_sflow_command_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  sflow_main_t *smp = &sflow_main;
  clib_error_t *error = NULL;
  vlib_cli_output (vm, "sflow sampling-rate %u\n", smp->samplingN);
  vlib_cli_output (vm, "sflow direction %s\n",
		   sflow_direction_str (smp->samplingD));
  vlib_cli_output (vm, "sflow polling-interval %u\n", smp->pollingS);
  vlib_cli_output (vm, "sflow header-bytes %u\n", smp->headerB);
  vlib_cli_output (vm, "sflow drop-monitoring %s\n",
		   smp->dropM ? "enable" : "disable");
  u32 itfs_enabled = 0;
  for (int ii = 0; ii < vec_len (smp->per_interface_data); ii++)
    {
      sflow_per_interface_data_t *sfif =
	vec_elt_at_index (smp->per_interface_data, ii);
      if (sfif && sfif->sflow_enabled)
	{
	  itfs_enabled++;
	  vnet_hw_interface_t *hw =
	    vnet_get_hw_interface (smp->vnet_main, sfif->hw_if_index);
	  vlib_cli_output (vm, "sflow enable %s\n", (char *) hw->name);
	}
    }
  vlib_cli_output (vm, "Status\n");
  vlib_cli_output (vm, "  interfaces enabled: %u\n", itfs_enabled);
  vlib_cli_output (vm, "  packet samples sent: %u\n", smp->psample_send);
  vlib_cli_output (vm, "  packet samples dropped: %u\n", total_drops (smp));
  vlib_cli_output (vm, "  counter samples sent: %u\n", smp->csample_send);
  vlib_cli_output (vm, "  counter samples dropped: %u\n",
		   smp->csample_send_drops);
  vlib_cli_output (vm, "  drop samples sent: %u\n", smp->dropmon_send);
  vlib_cli_output (vm, "  drop samples dropped: %u\n",
		   smp->dropmon_send_drops);
  return error;
}

VLIB_CLI_COMMAND (sflow_enable_disable_command, static) = {
  .path = "sflow enable-disable",
  .short_help = "sflow enable-disable <interface-name> [disable]",
  .function = sflow_enable_disable_command_fn,
};

VLIB_CLI_COMMAND (sflow_sampling_rate_command, static) = {
  .path = "sflow sampling-rate",
  .short_help = "sflow sampling-rate <N>",
  .function = sflow_sampling_rate_command_fn,
};

VLIB_CLI_COMMAND (sflow_polling_interval_command, static) = {
  .path = "sflow polling-interval",
  .short_help = "sflow polling-interval <S>",
  .function = sflow_polling_interval_command_fn,
};

VLIB_CLI_COMMAND (sflow_header_bytes_command, static) = {
  .path = "sflow header-bytes",
  .short_help = "sflow header-bytes <B>",
  .function = sflow_header_bytes_command_fn,
};

VLIB_CLI_COMMAND (sflow_direction_command, static) = {
  .path = "sflow direction",
  .short_help = "sflow direction <rx|tx|both>",
  .function = sflow_direction_command_fn,
};

VLIB_CLI_COMMAND (sflow_drop_monitoring_command, static) = {
  .path = "sflow drop-monitoring",
  .short_help = "sflow drop-monitoring <enable|disable>",
  .function = sflow_drop_monitoring_command_fn,
};

VLIB_CLI_COMMAND (show_sflow_command, static) = {
  .path = "show sflow",
  .short_help = "show sflow",
  .function = show_sflow_command_fn,
};

/* API message handler */
static void
vl_api_sflow_enable_disable_t_handler (vl_api_sflow_enable_disable_t *mp)
{
  vl_api_sflow_enable_disable_reply_t *rmp;
  sflow_main_t *smp = &sflow_main;
  int rv;

  rv = sflow_enable_disable (smp, ntohl (mp->hw_if_index),
			     (int) (mp->enable_disable));

  REPLY_MACRO (VL_API_SFLOW_ENABLE_DISABLE_REPLY);
}

static void
vl_api_sflow_sampling_rate_set_t_handler (vl_api_sflow_sampling_rate_set_t *mp)
{
  vl_api_sflow_sampling_rate_set_reply_t *rmp;
  sflow_main_t *smp = &sflow_main;
  int rv;

  rv = sflow_sampling_rate (smp, ntohl (mp->sampling_N));

  REPLY_MACRO (VL_API_SFLOW_SAMPLING_RATE_SET_REPLY);
}

static void
vl_api_sflow_sampling_rate_get_t_handler (vl_api_sflow_sampling_rate_get_t *mp)
{
  vl_api_sflow_sampling_rate_get_reply_t *rmp;
  sflow_main_t *smp = &sflow_main;

  REPLY_MACRO_DETAILS2 (VL_API_SFLOW_SAMPLING_RATE_GET_REPLY,
			({ rmp->sampling_N = ntohl (smp->samplingN); }));
}

static void
vl_api_sflow_polling_interval_set_t_handler (
  vl_api_sflow_polling_interval_set_t *mp)
{
  vl_api_sflow_polling_interval_set_reply_t *rmp;
  sflow_main_t *smp = &sflow_main;
  int rv;

  rv = sflow_polling_interval (smp, ntohl (mp->polling_S));

  REPLY_MACRO (VL_API_SFLOW_POLLING_INTERVAL_SET_REPLY);
}

static void
vl_api_sflow_polling_interval_get_t_handler (
  vl_api_sflow_polling_interval_get_t *mp)
{
  vl_api_sflow_polling_interval_get_reply_t *rmp;
  sflow_main_t *smp = &sflow_main;

  REPLY_MACRO_DETAILS2 (VL_API_SFLOW_POLLING_INTERVAL_GET_REPLY,
			({ rmp->polling_S = ntohl (smp->pollingS); }));
}

static void
vl_api_sflow_header_bytes_set_t_handler (vl_api_sflow_header_bytes_set_t *mp)
{
  vl_api_sflow_header_bytes_set_reply_t *rmp;
  sflow_main_t *smp = &sflow_main;
  int rv;

  rv = sflow_header_bytes (smp, ntohl (mp->header_B));

  REPLY_MACRO (VL_API_SFLOW_HEADER_BYTES_SET_REPLY);
}

static void
vl_api_sflow_header_bytes_get_t_handler (vl_api_sflow_header_bytes_get_t *mp)
{
  vl_api_sflow_header_bytes_get_reply_t *rmp;
  sflow_main_t *smp = &sflow_main;

  REPLY_MACRO_DETAILS2 (VL_API_SFLOW_HEADER_BYTES_GET_REPLY,
			({ rmp->header_B = ntohl (smp->headerB); }));
}

static void
vl_api_sflow_direction_set_t_handler (vl_api_sflow_direction_set_t *mp)
{
  vl_api_sflow_direction_set_reply_t *rmp;
  sflow_main_t *smp = &sflow_main;
  int rv;

  rv = sflow_direction (smp, ntohl (mp->sampling_D));

  REPLY_MACRO (VL_API_SFLOW_DIRECTION_SET_REPLY);
}

static void
vl_api_sflow_direction_get_t_handler (vl_api_sflow_direction_get_t *mp)
{
  vl_api_sflow_direction_get_reply_t *rmp;
  sflow_main_t *smp = &sflow_main;

  REPLY_MACRO_DETAILS2 (VL_API_SFLOW_DIRECTION_GET_REPLY,
			({ rmp->sampling_D = ntohl (smp->samplingD); }));
}

static void
vl_api_sflow_drop_monitoring_set_t_handler (
  vl_api_sflow_drop_monitoring_set_t *mp)
{
  vl_api_sflow_drop_monitoring_set_reply_t *rmp;
  sflow_main_t *smp = &sflow_main;
  int rv;

  rv = sflow_drop_monitoring (smp, ntohl (mp->drop_M));

  REPLY_MACRO (VL_API_SFLOW_DROP_MONITORING_SET_REPLY);
}

static void
vl_api_sflow_drop_monitoring_get_t_handler (
  vl_api_sflow_drop_monitoring_get_t *mp)
{
  vl_api_sflow_drop_monitoring_get_reply_t *rmp;
  sflow_main_t *smp = &sflow_main;

  REPLY_MACRO_DETAILS2 (VL_API_SFLOW_DROP_MONITORING_GET_REPLY,
			({ rmp->drop_M = ntohl (smp->dropM); }));
}

static void
send_sflow_interface_details (vpe_api_main_t *am, vl_api_registration_t *reg,
			      u32 context, const u32 hw_if_index)
{
  vl_api_sflow_interface_details_t *mp;
  sflow_main_t *smp = &sflow_main;

  mp = vl_msg_api_alloc_zero (sizeof (*mp));
  mp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_SFLOW_INTERFACE_DETAILS);
  mp->context = context;

  mp->hw_if_index = htonl (hw_if_index);
  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_sflow_interface_dump_t_handler (vl_api_sflow_interface_dump_t *mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  sflow_main_t *smp = &sflow_main;
  vl_api_registration_t *reg;
  u32 hw_if_index = ~0;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;
  hw_if_index = ntohl (mp->hw_if_index);

  for (int ii = 0; ii < vec_len (smp->per_interface_data); ii++)
    {
      sflow_per_interface_data_t *sfif =
	vec_elt_at_index (smp->per_interface_data, ii);
      if (sfif && sfif->sflow_enabled)
	{
	  if (hw_if_index == ~0 || hw_if_index == sfif->hw_if_index)
	    {
	      send_sflow_interface_details (am, reg, mp->context,
					    sfif->hw_if_index);
	    }
	}
    }
}

/* API definitions */
#include <sflow/sflow.api.c>

static clib_error_t *
sflow_init (vlib_main_t *vm)
{
  sflow_logger = vlib_log_register_class ("sflow", "all");

  sflow_main_t *smp = &sflow_main;
  clib_error_t *error = 0;

  smp->vlib_main = vm;
  smp->vnet_main = vnet_get_main ();

  /* set default sampling-rate and polling-interval so that "enable" is all
   * that is necessary */
  smp->samplingN = SFLOW_DEFAULT_SAMPLING_N;
  smp->pollingS = SFLOW_DEFAULT_POLLING_S;
  smp->headerB = SFLOW_DEFAULT_HEADER_BYTES;
  smp->samplingD = SFLOW_DIRN_INGRESS;
  smp->dropM = false;

  /* Add our API messages to the global name_crc hash table */
  smp->msg_id_base = setup_message_id_table ();

  /* access to counters - TODO: should this only happen on sflow enable? */
  sflow_stat_segment_client_init ();

  smp->lcp_itf_pair_get_vif_index_by_phy =
    vlib_get_plugin_symbol (SFLOW_LCP_LIB, SFLOW_LCP_SYM_GET_VIF_BY_PHY);
  if (smp->lcp_itf_pair_get_vif_index_by_phy)
    {
      SFLOW_NOTICE ("linux-cp found - using LIP vif_index, where available");
    }
  else
    {
      SFLOW_NOTICE ("linux-cp not found - using VPP sw_if_index");
    }

  return error;
}

VLIB_INIT_FUNCTION (sflow_init);

VNET_FEATURE_INIT (sflow, static) = {
  .arc_name = "device-input",
  .node_name = "sflow",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

VNET_FEATURE_INIT (sflow_egress, static) = {
  .arc_name = "interface-output",
  .node_name = "sflow-egress",
  .runs_before = VNET_FEATURES ("interface-output-arc-end"),
};

/* Add myself to the feature arc */
VNET_FEATURE_INIT (sflow_drop, static) = {
  .arc_name = "error-drop",
  .node_name = "sflow-drop",
  .runs_before = VNET_FEATURES ("drop"),
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "sFlow random packet sampling",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
