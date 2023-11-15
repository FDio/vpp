/*
 * Copyright (c) 2023 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>

#define __plugin_msg_base onp_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

#include <onp/api/onp.api_enum.h>
#include <onp/api/onp.api_types.h>

/* define message structures */
#define vl_endianfun
#include <plugins/onp/api/onp.api.h>
#undef vl_endianfun

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} onp_test_main_t;

onp_test_main_t onp_test_main;
static const char *ul = "====================================================="
			"=========================";

static int
api_onp_show_counters (vat_main_t *vam)
{
  vl_api_onp_show_counters_t *mp;
  u32 msg_size = sizeof (*mp);
  int ret;

  vam->result_ready = 0;
  mp = vl_msg_api_alloc_as_if_client (msg_size);

  M (ONP_SHOW_COUNTERS, mp);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static void
vl_api_onp_show_counters_reply_t_handler (vl_api_onp_show_counters_reply_t *mp)
{
  vat_main_t *vam = onp_test_main.vat_main;
  u32 thread_idx = 0, cnt_idx;

  if (mp->n_threads_with_stats)
    {

      print (vam->ofp, "%-16s %-40s %-20s", "Thread", "Per-thread counter",
	     "Value");
      print (vam->ofp, "%-.16s %-.40s %-.20s", ul, ul, ul);

      for (thread_idx = 0; thread_idx < mp->n_threads_with_stats; thread_idx++)
	{

	  print (vam->ofp, "%-16s", mp->td[thread_idx].thread_name);
	  for (cnt_idx = 0; cnt_idx < mp->onp_max_counters; cnt_idx++)
	    {
	      if (mp->td[thread_idx].counter_value[cnt_idx])
		print (vam->ofp, "%-16s %-40s %20Ld ", "",
		       mp->cd[cnt_idx].counter_name,
		       clib_net_to_host_u64 (
			 mp->td[thread_idx].counter_value[cnt_idx]));
	    }

	  if (mp->td[thread_idx].pool_stat)
	    print (vam->ofp, "%-16s %-40s %20Ld", "",
		   "default-pool-current-refill-deplete-val",
		   clib_net_to_host_u64 (mp->td[thread_idx].pool_stat));
	}
      print (vam->ofp, "\n");
    }

  if (mp->global_pool_stat || mp->global_second_pool_stat)
    {
      /* Display cumulative counters */
      print (vam->ofp, "%-16s %-40s %-20s", "", "Global counter", "Value");
      print (vam->ofp, "%-16s %-.40s %-.20s", "", ul, ul);

      for (cnt_idx = 0; cnt_idx < mp->onp_max_counters; cnt_idx++)
	{
	  if (mp->global_counter_value[cnt_idx])
	    print (vam->ofp, "%-16s %-40s %20Ld", "",
		   mp->cd[cnt_idx].counter_name,
		   clib_net_to_host_u64 (mp->global_counter_value[cnt_idx]));
	}

      if (mp->global_pool_stat)
	print (vam->ofp, "%-16s %-40s %20Ld", "",
	       "default-pool-current-refill-deplete-val",
	       clib_net_to_host_u64 (mp->global_pool_stat));
    }

  vam->result_ready = 1;
}

#include <onp/api/onp.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
