/*
 * Copyright (c) 2023 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <stddef.h>

#include <vnet/vnet.h>
#include <vpp/app/version.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <onp/onp.h>

/* Define generated endian-swappers */
#define vl_endianfun
#include <plugins/onp/api/onp.api_enum.h>
#include <plugins/onp/api/onp.api_types.h>
#undef vl_endianfun

/* Instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)

/**
 * Base message ID for the plugin
 */
static u32 onp_base_msg_id;

#include <vlibapi/api_helper_macros.h>

#define mp_be_to_cpu(x, bits)                                                 \
  do                                                                          \
    {                                                                         \
      if ((bits) == 16)                                                       \
	x = clib_net_to_host_u16 (x);                                         \
      if ((bits) == 32)                                                       \
	x = clib_net_to_host_u32 (x);                                         \
      if ((bits) == 64)                                                       \
	x = clib_net_to_host_u64 (x);                                         \
    }                                                                         \
  while (0)

#define ONP_MP_ENDIAN_MACRO(api, body)                                        \
  do                                                                          \
    {                                                                         \
      body;                                                                   \
    }                                                                         \
  while (0)

#define mp_cpu_to_be(x, bits)                                                 \
  do                                                                          \
    {                                                                         \
      if ((bits) == 16)                                                       \
	x = clib_host_to_net_u16 (x);                                         \
      if ((bits) == 32)                                                       \
	x = clib_host_to_net_u32 (x);                                         \
      if ((bits) == 64)                                                       \
	x = clib_host_to_net_u64 (x);                                         \
    }                                                                         \
  while (0)

#define ONP_REPLY_MACRO(t, api, body)                                         \
  do                                                                          \
    {                                                                         \
      vl_api_##api##_reply_t *reply;                                          \
      vl_api_registration_t *rp;                                              \
                                                                              \
      /* Send response message back */                                        \
      rp = vl_api_client_index_to_registration (mp->client_index);            \
      if (rp == 0)                                                            \
	return;                                                               \
                                                                              \
      reply = vl_msg_api_alloc (sizeof (*reply));                             \
      if (!reply)                                                             \
	return;                                                               \
                                                                              \
      memset (reply, 0, sizeof (vl_api_##api##_reply_t));                     \
      reply->_vl_msg_id = clib_host_to_net_u16 ((t) + onp_base_msg_id);       \
      reply->context = mp->context;                                           \
      do                                                                      \
	{                                                                     \
	  body;                                                               \
	}                                                                     \
      while (0);                                                              \
      reply->retval = clib_host_to_net_u32 (rv);                              \
      vl_api_send_msg (rp, (u8 *) reply);                                     \
    }                                                                         \
  while (0)

static void
onp_update_per_thread_stats (u64 **stat, u64 *pool_stat, u32 n_threads,
			     u8 *is_valid, u64 *threads_with_stats,
			     unsigned int n_threads_with_stats,
			     vl_api_onp_show_counters_reply_t *reply)
{
  onp_main_t *om = onp_get_main ();
  vlib_simple_counter_main_t *cm;
  u32 idx, thread_idx = 0;

  for (idx = 0; idx < n_threads_with_stats; idx++)
    {

      thread_idx = threads_with_stats[idx];
      clib_memcpy (reply->td[thread_idx].thread_name,
		   vlib_worker_threads[thread_idx].name,
		   sizeof (reply->td[thread_idx].thread_name));

      /* clang-format off */
#define _(i, s, n, v)                                                 \
      cm = &om->onp_counters.s##_counters;                            \
      clib_memcpy (reply->cd[i].counter_name, cm->name,               \
                   sizeof (reply->cd[i].counter_name));               \
      if (is_valid[i] && stat[i][thread_idx])                         \
        reply->td[thread_idx].counter_value[i] = stat[i][thread_idx];
      foreach_onp_counters;
#undef _
      /* clang-format on */

      if (pool_stat[thread_idx])
	reply->td[thread_idx].pool_stat = pool_stat[thread_idx];
    }
}

static void
vl_api_onp_show_counters_t_handler (vl_api_onp_show_counters_t *mp)
{
  u32 cnt_idx = 0, thread_idx = 0, n_threads_with_stats = 0;
  u32 n_threads = vlib_get_n_threads ();
  u8 is_valid[ONP_MAX_COUNTERS] = { 0 };
  u64 *stat[ONP_MAX_COUNTERS] = { 0 };
  u64 threads_with_stats[n_threads];
  onp_main_t *om = onp_get_main ();
  vlib_simple_counter_main_t *cm;
  counter_t *counters = NULL;
  u64 *pool_stat = NULL;
  u8 verbose = 0;
  int rv = 0;

  /* clang-format off */
  ONP_MP_ENDIAN_MACRO(onp_show_counters, ({
   /*
    * All fields required to be used from API msg needs
    * to be called as shown below. They will be converted
    * to host-endian format before usage in the handler
    * when called in binary API mode.
    *
    * mp_be_to_cpu(mp->field16, 16);
    * mp_be_to_cpu(mp->field32, 32);
    * mp_be_to_cpu(mp->field64, 64);
    */
  }));

#define _(i, s, n, v)                                                         \
  cm = &om->onp_counters.s##_counters;                                        \
  vec_validate_init_empty (stat[i], n_threads, 0);                            \
  for (thread_idx = 0; thread_idx < n_threads; thread_idx++)                  \
    {                                                                         \
      counters = cm->counters[thread_idx];                                    \
      stat[i][thread_idx] = counters[0];                                      \
    }
  foreach_onp_counters;
#undef _
  /* clang-format on */

  vec_validate_init_empty (pool_stat, n_threads, 0);

  n_threads_with_stats = onp_get_per_thread_stats (
    stat, pool_stat, n_threads, verbose, is_valid, threads_with_stats);

  /* clang-format off */
  /*
   * NOTE: Updates to reply field MUST be done only inside
   * this macro body.
   */

  ONP_REPLY_MACRO(VL_API_ONP_SHOW_COUNTERS_REPLY, onp_show_counters, ({

    reply->n_threads_with_stats = n_threads_with_stats;
    reply->onp_max_counters = ONP_MAX_COUNTERS;
    onp_update_per_thread_stats (stat, pool_stat, n_threads,
				 is_valid, threads_with_stats,
				 n_threads_with_stats, reply);
    for (thread_idx = 0; thread_idx < n_threads; thread_idx++)
      {
	for (cnt_idx = 0; cnt_idx < ONP_MAX_COUNTERS; cnt_idx++)
	  {
	    reply->global_counter_value[cnt_idx] += stat[cnt_idx][thread_idx];
	    reply->n_global_stats++;
	    mp_cpu_to_be (reply->td[thread_idx].counter_value[cnt_idx], 64);
	  }

	reply->global_pool_stat += pool_stat[thread_idx];
	mp_cpu_to_be (reply->td[thread_idx].pool_stat, 64);
      }

    for (cnt_idx = 0; cnt_idx < ONP_MAX_COUNTERS; cnt_idx++)
    mp_cpu_to_be (reply->global_counter_value[cnt_idx], 64);

    mp_cpu_to_be (reply->global_pool_stat, 64);

  }));

  /* clang-format on */

  for (cnt_idx = 0; cnt_idx < ONP_MAX_COUNTERS; cnt_idx++)
    vec_free (stat[cnt_idx]);

  vec_free (pool_stat);
}

#include <onp/api/onp.api.c>

static clib_error_t *
onp_api_init (vlib_main_t *vm)
{
  /* Add our API messages to the global name_crc hash table */
  onp_base_msg_id = setup_message_id_table ();

  return NULL;
}

VLIB_INIT_FUNCTION (onp_api_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
