#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/session/session.h>
#include <vnet/session/segment_manager.h>
#include <vnet/session/application.h>

#define SEG_MGR_TEST_I(_cond, _comment, _args...)               \
({                                                              \
  int _evald = (_cond);                                         \
  if (!(_evald)) {                                              \
    fformat(stderr, "FAIL:%d: " _comment "\n",                  \
            __LINE__, ##_args);                                 \
  } else {                                                      \
    fformat(stderr, "PASS:%d: " _comment "\n",                  \
            __LINE__, ##_args);                                 \
  }                                                             \
  _evald;                                                       \
})

#define SEG_MGR_TEST(_cond, _comment, _args...)                 \
{                                                               \
    if (!SEG_MGR_TEST_I(_cond, _comment, ##_args)) {            \
        return 1;                                               \
    }                                                           \
}

#define ST_DBG(_comment, _args...)                              \
    fformat(stderr,  _comment "\n",  ##_args);                  \

#define SEGMENT_MANAGER_GET_INDEX_FROM_HANDLE(x) (x >> 32)

/* dummy callback functions */
static void
dummy_session_reset_callback (session_t * s)
{
  clib_warning ("called...");
}

static int
dummy_session_connected_callback (u32 app_index, u32 api_context,
				  session_t * s, u8 is_fail)
{
  clib_warning ("called...");
  return 0;
}

static int
dummy_add_segment_callback (u32 client_index, u64 segment_handle)
{
  clib_warning ("called...");
  return 0;
}

static int
dummy_del_segment_callback (u32 client_index, u64 segment_handle)
{
  clib_warning ("called...");
  return 0;
}

static void
dummy_session_disconnect_callback (session_t * s)
{
  clib_warning ("called...");
}

static int
dummy_session_accept_callback (session_t * s)
{
  clib_warning ("called...");
  return 0;
}

static int
dummy_server_rx_callback (session_t * s)
{
  clib_warning ("called...");
  return -1;
}

/* *INDENT-OFF* */
static session_cb_vft_t dummy_session_cbs = {
  .session_reset_callback = dummy_session_reset_callback,
  .session_connected_callback = dummy_session_connected_callback,
  .session_accept_callback = dummy_session_accept_callback,
  .session_disconnect_callback = dummy_session_disconnect_callback,
  .builtin_app_rx_callback = dummy_server_rx_callback,
  .add_segment_callback = dummy_add_segment_callback,
  .del_segment_callback = dummy_del_segment_callback,
};
/* *INDENT-ON* */


const char *
states_str (int state)
{
  switch (state)
    {
    case MEM_PRESSURE_NO_PRESSURE:
      return "NO_PRESSURE";
      break;
    case MEM_PRESSURE_LOW_PRESSURE:
      return "LOW_PRESSURE";
      break;
    case MEM_PRESSURE_HIGH_PRESSURE:
      return "HIGH_PRESSURE";
      break;
    case MEM_PRESSURE_NO_MEMORY:
      return "NO_MEMORY";
      break;
    default:
      return "INVALID STATUS CODE";
      break;
    }
}

static inline u32
fs_freelist_for_size (u32 size)
{
  return max_log2 (size) - FIFO_SEGMENT_MIN_LOG2_FIFO_SIZE;
}

static inline u32
fs_freelist_index_to_size (u32 fl_index)
{
  return 1 << (fl_index + FIFO_SEGMENT_MIN_LOG2_FIFO_SIZE);
}

static u32 size_4KB = 4 << 10;
static u32 size_128KB = 128 << 10;
static u32 size_2MB = 2 << 20;
static uword size_2GB = 2UL << 30;



static int
fifo_tuning_logic_test_basic (vlib_main_t * vm, unformat_input_t * input)
{
  int rv;
  segment_manager_t *sm;
  uword app_seg_size = size_2GB;
  u64 options[APP_OPTIONS_N_OPTIONS];

  memset (&options, 0, sizeof (options));

  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &dummy_session_cbs,
    .name = format (0, "fifo_tuning_logic_test_basic"),
  };

  attach_args.options[APP_OPTIONS_SEGMENT_SIZE] = app_seg_size;
  attach_args.options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  rv = vnet_application_attach (&attach_args);
  SEG_MGR_TEST ((rv == 0), "vnet_application_attach %d", rv);

  sm =
    segment_manager_get (SEGMENT_MANAGER_GET_INDEX_FROM_HANDLE
			 (attach_args.segment_handle));
  SEG_MGR_TEST ((sm != 0), "segment_manager_get %p", sm);

  SEG_MGR_TEST ((sm->allocated >= app_seg_size), "sm->allocated %llu",
		sm->allocated);
  SEG_MGR_TEST ((sm->high_watermark == 80), "sm->high_watermark %d",
		sm->high_watermark);
  SEG_MGR_TEST ((sm->low_watermark == 50), "sm->low_watermark %d",
		sm->low_watermark);

  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_NO_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));

  vnet_app_detach_args_t detach_args = {
    .app_index = attach_args.app_index,
    .api_client_index = ~0,
  };
  rv = vnet_application_detach (&detach_args);
  SEG_MGR_TEST ((rv == 0), "vnet_application_detach %d", rv);

  return 0;
}

static int
fifo_tuning_logic_test_pressure_1 (vlib_main_t * vm, unformat_input_t * input)
{
  int rv;
  segment_manager_t *sm;
  svm_fifo_t *rx_fifo, *tx_fifo;
  uword app_seg_size = size_2MB;
  u32 fifo_size = size_128KB;
  u64 options[APP_OPTIONS_N_OPTIONS];

  memset (&options, 0, sizeof (options));

  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &dummy_session_cbs,
    .name = format (0, "fifo_tuning_logic_test_pressure_1"),
  };

  attach_args.options[APP_OPTIONS_SEGMENT_SIZE] = app_seg_size;
  attach_args.options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  attach_args.options[APP_OPTIONS_RX_FIFO_SIZE] = fifo_size;
  attach_args.options[APP_OPTIONS_TX_FIFO_SIZE] = fifo_size;
  rv = vnet_application_attach (&attach_args);
  SEG_MGR_TEST ((rv == 0), "vnet_application_attach %d", rv);

  sm =
    segment_manager_get (SEGMENT_MANAGER_GET_INDEX_FROM_HANDLE
			 (attach_args.segment_handle));
  SEG_MGR_TEST ((sm != 0), "segment_manager_get %p", sm);

  SEG_MGR_TEST ((sm->allocated >= app_seg_size), "sm->allocated %llu",
		sm->allocated);

  /* initial status : (0 / 2MB) */
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_NO_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));


  /* allocate a fifo : 128KB x2 */
  rv = segment_manager_alloc_session_fifos (sm,
					    vlib_get_thread_index (),
					    &rx_fifo, &tx_fifo);
  SEG_MGR_TEST ((rv == 0), "segment_manager_alloc_session_fifos %d", rv);

  svm_fifo_set_single_thread_owned (rx_fifo);
  svm_fifo_set_single_thread_owned (tx_fifo);


  /* 256KB+ / 2048KB+ => ~12% */
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_NO_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));

  /* note:
   * in this test, we just grow and shrink the fifos.
   * there's no actual enqueue/dequeue.
   * the condition for shrink depends on the head/tail position
   * (and also the existence of the end_chunk != start_chunk
   */

  /* grow fifo */
  segment_manager_grow_fifo (sm, rx_fifo, fifo_size);
  segment_manager_grow_fifo (sm, rx_fifo, fifo_size);
  segment_manager_grow_fifo (sm, rx_fifo, fifo_size);
  segment_manager_grow_fifo (sm, tx_fifo, fifo_size);
  segment_manager_grow_fifo (sm, tx_fifo, fifo_size);
  segment_manager_grow_fifo (sm, tx_fifo, fifo_size);

  /* 1024KB+ / 2048KB+ =>  a bit smaller than 50% */
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_NO_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));

  /* grow fifos */
  segment_manager_grow_fifo (sm, rx_fifo, fifo_size);
  segment_manager_grow_fifo (sm, tx_fifo, fifo_size);

  /* 1280KB+ / 2048KB+ => ~62% */
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_LOW_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));

  /* grow fifos */
  segment_manager_grow_fifo (sm, rx_fifo, fifo_size);
  segment_manager_grow_fifo (sm, rx_fifo, fifo_size);
  segment_manager_grow_fifo (sm, tx_fifo, fifo_size);
  segment_manager_grow_fifo (sm, tx_fifo, fifo_size);

  /* 1792KB+ / 2048KB+ => ~87% */
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_HIGH_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));


  /* shrink fifos */
  segment_manager_shrink_fifo (sm, rx_fifo, fifo_size, 1);
  segment_manager_shrink_fifo (sm, rx_fifo, fifo_size, 1);
  segment_manager_shrink_fifo (sm, tx_fifo, fifo_size, 1);
  segment_manager_shrink_fifo (sm, tx_fifo, fifo_size, 1);

  /* 1280KB+ / 2048KB+ => ~62% */
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_LOW_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));


  /* grow fifos */
  segment_manager_grow_fifo (sm, rx_fifo, fifo_size);
  segment_manager_grow_fifo (sm, rx_fifo, fifo_size);
  segment_manager_grow_fifo (sm, tx_fifo, fifo_size);
  segment_manager_grow_fifo (sm, tx_fifo, fifo_size);

  /* 1792KB+ / 2048KB+ => ~87% */
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_HIGH_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));

  segment_manager_shrink_fifo (sm, rx_fifo, fifo_size, 1);
  segment_manager_shrink_fifo (sm, rx_fifo, fifo_size, 1);
  segment_manager_shrink_fifo (sm, tx_fifo, fifo_size, 1);
  segment_manager_shrink_fifo (sm, tx_fifo, fifo_size, 1);


  /* 1280KB+ / 2048KB+ => ~62% */
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_LOW_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));

  /* shrink fifos */
  segment_manager_shrink_fifo (sm, rx_fifo, fifo_size, 1);
  segment_manager_shrink_fifo (sm, rx_fifo, fifo_size, 1);
  segment_manager_shrink_fifo (sm, rx_fifo, fifo_size, 1);
  segment_manager_shrink_fifo (sm, rx_fifo, fifo_size, 1);
  segment_manager_shrink_fifo (sm, tx_fifo, fifo_size, 1);
  segment_manager_shrink_fifo (sm, tx_fifo, fifo_size, 1);
  segment_manager_shrink_fifo (sm, tx_fifo, fifo_size, 1);
  segment_manager_shrink_fifo (sm, tx_fifo, fifo_size, 1);

  /* 256KB+ / 2048KB+ => ~12% */
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_NO_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));


  vnet_app_detach_args_t detach_args = {
    .app_index = attach_args.app_index,
    .api_client_index = ~0,
  };
  rv = vnet_application_detach (&detach_args);
  SEG_MGR_TEST ((rv == 0), "vnet_application_detach %d", rv);

  return 0;
}

static int
fifo_tuning_logic_test_pressure_2 (vlib_main_t * vm, unformat_input_t * input)
{
  int rv, i;
  segment_manager_t *sm;
  svm_fifo_t *rx_fifo, *tx_fifo;
  uword app_seg_size = size_2MB;
  u32 fifo_size = size_4KB;
  u64 options[APP_OPTIONS_N_OPTIONS];

  memset (&options, 0, sizeof (options));

  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &dummy_session_cbs,
    .name = format (0, "fifo_tuning_logic_test_pressure_1"),
  };

  attach_args.options[APP_OPTIONS_SEGMENT_SIZE] = app_seg_size;
  attach_args.options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  attach_args.options[APP_OPTIONS_RX_FIFO_SIZE] = fifo_size;
  attach_args.options[APP_OPTIONS_TX_FIFO_SIZE] = fifo_size;
  rv = vnet_application_attach (&attach_args);
  SEG_MGR_TEST ((rv == 0), "vnet_application_attach %d", rv);

  sm =
    segment_manager_get (SEGMENT_MANAGER_GET_INDEX_FROM_HANDLE
			 (attach_args.segment_handle));
  SEG_MGR_TEST ((sm != 0), "segment_manager_get %p", sm);

  SEG_MGR_TEST ((sm->allocated >= app_seg_size), "sm->allocated %llu",
		sm->allocated);

  /* initial status : (0 / 2MB) */
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_NO_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));


  /* allocate fifos : 4KB x2 */
  rv = segment_manager_alloc_session_fifos (sm,
					    vlib_get_thread_index (),
					    &rx_fifo, &tx_fifo);
  SEG_MGR_TEST ((rv == 0), "segment_manager_alloc_session_fifos %d", rv);

  /* grow fifos */
  for (i = 0; i < 501; ++i)
    {
      segment_manager_grow_fifo (sm, rx_fifo, fifo_size);
    }

  /* 503 chunks : 2012KB is 98% of 2MB */
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_HIGH_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));

  /* this fifo growth is expected fail */
  rv = segment_manager_grow_fifo (sm, rx_fifo, fifo_size);
  SEG_MGR_TEST ((rv != 0), "segment_manager_grow_fifo %d", rv);

  /* then, no-memory is detected */
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_NO_MEMORY),
		"segment_manager_get_mem_status %s", states_str (rv));

  /* shrink fifos */
  for (i = 0; i < 10; ++i)
    {
      segment_manager_shrink_fifo (sm, rx_fifo, fifo_size, 1);
    }

  /* 491 chunks : 1972KB is 96%, it is high-pressure level
   * but the reached-mem-limit record is not reset
   * so the no-memory state lasts.
   */
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_NO_MEMORY),
		"segment_manager_get_mem_status %s", states_str (rv));

  /* shrink fifos */
  for (i = 0; i < 133; ++i)
    {
      segment_manager_shrink_fifo (sm, rx_fifo, fifo_size, 1);
    }

  /* 358 chunks : 1432KB is 70% of 2MB */
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_LOW_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));

  /* shrink fifos */
  for (i = 0; i < 356; ++i)
    {
      segment_manager_shrink_fifo (sm, rx_fifo, fifo_size, 1);
    }

  /* 8KB is 1% of 2MB */
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_NO_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));


  vnet_app_detach_args_t detach_args = {
    .app_index = attach_args.app_index,
    .api_client_index = ~0,
  };
  rv = vnet_application_detach (&detach_args);
  SEG_MGR_TEST ((rv == 0), "vnet_application_detach %d", rv);

  return 0;
}

static int
fifo_tuning_logic_test_fifo_balanced_alloc (vlib_main_t * vm,
					    unformat_input_t * input)
{
  int rv, i, fs_index;
  segment_manager_t *sm;
  svm_fifo_t *rx_fifo[4], *tx_fifo[4];
  uword app_seg_size = size_2MB;
  u32 fifo_size = size_4KB;
  u64 options[APP_OPTIONS_N_OPTIONS];

  memset (&options, 0, sizeof (options));

  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &dummy_session_cbs,
    .name = format (0, "fifo_tuning_logic_test_pressure_1"),
  };

  attach_args.options[APP_OPTIONS_SEGMENT_SIZE] = app_seg_size;
  attach_args.options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  attach_args.options[APP_OPTIONS_RX_FIFO_SIZE] = fifo_size;
  attach_args.options[APP_OPTIONS_TX_FIFO_SIZE] = fifo_size;
  rv = vnet_application_attach (&attach_args);
  SEG_MGR_TEST ((rv == 0), "vnet_application_attach %d", rv);

  sm =
    segment_manager_get (SEGMENT_MANAGER_GET_INDEX_FROM_HANDLE
			 (attach_args.segment_handle));
  SEG_MGR_TEST ((sm != 0), "segment_manager_get %p", sm);

  SEG_MGR_TEST ((sm->allocated >= app_seg_size), "sm->allocated %llu",
		sm->allocated);

  /* initial status : (0 / 2MB) */
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_NO_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));

  /* allocate fifos : 4KB x2 */
  rv = segment_manager_alloc_session_fifos (sm,
					    vlib_get_thread_index (),
					    &rx_fifo[0], &tx_fifo[0]);
  SEG_MGR_TEST ((rv == 0), "segment_manager_alloc_session_fifos %d", rv);
  SEG_MGR_TEST ((rx_fifo[0]->segment_index == 0),
		"segment_index %d", rx_fifo[0]->segment_index);
  SEG_MGR_TEST ((tx_fifo[0]->segment_index == 0),
		"segment_index %d", tx_fifo[0]->segment_index);

  /* grow fifos */
  for (i = 0; i < 200; ++i)
    {
      segment_manager_grow_fifo (sm, rx_fifo[0], fifo_size);
    }

  /* add another 2MB segment */
  fs_index = segment_manager_add_segment (sm, size_2MB);
  SEG_MGR_TEST ((fs_index == 1), "fs_index %d", fs_index);

  /* allocate fifos : 4KB x2
   * expected to be allocated on the newer segment,
   * because the usage of the first segment is high.
   */
  rv = segment_manager_alloc_session_fifos (sm,
					    vlib_get_thread_index (),
					    &rx_fifo[1], &tx_fifo[1]);
  SEG_MGR_TEST ((rv == 0), "segment_manager_alloc_session_fifos %d", rv);
  SEG_MGR_TEST ((rx_fifo[1]->segment_index == 1),
		"segment_index %d", rx_fifo[1]->segment_index);
  SEG_MGR_TEST ((tx_fifo[1]->segment_index == 1),
		"segment_index %d", tx_fifo[1]->segment_index);

  /* allocate fifos : 4KB x2
   * expected to be allocated on the newer segment.
   */
  rv = segment_manager_alloc_session_fifos (sm,
					    vlib_get_thread_index (),
					    &rx_fifo[2], &tx_fifo[2]);
  SEG_MGR_TEST ((rv == 0), "segment_manager_alloc_session_fifos %d", rv);
  SEG_MGR_TEST ((rx_fifo[2]->segment_index == 1),
		"segment_index %d", rx_fifo[2]->segment_index);
  SEG_MGR_TEST ((tx_fifo[2]->segment_index == 1),
		"segment_index %d", tx_fifo[2]->segment_index);

  /* grow fifos, so the usage of the secong segment becomes
   * higher than the first one.
   */
  for (i = 0; i < 400; ++i)
    {
      segment_manager_grow_fifo (sm, rx_fifo[1], fifo_size);
    }

  /* allocate fifos : 4KB x2
   * expected to be allocated on the first segment.
   */
  rv = segment_manager_alloc_session_fifos (sm,
					    vlib_get_thread_index (),
					    &rx_fifo[3], &tx_fifo[3]);
  SEG_MGR_TEST ((rv == 0), "segment_manager_alloc_session_fifos %d", rv);
  SEG_MGR_TEST ((rx_fifo[3]->segment_index == 0),
		"segment_index %d", rx_fifo[3]->segment_index);
  SEG_MGR_TEST ((tx_fifo[3]->segment_index == 0),
		"segment_index %d", tx_fifo[3]->segment_index);



  vnet_app_detach_args_t detach_args = {
    .app_index = attach_args.app_index,
    .api_client_index = ~0,
  };
  rv = vnet_application_detach (&detach_args);
  SEG_MGR_TEST ((rv == 0), "vnet_application_detach %d", rv);

  return 0;
}


static clib_error_t *
fifo_tuning_logic_test (vlib_main_t * vm,
			unformat_input_t * input,
			vlib_cli_command_t * cmd_arg)
{
  int res = 0;

  vnet_session_enable_disable (vm, 1);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "basic"))
	res = fifo_tuning_logic_test_basic (vm, input);
      else if (unformat (input, "pressure_levels_1"))
	res = fifo_tuning_logic_test_pressure_1 (vm, input);
      else if (unformat (input, "pressure_levels_2"))
	res = fifo_tuning_logic_test_pressure_2 (vm, input);
      else if (unformat (input, "alloc"))
	res = fifo_tuning_logic_test_fifo_balanced_alloc (vm, input);

      else if (unformat (input, "all"))
	{
	  if ((res = fifo_tuning_logic_test_basic (vm, input)))
	    goto done;
	  if ((res = fifo_tuning_logic_test_pressure_1 (vm, input)))
	    goto done;
	  if ((res = fifo_tuning_logic_test_pressure_2 (vm, input)))
	    goto done;
	  if ((res = fifo_tuning_logic_test_fifo_balanced_alloc (vm, input)))
	    goto done;
	}
      else
	break;
    }

done:
  if (res)
    return clib_error_return (0, "Fifo tuning logic unit test failed.");
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (tcp_test_command, static) =
{
  .path = "test fifo tuning logic",
  .short_help = "fifo tuning logic unit tests",
  .function = fifo_tuning_logic_test,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

