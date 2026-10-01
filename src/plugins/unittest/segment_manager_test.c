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

#define SEG_MGR_TEST_CLEANUP(_cond, _comment, _args...)                                            \
  do                                                                                               \
    {                                                                                              \
      if (!SEG_MGR_TEST_I (_cond, _comment, ##_args))                                              \
	goto cleanup;                                                                              \
    }                                                                                              \
  while (0)

/* placeholder callback functions */
static void
placeholder_session_reset_callback (session_t * s)
{
  clib_warning ("called...");
}

static int
placeholder_session_connected_callback (u32 app_index, u32 api_context,
					session_t * s, session_error_t err)
{
  clib_warning ("called...");
  return 0;
}

static int
placeholder_add_segment_callback (u32 client_index, u64 segment_handle)
{
  clib_warning ("called...");
  return 0;
}

static int
placeholder_del_segment_callback (u32 client_index, u64 segment_handle)
{
  clib_warning ("called...");
  return 0;
}

static void
placeholder_session_disconnect_callback (session_t * s)
{
  clib_warning ("called...");
}

static int
placeholder_session_accept_callback (session_t * s)
{
  clib_warning ("called...");
  return 0;
}

static int
placeholder_server_rx_callback (session_t * s)
{
  clib_warning ("called...");
  return -1;
}

static session_cb_vft_t placeholder_session_cbs = {
  .session_reset_callback = placeholder_session_reset_callback,
  .session_connected_callback = placeholder_session_connected_callback,
  .session_accept_callback = placeholder_session_accept_callback,
  .session_disconnect_callback = placeholder_session_disconnect_callback,
  .builtin_app_rx_callback = placeholder_server_rx_callback,
  .add_segment_callback = placeholder_add_segment_callback,
  .del_segment_callback = placeholder_del_segment_callback,
};

static char *states_str[] = {
#define _(sym,str) str,
  foreach_segment_mem_status
#undef _
};

static u32 size_4KB = 4 << 10;
static u32 size_8KB = 8 << 10;
static u32 size_12KB = 12 << 10;
static u32 size_16KB = 16 << 10;
static u32 size_20KB = 20 << 10;
static u32 size_32KB = 32 << 10;
static u32 size_52KB = 52 << 10;
static u32 size_64KB = 64 << 10;
static u32 size_128KB = 128 << 10;
static u32 size_1MB = 1 << 20;
static u32 size_2MB = 2 << 20;


static int
segment_manager_test_pressure_1 (vlib_main_t * vm, unformat_input_t * input)
{
  int rv;
  segment_manager_t *sm;
  fifo_segment_t *fs0, *fs;
  svm_fifo_t *rx_fifo, *tx_fifo;
  uword app_seg_size = size_2MB;
  u32 fifo_size = size_128KB;
  u64 options[APP_OPTIONS_N_OPTIONS];
  u8 data[size_128KB];

  memset (&options, 0, sizeof (options));

  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &placeholder_session_cbs,
    .name = format (0, "segment_manager_test_pressure_1"),
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

  /* initial status : (0 / 2MB) */
  fs0 = segment_manager_get_segment (sm, 0);
  rv = fifo_segment_get_mem_status (fs0);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_NO_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);


  /* allocate a fifo : 128KB x2 */
  rv = segment_manager_alloc_session_fifos (sm,
					    vlib_get_thread_index (),
					    &rx_fifo, &tx_fifo);
  SEG_MGR_TEST ((rv == 0), "segment_manager_alloc_session_fifos %d", rv);

  svm_fifo_set_size (rx_fifo, size_1MB);
  svm_fifo_set_size (tx_fifo, size_1MB);

  fs = segment_manager_get_segment (sm, rx_fifo->segment_index);
  SEG_MGR_TEST ((fs == fs0), "fs %p", fs);

  /* fill fifos (but not add chunks) */
  svm_fifo_enqueue (rx_fifo, fifo_size - 1, data);
  svm_fifo_enqueue (tx_fifo, fifo_size - 1, data);

  /* 256KB+ / 2048KB+ => ~12% */
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_NO_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* grow fifos */
  svm_fifo_enqueue (rx_fifo, fifo_size, data);
  svm_fifo_enqueue (rx_fifo, fifo_size, data);
  svm_fifo_enqueue (rx_fifo, fifo_size, data);
  svm_fifo_enqueue (tx_fifo, fifo_size, data);
  svm_fifo_enqueue (tx_fifo, fifo_size, data);

  /* 7 chunks : ~44% */
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_NO_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* grow fifos */
  svm_fifo_enqueue (tx_fifo, fifo_size, data);
  svm_fifo_enqueue (rx_fifo, fifo_size, data);
  svm_fifo_enqueue (tx_fifo, fifo_size, data);

  /* 10 chunks : 61% */
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_LOW_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* grow fifos */
  svm_fifo_enqueue (rx_fifo, fifo_size, data);
  svm_fifo_enqueue (rx_fifo, fifo_size, data);
  svm_fifo_enqueue (tx_fifo, fifo_size, data);
  svm_fifo_enqueue (tx_fifo, fifo_size, data);

  /* 14 chunks : 85% */
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_HIGH_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);


  /* shrink fifos */
  svm_fifo_dequeue_drop (rx_fifo, fifo_size);
  svm_fifo_dequeue_drop (rx_fifo, fifo_size);
  svm_fifo_dequeue_drop (tx_fifo, fifo_size);
  svm_fifo_dequeue_drop (tx_fifo, fifo_size);

  /* 10 chunks : 63% */
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_LOW_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);


  /* grow fifos */
  svm_fifo_enqueue (rx_fifo, fifo_size, data);
  svm_fifo_enqueue (rx_fifo, fifo_size, data);
  svm_fifo_enqueue (tx_fifo, fifo_size, data);
  svm_fifo_enqueue (tx_fifo, fifo_size, data);

  /* 14 chunks : 88% */
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_HIGH_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  svm_fifo_dequeue_drop (rx_fifo, fifo_size);
  svm_fifo_dequeue_drop (rx_fifo, fifo_size);
  svm_fifo_dequeue_drop (tx_fifo, fifo_size);
  svm_fifo_dequeue_drop (tx_fifo, fifo_size);

  /* 10 chunks : 63% */
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_LOW_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* shrink fifos */
  svm_fifo_dequeue_drop (rx_fifo, fifo_size);
  svm_fifo_dequeue_drop (rx_fifo, fifo_size);
  svm_fifo_dequeue_drop (rx_fifo, fifo_size);
  svm_fifo_dequeue_drop (rx_fifo, fifo_size);
  svm_fifo_dequeue_drop (tx_fifo, fifo_size);
  svm_fifo_dequeue_drop (tx_fifo, fifo_size);
  svm_fifo_dequeue_drop (tx_fifo, fifo_size);
  svm_fifo_dequeue_drop (tx_fifo, fifo_size);

  /* 2 chunks : 12% */
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_NO_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);


  vnet_app_detach_args_t detach_args = {
    .app_index = attach_args.app_index,
    .api_client_index = ~0,
  };
  rv = vnet_application_detach (&detach_args);
  SEG_MGR_TEST ((rv == 0), "vnet_application_detach %d", rv);

  return 0;
}

static int
segment_manager_test_pressure_2 (vlib_main_t * vm, unformat_input_t * input)
{
  int rv, i;
  segment_manager_t *sm;
  fifo_segment_t *fs0, *fs;
  svm_fifo_t *rx_fifo, *tx_fifo;
  uword app_seg_size = size_2MB;
  u32 fifo_size = size_4KB;
  u64 options[APP_OPTIONS_N_OPTIONS];
  u8 data[size_4KB];

  memset (&options, 0, sizeof (options));

  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &placeholder_session_cbs,
    .name = format (0, "segment_manager_test_pressure_2"),
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

  /* initial status : (0 / 2MB) */
  fs0 = segment_manager_get_segment (sm, 0);
  rv = fifo_segment_get_mem_status (fs0);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_NO_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);


  /* allocate fifos : 4KB x2 */
  rv = segment_manager_alloc_session_fifos (sm,
					    vlib_get_thread_index (),
					    &rx_fifo, &tx_fifo);
  SEG_MGR_TEST ((rv == 0), "segment_manager_alloc_session_fifos %d", rv);

  svm_fifo_set_size (rx_fifo, size_1MB);
  svm_fifo_set_size (tx_fifo, size_1MB);

  /* fill fifos (but not add chunks) */
  svm_fifo_enqueue (rx_fifo, fifo_size - 1, data);
  svm_fifo_enqueue (tx_fifo, fifo_size - 1, data);

  fs = segment_manager_get_segment (sm, rx_fifo->segment_index);

  /* grow fifos */
  for (i = 0; i < 509; ++i)
    {
      svm_fifo_enqueue (rx_fifo, fifo_size, data);
      svm_fifo_enqueue (tx_fifo, fifo_size, data);
    }

  /* 100% of 2MB */
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_HIGH_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* this fifo growth is expected to fail */
  rv = svm_fifo_enqueue (rx_fifo, fifo_size, data);
  SEG_MGR_TEST ((rv == SVM_FIFO_EGROW), "svm_fifo_enqueue %d", rv);

  /* shrink fifos */
  for (i = 0; i < 20; ++i)
    {
      svm_fifo_dequeue_drop (rx_fifo, fifo_size);
      svm_fifo_dequeue_drop (tx_fifo, fifo_size);
    }

  /* 489 chunks : 96%, it is high-pressure level
   * but the reached-mem-limit record is not reset
   * so the no-memory state lasts.
   */
  /*
   rv = fifo_segment_get_mem_status (fs);
   SEG_MGR_TEST ((rv == MEMORY_PRESSURE_NO_MEMORY),
		 "fifo_segment_get_mem_status %s", states_str[rv]);
  */

  /* shrink fifos */
  for (i = 0; i < 133; ++i)
    {
      svm_fifo_dequeue_drop (rx_fifo, fifo_size);
    }

  /* 356 chunks : 70% of 2MB */
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_LOW_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* shrink fifos */
  for (i = 0; i < 360; ++i)
    {
      svm_fifo_dequeue_drop (rx_fifo, fifo_size);
      svm_fifo_dequeue_drop (tx_fifo, fifo_size);
    }

  /* 2 chunks : 3% of 2MB */
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_NO_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);


  vnet_app_detach_args_t detach_args = {
    .app_index = attach_args.app_index,
    .api_client_index = ~0,
  };
  rv = vnet_application_detach (&detach_args);
  SEG_MGR_TEST ((rv == 0), "vnet_application_detach %d", rv);

  return 0;
}

static int
segment_manager_test_fifo_balanced_alloc (vlib_main_t * vm,
					  unformat_input_t * input)
{
  int rv, i, fs_index;
  segment_manager_t *sm;
  fifo_segment_t *fs[4];
  svm_fifo_t *rx_fifo[4], *tx_fifo[4];
  uword app_seg_size = size_2MB;
  u32 fifo_size = size_4KB;
  u64 options[APP_OPTIONS_N_OPTIONS];
  u8 data[size_4KB];

  memset (&options, 0, sizeof (options));

  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &placeholder_session_cbs,
    .name = format (0, "segment_manager_test_fifo_balanced_alloc"),
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

  /* initial status : (0 / 2MB) */
  fs[0] = segment_manager_get_segment (sm, 0);
  rv = fifo_segment_get_mem_status (fs[0]);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_NO_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

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
  svm_fifo_set_size (rx_fifo[0], size_1MB);
  for (i = 0; i < 200; ++i)
    {
      svm_fifo_enqueue (rx_fifo[0], fifo_size, data);
    }

  /* add another 2MB segment */
  fs_index = segment_manager_add_segment (sm, size_2MB, 0);
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
  svm_fifo_set_size (rx_fifo[1], size_1MB);
  for (i = 0; i < 400; ++i)
    {
      svm_fifo_enqueue (rx_fifo[1], fifo_size, data);
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

/* disabled until fifo tuning and memory pressure are properly working */
__clib_unused static int
segment_manager_test_fifo_ops (vlib_main_t *vm, unformat_input_t *input)
{
  int rv, i;
  segment_manager_t *sm;
  fifo_segment_t *fs;
  svm_fifo_t *rx_fifo, *tx_fifo;
  uword app_seg_size = size_2MB, most_grown = 0;
  u32 fifo_size = size_4KB;
  u32 max_dequeue = 0;
  u64 options[APP_OPTIONS_N_OPTIONS];
  u8 data[size_128KB];

  memset (&options, 0, sizeof (options));

  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &placeholder_session_cbs,
    .name = format (0, "segment_manager_test_pressure_1"),
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

  /* initial status : (0 / 2MB) */
  fs = segment_manager_get_segment (sm, 0);
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_NO_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* allocate fifos : 4KB x2 */
  rv = segment_manager_alloc_session_fifos (sm,
					    vlib_get_thread_index (),
					    &rx_fifo, &tx_fifo);
  SEG_MGR_TEST ((rv == 0), "segment_manager_alloc_session_fifos %d", rv);

  /* check the initial fifo size : 4KB */
  rv = svm_fifo_size (rx_fifo);
  SEG_MGR_TEST ((rv == size_4KB), "svm_fifo_size %d", rv);

  /* fill 4KB */
  rv = svm_fifo_enqueue (rx_fifo, size_4KB, data);
  SEG_MGR_TEST ((rv == size_4KB), "svm_fifo_enqueue %d", rv);
  max_dequeue = svm_fifo_max_dequeue (rx_fifo);
  SEG_MGR_TEST ((max_dequeue == size_4KB), "max_dequeue %u", max_dequeue);

  /* grow the fifo size : 4KB -> 8KB */
  svm_fifo_set_size (rx_fifo, size_8KB);
  rv = svm_fifo_size (rx_fifo);
  SEG_MGR_TEST ((rv == size_8KB), "svm_fifo_size %d", rv);

  /* verify that fifo cannot grow larger than the fifo size */
  /* 4KB + 8KB > 8KB, so only 4KB is queued */
  rv = svm_fifo_enqueue (rx_fifo, size_8KB, data);
  SEG_MGR_TEST ((rv == size_4KB), "svm_fifo_enqueue %d", rv);
  max_dequeue = svm_fifo_max_dequeue (rx_fifo);
  SEG_MGR_TEST ((max_dequeue == size_8KB), "max_dequeue %u", max_dequeue);

  /* grow the fifo size : 8KB -> 16KB */
  svm_fifo_set_size (rx_fifo, size_16KB);

  /* 8KB + 4KB = 12KB */
  svm_fifo_enqueue (rx_fifo, size_4KB, data);
  max_dequeue = svm_fifo_max_dequeue (rx_fifo);
  SEG_MGR_TEST ((max_dequeue == size_12KB), "max_dequeue %u", max_dequeue);

  /* grow the fifo size : 16KB -> 32KB */
  svm_fifo_set_size (rx_fifo, size_32KB);

  /* 12KB + 8KB = 20KB */
  svm_fifo_enqueue (rx_fifo, size_8KB, data);
  max_dequeue = svm_fifo_max_dequeue (rx_fifo);
  SEG_MGR_TEST ((max_dequeue == size_20KB), "max_dequeue %u", max_dequeue);

  /* grow the fifo size : 32KB -> 64KB */
  svm_fifo_set_size (rx_fifo, size_64KB);

  /* 20KB + 32KB = 52KB */
  svm_fifo_enqueue (rx_fifo, size_32KB, data);
  max_dequeue = svm_fifo_max_dequeue (rx_fifo);
  SEG_MGR_TEST ((max_dequeue == size_52KB), "max_dequeue %u", max_dequeue);

  /* bulk enqueue */
  for (i = 0; i < 55; ++i)
    {
      svm_fifo_set_size (rx_fifo, svm_fifo_size (rx_fifo) + size_32KB);
      svm_fifo_enqueue (rx_fifo, size_32KB, data);
    }
  max_dequeue = svm_fifo_max_dequeue (rx_fifo);
  SEG_MGR_TEST ((max_dequeue == (size_52KB + size_32KB * 55)),
		"max_dequeue %u", max_dequeue);
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_HIGH_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);
  most_grown = svm_fifo_size (rx_fifo);

  /* dequeue */
  svm_fifo_dequeue_drop (rx_fifo, size_20KB);
  svm_fifo_dequeue_drop (rx_fifo, size_32KB);

  /* bulk dequeue */
  for (i = 0; i < 20; ++i)
    svm_fifo_dequeue_drop (rx_fifo, size_32KB);
  max_dequeue = svm_fifo_max_dequeue (rx_fifo);
  SEG_MGR_TEST ((max_dequeue == (size_32KB * 35)), "max_dequeue %u",
		max_dequeue);
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_LOW_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* bulk dequeue */
  for (i = 0; i < 10; ++i)
    svm_fifo_dequeue_drop (rx_fifo, size_32KB);
  max_dequeue = svm_fifo_max_dequeue (rx_fifo);
  SEG_MGR_TEST ((max_dequeue == (size_32KB * 25)), "max_dequeue %u",
		max_dequeue);
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_NO_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* bulk enqueue */
  for (i = 0; i < 30; ++i)
    svm_fifo_enqueue (rx_fifo, size_32KB, data);
  max_dequeue = svm_fifo_max_dequeue (rx_fifo);
  SEG_MGR_TEST ((max_dequeue == (size_32KB * 55)), "max_dequeue %u",
		max_dequeue);
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_HIGH_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* bulk dequeue */
  for (i = 0; i < 20; ++i)
    svm_fifo_dequeue_drop (rx_fifo, size_32KB);
  max_dequeue = svm_fifo_max_dequeue (rx_fifo);
  SEG_MGR_TEST ((max_dequeue == (size_32KB * 35)), "max_dequeue %u",
		max_dequeue);
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_LOW_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* bulk dequeue */
  for (i = 0; i < 35; ++i)
    svm_fifo_dequeue_drop (rx_fifo, size_32KB);
  max_dequeue = svm_fifo_max_dequeue (rx_fifo);
  SEG_MGR_TEST ((max_dequeue == 0), "max_dequeue %u", max_dequeue);
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_NO_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* (virtual) fifo size is still large as it is not updated */
  SEG_MGR_TEST ((rx_fifo->shr->size == most_grown), "rx_fifo->size %u",
		rx_fifo->shr->size);

  vnet_app_detach_args_t detach_args = {
    .app_index = attach_args.app_index,
    .api_client_index = ~0,
  };
  rv = vnet_application_detach (&detach_args);
  SEG_MGR_TEST ((rv == 0), "vnet_application_detach %d", rv);

  return 0;
}

static int
segment_manager_test_prealloc_hdrs (vlib_main_t * vm,
				    unformat_input_t * input)
{
  u32 fifo_size = size_4KB, prealloc_hdrs, sm_index, fs_index;
  u64 options[APP_OPTIONS_N_OPTIONS];
  uword app_seg_size = size_2MB * 2;
  segment_manager_t *sm;
  fifo_segment_t *fs;
  int rv;

  memset (&options, 0, sizeof (options));

  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &placeholder_session_cbs,
    .name = format (0, "segment_manager_test_prealloc_hdrs"),
  };

  prealloc_hdrs = 64;

  attach_args.options[APP_OPTIONS_SEGMENT_SIZE] = app_seg_size;
  attach_args.options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  attach_args.options[APP_OPTIONS_RX_FIFO_SIZE] = fifo_size;
  attach_args.options[APP_OPTIONS_TX_FIFO_SIZE] = fifo_size;
  attach_args.options[APP_OPTIONS_PREALLOC_FIFO_HDRS] = prealloc_hdrs;

  rv = vnet_application_attach (&attach_args);
  vec_free (attach_args.name);

  SEG_MGR_TEST ((rv == 0), "vnet_application_attach %d", rv);

  segment_manager_parse_segment_handle (attach_args.segment_handle, &sm_index,
					&fs_index);
  sm = segment_manager_get (sm_index);

  SEG_MGR_TEST ((sm != 0), "seg manager is valid", sm);

  fs = segment_manager_get_segment (sm, fs_index);
  SEG_MGR_TEST (fifo_segment_num_free_fifos (fs) == prealloc_hdrs,
		"prealloc should be %u", prealloc_hdrs);

  vnet_app_detach_args_t detach_args = {
    .app_index = attach_args.app_index,
    .api_client_index = ~0,
  };
  rv = vnet_application_detach (&detach_args);
  SEG_MGR_TEST ((rv == 0), "vnet_application_detach %d", rv);
  return 0;
}

static int
segment_manager_test_listener_limit (vlib_main_t *vm, unformat_input_t *input)
{
  u64 options[APP_OPTIONS_N_OPTIONS] = { 0 };
  svm_fifo_t *rx[16] = { 0 }, *tx[16] = { 0 };
  u32 app_index = APP_INVALID_INDEX, transport_index = APP_INVALID_INDEX;
  u32 sm_index, owner_index, n_pairs = 0;
  vnet_app_worker_add_del_args_t worker = { .wrk_map_index = APP_INVALID_INDEX,
					    .api_client_index = 0xffff,
					    .is_add = 1 };
  vnet_listen_args_t listen = { .sep_ext = SESSION_ENDPOINT_CFG_NULL };
  vnet_app_attach_args_t attach = { .api_client_index = APP_INVALID_INDEX,
				    .options = options,
				    .session_cb_vft = &placeholder_session_cbs };
  segment_manager_t *sm;
  app_listener_t *al;
  app_worker_t *app_wrk;
  int rv, result = 1;

  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  options[APP_OPTIONS_SEGMENT_SIZE] = size_1MB;
  options[APP_OPTIONS_ADD_SEGMENT_SIZE] = size_1MB;
  options[APP_OPTIONS_MAX_FIFO_MEMORY] = size_1MB;
  options[APP_OPTIONS_RX_FIFO_SIZE] = size_32KB;
  options[APP_OPTIONS_TX_FIFO_SIZE] = size_32KB;
  options[APP_OPTIONS_PCT_FIRST_ALLOC] = 100;
  attach.name = format (0, "segment_manager_test_listener_limit");
  rv = vnet_application_attach (&attach);
  vec_free (attach.name);
  SEG_MGR_TEST_CLEANUP (!rv, "attach listener app: %d", rv);
  app_index = attach.app_index;

  listen.app_index = app_index;
  listen.sep_ext.is_ip4 = 1;
  listen.sep_ext.port = clib_host_to_net_u16 (12345);
  listen.sep_ext.transport_proto = TRANSPORT_PROTO_UDP;
  rv = vnet_listen (&listen);
  SEG_MGR_TEST_CLEANUP (!rv, "first worker listens with a one-segment limit: %d", rv);
  al = app_listener_get_w_handle (listen.handle);
  sm_index = al->sm_index;

  worker.app_index = app_index;
  rv = vnet_app_worker_add_del (&worker);
  SEG_MGR_TEST_CLEANUP (!rv, "add second listener worker: %d", rv);
  listen.wrk_map_index = worker.wrk_map_index;
  rv = vnet_listen (&listen);
  SEG_MGR_TEST_CLEANUP (!rv, "second worker has its own segment budget: %d", rv);

  /* Model the listener borrowed by a builtin transport. Its fifo size also
   * requires a private segment larger than the app's configured segment. */
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_IS_TRANSPORT_APP;
  options[APP_OPTIONS_MAX_FIFO_MEMORY] = 0;
  options[APP_OPTIONS_RX_FIFO_SIZE] = 512 << 10;
  options[APP_OPTIONS_TX_FIFO_SIZE] = 512 << 10;
  attach.name = format (0, "segment_manager_test_transport_limit");
  rv = vnet_application_attach (&attach);
  vec_free (attach.name);
  SEG_MGR_TEST_CLEANUP (!rv, "attach builtin transport: %d", rv);
  transport_index = attach.app_index;
  listen.app_index = transport_index;
  listen.wrk_map_index = 0;
  listen.sep_ext.port = clib_host_to_net_u16 (12346);
  listen.sep_ext.sm_index = sm_index;
  rv = vnet_listen (&listen);
  SEG_MGR_TEST_CLEANUP (!rv, "private transport fifos do not consume worker budgets: %d", rv);

  app_wrk = application_get_default_worker (application_get (app_index));
  owner_index = app_wrk->wrk_index;
  sm = segment_manager_get (sm_index);
  SEG_MGR_TEST_CLEANUP (pool_elts (sm->segments) == 3,
			"two worker segments and one private transport segment");

  /* Fill one owner's segment and verify that its cap is still enforced. */
  while (n_pairs < ARRAY_LEN (rx))
    {
      rv = segment_manager_alloc_session_fifos_w_owner (sm, owner_index, size_128KB, size_128KB, 0,
							&rx[n_pairs], &tx[n_pairs]);
      if (rv)
	break;
      n_pairs++;
    }
  SEG_MGR_TEST_CLEANUP (n_pairs > 0 && n_pairs < ARRAY_LEN (rx) && rv == SESSION_E_SEG_CREATE,
			"owner cannot allocate a second segment: %d", rv);
  SEG_MGR_TEST_CLEANUP (pool_elts (sm->segments) == 3,
			"failed allocation leaves no extra segments");

  sm = app_worker_get_connect_segment_manager (app_wrk);
  rv = segment_manager_add_segment (sm, size_1MB, 0);
  SEG_MGR_TEST_CLEANUP (rv < 0, "connects manager still enforces its segment limit");
  result = 0;

cleanup:
  while (n_pairs)
    {
      n_pairs--;
      segment_manager_dealloc_fifos (rx[n_pairs], tx[n_pairs]);
    }
  vnet_app_detach_args_t detach = { .api_client_index = APP_INVALID_INDEX };
  if (transport_index != APP_INVALID_INDEX)
    {
      detach.app_index = transport_index;
      vnet_application_detach (&detach);
    }
  if (worker.wrk_map_index != APP_INVALID_INDEX)
    {
      worker.is_add = 0;
      vnet_app_worker_add_del (&worker);
    }
  if (app_index != APP_INVALID_INDEX)
    {
      detach.app_index = app_index;
      vnet_application_detach (&detach);
    }
  return result;
}

static volatile session_handle_t sm_ct_test_accepted, sm_ct_test_connected;
static volatile session_error_t sm_ct_test_error;
static u32 sm_ct_test_worker;
static volatile u64 sm_ct_test_segment;

static int
sm_ct_test_accept (session_t *s)
{
  sm_ct_test_accepted = s->handle;
  return 0;
}

static int
sm_ct_test_connect (u32 app_wrk_index, u32 context, session_t *s, session_error_t err)
{
  sm_ct_test_error = err;
  if (s)
    sm_ct_test_connected = s->handle;
  return 0;
}

static int
sm_ct_test_add_segment (u32 app_wrk_index, u64 segment_handle)
{
  if (app_wrk_index == sm_ct_test_worker)
    sm_ct_test_segment = segment_handle;
  return 0;
}

static int
sm_ct_test_wait_connected (vlib_main_t *vm)
{
  u32 tries = 0;

  while (sm_ct_test_connected == SESSION_INVALID_HANDLE && !sm_ct_test_error && tries++ < 100)
    {
      vlib_worker_thread_barrier_release (vm);
      vlib_process_suspend (vm, 10e-3);
      vlib_worker_thread_barrier_sync (vm);
    }
  return sm_ct_test_connected != SESSION_INVALID_HANDLE && !sm_ct_test_error;
}

static int
segment_manager_test_ct_worker_reuse (vlib_main_t *vm, unformat_input_t *input)
{
  u64 options[APP_OPTIONS_N_OPTIONS] = { 0 };
  u32 server_index = APP_INVALID_INDEX, client_index = APP_INVALID_INDEX;
  u32 old_worker, old_segment, sm_index;
  svm_fifo_t *held_rx = 0, *held_tx = 0;
  session_cb_vft_t callbacks = placeholder_session_cbs;
  vnet_app_worker_add_del_args_t worker = { .wrk_map_index = APP_INVALID_INDEX,
					    .api_client_index = 0xffff,
					    .is_add = 1 };
  vnet_app_attach_args_t attach = { .api_client_index = APP_INVALID_INDEX,
				    .options = options,
				    .session_cb_vft = &callbacks };
  vnet_listen_args_t listen = { .sep_ext = SESSION_ENDPOINT_CFG_NULL };
  vnet_connect_args_t connect = { .sep_ext = SESSION_ENDPOINT_CFG_NULL };
  app_listener_t *al;
  session_t *s;
  int rv, result = 1;

  sm_ct_test_accepted = sm_ct_test_connected = SESSION_INVALID_HANDLE;
  sm_ct_test_error = SESSION_E_NONE;
  callbacks.session_accept_callback = sm_ct_test_accept;
  callbacks.session_connected_callback = sm_ct_test_connect;
  callbacks.add_segment_callback = sm_ct_test_add_segment;
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN | APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  options[APP_OPTIONS_SEGMENT_SIZE] = size_1MB;
  options[APP_OPTIONS_ADD_SEGMENT_SIZE] = size_1MB;
  attach.name = format (0, "segment_manager_test_ct_server");
  rv = vnet_application_attach (&attach);
  vec_free (attach.name);
  SEG_MGR_TEST_CLEANUP (!rv, "attach cut-through server: %d", rv);
  server_index = attach.app_index;
  worker.app_index = server_index;
  rv = vnet_app_worker_add_del (&worker);
  SEG_MGR_TEST_CLEANUP (!rv, "add server worker: %d", rv);
  old_worker =
    application_get_worker (application_get (server_index), worker.wrk_map_index)->wrk_index;
  sm_ct_test_worker = old_worker;

  listen.app_index = server_index;
  listen.wrk_map_index = worker.wrk_map_index;
  listen.sep_ext.is_ip4 = 1;
  listen.sep_ext.transport_proto = TRANSPORT_PROTO_TCP;
  listen.sep_ext.port = clib_host_to_net_u16 (12347);
  rv = vnet_listen (&listen);
  SEG_MGR_TEST_CLEANUP (!rv, "server worker listens: %d", rv);
  al = app_listener_get_w_handle (listen.handle);
  sm_index = al->sm_index;

  attach.name = format (0, "segment_manager_test_ct_client");
  rv = vnet_application_attach (&attach);
  vec_free (attach.name);
  SEG_MGR_TEST_CLEANUP (!rv, "attach cut-through client: %d", rv);
  client_index = attach.app_index;
  connect.app_index = client_index;
  connect.sep_ext.is_ip4 = 1;
  connect.sep_ext.ip.ip4.as_u32 = clib_host_to_net_u32 (0x7f000001);
  connect.sep_ext.port = listen.sep_ext.port;
  connect.sep_ext.transport_proto = TRANSPORT_PROTO_TCP;
  rv = vnet_connect2 (&connect);
  SEG_MGR_TEST_CLEANUP (!rv && sm_ct_test_wait_connected (vm),
			"first cut-through connection succeeds");

  s = session_get_from_handle (sm_ct_test_accepted);
  old_segment = s->rx_fifo->segment_index;
  held_rx = s->rx_fifo;
  held_tx = s->tx_fifo;
  held_rx->refcnt++;
  held_tx->refcnt++;

  /* Keep the listener alive on the default worker, then replace the worker
   * that owns the old segment. Extra fifo references delay CT accounting,
   * as a zero-copy proxy can do; the client also delays its close reply. */
  listen.wrk_map_index = 0;
  rv = vnet_listen (&listen);
  SEG_MGR_TEST_CLEANUP (!rv, "another worker keeps the listener alive: %d", rv);
  worker.is_add = 0;
  rv = vnet_app_worker_add_del (&worker);
  SEG_MGR_TEST_CLEANUP (!rv, "detach original server worker: %d", rv);
  worker.wrk_map_index = APP_INVALID_INDEX;
  SEG_MGR_TEST_CLEANUP (
    segment_manager_get_segment (segment_manager_get (sm_index), old_segment)->owner_index ==
      SEGMENT_MANAGER_INVALID_APP_INDEX,
    "old segment no longer has an owner");
  worker.is_add = 1;
  rv = vnet_app_worker_add_del (&worker);
  SEG_MGR_TEST_CLEANUP (!rv, "add replacement worker: %d", rv);
  SEG_MGR_TEST_CLEANUP (
    application_get_worker (application_get (server_index), worker.wrk_map_index)->wrk_index ==
      old_worker,
    "replacement reuses the old worker index");
  listen.wrk_map_index = worker.wrk_map_index;
  rv = vnet_listen (&listen);
  SEG_MGR_TEST_CLEANUP (!rv, "replacement joins the same listener: %d", rv);
  al = app_listener_get_w_handle (listen.handle);
  al->accept_rotor = worker.wrk_map_index - 1;
  sm_ct_test_accepted = sm_ct_test_connected = SESSION_INVALID_HANDLE;
  sm_ct_test_segment = SESSION_INVALID_HANDLE;
  rv = vnet_connect2 (&connect);
  SEG_MGR_TEST_CLEANUP (!rv && sm_ct_test_wait_connected (vm),
			"replacement accepts a new connection");
  s = session_get_from_handle (sm_ct_test_accepted);
  SEG_MGR_TEST_CLEANUP (s->app_wrk_index == old_worker,
			"new connection belongs to replacement worker");
  SEG_MGR_TEST_CLEANUP (s->rx_fifo->segment_index != old_segment,
			"replacement does not reuse the detached worker's segment");
  SEG_MGR_TEST_CLEANUP (sm_ct_test_segment == ((u64) sm_index << 32 | s->rx_fifo->segment_index),
			"replacement receives the new segment mapping notification");
  result = 0;

cleanup:
  if (held_rx)
    segment_manager_dealloc_fifos (held_rx, held_tx);
  vnet_app_detach_args_t detach = { .api_client_index = APP_INVALID_INDEX };
  if (client_index != APP_INVALID_INDEX)
    {
      detach.app_index = client_index;
      vnet_application_detach (&detach);
    }
  if (worker.wrk_map_index != APP_INVALID_INDEX)
    {
      worker.is_add = 0;
      vnet_app_worker_add_del (&worker);
    }
  if (server_index != APP_INVALID_INDEX)
    {
      detach.app_index = server_index;
      vnet_application_detach (&detach);
    }
  vlib_worker_thread_barrier_release (vm);
  vlib_process_suspend (vm, 100e-3);
  vlib_worker_thread_barrier_sync (vm);
  return result;
}

static clib_error_t *
segment_manager_test (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd_arg)
{
  int res = 0;
  session_enable_disable_args_t args = { .is_en = 1,
					 .rt_engine_type =
					   RT_BACKEND_ENGINE_RULE_TABLE };

  vnet_session_enable_disable (vm, &args);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "pressure_levels_1"))
	res = segment_manager_test_pressure_1 (vm, input);
      else if (unformat (input, "pressure_levels_2"))
	res = segment_manager_test_pressure_2 (vm, input);
      else if (unformat (input, "alloc"))
	res = segment_manager_test_fifo_balanced_alloc (vm, input);
      else if (unformat (input, "prealloc_hdrs"))
	res = segment_manager_test_prealloc_hdrs (vm, input);
      else if (unformat (input, "listener_limit"))
	res = segment_manager_test_listener_limit (vm, input);
      else if (unformat (input, "ct_worker_reuse"))
	res = segment_manager_test_ct_worker_reuse (vm, input);

      else if (unformat (input, "all"))
	{
	  if ((res = segment_manager_test_pressure_1 (vm, input)))
	    goto done;
	  if ((res = segment_manager_test_pressure_2 (vm, input)))
	    goto done;
	  if ((res = segment_manager_test_fifo_balanced_alloc (vm, input)))
	    goto done;
	  if ((res = segment_manager_test_prealloc_hdrs (vm, input)))
	    goto done;
	  if ((res = segment_manager_test_listener_limit (vm, input)))
	    goto done;
	  if ((res = segment_manager_test_ct_worker_reuse (vm, input)))
	    goto done;
	}
      else
	break;
    }

done:
  if (res)
    return clib_error_return (0, "Segment manager unit test failed.");
  return 0;
}

VLIB_CLI_COMMAND (tcp_test_command, static) = {
  .path = "test segment-manager",
  .short_help = "test segment manager [pressure_levels_1]"
		"[pressure_level_2][alloc][fifo_ops][prealloc_hdrs]"
		"[listener_limit][ct_worker_reuse][all]",
  .function = segment_manager_test,
};
