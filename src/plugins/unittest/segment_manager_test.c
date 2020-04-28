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
				  session_t * s, session_error_t err)
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
    .session_cb_vft = &dummy_session_cbs,
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
  fifo_segment_update_free_bytes (fs);
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_NO_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* grow fifos */
  svm_fifo_enqueue (rx_fifo, fifo_size, data);
  svm_fifo_enqueue (rx_fifo, fifo_size, data);
  svm_fifo_enqueue (rx_fifo, fifo_size, data);
  svm_fifo_enqueue (tx_fifo, fifo_size, data);
  svm_fifo_enqueue (tx_fifo, fifo_size, data);
  svm_fifo_enqueue (tx_fifo, fifo_size, data);

  /* 8 chunks : 49% */
  fifo_segment_update_free_bytes (fs);
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_NO_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* grow fifos */
  svm_fifo_enqueue (rx_fifo, fifo_size, data);
  svm_fifo_enqueue (tx_fifo, fifo_size, data);

  /* 10 chunks : 61% */
  fifo_segment_update_free_bytes (fs);
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_LOW_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* grow fifos */
  svm_fifo_enqueue (rx_fifo, fifo_size, data);
  svm_fifo_enqueue (rx_fifo, fifo_size, data);
  svm_fifo_enqueue (tx_fifo, fifo_size, data);
  svm_fifo_enqueue (tx_fifo, fifo_size, data);

  /* 14 chunks : 85% */
  fifo_segment_update_free_bytes (fs);
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_HIGH_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);


  /* shrink fifos */
  svm_fifo_dequeue_drop (rx_fifo, fifo_size);
  svm_fifo_dequeue_drop (rx_fifo, fifo_size);
  svm_fifo_dequeue_drop (tx_fifo, fifo_size);
  svm_fifo_dequeue_drop (tx_fifo, fifo_size);

  /* 10 chunks : 61% */
  fifo_segment_update_free_bytes (fs);
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_LOW_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);


  /* grow fifos */
  svm_fifo_enqueue (rx_fifo, fifo_size, data);
  svm_fifo_enqueue (rx_fifo, fifo_size, data);
  svm_fifo_enqueue (tx_fifo, fifo_size, data);
  svm_fifo_enqueue (tx_fifo, fifo_size, data);

  /* 14 chunks : 85% */
  fifo_segment_update_free_bytes (fs);
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_HIGH_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  svm_fifo_dequeue_drop (rx_fifo, fifo_size);
  svm_fifo_dequeue_drop (rx_fifo, fifo_size);
  svm_fifo_dequeue_drop (tx_fifo, fifo_size);
  svm_fifo_dequeue_drop (tx_fifo, fifo_size);


  /* 10 chunks : 61% */
  fifo_segment_update_free_bytes (fs);
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
  fifo_segment_update_free_bytes (fs);
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
    .session_cb_vft = &dummy_session_cbs,
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
  fifo_segment_update_free_bytes (fs0);
  rv = fifo_segment_get_mem_status (fs0);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_NO_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);


  /* allocate fifos : 4KB x2 */
  rv = segment_manager_alloc_session_fifos (sm,
					    vlib_get_thread_index (),
					    &rx_fifo, &tx_fifo);
  SEG_MGR_TEST ((rv == 0), "segment_manager_alloc_session_fifos %d", rv);

  svm_fifo_set_size (rx_fifo, size_2MB);
  svm_fifo_set_size (tx_fifo, size_2MB);

  /* fill fifos (but not add chunks) */
  svm_fifo_enqueue (rx_fifo, fifo_size - 1, data);
  svm_fifo_enqueue (tx_fifo, fifo_size - 1, data);

  fs = segment_manager_get_segment (sm, rx_fifo->segment_index);

  /* grow fifos */
  for (i = 0; i < 509; ++i)
    {
      svm_fifo_enqueue (rx_fifo, fifo_size, data);
    }

  /* 510 chunks : 100% of 2MB */
  fifo_segment_update_free_bytes (fs);
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_HIGH_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* this fifo growth is expected to fail */
  rv = svm_fifo_enqueue (rx_fifo, fifo_size, data);
  SEG_MGR_TEST ((rv == SVM_FIFO_EGROW), "svm_fifo_enqueue %d", rv);

  /* then, no-memory is detected */
  fifo_segment_update_free_bytes (fs);
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_NO_MEMORY),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* shrink fifos */
  for (i = 0; i < 20; ++i)
    {
      svm_fifo_dequeue_drop (rx_fifo, fifo_size);
    }

  /* 489 chunks : 96%, it is high-pressure level
   * but the reached-mem-limit record is not reset
   * so the no-memory state lasts.
   */
  fifo_segment_update_free_bytes (fs);
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_NO_MEMORY),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* shrink fifos */
  for (i = 0; i < 133; ++i)
    {
      svm_fifo_dequeue_drop (rx_fifo, fifo_size);
    }

  /* 356 chunks : 70% of 2MB */
  fifo_segment_update_free_bytes (fs);
  rv = fifo_segment_get_mem_status (fs);
  SEG_MGR_TEST ((rv == MEMORY_PRESSURE_LOW_PRESSURE),
		"fifo_segment_get_mem_status %s", states_str[rv]);

  /* shrink fifos */
  for (i = 0; i < 354; ++i)
    {
      svm_fifo_dequeue_drop (rx_fifo, fifo_size);
    }

  /* 2 chunks : 3% of 2MB */
  fifo_segment_update_free_bytes (fs);
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
    .session_cb_vft = &dummy_session_cbs,
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

static int
segment_manager_test_fifo_ops (vlib_main_t * vm, unformat_input_t * input)
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
    .session_cb_vft = &dummy_session_cbs,
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
  SEG_MGR_TEST ((rx_fifo->size == most_grown), "rx_fifo->size %u",
		rx_fifo->size);

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
  uword app_seg_size = size_2MB;
  segment_manager_t *sm;
  fifo_segment_t *fs;
  int rv;

  memset (&options, 0, sizeof (options));

  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &dummy_session_cbs,
    .name = format (0, "segment_manager_prealloc_hdrs"),
  };

  prealloc_hdrs = (app_seg_size - (16 << 10)) / sizeof (svm_fifo_t);

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

static clib_error_t *
segment_manager_test (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd_arg)
{
  int res = 0;

  vnet_session_enable_disable (vm, 1);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "pressure_levels_1"))
	res = segment_manager_test_pressure_1 (vm, input);
      else if (unformat (input, "pressure_levels_2"))
	res = segment_manager_test_pressure_2 (vm, input);
      else if (unformat (input, "alloc"))
	res = segment_manager_test_fifo_balanced_alloc (vm, input);
      else if (unformat (input, "fifo_ops"))
	res = segment_manager_test_fifo_ops (vm, input);
      else if (unformat (input, "prealloc_hdrs"))
	res = segment_manager_test_prealloc_hdrs (vm, input);

      else if (unformat (input, "all"))
	{
	  if ((res = segment_manager_test_pressure_1 (vm, input)))
	    goto done;
	  if ((res = segment_manager_test_pressure_2 (vm, input)))
	    goto done;
	  if ((res = segment_manager_test_fifo_balanced_alloc (vm, input)))
	    goto done;
	  if ((res = segment_manager_test_fifo_ops (vm, input)))
	    goto done;
	  if ((res = segment_manager_test_prealloc_hdrs (vm, input)))
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

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (tcp_test_command, static) =
{
  .path = "test segment-manager",
  .short_help = "test segment manager [pressure_levels_1]"
                "[pressure_level_2][alloc][fifo_ops][prealloc_hdrs][all]",
  .function = segment_manager_test,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

