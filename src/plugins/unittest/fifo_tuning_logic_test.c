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


static void
dummy_alloc (segment_manager_t * sm, u32 size)
{
  if (sm->pool_size >= size)
    {
      segment_manager_update_mem_usage (sm, size, -size, 0);
    }
  else if (sm->allocated >= sm->in_use + size)
    {
      segment_manager_update_mem_usage (sm, size, 0, 0);
    }
  else
    {
      segment_manager_notify_allocation_failure (sm);
    }
}

static void
dummy_dealloc (segment_manager_t * sm, u32 size)
{
  segment_manager_update_mem_usage (sm, -size, size, 0);
}

static void
dummy_virtual_fifo_size_update (segment_manager_t * sm,
				u32 current_value, u32 new_value)
{
  segment_manager_update_mem_usage (sm, 0, 0, (new_value - current_value));
}

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

static u8 default_high_watermark = 80;
static u8 default_low_watermark = 50;

static u32 size_1MB = 1 << 20;
static u32 size_2MB = 2 << 20;
static u32 size_10MB = 10 << 20;
static u32 size_12MB = 12 << 20;
static u32 size_16MB = 16 << 20;
static u32 size_18MB = 18 << 20;
static u32 size_20MB = 20 << 20;
static u32 size_22MB = 22 << 20;



static int
fifo_tuning_logic_test_basic (vlib_main_t * vm, unformat_input_t * input)
{
  int rv;
  segment_manager_t *sm;
  uword seg_size = 2UL << 30;	/* 2GB */
  u32 prealloc_fifo = 0;

  sm = segment_manager_alloc ();
  SEG_MGR_TEST ((sm != 0), "segment_manager_alloc %p", sm);

  rv = segment_manager_init (sm, seg_size, prealloc_fifo, 80, 50);
  SEG_MGR_TEST ((rv == 0), "segment_manager_init %d", rv);

  SEG_MGR_TEST ((sm->in_use == 0), "sm->in_use %d", sm->in_use);
  SEG_MGR_TEST ((sm->pool_size == 0), "sm->pool_size %d", sm->pool_size);
  SEG_MGR_TEST ((sm->reserved == 0), "sm->reserved %d", sm->reserved);
  SEG_MGR_TEST ((sm->high_watermark == 80),
		"sm->high_watermark %d", sm->high_watermark);
  SEG_MGR_TEST ((sm->low_watermark == 50),
		"sm->low_watermark %d", sm->low_watermark);

  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_NO_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));

  segment_manager_del_sessions (sm);
  segment_manager_app_detach (sm);
  segment_manager_free (sm);

  return 0;
}

static int
fifo_tuning_logic_test_pressure_1 (vlib_main_t * vm, unformat_input_t * input)
{
  int rv;
  segment_manager_t *sm;
  uword seg_size = size_10MB;
  u32 prealloc_fifo = 0;

  sm = segment_manager_alloc ();
  SEG_MGR_TEST ((sm != 0), "segment_manager_alloc %p", sm);

  rv = segment_manager_init (sm, seg_size, prealloc_fifo, 80, 50);
  SEG_MGR_TEST ((rv == 0), "segment_manager_init %d", rv);

  SEG_MGR_TEST ((sm->in_use == 0), "sm->in_use %d", sm->in_use);
  SEG_MGR_TEST ((sm->pool_size == 0), "sm->pool_size %d", sm->pool_size);
  SEG_MGR_TEST ((sm->reserved == 0), "sm->reserved %d", sm->reserved);

  /* initial status */
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_NO_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));

  dummy_virtual_fifo_size_update (sm, 0, size_1MB);
  dummy_virtual_fifo_size_update (sm, 0, size_1MB);
  dummy_virtual_fifo_size_update (sm, 0, size_1MB);
  dummy_virtual_fifo_size_update (sm, 0, size_1MB);
  dummy_virtual_fifo_size_update (sm, 0, size_1MB);
  dummy_virtual_fifo_size_update (sm, 0, size_1MB);
  dummy_virtual_fifo_size_update (sm, 0, size_1MB);
  dummy_virtual_fifo_size_update (sm, 0, size_1MB);
  dummy_virtual_fifo_size_update (sm, 0, size_1MB);
  dummy_virtual_fifo_size_update (sm, 0, size_1MB);
  dummy_virtual_fifo_size_update (sm, 0, size_1MB);
  dummy_virtual_fifo_size_update (sm, 0, size_1MB);
  dummy_alloc (sm, size_1MB);
  dummy_alloc (sm, size_1MB);
  dummy_alloc (sm, size_1MB);
  dummy_alloc (sm, size_1MB);
  /* 40% in_use, 120% reserved */
  SEG_MGR_TEST ((sm->reserved == size_12MB), "sm->reserved %d", sm->reserved);
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_NO_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));

  dummy_virtual_fifo_size_update (sm, size_1MB, size_2MB);
  dummy_virtual_fifo_size_update (sm, size_1MB, size_2MB);
  dummy_virtual_fifo_size_update (sm, size_1MB, size_2MB);
  dummy_virtual_fifo_size_update (sm, size_1MB, size_2MB);
  dummy_alloc (sm, size_1MB);
  /* 50% in_use, 160% reserved */
  SEG_MGR_TEST ((sm->reserved == size_16MB), "sm->reserved %d", sm->reserved);
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_LOW_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));

  dummy_virtual_fifo_size_update (sm, size_1MB, size_2MB);
  dummy_virtual_fifo_size_update (sm, size_1MB, size_2MB);
  dummy_virtual_fifo_size_update (sm, size_1MB, size_2MB);
  dummy_virtual_fifo_size_update (sm, size_1MB, size_2MB);
  dummy_dealloc (sm, size_1MB);
  /* 40% in_use, 200% reserved */
  SEG_MGR_TEST ((sm->reserved == size_20MB), "sm->reserved %d", sm->reserved);
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_NO_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));

  dummy_virtual_fifo_size_update (sm, 0, size_1MB);
  dummy_virtual_fifo_size_update (sm, 0, size_1MB);
  dummy_alloc (sm, size_1MB);
  dummy_alloc (sm, size_1MB);
  /* 60% in_use, 220% reserved ... */
  SEG_MGR_TEST ((sm->reserved == size_22MB), "sm->reserved %d", sm->reserved);
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_LOW_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));


  dummy_alloc (sm, size_2MB);
  /* 80% in_use */
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_HIGH_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));

  dummy_virtual_fifo_size_update (sm, size_2MB, size_1MB);
  dummy_virtual_fifo_size_update (sm, size_2MB, size_1MB);
  dummy_virtual_fifo_size_update (sm, size_2MB, size_1MB);
  dummy_virtual_fifo_size_update (sm, size_2MB, size_1MB);
  dummy_dealloc (sm, size_1MB);
  /* 70% in_use */
  SEG_MGR_TEST ((sm->reserved == size_18MB), "sm->reserved %d", sm->reserved);
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_LOW_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));

  dummy_virtual_fifo_size_update (sm, size_1MB, size_2MB);
  dummy_virtual_fifo_size_update (sm, size_1MB, size_2MB);
  dummy_alloc (sm, size_2MB);
  /* 90% in_use */
  SEG_MGR_TEST ((sm->reserved == size_20MB), "sm->reserved %d", sm->reserved);
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_HIGH_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));

  dummy_alloc (sm, size_1MB);
  /* 100% in_use but allocation failure should have not happened */
  SEG_MGR_TEST ((sm->no_memory_detected == 0),
		"sm->no_memory_detected %d", sm->no_memory_detected);
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_HIGH_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));

  dummy_virtual_fifo_size_update (sm, size_2MB, size_1MB);
  dummy_virtual_fifo_size_update (sm, size_2MB, size_1MB);
  dummy_alloc (sm, size_1MB);
  /* 100% in_use and allocation failure should have happened */
  SEG_MGR_TEST ((sm->reserved == size_18MB), "sm->reserved %d", sm->reserved);
  SEG_MGR_TEST ((sm->no_memory_detected == 1),
		"sm->no_memory_detected %d", sm->no_memory_detected);
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_NO_MEMORY),
		"segment_manager_get_mem_status %s", states_str (rv));

  dummy_virtual_fifo_size_update (sm, size_2MB, size_1MB);
  dummy_virtual_fifo_size_update (sm, size_2MB, size_1MB);
  dummy_virtual_fifo_size_update (sm, size_2MB, size_1MB);
  dummy_virtual_fifo_size_update (sm, size_2MB, size_1MB);
  dummy_virtual_fifo_size_update (sm, size_2MB, size_1MB);
  dummy_virtual_fifo_size_update (sm, size_2MB, size_1MB);
  dummy_dealloc (sm, size_1MB);
  /* 90% in_use, but should be in still no-memory state */
  SEG_MGR_TEST ((sm->reserved == size_12MB), "sm->reserved %d", sm->reserved);
  SEG_MGR_TEST ((sm->no_memory_detected == 1),
		"sm->no_memory_detected %d", sm->no_memory_detected);
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_NO_MEMORY),
		"segment_manager_get_mem_status %s", states_str (rv));

  dummy_dealloc (sm, size_1MB);
  /* 80% in_use, but should be in still no-memory state */
  SEG_MGR_TEST ((sm->no_memory_detected == 1),
		"sm->no_memory_detected %d", sm->no_memory_detected);
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_NO_MEMORY),
		"segment_manager_get_mem_status %s", states_str (rv));

  dummy_dealloc (sm, size_1MB);
  /* 70% in_use */
  /* remains in no-memory state until next get-mem-status */
  SEG_MGR_TEST ((sm->no_memory_detected == 1),
		"sm->no_memory_detected %d", sm->no_memory_detected);
  /* now getting out from no-memory state */
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_LOW_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));
  SEG_MGR_TEST ((sm->no_memory_detected == 0),
		"sm->no_memory_detected %d", sm->no_memory_detected);

  dummy_alloc (sm, size_1MB);
  /* 80% in_use but allocation failure should have not happened */
  SEG_MGR_TEST ((sm->no_memory_detected == 0),
		"sm->no_memory_detected %d", sm->no_memory_detected);
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_HIGH_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));

  dummy_virtual_fifo_size_update (sm, size_1MB, 0);
  dummy_virtual_fifo_size_update (sm, size_1MB, 0);
  dummy_virtual_fifo_size_update (sm, size_1MB, 0);
  dummy_virtual_fifo_size_update (sm, size_1MB, 0);
  dummy_virtual_fifo_size_update (sm, size_1MB, 0);
  dummy_virtual_fifo_size_update (sm, size_1MB, 0);
  dummy_virtual_fifo_size_update (sm, size_1MB, 0);
  dummy_virtual_fifo_size_update (sm, size_1MB, 0);
  dummy_virtual_fifo_size_update (sm, size_1MB, 0);
  dummy_virtual_fifo_size_update (sm, size_1MB, 0);
  dummy_virtual_fifo_size_update (sm, size_1MB, 0);
  dummy_virtual_fifo_size_update (sm, size_1MB, 0);
  dummy_dealloc (sm, size_1MB);
  dummy_dealloc (sm, size_1MB);
  dummy_dealloc (sm, size_1MB);
  dummy_dealloc (sm, size_1MB);
  dummy_dealloc (sm, size_1MB);
  dummy_dealloc (sm, size_1MB);
  dummy_dealloc (sm, size_1MB);
  dummy_dealloc (sm, size_1MB);

  /* 0% in_use */
  SEG_MGR_TEST ((sm->reserved == 0), "sm->reserved %d", sm->reserved);
  SEG_MGR_TEST ((sm->in_use == 0), "sm->in_use %d", sm->in_use);
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_NO_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));

  segment_manager_del_sessions (sm);
  segment_manager_app_detach (sm);
  segment_manager_free (sm);

  return 0;
}

static int
fifo_tuning_logic_test_pressure_2 (vlib_main_t * vm, unformat_input_t * input)
{
  int rv;
  segment_manager_t *sm;
  uword seg_size = size_10MB;
  u32 prealloc_fifo = 0;

  sm = segment_manager_alloc ();
  SEG_MGR_TEST ((sm != 0), "segment_manager_alloc %p", sm);

  rv = segment_manager_init (sm, seg_size, prealloc_fifo, 80, 50);
  SEG_MGR_TEST ((rv == 0), "segment_manager_init %d", rv);

  SEG_MGR_TEST ((sm->in_use == 0), "sm->in_use %d", sm->in_use);
  SEG_MGR_TEST ((sm->pool_size == 0), "sm->pool_size %d", sm->pool_size);
  SEG_MGR_TEST ((sm->reserved == 0), "sm->reserved %d", sm->reserved);

  /* initial status */
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_NO_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));

  dummy_alloc (sm, size_2MB);
  dummy_alloc (sm, size_2MB);
  dummy_alloc (sm, size_2MB);
  dummy_alloc (sm, size_2MB);

  /* 80% in_use */
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_HIGH_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));

  /* change the high_watermark and low_watermark */
  segment_manager_set_watermarks (sm, 85, 55);
  SEG_MGR_TEST ((sm->high_watermark == 85),
		"sm->high_watermark %d", sm->high_watermark);
  SEG_MGR_TEST ((sm->low_watermark == 55),
		"sm->low_watermark %d", sm->low_watermark);

  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_LOW_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));

  dummy_dealloc (sm, size_2MB);
  dummy_dealloc (sm, size_2MB);
  dummy_dealloc (sm, size_2MB);
  dummy_dealloc (sm, size_2MB);

  /* 0% in_use */
  SEG_MGR_TEST ((sm->reserved == 0), "sm->reserved %d", sm->reserved);
  SEG_MGR_TEST ((sm->in_use == 0), "sm->in_use %d", sm->in_use);
  rv = segment_manager_get_mem_status (sm);
  SEG_MGR_TEST ((rv == MEM_PRESSURE_NO_PRESSURE),
		"segment_manager_get_mem_status %s", states_str (rv));

  segment_manager_del_sessions (sm);
  segment_manager_app_detach (sm);
  segment_manager_free (sm);

  return 0;
}



static int
fifo_tuning_logic_test_app_attach_1 (vlib_main_t * vm,
				     unformat_input_t * input)
{
  int rv;
  segment_manager_t *sm;
  uword app_seg_size = 2UL << 30;	/* 2GB */
  u64 options[APP_OPTIONS_N_OPTIONS];

  memset (&options, 0, sizeof (options));

  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &dummy_session_cbs,
    .name = format (0, "fifo_tuning_logic_test_app_attach_1"),
  };

  attach_args.options[APP_OPTIONS_SEGMENT_SIZE] = app_seg_size;
  attach_args.options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  rv = vnet_application_attach (&attach_args);
  SEG_MGR_TEST ((rv == 0), "vnet_application_attach %d", rv);

  sm =
    segment_manager_get (SEGMENT_MANAGER_GET_INDEX_FROM_HANDLE
			 (attach_args.segment_handle));
  SEG_MGR_TEST ((sm != 0), "sm %p", sm);
  SEG_MGR_TEST ((sm->in_use == 0), "sm->in_use %d", sm->in_use);
  SEG_MGR_TEST ((sm->pool_size == 0), "sm->pool_size %d", sm->pool_size);
  SEG_MGR_TEST ((sm->reserved == 0), "sm->reserved %d", sm->reserved);
  SEG_MGR_TEST ((sm->high_watermark == default_high_watermark),
		"sm->high_watermark %d", sm->high_watermark);
  SEG_MGR_TEST ((sm->low_watermark == default_low_watermark),
		"sm->low_watermark %d", sm->low_watermark);

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
fifo_tuning_logic_test_app_attach_2 (vlib_main_t * vm,
				     unformat_input_t * input)
{
  int rv;
  segment_manager_t *sm;
  uword app_seg_size = 2UL << 30;	/* 2GB */
  u8 hwm = 90, lwm = 60;
  u64 options[APP_OPTIONS_N_OPTIONS];

  memset (&options, 0, sizeof (options));

  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &dummy_session_cbs,
    .name = format (0, "fifo_tuning_logic_test_app_attach_2"),
  };

  attach_args.options[APP_OPTIONS_SEGMENT_SIZE] = app_seg_size;
  attach_args.options[APP_OPTIONS_HIGH_WATERMARK] = hwm;
  attach_args.options[APP_OPTIONS_LOW_WATERMARK] = lwm;
  attach_args.options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  rv = vnet_application_attach (&attach_args);
  SEG_MGR_TEST ((rv == 0), "vnet_application_attach %d", rv);

  sm =
    segment_manager_get (SEGMENT_MANAGER_GET_INDEX_FROM_HANDLE
			 (attach_args.segment_handle));
  SEG_MGR_TEST ((sm != 0), "sm %p", sm);
  SEG_MGR_TEST ((sm->in_use == 0), "sm->in_use %d", sm->in_use);
  SEG_MGR_TEST ((sm->pool_size == 0), "sm->pool_size %d", sm->pool_size);
  SEG_MGR_TEST ((sm->reserved == 0), "sm->reserved %d", sm->reserved);
  SEG_MGR_TEST ((sm->high_watermark == hwm),
		"sm->high_watermark %d", sm->high_watermark);
  SEG_MGR_TEST ((sm->low_watermark == lwm),
		"sm->low_watermark %d", sm->low_watermark);

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
      else if (unformat (input, "app_attach_1"))
	res = fifo_tuning_logic_test_app_attach_1 (vm, input);
      else if (unformat (input, "app_attach_2"))
	res = fifo_tuning_logic_test_app_attach_2 (vm, input);

      else if (unformat (input, "all"))
	{
	  if ((res = fifo_tuning_logic_test_basic (vm, input)))
	    goto done;
	  if ((res = fifo_tuning_logic_test_pressure_1 (vm, input)))
	    goto done;
	  if ((res = fifo_tuning_logic_test_pressure_2 (vm, input)))
	    goto done;
	  if ((res = fifo_tuning_logic_test_app_attach_1 (vm, input)))
	    goto done;
	  if ((res = fifo_tuning_logic_test_app_attach_2 (vm, input)))
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

