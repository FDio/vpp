#include <vlib/vlib.h>
#include <vlib/stats/stats.h>
#include <vlib/cli.h>
#include <vppinfra/time.h>

// Message struct for the ring buffer
typedef struct
{
  u64 seq;
  f64 timestamp;
} ring_test_msg_t;

static clib_error_t *
ring_buffer_gen_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  u8 *name = 0;
  u32 count = 1000;
  u32 interval_usec = 1000;
  u32 ring_size = 16; // Default ring size
  u32 i;
  vlib_stats_ring_config_t config;
  u32 entry_index;
  ring_test_msg_t msg;

  // Parse CLI arguments
  if (!unformat (input, "%s %u %u %u", &name, &count, &interval_usec,
		 &ring_size))
    {
      // Try without ring_size (for backward compatibility)
      if (!unformat (input, "%s %u %u", &name, &count, &interval_usec))
	return clib_error_return (
	  0,
	  "parse error: '%U'\nUsage: test stats ring-buffer-gen <name> "
	  "<count> <interval-usec> [ring-size]",
	  format_unformat_error, input);
    }

  config.entry_size = sizeof (ring_test_msg_t);
  config.ring_size = ring_size;
  config.n_threads = 1;

  // Create or find the ring buffer
  entry_index = vlib_stats_find_entry_index ("%s", name);
  if (entry_index == STAT_SEGMENT_INDEX_INVALID)
    entry_index = vlib_stats_add_ring_buffer (&config, "%s", name);
  if (entry_index == STAT_SEGMENT_INDEX_INVALID)
    return clib_error_return (0, "Failed to create/find ring buffer");

  for (i = 0; i < count; ++i)
    {
      msg.seq = i;
      msg.timestamp = vlib_time_now (vm);
      vlib_stats_ring_produce (entry_index, 0, &msg);
      vlib_process_suspend (vm, 1e-6 * interval_usec);
    }

  vlib_cli_output (vm,
		   "Generated %u messages to ring buffer '%s' (ring size %u)",
		   count, name, ring_size);
  return 0;
}

VLIB_CLI_COMMAND (ring_buffer_gen_command, static) = {
  .path = "test stats ring-buffer-gen",
  .short_help =
    "test stats ring-buffer-gen <name> <count> <interval-usec> [ring-size]",
  .function = ring_buffer_gen_command_fn,
};
