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
    {
      clib_warning ("DEBUG: Creating new ring buffer with name: %s", name);
      entry_index = vlib_stats_add_ring_buffer (&config, "%s", name);
    }
  else
    {
      clib_warning (
	"DEBUG: Found existing ring buffer with name: %s, entry_index: %u",
	name, entry_index);
    }
  if (entry_index == STAT_SEGMENT_INDEX_INVALID)
    return clib_error_return (0, "Failed to create/find ring buffer");

  // Debug: Print initial ring buffer state
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  vlib_stats_entry_t *e = vlib_stats_get_entry (sm, entry_index);
  vlib_stats_ring_buffer_t *ring_buffer = e->data;
  vlib_stats_ring_metadata_t *metadata =
    (vlib_stats_ring_metadata_t *) ((u8 *) ring_buffer +
				    ring_buffer->metadata_offset);
  clib_warning ("DEBUG: Initial ring buffer state - head: %u, sequence: %lu",
		metadata->head, metadata->sequence);

  for (i = 0; i < count; ++i)
    {
      msg.seq = i;
      msg.timestamp = vlib_time_now (vm);
      vlib_stats_ring_produce (entry_index, 0, &msg);

      // Debug: Print every 10th entry or last few entries
      if (i % 10 == 0 || i >= count - 5)
	{
	  clib_warning (
	    "DEBUG: Wrote entry %u - seq: %lu, head: %u, sequence: %lu", i,
	    msg.seq, metadata->head, metadata->sequence);
	}

      vlib_process_suspend (vm, 1e-6 * interval_usec);
    }

  // Debug: Print final ring buffer state
  clib_warning ("DEBUG: Final ring buffer state - head: %u, sequence: %lu",
		metadata->head, metadata->sequence);

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
