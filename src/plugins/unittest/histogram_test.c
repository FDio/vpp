#include <vlib/vlib.h>
#include <vlib/stats/stats.h>
#include <vlib/cli.h>
#include <vlib/counter.h>
#include <vppinfra/time.h>

// Histogram test main structure
static vlib_log2_histogram_main_t histogram_test_main;

static clib_error_t *
histogram_gen_command_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  u8 *name = 0;
  u32 count = 1000;
  u32 interval_usec = 1000;
  u32 min_exp = 0;   // Minimum exponent (2^0 = 1)
  u32 num_bins = 16; // Number of bins
  u32 i;
  u32 value;

  // Parse CLI arguments
  if (!unformat (input, "%s %u %u %u %u", &name, &count, &interval_usec,
		 &min_exp, &num_bins))
    {
      // Try without min_exp and num_bins (for backward compatibility)
      if (!unformat (input, "%s %u %u", &name, &count, &interval_usec))
	return clib_error_return (
	  0,
	  "parse error: '%U'\nUsage: test stats histogram-gen <name> "
	  "<count> <interval-usec> [min-exp] [num-bins]",
	  format_unformat_error, input);
    }

  // Initialize histogram
  histogram_test_main.name = (char *) name;
  histogram_test_main.min_exp = min_exp;
  vlib_validate_log2_histogram (&histogram_test_main, num_bins);

  clib_warning ("DEBUG: Created histogram '%s' with min_exp=%u, num_bins=%u",
		name, min_exp, num_bins);

  // Generate test data with different distributions
  for (i = 0; i < count; ++i)
    {
      // Generate different types of values for testing
      if (i % 4 == 0)
	{
	  // Small values (0-15)
	  value = i % 16;
	}
      else if (i % 4 == 1)
	{
	  // Medium values (16-255)
	  value = 16 + (i % 240);
	}
      else if (i % 4 == 2)
	{
	  // Large values (256-4095)
	  value = 256 + (i % 3840);
	}
      else
	{
	  // Very large values (4096+)
	  value = 4096 + (i % 10000);
	}

      // Calculate bin index and increment
      u8 bin = vlib_log2_histogram_bin_index (&histogram_test_main, value);
      vlib_increment_log2_histogram_bin (&histogram_test_main, 0, bin, 1);

      // Debug: Print every 100th entry or last few entries
      if (i % 100 == 0 || i >= count - 5)
	{
	  clib_warning ("DEBUG: Entry %u - value: %u, bin: %u (2^%u = %u)", i,
			value, bin, min_exp + bin, 1ULL << (min_exp + bin));
	}

      vlib_process_suspend (vm, 1e-6 * interval_usec);
    }

  vlib_cli_output (
    vm, "Generated %u histogram entries for '%s' (min_exp=%u, bins=%u)", count,
    name, min_exp, num_bins);
  return 0;
}

VLIB_CLI_COMMAND (histogram_gen_command, static) = {
  .path = "test stats histogram-gen",
  .short_help = "test stats histogram-gen <name> <count> <interval-usec> "
		"[min-exp] [num-bins]",
  .function = histogram_gen_command_fn,
};

static clib_error_t *
histogram_clear_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  u8 *name = 0;
  u32 entry_index;

  if (!unformat (input, "%s", &name))
    return clib_error_return (
      0, "parse error: '%U'\nUsage: test stats histogram-clear <name>",
      format_unformat_error, input);

  entry_index = vlib_stats_find_entry_index ("%s", name);
  if (entry_index == STAT_SEGMENT_INDEX_INVALID)
    {
      return clib_error_return (0, "Histogram '%s' not found", name);
    }

  vlib_stats_remove_entry (entry_index);
  vlib_cli_output (vm, "Cleared histogram '%s'", name);
  return 0;
}

VLIB_CLI_COMMAND (histogram_clear_command, static) = {
  .path = "test stats histogram-clear",
  .short_help = "test stats histogram-clear <name>",
  .function = histogram_clear_command_fn,
};