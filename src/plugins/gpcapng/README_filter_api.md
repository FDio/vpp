# GPCAPNG Filter API

This document explains the pluggable filter API for the GPCAPNG plugin.

## Overview

The GPCAPNG plugin has been refactored to support pluggable filter implementations. The main plugin (`gpcapng`) provides the packet capture infrastructure and a generic API for filter implementations. Filter implementations are separate plugins that register themselves with the main plugin.

## Architecture

### Main Plugin (gpcapng)

The main plugin provides:
- Packet capture infrastructure
- Destination management (file, HTTP)
- Filter API management
- CLI commands for filter switching and management

### Filter Plugins

Filter plugins register with the main plugin and provide:
- Packet classification logic
- Custom CLI commands for configuration
- Filter-specific configuration management

## API Definition

Filter implementations must provide a classification function with this signature:

```c
typedef void (*gpcapng_filter_classify_fn_t) (
  /* API version - implementations MUST check this */
  u32 api_version,
  /* Input: buffers to classify */
  vlib_buffer_t **bufs,
  u32 n_buffers,
  /* Input: frame info */
  vlib_main_t *vm,
  vlib_node_runtime_t *node, 
  vlib_frame_t *frame,
  int is_output,
  /* Output: destination indices for each buffer */
  u32 *dest_indices,
  /* Output: statistics (can be NULL) */
  u32 *n_matched,
  u32 *n_captured
);
```

## Example: Simple Filter

The `gpcapng-simple-filter` plugin demonstrates how to create a filter implementation:

```c
/* Register the filter implementation */
static clib_error_t *
simple_filter_init (vlib_main_t *vm)
{
  gpcapng_filter_impl_t impl = {
    .name = "simple",
    .description = "Simple GENEVE filter with 5-tuple and option matching",
    .api_version = GPCAPNG_FILTER_API_VERSION,
    .classify_fn = simple_filter_classify,
    .priority = 100,  /* Default priority */
  };

  int rv = gpcapng_register_filter_impl (&impl);
  if (rv != 0)
    {
      return clib_error_return (0, "Failed to register simple filter implementation (error %d)", rv);
    }

  return 0;
}

VLIB_INIT_FUNCTION (simple_filter_init);
```

## CLI Commands

### Show available filter implementations
```
vpp# show gpcapng filter-implementations
```

### Set active filter implementation
```
vpp# gpcapng set-filter-implementation simple
```

### Original filter commands still work
All existing `gpcapng filter` commands continue to work with the simple filter implementation.

## Creating Custom Filter Implementations

To create a custom filter:

1. Create a new plugin directory (e.g., `src/plugins/my-custom-filter`)
2. Implement the filter classification function
3. Register the filter implementation in your plugin's init function
4. Add any custom CLI commands for configuration
5. Build and load your plugin

The classification function receives a vector of buffers and must set the `dest_indices` array to indicate which destination each packet should be sent to, or `~0` for no capture.

## Benefits

- **Modularity**: Filter logic is separate from capture infrastructure
- **Performance**: Only the filter logic that's needed is loaded
- **Extensibility**: Easy to add new filter types without modifying the main plugin
- **Compatibility**: Existing configurations continue to work with the simple filter
- **Flexibility**: Different filters can be switched at runtime