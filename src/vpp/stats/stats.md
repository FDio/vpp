# Statistics {#stats_doc}

In VPP most things are measured and counted. There are counters for interface statistics, like RX, TX counters, packet drops, and so on. Every node has a set of per-node counters, one set of error counters, like TTL exceeded, or packet to big or out-of-buffers. And a set of performance counters, like number of clocks, vectors, calls and suspends.

There is also a set of system counters and performance counters, e.g. memory utilization per heap, buffer utilisation and so on.

## VPP Counter Architecture

Counters are exposed directly via shared memory. These are the actual counters in VPP, no sampling or aggregation is done by the statistics infrastructure. With the exception of per node performance data under /sys/node and a few system counters.


Clients mount the shared memory segment read-only, using a optimistic concurrency algorithm.

Directory structure as an index.

### Memory layout

The memory segment consists of a shared header, containing atomics for the optimistic concurrency mechanism, and offsets into memory for the directory vectors. The only data structure used is the VPP vectors. All pointers are converted to offsets so that client applications can map the shared memory wherever it pleases.

### Directory layout

### Optimistic concurrency

```
/*
 * Shared header first in the shared memory segment.
 */
typedef struct {
  atomic_int_fast64_t epoch;
  atomic_int_fast64_t in_progress;
  atomic_int_fast64_t directory_offset;
  atomic_int_fast64_t error_offset;
  atomic_int_fast64_t stats_offset;
} stat_segment_shared_header_t;

```

#### Writer
On the VPP side there is a single writer (controlled by a spinlock). When the writer starts it sets in_progress=1, continues with the update of the data-structures, and when done, bumps epoch++ and sets in_progress=0.

#### Readers
If in_progress=1, there is no point continuing, so reader sits spinning on the in_progress flag until it is 0. Then it sets start_epoch = epoch and continues copying out the counter data it is interested in, while doing strict boundary checks on all offsets / pointers. When the reader is done, it checks if in_progress=1 or if epoch != start_epoch. If either of those are true is discards the data read.

## How are counters exposed out of VPP?

## Types of Counters

All counters under /err and /if are the directly exposed VPP counters.

* Gauges
* u64 / float
* Interface Counters
 * Simple counters, counter_t array of threads of an array of interfaces
 * Combined counters, vlib_counter_t array of threads of an array of interfaces.


## Client libraries
### Writing a new client library
A new client library can either wrap the C library (libvppapiclient.so) or it can integrate directly with the shared memory. That involves exchanging a file descriptor over the VPP stats Unix domain socket, and opening the memory mapped segment.

### Python

```
#!/usr/bin/env python
from vpp_papi.vpp_stats import VPPStats
stats = VPPStats('/var/run/stats.socks')
dir = stats.ls(['^/if', '/err/ip4-input', '/sys/node/ip4-input'])
counters = stats.dump(dir)

# Print the RX counters for the first interface on the first worker core
print ('RX interface core 0, sw_if_index 0', counters['/if/rx'][0][0])

```
### C
```
#include <vpp-api/client/stat_client.h>
#include <vppinfra/vec.h>

int main (int argc, char **argv) {
  uint8_t *patterns = 0;

  vec_add1(patterns, "^/if");
  vec_add1(patterns, "ip4-input");

  int rv = stat_segment_connect("/var/run/stats.sock");
  uint32_t *dir = stat_segment_ls(patterns);
  stat_segment_data_t *res = stat_segment_dump(dir);

  for (int i = 0; i < vec_len(res); i++) {
    switch (res[i].type) {
      case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
      for (k = 0; k < vec_len (res[i].simple_counter_vec) - 1; k++)
        for (j = 0; j < vec_len (res[i].simple_counter_vec[k]); j++)
          fformat (stdout, "[%d @ %d]: %llu packets %s\n",
                   j, k, res[i].simple_counter_vec[k][j],
                   res[i].name);
      break;

      case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
        for (k = 0; k < vec_len (res[i].combined_counter_vec); k++)
          for (j = 0; j < vec_len (res[i].combined_counter_vec[k]); j++)
            fformat (stdout, "[%d @ %d]: %llu packets, %llu bytes %s\n",
                     j, k, res[i].combined_counter_vec[k][j].packets,
                     res[i].combined_counter_vec[k][j].bytes,
                     res[i].name);
      break;

      case STAT_DIR_TYPE_ERROR_INDEX:
        fformat (stdout, "%llu %s\n", res[i].error_value, res[i].name);
      break;

      case STAT_DIR_TYPE_SCALAR_INDEX:
        fformat (stdout, "%.2f %s\n", res[i].scalar_value, res[i].name);
      break;

      default:
        ;
    }
  }
  stat_segment_data_free (res);
}
```

## Integrations
* CLI command. vpp_get_stats [ls | dump | poll]
* Prometheus

## Future evolution
* Deprecate the stats over binary API calls that are based on want_stats
