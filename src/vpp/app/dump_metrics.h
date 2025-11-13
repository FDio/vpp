#ifndef DUMP_METRICS_H
#define DUMP_METRICS_H
#include <vpp-api/client/stat_client.h>
#include <vlib/vlib.h>
#include <stdio.h>
void dump_metrics (FILE *stream, u8 **patterns, u8 v2, stat_client_main_t *shm);
#endif /* DUMP_METRICS_H */