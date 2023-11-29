#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/ip/ip4.h>
#include "ring_buffer.h"

#define MAX_CLASS 256

typedef struct {
    clib_bitmap_t *class_bitmap;
    ring_buffer_t queue_map[MAX_CLASS];
    unsigned long long num_round;
    int num_bit_excess;
} sch_fq_buffer_t;

typedef struct {
    int queue_i;
    int pos;
    unsigned long long start_time;
    unsigned long long finish_time;
} trace_en_t;

typedef struct {
    int queue_i;
    int pos;
    int rem_pkt;
    unsigned long long num_round;
} trace_de_t;

extern sch_fq_buffer_t *fq_buffer;