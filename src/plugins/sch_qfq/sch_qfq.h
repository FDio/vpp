#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/ip/ip4.h>
#include "ring_buffer.h"
#include <stdio.h>
#include <stdlib.h>
#include "tgmath.h"
#include <math.h>

#ifndef max
    #define max(a,b) ((a) > (b) ? (a) : (b))
#endif


#define MAX_CLASS 256
#define MAX_GROUP 32
#define MAX_BUCKET 64

enum state_t{ER = 0, EB = 1, IR = 2, IB = 3, IDLE = 4};

typedef struct flow_t flow_t;

struct flow_t {
    ring_buffer_t pkt_queue;
    unsigned long long start_time;
    unsigned long long finish_time;
    u16 group_index;
    int lmax;
    int bucket;
    flow_t* next_flow;
    flow_t* prev_flow;
    u8 id; //debug
};

typedef struct {
    unsigned long long approx_start_time;
    unsigned long long approx_finish_time;
    unsigned long long slot_size;
    flow_t* bucket_list[MAX_BUCKET];
    clib_bitmap_t* bucket_bitmap;
} group_t;

typedef struct {
    flow_t flow_map[MAX_CLASS];
    group_t group_map[MAX_GROUP];
    unsigned long long virtual_time;
    clib_bitmap_t* state_bitmaps[5];
    clib_bitmap_t* tool_bitmap;
} sch_qfq_buffer_t;

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
    unsigned long long virtual_time;
} trace_de_t;

extern sch_qfq_buffer_t *qfq_buffer;