#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/ip/ip4.h>
#include "ring_buffer.h"

#define MAX_CLASS 256

typedef struct {
    unsigned int quantum_size;
    clib_bitmap_t *class_bitmap;
    unsigned int deficit_counter[MAX_CLASS];
    ring_buffer queue_map[MAX_CLASS];
} sch_drr_buffer_t;

typedef struct {
    int queue_i;
    int pos;
} trace_en_t;

typedef struct {
    int queue_i;
    int pos;
    int rem_pkt;
} trace_de_t;

extern sch_drr_buffer_t *drr_buffer;