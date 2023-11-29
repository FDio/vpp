#include <vnet/vnet.h>
#include <stdbool.h>

#define QUEUE_SIZE 1000
#define NULL_BUFFER_T (buffer_t) { .pkt_data.finish_time = ~0, .pkt_data.pkt_index = ~0 }

typedef struct {
    u32 pkt_index;
    unsigned long long finish_time;
} pkt_data_t;

typedef union {
    u32 pkt_index;
    pkt_data_t pkt_data;
} buffer_t;

typedef struct {
    buffer_t buffer[QUEUE_SIZE];
    int begin;
    int end;
    int size;
    int count;
    bool is_init;
} ring_buffer_t;

void init_ring_buffer(ring_buffer_t *buf);
void ring_buffer_push(ring_buffer_t *buf, buffer_t data);
bool ring_buffer_empty(ring_buffer_t *buf);
buffer_t ring_buffer_pop(ring_buffer_t *buf);
buffer_t ring_buffer_front(ring_buffer_t *buf);
buffer_t ring_buffer_back(ring_buffer_t *buf);