#include <vnet/vnet.h>
#include <stdbool.h>

#define QUEUE_SIZE 1000

typedef struct {
    u32 pkt_index;
    unsigned long long finish_time;
} pkt_data_t;

typedef union {
    u32 pkt_index;
    pkt_data_t pkt_data;
} buffer_t;

typedef struct {
    u32 buffer[QUEUE_SIZE];
    int begin;
    int end;
    int size;
    int count;
    bool is_init;
} ring_buffer_t;

void init_ring_buffer(ring_buffer_t *buf);
void ring_buffer_push(ring_buffer_t *buf, u32 data);
bool ring_buffer_empty(ring_buffer_t *buf);
u32 ring_buffer_pop(ring_buffer_t *buf);
u32 ring_buffer_front(ring_buffer_t *buf);
u32 ring_buffer_back(ring_buffer_t *buf);