#include <vnet/vnet.h>
#include <stdbool.h>

#define QUEUE_SIZE 1000

typedef struct {
    u32 buffer[QUEUE_SIZE];
    int begin;
    int end;
    int size;
    int count;
    bool is_init;
} ring_buffer;

void init_ring_buffer(ring_buffer *buf);
void ring_buffer_push(ring_buffer *buf, u32 data);
u32 ring_buffer_pop(ring_buffer *buf);