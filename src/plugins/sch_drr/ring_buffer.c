#include "ring_buffer.h"

void init_ring_buffer (ring_buffer *buf) {
    buf->begin = 0;
    buf->end = 0;
    buf->size = QUEUE_SIZE;
    buf->count = 0;
    buf->is_init = true;
}

void ring_buffer_push(ring_buffer *buf, u32 data) {
    if (buf->count < buf->size) {
        buf->buffer[buf->end] = data;
        buf->end = (buf->end+1)%buf->size;
        buf->count++;
    }
}

u32 ring_buffer_pop(ring_buffer *buf) {
    if (buf->count > 0) {
        int begin_temp = buf->begin;
        buf->begin = (buf->begin+1)%buf->size;
        buf->count--;
        return buf->buffer[begin_temp];
    }
    return ~0;
}

u32 ring_buffer_front (ring_buffer *buf) {
    if (buf->count > 0)
        return buf->buffer[buf->begin];
    return ~0;
}