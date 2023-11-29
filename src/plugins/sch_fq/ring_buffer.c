#include "ring_buffer.h"

void init_ring_buffer (ring_buffer_t *buf) {
    buf->begin = 0;
    buf->end = 0;
    buf->size = QUEUE_SIZE;
    buf->count = 0;
    buf->is_init = true;
}

void ring_buffer_push(ring_buffer_t *buf, buffer_t data) {
    if (buf->count < buf->size) {
        buf->buffer[buf->end] = data;
        buf->end = (buf->end+1)%buf->size;
        buf->count++;
    }
}

bool ring_buffer_empty (ring_buffer_t *buf) {
  return !(buf->count);
}

buffer_t ring_buffer_pop(ring_buffer_t *buf) {
    if (buf->count > 0) {
        int begin_temp = buf->begin;
        buf->begin = (buf->begin+1)%buf->size;
        buf->count--;
        return buf->buffer[begin_temp];
    }
    return NULL_BUFFER_T;
}

buffer_t ring_buffer_front (ring_buffer_t *buf) {
    if (buf->count > 0)
        return buf->buffer[buf->begin];
    return NULL_BUFFER_T;
}

buffer_t ring_buffer_back (ring_buffer_t *buf) {
    if (buf->count > 0)
        return buf->buffer[buf->end - 1];
    return NULL_BUFFER_T;
}