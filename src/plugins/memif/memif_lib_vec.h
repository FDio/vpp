#ifndef _MEMIF_LIB_VEC_H_
#define _MEMIF_LIB_VEC_H_

#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
typedef uint64_t bitmap_t;

/* bitmap type width */
#define BITMAP_W (sizeof (bitmap_t) * CHAR_BIT)
/* bitmap array width */
#define MAX_BITMAP_W (v) (BITMAP_W * v->bitmap_len)

typedef struct
{
  bitmap_t *bitmap;
  uint16_t bitmap_len;
  ssize_t size;
  char data[0];
} vector_t;

static inline uint64_t
vec_get_final_index (vector_t *v)
{
    int i;
    for (i = v->bitmap_len - 1; i >= 0; i--)
    {
      if (v->bitmap[i] == 0)
        continue;
      return ((BITMAP_W - __builtin_clzl (v->bitmap[i])) + (i * BITMAP_W));
    }
    return 0;
}

static inline vector_t *
vec_get_hdr (void * pool)
{
    return (vector_t *) (pool - sizeof (vector_t));
}

static inline void
vec_free (void * pool)
{
    if (pool == NULL)
        return;
    vector_t *v = vec_get_hdr (pool);
    free (v);
    v = NULL;
}

static inline void *
vec_init (ssize_t size)
{
    vector_t *v = (vector_t *) malloc (sizeof (vector_t) +
                    (size * BITMAP_W));
    v->size = size;
    v->bitmap = (bitmap_t *) malloc (sizeof (bitmap_t));
    memset (v->bitmap, 0, sizeof (bitmap_t));
    v->bitmap_len = 1;
    return v->data;
}

static inline void *
vec_realloc (vector_t ** v)
{
    *v = (vector_t *) realloc (*v, sizeof (vector_t) +
                                ((*v)->size * BITMAP_W * (*v)->bitmap_len * 2));
    (*v)->bitmap = (bitmap_t *) realloc ((*v)->bitmap, sizeof (bitmap_t) * (*v)->bitmap_len * 2);
    (*v)->bitmap[(*v)->bitmap_len] = 0;
    (*v)->bitmap_len++;
    
    /* TODO: error handling */
    
    return (void *) (*v)->data;
}

static inline void *
vec_get (void ** pool)
{
    vector_t *v = vec_get_hdr (*pool);
    uint32_t i,e;
    for (e = 0; e < v->bitmap_len; e++)
    {
        if (v->bitmap[e] == (-1))
        {
            *pool = vec_realloc (&v);
            continue;
        }
        for (i = 0; i < BITMAP_W; i++)
        {
            if (((1 << i) & v->bitmap[e]) == 0)
                {
                    v->bitmap[e] |= 1 << i;
                    return v->data + (v->size * i) +
                            (e * v->size * BITMAP_W);
                }
        }
    }
    return NULL;
}

static inline void
vec_set_at_index (void * set, uint64_t index, void ** pool)
{
    vector_t *v = vec_get_hdr (*pool);
    uint32_t i = index % BITMAP_W;
    uint32_t e = index / BITMAP_W;
    while (e >= v->bitmap_len)
        *pool = vec_realloc (&v);
    v->bitmap[e] |= (1 << i);
    memcpy (v->data + (v->size * i) + (e * v->size * BITMAP_W),
        set, v->size);
}

static inline void *
vec_get_next (long *last_index, void * pool)
{
    vector_t *v = vec_get_hdr (pool);
    (*last_index)++;
    uint32_t index;
    uint16_t e;
    uint64_t final_index = vec_get_final_index (v);
    while (*last_index < final_index)
    {
        index = *last_index % BITMAP_W;
        e = *last_index / BITMAP_W;
        if (v->bitmap[e] < (1 << index))
            {
                (*last_index) += BITMAP_W - index;
                continue;
            }
        if ((1 << index) & v->bitmap[e])
            return v->data + (v->size * *last_index);
        (*last_index)++;
    }
    return NULL;
}

static inline void
vec_free_at_index (uint64_t index, void * pool)
{
    vector_t *v = vec_get_hdr (pool);
    uint32_t i = index % BITMAP_W;
    uint32_t e = index / BITMAP_W;
    if (e >= v->bitmap_len)
        return;
    v->bitmap[e] &= ~(1 << i);
}

static inline void
vec_free_ptr (void * ptr, void * pool)
{
    vec_free_at_index ((uint64_t) (ptr - pool), pool);
}

static inline void *
vec_get_at_index (uint64_t index, void * pool)
{
    vector_t *v = vec_get_hdr (pool);
    uint32_t i = index % BITMAP_W;
    uint32_t e = index / BITMAP_W;
    if (e >= v->bitmap_len)
        return NULL;
    if (v->bitmap[e] & (1 << i))
        return v->data + (v->size * index);
    return NULL;
}

static inline uint64_t
vec_get_len (void * pool)
{
    vector_t *v = vec_get_hdr (pool);
    uint16_t e;
    uint32_t res = 0;
    for (e = 0; e < v->bitmap_len; e++)
    {
      res += __builtin_popcount (v->bitmap[e]);
    }
    return res;
}

#endif
