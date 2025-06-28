#include <vlib/vlib.h>
#include <vppinfra/vec.h>
#include <vppinfra/pool.h>
#include <vppinfra/cache.h>

/*----------------------------------------------------------------------*
 * Bit-packing macros: steal one bit from the 32-bit session index
 * to store the visited flag.
 *----------------------------------------------------------------------*/
#define NAT_FIFO_PACK(idx, visited) ((((visited) & 1) << 31) | ((idx) & 0x7fffffff))
#define NAT_FIFO_UNPACK_IDX(val)      ((val) & 0x7fffffff)
#define NAT_FIFO_UNPACK_VISITED(val)  (((val) >> 31) & 1)

/*----------------------------------------------------------------------*
 * NAT FIFO structure (ring buffer). Use a power-of-2 size.
 *----------------------------------------------------------------------*/
typedef struct {
    u32 head;          // Index of the first element
    u32 tail;          // Index of the next free slot
    u32 size;          // Capacity (must be power-of-2)
    u32 mask;          // mask = size - 1
    u32 *entries;      // Ring buffer of packed u32 values
} nat_session_fifo_t;

/*----------------------------------------------------------------------*
 * Initialize the FIFO with a given capacity (power-of-2).
 *----------------------------------------------------------------------*/
static inline void __attribute__((always_inline))
nat_fifo_init (nat_session_fifo_t *fifo, u32 capacity)
{
    ASSERT ((capacity & (capacity - 1)) == 0); // must be power-of-2
    fifo->size = capacity;
    fifo->mask = capacity - 1;
    fifo->head = fifo->tail = 0;
    vec_validate (fifo->entries, capacity - 1);
}

/*----------------------------------------------------------------------*
 * Enqueue a new session index with the visited flag.
 * Returns 0 on success, -1 if the FIFO is full.
 *----------------------------------------------------------------------*/
static inline int __attribute__((always_inline))
nat_fifo_enqueue (nat_session_fifo_t *fifo, u32 session_index, u8 visited)
{
    u32 next_tail = (fifo->tail + 1) & fifo->mask;
    if (next_tail == fifo->head)
        return -1;  // FIFO is full

    fifo->entries[fifo->tail] = NAT_FIFO_PACK(session_index, visited);
    fifo->tail = next_tail;
    return 0;
}

/*----------------------------------------------------------------------*
 * Dequeue the FIFO entry at the head.
 * Returns 0 on success, -1 if the FIFO is empty.
 *----------------------------------------------------------------------*/
static inline int __attribute__((always_inline))
nat_fifo_dequeue (nat_session_fifo_t *fifo, u32 *packed_entry)
{
    if (fifo->head == fifo->tail)
        return -1; // FIFO is empty

    *packed_entry = fifo->entries[fifo->head];
    fifo->head = (fifo->head + 1) & fifo->mask;
    return 0;
}

/*----------------------------------------------------------------------*
 * Requeue an entry at the tail (used to give a second chance).
 *----------------------------------------------------------------------*/
static inline void __attribute__((always_inline))
nat_fifo_requeue (nat_session_fifo_t *fifo, u32 packed_entry)
{
    /* We assume there is room since we are requeuing an entry we just removed. */
    fifo->entries[fifo->tail] = packed_entry;
    fifo->tail = (fifo->tail + 1) & fifo->mask;
}

/*----------------------------------------------------------------------*
 * Eviction loop (SIEVE-style lazy promotion) with prefetching.
 * 
 * 'session_pool' is a VPP pool of nat_session_t, which must have:
 *   - s->last_heard: timestamp
 *   - s->timeout: allowed inactivity period
 *
 * 'now' is the current timestamp.
 * 'max_sweep' is the maximum number of entries to process.
 *----------------------------------------------------------------------*/
void
nat_fifo_eviction_pass (nat_session_fifo_t *fifo,
                        nat_session_t *session_pool,
                        u32 now,
                        u32 max_sweep)
{
    u32 packed_entry;
    u32 count = 0;

    while (count < max_sweep && nat_fifo_dequeue(fifo, &packed_entry) == 0)
    {
        u32 session_index = NAT_FIFO_UNPACK_IDX(packed_entry);
        u8 visited = NAT_FIFO_UNPACK_VISITED(packed_entry);
        nat_session_t *s = pool_elt_at_index(session_pool, session_index);

        /* Prefetch the next FIFO entry to hide memory latency */
        if (((fifo->head + 1) & fifo->mask) != fifo->tail)
            __builtin_prefetch(&fifo->entries[(fifo->head + 1) & fifo->mask], 0, 1);

        /* Prefetch the session structure for the next iteration */
        __builtin_prefetch(s, 0, 1);

        /* If session is still active, requeue it */
        if ((now - s->last_heard) < s->timeout) {
            packed_entry = NAT_FIFO_PACK(session_index, 0); // reset visited
            nat_fifo_requeue(fifo, packed_entry);
            count++;
            continue;
        }

        /* If expired by time but was recently visited, give a second chance */
        if (visited) {
            packed_entry = NAT_FIFO_PACK(session_index, 0); // reset visited
            nat_fifo_requeue(fifo, packed_entry);
        } else {
            /* Evict session: remove from pool and associated structures */
            pool_put(session_pool, s);
            /* Optionally remove from bihash here */
        }
        count++;
    }
}

/*----------------------------------------------------------------------*
 * Free the FIFO vector.
 *----------------------------------------------------------------------*/
static inline void __attribute__((always_inline))
nat_fifo_free (nat_session_fifo_t *fifo)
{
    vec_free (fifo->entries);
}

