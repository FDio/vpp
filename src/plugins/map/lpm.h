#include <vppinfra/types.h>
#include <vppinfra/bihash_16_8.h>

enum lpm_type_e {
  LPM_TYPE_KEY32,
  LPM_TYPE_KEY128,
};

typedef struct lpm_ {
  void (*add) (struct lpm_ *lpm, void *addr_v, u8 pfxlen, u32 value);
  void (*delete) (struct lpm_ *lpm, void *addr_v, u8 pfxlen);
  u32 (*lookup) (struct lpm_ *lpm, void *addr_v, u8 pfxlen);

  uword *hash[33];
  BVT (clib_bihash) bihash;
  uword *prefix_lengths_bitmap;
  u32 prefix_length_refcount[129];
} lpm_t;

lpm_t *lpm_table_init (enum lpm_type_e lpm_type);
