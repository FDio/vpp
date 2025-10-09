#ifndef __included_lookup_parser_h__
#define __included_lookup_parser_h__
#include <vlib/vlib.h>
#include <vppinfra/cpu.h>
#include <vnet/sfdp/common.h>
#include <vnet/sfdp/sfdp.h>

#define SFDP_PARSER_MAX_KEY_SIZE 64
typedef u8 calc_key_fn_t (vlib_buffer_t *b, u32 context_id, void *skey,
			  u64 *lookup_val, u64 *h, i16 *l4_hdr_offset,
			  u8 slowpath);

typedef void normalize_key_fn_t (sfdp_session_t *session, void *result,
				 u8 key_idx);

enum
{
  SFDP_PARSER_FORMAT_FUNCTION_INGRESS,
  SFDP_PARSER_FORMAT_FUNCTION_EGRESS,
  SFDP_PARSER_FORMAT_FUNCTION_CONTEXT,
  SFDP_PARSER_N_FORMAT_FUNCTION
};

/* Per march parser registration structure */
typedef struct
{
  char *name;
  calc_key_fn_t *const calc_key_fn;
  const uword key_size;
  const uword proto_offset;
  sfdp_session_type_t type;
  format_function_t *format_fn[SFDP_PARSER_N_FORMAT_FUNCTION];
  normalize_key_fn_t *normalize_key_fn;

} sfdp_parser_registration_t;

typedef struct _sfdp_parser_registration_mutable_t
{
  struct _sfdp_parser_registration_mutable_t *next;
  uword key_size;
  uword sfdp_parser_data_index;
  char *name;
  vlib_node_registration_t *node_reg;
  format_function_t *const *format_fn;
  normalize_key_fn_t *normalize_key_fn;
} sfdp_parser_registration_mutable_t;

typedef void sfdp_parser_bihash_init_fn_t (void *bihash, char *name,
					   u32 nbuckets, uword memory_size);
typedef int sfdp_parser_bihash_add_del_fn_t (void *bihash, void *kv,
					     int is_add);
typedef u64 sfdp_parser_bihash_hash_fn_t (void *kv);
typedef void sfdp_parser_bihash_prefetch_bucket_fn_t (void *bihash, u64 hash);
typedef int sfdp_parser_bihash_search_with_hash_fn_t (void *bihash, u64 hash,
						      void *kv_result);

typedef int sfdp_parser_bihash_add_del_with_hash_fn_t (
  void *bihash, void *kv, u64 hash, u8 is_add, void *is_stale_cb,
  void *is_stale_arg, void *overwrite_cb, void *overwrite_arg);

/* Per march bihash vfts */
typedef struct
{
  sfdp_parser_bihash_init_fn_t *const sfdp_parser_bihash_init_fn;
  sfdp_parser_bihash_add_del_fn_t *const sfdp_parser_bihash_add_del_fn;
  sfdp_parser_bihash_hash_fn_t *const sfdp_parser_bihash_hash_fn;
  sfdp_parser_bihash_prefetch_bucket_fn_t
    *const sfdp_parser_bihash_prefetch_bucket_fn;
  sfdp_parser_bihash_search_with_hash_fn_t
    *const sfdp_parser_bihash_search_with_hash_fn;
  /*  sfdp_parser_bihash_add_del_with_hash_fn_t *const
   * sfdp_parser_bihash_add_del_with_hash_fn; */
  uword table_size;
} sfdp_parser_bihash_registration_t;

typedef struct
{
  void *bihash_table;
  void **keys_ptd; /* per thread vector of VLIB_FRAME_SIZE keys */
  void **kv_ptd;   /* per thread vector of kv */
  uword key_size;
  char *name;
  format_function_t *const *format_fn;
  normalize_key_fn_t *normalize_key_fn;
} sfdp_parser_data_t;

typedef struct
{
  sfdp_parser_data_t *parsers;
  sfdp_parser_registration_mutable_t *regs;
  uword *parser_index_per_name;
} sfdp_parser_main_t;

#ifndef CLIB_MARCH_VARIANT
#define SFDP_PARSER_REGISTER(x)                                               \
  static const sfdp_parser_registration_t sfdp_parser_registration_##x;       \
  sfdp_parser_registration_mutable_t sfdp_parser_registration_mutable_##x;    \
  static void __sfdp_parser_registration_mutable_add_registration__##x (void) \
    __attribute__ ((__constructor__));                                        \
  static void __sfdp_parser_registration_mutable_add_registration__##x (void) \
  {                                                                           \
    sfdp_parser_main_t *pm = &sfdp_parser_main;                               \
    sfdp_parser_registration_mutable_t *r =                                   \
      &sfdp_parser_registration_mutable_##x;                                  \
    r->next = pm->regs;                                                       \
    r->key_size = sfdp_parser_registration_##x.key_size;                      \
    r->name = sfdp_parser_registration_##x.name;                              \
    r->format_fn = sfdp_parser_registration_##x.format_fn;                    \
    r->normalize_key_fn = sfdp_parser_registration_##x.normalize_key_fn;      \
    pm->regs = r;                                                             \
  }                                                                           \
  static const sfdp_parser_registration_t sfdp_parser_registration_##x
#else
#define SFDP_PARSER_REGISTER(x)                                               \
  extern sfdp_parser_registration_mutable_t                                   \
    sfdp_parser_registration_mutable_##x;                                     \
  static sfdp_parser_registration_t sfdp_parser_registration_##x
#endif

extern sfdp_parser_main_t sfdp_parser_main;

#endif /*__included_lookup_parser_h__*/