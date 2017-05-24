#ifndef _ACL_HASH_LOOKUP_TYPES_H_
#define _ACL_HASH_LOOKUP_TYPES_H_

/* The structure representing the single entry with hash representation */
typedef struct {
  /* these two are mostly for easily tracing what belongs where */
  u32 acl_index;
  u32 ace_index;
  
  u32 mask_type_index;
  u8 src_portrange_not_powerof2;
  u8 dst_portrange_not_powerof2;

  fa_5tuple_t match;
  u8 action;
} hash_ace_info_t;

/* 
 * The structure holding the information necessary for the hash-based ACL operation
 */
typedef struct {
  /* The mask types present in this ACL */
  uword *mask_type_index_bitmap;
  hash_ace_info_t *rules;
} hash_acl_info_t;

typedef struct {
  /* original non-compiled ACL */
  u32 acl_index;
  u32 ace_index;

  u32 hash_ace_info_index;
} applied_ace_hash_entry_t;


typedef union {
  u64 as_u64;
  struct {
    u32 applied_entry_index;
    u16 reserved_u16;
    u8 reserved_u8;
    /* means there is some other entry in front intersecting */
    u8 shadowed:1;
    u8 need_portrange_check:1;
    u8 reserved_flags:6;
  };
} hash_acl_lookup_value_t;

#define CT_ASSERT_EQUAL(name, x,y) typedef int assert_ ## name ## _compile_time_assertion_failed[((x) == (y))-1]

CT_ASSERT_EQUAL(hash_acl_lookup_value_t_is_u64, sizeof(hash_acl_lookup_value_t), sizeof(u64));

#undef CT_ASSERT_EQUAL

#endif
