#ifndef __included_simple_filter_h__
#define __included_simple_filter_h__

#include <stdbool.h>
#include "filter.h"

/* GENEVE header structure */
typedef struct
{
  u8 ver_opt_len;
  u8 flags;
  u16 protocol;
  u8 vni[3];
  u8 reserved;
} geneve_header_t;

typedef struct
{
  u16 opt_class;
  u8 type;
  u8 flags_length;
  u8 data[0];
} geneve_option_t;

/* Per-interface filter data for simple filter */
typedef struct
{
  geneve_capture_filter_t *filters; /* Vector of active filters */
} simple_filter_per_interface_t;

/* Simple filter plugin state */
typedef struct
{
  /* Vector of registered option definitions */
  geneve_option_def_t *option_defs;

  /* Hash table: option_name -> index in option_defs */
  uword *option_by_name;

  /* Hash table: (class,type) -> index in option_defs */
  uword *option_by_class_type;

  /* Global filters */
  geneve_capture_filter_t *global_filters;

  /* Per-interface filter data */
  simple_filter_per_interface_t *per_interface;

} simple_filter_main_t;

extern simple_filter_main_t simple_filter_main;

static inline simple_filter_main_t *
get_simple_filter_main (void)
{
  return &simple_filter_main;
}

/* GENEVE helper functions */
static_always_inline u8
geneve_get_version (const geneve_header_t *h)
{
  return (h->ver_opt_len & GENEVE_VERSION_MASK) >> GENEVE_VERSION_SHIFT;
}

static_always_inline u8
geneve_get_opt_len (const geneve_header_t *h)
{
  return (h->ver_opt_len & GENEVE_OPT_LEN_MASK) >> GENEVE_OPT_LEN_SHIFT;
}

static_always_inline u32
geneve_get_vni (const geneve_header_t *h)
{
  return (((u32) h->vni[0]) << 16) | (((u32) h->vni[1]) << 8) | h->vni[2];
}

static_always_inline u8
geneve_opt_get_length (const geneve_option_t *opt)
{
  return (opt->flags_length & 0x1F) * 4;
}

/* Extract inner IP header from packet */
static_always_inline u8 *
get_inner_ip_header (const geneve_header_t *geneve_hdr, u32 geneve_header_len,
		     u32 *inner_len)
{
  u8 *inner_hdr;

  inner_hdr = (u8 *) (geneve_hdr) + geneve_header_len;
  *inner_len = 60; /* Conservative estimate */

  return inner_hdr;
}

/* Function to check if a packet matches a 5-tuple filter */
static_always_inline bool
packet_matches_tuple_filter (const u8 *packet_data, u32 packet_len,
			     const geneve_tuple_filter_t *filter)
{
  u32 i;

  if (packet_len < filter->length)
    return false;

  for (i = 0; i < filter->length; i++)
    {
      if ((packet_data[i] & filter->mask[i]) !=
	  (filter->value[i] & filter->mask[i]))
	return false;
    }

  return true;
}

/* Check if packet matches a Geneve filter */
static_always_inline u32
geneve_packet_matches_filter (simple_filter_main_t *sfm, const u8 *outer_hdr,
			      u32 outer_len, const u8 *inner_hdr,
			      u32 inner_len, const geneve_header_t *geneve_hdr,
			      u32 geneve_header_len,
			      const geneve_capture_filter_t *filter)
{
  const geneve_option_t *opt;
  u32 remaining_len;
  int i;
  const u32 DEST_INDEX_NONE = ~0;
  u32 dest_index_match = filter->destination_index;

  /* Check basic Geneve header fields if specified in filter */
  if (filter->ver_present && filter->ver != geneve_get_version (geneve_hdr))
    return DEST_INDEX_NONE;

  if (filter->opt_len_present &&
      filter->opt_len != geneve_get_opt_len (geneve_hdr))
    return DEST_INDEX_NONE;

  if (filter->proto_present &&
      filter->protocol != clib_net_to_host_u16 (geneve_hdr->protocol))
    return DEST_INDEX_NONE;

  if (filter->vni_present && filter->vni != geneve_get_vni (geneve_hdr))
    return DEST_INDEX_NONE;

  /* Check 5-tuple filters */
  if (filter->outer_tuple_present &&
      !packet_matches_tuple_filter (outer_hdr, outer_len,
				    &filter->outer_tuple))
    return DEST_INDEX_NONE;

  if (filter->inner_tuple_present &&
      !packet_matches_tuple_filter (inner_hdr, inner_len,
				    &filter->inner_tuple))
    return DEST_INDEX_NONE;

  /* No option filters, match just on basic headers and tuples */
  if (vec_len (filter->option_filters) == 0)
    return dest_index_match;

  /* Start of options */
  opt = (const geneve_option_t *) (geneve_hdr + 1);
  remaining_len = geneve_header_len - sizeof (geneve_header_t);

  /* Check each option filter */
  for (i = 0; i < vec_len (filter->option_filters); i++)
    {
      const geneve_option_t *current_opt = opt;
      bool found = false;
      u16 opt_class;
      u8 opt_type;
      uword *p;

      /* Resolve option class/type from name if needed */
      if (filter->option_filters[i].option_name)
	{
	  p = hash_get_mem (sfm->option_by_name,
			    filter->option_filters[i].option_name);
	  if (!p)
	    return DEST_INDEX_NONE;

	  const geneve_option_def_t *opt_def = &sfm->option_defs[p[0]];
	  opt_class = opt_def->opt_class;
	  opt_type = opt_def->type;
	}
      else
	{
	  opt_class = filter->option_filters[i].opt_class;
	  opt_type = filter->option_filters[i].type;
	}

      /* Search for the option in the packet */
      current_opt = opt;
      while (remaining_len >= sizeof (geneve_option_t))
	{
	  u8 opt_len = geneve_opt_get_length (current_opt);

	  if (clib_net_to_host_u16 (current_opt->opt_class) == opt_class &&
	      current_opt->type == opt_type)
	    {
	      found = true;

	      if (filter->option_filters[i].match_any)
		break;

	      /* Check data content */
	      if (filter->option_filters[i].data_len > 0)
		{
		  u8 check_len = filter->option_filters[i].data_len;

		  if (check_len > opt_len - 4)
		    check_len = opt_len - 4;

		  if (check_len <= 0)
		    {
		      found = false;
		      break;
		    }

		  /* If we have a mask, apply it */
		  if (filter->option_filters[i].mask)
		    {
		      u8 j;
		      for (j = 0; j < check_len; j++)
			{
			  u8 masked_data = current_opt->data[j] &
					   filter->option_filters[i].mask[j];
			  u8 masked_filter =
			    filter->option_filters[i].data[j] &
			    filter->option_filters[i].mask[j];

			  if (masked_data != masked_filter)
			    {
			      found = false;
			      break;
			    }
			}
		    }
		  else
		    {
		      /* Exact match */
		      if (memcmp (current_opt->data,
				  filter->option_filters[i].data,
				  check_len) != 0)
			found = false;
		    }
		}

	      break;
	    }

	  /* Move to next option */
	  if (opt_len < sizeof (geneve_option_t))
	    break;

	  current_opt =
	    (const geneve_option_t *) ((u8 *) current_opt + opt_len);
	  remaining_len -= opt_len;
	}

      /* If required option wasn't found, no match */
      if (!found)
	return DEST_INDEX_NONE;
    }

  /* All filters matched */
  return dest_index_match;
}

/* Check if the packet matches any global filter */
static_always_inline u32
geneve_packet_matches_global_filter (simple_filter_main_t *sfm,
				     const u8 *outer_hdr, u32 outer_len,
				     const u8 *inner_hdr, u32 inner_len,
				     const geneve_header_t *geneve_hdr,
				     u32 geneve_header_len)
{
  int i;

  /* Check each global filter */
  for (i = 0; i < vec_len (sfm->global_filters); i++)
    {
      u32 dest_index = geneve_packet_matches_filter (
	sfm, outer_hdr, outer_len, inner_hdr, inner_len, geneve_hdr,
	geneve_header_len, &sfm->global_filters[i]);
      if (dest_index != ~0)
	return dest_index;
    }

  return ~0;
}

#endif /* __included_simple_filter_h__ */