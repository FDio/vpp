#ifndef __included_trivial_filter_h__
#define __included_trivial_filter_h__

#include <gpcapng/gpcapng_filter_api.h>

/* Trivial filter modes */
typedef enum
{
  TRIVIAL_FILTER_CAPTURE_NONE = 0,
  TRIVIAL_FILTER_CAPTURE_ALL = 1,
} trivial_filter_mode_t;

/* Trivial filter plugin state */
typedef struct
{
  /* Current filter mode */
  trivial_filter_mode_t mode;

  /* Destination index for capture-all mode */
  u32 destination_index;

} trivial_filter_main_t;

extern trivial_filter_main_t trivial_filter_main;

static inline trivial_filter_main_t *
get_trivial_filter_main (void)
{
  return &trivial_filter_main;
}

#endif /* __included_trivial_filter_h__ */