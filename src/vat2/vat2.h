#ifndef included_vat2_h
#define included_vat2_h

#include <stdbool.h>

extern bool vat2_debug;

#define DBG(fmt, args...)                                                     \
  do                                                                          \
    {                                                                         \
      if (vat2_debug)                                                         \
	fprintf (stderr, fmt, ##args);                                        \
    }                                                                         \
  while (0)
#define ERR(fmt, args...) fprintf(stderr, "VAT2: %s:%d:%s(): " fmt, \
                                  __FILE__, __LINE__, __func__, ##args)

#endif
