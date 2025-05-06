
#ifndef _GPCAPNG_OUTPUT_H_
#define _GPCAPNG_OUTPUT_H_

#include <gpcapng/lib/gpcapng.h>


u32 find_destination_by_name (const char *name);

u8 *get_pcapng_preamble_vec ();

void set_pcapng_output_file (gpcapng_dest_t *output);

void gpcapng_ensure_session_manager ();
void set_pcapng_output_http (gpcapng_dest_t *output);

/* Worker Destination Index (WDI): a combination of the worker index and
 * destination index */

always_inline worker_dest_index_t
make_wdi (u16 worker_index, u16 destination_index)
{
  return (((u32) worker_index << 16) + ((u32) destination_index));
}

always_inline u16
wdi_to_worker_index (worker_dest_index_t wdi)
{
  return (wdi >> 16);
}

always_inline u16
wdi_to_destination_index (worker_dest_index_t wdi)
{
  return (wdi & 0xffff);
}

void *wdi_to_worker_context (worker_dest_index_t wdi);
void wdi_set_ready_flag (worker_dest_index_t wdi, int is_ready);
gpcapng_dest_t *wdi_to_dest (worker_dest_index_t wdi);

#endif // _GPCAPNG_OUTPUT_H_
