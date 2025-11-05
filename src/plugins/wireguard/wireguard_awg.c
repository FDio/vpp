/*
 * Copyright (c) 2025 AmneziaWG integration for VPP
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vnet/vnet.h>
#include <vppinfra/random.h>
#include <wireguard/wireguard_awg.h>
#include <wireguard/wireguard_send.h>

/* Thread-local random state for junk generation */
__thread u64 wg_awg_random_state = 0;

static_always_inline void
wg_awg_init_random (void)
{
  if (PREDICT_FALSE (wg_awg_random_state == 0))
    {
      wg_awg_random_state = random_default_seed ();
    }
}

/* Generate cryptographically random junk data */
void
wg_awg_generate_junk (u8 *buffer, u32 size)
{
  wg_awg_init_random ();

  /* Use VPP's random number generator for junk data */
  u32 i;
  for (i = 0; i + sizeof (u64) <= size; i += sizeof (u64))
    {
      u64 rand_val = random_u64 (&wg_awg_random_state);
      clib_memcpy (buffer + i, &rand_val, sizeof (u64));
    }

  /* Fill remaining bytes */
  if (i < size)
    {
      u64 rand_val = random_u64 (&wg_awg_random_state);
      clib_memcpy (buffer + i, &rand_val, size - i);
    }
}

/* Generate a random size between min and max */
static_always_inline u32
wg_awg_random_size (u32 min_size, u32 max_size)
{
  wg_awg_init_random ();

  if (min_size >= max_size)
    return min_size;

  u32 range = max_size - min_size + 1;
  return min_size + (random_u32 (&wg_awg_random_state) % range);
}

/* Send junk packets before actual handshake */
void
wg_awg_send_junk_packets (vlib_main_t *vm, const wg_awg_cfg_t *cfg,
			  const u8 *rewrite, u8 is_ip4)
{
  if (!wg_awg_is_enabled (cfg) || cfg->junk_packet_count == 0)
    return;

  u32 count = cfg->junk_packet_count;
  if (count > WG_AWG_MAX_JUNK_PACKET_COUNT)
    count = WG_AWG_MAX_JUNK_PACKET_COUNT;

  /* Generate and send junk packets */
  for (u32 i = 0; i < count; i++)
    {
      u32 junk_size = wg_awg_random_size (cfg->junk_packet_min_size,
					  cfg->junk_packet_max_size);
      if (junk_size == 0 || junk_size > WG_AWG_MAX_JUNK_PACKET_SIZE)
	continue;

      /* Allocate buffer for junk packet */
      u8 *junk_packet = clib_mem_alloc (junk_size);
      if (!junk_packet)
	continue;

      /* Fill with random data */
      wg_awg_generate_junk (junk_packet, junk_size);

      /* Send the junk packet */
      u32 bi = 0;
      if (wg_create_buffer (vm, rewrite, junk_packet, junk_size, &bi, is_ip4))
	{
	  /* Enqueue for sending */
	  ip46_enqueue_packet (vm, bi, is_ip4);
	}

      clib_mem_free (junk_packet);
    }
}

/* Send i-header signature chain packets (AmneziaWG 1.5) */
void
wg_awg_send_i_header_packets (vlib_main_t *vm, wg_awg_cfg_t *cfg,
			      const u8 *rewrite, u8 is_ip4)
{
  u32 i;

  if (!cfg->i_headers_enabled)
    return;

  /* Send i1 through i5 packets (if configured) */
  for (i = 0; i < WG_AWG_MAX_I_HEADERS; i++)
    {
      wg_awg_i_header_t *ihdr = &cfg->i_headers[i];

      if (!ihdr->enabled)
	continue; /* Skip if i-header not configured */

      /* Generate packet from tags */
      u8 *packet = wg_awg_generate_i_header_packet (ihdr);
      if (!packet)
	continue;

      u32 packet_len = ihdr->total_size;

      /* Send the i-header packet */
      u32 bi = 0;
      if (wg_create_buffer (vm, rewrite, packet, packet_len, &bi, is_ip4))
	{
	  ip46_enqueue_packet (vm, bi, is_ip4);
	}

      clib_mem_free (packet);
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
