/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#ifndef __POLICE_H__
#define __POLICE_H__

typedef enum
{
  POLICE_CONFORM = 0,
  POLICE_EXCEED = 1,
  POLICE_VIOLATE = 2,
} policer_result_e;

// This is the hardware representation of the policer.
// To be multithread-safe, the policer is accessed through a spin-lock
// on the lock field. (For a policer update operation, 24B needs to be
// modified and this would be a challenge to do with atomic instructions.)
// The structure is padded so that no other data is put into the same
// 64B cache-line. This reduces cache-thrashing between threads.
//
// A note on scale:
// The HW TSC tick is roughly one CPU clock cycle.
// This is shifted to create a larger period, with a goal to be around 50usec.
// The period time will vary based on CPU clock speed.
// CPU speeds of 1Ghz to 8Ghz are targetted.
// The shift amount is a constant 17 bits, resulting in a period between
// 16usec (8Ghz CPU) and 131usec (1Ghz CPU).
// The token_per_period computation takes into account the clock speed.
//
// The 32-bit bucket/limit supports about 850ms of burst on a 40GE port,
// or 340ms on a 100GE port. If a larger burst is configured, then the
// programmed value is simply capped at 2^32-1. If we needed to support
// more than that, the bucket and limit fields could be expanded.
//
// tokens_per_period should be > 1000 to support 0.1% granularity.
// To support lower rates (which would not meet this requirement), the packet
// length, bucket, and limit values can be scaled. The scale is a power of 2
// so the multiplication can be implemented as a shift. The control plane
// computes the shift amount be the largest possible that still supports the
// burst size. This makes the rate accuracy as high as possible.
//
// The 64-bit last_update_time supports a 4Ghz CPU without rollover for 100
// years
//
// The lock field should be used for a spin-lock on the struct. Alternatively,
// a thread index field is provided so that policed packets may be handed
// off to a single worker thread.

#define POLICER_TICKS_PER_PERIOD_SHIFT 17
#define POLICER_TICKS_PER_PERIOD       (1 << POLICER_TICKS_PER_PERIOD_SHIFT)

typedef struct
{

  u32 lock;			// for exclusive access to the struct

  u32 single_rate;		// 1 = single rate policer, 0 = two rate policer
  u32 color_aware;		// for hierarchical policing
  u32 scale;			// power-of-2 shift amount for lower rates
  u8 action[3];
  u8 mark_dscp[3];
  u8 pad[2];

  // Fields are marked as 2R if they are only used for a 2-rate policer,
  // and MOD if they are modified as part of the update operation.
  // 1 token = 1 byte.

  u32 cir_tokens_per_period;	// # of tokens for each period
  u32 pir_tokens_per_period;	// 2R

  u32 current_limit;
  u32 current_bucket;		// MOD
  u32 extended_limit;
  u32 extended_bucket;		// MOD

  u64 last_update_time;		// MOD
  u32 thread_index;		// Tie policer to a thread, rather than lock
  u32 pad32;

} policer_read_response_type_st;

static inline policer_result_e
vnet_police_packet (policer_read_response_type_st * policer,
		    u32 packet_length,
		    policer_result_e packet_color, u64 time)
{
  u64 n_periods;
  u64 current_tokens, extended_tokens;
  policer_result_e result;

  // Scale packet length to support a wide range of speeds
  packet_length = packet_length << policer->scale;

  // Compute the number of policer periods that have passed since the last
  // operation.
  n_periods = time - policer->last_update_time;
  policer->last_update_time = time;

  // Since there is no background last-update-time adjustment, n_periods
  // could grow large if the policer is idle for a long time. This could
  // cause a 64-bit overflow when computing tokens_per_period * num_periods.
  // It will overflow if log2(n_periods) + log2(tokens_per_period) > 64.
  //
  // To mitigate this, the policer configuration algorithm insures that
  // tokens_per_period is less than 2^22, i.e. this is a 22 bit value not
  // a 32-bit value. Thus overflow will only occur if n_periods > 64-22 or
  // 42. 2^42 min-sized periods is 16us * 2^42, or 2 years. So this can
  // rarely occur. If overflow does happen, the only effect will be that
  // fewer tokens than the max burst will be added to the bucket for this
  // packet. This constraint on tokens_per_period lets the ucode omit
  // code to dynamically check for or prevent the overflow.

  if (policer->single_rate)
    {

      // Compute number of tokens for this time period
      current_tokens =
	policer->current_bucket + n_periods * policer->cir_tokens_per_period;
      if (current_tokens > policer->current_limit)
	{
	  current_tokens = policer->current_limit;
	}

      extended_tokens =
	policer->extended_bucket + n_periods * policer->cir_tokens_per_period;
      if (extended_tokens > policer->extended_limit)
	{
	  extended_tokens = policer->extended_limit;
	}

      // Determine color

      if ((!policer->color_aware || (packet_color == POLICE_CONFORM))
	  && (current_tokens >= packet_length))
	{
	  policer->current_bucket = current_tokens - packet_length;
	  policer->extended_bucket = extended_tokens - packet_length;
	  result = POLICE_CONFORM;
	}
      else if ((!policer->color_aware || (packet_color != POLICE_VIOLATE))
	       && (extended_tokens >= packet_length))
	{
	  policer->current_bucket = current_tokens;
	  policer->extended_bucket = extended_tokens - packet_length;
	  result = POLICE_EXCEED;
	}
      else
	{
	  policer->current_bucket = current_tokens;
	  policer->extended_bucket = extended_tokens;
	  result = POLICE_VIOLATE;
	}

    }
  else
    {
      // Two-rate policer

      // Compute number of tokens for this time period
      current_tokens =
	policer->current_bucket + n_periods * policer->cir_tokens_per_period;
      extended_tokens =
	policer->extended_bucket + n_periods * policer->pir_tokens_per_period;
      if (current_tokens > policer->current_limit)
	{
	  current_tokens = policer->current_limit;
	}
      if (extended_tokens > policer->extended_limit)
	{
	  extended_tokens = policer->extended_limit;
	}

      // Determine color

      if ((policer->color_aware && (packet_color == POLICE_VIOLATE))
	  || (extended_tokens < packet_length))
	{
	  policer->current_bucket = current_tokens;
	  policer->extended_bucket = extended_tokens;
	  result = POLICE_VIOLATE;
	}
      else if ((policer->color_aware && (packet_color == POLICE_EXCEED))
	       || (current_tokens < packet_length))
	{
	  policer->current_bucket = current_tokens;
	  policer->extended_bucket = extended_tokens - packet_length;
	  result = POLICE_EXCEED;
	}
      else
	{
	  policer->current_bucket = current_tokens - packet_length;
	  policer->extended_bucket = extended_tokens - packet_length;
	  result = POLICE_CONFORM;
	}
    }
  return result;
}

#endif // __POLICE_H__

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
