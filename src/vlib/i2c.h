/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#ifndef included_vlib_i2c_h
#define included_vlib_i2c_h

#include <vppinfra/types.h>


#define I2C_MSG_FLAG_WRITE  0
#define I2C_MSG_FLAG_READ   1

typedef struct
{
  u8 addr;
  u8 flags;
  u16 len;
  u8 *buffer;
} i2c_msg_t;

typedef struct i2c_bus_t
{
  void (*put_bits) (struct i2c_bus_t * b, int scl, int sda);
  void (*get_bits) (struct i2c_bus_t * b, int *scl, int *sda);

  int timeout;
  u32 clock;
  f64 hold_time;
  f64 rise_fall_time;

  /* Private data */
  uword private_data;

} i2c_bus_t;

void vlib_i2c_init (i2c_bus_t * bus);
void vlib_i2c_xfer (i2c_bus_t * bus, i2c_msg_t * msgs);
void vlib_i2c_read_eeprom (i2c_bus_t * bus, u8 i2c_addr, u16 start_addr,
			   u16 length, u8 * data);

static inline int
vlib_i2c_bus_timed_out (i2c_bus_t * bus)
{
  return bus->timeout;
}

#endif /* included_vlib_i2c_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
