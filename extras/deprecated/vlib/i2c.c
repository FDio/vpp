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

#include <vlib/vlib.h>
#include <vlib/i2c.h>

static inline void
i2c_delay (i2c_bus_t * b, f64 timeout)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_time_wait (vm, timeout);
}

static void
i2c_wait_for_scl (i2c_bus_t * b)
{
  f64 t = 0;

  while (t < b->hold_time)
    {
      int sda, scl;
      i2c_delay (b, b->rise_fall_time);
      b->get_bits (b, &scl, &sda);

      if (scl)
	return;

      t += b->rise_fall_time;
    }
  b->timeout = 1;
}

static void
i2c_start (i2c_bus_t * b)
{
  b->timeout = 0;

  b->put_bits (b, 1, 1);
  i2c_wait_for_scl (b);

  if (vlib_i2c_bus_timed_out (b))
    return;

  b->put_bits (b, 1, 0);
  i2c_delay (b, b->hold_time);
  b->put_bits (b, 0, 0);
  i2c_delay (b, b->hold_time);
}

static void
i2c_stop (i2c_bus_t * b)
{
  b->put_bits (b, 0, 0);
  i2c_delay (b, b->rise_fall_time);

  b->put_bits (b, 1, 0);
  i2c_delay (b, b->hold_time);

  b->put_bits (b, 1, 1);
  i2c_delay (b, b->hold_time);
}

static void
i2c_write_bit (i2c_bus_t * b, int sda)
{
  b->put_bits (b, 0, sda);
  i2c_delay (b, b->rise_fall_time);

  b->put_bits (b, 1, sda);
  i2c_wait_for_scl (b);
  i2c_delay (b, b->hold_time);

  b->put_bits (b, 0, sda);
  i2c_delay (b, b->rise_fall_time);
}

static void
i2c_read_bit (i2c_bus_t * b, int *sda)
{
  int scl;

  b->put_bits (b, 1, 1);
  i2c_wait_for_scl (b);
  i2c_delay (b, b->hold_time);

  b->get_bits (b, &scl, sda);

  b->put_bits (b, 0, 1);
  i2c_delay (b, b->rise_fall_time);
}

static void
i2c_write_byte (i2c_bus_t * b, u8 data)
{
  int i, sda;

  for (i = 7; i >= 0; i--)
    {
      i2c_write_bit (b, (data >> i) & 1);
      if (b->timeout)
	return;
    }

  b->put_bits (b, 0, 1);
  i2c_delay (b, b->rise_fall_time);

  i2c_read_bit (b, &sda);

  if (sda)
    b->timeout = 1;
}


static void
i2c_read_byte (i2c_bus_t * b, u8 * data, int ack)
{
  int i, sda;

  *data = 0;

  b->put_bits (b, 0, 1);
  i2c_delay (b, b->rise_fall_time);

  for (i = 7; i >= 0; i--)
    {
      i2c_read_bit (b, &sda);
      if (b->timeout)
	return;

      *data |= (sda != 0) << i;
    }

  i2c_write_bit (b, ack == 0);
}


void
vlib_i2c_init (i2c_bus_t * b)
{
  f64 tick;
  if (!b->clock)
    b->clock = 400000;

  tick = 1.0 / b->clock;

  /* Spend 40% of time in low and high states */
  if (!b->hold_time)
    b->hold_time = 0.4 * tick;

  /* Spend 10% of time waiting for rise and fall */
  if (!b->rise_fall_time)
    b->rise_fall_time = 0.1 * tick;
}

void
vlib_i2c_xfer (i2c_bus_t * bus, i2c_msg_t * msgs)
{
  i2c_msg_t *msg;
  int i;

  vec_foreach (msg, msgs)
  {
    i2c_start (bus);
    i2c_write_byte (bus,
		    (msg->addr << 1) + (msg->flags == I2C_MSG_FLAG_READ));

    if (msg->flags & I2C_MSG_FLAG_READ)
      for (i = 0; i < msg->len; i++)
	{
	  i2c_read_byte (bus, &msg->buffer[i], /* ack */ i + 1 != msg->len);
	  if (bus->timeout)
	    goto done;
	}

    else
      for (i = 0; i < msg->len; i++)
	{
	  i2c_write_byte (bus, msg->buffer[i]);
	  if (bus->timeout)
	    goto done;
	}
  }

done:
  i2c_stop (bus);
}

void
vlib_i2c_read_eeprom (i2c_bus_t * bus, u8 i2c_addr, u16 start_addr,
		      u16 length, u8 * data)
{
  i2c_msg_t *msg = 0;
  u8 start_address[1];

  vec_validate (msg, 1);

  start_address[0] = start_addr;
  msg[0].addr = i2c_addr;
  msg[0].flags = I2C_MSG_FLAG_WRITE;
  msg[0].buffer = (u8 *) & start_address;
  msg[0].len = 1;

  msg[1].addr = i2c_addr;
  msg[1].flags = I2C_MSG_FLAG_READ;
  msg[1].buffer = data;
  msg[1].len = length;

  vlib_i2c_xfer (bus, msg);

  vec_free (msg);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
