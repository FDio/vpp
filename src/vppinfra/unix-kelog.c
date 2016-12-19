/*
  Copyright (c) 2010 Cisco and/or its affiliates.

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

#include <vppinfra/error.h>
#include <vppinfra/unix.h>
#include <vppinfra/elog.h>
#include <vppinfra/format.h>
#include <vppinfra/os.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

typedef enum
{
  RUNNING = 0,
  WAKEUP,
} sched_event_type_t;

typedef struct
{
  u32 cpu;
  u8 *task;
  u32 pid;
  f64 timestamp;
  sched_event_type_t type;
} sched_event_t;

void
kelog_init (elog_main_t * em, char *kernel_tracer, u32 n_events)
{
  int enable_fd, current_tracer_fd, data_fd;
  int len;
  struct timespec ts, ts2;
  char *trace_enable = "/debug/tracing/tracing_enabled";
  char *current_tracer = "/debug/tracing/current_tracer";
  char *trace_data = "/debug/tracing/trace";
  f64 realtime, monotonic;
  f64 freq, secs_per_clock;

  ASSERT (kernel_tracer);

  /*$$$$ fixme */
  n_events = 1 << 18;

  /* init first so we won't hurt ourselves if we bail */
  elog_init (em, n_events);

  enable_fd = open (trace_enable, O_RDWR);
  if (enable_fd < 0)
    {
      clib_warning ("Couldn't open %s", trace_enable);
      return;
    }
  /* disable kernel tracing */
  if (write (enable_fd, "0\n", 2) != 2)
    {
      clib_unix_warning ("disable tracing");
      close (enable_fd);
      return;
    }

  /*
   * open + clear the data buffer.
   * see .../linux/kernel/trace/trace.c:tracing_open()
   */
  data_fd = open (trace_data, O_RDWR | O_TRUNC);
  if (data_fd < 0)
    {
      clib_warning ("Couldn't open+clear %s", trace_data);
      return;
    }
  close (data_fd);

  /* configure tracing */
  current_tracer_fd = open (current_tracer, O_RDWR);

  if (current_tracer_fd < 0)
    {
      clib_warning ("Couldn't open %s", current_tracer);
      close (enable_fd);
      return;
    }

  len = strlen (kernel_tracer);

  if (write (current_tracer_fd, kernel_tracer, len) != len)
    {
      clib_unix_warning ("configure trace");
      close (current_tracer_fd);
      close (enable_fd);
      return;
    }

  close (current_tracer_fd);

  /*
   * The kernel event log uses CLOCK_MONOTONIC timestamps,
   * not CLOCK_REALTIME timestamps. These differ by a constant
   * but the constant is not available in user mode.
   * This estimate will be off by one syscall round-trip.
   */
  clib_time_init (&em->cpu_timer);
  em->init_time.cpu = em->cpu_timer.init_cpu_time;
  syscall (SYS_clock_gettime, CLOCK_MONOTONIC, &ts);

  /* enable kernel tracing */
  if (write (enable_fd, "1\n", 2) != 2)
    {
      clib_unix_warning ("enable tracing");
      close (enable_fd);
      return;
    }

  close (enable_fd);
}


u8 *
format_sched_event (u8 * s, va_list * va)
{
  sched_event_t *e = va_arg (*va, sched_event_t *);

  s = format (s, "cpu %d task %10s type %s timestamp %12.6f\n",
	      e->cpu, e->task, e->type ? "WAKEUP " : "RUNNING", e->timestamp);

  return s;
}

sched_event_t *
parse_sched_switch_trace (u8 * tdata, u32 * index)
{
  u8 *cp = tdata + *index;
  u8 *limit = tdata + vec_len (tdata);
  int colons;
  static sched_event_t event;
  sched_event_t *e = &event;
  static u8 *task_name;
  u32 secs, usecs;
  int i;

again:
  /* eat leading w/s */
  while (cp < limit && (*cp == ' ' && *cp == '\t'))
    cp++;
  if (cp == limit)
    return 0;

  /* header line */
  if (*cp == '#')
    {
      while (cp < limit && (*cp != '\n'))
	cp++;
      if (*cp == '\n')
	{
	  cp++;
	  goto again;
	}
      clib_warning ("bugger 0");
      return 0;
    }

  while (cp < limit && *cp != ']')
    cp++;

  if (*cp == 0)
    return 0;

  if (*cp != ']')
    {
      clib_warning ("bugger 0.1");
      return 0;
    }

  cp++;
  while (cp < limit && (*cp == ' ' && *cp == '\t'))
    cp++;
  if (cp == limit)
    {
      clib_warning ("bugger 0.2");
      return 0;
    }

  secs = atoi (cp);

  while (cp < limit && (*cp != '.'))
    cp++;

  if (cp == limit)
    {
      clib_warning ("bugger 0.3");
      return 0;
    }

  cp++;

  usecs = atoi (cp);

  e->timestamp = ((f64) secs) + ((f64) usecs) * 1e-6;

  /* eat up to third colon */
  for (i = 0; i < 3; i++)
    {
      while (cp < limit && *cp != ':')
	cp++;
      cp++;
    }
  --cp;
  if (*cp != ':')
    {
      clib_warning ("bugger 1");
      return 0;
    }
  /* aim at '>' (switch-to) / '+' (wakeup) */
  cp += 5;
  if (cp >= limit)
    {
      clib_warning ("bugger 2");
      return 0;
    }
  if (*cp == '>')
    e->type = RUNNING;
  else if (*cp == '+')
    e->type = WAKEUP;
  else
    {
      clib_warning ("bugger 3");
      return 0;
    }

  cp += 3;
  if (cp >= limit)
    {
      clib_warning ("bugger 4");
      return 0;
    }

  e->cpu = atoi (cp);
  cp += 4;

  if (cp >= limit)
    {
      clib_warning ("bugger 4");
      return 0;
    }
  while (cp < limit && (*cp == ' ' || *cp == '\t'))
    cp++;

  e->pid = atoi (cp);

  for (i = 0; i < 2; i++)
    {
      while (cp < limit && *cp != ':')
	cp++;
      cp++;
    }
  --cp;
  if (*cp != ':')
    {
      clib_warning ("bugger 5");
      return 0;
    }

  cp += 3;
  if (cp >= limit)
    {
      clib_warning ("bugger 6");
      return 0;
    }
  while (cp < limit && (*cp != ' ' && *cp != '\n'))
    {
      vec_add1 (task_name, *cp);
      cp++;
    }
  vec_add1 (task_name, 0);
  /* _vec_len() = 0 in caller */
  e->task = task_name;

  if (cp < limit)
    cp++;

  *index = cp - tdata;
  return e;
}

static u32
elog_id_for_pid (elog_main_t * em, u8 * name, u32 pid)
{
  uword *p, r;
  mhash_t *h = &em->string_table_hash;

  if (!em->string_table_hash.hash)
    mhash_init (h, sizeof (uword), sizeof (pid));

  p = mhash_get (h, &pid);
  if (p)
    return p[0];
  r = elog_string (em, "%s(%d)", name, pid);
  mhash_set (h, &pid, r, /* old_value */ 0);
  return r;
}

void
kelog_collect_sched_switch_trace (elog_main_t * em)
{
  int enable_fd, data_fd;
  char *trace_enable = "/debug/tracing/tracing_enabled";
  char *trace_data = "/debug/tracing/trace";
  u8 *data = 0;
  u8 *dp;
  int bytes, total_bytes;
  u32 pos;
  sched_event_t *evt;
  u64 nsec_to_add;
  u32 index;
  f64 clocks_per_sec;

  enable_fd = open (trace_enable, O_RDWR);
  if (enable_fd < 0)
    {
      clib_warning ("Couldn't open %s", trace_enable);
      return;
    }
  /* disable kernel tracing */
  if (write (enable_fd, "0\n", 2) != 2)
    {
      clib_unix_warning ("disable tracing");
      close (enable_fd);
      return;
    }
  close (enable_fd);

  /* Read the trace data */
  data_fd = open (trace_data, O_RDWR);
  if (data_fd < 0)
    {
      clib_warning ("Couldn't open %s", trace_data);
      return;
    }

  /*
   * Extract trace into a vector. Note that seq_printf() [kernel]
   * is not guaranteed to produce 4096 bytes at a time.
   */
  vec_validate (data, 4095);
  total_bytes = 0;
  pos = 0;
  while (1)
    {
      bytes = read (data_fd, data + pos, 4096);
      if (bytes <= 0)
	break;

      total_bytes += bytes;
      _vec_len (data) = total_bytes;

      pos = vec_len (data);
      vec_validate (data, vec_len (data) + 4095);
    }
  vec_add1 (data, 0);

  /* Synthesize events */
  em->is_enabled = 1;

  index = 0;
  while ((evt = parse_sched_switch_trace (data, &index)))
    {
      u64 fake_cpu_clock;

      fake_cpu_clock = evt->timestamp * em->cpu_timer.clocks_per_second;
      {
	ELOG_TYPE_DECLARE (e) =
	{
	  .format = "%d: %s %s",.format_args = "i4T4t4",.n_enum_strings =
	    2,.enum_strings =
	  {
	  "running", "wakeup",}
	,};
	struct
	{
	  u32 cpu, string_table_offset, which;
	} *ed;

	ed = elog_event_data_not_inline (em, &__ELOG_TYPE_VAR (e),
					 &em->default_track, fake_cpu_clock);
	ed->cpu = evt->cpu;
	ed->string_table_offset = elog_id_for_pid (em, evt->task, evt->pid);
	ed->which = evt->type;
      }
      _vec_len (evt->task) = 0;
    }
  em->is_enabled = 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
