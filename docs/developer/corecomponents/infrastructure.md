VPPINFRA (Infrastructure)
=========================

The files associated with the VPP Infrastructure layer are located in
the ./src/vppinfra folder.

VPPinfra is a collection of basic c-library services, quite
sufficient to build standalone programs to run directly on bare metal.
It also provides high-performance dynamic arrays, hashes, bitmaps,
high-precision real-time clock support, fine-grained event-logging, and
data structure serialization.

One fair comment / fair warning about vppinfra: you can\'t always tell a
macro from an inline function from an ordinary function simply by name.
Macros are used to avoid function calls in the typical case, and to
cause (intentional) side-effects.

Vppinfra has been around for almost 20 years and tends not to change
frequently. The VPP Infrastructure layer contains the following
functions:

Vectors
-------

Vppinfra vectors are ubiquitous dynamically resized arrays with by user
defined \"headers\". Many vpppinfra data structures (e.g. hash, heap,
pool) are vectors with various different headers.

The memory layout looks like this:

```
                   User header (optional, uword aligned)
                   Alignment padding (if needed)
                   Vector length in elements
 User's pointer -> Vector element 0
                   Vector element 1
                   ...
                   Vector element N-1
```

As shown above, the vector APIs deal with pointers to the 0th element of
a vector. Null pointers are valid vectors of length zero.

To avoid thrashing the memory allocator, one often resets the length of
a vector to zero while retaining the memory allocation. Set the vector
length field to zero via the vec\_reset\_length(v) macro. \[Use the
macro! It's smart about NULL pointers.\]

Typically, the user header is not present. User headers allow for other
data structures to be built atop vppinfra vectors. Users may specify the
alignment for first data element of a vector via the \[vec\]()\*\_aligned
macros.

Vector elements can be any C type e.g. (int, double, struct bar). This
is also true for data types built atop vectors (e.g. heap, pool, etc.).
Many macros have \_a variants supporting alignment of vector elements
and \_h variants supporting non-zero-length vector headers. The \_ha
variants support both.  Additionally cacheline alignment within a
vector element structure can be specified using the
\[CLIB_CACHE_LINE_ALIGN_MARK\]() macro.

Inconsistent usage of header and/or alignment related macro variants
will cause delayed, confusing failures.

Standard programming error: memorize a pointer to the ith element of a
vector, and then expand the vector. Vectors expand by 3/2, so such code
may appear to work for a period of time. Correct code almost always
memorizes vector **indices** which are invariant across reallocations.

In typical application images, one supplies a set of global functions
designed to be called from gdb. Here are a few examples:

-   vl(v) - prints vec\_len(v)
-   pe(p) - prints pool\_elts(p)
-   pifi(p, index) - prints pool\_is\_free\_index(p, index)
-   debug\_hex\_bytes (p, nbytes) - hex memory dump nbytes starting at p

Use the "show gdb" debug CLI command to print the current set.

Bitmaps
-------

Vppinfra bitmaps are dynamic, built using the vppinfra vector APIs.
Quite handy for a variety jobs.

Pools
-----

Vppinfra pools combine vectors and bitmaps to rapidly allocate and free
fixed-size data structures with independent lifetimes. Pools are perfect
for allocating per-session structures.

Hashes
------

Vppinfra provides several hash flavors. Data plane problems involving
packet classification / session lookup often use
./src/vppinfra/bihash\_template.\[ch\] bounded-index extensible
hashes. These templates are instantiated multiple times, to efficiently
service different fixed-key sizes.

Bihashes are thread-safe. Read-locking is not required. A simple
spin-lock ensures that only one thread writes an entry at a time.

The original vppinfra hash implementation in
./src/vppinfra/hash.\[ch\] are simple to use, and are often used in
control-plane code which needs exact-string-matching.

In either case, one almost always looks up a key in a hash table to
obtain an index in a related vector or pool. The APIs are simple enough,
but one must take care when using the unmanaged arbitrary-sized key
variant. Hash\_set\_mem (hash\_table, key\_pointer, value) memorizes
key\_pointer. It is usually a bad mistake to pass the address of a
vector element as the second argument to hash\_set\_mem. It is perfectly
fine to memorize constant string addresses in the text segment.

Timekeeping
-----------

Vppinfra includes high-precision, low-cost timing services. The
datatype clib_time_t and associated functions reside in
./src/vppinfra/time.\[ch\]. Call clib_time_init (clib_time_t \*cp) to
initialize the clib_time_t object.

Clib_time_init(...) can use a variety of different ways to establish
the hardware clock frequency. At the end of the day, vppinfra
timekeeping takes the attitude that the operating system's clock is
the closest thing to a gold standard it has handy.

When properly configured, NTP maintains kernel clock synchronization
with a highly accurate off-premises reference clock.  Notwithstanding
network propagation delays, a synchronized NTP client will keep the
kernel clock accurate to within 50ms or so.

Why should one care? Simply put, oscillators used to generate CPU
ticks aren't super accurate. They work pretty well, but a 0.1% error
wouldn't be out of the question. That's a minute and a half's worth of
error in 1 day. The error changes constantly, due to temperature
variation, and a host of other physical factors.

It's far too expensive to use system calls for timing, so we're left
with the problem of continously adjusting our view of the CPU tick
register's clocks_per_second parameter.

The clock rate adjustment algorithm measures the number of cpu ticks
and the "gold standard" reference time across an interval of
approximately 16 seconds. We calculate clocks_per_second for the
interval: use rdtsc (on x86_64) and a system call to get the latest
cpu tick count and the kernel's latest nanosecond timestamp. We
subtract the previous interval end values, and use exponential
smoothing to merge the new clock rate sample into the clocks_per_second
parameter.

As of this writing, we maintain the clock rate by way of the following
first-order differential equation:


```
   clocks_per_second(t) = clocks_per_second(t-1) * K + sample_cps(t)*(1-K)
   where K = e**(-1.0/3.75);
```

This yields a per observation "half-life" of 1 minute. Empirically,
the clock rate converges within 5 minutes, and appears to maintain
near-perfect agreement with the kernel clock in the face of ongoing
NTP time adjustments.

See ./src/vppinfra/time.c:clib_time_verify_frequency(...) to look at
the rate adjustment algorithm. The code rejects frequency samples
corresponding to the sort of adjustment which might occur if someone
changes the gold standard kernel clock by several seconds.

### Monotonic timebase support

Particularly during system initialization, the "gold standard" system
reference clock can change by a large amount, in an instant. It's not
a best practice to yank the reference clock - in either direction - by
hours or days. In fact, some poorly-constructed use-cases do so.

To deal with this reality, clib_time_now(...) returns the number of
seconds since vpp started, *guaranteed to be monotonically
increasing, no matter what happens to the system reference clock*.

This is first-order important, to avoid breaking every active timer in
the system. The vpp host stack alone may account for tens of millions
of active timers. It's utterly impractical to track down and fix
timers, so we must deal with the issue at the timebase level.

Here's how it works. Prior to adjusting the clock rate, we collect the
kernel reference clock and the cpu clock:

```
  /* Ask the kernel and the CPU what time it is... */
  now_reference = unix_time_now ();
  now_clock = clib_cpu_time_now ();
```

Compute changes for both clocks since the last rate adjustment,
roughly 15 seconds ago:

```
  /* Compute change in the reference clock */
  delta_reference = now_reference - c->last_verify_reference_time;

  /* And change in the CPU clock */
  delta_clock_in_seconds = (f64) (now_clock - c->last_verify_cpu_time) *
    c->seconds_per_clock;
```

Delta_reference is key. Almost 100% of the time, delta_reference and
delta_clock_in_seconds are identical modulo one system-call
time. However, NTP or a privileged user can yank the system reference
time - in either direction - by an hour, a day, or a decade.

As described above, clib_time_now(...) must return monotonically
increasing answers to the question "how long has it been since vpp
started, in seconds." To do that, the clock rate adjustment algorithm
begins by recomputing the initial reference time:

```
  c->init_reference_time += (delta_reference - delta_clock_in_seconds);
```

It's easy to convince yourself that if the reference clock changes by
15.000000 seconds and the cpu clock tick time changes by 15.000000
seconds, the initial reference time won't change.

If, on the other hand, delta_reference is -86400.0 and delta clock is
15.0 - reference time jumped backwards by exactly one day in a
15-second rate update interval - we add -86415.0 to the initial
reference time.

Given the corrected initial reference time, we recompute the total
number of cpu ticks which have occurred since the corrected initial
reference time, at the current clock tick rate:

```
  c->total_cpu_time = (now_reference - c->init_reference_time)
    * c->clocks_per_second;
```

### Timebase precision

Cognoscenti may notice that vlib/clib\_time\_now(...) return a 64-bit
floating-point value; the number of seconds since vpp started.

Please see [this Wikipedia
article](https://en.wikipedia.org/wiki/Double-precision_floating-point_format)
for more information. C double-precision floating point numbers
(called f64 in the vpp code base) have a 53-bit effective mantissa,
and can accurately represent 15 decimal digits' worth of precision.

There are 315,360,000.000001 seconds in ten years plus one
microsecond. That string has exactly 15 decimal digits. The vpp time
base retains 1us precision for roughly 30 years.

vlib/clib\_time\_now do *not* provide precision in excess of 1e-6
seconds. If necessary, please use clib_cpu_time_now(...) for direct
access to the CPU clock-cycle counter. Note that the number of CPU
clock cycles per second varies significantly across CPU architectures.

Timer Wheels
------------

Vppinfra includes configurable timer wheel support. See the source
code in .../src/vppinfra/tw_timer_template.[ch], as well as a
considerable number of template instances defined in
.../src/vppinfra/tw_timer_<wheel-geometry-spec>.[ch].

Instantiation of tw_timer_template.h generates named structures to
implement specific timer wheel geometries. Choices include: number of
timer wheels (currently, 1 or 2), number of slots per ring (a power of
two), and the number of timers per "object handle".

Internally, user object/timer handles are 32-bit integers, so if one
selects 16 timers/object (4 bits), the resulting timer wheel handle is
limited to 2**28 objects.

Here are the specific settings required to generate a single 2048 slot
wheel which supports 2 timers per object:

```
    #define TW_TIMER_WHEELS 1
    #define TW_SLOTS_PER_RING 2048
    #define TW_RING_SHIFT 11
    #define TW_RING_MASK (TW_SLOTS_PER_RING -1)
    #define TW_TIMERS_PER_OBJECT 2
    #define LOG2_TW_TIMERS_PER_OBJECT 1
    #define TW_SUFFIX _2t_1w_2048sl
    #define TW_FAST_WHEEL_BITMAP 0
    #define TW_TIMER_ALLOW_DUPLICATE_STOP 0
```

See tw_timer_2t_1w_2048sl.h for a complete
example.

tw_timer_template.h is not intended to be #included directly. Client
codes can include multiple timer geometry header files, although
extreme caution would required to use the TW and TWT macros in such a
case.

### API usage examples

The unit test code in .../src/vppinfra/test_tw_timer.c provides a
concrete API usage example. It uses a synthetic clock to rapidly
exercise the underlying tw_timer_expire_timers(...) template.

There are not many API routines to call.

#### Initialize a two-timer, single 2048-slot wheel w/ a 1-second timer granularity

```
    tw_timer_wheel_init_2t_1w_2048sl (&tm->single_wheel,
                                     expired_timer_single_callback,
				      1.0 / * timer interval * / );
```

#### Start a timer

```
    handle = tw_timer_start_2t_1w_2048sl (&tm->single_wheel, elt_index,
                                          [0 | 1] / * timer id * / ,
                                          expiration_time_in_u32_ticks);
```

#### Stop a timer

```
    tw_timer_stop_2t_1w_2048sl (&tm->single_wheel, handle);
```

#### An expired timer callback

```
    static void
    expired_timer_single_callback (u32 * expired_timers)
    {
    	int i;
        u32 pool_index, timer_id;
        tw_timer_test_elt_t *e;
        tw_timer_test_main_t *tm = &tw_timer_test_main;

        for (i = 0; i < vec_len (expired_timers);
            {
            pool_index = expired_timers[i] & 0x7FFFFFFF;
            timer_id = expired_timers[i] >> 31;

            ASSERT (timer_id == 1);

            e = pool_elt_at_index (tm->test_elts, pool_index);

            if (e->expected_to_expire != tm->single_wheel.current_tick)
              {
              	fformat (stdout, "[%d] expired at %d not %d\n",
                         e - tm->test_elts, tm->single_wheel.current_tick,
                         e->expected_to_expire);
              }
         pool_put (tm->test_elts, e);
         }
     }
```

We use wheel timers extensively in the vpp host stack. Each TCP
session needs 5 timers, so supporting 10 million flows requires up to
50 million concurrent timers.

Timers rarely expire, so it's of utmost important that stopping and
restarting a timer costs as few clock cycles as possible.

Stopping a timer costs a doubly-linked list dequeue. Starting a timer
involves modular arithmetic to determine the correct timer wheel and
slot, and a list head enqueue.

Expired timer processing generally involves bulk link-list retirement
with user callback presentation. Some additional complexity at wheel
wrap time, to relocate timers from slower-turning timer wheels into
faster-turning wheels.

Format
------

Vppinfra format is roughly equivalent to printf.

Format has a few properties worth mentioning. Format's first argument is
a (u8 \*) vector to which it appends the result of the current format
operation. Chaining calls is very easy:

```c
    u8 * result;

    result = format (0, "junk = %d, ", junk);
    result = format (result, "more junk = %d\n", more_junk);
```

As previously noted, NULL pointers are perfectly proper 0-length
vectors. Format returns a (u8 \*) vector, **not** a C-string. If you
wish to print a (u8 \*) vector, use the "%v" format string. If you need
a (u8 \*) vector which is also a proper C-string, either of these
schemes may be used:

```c
    vec_add1 (result, 0)
    or
    result = format (result, "<whatever>%c", 0);
```

Remember to vec\_free() the result if appropriate. Be careful not to
pass format an uninitialized (u8 \*).

Format implements a particularly handy user-format scheme via the "%U"
format specification. For example:

```c
    u8 * format_junk (u8 * s, va_list *va)
    {
      junk = va_arg (va, u32);
      s = format (s, "%s", junk);
      return s;
    }

    result = format (0, "junk = %U, format_junk, "This is some junk");
```

format\_junk() can invoke other user-format functions if desired. The
programmer shoulders responsibility for argument type-checking. It is
typical for user format functions to blow up spectacularly if the
va\_arg(va, type) macros don't match the caller's idea of reality.

Unformat
--------

Vppinfra unformat is vaguely related to scanf, but considerably more
general.

A typical use case involves initializing an unformat\_input\_t from
either a C-string or a (u8 \*) vector, then parsing via unformat() as
follows:

```c
    unformat_input_t input;
    u8 *s = "<some-C-string>";

    unformat_init_string (&input, (char *) s, strlen((char *) s));
    /* or */
    unformat_init_vector (&input, <u8-vector>);
```

Then loop parsing individual elements:

```c
    while (unformat_check_input (&input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (&input, "value1 %d", &value1))
        ;/* unformat sets value1 */
      else if (unformat (&input, "value2 %d", &value2)
        ;/* unformat sets value2 */
      else
        return clib_error_return (0, "unknown input '%U'",
                                  format_unformat_error, input);
    }
```

As with format, unformat implements a user-unformat function capability
via a "%U" user unformat function scheme. Generally, one can trivially
transform "format (s, "foo %d", foo) -> "unformat (input, "foo %d", &foo)".

Unformat implements a couple of handy non-scanf-like format specifiers:

```c
    unformat (input, "enable %=", &enable, 1 /* defaults to 1 */);
    unformat (input, "bitzero %|", &mask, (1<<0));
    unformat (input, "bitone %|", &mask, (1<<1));
    <etc>
```

The phrase "enable %=" means "set the supplied variable to the default
value" if unformat parses the "enable" keyword all by itself. If
unformat parses "enable 123" set the supplied variable to 123.

We could clean up a number of hand-rolled "verbose" + "verbose %d"
argument parsing codes using "%=".

The phrase "bitzero %|" means "set the specified bit in the supplied
bitmask" if unformat parses "bitzero". Although it looks like it could
be fairly handy, it's very lightly used in the code base.

`%_` toggles whether or not to skip input white space.

For transition from skip to no-skip in middle of format string, skip input white space.  For example, the following:

```c
fmt = "%_%d.%d%_->%_%d.%d%_"
unformat (input, fmt, &one, &two, &three, &four);
```
matches input "1.2 -> 3.4".
Without this, the space after -> does not get skipped.


```

### How to parse a single input line

Debug CLI command functions MUST NOT accidentally consume input
belonging to other debug CLI commands. Otherwise, it's impossible to
script a set of debug CLI commands which "work fine" when issued one
at a time.

This bit of code is NOT correct:

```c
  /* Eats script input NOT beloging to it, and chokes! */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, ...))
	;
      else if (unformat (input, ...))
	;
      else
        return clib_error_return (0, "parse error: '%U'",
              			     format_unformat_error, input);
	}
    }
```

When executed as part of a script, such a function will return "parse
error: '<next-command-text>'" every time, unless it happens to be the
last command in the script.

Instead, use "unformat_line_input" to consume the rest of a line's
worth of input - everything past the path specified in the
VLIB_CLI_COMMAND declaration.

For example, unformat_line_input with "my_command" set up as shown
below and user input "my path is clear" will produce an
unformat_input_t that contains "is clear".

```c
    VLIB_CLI_COMMAND (...) = {
        .path = "my path",
    };
```

Here's a bit of code which shows the required mechanics, in full:

```c
    static clib_error_t *
    my_command_fn (vlib_main_t * vm,
                   unformat_input_t * input,
                   vlib_cli_command_t * cmd)
    {
      unformat_input_t _line_input, *line_input = &_line_input;
      u32 this, that;
      clib_error_t *error = 0;

      if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

      /*
       * Here, UNFORMAT_END_OF_INPUT is at the end of the line we consumed,
       * not at the end of the script...
       */
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
        {
           if (unformat (line_input, "this %u", &this))
             ;
           else if (unformat (line_input, "that %u", &that))
             ;
           else
             {
               error = clib_error_return (0, "parse error: '%U'",
              	     		     format_unformat_error, line_input);
               goto done;
             }
          }

    <do something based on "this" and "that", etc>

    done:
      unformat_free (line_input);
      return error;
    }
   /* *INDENT-OFF* */
   VLIB_CLI_COMMAND (my_command, static) = {
     .path = "my path",
     .function = my_command_fn",
   };
   /* *INDENT-ON* */

```


Vppinfra errors and warnings
----------------------------

Many functions within the vpp dataplane have return-values of type
clib\_error\_t \*. Clib\_error\_t's are arbitrary strings with a bit of
metadata \[fatal, warning\] and are easy to announce. Returning a NULL
clib\_error\_t \* indicates "A-OK, no error."

Clib\_warning(format-args) is a handy way to add debugging
output; clib warnings prepend function:line info to unambiguously locate
the message source. Clib\_unix\_warning() adds perror()-style Linux
system-call information. In production images, clib\_warnings result in
syslog entries.

Serialization
-------------

Vppinfra serialization support allows the programmer to easily serialize
and unserialize complex data structures.

The underlying primitive serialize/unserialize functions use network
byte-order, so there are no structural issues serializing on a
little-endian host and unserializing on a big-endian host.
