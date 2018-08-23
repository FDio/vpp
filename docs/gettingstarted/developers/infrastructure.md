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
alignment for data elements via the [vec]()\*\_aligned macros.

Vectors elements can be any C type e.g. (int, double, struct bar). This
is also true for data types built atop vectors (e.g. heap, pool, etc.).
Many macros have \_a variants supporting alignment of vector data and
\_h variants supporting non-zero-length vector headers. The \_ha
variants support both.

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
typical for user format functions to blow up if the va\_arg(va,
type) macros don't match the caller's idea of reality.

Unformat
--------

Vppinfra unformat is vaguely related to scanf, but considerably more
general.

A typical use case involves initializing an unformat\_input\_t from
either a C-string or a (u8 \*) vector, then parsing via unformat() as
follows:

```c
    unformat_input_t input;

    unformat_init_string (&input, "<some-C-string>");
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
via a "%U" user unformat function scheme.

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
