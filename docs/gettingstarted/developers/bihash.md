Bounded-index Extensible Hashing (bihash)
=========================================

Vpp uses bounded-index extensible hashing to solve a variety of
exact-match (key, value) lookup problems. Benefits of the current
implementation:

* Very high record count scaling, tested to 100,000,000 records.
* Lookup performance degrades gracefully as the number of records increases
* No reader locking required
* Template implementation, it's easy to support arbitrary (key,value) types

Bounded-index extensible hashing has been widely used in databases for
decades.

Bihash uses a two-level data structure:

```
    +-----------------+
    | bucket-0        |
    |  log2_size      |
    |  backing store  |
    +-----------------+
    | bucket-1        |
    |  log2_size      |           +--------------------------------+
    |  backing store  | --------> | KVP_PER_PAGE * key-value-pairs |
    +-----------------+           | page 0                         |
         ...                      +--------------------------------+
    +-----------------+           | KVP_PER_PAGE * key-value-pairs |
    | bucket-2**N-1   |           | page 1                         |
    |  log2_size      |           +--------------------------------+
    |  backing store  |                       ---
    +-----------------+           +--------------------------------+
                                  | KVP_PER_PAGE * key-value-pairs |
                                  | page 2**(log2(size)) - 1       |
                                  +--------------------------------+
```

Discussion of the algorithm
---------------------------

This structure has a couple of major advantages. In practice, each
bucket entry fits into a 64-bit integer. Coincidentally, vpp's target
CPU architectures support 64-bit atomic operations. When modifying the
contents of a specific bucket, we do the following:

* Make a working copy of the bucket's backing storage
* Atomically swap a pointer to the working copy into the bucket array
* Change the original backing store data
* Atomically swap back to the original

So, no reader locking is required to search a bihash table.

At lookup time, the implementation computes a key hash code. We use
the least-significant N bits of the hash to select the bucket.

With the bucket in hand, we learn log2 (nBackingPages) for the
selected bucket. At this point, we use the next log2_size bits from
the hash code to select the specific backing page in which the
(key,value) page will be found.

Net result: we search **one** backing page, not 2**log2_size
pages. This is a key property of the algorithm.

When sufficient collisions occur to fill the backing pages for a given
bucket, we double the bucket size, rehash, and deal the bucket
contents into a double-sized set of backing pages. In the future, we
may represent the size as a linear combination of two powers-of-two,
to increase space efficiency.

To solve the "jackpot case" where a set of records collide under
hashing in a bad way, the implementation will fall back to linear
search across 2**log2_size backing pages on a per-bucket basis.

To maintain *space* efficiency, we should configure the bucket array
so that backing pages are effectively utilized. Lookup performance
tends to change *very little* if the bucket array is too small or too
large.

Bihash depends on selecting an effective hash function. If one were to
use a truly broken hash function such as "return 1ULL." bihash would
still work, but it would be equivalent to poorly-programmed linear
search.

We often use cpu intrinsic functions - think crc32 - to rapidly
compute a hash code which has decent statistics.

Bihash Cookbook
---------------

### Using current (key,value) template instance types

It's quite easy to use one of the template instance types. As of this
writing, .../src/vppinfra provides pre-built templates for 8, 16, 20,
24, 40, and 48 byte keys, u8 * vector keys, and 8 byte values.

See .../src/vppinfra/{bihash_<key-size>_8}.h

To define the data types, #include a specific template instance, most
often in a subsystem header file:

```c
     #include <vppinfra/bihash_8_8.h>
```

If you're building a standalone application, you'll need to define the
various functions by #including the method implementation file in a C
source file.

The core vpp engine currently uses most if not all of the known bihash
types, so you probably won't need to #include the method
implementation file.


```c
     #include <vppinfra/bihash_template.c>
```

Add an instance of the selected bihash data structure to e.g. a
"main_t" structure:

```c
    typedef struct
    {
      ...
      BVT (clib_bihash) hash_table;
      or
      clib_bihash_8_8_t hash_table;
      ...
    } my_main_t;
```

The BV macro concatenate its argument with the value of the
preprocessor symbol BIHASH_TYPE. The BVT macro concatenates its
argument with the value of BIHASH_TYPE and the fixed-string "_t". So
in the above example, BVT (clib_bihash) generates "clib_bihash_8_8_t".

If you're sure you won't decide to change the template / type name
later, it's perfectly OK to code "clib_bihash_8_8_t" and so forth.

In fact, if you #include multiple template instances in a single
source file, you **must** use fully-enumerated type names. The macros
stand no chance of working.

### Initializing a bihash table

Call the init function as shown. As a rough guide, pick a number of
buckets which is approximately
number_of_expected_records/BIHASH_KVP_PER_PAGE from the relevant
template instance header-file.  See previous discussion.

The amount of memory selected should easily contain all of the
records, with a generous allowance for hash collisions. Bihash memory
is allocated separately from the main heap, and won't cost anything
except kernel PTE's until touched, so it's OK to be reasonably
generous.

For example:

```c
    my_main_t *mm = &my_main;
    clib_bihash_8_8_t *h;

    h = &mm->hash_table;

    clib_bihash_init_8_8 (h, "test", (u32) number_of_buckets,
                           (uword) memory_size);
```

### Add or delete a key/value pair

Use BV(clib_bihash_add_del), or the explicit type variant:

```c
   clib_bihash_kv_8_8_t kv;
   clib_bihash_8_8_t * h;
   my_main_t *mm = &my_main;
   clib_bihash_8_8_t *h;

   h = &mm->hash_table;
   kv.key = key_to_add_or_delete;
   kv.value = value_to_add_or_delete;

   clib_bihash_add_del_8_8 (h, &kv, is_add /* 1=add, 0=delete */);
```

In the delete case, kv.value is irrelevant. To change the value associated
with an existing (key,value) pair, simply re-add the [new] pair.

### Simple search

The simplest possible (key, value) search goes like so:

```c
   clib_bihash_kv_8_8_t search_kv, return_kv;
   clib_bihash_8_8_t * h;
   my_main_t *mm = &my_main;
   clib_bihash_8_8_t *h;

   h = &mm->hash_table;
   search_kv.key = key_to_add_or_delete;

   if (clib_bihash_search_8_8 (h, &search_kv, &return_kv) < 0)
     key_not_found();
   else
     key_found();
```

Note that it's perfectly fine to collect the lookup result

```c
   if (clib_bihash_search_8_8 (h, &search_kv, &search_kv))
     key_not_found();
   etc.
```

### Bihash vector processing

When processing a vector of packets which need a certain lookup
performed, it's worth the trouble to compute the key hash, and
prefetch the correct bucket ahead of time.

Here's a sketch of one way to write the required code:

Dual-loop:
* 6 packets ahead, prefetch 2x vlib_buffer_t's and 2x packet data
  required to form the record keys
* 4 packets ahead, form 2x record keys and call BV(clib_bihash_hash)
  or the explicit hash function to calculate the record hashes.
  Call 2x BV(clib_bihash_prefetch_bucket) to prefetch the buckets
* 2 packets ahead, call 2x BV(clib_bihash_prefetch_data) to prefetch
  2x (key,value) data pages.
* In the processing section, call 2x BV(clib_bihash_search_inline_with_hash)
  to perform the search

Programmer's choice whether to stash the hash code somewhere in
vnet_buffer(b) metadata, or to use local variables.

Single-loop:
* Use simple search as shown above.

### Walking a bihash table

A fairly common scenario to build "show" commands involves walking a
bihash table. It's simple enough:

```c
   my_main_t *mm = &my_main;
   clib_bihash_8_8_t *h;
   void callback_fn (clib_bihash_kv_8_8_t *, void *);

   h = &mm->hash_table;

   BV(clib_bihash_foreach_key_value_pair) (h, callback_fn, (void *) arg);
```
To nobody's great surprise: clib_bihash_foreach_key_value_pair
iterates across the entire table, calling callback_fn with active
entries.

#### Bihash table iteration safety

The iterator template "clib_bihash_foreach_key_value_pair" must be
used with a certain amount of care. For one thing, the iterator
template does _not_ take the bihash hash table writer lock. If your
use-case requires it, lock the table.

For another, the iterator template is not safe under all conditions:

* It's __OK to delete__ bihash table entries during a table-walk. The
iterator checks whether the current bucket has been freed after each
_callback_fn(...)_ invocation.

* It is __not OK to add__ entries during a table-walk.

The add-during-walk case involves a jackpot: while processing a
key-value-pair in a particular bucket, add a certain number of
entries. By luck, assume that one or more of the added entries causes
the __current bucket__ to split-and-rehash.

Since we rehash KVP's to different pages based on what amounts to a
different hash function, either of these things can go wrong:

* We may revisit previously-visited entries. Depending on how one
coded the use-case, we could end up in a recursive-add situation.

* We may skip entries that have not been visited

One could build an add-safe iterator, at a significant cost in
performance: copy the entire bucket, and walk the copy.

It's hard to imagine a worthwhile add-during walk use-case in the
first place; let alone one which couldn't be implemented by walking
the table without modifying it, then adding a set of records.

### Creating a new template instance

Creating a new template is easy. Use one of the existing templates as
a model, and make the obvious changes. The hash and key_compare
methods are performance-critical in multiple senses.

If the key compare method is slow, every lookup will be slow. If the
hash function is slow, same story. If the hash function has poor
statistical properties, space efficiency will suffer. In the limit, a
bad enough hash function will cause large portions of the table to
revert to linear search.

Use of the best available vector unit is well worth the trouble in the
hash and key_compare functions.
