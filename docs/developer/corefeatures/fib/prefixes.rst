.. _prefixes:

Prefixes
^^^^^^^^

Some nomenclature used to describe prefixes:

* 1.1.1.1 This is an address since it has no associated mask
* 1.1.1.0/24 This is a prefix.
* 1.1.1.1/32 This is a host prefix (the mask length is the size of the address).

Prefix A is more specific than B if its mask length is longer, and less specific if
the mask is shorter. For example, 1.1.1.0/28 is more specific than 1.1.1.0/24. A
less specific prefix that overlaps with a more specific is the **covering** prefix.
For example, 1.1.1.0/24 is the covering prefix for 1.1.1.0/28 and 1.1.1.0/28 is termed
the **covered** prefix. A covering prefix is therefore always less specific than its
covered prefixes.
