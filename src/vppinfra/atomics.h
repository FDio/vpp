/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
 * Copyright (c) 2018 Arm Limited. and/or its affiliates.
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

#ifndef included_clib_atomics_h
#define included_clib_atomics_h

/* Legacy __sync builtins */

/* Full Barrier */
#define clib_atomic_fetch_add(a, b) __sync_fetch_and_add(a, b)
#define clib_atomic_fetch_sub(a, b) __sync_fetch_and_sub(a, b)
#define clib_atomic_fetch_and(a, b) __sync_fetch_and_and(a, b)
#define clib_atomic_fetch_xor(a, b) __sync_fetch_and_xor(a, b)
#define clib_atomic_fetch_or(a, b) __sync_fetch_and_or(a, b)
#define clib_atomic_fetch_nand(a, b) __sync_fetch_nand(a, b)

#define clib_atomic_add_fetch(a, b) __sync_add_and_fetch(a, b)
#define clib_atomic_sub_fetch(a, b) __sync_sub_and_fetch(a, b)
#define clib_atomic_and_fetch(a, b) __sync_and_and_fetch(a, b)
#define clib_atomic_xor_fetch(a, b) __sync_xor_and_fetch(a, b)
#define clib_atomic_or_fetch(a, b) __sync_or_and_fetch(a, b)
#define clib_atomic_nand_fetch(a, b) __sync_nand_and_fetch(a, b)

#define clib_atomic_cmp_and_swap(addr,old,new) __sync_val_compare_and_swap(addr, old, new)
#define clib_atomic_bool_cmp_and_swap(addr,old,new) __sync_bool_compare_and_swap(addr, old, new)

#define clib_atomic_test_and_set(a) __sync_lock_test_and_set(a, 1)
#define clib_atomic_release(a) __sync_lock_release(a)

#define clib_atomic_store_rel_n(a, b) __atomic_store_n ((a), (b), __ATOMIC_RELEASE)
#define clib_atomic_swap_acq_n(a, b) __atomic_exchange_n ((a), (b), __ATOMIC_ACQUIRE)

#endif /* included_clib_atomics_h */
