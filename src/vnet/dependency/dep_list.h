/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Copyright (c) 2021 Graphiant and/or its affiliates.
 *
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
/**
 * @brief a hetrogeneous w.r.t. FIB node type, list of FIB nodes.
 * Since we cannot use C pointers, due to memeory reallocs, the next/prev
 * are described as an index to an element. Each element contains a pointer
 * (key:{type, index}) to a FIB node.
 */

#ifndef __DEP_LIST_H__
#define __DEP_LIST_H__

#include <vnet/dependency/dep.h>

extern dep_list_t dep_list_create (void);
extern void dep_list_destroy (dep_list_t *list);

extern u32 dep_list_push_front (dep_list_t head, int owner_id, dep_type_t type,
				dep_index_t index);
extern u32 dep_list_push_back (dep_list_t head, int owner_id, dep_type_t type,
			       dep_index_t index);
extern void dep_list_remove (dep_list_t head, u32 sibling);
extern void dep_list_elt_remove (u32 sibling);

extern int dep_list_advance (u32 sibling);

extern int dep_list_get_front (dep_list_t head, dep_ptr_t *ptr);

extern int dep_list_elt_get_next (u32 elt, dep_ptr_t *ptr);

extern u32 dep_list_get_size (dep_list_t head);

/**
 * @brief Callback function invoked during a list walk
 */
typedef walk_rc_t (*dep_list_walk_cb_t) (dep_ptr_t *owner, void *args);

extern void dep_list_walk (dep_list_t head, dep_list_walk_cb_t fn, void *args);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
