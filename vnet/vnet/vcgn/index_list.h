/* 
 *------------------------------------------------------------------
 * index_list.h - vector-index-based doubly-linked lists
 *
 * Copyright (c) 2008-2009 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifndef _INDEX_LIST_H_
#define _INDEX_LIST_H_ 1

/* An index we can't possibly see in practice... */
#define EMPTY ((u32)~0)

typedef struct index_slist_ {
    u32 next;
} index_slist_t;

/*
 * index_slist_addhead
 *
 * args:  headp -- pointer to e.g. a hash bucket
 *       vector -- vector containing the list
 *       elsize -- size of an element in this vector
 *       offset -- offset in each vector element of this list thread
 * index_to_add -- index in the vector to add to the list
 *
 * Adds new items to the head of the list. Try not to screw up the args!
 */
static inline void 
              index_slist_addhead_inline (index_slist_t *headp,
                                          u8 *vector, u32 elsize, 
                                          u32 offset, u32 index_to_add)
{
    index_slist_t *addme;

    addme = (index_slist_t *)(vector + offset + elsize*index_to_add);
    addme->next = EMPTY;

    if (headp->next == EMPTY) {
        headp->next = index_to_add;
        return;
    } else {
        addme->next = headp->next;
        headp->next = index_to_add;
    }
}

/*
 * index_slist_remelem
 *
 * args:  headp -- pointer to e.g. a hash bucket
 *       vector -- vector containing the list
 *       elsize -- size of an element in this vector
 *       offset -- offset in each vector element of this list thread
 * index_to_del -- index in the vector to delete from the list
 *
 * Try not to screw up the args!
 */

static inline int 
              index_slist_remelem_inline (index_slist_t *headp,
                                              u8 *vector, u32 elsize, 
                                              u32 offset, u32 index_to_delete)
{
    index_slist_t *findme;
    index_slist_t *prev;
    index_slist_t *cur;

    findme = (index_slist_t *)(vector + offset + elsize*index_to_delete);

    if (headp->next == index_to_delete) {
        headp->next = findme->next;
        findme->next = EMPTY;
        return 0;
    }

    prev = (index_slist_t *)(vector + offset + elsize*headp->next);
    cur = (index_slist_t *)(vector + offset + elsize*prev->next);
    while (cur != findme) {
        if (cur->next == EMPTY)
            return (1);
        prev = cur;
        cur = (index_slist_t *)(vector + offset + elsize*cur->next);
    }
    prev->next = findme->next;
    findme->next = EMPTY;
    return 0;
}

void index_slist_addhead (index_slist_t *headp, 
                          u8 *vector, u32 elsize, u32 offset, u32 index);
int index_slist_remelem (index_slist_t *headp,
                         u8 *vector, u32 elsize, u32 offset, u32 index);

typedef struct index_dlist_ {
    u32 next;
    u32 prev;
} index_dlist_t;

void index_dlist_addtail (u32 head_index, u8 *vector, u32 elsize, 
                          u32 offset, u32 index_to_add);

u32 index_dlist_remelem (u32 head_index, 
                         u8 *vector, u32 elsize, u32 offset, 
                         u32 index_to_delete);
#endif /* _INDEX_LIST_H_ */
