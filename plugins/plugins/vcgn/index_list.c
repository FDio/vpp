/* 
 *------------------------------------------------------------------
 * index_list.c - vector-index-based lists. 64-bit pointers suck.
 *
 * Copyright (c) 2008-2009, 2011 Cisco and/or its affiliates.
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

#include <stdio.h>
#include <string.h>
//#include <clib_lite.h>
#include <vppinfra/vec.h>
#include "index_list.h"

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
void index_slist_addhead (index_slist_t *headp,
                          u8 *vector, u32 elsize, u32 offset, u32 index_to_add)
{
    return (index_slist_addhead_inline(headp, vector, elsize, offset,
                                      index_to_add));
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

int index_slist_remelem (index_slist_t *headp,
                         u8 *vector, u32 elsize, u32 offset, 
                         u32 index_to_delete)
{
    return (index_slist_remelem_inline(headp, vector, elsize, offset,
                                       index_to_delete));
}


/*
 * index_dlist_addtail
 *
 * Append the indicated vector element to the doubly-linked list
 * whose first element is pointed to by headp.
 * 
 * args: head_index -- listhead vector element index.
 *       vector -- vector containing the list
 *       elsize -- size of an element in this vector
 *       offset -- offset in each vector element of this list thread
 * index_to_add -- index in the vector to add to the list
 *
 * Do not call this routine to create the listhead. Simply set
 * index_dlist->next = index_dlist->prev = index of item.
 *
 * Try not to screw up the args.
 */

void index_dlist_addtail (u32 head_index, u8 *vector, u32 elsize, 
                          u32 offset, u32 index_to_add)
{
    index_dlist_t *elp;
    index_dlist_t *elp_next;
    index_dlist_t *headp;

    headp = (index_dlist_t *)(vector + offset + elsize*head_index);
    elp = (index_dlist_t *)(vector + offset + elsize*index_to_add);
    elp->next = index_to_add;
    elp->prev = index_to_add;

    elp->next = headp->next;
    headp->next = index_to_add;
    
    elp_next = (index_dlist_t *)(vector + offset + elsize*elp->next);
    elp->prev = elp_next->prev;
    elp_next->prev = index_to_add;
}

u32 index_dlist_remelem (u32 head_index, 
                         u8 *vector, u32 elsize, u32 offset, 
                         u32 index_to_delete)
{
    u32 rv = head_index;
    index_dlist_t *headp, *elp, *elp_next;

    elp = (index_dlist_t *)(vector + offset + elsize*index_to_delete);

    /* Deleting the head index? */
    if (PREDICT_FALSE(head_index == index_to_delete)) {
        rv = elp->next;
        /* The only element on the list? */
        if (PREDICT_FALSE(rv == head_index))
            rv = EMPTY;
    }
    
    headp = (index_dlist_t *)(vector + offset + elsize*elp->prev);
    headp->next = elp->next;
    elp_next = (index_dlist_t *)(vector + offset + elsize*elp->next);
    elp_next->prev = elp->prev;

    elp->next = elp->prev = EMPTY;
        
    return rv;
}


#ifdef TEST_CODE2

typedef struct tv_ {
    char junk[43];
    index_dlist_t l;
} tv_t;


void index_list_test_cmd(int argc, unsigned long *argv)
{
    int i, j;
    u32 head_index;
    index_dlist_t *headp;
    tv_t *tp=0;
    
    vec_validate(tp, 3);
    head_index = 3;

    memset(tp, 0xa, sizeof(tp[0])*vec_len(tp));

    /* Here's how to set up the head element... */
    headp = &((tp + head_index)->l);
    headp->next = headp->prev = head_index;
    
    for (i = 0; i < 3; i++) {
        index_dlist_addtail(head_index, (u8 *)tp, sizeof(tp[0]), 
                            STRUCT_OFFSET_OF(tv_t, l), i);
        printf("headp next %d prev %d\n",
               headp->next, headp->prev);
        for (j = 0; j <= 3; j++) {
            printf ("[%d]: next %d prev %d\n", j,
                    tp[j].l.next, tp[j].l.prev);
        }
        printf("---------------\n");

    }

    printf("After all adds:\n");

    printf("headp next %d prev %d\n",
           headp->next, headp->prev);

    for (j = 0; j <= 3; j++) {
        printf ("[%d]: next %d prev %d\n", j,
                tp[j].l.next, tp[j].l.prev);
    }
    printf("---------------\n");

    head_index = index_dlist_remelem (head_index, (u8 *)tp, sizeof(tp[0]), 
                                      STRUCT_OFFSET_OF(tv_t, l), 1);

    printf("after delete 1, head index %d\n", head_index);
    headp = &((tp + head_index)->l);
    printf("headp next %d prev %d\n",
           headp->next, headp->prev);
    for (j = 0; j <= 3; j++) {
        printf ("[%d]: next %d prev %d\n", j,
                tp[j].l.next, tp[j].l.prev);
    }
    printf("---------------\n");

    index_dlist_addtail(head_index, (u8 *)tp, sizeof(tp[0]), 
                        STRUCT_OFFSET_OF(tv_t, l), 1);
    
    printf("after re-add 1, head index %d\n", head_index);
    headp = &((tp + head_index)->l);
    printf("headp next %d prev %d\n",
           headp->next, headp->prev);
    for (j = 0; j <= 3; j++) {
        printf ("[%d]: next %d prev %d\n", j,
                tp[j].l.next, tp[j].l.prev);
    }
    printf("---------------\n");

    for (i = 3; i >= 0; i--) {
        head_index = index_dlist_remelem (head_index, (u8 *)tp, sizeof(tp[0]), 
                            STRUCT_OFFSET_OF(tv_t, l), i);
        printf("after delete, head index %d\n", head_index);
        if (head_index != EMPTY) {
            headp = &((tp + head_index)->l);
            printf("headp next %d prev %d\n",
                   headp->next, headp->prev);
            for (j = 0; j <= 3; j++) {
                printf ("[%d]: next %d prev %d\n", j,
                        tp[j].l.next, tp[j].l.prev);
            }
        } else {
            printf("empty list\n");
        }
        printf("---------------\n");
    }
}
#endif /* test code 2 */

#ifdef TEST_CODE

typedef struct tv_ {
    char junk[43];
    index_slist_t l;
} tv_t;


void index_list_test_cmd(int argc, unsigned long *argv)
{
    int i, j;
    tv_t *tp = 0;
    index_slist_t *buckets = 0;

    vec_add1((u32 *)buckets, EMPTY);
    vec_validate(tp, 9);
    
    for (i = 0; i < 10; i++) {
        index_slist_addhead(buckets, (u8 *)tp, sizeof(*tp), 
                            STRUCT_OFFSET_OF(tv_t, l), i);
    }
    
    printf ("after adds, buckets[0] = %u\n", buckets[0]);

    for (j = 0; j < 10; j++) {
        printf("tp[%d] next %u\n", j, tp[j].l);
        
    }

    for (i = 0; i < 10; i++) {
        if (PREDICT_FALSE(index_slist_remelem(buckets, (u8 *) tp, sizeof(*tp), 
                                STRUCT_OFFSET_OF(tv_t, l), i))) {
            printf("OUCH: remelem failure at index %d\n", i);
        }
        if (PREDICT_FALSE(tp[i].l.next != EMPTY)) {
            printf("OUCH: post-remelem next not EMPTY, index %d\n", i);
        }
    }

    printf ("after deletes, buckets[0] = %x\n", buckets[0]);

    for (i = 0; i < 10; i++) {
        index_slist_addhead(buckets, (u8 *)tp, sizeof(*tp), 
                            STRUCT_OFFSET_OF(tv_t, l), i);
    }
    
    printf ("after adds, buckets[0] = %u\n", buckets[0]);

    for (j = 0; j < 10; j++) {
        printf("tp[%d] next %u\n", j, tp[j].l);
        
    }

    for (i = 9; i >= 0; i--) {
        if (PREDICT_FALSE(index_slist_remelem(buckets, (u8 *) tp, sizeof(*tp), 
                                STRUCT_OFFSET_OF(tv_t, l), i))) {
            printf("OUCH: remelem failure at index %d\n", i);
        }
        if ((tp[i].l.next != EMPTY)) {
            printf("OUCH: post-remelem next not EMPTY, index %d\n", i);
        }
    }

    printf ("after deletes, buckets[0] = %x\n", buckets[0]);

    printf("add evens, then odds...\n");

    for (i = 0; i < 10; i += 2) {
        index_slist_addhead(buckets, (u8 *)tp, sizeof(*tp), 
                            STRUCT_OFFSET_OF(tv_t, l), i);

        printf ("head = buckets[0].next = %d\n", buckets[0].next);
        for (j = 0; j < 10; j++) {
            printf("tp[%d] next %u\n", j, tp[j].l);
        }
        printf("-------------\n");
    }
    
    for (i = 1; i < 10; i += 2) {
        index_slist_addhead(buckets, (u8 *)tp, sizeof(*tp), 
                            STRUCT_OFFSET_OF(tv_t, l), i);

        printf ("head = buckets[0].next = %d\n", buckets[0].next);
        for (j = 0; j < 10; j++) {
            printf("tp[%d] next %u\n", j, tp[j].l);
        }
        printf("-------------\n");
    }
    
    printf ("after adds, buckets[0] = %u\n", buckets[0]);

    for (j = 0; j < 10; j++) {
        printf("tp[%d] next %u\n", j, tp[j].l);
        
    }

    for (i = 9; i >= 0; i--) {
        if (PREDICT_FALSE(index_slist_remelem(buckets, (u8 *) tp, sizeof(*tp), 
                                STRUCT_OFFSET_OF(tv_t, l), i))) {
            printf("OUCH: remelem failure at index %d\n", i);
        }
        if (PREDICT_FALSE(tp[i].l.next != EMPTY)) {
            printf("OUCH: post-remelem next not EMPTY, index %d\n", i);
        }
    }

    printf ("after deletes, buckets[0] = %x\n", buckets[0]);

    vec_free(buckets);
    vec_free(tp);
}
#endif /* test code */
