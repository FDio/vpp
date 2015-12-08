/* 
 *------------------------------------------------------------------
 * spp_timers.h
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
#ifndef __SPP_TIMERS_H__
#define __SPP_TIMERS_H__


typedef struct d_list_el_ {
    struct d_list_el_ *next;
    struct d_list_el_ *prev;
} d_list_el_t;

/*
 * d_list_init
 */

static inline void d_list_init (d_list_el_t *headp)
{
    headp->prev = headp->next = headp;
}

/*
 * d_list_init - add at head of list
 */

static inline void d_list_add_head (d_list_el_t *headp, 
                                                  d_list_el_t *elp)
{
    ASSERT(elp->prev == elp);     /* multiple enqueue, BAD! */
    ASSERT(elp->next == elp);

    elp->next = headp->next;
    headp->next = elp;
    elp->prev = elp->next->prev;
    elp->next->prev = elp;
}

/*
 * d_list_add_tail - add element at tail of list
 */
static inline void d_list_add_tail (d_list_el_t *headp, 
                                                  d_list_el_t *elp)
{
    ASSERT(elp->prev == elp);     /* multiple enqueue, BAD! */
    ASSERT(elp->next == elp);

    headp = headp->prev;

    elp->next = headp->next;
    headp->next = elp;
    elp->prev = elp->next->prev;
    elp->next->prev = elp;
}

/*
 * d_list_rem_head - removes first element from list
 */
static inline d_list_el_t *d_list_rem_head (d_list_el_t *headp)
{
    d_list_el_t *elp;

    elp = headp->next;
    if (elp == headp)
        return (NULL);
    headp->next = elp->next;
    elp->next->prev = elp->prev;

    elp->next = elp->prev = elp;
    return (elp);
}

/*
 * d_list_rem_elem - removes specific element from list.
 */
static inline void d_list_rem_elem (d_list_el_t *elp)
{
    d_list_el_t *headp;

    headp = elp->prev;

    headp->next = elp->next;
    elp->next->prev = elp->prev;
    elp->next = elp->prev = elp;
}

#define TIMER_BKTS_PER_WHEEL	128 /* power of 2, please */
#define TIMER_NWHEELS   	4

typedef struct {
    i32 curindex;               /* current index for this wheel */
    d_list_el_t *bkts;          /* vector of bucket listheads */
} spp_timer_wheel_t;


typedef struct {
    u64 next_run_ticks;         /* Next time we expire timers */
    spp_timer_wheel_t **wheels; /* pointers to wheels */
} spp_timer_axle_t;


typedef struct {
    d_list_el_t el;
    u16 cb_index;
    u16 flags;
    u64 expires;
} spp_timer_t;

#define SPP_TIMER_RUNNING	0x0001


/*
 * prototypes
 */
void spp_timer_set_ticks_per_ms(u64);
void spp_timer_axle_init (spp_timer_axle_t *ta);
void spp_timer_expire(spp_timer_axle_t *ta, u64 now);
void spp_timer_final_init(void);

void spp_timer_start(spp_timer_t *tp);
void spp_timer_start_axle(spp_timer_axle_t *ta, spp_timer_t *tp);
void spp_timer_stop(spp_timer_t *tp);
u16 spp_timer_register_callback (void (*fp)(spp_timer_t *));

#endif /* __SPP_TIMERS_H__ */
