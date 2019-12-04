/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vnet/fib/fib_source.h>

static const char *fib_source_names[] = FIB_SOURCES;
static const char *fib_source_behaviour_names[] = FIB_SOURCE_BEHAVIOURS;

static fib_source_t fib_source_id = FIB_SOURCE_LAST+1;

typedef struct fib_source_prio_t_
{
    fib_source_priority_t fsp_class;
    fib_source_priority_t fsp_slot;
} fib_source_prio_t;

/**
 * for each client requested priority count the number pf uses of
 * that prio so we can asign is usage a slot number, and therefore
 * each request will have a unique value.
 */
STATIC_ASSERT_SIZEOF(fib_source_priority_t, 1);
static fib_source_priority_t fib_source_prio_by_class[0x100];

typedef struct fib_source_reg_t_
{
    fib_source_t fsr_source;
    const char *fsr_name;
    fib_source_behaviour_t fsr_behaviour;
    fib_source_prio_t fsr_prio;
} fib_source_reg_t;

static fib_source_reg_t *fib_source_regs;


u16
fib_source_get_prio (fib_source_t src)
{
    ASSERT(vec_len(fib_source_regs) > src);

    return (((u16)fib_source_regs[src].fsr_prio.fsp_class << 8) |
            fib_source_regs[src].fsr_prio.fsp_slot);
}

fib_source_behaviour_t
fib_source_get_behaviour (fib_source_t src)
{
    ASSERT(vec_len(fib_source_regs) > src);

    return (fib_source_regs[src].fsr_behaviour);
}

u8 *
format_fib_source (u8 *s, va_list *a)
{
    fib_source_t src = va_arg(*a, int);

    ASSERT(vec_len(fib_source_regs) > src);

    return (format(s, "%s", fib_source_regs[src].fsr_name));
}

fib_source_priority_cmp_t
fib_source_cmp (fib_source_t s1,
                fib_source_t s2)
{
    if (fib_source_get_prio(s1) <
        fib_source_get_prio(s2))
    {
        return (FIB_SOURCE_CMP_BETTER);
    }
    else if (fib_source_get_prio(s1) >
             fib_source_get_prio(s2))
    {
        return (FIB_SOURCE_CMP_WORSE);
    }
    return (FIB_SOURCE_CMP_EQUAL);
}

static void
fib_source_reg_init (fib_source_t src,
                     const char *name,
                     fib_source_priority_t prio,
                     fib_source_behaviour_t bh)
{
    fib_source_priority_t slot;
    fib_source_reg_t *fsr;

    /*
     * ensure we assign a unique priority to each request
     * otherwise different source will be treated like ECMP
     */
    slot = fib_source_prio_by_class[prio]++;

    vec_validate(fib_source_regs, src);

    fsr = &fib_source_regs[src];
    fsr->fsr_source = src;
    fsr->fsr_name = strdup(name);
    fsr->fsr_prio.fsp_class = prio;
    fsr->fsr_prio.fsp_slot = slot;
    fsr->fsr_behaviour = bh;
}

fib_source_t
fib_source_allocate (const char *name,
                     fib_source_priority_t prio,
                     fib_source_behaviour_t bh)
{
    fib_source_t src;

    // max value range
    ASSERT(fib_source_id < 255);
    if (fib_source_id == 255)
        return (FIB_SOURCE_INVALID);

    src = fib_source_id++;

    fib_source_reg_init(src, name, prio, bh);

    return (src);
}

void
fib_source_register (fib_source_t src,
                     fib_source_priority_t prio,
                     fib_source_behaviour_t bh)
{
    fib_source_reg_init(src, fib_source_names[src], prio, bh);
}

static u8 *
format_fib_source_reg (u8 *s, va_list *a)
{
    fib_source_reg_t *fsr = va_arg(*a, fib_source_reg_t*);

    s = format(s, "[%d] %U prio:%d.%d behaviour:%s",
               fsr->fsr_source,
               format_fib_source, fsr->fsr_source,
               fsr->fsr_prio.fsp_class, fsr->fsr_prio.fsp_slot,
               fib_source_behaviour_names[fsr->fsr_behaviour]);

    return (s);
}

static int
fib_source_reg_cmp_for_sort (void * v1,
                             void * v2)
{
    fib_source_reg_t *fsr1 = v1, *fsr2 = v2;

    return (fib_source_get_prio(fsr1->fsr_source) -
            fib_source_get_prio(fsr2->fsr_source));
}

void
fib_source_walk (fib_source_walk_t fn,
                 void *ctx)
{
    fib_source_reg_t *fsr;

    vec_foreach(fsr, fib_source_regs)
    {
        if (WALK_STOP == fn(fsr->fsr_source,
                            fsr->fsr_name,
                            fsr->fsr_prio.fsp_class,
                            fsr->fsr_behaviour,
                            ctx))
            break;
    }
}

static clib_error_t *
fib_source_show (vlib_main_t * vm,
		 unformat_input_t * input,
		 vlib_cli_command_t * cmd)
{
    fib_source_reg_t *fsr, *fsrs;

    fsrs = vec_dup(fib_source_regs);

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
	if (unformat (input, "prio")   ||
	    unformat (input, "priority"))
            vec_sort_with_function(fsrs, fib_source_reg_cmp_for_sort);
    }
    vec_foreach(fsr, fsrs)
    {
        vlib_cli_output(vm, "%U", format_fib_source_reg, fsr);
    }
    vec_free(fsrs);

    return (NULL);
}

VLIB_CLI_COMMAND (show_fib_sources, static) = {
    .path = "show fib source",
    .function = fib_source_show,
    .short_help = "show fib source [prio]",
};


void
fib_source_module_init (void)
{
#define _(s,p,b) fib_source_register(s,p,b);
    foreach_fib_source
#undef _
}
