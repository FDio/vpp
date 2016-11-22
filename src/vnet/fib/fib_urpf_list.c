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

#include <vnet/fib/fib_urpf_list.h>
#include <vnet/adj/adj.h>

/**
 * @brief pool of all fib_urpf_list
 */
fib_urpf_list_t *fib_urpf_list_pool;

u8 *
format_fib_urpf_list (u8 *s, va_list args)
{
    fib_urpf_list_t *urpf;
    index_t ui;
    u32 *swi;

    ui = va_arg(args, index_t);

    if (INDEX_INVALID != ui)
    {
        urpf = fib_urpf_list_get(ui);

        s = format(s, "uPRF-list:%d len:%d itfs:[",
                   ui, vec_len(urpf->furpf_itfs));

        vec_foreach(swi, urpf->furpf_itfs)
        {
            s = format(s, "%d, ", *swi);
        }
        s = format(s, "]");
    }
    else
    {
        s = format(s, "uRPF-list: None");
    }

    return (s);
}

index_t
fib_urpf_list_alloc_and_lock (void)
{
    fib_urpf_list_t *urpf;

    pool_get(fib_urpf_list_pool, urpf);
    memset(urpf, 0, sizeof(*urpf));

    urpf->furpf_locks++;

    return (urpf - fib_urpf_list_pool);
}

void
fib_urpf_list_unlock (index_t ui)
{
    fib_urpf_list_t *urpf;

    if (INDEX_INVALID == ui)
	return;

    urpf = fib_urpf_list_get(ui);

    urpf->furpf_locks--;

    if (0 == urpf->furpf_locks)
    {
	vec_free(urpf->furpf_itfs);
	pool_put(fib_urpf_list_pool, urpf);
    }
}

void
fib_urpf_list_lock (index_t ui)
{
    fib_urpf_list_t *urpf;

    urpf = fib_urpf_list_get(ui);

    urpf->furpf_locks++;
}

/**
 * @brief Append another interface to the list.
 */
void
fib_urpf_list_append (index_t ui,
		      u32 sw_if_index)
{
    fib_urpf_list_t *urpf;

    urpf = fib_urpf_list_get(ui);

    vec_add1(urpf->furpf_itfs, sw_if_index);
}

/**
 * @brief Combine to interface lists
 */
void
fib_urpf_list_combine (index_t ui1,
		       index_t ui2)
{
    fib_urpf_list_t *urpf1, *urpf2;

    urpf1 = fib_urpf_list_get(ui1);
    urpf2 = fib_urpf_list_get(ui2);

    vec_append(urpf1->furpf_itfs, urpf2->furpf_itfs);
}

/**
 * @brief Sort the interface indicies.
 * The sort is the first step in obtaining a unique list, so the order,
 * w.r.t. next-hop, interface,etc is not important. So a sort based on the
 * index is all we need.
 */
static int
fib_urpf_itf_cmp_for_sort (void * v1,
			   void * v2)
{
    fib_node_index_t *i1 = v1, *i2 = v2;

    return (*i2 < *i1);
}

/**
 * @brief Convert the uRPF list from the itf set obtained during the walk
 * to a unique list.
 */
void
fib_urpf_list_bake (index_t ui)
{
    fib_urpf_list_t *urpf;

    urpf = fib_urpf_list_get(ui);

    ASSERT(!(urpf->furpf_flags & FIB_URPF_LIST_BAKED));

    if (vec_len(urpf->furpf_itfs) > 1)
    {
	u32 i,j;

	/*
	 * cat list | sort | uniq > rpf_list
	 */
	vec_sort_with_function(urpf->furpf_itfs, fib_urpf_itf_cmp_for_sort);

	i = 0, j = 1;
	while (j < vec_len(urpf->furpf_itfs))
	{
	    if (urpf->furpf_itfs[i] == urpf->furpf_itfs[j])
	    {
		/*
		 * the itfacenct entries are the same.
		 * search forward for a unique one
		 */
		while (urpf->furpf_itfs[i] == urpf->furpf_itfs[j] &&
		       j < vec_len(urpf->furpf_itfs))
		{
		    j++;
		}
		if (j == vec_len(urpf->furpf_itfs))
		{
		    /*
		     * ran off the end without finding a unique index.
		     * we are done.
		     */
		    break;
		}
		else
		{
		    urpf->furpf_itfs[i+1] = urpf->furpf_itfs[j];
		}
	    }
	    i++, j++;
	}

	/*
	 * set the length of the vector to the number of unique itfs
	 */
	_vec_len(urpf->furpf_itfs) = i+1;
    }

    urpf->furpf_flags |= FIB_URPF_LIST_BAKED;
}

void
fib_urpf_list_show_mem (void)
{
    fib_show_memory_usage("uRPF-list",
			  pool_elts(fib_urpf_list_pool),
			  pool_len(fib_urpf_list_pool),
			  sizeof(fib_urpf_list_t));
}

static clib_error_t *
show_fib_urpf_list_command (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
    index_t ui;

    if (unformat (input, "%d", &ui))
    {
	/*
	 * show one in detail
	 */
	if (!pool_is_free_index(fib_urpf_list_pool, ui))
	{
	    vlib_cli_output (vm, "%d@%U",
			     ui,
			     format_fib_urpf_list, ui);
	}
	else
	{
	    vlib_cli_output (vm, "uRPF %d invalid", ui);
	}
    }
    else
    {
	/*
	 * show all
	 */
	vlib_cli_output (vm, "FIB uRPF Entries:");
	pool_foreach_index(ui, fib_urpf_list_pool,
        ({
	    vlib_cli_output (vm, "%d@%U",
			     ui,
			     format_fib_urpf_list, ui);
	}));
    }

    return (NULL);
}

/* *INDENT-OFF* */
/*?
 * The '<em>sh fib uRPF [index] </em>' command displays the uRPF lists
 *
 * @cliexpar
 * @cliexstart{show fib uRPF}
 * FIB uRPF Entries:
 *  0@uPRF-list:0 len:0 itfs:[]
 *  1@uPRF-list:1 len:2 itfs:[1, 2, ]
 *  2@uPRF-list:2 len:1 itfs:[3, ]
 *  3@uPRF-list:3 len:1 itfs:[9, ]
 * @cliexend
?*/
VLIB_CLI_COMMAND (show_fib_urpf_list, static) = {
  .path = "show fib uRPF",
  .function = show_fib_urpf_list_command,
  .short_help = "show fib uRPF",
};
/* *INDENT-OFF* */
