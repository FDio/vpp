/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
/*
 * interface.c: VNET interfaces/sub-interfaces
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/adj/adj.h>
#include <vnet/adj/adj_mcast.h>

#define VNET_INTERFACE_SET_FLAGS_HELPER_IS_CREATE (1 << 0)
#define VNET_INTERFACE_SET_FLAGS_HELPER_WANT_REDISTRIBUTE (1 << 1)

static clib_error_t *vnet_hw_interface_set_flags_helper (vnet_main_t * vnm,
							 u32 hw_if_index,
							 u32 flags,
							 u32 helper_flags);

static clib_error_t *vnet_sw_interface_set_flags_helper (vnet_main_t * vnm,
							 u32 sw_if_index,
							 u32 flags,
							 u32 helper_flags);

static clib_error_t *vnet_hw_interface_set_class_helper (vnet_main_t * vnm,
							 u32 hw_if_index,
							 u32 hw_class_index,
							 u32 redistribute);

typedef struct
{
  /* Either sw or hw interface index. */
  u32 sw_hw_if_index;

  /* Flags. */
  u32 flags;
} vnet_sw_hw_interface_state_t;

static void
serialize_vec_vnet_sw_hw_interface_state (serialize_main_t * m, va_list * va)
{
  vnet_sw_hw_interface_state_t *s =
    va_arg (*va, vnet_sw_hw_interface_state_t *);
  u32 n = va_arg (*va, u32);
  u32 i;
  for (i = 0; i < n; i++)
    {
      serialize_integer (m, s[i].sw_hw_if_index,
			 sizeof (s[i].sw_hw_if_index));
      serialize_integer (m, s[i].flags, sizeof (s[i].flags));
    }
}

static void
unserialize_vec_vnet_sw_hw_interface_state (serialize_main_t * m,
					    va_list * va)
{
  vnet_sw_hw_interface_state_t *s =
    va_arg (*va, vnet_sw_hw_interface_state_t *);
  u32 n = va_arg (*va, u32);
  u32 i;
  for (i = 0; i < n; i++)
    {
      unserialize_integer (m, &s[i].sw_hw_if_index,
			   sizeof (s[i].sw_hw_if_index));
      unserialize_integer (m, &s[i].flags, sizeof (s[i].flags));
    }
}

static void
serialize_vnet_sw_hw_interface_set_flags (serialize_main_t * m, va_list * va)
{
  vnet_sw_hw_interface_state_t *s =
    va_arg (*va, vnet_sw_hw_interface_state_t *);
  serialize (m, serialize_vec_vnet_sw_hw_interface_state, s, 1);
}

static void
unserialize_vnet_sw_interface_set_flags (serialize_main_t * m, va_list * va)
{
  CLIB_UNUSED (mc_main_t * mc) = va_arg (*va, mc_main_t *);
  vnet_sw_hw_interface_state_t s;

  unserialize (m, unserialize_vec_vnet_sw_hw_interface_state, &s, 1);

  vnet_sw_interface_set_flags_helper
    (vnet_get_main (), s.sw_hw_if_index, s.flags,
     /* helper_flags no redistribution */ 0);
}

static void
unserialize_vnet_hw_interface_set_flags (serialize_main_t * m, va_list * va)
{
  CLIB_UNUSED (mc_main_t * mc) = va_arg (*va, mc_main_t *);
  vnet_sw_hw_interface_state_t s;

  unserialize (m, unserialize_vec_vnet_sw_hw_interface_state, &s, 1);

  vnet_hw_interface_set_flags_helper
    (vnet_get_main (), s.sw_hw_if_index, s.flags,
     /* helper_flags no redistribution */ 0);
}

MC_SERIALIZE_MSG (vnet_sw_interface_set_flags_msg, static) =
{
.name = "vnet_sw_interface_set_flags",.serialize =
    serialize_vnet_sw_hw_interface_set_flags,.unserialize =
    unserialize_vnet_sw_interface_set_flags,};

MC_SERIALIZE_MSG (vnet_hw_interface_set_flags_msg, static) =
{
.name = "vnet_hw_interface_set_flags",.serialize =
    serialize_vnet_sw_hw_interface_set_flags,.unserialize =
    unserialize_vnet_hw_interface_set_flags,};

void
serialize_vnet_interface_state (serialize_main_t * m, va_list * va)
{
  vnet_main_t *vnm = va_arg (*va, vnet_main_t *);
  vnet_sw_hw_interface_state_t *sts = 0, *st;
  vnet_sw_interface_t *sif;
  vnet_hw_interface_t *hif;
  vnet_interface_main_t *im = &vnm->interface_main;

  /* Serialize hardware interface classes since they may have changed.
     Must do this before sending up/down flags. */
  /* *INDENT-OFF* */
  pool_foreach (hif, im->hw_interfaces, ({
    vnet_hw_interface_class_t * hw_class = vnet_get_hw_interface_class (vnm, hif->hw_class_index);
    serialize_cstring (m, hw_class->name);
  }));
  /* *INDENT-ON* */

  /* Send sw/hw interface state when non-zero. */
  /* *INDENT-OFF* */
  pool_foreach (sif, im->sw_interfaces, ({
    if (sif->flags != 0)
      {
	vec_add2 (sts, st, 1);
	st->sw_hw_if_index = sif->sw_if_index;
	st->flags = sif->flags;
      }
  }));
  /* *INDENT-ON* */

  vec_serialize (m, sts, serialize_vec_vnet_sw_hw_interface_state);

  if (sts)
    _vec_len (sts) = 0;

  /* *INDENT-OFF* */
  pool_foreach (hif, im->hw_interfaces, ({
    if (hif->flags != 0)
      {
	vec_add2 (sts, st, 1);
	st->sw_hw_if_index = hif->hw_if_index;
	st->flags = hif->flags;
      }
  }));
  /* *INDENT-ON* */

  vec_serialize (m, sts, serialize_vec_vnet_sw_hw_interface_state);

  vec_free (sts);
}

void
unserialize_vnet_interface_state (serialize_main_t * m, va_list * va)
{
  vnet_main_t *vnm = va_arg (*va, vnet_main_t *);
  vnet_sw_hw_interface_state_t *sts = 0, *st;

  /* First set interface hardware class. */
  {
    vnet_interface_main_t *im = &vnm->interface_main;
    vnet_hw_interface_t *hif;
    char *class_name;
    uword *p;
    clib_error_t *error;

    /* *INDENT-OFF* */
    pool_foreach (hif, im->hw_interfaces, ({
      unserialize_cstring (m, &class_name);
      p = hash_get_mem (im->hw_interface_class_by_name, class_name);
      ASSERT (p != 0);
      error = vnet_hw_interface_set_class_helper (vnm, hif->hw_if_index, p[0], /* redistribute */ 0);
      if (error)
	clib_error_report (error);
      vec_free (class_name);
    }));
    /* *INDENT-ON* */
  }

  vec_unserialize (m, &sts, unserialize_vec_vnet_sw_hw_interface_state);
  vec_foreach (st, sts)
    vnet_sw_interface_set_flags_helper (vnm, st->sw_hw_if_index, st->flags,
					/* no distribute */ 0);
  vec_free (sts);

  vec_unserialize (m, &sts, unserialize_vec_vnet_sw_hw_interface_state);
  vec_foreach (st, sts)
    vnet_hw_interface_set_flags_helper (vnm, st->sw_hw_if_index, st->flags,
					/* no distribute */ 0);
  vec_free (sts);
}

static clib_error_t *
call_elf_section_interface_callbacks (vnet_main_t * vnm, u32 if_index,
				      u32 flags,
				      _vnet_interface_function_list_elt_t **
				      elts)
{
  _vnet_interface_function_list_elt_t *elt;
  vnet_interface_function_priority_t prio;
  clib_error_t *error = 0;

  for (prio = VNET_ITF_FUNC_PRIORITY_LOW;
       prio <= VNET_ITF_FUNC_PRIORITY_HIGH; prio++)
    {
      elt = elts[prio];

      while (elt)
	{
	  error = elt->fp (vnm, if_index, flags);
	  if (error)
	    return error;
	  elt = elt->next_interface_function;
	}
    }
  return error;
}

static clib_error_t *
call_hw_interface_add_del_callbacks (vnet_main_t * vnm, u32 hw_if_index,
				     u32 is_create)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_hw_interface_class_t *hw_class =
    vnet_get_hw_interface_class (vnm, hi->hw_class_index);
  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hi->dev_class_index);
  clib_error_t *error = 0;

  if (hw_class->interface_add_del_function
      && (error =
	  hw_class->interface_add_del_function (vnm, hw_if_index, is_create)))
    return error;

  if (dev_class->interface_add_del_function
      && (error =
	  dev_class->interface_add_del_function (vnm, hw_if_index,
						 is_create)))
    return error;

  error = call_elf_section_interface_callbacks
    (vnm, hw_if_index, is_create, vnm->hw_interface_add_del_functions);

  return error;
}

static clib_error_t *
call_sw_interface_add_del_callbacks (vnet_main_t * vnm, u32 sw_if_index,
				     u32 is_create)
{
  return call_elf_section_interface_callbacks
    (vnm, sw_if_index, is_create, vnm->sw_interface_add_del_functions);
}

#define VNET_INTERFACE_SET_FLAGS_HELPER_IS_CREATE (1 << 0)
#define VNET_INTERFACE_SET_FLAGS_HELPER_WANT_REDISTRIBUTE (1 << 1)

static clib_error_t *
vnet_hw_interface_set_flags_helper (vnet_main_t * vnm, u32 hw_if_index,
				    u32 flags, u32 helper_flags)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_hw_interface_class_t *hw_class =
    vnet_get_hw_interface_class (vnm, hi->hw_class_index);
  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hi->dev_class_index);
  vlib_main_t *vm = vnm->vlib_main;
  u32 mask;
  clib_error_t *error = 0;
  u32 is_create =
    (helper_flags & VNET_INTERFACE_SET_FLAGS_HELPER_IS_CREATE) != 0;

  mask =
    (VNET_HW_INTERFACE_FLAG_LINK_UP | VNET_HW_INTERFACE_FLAG_DUPLEX_MASK |
     VNET_HW_INTERFACE_FLAG_SPEED_MASK);
  flags &= mask;

  /* Call hardware interface add/del callbacks. */
  if (is_create)
    call_hw_interface_add_del_callbacks (vnm, hw_if_index, is_create);

  /* Already in the desired state? */
  if (!is_create && (hi->flags & mask) == flags)
    goto done;

  /* Some interface classes do not redistribute (e.g. are local). */
  if (!dev_class->redistribute)
    helper_flags &= ~VNET_INTERFACE_SET_FLAGS_HELPER_WANT_REDISTRIBUTE;

  if (vm->mc_main
      && (helper_flags & VNET_INTERFACE_SET_FLAGS_HELPER_WANT_REDISTRIBUTE))
    {
      vnet_sw_hw_interface_state_t s;
      s.sw_hw_if_index = hw_if_index;
      s.flags = flags;
      mc_serialize (vm->mc_main, &vnet_hw_interface_set_flags_msg, &s);
    }

  if ((hi->flags & VNET_HW_INTERFACE_FLAG_LINK_UP) !=
      (flags & VNET_HW_INTERFACE_FLAG_LINK_UP))
    {
      /* Do hardware class (e.g. ethernet). */
      if (hw_class->link_up_down_function
	  && (error = hw_class->link_up_down_function (vnm, hw_if_index,
						       flags)))
	goto done;

      error = call_elf_section_interface_callbacks
	(vnm, hw_if_index, flags, vnm->hw_interface_link_up_down_functions);

      if (error)
	goto done;
    }

  hi->flags &= ~mask;
  hi->flags |= flags;

done:
  return error;
}

static clib_error_t *
vnet_sw_interface_set_flags_helper (vnet_main_t * vnm, u32 sw_if_index,
				    u32 flags, u32 helper_flags)
{
  vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);
  vlib_main_t *vm = vnm->vlib_main;
  u32 mask;
  clib_error_t *error = 0;
  u32 is_create =
    (helper_flags & VNET_INTERFACE_SET_FLAGS_HELPER_IS_CREATE) != 0;
  u32 old_flags;

  mask = VNET_SW_INTERFACE_FLAG_ADMIN_UP | VNET_SW_INTERFACE_FLAG_PUNT;
  flags &= mask;

  if (is_create)
    {
      error =
	call_sw_interface_add_del_callbacks (vnm, sw_if_index, is_create);
      if (error)
	goto done;

      if (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
	{
	  /* Notify everyone when the interface is created as admin up */
	  error = call_elf_section_interface_callbacks (vnm, sw_if_index,
							flags,
							vnm->
							sw_interface_admin_up_down_functions);
	  if (error)
	    goto done;
	}
    }
  else
    {
      vnet_sw_interface_t *si_sup = si;

      /* Check that super interface is in correct state. */
      if (si->type == VNET_SW_INTERFACE_TYPE_SUB)
	{
	  si_sup = vnet_get_sw_interface (vnm, si->sup_sw_if_index);

	  /* Check to see if we're bringing down the soft interface and if it's parent is up */
	  if ((flags != (si_sup->flags & mask)) &&
	      (!((flags == 0)
		 && ((si_sup->flags & mask) ==
		     VNET_SW_INTERFACE_FLAG_ADMIN_UP))))
	    {
	      error = clib_error_return (0, "super-interface %U must be %U",
					 format_vnet_sw_interface_name, vnm,
					 si_sup,
					 format_vnet_sw_interface_flags,
					 flags);
	      goto done;
	    }
	}

      /* Donot change state for slave link of bonded interfaces */
      if (si->flags & VNET_SW_INTERFACE_FLAG_BOND_SLAVE)
	{
	  error = clib_error_return
	    (0, "not allowed as %U belong to a BondEthernet interface",
	     format_vnet_sw_interface_name, vnm, si);
	  goto done;
	}

      /* Already in the desired state? */
      if ((si->flags & mask) == flags)
	goto done;

      /* Sub-interfaces of hardware interfaces that do no redistribute,
         do not redistribute themselves. */
      if (si_sup->type == VNET_SW_INTERFACE_TYPE_HARDWARE)
	{
	  vnet_hw_interface_t *hi =
	    vnet_get_hw_interface (vnm, si_sup->hw_if_index);
	  vnet_device_class_t *dev_class =
	    vnet_get_device_class (vnm, hi->dev_class_index);
	  if (!dev_class->redistribute)
	    helper_flags &=
	      ~VNET_INTERFACE_SET_FLAGS_HELPER_WANT_REDISTRIBUTE;
	}

      if (vm->mc_main
	  && (helper_flags &
	      VNET_INTERFACE_SET_FLAGS_HELPER_WANT_REDISTRIBUTE))
	{
	  vnet_sw_hw_interface_state_t s;
	  s.sw_hw_if_index = sw_if_index;
	  s.flags = flags;
	  mc_serialize (vm->mc_main, &vnet_sw_interface_set_flags_msg, &s);
	}

      /* set the flags now before invoking the registered clients
       * so that the state they query is consistent with the state here notified */
      old_flags = si->flags;
      si->flags &= ~mask;
      si->flags |= flags;
      if ((flags | old_flags) & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
	error = call_elf_section_interface_callbacks
	  (vnm, sw_if_index, flags,
	   vnm->sw_interface_admin_up_down_functions);
      si->flags = old_flags;

      if (error)
	goto done;

      if (si->type == VNET_SW_INTERFACE_TYPE_HARDWARE)
	{
	  vnet_hw_interface_t *hi =
	    vnet_get_hw_interface (vnm, si->hw_if_index);
	  vnet_hw_interface_class_t *hw_class =
	    vnet_get_hw_interface_class (vnm, hi->hw_class_index);
	  vnet_device_class_t *dev_class =
	    vnet_get_device_class (vnm, hi->dev_class_index);

	  if ((flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) &&
	      (si->flags & VNET_SW_INTERFACE_FLAG_ERROR))
	    {
	      error = clib_error_return (0, "Interface in the error state");
	      goto done;
	    }

	  /* save the si admin up flag */
	  old_flags = si->flags;

	  /* update si admin up flag in advance if we are going admin down */
	  if (!(flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP))
	    si->flags &= ~VNET_SW_INTERFACE_FLAG_ADMIN_UP;

	  if (dev_class->admin_up_down_function
	      && (error = dev_class->admin_up_down_function (vnm,
							     si->hw_if_index,
							     flags)))
	    {
	      /* restore si admin up flag to it's original state on errors */
	      si->flags = old_flags;
	      goto done;
	    }

	  if (hw_class->admin_up_down_function
	      && (error = hw_class->admin_up_down_function (vnm,
							    si->hw_if_index,
							    flags)))
	    {
	      /* restore si admin up flag to it's original state on errors */
	      si->flags = old_flags;
	      goto done;
	    }

	  /* Admin down implies link down. */
	  if (!(flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
	      && (hi->flags & VNET_HW_INTERFACE_FLAG_LINK_UP))
	    vnet_hw_interface_set_flags_helper (vnm, si->hw_if_index,
						hi->flags &
						~VNET_HW_INTERFACE_FLAG_LINK_UP,
						helper_flags);
	}
    }

  si->flags &= ~mask;
  si->flags |= flags;

done:
  return error;
}

clib_error_t *
vnet_hw_interface_set_flags (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  return vnet_hw_interface_set_flags_helper
    (vnm, hw_if_index, flags,
     VNET_INTERFACE_SET_FLAGS_HELPER_WANT_REDISTRIBUTE);
}

clib_error_t *
vnet_sw_interface_set_flags (vnet_main_t * vnm, u32 sw_if_index, u32 flags)
{
  return vnet_sw_interface_set_flags_helper
    (vnm, sw_if_index, flags,
     VNET_INTERFACE_SET_FLAGS_HELPER_WANT_REDISTRIBUTE);
}

static u32
vnet_create_sw_interface_no_callbacks (vnet_main_t * vnm,
				       vnet_sw_interface_t * template)
{
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_sw_interface_t *sw;
  u32 sw_if_index;

  pool_get (im->sw_interfaces, sw);
  sw_if_index = sw - im->sw_interfaces;

  sw[0] = template[0];

  sw->flags = 0;
  sw->sw_if_index = sw_if_index;
  if (sw->type == VNET_SW_INTERFACE_TYPE_HARDWARE)
    sw->sup_sw_if_index = sw->sw_if_index;

  /* Allocate counters for this interface. */
  {
    u32 i;

    vnet_interface_counter_lock (im);

    for (i = 0; i < vec_len (im->sw_if_counters); i++)
      {
	vlib_validate_simple_counter (&im->sw_if_counters[i], sw_if_index);
	vlib_zero_simple_counter (&im->sw_if_counters[i], sw_if_index);
      }

    for (i = 0; i < vec_len (im->combined_sw_if_counters); i++)
      {
	vlib_validate_combined_counter (&im->combined_sw_if_counters[i],
					sw_if_index);
	vlib_zero_combined_counter (&im->combined_sw_if_counters[i],
				    sw_if_index);
      }

    vnet_interface_counter_unlock (im);
  }

  return sw_if_index;
}

clib_error_t *
vnet_create_sw_interface (vnet_main_t * vnm, vnet_sw_interface_t * template,
			  u32 * sw_if_index)
{
  clib_error_t *error;
  vnet_hw_interface_t *hi;
  vnet_device_class_t *dev_class;

  hi = vnet_get_sup_hw_interface (vnm, template->sup_sw_if_index);
  dev_class = vnet_get_device_class (vnm, hi->dev_class_index);

  if (template->type == VNET_SW_INTERFACE_TYPE_SUB &&
      dev_class->subif_add_del_function)
    {
      error = dev_class->subif_add_del_function (vnm, hi->hw_if_index,
						 (struct vnet_sw_interface_t
						  *) template, 1);
      if (error)
	return error;
    }

  *sw_if_index = vnet_create_sw_interface_no_callbacks (vnm, template);
  error = vnet_sw_interface_set_flags_helper
    (vnm, *sw_if_index, template->flags,
     VNET_INTERFACE_SET_FLAGS_HELPER_IS_CREATE);

  if (error)
    {
      /* undo the work done by vnet_create_sw_interface_no_callbacks() */
      vnet_interface_main_t *im = &vnm->interface_main;
      vnet_sw_interface_t *sw =
	pool_elt_at_index (im->sw_interfaces, *sw_if_index);
      pool_put (im->sw_interfaces, sw);
    }

  return error;
}

void
vnet_delete_sw_interface (vnet_main_t * vnm, u32 sw_if_index)
{
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_sw_interface_t *sw =
    pool_elt_at_index (im->sw_interfaces, sw_if_index);

  /* Check if the interface has config and is removed from L2 BD or XConnect */
  vlib_main_t *vm = vlib_get_main ();
  l2_input_config_t *config;
  if (sw_if_index < vec_len (l2input_main.configs))
    {
      config = vec_elt_at_index (l2input_main.configs, sw_if_index);
      if (config->xconnect)
	set_int_l2_mode (vm, vnm, MODE_L3, config->output_sw_if_index, 0, 0,
			 0, 0);
      if (config->xconnect || config->bridge)
	set_int_l2_mode (vm, vnm, MODE_L3, sw_if_index, 0, 0, 0, 0);
    }

  /* Bring down interface in case it is up. */
  if (sw->flags != 0)
    vnet_sw_interface_set_flags (vnm, sw_if_index, /* flags */ 0);

  call_sw_interface_add_del_callbacks (vnm, sw_if_index, /* is_create */ 0);

  pool_put (im->sw_interfaces, sw);
}

static void
setup_tx_node (vlib_main_t * vm,
	       u32 node_index, vnet_device_class_t * dev_class)
{
  vlib_node_t *n = vlib_get_node (vm, node_index);

  n->function = dev_class->tx_function;
  n->format_trace = dev_class->format_tx_trace;

  vlib_register_errors (vm, node_index,
			dev_class->tx_function_n_errors,
			dev_class->tx_function_error_strings);
}

static void
setup_output_node (vlib_main_t * vm,
		   u32 node_index, vnet_hw_interface_class_t * hw_class)
{
  vlib_node_t *n = vlib_get_node (vm, node_index);
  n->format_buffer = hw_class->format_header;
  n->unformat_buffer = hw_class->unformat_header;
}

/* Register an interface instance. */
u32
vnet_register_interface (vnet_main_t * vnm,
			 u32 dev_class_index,
			 u32 dev_instance,
			 u32 hw_class_index, u32 hw_instance)
{
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_interface_t *hw;
  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, dev_class_index);
  vnet_hw_interface_class_t *hw_class =
    vnet_get_hw_interface_class (vnm, hw_class_index);
  vlib_main_t *vm = vnm->vlib_main;
  vnet_feature_config_main_t *fcm;
  vnet_config_main_t *cm;
  u32 hw_index, i;
  char *tx_node_name, *output_node_name;

  pool_get (im->hw_interfaces, hw);

  hw_index = hw - im->hw_interfaces;
  hw->hw_if_index = hw_index;
  hw->default_rx_mode = VNET_HW_INTERFACE_RX_MODE_POLLING;

  if (dev_class->format_device_name)
    hw->name = format (0, "%U", dev_class->format_device_name, dev_instance);
  else if (hw_class->format_interface_name)
    hw->name = format (0, "%U", hw_class->format_interface_name,
		       dev_instance);
  else
    hw->name = format (0, "%s%x", hw_class->name, dev_instance);

  if (!im->hw_interface_by_name)
    im->hw_interface_by_name = hash_create_vec ( /* size */ 0,
						sizeof (hw->name[0]),
						sizeof (uword));

  hash_set_mem (im->hw_interface_by_name, hw->name, hw_index);

  /* Make hardware interface point to software interface. */
  {
    vnet_sw_interface_t sw = {
      .type = VNET_SW_INTERFACE_TYPE_HARDWARE,
      .flood_class = VNET_FLOOD_CLASS_NORMAL,
      .hw_if_index = hw_index
    };
    hw->sw_if_index = vnet_create_sw_interface_no_callbacks (vnm, &sw);
  }

  hw->dev_class_index = dev_class_index;
  hw->dev_instance = dev_instance;
  hw->hw_class_index = hw_class_index;
  hw->hw_instance = hw_instance;

  hw->max_rate_bits_per_sec = 0;
  hw->min_packet_bytes = 0;
  hw->per_packet_overhead_bytes = 0;
  hw->max_l3_packet_bytes[VLIB_RX] = ~0;
  hw->max_l3_packet_bytes[VLIB_TX] = ~0;

  tx_node_name = (char *) format (0, "%v-tx", hw->name);
  output_node_name = (char *) format (0, "%v-output", hw->name);

  /* If we have previously deleted interface nodes, re-use them. */
  if (vec_len (im->deleted_hw_interface_nodes) > 0)
    {
      vnet_hw_interface_nodes_t *hn;
      vlib_node_t *node;
      vlib_node_runtime_t *nrt;

      hn = vec_end (im->deleted_hw_interface_nodes) - 1;

      hw->tx_node_index = hn->tx_node_index;
      hw->output_node_index = hn->output_node_index;

      vlib_node_rename (vm, hw->tx_node_index, "%v", tx_node_name);
      vlib_node_rename (vm, hw->output_node_index, "%v", output_node_name);

      /* *INDENT-OFF* */
      foreach_vlib_main ({
        vnet_interface_output_runtime_t *rt;

	rt = vlib_node_get_runtime_data (this_vlib_main, hw->output_node_index);
	ASSERT (rt->is_deleted == 1);
	rt->is_deleted = 0;
	rt->hw_if_index = hw_index;
	rt->sw_if_index = hw->sw_if_index;
	rt->dev_instance = hw->dev_instance;

	rt = vlib_node_get_runtime_data (this_vlib_main, hw->tx_node_index);
	rt->hw_if_index = hw_index;
	rt->sw_if_index = hw->sw_if_index;
	rt->dev_instance = hw->dev_instance;
      });
      /* *INDENT-ON* */

      /* The new class may differ from the old one.
       * Functions have to be updated. */
      node = vlib_get_node (vm, hw->output_node_index);
      node->function = vnet_interface_output_node_multiarch_select ();
      node->format_trace = format_vnet_interface_output_trace;
      /* *INDENT-OFF* */
      foreach_vlib_main ({
        nrt = vlib_node_get_runtime (this_vlib_main, hw->output_node_index);
        nrt->function = node->function;
      });
      /* *INDENT-ON* */

      node = vlib_get_node (vm, hw->tx_node_index);
      node->function = dev_class->tx_function;
      node->format_trace = dev_class->format_tx_trace;
      /* *INDENT-OFF* */
      foreach_vlib_main ({
        nrt = vlib_node_get_runtime (this_vlib_main, hw->tx_node_index);
        nrt->function = node->function;
      });
      /* *INDENT-ON* */

      _vec_len (im->deleted_hw_interface_nodes) -= 1;
    }
  else
    {
      vlib_node_registration_t r;
      vnet_interface_output_runtime_t rt = {
	.hw_if_index = hw_index,
	.sw_if_index = hw->sw_if_index,
	.dev_instance = hw->dev_instance,
	.is_deleted = 0,
      };

      memset (&r, 0, sizeof (r));
      r.type = VLIB_NODE_TYPE_INTERNAL;
      r.runtime_data = &rt;
      r.runtime_data_bytes = sizeof (rt);
      r.scalar_size = 0;
      r.vector_size = sizeof (u32);

      r.flags = VLIB_NODE_FLAG_IS_OUTPUT;
      r.name = tx_node_name;
      r.function = dev_class->tx_function;

      hw->tx_node_index = vlib_register_node (vm, &r);

      vlib_node_add_named_next_with_slot (vm, hw->tx_node_index,
					  "error-drop",
					  VNET_INTERFACE_TX_NEXT_DROP);

      r.flags = 0;
      r.name = output_node_name;
      r.function = vnet_interface_output_node_multiarch_select ();
      r.format_trace = format_vnet_interface_output_trace;

      {
	static char *e[] = {
	  "interface is down",
	  "interface is deleted",
	};

	r.n_errors = ARRAY_LEN (e);
	r.error_strings = e;
      }
      hw->output_node_index = vlib_register_node (vm, &r);

      vlib_node_add_named_next_with_slot (vm, hw->output_node_index,
					  "error-drop",
					  VNET_INTERFACE_OUTPUT_NEXT_DROP);
      vlib_node_add_next_with_slot (vm, hw->output_node_index,
				    hw->tx_node_index,
				    VNET_INTERFACE_OUTPUT_NEXT_TX);

      /* add interface to the list of "output-interface" feature arc start nodes
         and clone nexts from 1st interface if it exists */
      fcm = vnet_feature_get_config_main (im->output_feature_arc_index);
      cm = &fcm->config_main;
      i = vec_len (cm->start_node_indices);
      vec_validate (cm->start_node_indices, i);
      cm->start_node_indices[i] = hw->output_node_index;
      if (hw_index)
	{
	  /* copy nexts from 1st interface */
	  vnet_hw_interface_t *first_hw;
	  vlib_node_t *first_node;

	  first_hw = vnet_get_hw_interface (vnm, /* hw_if_index */ 0);
	  first_node = vlib_get_node (vm, first_hw->output_node_index);

	  /* 1st 2 nexts are already added above */
	  for (i = 2; i < vec_len (first_node->next_nodes); i++)
	    vlib_node_add_next_with_slot (vm, hw->output_node_index,
					  first_node->next_nodes[i], i);
	}
    }

  setup_output_node (vm, hw->output_node_index, hw_class);
  setup_tx_node (vm, hw->tx_node_index, dev_class);

  /* Call all up/down callbacks with zero flags when interface is created. */
  vnet_sw_interface_set_flags_helper (vnm, hw->sw_if_index, /* flags */ 0,
				      VNET_INTERFACE_SET_FLAGS_HELPER_IS_CREATE);
  vnet_hw_interface_set_flags_helper (vnm, hw_index, /* flags */ 0,
				      VNET_INTERFACE_SET_FLAGS_HELPER_IS_CREATE);

  return hw_index;
}

void
vnet_delete_hw_interface (vnet_main_t * vnm, u32 hw_if_index)
{
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  vlib_main_t *vm = vnm->vlib_main;

  /* If it is up, mark it down. */
  if (hw->flags != 0)
    vnet_hw_interface_set_flags (vnm, hw_if_index, /* flags */ 0);

  /* Call delete callbacks. */
  call_hw_interface_add_del_callbacks (vnm, hw_if_index, /* is_create */ 0);

  /* Delete software interface corresponding to hardware interface. */
  vnet_delete_sw_interface (vnm, hw->sw_if_index);

  /* Delete any sub-interfaces. */
  {
    u32 id, sw_if_index;
    /* *INDENT-OFF* */
    hash_foreach (id, sw_if_index, hw->sub_interface_sw_if_index_by_id, ({
      vnet_delete_sw_interface (vnm, sw_if_index);
    }));
    /* *INDENT-ON* */
  }

  {
    vnet_hw_interface_nodes_t *dn;

    /* *INDENT-OFF* */
    foreach_vlib_main ({
      vnet_interface_output_runtime_t *rt =
        vlib_node_get_runtime_data (this_vlib_main, hw->output_node_index);

      /* Mark node runtime as deleted so output node (if called)
       * will drop packets. */
      rt->is_deleted = 1;
    });
    /* *INDENT-ON* */

    vlib_node_rename (vm, hw->output_node_index,
		      "interface-%d-output-deleted", hw_if_index);
    vlib_node_rename (vm, hw->tx_node_index, "interface-%d-tx-deleted",
		      hw_if_index);
    vec_add2 (im->deleted_hw_interface_nodes, dn, 1);
    dn->tx_node_index = hw->tx_node_index;
    dn->output_node_index = hw->output_node_index;
  }

  hash_unset_mem (im->hw_interface_by_name, hw->name);
  vec_free (hw->name);
  vec_free (hw->input_node_thread_index_by_queue);
  vec_free (hw->dq_runtime_index_by_queue);

  pool_put (im->hw_interfaces, hw);
}

void
vnet_hw_interface_walk_sw (vnet_main_t * vnm,
			   u32 hw_if_index,
			   vnet_hw_sw_interface_walk_t fn, void *ctx)
{
  vnet_hw_interface_t *hi;
  u32 id, sw_if_index;

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  /* the super first, then the and sub interfaces */
  fn (vnm, hi->sw_if_index, ctx);

  /* *INDENT-OFF* */
  hash_foreach (id, sw_if_index,
                hi->sub_interface_sw_if_index_by_id,
  ({
    fn (vnm, sw_if_index, ctx);
  }));
  /* *INDENT-ON* */
}

static void
serialize_vnet_hw_interface_set_class (serialize_main_t * m, va_list * va)
{
  u32 hw_if_index = va_arg (*va, u32);
  char *hw_class_name = va_arg (*va, char *);
  serialize_integer (m, hw_if_index, sizeof (hw_if_index));
  serialize_cstring (m, hw_class_name);
}

static void
unserialize_vnet_hw_interface_set_class (serialize_main_t * m, va_list * va)
{
  CLIB_UNUSED (mc_main_t * mc) = va_arg (*va, mc_main_t *);
  vnet_main_t *vnm = vnet_get_main ();
  u32 hw_if_index;
  char *hw_class_name;
  uword *p;
  clib_error_t *error;

  unserialize_integer (m, &hw_if_index, sizeof (hw_if_index));
  unserialize_cstring (m, &hw_class_name);
  p =
    hash_get (vnm->interface_main.hw_interface_class_by_name, hw_class_name);
  ASSERT (p != 0);
  error = vnet_hw_interface_set_class_helper (vnm, hw_if_index, p[0],
					      /* redistribute */ 0);
  if (error)
    clib_error_report (error);
}

MC_SERIALIZE_MSG (vnet_hw_interface_set_class_msg, static) =
{
.name = "vnet_hw_interface_set_class",.serialize =
    serialize_vnet_hw_interface_set_class,.unserialize =
    unserialize_vnet_hw_interface_set_class,};

void
vnet_hw_interface_init_for_class (vnet_main_t * vnm, u32 hw_if_index,
				  u32 hw_class_index, u32 hw_instance)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_hw_interface_class_t *hc =
    vnet_get_hw_interface_class (vnm, hw_class_index);

  hi->hw_class_index = hw_class_index;
  hi->hw_instance = hw_instance;
  setup_output_node (vnm->vlib_main, hi->output_node_index, hc);
}

static clib_error_t *
vnet_hw_interface_set_class_helper (vnet_main_t * vnm, u32 hw_if_index,
				    u32 hw_class_index, u32 redistribute)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, hi->sw_if_index);
  vnet_hw_interface_class_t *old_class =
    vnet_get_hw_interface_class (vnm, hi->hw_class_index);
  vnet_hw_interface_class_t *new_class =
    vnet_get_hw_interface_class (vnm, hw_class_index);
  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hi->dev_class_index);
  clib_error_t *error = 0;

  /* New class equals old class?  Nothing to do. */
  if (hi->hw_class_index == hw_class_index)
    return 0;

  /* No need (and incorrect since admin up flag may be set) to do error checking when
     receiving unserialize message. */
  if (redistribute)
    {
      if (si->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
	return clib_error_return (0,
				  "%v must be admin down to change class from %s to %s",
				  hi->name, old_class->name, new_class->name);

      /* Make sure interface supports given class. */
      if ((new_class->is_valid_class_for_interface
	   && !new_class->is_valid_class_for_interface (vnm, hw_if_index,
							hw_class_index))
	  || (dev_class->is_valid_class_for_interface
	      && !dev_class->is_valid_class_for_interface (vnm, hw_if_index,
							   hw_class_index)))
	return clib_error_return (0,
				  "%v class cannot be changed from %s to %s",
				  hi->name, old_class->name, new_class->name);

      if (vnm->vlib_main->mc_main)
	{
	  mc_serialize (vnm->vlib_main->mc_main,
			&vnet_hw_interface_set_class_msg, hw_if_index,
			new_class->name);
	  return 0;
	}
    }

  if (old_class->hw_class_change)
    old_class->hw_class_change (vnm, hw_if_index, old_class->index,
				new_class->index);

  vnet_hw_interface_init_for_class (vnm, hw_if_index, new_class->index,
				    /* instance */ ~0);

  if (new_class->hw_class_change)
    new_class->hw_class_change (vnm, hw_if_index, old_class->index,
				new_class->index);

  if (dev_class->hw_class_change)
    dev_class->hw_class_change (vnm, hw_if_index, new_class->index);

  return error;
}

clib_error_t *
vnet_hw_interface_set_class (vnet_main_t * vnm, u32 hw_if_index,
			     u32 hw_class_index)
{
  return vnet_hw_interface_set_class_helper (vnm, hw_if_index, hw_class_index,
					     /* redistribute */ 1);
}

static int
vnet_hw_interface_rx_redirect_to_node_helper (vnet_main_t * vnm,
					      u32 hw_if_index,
					      u32 node_index,
					      u32 redistribute)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_device_class_t *dev_class = vnet_get_device_class
    (vnm, hi->dev_class_index);

  if (redistribute)
    {
      /* $$$$ fixme someday maybe */
      ASSERT (vnm->vlib_main->mc_main == 0);
    }
  if (dev_class->rx_redirect_to_node)
    {
      dev_class->rx_redirect_to_node (vnm, hw_if_index, node_index);
      return 0;
    }

  return VNET_API_ERROR_UNIMPLEMENTED;
}

int
vnet_hw_interface_rx_redirect_to_node (vnet_main_t * vnm, u32 hw_if_index,
				       u32 node_index)
{
  return vnet_hw_interface_rx_redirect_to_node_helper (vnm, hw_if_index,
						       node_index,
						       1 /* redistribute */ );
}

word
vnet_sw_interface_compare (vnet_main_t * vnm,
			   uword sw_if_index0, uword sw_if_index1)
{
  vnet_sw_interface_t *sup0 = vnet_get_sup_sw_interface (vnm, sw_if_index0);
  vnet_sw_interface_t *sup1 = vnet_get_sup_sw_interface (vnm, sw_if_index1);
  vnet_hw_interface_t *h0 = vnet_get_hw_interface (vnm, sup0->hw_if_index);
  vnet_hw_interface_t *h1 = vnet_get_hw_interface (vnm, sup1->hw_if_index);

  if (h0 != h1)
    return vec_cmp (h0->name, h1->name);
  return (word) h0->hw_instance - (word) h1->hw_instance;
}

word
vnet_hw_interface_compare (vnet_main_t * vnm,
			   uword hw_if_index0, uword hw_if_index1)
{
  vnet_hw_interface_t *h0 = vnet_get_hw_interface (vnm, hw_if_index0);
  vnet_hw_interface_t *h1 = vnet_get_hw_interface (vnm, hw_if_index1);

  if (h0 != h1)
    return vec_cmp (h0->name, h1->name);
  return (word) h0->hw_instance - (word) h1->hw_instance;
}

int
vnet_sw_interface_is_p2p (vnet_main_t * vnm, u32 sw_if_index)
{
  vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);
  if (si->type == VNET_SW_INTERFACE_TYPE_P2P)
    return 1;

  vnet_hw_interface_t *hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  vnet_hw_interface_class_t *hc =
    vnet_get_hw_interface_class (vnm, hw->hw_class_index);

  return (hc->flags & VNET_HW_INTERFACE_CLASS_FLAG_P2P);
}

clib_error_t *
vnet_interface_init (vlib_main_t * vm)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vlib_buffer_t *b = 0;
  vnet_buffer_opaque_t *o = 0;
  clib_error_t *error;

  /*
   * Keep people from shooting themselves in the foot.
   */
  if (sizeof (b->opaque) != sizeof (vnet_buffer_opaque_t))
    {
#define _(a) if (sizeof(o->a) > sizeof (o->unused))                     \
      clib_warning                                                      \
        ("FATAL: size of opaque union subtype %s is %d (max %d)",       \
         #a, sizeof(o->a), sizeof (o->unused));
      foreach_buffer_opaque_union_subtype;
#undef _

      return clib_error_return
	(0, "FATAL: size of vlib buffer opaque %d, size of vnet opaque %d",
	 sizeof (b->opaque), sizeof (vnet_buffer_opaque_t));
    }

  im->sw_if_counter_lock = clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES,
						   CLIB_CACHE_LINE_BYTES);
  im->sw_if_counter_lock[0] = 1;	/* should be no need */

  vec_validate (im->sw_if_counters, VNET_N_SIMPLE_INTERFACE_COUNTER - 1);
  im->sw_if_counters[VNET_INTERFACE_COUNTER_DROP].name = "drops";
  im->sw_if_counters[VNET_INTERFACE_COUNTER_PUNT].name = "punts";
  im->sw_if_counters[VNET_INTERFACE_COUNTER_IP4].name = "ip4";
  im->sw_if_counters[VNET_INTERFACE_COUNTER_IP6].name = "ip6";
  im->sw_if_counters[VNET_INTERFACE_COUNTER_RX_NO_BUF].name = "rx-no-buf";
  im->sw_if_counters[VNET_INTERFACE_COUNTER_RX_MISS].name = "rx-miss";
  im->sw_if_counters[VNET_INTERFACE_COUNTER_RX_ERROR].name = "rx-error";
  im->sw_if_counters[VNET_INTERFACE_COUNTER_TX_ERROR].name = "tx-error";

  vec_validate (im->combined_sw_if_counters,
		VNET_N_COMBINED_INTERFACE_COUNTER - 1);
  im->combined_sw_if_counters[VNET_INTERFACE_COUNTER_RX].name = "rx";
  im->combined_sw_if_counters[VNET_INTERFACE_COUNTER_TX].name = "tx";

  im->sw_if_counter_lock[0] = 0;

  im->device_class_by_name = hash_create_string ( /* size */ 0,
						 sizeof (uword));
  {
    vnet_device_class_t *c;

    c = vnm->device_class_registrations;

    while (c)
      {
	c->index = vec_len (im->device_classes);
	hash_set_mem (im->device_class_by_name, c->name, c->index);
	vec_add1 (im->device_classes, c[0]);
	c = c->next_class_registration;
      }
  }

  im->hw_interface_class_by_name = hash_create_string ( /* size */ 0,
						       sizeof (uword));

  im->sw_if_index_by_sup_and_sub = hash_create_mem (0, sizeof (u64),
						    sizeof (uword));
  {
    vnet_hw_interface_class_t *c;

    c = vnm->hw_interface_class_registrations;

    while (c)
      {
	c->index = vec_len (im->hw_interface_classes);
	hash_set_mem (im->hw_interface_class_by_name, c->name, c->index);

	if (NULL == c->build_rewrite)
	  c->build_rewrite = default_build_rewrite;
	if (NULL == c->update_adjacency)
	  c->update_adjacency = default_update_adjacency;

	vec_add1 (im->hw_interface_classes, c[0]);
	c = c->next_class_registration;
      }
  }

  if ((error = vlib_call_init_function (vm, vnet_interface_cli_init)))
    return error;

  vnm->interface_tag_by_sw_if_index = hash_create (0, sizeof (uword));

#if VLIB_BUFFER_TRACE_TRAJECTORY > 0
  if ((error = vlib_call_init_function (vm, trajectory_trace_init)))
    return error;
#endif

  return 0;
}

VLIB_INIT_FUNCTION (vnet_interface_init);

/* Kludge to renumber interface names [only!] */
int
vnet_interface_name_renumber (u32 sw_if_index, u32 new_show_dev_instance)
{
  int rv;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_interface_t *hi = vnet_get_sup_hw_interface (vnm, sw_if_index);

  vnet_device_class_t *dev_class = vnet_get_device_class
    (vnm, hi->dev_class_index);

  if (dev_class->name_renumber == 0 || dev_class->format_device_name == 0)
    return VNET_API_ERROR_UNIMPLEMENTED;

  rv = dev_class->name_renumber (hi, new_show_dev_instance);

  if (rv)
    return rv;

  hash_unset_mem (im->hw_interface_by_name, hi->name);
  vec_free (hi->name);
  /* Use the mapping we set up to call it Ishmael */
  hi->name = format (0, "%U", dev_class->format_device_name,
		     hi->dev_instance);

  hash_set_mem (im->hw_interface_by_name, hi->name, hi->hw_if_index);
  return rv;
}

clib_error_t *
vnet_rename_interface (vnet_main_t * vnm, u32 hw_if_index, char *new_name)
{
  vnet_interface_main_t *im = &vnm->interface_main;
  vlib_main_t *vm = vnm->vlib_main;
  vnet_hw_interface_t *hw;
  u8 *old_name;
  clib_error_t *error = 0;

  hw = vnet_get_hw_interface (vnm, hw_if_index);
  if (!hw)
    {
      return clib_error_return (0,
				"unable to find hw interface for index %u",
				hw_if_index);
    }

  old_name = hw->name;

  /* set new hw->name */
  hw->name = format (0, "%s", new_name);

  /* remove the old name to hw_if_index mapping and install the new one */
  hash_unset_mem (im->hw_interface_by_name, old_name);
  hash_set_mem (im->hw_interface_by_name, hw->name, hw_if_index);

  /* rename tx/output nodes */
  vlib_node_rename (vm, hw->tx_node_index, "%v-tx", hw->name);
  vlib_node_rename (vm, hw->output_node_index, "%v-output", hw->name);

  /* free the old name vector */
  vec_free (old_name);

  return error;
}

static clib_error_t *
vnet_hw_interface_change_mac_address_helper (vnet_main_t * vnm,
					     u32 hw_if_index,
					     u8 * mac_address)
{
  clib_error_t *error = 0;
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);

  if (hi->hw_address)
    {
      vnet_device_class_t *dev_class =
	vnet_get_device_class (vnm, hi->dev_class_index);
      if (dev_class->mac_addr_change_function)
	{
	  error =
	    dev_class->mac_addr_change_function (hi, (char *) mac_address);
	}
      if (!error)
	{
	  vnet_hw_interface_class_t *hw_class;

	  hw_class = vnet_get_hw_interface_class (vnm, hi->hw_class_index);

	  if (NULL != hw_class->mac_addr_change_function)
	    hw_class->mac_addr_change_function (hi, (char *) mac_address);
	}
      else
	{
	  error =
	    clib_error_return (0,
			       "MAC Address Change is not supported on this interface");
	}
    }
  else
    {
      error =
	clib_error_return (0,
			   "mac address change is not supported for interface index %u",
			   hw_if_index);
    }
  return error;
}

clib_error_t *
vnet_hw_interface_change_mac_address (vnet_main_t * vnm, u32 hw_if_index,
				      u8 * mac_address)
{
  return vnet_hw_interface_change_mac_address_helper
    (vnm, hw_if_index, mac_address);
}

vnet_l3_packet_type_t
vnet_link_to_l3_proto (vnet_link_t link)
{
  switch (link)
    {
    case VNET_LINK_IP4:
      return (VNET_L3_PACKET_TYPE_IP4);
    case VNET_LINK_IP6:
      return (VNET_L3_PACKET_TYPE_IP6);
    case VNET_LINK_MPLS:
      return (VNET_L3_PACKET_TYPE_MPLS);
    case VNET_LINK_ARP:
      return (VNET_L3_PACKET_TYPE_ARP);
    case VNET_LINK_ETHERNET:
    case VNET_LINK_NSH:
      ASSERT (0);
      break;
    }
  ASSERT (0);
  return (0);
}

u8 *
default_build_rewrite (vnet_main_t * vnm,
		       u32 sw_if_index,
		       vnet_link_t link_type, const void *dst_address)
{
  return (NULL);
}

void
default_update_adjacency (vnet_main_t * vnm, u32 sw_if_index, u32 ai)
{
  ip_adjacency_t *adj;

  adj = adj_get (ai);

  switch (adj->lookup_next_index)
    {
    case IP_LOOKUP_NEXT_ARP:
    case IP_LOOKUP_NEXT_GLEAN:
      /*
       * default rewirte in neighbour adj
       */
      adj_nbr_update_rewrite
	(ai,
	 ADJ_NBR_REWRITE_FLAG_COMPLETE,
	 vnet_build_rewrite_for_sw_interface (vnm,
					      sw_if_index,
					      adj_get_link_type (ai), NULL));
      break;
    case IP_LOOKUP_NEXT_MCAST:
      /*
       * mcast traffic also uses default rewrite string with no mcast
       * switch time updates.
       */
      adj_mcast_update_rewrite
	(ai,
	 vnet_build_rewrite_for_sw_interface (vnm,
					      sw_if_index,
					      adj_get_link_type (ai),
					      NULL), 0, 0);
      break;
    case IP_LOOKUP_NEXT_DROP:
    case IP_LOOKUP_NEXT_PUNT:
    case IP_LOOKUP_NEXT_LOCAL:
    case IP_LOOKUP_NEXT_REWRITE:
    case IP_LOOKUP_NEXT_MCAST_MIDCHAIN:
    case IP_LOOKUP_NEXT_MIDCHAIN:
    case IP_LOOKUP_NEXT_ICMP_ERROR:
    case IP_LOOKUP_N_NEXT:
      ASSERT (0);
      break;
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
