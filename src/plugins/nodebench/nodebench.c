/*
 * nodebench.c - skeleton vpp engine plug-in
 *
 * Copyright (c) <current-year> <your-organization>
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

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <nodebench/nodebench.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

#include <nodebench/nodebench.api_enum.h>
#include <nodebench/nodebench.api_types.h>

#define REPLY_MSG_ID_BASE nmp->msg_id_base
#include <vlibapi/api_helper_macros.h>

nodebench_main_t nodebench_main;

/* Action function shared between message handler and debug CLI */

int
nodebench_run (nodebench_main_t *nmp, int run)
{
  int rv = 0;

  return rv;
}

static void
nodebench_disable ()
{
  foreach_vlib_main ()
    {
      vlib_node_set_dispatch_wrapper (this_vlib_main, 0);
    }
}

uword
dispatch_nodebench (vlib_main_t *vm, vlib_node_runtime_t *node,
		    vlib_frame_t *frame)
{
  int i;
  vlib_node_main_t *nm = &vm->node_main;
  nodebench_main_t *nmp = &nodebench_main;
  {
    vlib_node_t *n = vlib_get_node (vm, node->node_index);
    if (n->index != 692)
      {
	// clib_warning("dispatch for %v index %d", n->name, n->index);
      }
  }
  for (i = 0; i < _vec_len (nm->pending_frames); i++)
    {
      /*
      vlib_pending_frame_t *pf = vec_elt_at_index(nm->pending_frames, i);
      vlib_node_runtime_t *nrt = vlib_node_get_runtime(vm,
      pf->node_runtime_index); vlib_frame_t *f = pf->frame; vlib_node_t *n =
      vlib_get_node (vm, nrt->node_index); clib_warning("| pf index: %d node rt
      index: %d node_index: %d next_frame_index: %x name: %v frame n_vectors:
      %d", i, pf->node_runtime_index, nrt->node_index, pf->next_frame_index,
      n->name, f->n_vectors);
		      */
    }
  if (node->node_index == nodebench_sink_node.index)
    {
      node->flags |= VLIB_NODE_FLAG_TRACE;
    }
  uword result = node->function (vm, node, frame);

  if (node->node_index == nmp->benched_node_index)
    {
      if (result > 0)
	{
	  // clib_warning("processed: %d", result);
	  {
	    // vlib_next_frame_t *nf;
	    // vlib_node_t *nn = vlib_get_node (vm, node->node_index);
	    if (1)
	      {
		for (i = 0; i < node->n_next_nodes; i++)
		  {
		    vlib_next_frame_t *nf;
		    vlib_frame_t *f;
		    vlib_frame_t *fsink;
		    u32 *from, *to_next;
		    int bi;
		    nf = vlib_node_runtime_get_next_frame (vm, node, i);
		    f = nf->frame;
		    // vlib_node_runtime_t *nrt = vlib_node_get_runtime(vm,
		    // nf->node_runtime_index); vlib_node_t *n = vlib_get_node
		    // (vm, nn->next_nodes[i]); clib_warning("next %d : %v
		    // frame %p n_vectors %d", i, n->name, f, f ? f->n_vectors
		    // : 0);

		    if (f)
		      {

			vlib_node_runtime_t *sink_node_runtime =
			  vlib_node_get_runtime (vm,
						 nodebench_sink_node.index);
			sink_node_runtime->flags |= VLIB_NODE_FLAG_TRACE;
			fsink = vlib_get_frame_to_node (
			  vm, nodebench_sink_node.index);
			to_next = vlib_frame_vector_args (fsink);
			from = vlib_frame_vector_args (f);
			for (bi = 0; bi < f->n_vectors; bi++)
			  {
			    vlib_buffer_t *b = vlib_get_buffer (vm, from[bi]);
			    to_next[bi] = from[bi];
			    *(u32 *) b->opaque2 = i;
			  }
			fsink->n_vectors = f->n_vectors;

			vlib_put_frame_to_node (vm, nodebench_sink_node.index,
						fsink);

			for (i = 0; i < _vec_len (nm->pending_frames); i++)
			  {
			    vlib_pending_frame_t *pf =
			      vec_elt_at_index (nm->pending_frames, i);
			    if (pf->frame == f)
			      {
				vec_del1 (nm->pending_frames, i);
				break;
			      }
			  }
			/*
			u32 *from = vlib_frame_vector_args (f);
			vlib_buffer_free (vm, from, f->n_vectors);
			*/
			f->n_vectors = 0;
			f->frame_flags &= ~VLIB_FRAME_PENDING;
		      }
		  }
	      }
	  }
	  for (i = 0; i < _vec_len (nm->pending_frames); i++)
	    {
	      /*
	      vlib_pending_frame_t *pf = vec_elt_at_index(nm->pending_frames,
	      i); vlib_node_runtime_t *nrt = vlib_node_get_runtime(vm,
	      pf->node_runtime_index); vlib_frame_t *f = pf->frame; vlib_node_t
	      *n = vlib_get_node (vm, nrt->node_index); clib_warning("pf index:
	      %d node rt index: %d node_index: %d frame: %p next_frame_index:
	      %x name: %v frame n_vectors: %d", i, pf->node_runtime_index,
	      nrt->node_index, f, pf->next_frame_index, n->name, f->n_vectors);
			   */
	    }
	}
      else
	{
	  nodebench_disable ();
	}
    }
  return result;
}

static clib_error_t *
nodebench_run_command_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  nodebench_main_t *nmp = &nodebench_main;
  u8 *node_name = 0;
  u8 *arc_name = 0;
  u8 feature_arc_index = 0;
  vlib_node_t *n;
  int run = 1;
  // vlib_node_runtime_t *node;
  // vlib_frame_t *frame = 0;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "node %v", &node_name))
	{
	  n = vlib_get_node_by_name (vm, node_name);
	}
      else if (unformat (input, "feature-arc %v", &arc_name))
	{
	  vec_add1 (arc_name, 0);
	  feature_arc_index = vnet_get_feature_arc_index ((void *) arc_name);
	  clib_warning ("unformat feature arc index: %d", feature_arc_index);

	  if (feature_arc_index == 255)
	    {
	      clib_error_return (0, "unknown arc `%U'", format_unformat_error,
				 input);
	    }
	}

      else
	break;
    }

  if (n == 0)
    {
      vec_free (node_name);
      return clib_error_return (0, "Please specify a valid node name...");
    }

  if (nmp->benched_node_name)
    {
      vec_free (nmp->benched_node_name);
    }
  nmp->benched_feature_arc_index = feature_arc_index;
  nmp->benched_node_name = node_name;
  nmp->benched_node_index = n->index;
  clib_warning ("benched node index: %d", n->index);

  nmp->benched_node_next_index =
    vlib_node_add_next (vm, nodebench_node.index, nmp->benched_node_index);

  vec_add1 (nmp->benched_node_name, 0);
  u8 feature_index = vnet_get_feature_index (feature_arc_index,
					     (char *) nmp->benched_node_name);
  clib_warning ("feature index in arc: %d", feature_index);

  // vnet_interface_features_show (vm, 1, 1);

  foreach_vlib_main ()
    {
      if (vlib_node_set_dispatch_wrapper (this_vlib_main, dispatch_nodebench))
	clib_warning ("Dispatch wrapper already in use on thread %u",
		      this_vlib_main->thread_index);
    }

  // node = vlib_node_get_runtime(vm, n->index);
  // node->flags |= VLIB_NODE_FLAG_TRACE;
  // frame = vlib_get_frame_to_node(vm, n->index);

  // node->function(vm, node, frame)

  rv = nodebench_run (nmp, run);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return (
	0, "Invalid interface, only works on physical ports");
      break;

    case VNET_API_ERROR_UNIMPLEMENTED:
      return clib_error_return (0,
				"Device driver doesn't support redirection");
      break;

    default:
      return clib_error_return (0, "nodebench_run returned %d", rv);
    }
  return 0;
}

VLIB_CLI_COMMAND (nodebench_run_command, static) = {
  .path = "nodebench run",
  .short_help = "nodebench run <node-name> [disable]",
  .function = nodebench_run_command_fn,
};

/* API message handler */
static void
vl_api_nodebench_run_t_handler (vl_api_nodebench_run_t *mp)
{
  vl_api_nodebench_run_reply_t *rmp;
  nodebench_main_t *nmp = &nodebench_main;
  int rv;

  rv = nodebench_run (nmp, (int) (mp->enable_disable));

  REPLY_MACRO (VL_API_NODEBENCH_RUN_REPLY);
}

/* API definitions */
#include <nodebench/nodebench.api.c>

static clib_error_t *
nodebench_init (vlib_main_t *vm)
{
  nodebench_main_t *nmp = &nodebench_main;
  clib_error_t *error = 0;

  nmp->vlib_main = vm;
  nmp->vnet_main = vnet_get_main ();

  /* Add our API messages to the global name_crc hash table */
  nmp->msg_id_base = setup_message_id_table ();

  nmp->benched_node_name = 0;
  nmp->benched_node_index = ~0;
  nmp->benched_node_next_index = 0;
  nmp->benched_feature_arc_index = 0;

  return error;
}

VLIB_INIT_FUNCTION (nodebench_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "nodebench plugin description goes here",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
