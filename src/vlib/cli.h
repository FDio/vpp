/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* cli.h: command line interface */

#ifndef included_vlib_cli_h
#define included_vlib_cli_h

#include <vppinfra/format.h>
#include <vlib/log.h>

struct vlib_cli_command_t;

typedef struct
{
  u32 min_char;

  /* Indexed by name[position] - min_char. */
  uword **bitmaps;
} vlib_cli_parse_position_t;

typedef struct
{
  u8 *name;

  u32 index;
} vlib_cli_sub_command_t;

typedef struct
{
  u8 *name;

  u32 rule_index;

  u32 command_index;
} vlib_cli_sub_rule_t;

typedef struct
{
  char *name;
  char *short_help;
  char *long_help;

  /* Number of bytes in parsed data.  Zero for vector. */
  uword data_size;

  unformat_function_t *unformat_function;

  /* Opaque for unformat function. */
  uword unformat_function_arg[2];
} vlib_cli_parse_rule_t;

/* CLI command callback function. */
typedef clib_error_t *(vlib_cli_command_function_t)
  (struct vlib_main_t * vm,
   unformat_input_t * input, struct vlib_cli_command_t * cmd);

typedef struct vlib_cli_command_t
{
  /* Command path (e.g. "show something").
     Spaces delimit elements of path. */
  char *path;

  /* Short/long help strings. */
  char *short_help;
  char *long_help;

  /* Callback function. */
  vlib_cli_command_function_t *function;

  /* Opaque. */
  uword function_arg;

  /* Known MP-safe? */
  uword is_mp_safe;

  /* Sub commands for this command. */
  vlib_cli_sub_command_t *sub_commands;

  /* Hash table mapping name (e.g. last path element) to sub command index. */
  uword *sub_command_index_by_name;

  /* bitmap[p][c][i] says whether sub-command i has character
     c in position p. */
  vlib_cli_parse_position_t *sub_command_positions;

  /* Hash table mapping name (e.g. last path element) to sub rule index. */
  uword *sub_rule_index_by_name;

  /* Vector of possible parse rules for this path. */
  vlib_cli_sub_rule_t *sub_rules;

  /* List of CLI commands, built by constructors */
  struct vlib_cli_command_t *next_cli_command;

  /* Hit counter */
  u32 hit_counter;
} vlib_cli_command_t;

typedef void (vlib_cli_output_function_t) (uword arg,
					   u8 * buffer, uword buffer_bytes);
typedef struct vlib_cli_main_t
{
  /* Vector of all known commands. */
  vlib_cli_command_t *commands;

  /* Hash table mapping normalized path to index into all_commands. */
  uword *command_index_by_path;

  /* registration list added by constructors */
  vlib_cli_command_t *cli_command_registrations;

  /* index vector, to sort commands, etc. */
  u32 *sort_vector;


  /* performance counter callback */
  void (**perf_counter_cbs)
    (struct vlib_cli_main_t *, u32 id, int before_or_after);
  void (**perf_counter_cbs_tmp)
    (struct vlib_cli_main_t *, u32 id, int before_or_after);

  /* cli log */
  vlib_log_class_t log;

} vlib_cli_main_t;

#ifndef CLIB_MARCH_VARIANT
#define VLIB_CLI_COMMAND(x, ...)                                              \
  __VA_ARGS__ vlib_cli_command_t x;                                           \
  static void __vlib_cli_command_registration_##x (void)                      \
    __attribute__ ((__constructor__));                                        \
  static void __vlib_cli_command_registration_##x (void)                      \
  {                                                                           \
    vlib_global_main_t *vgm = vlib_get_global_main ();                        \
    vlib_cli_main_t *cm = &vgm->cli_main;                                     \
    x.next_cli_command = cm->cli_command_registrations;                       \
    cm->cli_command_registrations = &x;                                       \
  }                                                                           \
  static void __vlib_cli_command_unregistration_##x (void)                    \
    __attribute__ ((__destructor__));                                         \
  static void __vlib_cli_command_unregistration_##x (void)                    \
  {                                                                           \
    vlib_global_main_t *vgm = vlib_get_global_main ();                        \
    vlib_cli_main_t *cm = &vgm->cli_main;                                     \
    VLIB_REMOVE_FROM_LINKED_LIST (cm->cli_command_registrations, &x,          \
				  next_cli_command);                          \
  }                                                                           \
  __VA_ARGS__ vlib_cli_command_t x
#else
/* create unused pointer to silence compiler warnings and get whole
   function optimized out */
#define VLIB_CLI_COMMAND(x,...)                                         \
static __clib_unused vlib_cli_command_t __clib_unused_##x
#endif

#define VLIB_CLI_PARSE_RULE(x) \
  vlib_cli_parse_rule_t x
/* Output to current CLI connection. */
void vlib_cli_output (struct vlib_main_t *vm, char *fmt, ...);

/* Process CLI input. */
int vlib_cli_input (struct vlib_main_t *vm,
		    unformat_input_t * input,
		    vlib_cli_output_function_t * function,
		    uword function_arg);

clib_error_t *vlib_cli_register (struct vlib_main_t *vm,
				 vlib_cli_command_t * c);
clib_error_t *vlib_cli_register_parse_rule (struct vlib_main_t *vm,
					    vlib_cli_parse_rule_t * c);

unformat_function_t unformat_vlib_cli_line;
uword unformat_vlib_cli_sub_input (unformat_input_t * i, va_list * args);

/* Return an vector of strings consisting of possible auto-completions
 * for a given input string */
u8 **vlib_cli_get_possible_completions (u8 * input_str);

#endif /* included_vlib_cli_h */
