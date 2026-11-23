/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

/* cli.h: declarative CLI infrastructure.
 *
 * A command declares its arguments as typed, named data. Parsing,
 * completion, help, error reporting, structured output and the JSON schema
 * are all derived from that declaration. This part only depends on vppinfra,
 * vlib registers the commands (a VLIB_CLI_COMMAND with a handler) and
 * connects the parser to the CLI sessions.
 */

#pragma once

#include <vppinfra/format.h>
#include <vppinfra/error.h>
#include <vppinfra/json.h>

typedef struct cli_arg_t cli_arg_t;
typedef struct cli_ctx_t cli_ctx_t;
typedef struct cli_type_t cli_type_t;

/* Candidate for completion: text replaces the word under the cursor. */
/* Completion candidate: text replaces the word under the cursor, help is an
 * optional description. Both are owned vectors. */
typedef struct
{
  u8 *text;
  u8 *help;
} cli_candidate_t;

typedef enum
{
  CLI_K_END = 0,
  CLI_K_VALUE,	 /* positional value */
  CLI_K_KEYWORD, /* keyword followed by a value */
  CLI_K_FLAG,	 /* keyword without value */
  CLI_K_ONEOF,	 /* children are alternatives */
  CLI_K_SEQ,	 /* children are an ordered group */
  CLI_K_GROUP,	 /* keyword which enables its child keywords/flags */
} cli_kind_t;

#define CLI_F_OPTIONAL (1 << 0)
#define CLI_F_REPEAT   (1 << 1)
/* accepted, but not completed, not in the usage and not in the help */
#define CLI_F_HIDDEN (1 << 2)

typedef struct
{
  const char *name;
  const char *help;
  u32 value;
} cli_choice_t;

typedef struct
{
  const cli_arg_t *arg;
  /* token of the line the value was given at, for error reporting */
  u32 tok;
  /* the value is the default of the argument, it was not given */
  u8 is_default;
  union
  {
    u64 u64;
    f64 f64;
    u32 index; /* enum index/value, sw_if_index, hw_if_index, node index */
    u8 *str;
    struct
    {
      u8 addr[16];
      u8 len;
      u8 is_ip6;
    } prefix;
    struct
    {
      u8 start[16];
      u8 stop[16];
      u8 is_ip6;
    } ip_range;
    struct
    {
      u32 start, stop;
    } range;
  };
} cli_value_t;

struct cli_type_t
{
  const char *name;
  const char *help;
  /* how a value of the type is shown in the usage instead of <name>, e.g. {on|off} */
  const char *usage;
  /* value->str is a vector owned by the value, freed with the context */
  u8 owns_str;
  /* takes the rest of the line, up to a '|', as it was typed. value->str is
   * the text, parse and complete are not used. */
  u8 greedy;
  /* Returns 0 on success, otherwise an error message vector. */
  u8 *(*parse) (const cli_arg_t *arg, u8 *tok, cli_value_t *v);
  /* Appends candidates starting with prefix. */
  void (*complete) (const cli_arg_t *arg, u8 *prefix, cli_candidate_t **out);
  /* For types which are one of a set of names, e.g. the objects of a pool:
   * returns the next name and sets *value, which is stored in v->index, and
   * optionally *help to the description. iter is 0 at the first call. With
   * parse and complete set
   * to cli_names_parse and cli_names_complete the type needs nothing else. */
  const char *(*next_name) (const cli_arg_t *arg, u32 *iter, u32 *value, const char **help);

  /* private */
  struct cli_type_t *next;
};

struct cli_arg_t
{
  cli_kind_t kind;
  const char *name;
  const char *alias;
  const char *help;
  const cli_type_t *type;
  u32 flags;
  u64 min, max; /* range for integer types, max == 0 means type maximum */
  const cli_choice_t *choices;
  const cli_arg_t *children;
  /* default, as it would be typed. The argument has to be optional, if it is
   * not given the parsed default is its value, see cli_value_t.is_default. */
  const char *def;
  /* names of the arguments which have to be given with this one, and of those
   * which can not be given with it, separated by ',' */
  const char *requires;
  const char *excludes;
  /* the argument is accepted but not advertised, using it prints a warning
   * with this text, e.g. "use 'new-name' instead" */
  const char *deprecated;
};

/* Argument list of a command, adds the terminating empty element:
 * .args = CLI_ARGS (CLI_VALUE ("id", cli_type_u32), CLI_FLAG ("verbose")) */
#define CLI_ARGS(...)                                                                              \
  (cli_arg_t[])                                                                                    \
  {                                                                                                \
    __VA_ARGS__, {}                                                                                \
  }

/* Argument declaration helpers. */
#define CLI_VALUE(n, t, ...)   { .kind = CLI_K_VALUE, .name = n, .type = &t, __VA_ARGS__ }
#define CLI_KEYWORD(n, t, ...) { .kind = CLI_K_KEYWORD, .name = n, .type = &t, __VA_ARGS__ }
/* Optional keyword. CLI_OPT_KEYWORD must not be given .flags, use
 * CLI_OPT_KEYWORD_F to add flags such as CLI_F_REPEAT */
#define CLI_OPT_KEYWORD(n, t, ...) CLI_KEYWORD (n, t, .flags = CLI_F_OPTIONAL, __VA_ARGS__)
#define CLI_OPT_KEYWORD_F(n, t, f, ...)                                                            \
  CLI_KEYWORD (n, t, .flags = CLI_F_OPTIONAL | (f), __VA_ARGS__)
#define CLI_FLAG(n, ...) { .kind = CLI_K_FLAG, .name = n, __VA_ARGS__ }
#define CLI_ENUM(n, f, ...)                                                                        \
  {                                                                                                \
    .kind = CLI_K_VALUE,                                                                           \
    .name = n,                                                                                     \
    .type = &cli_type_enum,                                                                        \
    .flags = f,                                                                                    \
    .choices = (const cli_choice_t[]) { __VA_ARGS__, {} },                                         \
  }
#define CLI_ONEOF(n, f, ...)                                                                       \
  {                                                                                                \
    .kind = CLI_K_ONEOF,                                                                           \
    .name = n,                                                                                     \
    .flags = f,                                                                                    \
    .children = (const cli_arg_t[]) { __VA_ARGS__, {} },                                           \
  }
/* Optional keyword followed, in any order, by its own keywords and flags:
 * CLI_GROUP ("tunnel", "tunnel parameters", CLI_KEYWORD ("src", ...), ...) */
#define CLI_GROUP(n, h, ...)                                                                       \
  {                                                                                                \
    .kind = CLI_K_GROUP,                                                                           \
    .name = n,                                                                                     \
    .help = h,                                                                                     \
    .flags = CLI_F_OPTIONAL,                                                                       \
    .children = (const cli_arg_t[]) { __VA_ARGS__, {} },                                           \
  }
/* A group which needs some of its keywords when it is given: the names of the
 * keywords, separated by ',', are in req */
#define CLI_GROUP_REQUIRES(n, h, req, ...)                                                         \
  {                                                                                                \
    .kind = CLI_K_GROUP,                                                                           \
    .name = n,                                                                                     \
    .help = h,                                                                                     \
    .flags = CLI_F_OPTIONAL,                                                                       \
    .requires = req,                                                                               \
    .children = (const cli_arg_t[]) { __VA_ARGS__, {} },                                           \
  }
#define CLI_SEQ(...)                                                                               \
  {                                                                                                \
    .kind = CLI_K_SEQ,                                                                             \
    .children = (const cli_arg_t[]) { __VA_ARGS__, {} },                                           \
  }

/* Argument types. Any component, including plugins, can register new types
 * with CLIB_CLI_TYPE and use them in its commands, e.g.:
 *
 *   CLIB_CLI_TYPE (cli_type_foo) = {
 *     .name = "foo", .help = "foo name",
 *     .parse = foo_parse, .complete = foo_complete,
 *   };
 *
 * Registered types show up in 'show cli schema'. */
__clib_export extern cli_type_t cli_type_u32;
__clib_export extern cli_type_t cli_type_u64;
__clib_export extern cli_type_t cli_type_f64;
__clib_export extern cli_type_t cli_type_string;
__clib_export extern cli_type_t cli_type_enum;
__clib_export extern cli_type_t cli_type_range;
__clib_export extern cli_type_t cli_type_rest;
/* v->str is a bitmap, set with unformat_bitmap_list syntax: 0-3,5 */
__clib_export extern cli_type_t cli_type_bitmap;
/* v->f64 is seconds: 10, 1.5, 250ms, 10s, 5m, 2h, 1d */
__clib_export extern cli_type_t cli_type_duration;
/* v->u64 is bytes: 4096, 4K, 64M, 2G, 1T (powers of 1024), min and max apply */
__clib_export extern cli_type_t cli_type_size;
/* v->index is 1 for on, enable, yes, true and 0 for off, disable, no, false */
__clib_export extern cli_type_t cli_type_bool;
/* v->str is a vector of bytes: 0xdead, dead. max is the number of bytes */
__clib_export extern cli_type_t cli_type_hex;
/* v->str is the path, completes the files and directories */
__clib_export extern cli_type_t cli_type_file;
/* v->f64 is 0 to 100, with an optional % */
__clib_export extern cli_type_t cli_type_percent;
/* v->u64 is the or of the values of the choices which were given, a comma
 * separated list. Case is ignored and '-' is the same as '_' */
__clib_export extern cli_type_t cli_type_flags;
/* v->str is a vector of u32: 1,2,5-7. max is the number of entries */
__clib_export extern cli_type_t cli_type_u32_list;

/* parse and complete of the types which have next_name */
__clib_export u8 *cli_names_parse (const cli_arg_t *a, u8 *tok, cli_value_t *v);
__clib_export void cli_names_complete (const cli_arg_t *a, u8 *prefix, cli_candidate_t **out);

__clib_export void cli_type_registration_helper (cli_type_t *x);
__clib_export void cli_type_unregistration_helper (cli_type_t *x);

#ifndef CLIB_MARCH_VARIANT
#define CLIB_CLI_TYPE(x, ...)                                                                      \
  __VA_ARGS__ cli_type_t x;                                                                        \
  static void __cli_type_registration_##x (void) __attribute__ ((__constructor__));                \
  static void __cli_type_registration_##x (void) { cli_type_registration_helper (&x); }            \
  static void __cli_type_unregistration_##x (void) __attribute__ ((__destructor__));               \
  static void __cli_type_unregistration_##x (void) { cli_type_unregistration_helper (&x); }        \
  __VA_ARGS__ cli_type_t x

#else
#define CLIB_CLI_TYPE(x, ...) static __clib_unused cli_type_t __clib_unused_##x
#endif

static_always_inline int
cli_is_digit (u8 c)
{
  return c >= '0' && c <= '9';
}

static_always_inline u8
cli_to_lower (u8 c)
{
  if (c >= 'A' && c <= 'Z')
    return c + 'a' - 'A';
  return c;
}

/* Value access. Names are the declared argument names. */
__clib_export cli_value_t *cli_get (cli_ctx_t *ctx, const char *name);
__clib_export cli_value_t *cli_get_next (cli_ctx_t *ctx, cli_value_t *prev);

#define cli_foreach(v, ctx, name)                                                                  \
  for ((v) = cli_get ((ctx), (name)); (v); (v) = cli_get_next ((ctx), (v)))

static_always_inline int
cli_flag (cli_ctx_t *ctx, const char *name)
{
  return cli_get (ctx, name) != 0;
}

static_always_inline u64
cli_u64 (cli_ctx_t *ctx, const char *name, u64 def)
{
  cli_value_t *v = cli_get (ctx, name);
  return v ? v->u64 : def;
}

/* Index-like value (enum, interface, node ...), ~0 if not present. */
static_always_inline u32
cli_index (cli_ctx_t *ctx, const char *name)
{
  cli_value_t *v = cli_get (ctx, name);
  return v ? v->index : ~0;
}

/* Structured output. Handlers build a clib_json tree and emit it, the
 * infrastructure renders it as a table, key/value list or JSON depending
 * on the pipeline given by the user (e.g. '| json', '| where ...'). */
typedef struct
{
  const char *key;
  const char *header;
} cli_column_t;

/* True if the user asked for structured output ('| json', '| where'). */
__clib_export int cli_is_structured (cli_ctx_t *ctx);
__clib_export int cli_is_json (cli_ctx_t *ctx);

/* Emit a JSON text whose root is an array of objects, one per row. The
 * text is consumed (freed), the output is collected in ctx->out. */
__clib_export clib_error_t *cli_emit_table (cli_ctx_t *ctx, clib_json_text_t *j,
					    const cli_column_t *cols);
/* Emit a JSON text whose root is a single object. The text is consumed. */
__clib_export clib_error_t *cli_emit_object (cli_ctx_t *ctx, clib_json_text_t *j,
					     const cli_column_t *cols);

/* --- Internal, shared between cli*.c --- */

typedef struct
{
  u8 *s;
  u32 pos, end; /* offsets in the input line */
  u8 quoted;
} cli_tok_t;

typedef enum
{
  CLI_FILTER_JSON,
  CLI_FILTER_GREP,
  CLI_FILTER_HEAD,
  CLI_FILTER_TAIL,
  CLI_FILTER_COUNT,
  CLI_FILTER_WHERE,
} cli_filter_kind_t;

typedef struct
{
  cli_filter_kind_t kind;
  u8 invert, icase;
  u32 n;
  u8 *pat;   /* grep pattern, where value */
  u8 *field; /* where field */
  u8 *op;    /* where operator */
} cli_filter_t;

struct cli_ctx_t
{
  cli_value_t *values;
  cli_filter_t *filters;
  u8 *out;	/* structured output, see cli_emit_table () */
  u8 *warnings; /* text for the user, e.g. use of deprecated arguments */
  u8 json;
  u8 has_where;
  u8 emitted;
  u8 help;	      /* the line ended with '?' */
  u8 plain_text_only; /* the handler must not use ANSI sequences, such as colors */
};

/* Parses a command line, the arguments followed by optional "| filter ...",
 * according to args. On success the values and the filters are in ctx. On
 * failure the error has the message, the line and a marker below the
 * offending token. If the line ends with '?' only ctx->help is set. */
__clib_export clib_error_t *cli_parse_line (const cli_arg_t *args, u8 *line, cli_ctx_t *ctx);

/* Parses text of the form "filter [args] | filter ..." which follows the '|'
 * of a command line, for commands which parse their arguments by themselves.
 * Same errors as cli_parse_line (). */
__clib_export clib_error_t *cli_parse_pipeline (u8 *text, cli_ctx_t *ctx);

/* The user asked for output which the command did not emit */
__clib_export clib_error_t *cli_check_output (cli_ctx_t *ctx);

/* Parses the tokens following a '|' */
u8 *cli_parse_filters (cli_ctx_t *ctx, cli_tok_t *toks, u32 n_tok, u32 *err_tok);
__clib_export int cli_has_text_filters (cli_ctx_t *ctx);
/* Applies grep, head, tail and count to text. */
__clib_export u8 *cli_apply_text_filters (cli_ctx_t *ctx, u8 *text);
__clib_export void cli_ctx_free (cli_ctx_t *ctx);
__clib_export void cli_candidate_add (cli_candidate_t **out, const char *text, const char *help);
__clib_export void cli_candidates_free (cli_candidate_t *c);
__clib_export int cli_prefix_match (const char *s, const u8 *prefix);
u8 *cli_suggest (u8 *word, cli_candidate_t *cands);
extern const char *cli_filter_names[];

/* Appends the candidates for the word under the cursor, rest is the part of
 * the command line after the command path. */
__clib_export void cli_complete_args (const cli_arg_t *args, u8 *rest, cli_candidate_t **out);

/* usage and help of a command: path, short help, long help and arguments */
__clib_export format_function_t format_cli_help;

/* schema of arguments, adds an array element for each argument, and of all
 * registered types, to the current array of j */
__clib_export void cli_args_to_json (clib_json_text_t *j, const cli_arg_t *args);
__clib_export void cli_types_to_json (clib_json_text_t *j);
