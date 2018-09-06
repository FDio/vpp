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
 * cli.c: Unix stdin/socket CLI.
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
/**
 * @file
 * @brief Unix stdin/socket command line interface.
 * Provides a command line interface so humans can interact with VPP.
 * This is predominantly a debugging and testing mechanism.
 */
/*? %%clicmd:group_label Command line session %% ?*/
/*? %%syscfg:group_label Command line session %% ?*/

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vppinfra/timer.h>

#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <termios.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/telnet.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>
#include <netinet/tcp.h>

/** ANSI escape code. */
#define ESC "\x1b"

/** ANSI Control Sequence Introducer. */
#define CSI ESC "["

/** ANSI clear screen. */
#define ANSI_CLEAR      CSI "2J" CSI "1;1H"
/** ANSI reset color settings. */
#define ANSI_RESET      CSI "0m"
/** ANSI Start bold text. */
#define ANSI_BOLD       CSI "1m"
/** ANSI Stop bold text. */
#define ANSI_DIM        CSI "2m"
/** ANSI Start dark red text. */
#define ANSI_DRED       ANSI_DIM CSI "31m"
/** ANSI Start bright red text. */
#define ANSI_BRED       ANSI_BOLD CSI "31m"
/** ANSI clear line cursor is on. */
#define ANSI_CLEARLINE  CSI "2K"
/** ANSI scroll screen down one line. */
#define ANSI_SCROLLDN   CSI "1T"
/** ANSI save cursor position. */
#define ANSI_SAVECURSOR CSI "s"
/** ANSI restore cursor position if previously saved. */
#define ANSI_RESTCURSOR CSI "u"

/** Maximum depth into a byte stream from which to compile a Telnet
 * protocol message. This is a safety measure. */
#define UNIX_CLI_MAX_DEPTH_TELNET 24

/** Maximum terminal width we will accept */
#define UNIX_CLI_MAX_TERMINAL_WIDTH 512
/** Maximum terminal height we will accept */
#define UNIX_CLI_MAX_TERMINAL_HEIGHT 512
/** Default terminal height */
#define UNIX_CLI_DEFAULT_TERMINAL_HEIGHT 24
/** Default terminal width */
#define UNIX_CLI_DEFAULT_TERMINAL_WIDTH 80

/** A CLI banner line. */
typedef struct
{
  u8 *line;	/**< The line to print. */
  u32 length;	/**< The length of the line without terminating NUL. */
} unix_cli_banner_t;

#define _(a) { .line = (u8 *)(a), .length = sizeof(a) - 1 }
/** Plain welcome banner. */
static unix_cli_banner_t unix_cli_banner[] = {
  _("    _______    _        _   _____  ___ \n"),
  _(" __/ __/ _ \\  (_)__    | | / / _ \\/ _ \\\n"),
  _(" _/ _// // / / / _ \\   | |/ / ___/ ___/\n"),
  _(" /_/ /____(_)_/\\___/   |___/_/  /_/    \n"),
  _("\n")
};

/** ANSI color welcome banner. */
static unix_cli_banner_t unix_cli_banner_color[] = {
  _(ANSI_BRED "    _______    _     " ANSI_RESET "   _   _____  ___ \n"),
  _(ANSI_BRED " __/ __/ _ \\  (_)__ " ANSI_RESET "   | | / / _ \\/ _ \\\n"),
  _(ANSI_BRED " _/ _// // / / / _ \\" ANSI_RESET "   | |/ / ___/ ___/\n"),
  _(ANSI_BRED " /_/ /____(_)_/\\___/" ANSI_RESET "   |___/_/  /_/    \n"),
  _("\n")
};

#undef _

/** Pager line index */
typedef struct
{
  /** Index into pager_vector */
  u32 line;

  /** Offset of the string in the line */
  u32 offset;

  /** Length of the string in the line */
  u32 length;
} unix_cli_pager_index_t;


/** Unix CLI session. */
typedef struct
{
  /** The file index held by unix.c */
  u32 clib_file_index;

  /** Vector of output pending write to file descriptor. */
  u8 *output_vector;

  /** Vector of input saved by Unix input node to be processed by
     CLI process. */
  u8 *input_vector;

  /** This session has command history. */
  u8 has_history;
  /** Array of vectors of commands in the history. */
  u8 **command_history;
  /** The command currently pointed at by the history cursor. */
  u8 *current_command;
  /** How far from the end of the history array the user has browsed. */
  i32 excursion;

  /** Maximum number of history entries this session will store. */
  u32 history_limit;

  /** Current command line counter */
  u32 command_number;

  /** The string being searched for in the history. */
  u8 *search_key;
  /** If non-zero then the CLI is searching in the history array.
   * - @c -1 means search backwards.
   * - @c 1 means search forwards.
   */
  int search_mode;

  /** Position of the insert cursor on the current input line */
  u32 cursor;

  /** Line mode or char mode */
  u8 line_mode;

  /** Set if the CRLF mode wants CR + LF */
  u8 crlf_mode;

  /** Can we do ANSI output? */
  u8 ansi_capable;

  /** Has the session started? */
  u8 started;

  /** Disable the pager? */
  u8 no_pager;

  /** Whether the session is interactive or not.
   * Controls things like initial banner, the CLI prompt etc.  */
  u8 is_interactive;

  /** Whether the session is attached to a socket. */
  u8 is_socket;

  /** If EPIPE has been detected, prevent further write-related
   * activity on the descriptor.
   */
  u8 has_epipe;

  /** Pager buffer */
  u8 **pager_vector;

  /** Index of line fragments in the pager buffer */
  unix_cli_pager_index_t *pager_index;

  /** Line number of top of page */
  u32 pager_start;

  /** Terminal width */
  u32 width;

  /** Terminal height */
  u32 height;

  /** Process node identifier */
  u32 process_node_index;

  /** The current direction of cursor travel.
   *  This is important since when advancing left-to-right, at the
   *  right hand edge of the console the terminal typically defers
   *  wrapping the cursor to the next line until a character is
   *  actually displayed.
   *  This messes up our heuristic for whether to use ANSI to return
   *  the cursor to the end of the line and instead we have to
   *  nudge the cursor to the next line.
   *  A Value of @c 0 means we're advancing left-to-right; @c 1 means
   *  the opposite.
   */
  u8 cursor_direction;

} unix_cli_file_t;

/** Resets the pager buffer and other data.
 * @param f The CLI session whose pager needs to be reset.
 */
always_inline void
unix_cli_pager_reset (unix_cli_file_t * f)
{
  u8 **p;

  f->pager_start = 0;

  vec_free (f->pager_index);
  f->pager_index = 0;

  vec_foreach (p, f->pager_vector)
  {
    vec_free (*p);
  }
  vec_free (f->pager_vector);
  f->pager_vector = 0;
}

/** Release storage used by a CLI session.
 * @param f The CLI session whose storage needs to be released.
 */
always_inline void
unix_cli_file_free (unix_cli_file_t * f)
{
  vec_free (f->output_vector);
  vec_free (f->input_vector);
  unix_cli_pager_reset (f);
}

/** CLI actions */
typedef enum
{
  UNIX_CLI_PARSE_ACTION_NOACTION = 0,	/**< No action */
  UNIX_CLI_PARSE_ACTION_CRLF,		/**< Carriage return, newline or enter */
  UNIX_CLI_PARSE_ACTION_TAB,		/**< Tab key */
  UNIX_CLI_PARSE_ACTION_ERASE,		/**< Erase cursor left */
  UNIX_CLI_PARSE_ACTION_ERASERIGHT,	/**< Erase cursor right */
  UNIX_CLI_PARSE_ACTION_UP,		/**< Up arrow */
  UNIX_CLI_PARSE_ACTION_DOWN,		/**< Down arrow */
  UNIX_CLI_PARSE_ACTION_LEFT,		/**< Left arrow */
  UNIX_CLI_PARSE_ACTION_RIGHT,		/**< Right arrow */
  UNIX_CLI_PARSE_ACTION_HOME,		/**< Home key (jump to start of line) */
  UNIX_CLI_PARSE_ACTION_END,		/**< End key (jump to end of line) */
  UNIX_CLI_PARSE_ACTION_WORDLEFT,	/**< Jump cursor to start of left word */
  UNIX_CLI_PARSE_ACTION_WORDRIGHT,	/**< Jump cursor to start of right word */
  UNIX_CLI_PARSE_ACTION_ERASELINELEFT,	/**< Erase line to left of cursor */
  UNIX_CLI_PARSE_ACTION_ERASELINERIGHT,	/**< Erase line to right & including cursor */
  UNIX_CLI_PARSE_ACTION_CLEAR,		/**< Clear the terminal */
  UNIX_CLI_PARSE_ACTION_REVSEARCH,	/**< Search backwards in command history */
  UNIX_CLI_PARSE_ACTION_FWDSEARCH,	/**< Search forwards in command history */
  UNIX_CLI_PARSE_ACTION_YANK,		/**< Undo last erase action */
  UNIX_CLI_PARSE_ACTION_TELNETIAC,	/**< Telnet control code */

  UNIX_CLI_PARSE_ACTION_PAGER_CRLF,	/**< Enter pressed (CR, CRLF, LF, etc) */
  UNIX_CLI_PARSE_ACTION_PAGER_QUIT,	/**< Exit the pager session */
  UNIX_CLI_PARSE_ACTION_PAGER_NEXT,	/**< Scroll to next page */
  UNIX_CLI_PARSE_ACTION_PAGER_DN,	/**< Scroll to next line */
  UNIX_CLI_PARSE_ACTION_PAGER_UP,	/**< Scroll to previous line */
  UNIX_CLI_PARSE_ACTION_PAGER_TOP,	/**< Scroll to first line */
  UNIX_CLI_PARSE_ACTION_PAGER_BOTTOM,	/**< Scroll to last line */
  UNIX_CLI_PARSE_ACTION_PAGER_PGDN,	/**< Scroll to next page */
  UNIX_CLI_PARSE_ACTION_PAGER_PGUP,	/**< Scroll to previous page */
  UNIX_CLI_PARSE_ACTION_PAGER_REDRAW,	/**< Clear and redraw the page on the terminal */
  UNIX_CLI_PARSE_ACTION_PAGER_SEARCH,	/**< Search the pager buffer */

  UNIX_CLI_PARSE_ACTION_PARTIALMATCH,	/**< Action parser found a partial match */
  UNIX_CLI_PARSE_ACTION_NOMATCH		/**< Action parser did not find any match */
} unix_cli_parse_action_t;

/** @brief Mapping of input buffer strings to action values.
 * @note This won't work as a hash since we need to be able to do
 *       partial matches on the string.
 */
typedef struct
{
  u8 *input;			    /**< Input string to match. */
  u32 len;			    /**< Length of input without final NUL. */
  unix_cli_parse_action_t action;   /**< Action to take when matched. */
} unix_cli_parse_actions_t;

/** @brief Given a capital ASCII letter character return a @c NUL terminated
 * string with the control code for that letter.
 *
 * @param c An ASCII character.
 * @return A @c NUL terminated string of type @c u8[].
 *
 * @par Example
 *     @c CTL('A') returns <code>{ 0x01, 0x00 }</code> as a @c u8[].
 */
#define CTL(c) (u8[]){ (c) - '@', 0 }

#define _(a,b) { .input = (u8 *)(a), .len = sizeof(a) - 1, .action = (b) }
/**
 * Patterns to match on a CLI input stream.
 * @showinitializer
 */
static unix_cli_parse_actions_t unix_cli_parse_strings[] = {
  /* Line handling */
  _("\r\n", UNIX_CLI_PARSE_ACTION_CRLF),	/* Must be before '\r' */
  _("\n", UNIX_CLI_PARSE_ACTION_CRLF),
  _("\r\0", UNIX_CLI_PARSE_ACTION_CRLF),	/* Telnet does this */
  _("\r", UNIX_CLI_PARSE_ACTION_CRLF),

  /* Unix shell control codes */
  _(CTL ('B'), UNIX_CLI_PARSE_ACTION_LEFT),
  _(CTL ('F'), UNIX_CLI_PARSE_ACTION_RIGHT),
  _(CTL ('P'), UNIX_CLI_PARSE_ACTION_UP),
  _(CTL ('N'), UNIX_CLI_PARSE_ACTION_DOWN),
  _(CTL ('A'), UNIX_CLI_PARSE_ACTION_HOME),
  _(CTL ('E'), UNIX_CLI_PARSE_ACTION_END),
  _(CTL ('D'), UNIX_CLI_PARSE_ACTION_ERASERIGHT),
  _(CTL ('U'), UNIX_CLI_PARSE_ACTION_ERASELINELEFT),
  _(CTL ('K'), UNIX_CLI_PARSE_ACTION_ERASELINERIGHT),
  _(CTL ('Y'), UNIX_CLI_PARSE_ACTION_YANK),
  _(CTL ('L'), UNIX_CLI_PARSE_ACTION_CLEAR),
  _(ESC "b", UNIX_CLI_PARSE_ACTION_WORDLEFT),	/* Alt-B */
  _(ESC "f", UNIX_CLI_PARSE_ACTION_WORDRIGHT),	/* Alt-F */
  _("\b", UNIX_CLI_PARSE_ACTION_ERASE),	/* ^H */
  _("\x7f", UNIX_CLI_PARSE_ACTION_ERASE),	/* Backspace */
  _("\t", UNIX_CLI_PARSE_ACTION_TAB),	/* ^I */

  /* VT100 Normal mode - Broadest support */
  _(CSI "A", UNIX_CLI_PARSE_ACTION_UP),
  _(CSI "B", UNIX_CLI_PARSE_ACTION_DOWN),
  _(CSI "C", UNIX_CLI_PARSE_ACTION_RIGHT),
  _(CSI "D", UNIX_CLI_PARSE_ACTION_LEFT),
  _(CSI "H", UNIX_CLI_PARSE_ACTION_HOME),
  _(CSI "F", UNIX_CLI_PARSE_ACTION_END),
  _(CSI "3~", UNIX_CLI_PARSE_ACTION_ERASERIGHT),	/* Delete */
  _(CSI "1;5D", UNIX_CLI_PARSE_ACTION_WORDLEFT),	/* C-Left */
  _(CSI "1;5C", UNIX_CLI_PARSE_ACTION_WORDRIGHT),	/* C-Right */

  /* VT100 Application mode - Some Gnome Terminal functions use these */
  _(ESC "OA", UNIX_CLI_PARSE_ACTION_UP),
  _(ESC "OB", UNIX_CLI_PARSE_ACTION_DOWN),
  _(ESC "OC", UNIX_CLI_PARSE_ACTION_RIGHT),
  _(ESC "OD", UNIX_CLI_PARSE_ACTION_LEFT),
  _(ESC "OH", UNIX_CLI_PARSE_ACTION_HOME),
  _(ESC "OF", UNIX_CLI_PARSE_ACTION_END),

  /* ANSI X3.41-1974 - sent by Microsoft Telnet and PuTTY */
  _(CSI "1~", UNIX_CLI_PARSE_ACTION_HOME),
  _(CSI "4~", UNIX_CLI_PARSE_ACTION_END),

  /* Emacs-ish history search */
  _(CTL ('S'), UNIX_CLI_PARSE_ACTION_FWDSEARCH),
  _(CTL ('R'), UNIX_CLI_PARSE_ACTION_REVSEARCH),

  /* Other protocol things */
  _("\xff", UNIX_CLI_PARSE_ACTION_TELNETIAC),	/* IAC */
  _("\0", UNIX_CLI_PARSE_ACTION_NOACTION),	/* NUL */
  _(NULL, UNIX_CLI_PARSE_ACTION_NOMATCH)
};

/**
 * Patterns to match when a CLI session is in the pager.
 * @showinitializer
 */
static unix_cli_parse_actions_t unix_cli_parse_pager[] = {
  /* Line handling */
  _("\r\n", UNIX_CLI_PARSE_ACTION_PAGER_CRLF),	/* Must be before '\r' */
  _("\n", UNIX_CLI_PARSE_ACTION_PAGER_CRLF),
  _("\r\0", UNIX_CLI_PARSE_ACTION_PAGER_CRLF),	/* Telnet does this */
  _("\r", UNIX_CLI_PARSE_ACTION_PAGER_CRLF),

  /* Pager commands */
  _(" ", UNIX_CLI_PARSE_ACTION_PAGER_NEXT),
  _("q", UNIX_CLI_PARSE_ACTION_PAGER_QUIT),
  _(CTL ('L'), UNIX_CLI_PARSE_ACTION_PAGER_REDRAW),
  _(CTL ('R'), UNIX_CLI_PARSE_ACTION_PAGER_REDRAW),
  _("/", UNIX_CLI_PARSE_ACTION_PAGER_SEARCH),

  /* VT100 */
  _(CSI "A", UNIX_CLI_PARSE_ACTION_PAGER_UP),
  _(CSI "B", UNIX_CLI_PARSE_ACTION_PAGER_DN),
  _(CSI "H", UNIX_CLI_PARSE_ACTION_PAGER_TOP),
  _(CSI "F", UNIX_CLI_PARSE_ACTION_PAGER_BOTTOM),

  /* VT100 Application mode */
  _(ESC "OA", UNIX_CLI_PARSE_ACTION_PAGER_UP),
  _(ESC "OB", UNIX_CLI_PARSE_ACTION_PAGER_DN),
  _(ESC "OH", UNIX_CLI_PARSE_ACTION_PAGER_TOP),
  _(ESC "OF", UNIX_CLI_PARSE_ACTION_PAGER_BOTTOM),

  /* ANSI X3.41-1974 */
  _(CSI "1~", UNIX_CLI_PARSE_ACTION_PAGER_TOP),
  _(CSI "4~", UNIX_CLI_PARSE_ACTION_PAGER_BOTTOM),
  _(CSI "5~", UNIX_CLI_PARSE_ACTION_PAGER_PGUP),
  _(CSI "6~", UNIX_CLI_PARSE_ACTION_PAGER_PGDN),

  /* Other protocol things */
  _("\xff", UNIX_CLI_PARSE_ACTION_TELNETIAC),	/* IAC */
  _("\0", UNIX_CLI_PARSE_ACTION_NOACTION),	/* NUL */
  _(NULL, UNIX_CLI_PARSE_ACTION_NOMATCH)
};

#undef _

/** CLI session events. */
typedef enum
{
  UNIX_CLI_PROCESS_EVENT_READ_READY,  /**< A file descriptor has data to be read. */
  UNIX_CLI_PROCESS_EVENT_QUIT,	      /**< A CLI session wants to close. */
} unix_cli_process_event_type_t;

/** CLI global state. */
typedef struct
{
  /** Prompt string for CLI. */
  u8 *cli_prompt;

  /** Vec pool of CLI sessions. */
  unix_cli_file_t *cli_file_pool;

  /** Vec pool of unused session indices. */
  u32 *unused_cli_process_node_indices;

  /** The session index of the stdin cli */
  u32 stdin_cli_file_index;

  /** File pool index of current input. */
  u32 current_input_file_index;
} unix_cli_main_t;

/** CLI global state */
static unix_cli_main_t unix_cli_main;

/**
 * @brief Search for a byte sequence in the action list.
 *
 * Searches the @ref unix_cli_parse_actions_t list in @a a for a match with
 * the bytes in @a input of maximum length @a ilen bytes.
 * When a match is made @a *matched indicates how many bytes were matched.
 * Returns a value from the enum @ref unix_cli_parse_action_t to indicate
 * whether no match was found, a partial match was found or a complete
 * match was found and what action, if any, should be taken.
 *
 * @param[in]  a        Actions list to search within.
 * @param[in]  input    String fragment to search for.
 * @param[in]  ilen     Length of the string in 'input'.
 * @param[out] matched  Pointer to an integer that will contain the number
 *                      of bytes matched when a complete match is found.
 *
 * @return Action from @ref unix_cli_parse_action_t that the string fragment
 *         matches.
 *         @ref UNIX_CLI_PARSE_ACTION_PARTIALMATCH is returned when the
 *         whole input string matches the start of at least one action.
 *         @ref UNIX_CLI_PARSE_ACTION_NOMATCH is returned when there is no
 *         match at all.
 */
static unix_cli_parse_action_t
unix_cli_match_action (unix_cli_parse_actions_t * a,
		       u8 * input, u32 ilen, i32 * matched)
{
  u8 partial = 0;

  while (a->input)
    {
      if (ilen >= a->len)
	{
	  /* see if the start of the input buffer exactly matches the current
	   * action string. */
	  if (memcmp (input, a->input, a->len) == 0)
	    {
	      *matched = a->len;
	      return a->action;
	    }
	}
      else
	{
	  /* if the first ilen characters match, flag this as a partial -
	   * meaning keep collecting bytes in case of a future match */
	  if (memcmp (input, a->input, ilen) == 0)
	    partial = 1;
	}

      /* check next action */
      a++;
    }

  return partial ?
    UNIX_CLI_PARSE_ACTION_PARTIALMATCH : UNIX_CLI_PARSE_ACTION_NOMATCH;
}


/** Add bytes to the output vector and then flagg the I/O system that bytes
 * are available to be sent.
 */
static void
unix_cli_add_pending_output (clib_file_t * uf,
			     unix_cli_file_t * cf,
			     u8 * buffer, uword buffer_bytes)
{
  clib_file_main_t *fm = &file_main;

  vec_add (cf->output_vector, buffer, buffer_bytes);
  if (vec_len (cf->output_vector) > 0)
    {
      int skip_update = 0 != (uf->flags & UNIX_FILE_DATA_AVAILABLE_TO_WRITE);
      uf->flags |= UNIX_FILE_DATA_AVAILABLE_TO_WRITE;
      if (!skip_update)
	fm->file_update (uf, UNIX_FILE_UPDATE_MODIFY);
    }
}

/** Delete all bytes from the output vector and flag the I/O system
 * that no more bytes are available to be sent.
 */
static void
unix_cli_del_pending_output (clib_file_t * uf,
			     unix_cli_file_t * cf, uword n_bytes)
{
  clib_file_main_t *fm = &file_main;

  vec_delete (cf->output_vector, n_bytes, 0);
  if (vec_len (cf->output_vector) <= 0)
    {
      int skip_update = 0 == (uf->flags & UNIX_FILE_DATA_AVAILABLE_TO_WRITE);
      uf->flags &= ~UNIX_FILE_DATA_AVAILABLE_TO_WRITE;
      if (!skip_update)
	fm->file_update (uf, UNIX_FILE_UPDATE_MODIFY);
    }
}

/** @brief A bit like strchr with a buffer length limit.
 * Search a buffer for the first instance of a character up to the limit of
 * the buffer length. If found then return the position of that character.
 *
 * The key departure from strchr is that if the character is not found then
 * return the buffer length.
 *
 * @param chr The byte value to search for.
 * @param str The buffer in which to search for the value.
 * @param len The depth into the buffer to search.
 *
 * @return The index of the first occurence of \c chr. If \c chr is not
 *          found then \c len instead.
 */
always_inline word
unix_vlib_findchr (u8 chr, u8 * str, word len)
{
  word i = 0;
  for (i = 0; i < len; i++, str++)
    {
      if (*str == chr)
	return i;
    }
  return len;
}

/** @brief Send a buffer to the CLI stream if possible, enqueue it otherwise.
 * Attempts to write given buffer to the file descriptor of the given
 * Unix CLI session. If that session already has data in the output buffer
 * or if the write attempt tells us to try again later then the given buffer
 * is appended to the pending output buffer instead.
 *
 * This is typically called only from \c unix_vlib_cli_output_cooked since
 * that is where CRLF handling occurs or from places where we explicitly do
 * not want cooked handling.
 *
 * @param cf Unix CLI session of the desired stream to write to.
 * @param uf The Unix file structure of the desired stream to write to.
 * @param buffer Pointer to the buffer that needs to be written.
 * @param buffer_bytes The number of bytes from \c buffer to write.
 */
static void
unix_vlib_cli_output_raw (unix_cli_file_t * cf,
			  clib_file_t * uf, u8 * buffer, uword buffer_bytes)
{
  int n = 0;

  if (cf->has_epipe)		/* don't try writing anything */
    return;

  if (vec_len (cf->output_vector) == 0)
    {
      if (cf->is_socket)
	/* If it's a socket we use MSG_NOSIGNAL to prevent SIGPIPE */
	n = send (uf->file_descriptor, buffer, buffer_bytes, MSG_NOSIGNAL);
      else
	n = write (uf->file_descriptor, buffer, buffer_bytes);
    }

  if (n < 0 && errno != EAGAIN)
    {
      if (errno == EPIPE)
	{
	  /* connection closed on us */
	  unix_main_t *um = &unix_main;
	  cf->has_epipe = 1;
	  vlib_process_signal_event (um->vlib_main, cf->process_node_index,
				     UNIX_CLI_PROCESS_EVENT_QUIT,
				     uf->private_data);
	}
      else
	{
	  clib_unix_warning ("write");
	}
    }
  else if ((word) n < (word) buffer_bytes)
    {
      /* We got EAGAIN or we already have stuff in the buffer;
       * queue up whatever didn't get sent for later. */
      if (n < 0)
	n = 0;
      unix_cli_add_pending_output (uf, cf, buffer + n, buffer_bytes - n);
    }
}

/** @brief Process a buffer for CRLF handling before outputting it to the CLI.
 *
 * @param cf Unix CLI session of the desired stream to write to.
 * @param uf The Unix file structure of the desired stream to write to.
 * @param buffer Pointer to the buffer that needs to be written.
 * @param buffer_bytes The number of bytes from \c buffer to write.
 */
static void
unix_vlib_cli_output_cooked (unix_cli_file_t * cf,
			     clib_file_t * uf,
			     u8 * buffer, uword buffer_bytes)
{
  word end = 0, start = 0;

  while (end < buffer_bytes)
    {
      if (cf->crlf_mode)
	{
	  /* iterate the line on \n's so we can insert a \r before it */
	  end = unix_vlib_findchr ('\n',
				   buffer + start,
				   buffer_bytes - start) + start;
	}
      else
	{
	  /* otherwise just send the whole buffer */
	  end = buffer_bytes;
	}

      unix_vlib_cli_output_raw (cf, uf, buffer + start, end - start);

      if (cf->crlf_mode)
	{
	  if (end < buffer_bytes)
	    {
	      unix_vlib_cli_output_raw (cf, uf, (u8 *) "\r\n", 2);
	      end++;		/* skip the \n that we already sent */
	    }
	  start = end;
	}
    }

  /* Use the last character to determine the last direction of the cursor. */
  if (buffer_bytes > 0)
    cf->cursor_direction = (buffer[buffer_bytes - 1] == (u8) '\b');
}

/** @brief Moves the terminal cursor one character to the left, with
 * special handling when it reaches the left edge of the terminal window.
 *
 * Ordinarily we can simply send a '\b' to move the cursor left, however
 * most terminals will not reverse-wrap to the end of the previous line
 * if the cursor is in the left-most column. To counter this we must
 * check the cursor position + prompt length modulo terminal width and
 * if available use some other means, such as ANSI terminal escape
 * sequences, to move the cursor.
 *
 * @param cf Unix CLI session of the desired stream to write to.
 * @param uf The Unix file structure of the desired stream to write to.
 */
static void
unix_vlib_cli_output_cursor_left (unix_cli_file_t * cf, clib_file_t * uf)
{
  unix_cli_main_t *cm = &unix_cli_main;
  static u8 *ansi = 0;		/* assumes no reentry */
  u32 position;

  if (!cf->is_interactive || !cf->ansi_capable || !cf->width)
    {
      /* No special handling for dumb terminals */
      unix_vlib_cli_output_cooked (cf, uf, (u8 *) "\b", 1);
      return;
    }

  position = ((u32) vec_len (cm->cli_prompt) + cf->cursor) % cf->width;

  if (position != 0)
    {
      /* No special handling required if we're not at the left edge */
      unix_vlib_cli_output_cooked (cf, uf, (u8 *) "\b", 1);
      return;
    }

  if (!cf->cursor_direction)
    {
      /* Special handling for when we are at the left edge but
       * the cursor was going left-to-right, but in this situation
       * xterm-like terminals actually hide the cursor off the right
       * edge. A \b here seems to jump one char too many, so let's
       * force the cursor onto the next line instead.
       */
      if (cf->cursor < vec_len (cf->current_command))
	unix_vlib_cli_output_cooked (cf, uf, &cf->current_command[cf->cursor],
				     1);
      else
	unix_vlib_cli_output_cooked (cf, uf, (u8 *) " ", 1);
      unix_vlib_cli_output_cooked (cf, uf, (u8 *) "\r", 1);
    }

  /* Relocate the cursor at the right hand edge one line above */
  ansi = format (ansi, CSI "A" CSI "%dC", cf->width - 1);
  unix_vlib_cli_output_cooked (cf, uf, ansi, vec_len (ansi));
  vec_reset_length (ansi);	/* keep the vec around for next time */
  cf->cursor_direction = 1;	/* going backwards now */
}

/** @brief Output the CLI prompt */
static void
unix_cli_cli_prompt (unix_cli_file_t * cf, clib_file_t * uf)
{
  unix_cli_main_t *cm = &unix_cli_main;

  if (cf->is_interactive)	/* Only interactive sessions get a prompt */
    unix_vlib_cli_output_raw (cf, uf, cm->cli_prompt,
			      vec_len (cm->cli_prompt));
}

/** @brief Output a pager prompt and show number of buffered lines */
static void
unix_cli_pager_prompt (unix_cli_file_t * cf, clib_file_t * uf)
{
  u8 *prompt;
  u32 h;

  h = cf->pager_start + (cf->height - 1);
  if (h > vec_len (cf->pager_index))
    h = vec_len (cf->pager_index);

  prompt = format (0, "\r%s-- more -- (%d-%d/%d)%s",
		   cf->ansi_capable ? ANSI_BOLD : "",
		   cf->pager_start + 1,
		   h,
		   vec_len (cf->pager_index),
		   cf->ansi_capable ? ANSI_RESET : "");

  unix_vlib_cli_output_cooked (cf, uf, prompt, vec_len (prompt));

  vec_free (prompt);
}

/** @brief Output a pager "skipping" message */
static void
unix_cli_pager_message (unix_cli_file_t * cf, clib_file_t * uf,
			char *message, char *postfix)
{
  u8 *prompt;

  prompt = format (0, "\r%s-- %s --%s%s",
		   cf->ansi_capable ? ANSI_BOLD : "",
		   message, cf->ansi_capable ? ANSI_RESET : "", postfix);

  unix_vlib_cli_output_cooked (cf, uf, prompt, vec_len (prompt));

  vec_free (prompt);
}

/** @brief Erase the printed pager prompt */
static void
unix_cli_pager_prompt_erase (unix_cli_file_t * cf, clib_file_t * uf)
{
  if (cf->ansi_capable)
    {
      unix_vlib_cli_output_cooked (cf, uf, (u8 *) "\r", 1);
      unix_vlib_cli_output_cooked (cf, uf,
				   (u8 *) ANSI_CLEARLINE,
				   sizeof (ANSI_CLEARLINE) - 1);
    }
  else
    {
      int i;

      unix_vlib_cli_output_cooked (cf, uf, (u8 *) "\r", 1);
      for (i = 0; i < cf->width - 1; i++)
	unix_vlib_cli_output_cooked (cf, uf, (u8 *) " ", 1);
      unix_vlib_cli_output_cooked (cf, uf, (u8 *) "\r", 1);
    }
}

/** @brief Uses an ANSI escape sequence to move the cursor */
static void
unix_cli_ansi_cursor (unix_cli_file_t * cf, clib_file_t * uf, u16 x, u16 y)
{
  u8 *str;

  str = format (0, "%s%d;%dH", CSI, y, x);

  unix_vlib_cli_output_cooked (cf, uf, str, vec_len (str));

  vec_free (str);
}

/** Redraw the currently displayed page of text.
 * @param cf CLI session to redraw the pager buffer of.
 * @param uf Unix file of the CLI session.
 */
static void
unix_cli_pager_redraw (unix_cli_file_t * cf, clib_file_t * uf)
{
  unix_cli_pager_index_t *pi = NULL;
  u8 *line = NULL;
  word i;

  /* No active pager? Do nothing. */
  if (!vec_len (cf->pager_index))
    return;

  if (cf->ansi_capable)
    {
      /* If we have ANSI, send the clear screen sequence */
      unix_vlib_cli_output_cooked (cf, uf,
				   (u8 *) ANSI_CLEAR,
				   sizeof (ANSI_CLEAR) - 1);
    }
  else
    {
      /* Otherwise make sure we're on a blank line */
      unix_cli_pager_prompt_erase (cf, uf);
    }

  /* (Re-)send the current page of content */
  for (i = 0; i < cf->height - 1 &&
       i + cf->pager_start < vec_len (cf->pager_index); i++)
    {
      pi = &cf->pager_index[cf->pager_start + i];
      line = cf->pager_vector[pi->line] + pi->offset;

      unix_vlib_cli_output_cooked (cf, uf, line, pi->length);
    }
  /* if the last line didn't end in newline, add a newline */
  if (pi && line[pi->length - 1] != '\n')
    unix_vlib_cli_output_cooked (cf, uf, (u8 *) "\n", 1);

  unix_cli_pager_prompt (cf, uf);
}

/** @brief Process and add a line to the pager index.
 * In normal operation this function will take the given character string
 * found in @c line and with length @c len_or_index and iterates the over the
 * contents, adding each line of text discovered within it to the
 * pager index. Lines are identified by newlines ("<code>\\n</code>") and by
 * strings longer than the width of the terminal.
 *
 * If instead @c line is @c NULL then @c len_or_index is taken to mean the
 * index of an existing line in the pager buffer; this simply means that the
 * input line does not need to be cloned since we alreayd have it. This is
 * typical if we are reindexing the pager buffer.
 *
 * @param cf           The CLI session whose pager we are adding to.
 * @param line         The string of text to be indexed into the pager buffer.
 *                     If @c line is @c NULL then the mode of operation
 *                     changes slightly; see the description above.
 * @param len_or_index If @c line is a pointer to a string then this parameter
 *                     indicates the length of that string; Otherwise this
 *                     value provides the index in the pager buffer of an
 *                     existing string to be indexed.
 */
static void
unix_cli_pager_add_line (unix_cli_file_t * cf, u8 * line, word len_or_index)
{
  u8 *p = NULL;
  word i, j, k;
  word line_index, len;
  u32 width = cf->width;
  unix_cli_pager_index_t *pi;

  if (line == NULL)
    {
      /* Use a line already in the pager buffer */
      line_index = len_or_index;
      if (cf->pager_vector != NULL)
	p = cf->pager_vector[line_index];
      len = vec_len (p);
    }
  else
    {
      len = len_or_index;
      /* Add a copy of the raw string to the pager buffer */
      p = vec_new (u8, len);
      clib_memcpy (p, line, len);

      /* store in pager buffer */
      line_index = vec_len (cf->pager_vector);
      vec_add1 (cf->pager_vector, p);
    }

  i = 0;
  while (i < len)
    {
      /* Find the next line, or run to terminal width, or run to EOL */
      int l = len - i;
      j = unix_vlib_findchr ((u8) '\n', p, l < width ? l : width);

      if (j < l && p[j] == '\n')	/* incl \n */
	j++;

      /* Add the line to the index */
      k = vec_len (cf->pager_index);
      vec_validate (cf->pager_index, k);
      pi = &cf->pager_index[k];

      pi->line = line_index;
      pi->offset = i;
      pi->length = j;

      i += j;
      p += j;
    }
}

/** @brief Reindex entire pager buffer.
 * Resets the current pager index and then re-adds the lines in the pager
 * buffer to the index.
 *
 * Additionally this function attempts to retain the current page start
 * line offset by searching for the same top-of-screen line in the new index.
 *
 * @param cf The CLI session whose pager buffer should be reindexed.
 */
static void
unix_cli_pager_reindex (unix_cli_file_t * cf)
{
  word i, old_line, old_offset;
  unix_cli_pager_index_t *pi;

  /* If there is nothing in the pager buffer then make sure the index
   * is empty and move on.
   */
  if (cf->pager_vector == 0)
    {
      vec_reset_length (cf->pager_index);
      return;
    }

  /* Retain a pointer to the current page start line so we can
   * find it later
   */
  pi = &cf->pager_index[cf->pager_start];
  old_line = pi->line;
  old_offset = pi->offset;

  /* Re-add the buffered lines to the index */
  vec_reset_length (cf->pager_index);
  vec_foreach_index (i, cf->pager_vector)
  {
    unix_cli_pager_add_line (cf, NULL, i);
  }

  /* Attempt to re-locate the previously stored page start line */
  vec_foreach_index (i, cf->pager_index)
  {
    pi = &cf->pager_index[i];

    if (pi->line == old_line &&
	(pi->offset <= old_offset || pi->offset + pi->length > old_offset))
      {
	/* Found it! */
	cf->pager_start = i;
	break;
      }
  }

  /* In case the start line was not found (rare), ensure the pager start
   * index is within bounds
   */
  if (cf->pager_start >= vec_len (cf->pager_index))
    {
      if (!cf->height || vec_len (cf->pager_index) < (cf->height - 1))
	cf->pager_start = 0;
      else
	cf->pager_start = vec_len (cf->pager_index) - (cf->height - 1);
    }
}

/** VLIB CLI output function.
 *
 * If the terminal has a pager configured then this function takes care
 * of collating output into the pager buffer; ensuring only the first page
 * is displayed and any lines in excess of the first page are buffered.
 *
 * If the maximum number of index lines in the buffer is exceeded then the
 * pager is cancelled and the contents of the current buffer are sent to the
 * terminal.
 *
 * If there is no pager configured then the output is sent directly to the
 * terminal.
 *
 * @param cli_file_index Index of the CLI session where this output is
 *                       directed.
 * @param buffer         String of printabe bytes to be output.
 * @param buffer_bytes   The number of bytes in @c buffer to be output.
 */
static void
unix_vlib_cli_output (uword cli_file_index, u8 * buffer, uword buffer_bytes)
{
  unix_main_t *um = &unix_main;
  clib_file_main_t *fm = &file_main;
  unix_cli_main_t *cm = &unix_cli_main;
  unix_cli_file_t *cf;
  clib_file_t *uf;

  cf = pool_elt_at_index (cm->cli_file_pool, cli_file_index);
  uf = pool_elt_at_index (fm->file_pool, cf->clib_file_index);

  if (cf->no_pager || um->cli_pager_buffer_limit == 0 || cf->height == 0)
    {
      unix_vlib_cli_output_cooked (cf, uf, buffer, buffer_bytes);
    }
  else
    {
      word row = vec_len (cf->pager_index);
      u8 *line;
      unix_cli_pager_index_t *pi;

      /* Index and add the output lines to the pager buffer. */
      unix_cli_pager_add_line (cf, buffer, buffer_bytes);

      /* Now iterate what was added to display the lines.
       * If we reach the bottom of the page, display a prompt.
       */
      while (row < vec_len (cf->pager_index))
	{
	  if (row < cf->height - 1)
	    {
	      /* output this line */
	      pi = &cf->pager_index[row];
	      line = cf->pager_vector[pi->line] + pi->offset;
	      unix_vlib_cli_output_cooked (cf, uf, line, pi->length);

	      /* if the last line didn't end in newline, and we're at the
	       * bottom of the page, add a newline */
	      if (line[pi->length - 1] != '\n' && row == cf->height - 2)
		unix_vlib_cli_output_cooked (cf, uf, (u8 *) "\n", 1);
	    }
	  else
	    {
	      /* Display the pager prompt every 10 lines */
	      if (!(row % 10))
		unix_cli_pager_prompt (cf, uf);
	    }
	  row++;
	}

      /* Check if we went over the pager buffer limit */
      if (vec_len (cf->pager_index) > um->cli_pager_buffer_limit)
	{
	  /* Stop using the pager for the remainder of this CLI command */
	  cf->no_pager = 2;

	  /* If we likely printed the prompt, erase it */
	  if (vec_len (cf->pager_index) > cf->height - 1)
	    unix_cli_pager_prompt_erase (cf, uf);

	  /* Dump out the contents of the buffer */
	  for (row = cf->pager_start + (cf->height - 1);
	       row < vec_len (cf->pager_index); row++)
	    {
	      pi = &cf->pager_index[row];
	      line = cf->pager_vector[pi->line] + pi->offset;
	      unix_vlib_cli_output_cooked (cf, uf, line, pi->length);
	    }

	  unix_cli_pager_reset (cf);
	}
    }
}

/** Identify whether a terminal type is ANSI capable.
 *
 * Compares the string given in @c term with a list of terminal types known
 * to support ANSI escape sequences.
 *
 * This list contains, for example, @c xterm, @c screen and @c ansi.
 *
 * @param term A string with a terminal type in it.
 * @param len The length of the string in @c term.
 *
 * @return @c 1 if the terminal type is recognized as supporting ANSI
 *         terminal sequences; @c 0 otherwise.
 */
static u8
unix_cli_terminal_type_ansi (u8 * term, uword len)
{
  /* This may later be better done as a hash of some sort. */
#define _(a) do { \
    if (strncasecmp(a, (char *)term, (size_t)len) == 0) return 1; \
  } while(0)

  _("xterm");
  _("xterm-color");
  _("xterm-256color");		/* iTerm on Mac */
  _("screen");
  _("screen-256color");		/* Screen and tmux */
  _("ansi");			/* Microsoft Telnet */
#undef _

  return 0;
}

/** Identify whether a terminal type is non-interactive.
 *
 * Compares the string given in @c term with a list of terminal types known
 * to be non-interactive, as send by tools such as @c vppctl .
 *
 * This list contains, for example, @c vppctl.
 *
 * @param term A string with a terminal type in it.
 * @param len The length of the string in @c term.
 *
 * @return @c 1 if the terminal type is recognized as being non-interactive;
 *         @c 0 otherwise.
 */
static u8
unix_cli_terminal_type_noninteractive (u8 * term, uword len)
{
  /* This may later be better done as a hash of some sort. */
#define _(a) do { \
    if (strncasecmp(a, (char *)term, (size_t)len) == 0) return 1; \
  } while(0)

  _("vppctl");
#undef _

  return 0;
}

/** Set a session to be non-interactive. */
static void
unix_cli_set_session_noninteractive (unix_cli_file_t * cf)
{
  /* Non-interactive sessions don't get these */
  cf->is_interactive = 0;
  cf->no_pager = 1;
  cf->history_limit = 0;
  cf->has_history = 0;
  cf->line_mode = 1;
}

/** @brief Emit initial welcome banner and prompt on a connection. */
static void
unix_cli_file_welcome (unix_cli_main_t * cm, unix_cli_file_t * cf)
{
  unix_main_t *um = &unix_main;
  clib_file_main_t *fm = &file_main;
  clib_file_t *uf = pool_elt_at_index (fm->file_pool, cf->clib_file_index);
  unix_cli_banner_t *banner;
  int i, len;

  /* Mark the session as started if we get here */
  cf->started = 1;

  if (!(cf->is_interactive))	/* No banner for non-interactive sessions */
    return;

  /*
   * Put the first bytes directly into the buffer so that further output is
   * queued until everything is ready. (oterwise initial prompt can appear
   * mid way through VPP initialization)
   */
  unix_cli_add_pending_output (uf, cf, (u8 *) "\r", 1);

  if (!um->cli_no_banner)
    {
      if (cf->ansi_capable)
	{
	  banner = unix_cli_banner_color;
	  len = ARRAY_LEN (unix_cli_banner_color);
	}
      else
	{
	  banner = unix_cli_banner;
	  len = ARRAY_LEN (unix_cli_banner);
	}

      for (i = 0; i < len; i++)
	{
	  unix_vlib_cli_output_cooked (cf, uf,
				       banner[i].line, banner[i].length);
	}
    }

  /* Prompt. */
  unix_cli_cli_prompt (cf, uf);

}

/** @brief A failsafe triggered on a timer to ensure we send the prompt
 * to telnet sessions that fail to negotiate the terminal type. */
static void
unix_cli_file_welcome_timer (any arg, f64 delay)
{
  unix_cli_main_t *cm = &unix_cli_main;
  unix_cli_file_t *cf;
  (void) delay;

  /* Check the connection didn't close already */
  if (pool_is_free_index (cm->cli_file_pool, (uword) arg))
    return;

  cf = pool_elt_at_index (cm->cli_file_pool, (uword) arg);

  if (!cf->started)
    unix_cli_file_welcome (cm, cf);
}

/** @brief A mostly no-op Telnet state machine.
 * Process Telnet command bytes in a way that ensures we're mostly
 * transparent to the Telnet protocol. That is, it's mostly a no-op.
 *
 * @return -1 if we need more bytes, otherwise a positive integer number of
 *          bytes to consume from the input_vector, not including the initial
 *          IAC byte.
 */
static i32
unix_cli_process_telnet (unix_main_t * um,
			 unix_cli_file_t * cf,
			 clib_file_t * uf, u8 * input_vector, uword len)
{
  /* Input_vector starts at IAC byte.
   * See if we have a complete message; if not, return -1 so we wait for more.
   * if we have a complete message, consume those bytes from the vector.
   */
  i32 consume = 0;

  if (len == 1)
    return -1;			/* want more bytes */

  switch (input_vector[1])
    {
    case IAC:
      /* two IAC's in a row means to pass through 0xff.
       * since that makes no sense here, just consume it.
       */
      consume = 1;
      break;

    case WILL:
    case WONT:
    case DO:
    case DONT:
      /* Expect 3 bytes */
      if (len < 3)
	return -1;		/* want more bytes */

      consume = 2;
      break;

    case SB:
      {
	/* Sub option - search ahead for IAC SE to end it */
	i32 i;
	for (i = 3; i < len && i < UNIX_CLI_MAX_DEPTH_TELNET; i++)
	  {
	    if (input_vector[i - 1] == IAC && input_vector[i] == SE)
	      {
		/* We have a complete message; see if we care about it */
		switch (input_vector[2])
		  {
		  case TELOPT_TTYPE:
		    if (input_vector[3] != 0)
		      break;
		    {
		      /* See if the the terminal type is recognized */
		      u8 *term = input_vector + 4;
		      uword len = i - 5;

		      /* See if the terminal type is ANSI capable */
		      cf->ansi_capable =
			unix_cli_terminal_type_ansi (term, len);

		      /* See if the terminal type indicates non-interactive */
		      if (unix_cli_terminal_type_noninteractive (term, len))
			unix_cli_set_session_noninteractive (cf);
		    }

		    /* If session not started, we can release the pause */
		    if (!cf->started)
		      /* Send the welcome banner and initial prompt */
		      unix_cli_file_welcome (&unix_cli_main, cf);
		    break;

		  case TELOPT_NAWS:
		    /* Window size */
		    if (i != 8)	/* check message is correct size */
		      break;

		    cf->width =
		      clib_net_to_host_u16 (*((u16 *) (input_vector + 3)));
		    if (cf->width > UNIX_CLI_MAX_TERMINAL_WIDTH)
		      cf->width = UNIX_CLI_MAX_TERMINAL_WIDTH;
		    if (cf->width == 0)
		      cf->width = UNIX_CLI_DEFAULT_TERMINAL_WIDTH;

		    cf->height =
		      clib_net_to_host_u16 (*((u16 *) (input_vector + 5)));
		    if (cf->height > UNIX_CLI_MAX_TERMINAL_HEIGHT)
		      cf->height = UNIX_CLI_MAX_TERMINAL_HEIGHT;
		    if (cf->height == 0)
		      cf->height = UNIX_CLI_DEFAULT_TERMINAL_HEIGHT;

		    /* reindex pager buffer */
		    unix_cli_pager_reindex (cf);
		    /* redraw page */
		    unix_cli_pager_redraw (cf, uf);
		    break;

		  default:
		    break;
		  }
		/* Consume it all */
		consume = i;
		break;
	      }
	  }

	if (i == UNIX_CLI_MAX_DEPTH_TELNET)
	  consume = 1;		/* hit max search depth, advance one byte */

	if (consume == 0)
	  return -1;		/* want more bytes */

	break;
      }

    case GA:
    case EL:
    case EC:
    case AO:
    case IP:
    case BREAK:
    case DM:
    case NOP:
    case SE:
    case EOR:
    case ABORT:
    case SUSP:
    case xEOF:
      /* Simple one-byte messages */
      consume = 1;
      break;

    case AYT:
      /* Are You There - trigger a visible response */
      consume = 1;
      unix_vlib_cli_output_cooked (cf, uf, (u8 *) "fd.io VPP\n", 10);
      break;

    default:
      /* Unknown command! Eat the IAC byte */
      break;
    }

  return consume;
}

/** @brief Process actionable input.
 * Based on the \c action process the input; this typically involves
 * searching the command history or editing the current command line.
 */
static int
unix_cli_line_process_one (unix_cli_main_t * cm,
			   unix_main_t * um,
			   unix_cli_file_t * cf,
			   clib_file_t * uf,
			   u8 input, unix_cli_parse_action_t action)
{
  u8 *prev;
  u8 *save = 0;
  u8 **possible_commands;
  int j, delta;

  switch (action)
    {
    case UNIX_CLI_PARSE_ACTION_NOACTION:
      break;

    case UNIX_CLI_PARSE_ACTION_REVSEARCH:
    case UNIX_CLI_PARSE_ACTION_FWDSEARCH:
      if (!cf->has_history || !cf->history_limit)
	break;
      if (cf->search_mode == 0)
	{
	  /* Erase the current command (if any) */
	  for (; cf->cursor > 0; cf->cursor--)
	    {
	      unix_vlib_cli_output_cursor_left (cf, uf);
	      unix_vlib_cli_output_cooked (cf, uf, (u8 *) " ", 1);
	      unix_vlib_cli_output_cursor_left (cf, uf);
	    }

	  vec_reset_length (cf->search_key);
	  vec_reset_length (cf->current_command);

	  if (action == UNIX_CLI_PARSE_ACTION_REVSEARCH)
	    cf->search_mode = -1;
	  else
	    cf->search_mode = 1;
	}
      else
	{
	  if (action == UNIX_CLI_PARSE_ACTION_REVSEARCH)
	    cf->search_mode = -1;
	  else
	    cf->search_mode = 1;

	  cf->excursion += cf->search_mode;
	  goto search_again;
	}
      break;

    case UNIX_CLI_PARSE_ACTION_ERASELINELEFT:
      /* Erase the command from the cursor to the start */

      j = cf->cursor;
      /* Shimmy backwards to the new end of line position */
      delta = vec_len (cf->current_command) - cf->cursor;
      for (; cf->cursor > delta; cf->cursor--)
	unix_vlib_cli_output_cursor_left (cf, uf);
      /* Zap from here to the end of what is currently displayed */
      for (; cf->cursor < vec_len (cf->current_command); cf->cursor++)
	unix_vlib_cli_output_cooked (cf, uf, (u8 *) " ", 1);
      /* Get back to the start of the line */
      for (; cf->cursor > 0; cf->cursor--)
	unix_vlib_cli_output_cursor_left (cf, uf);

      /* Delete the desired text from the command */
      memmove (cf->current_command, cf->current_command + j, delta);
      _vec_len (cf->current_command) = delta;

      /* Print the new contents */
      unix_vlib_cli_output_cooked (cf, uf, cf->current_command, delta);
      cf->cursor = delta;	/* for backspace tracking */

      /* Shimmy back to the start */
      for (; cf->cursor > 0; cf->cursor--)
	unix_vlib_cli_output_cursor_left (cf, uf);

      cf->search_mode = 0;
      break;

    case UNIX_CLI_PARSE_ACTION_ERASELINERIGHT:
      /* Erase the command from the cursor to the end */

      j = cf->cursor;
      /* Zap from cursor to end of what is currently displayed */
      for (; cf->cursor < (vec_len (cf->current_command)); cf->cursor++)
	unix_vlib_cli_output_cooked (cf, uf, (u8 *) " ", 1);
      /* Get back to where we were */
      for (; cf->cursor > j; cf->cursor--)
	unix_vlib_cli_output_cursor_left (cf, uf);

      /* Truncate the line at the cursor */
      _vec_len (cf->current_command) = cf->cursor;

      cf->search_mode = 0;
      break;

    case UNIX_CLI_PARSE_ACTION_LEFT:
      if (cf->cursor > 0)
	{
	  unix_vlib_cli_output_cursor_left (cf, uf);
	  cf->cursor--;
	}

      cf->search_mode = 0;
      break;

    case UNIX_CLI_PARSE_ACTION_RIGHT:
      if (cf->cursor < vec_len (cf->current_command))
	{
	  /* have to emit the character under the cursor */
	  unix_vlib_cli_output_cooked (cf, uf,
				       cf->current_command + cf->cursor, 1);
	  cf->cursor++;
	}

      cf->search_mode = 0;
      break;

    case UNIX_CLI_PARSE_ACTION_UP:
    case UNIX_CLI_PARSE_ACTION_DOWN:
      if (!cf->has_history || !cf->history_limit)
	break;
      cf->search_mode = 0;
      /* Erase the command */
      for (; cf->cursor < vec_len (cf->current_command); cf->cursor++)
	unix_vlib_cli_output_cooked (cf, uf, (u8 *) " ", 1);
      for (; cf->cursor > 0; cf->cursor--)
	{
	  unix_vlib_cli_output_cursor_left (cf, uf);
	  unix_vlib_cli_output_cooked (cf, uf, (u8 *) " ", 1);
	  unix_vlib_cli_output_cursor_left (cf, uf);
	}
      vec_reset_length (cf->current_command);
      if (vec_len (cf->command_history))
	{
	  if (action == UNIX_CLI_PARSE_ACTION_UP)
	    delta = -1;
	  else
	    delta = 1;

	  cf->excursion += delta;

	  if (cf->excursion == vec_len (cf->command_history))
	    {
	      /* down-arrowed to last entry - want a blank line */
	      _vec_len (cf->current_command) = 0;
	    }
	  else if (cf->excursion < 0)
	    {
	      /* up-arrowed over the start to the end, want a blank line */
	      cf->excursion = vec_len (cf->command_history);
	      _vec_len (cf->current_command) = 0;
	    }
	  else
	    {
	      if (cf->excursion > (i32) vec_len (cf->command_history) - 1)
		/* down-arrowed past end - wrap to start */
		cf->excursion = 0;

	      /* Print the command at the current position */
	      prev = cf->command_history[cf->excursion];
	      vec_validate (cf->current_command, vec_len (prev) - 1);

	      clib_memcpy (cf->current_command, prev, vec_len (prev));
	      _vec_len (cf->current_command) = vec_len (prev);
	      unix_vlib_cli_output_cooked (cf, uf, cf->current_command,
					   vec_len (cf->current_command));
	    }
	}
      cf->cursor = vec_len (cf->current_command);
      break;

    case UNIX_CLI_PARSE_ACTION_HOME:
      if (vec_len (cf->current_command) && cf->cursor > 0)
	{
	  for (; cf->cursor > 0; cf->cursor--)
	    unix_vlib_cli_output_cursor_left (cf, uf);
	}

      cf->search_mode = 0;
      break;

    case UNIX_CLI_PARSE_ACTION_END:
      if (vec_len (cf->current_command) &&
	  cf->cursor < vec_len (cf->current_command))
	{
	  unix_vlib_cli_output_cooked (cf, uf,
				       cf->current_command + cf->cursor,
				       vec_len (cf->current_command) -
				       cf->cursor);
	  cf->cursor = vec_len (cf->current_command);
	}

      cf->search_mode = 0;
      break;

    case UNIX_CLI_PARSE_ACTION_WORDLEFT:
      if (vec_len (cf->current_command) && cf->cursor > 0)
	{
	  unix_vlib_cli_output_cursor_left (cf, uf);
	  cf->cursor--;

	  while (cf->cursor && isspace (cf->current_command[cf->cursor]))
	    {
	      unix_vlib_cli_output_cursor_left (cf, uf);
	      cf->cursor--;
	    }
	  while (cf->cursor && !isspace (cf->current_command[cf->cursor]))
	    {
	      if (isspace (cf->current_command[cf->cursor - 1]))
		break;
	      unix_vlib_cli_output_cursor_left (cf, uf);
	      cf->cursor--;
	    }

	}

      cf->search_mode = 0;
      break;

    case UNIX_CLI_PARSE_ACTION_WORDRIGHT:
      if (vec_len (cf->current_command) &&
	  cf->cursor < vec_len (cf->current_command))
	{
	  int e = vec_len (cf->current_command);
	  j = cf->cursor;
	  while (j < e && !isspace (cf->current_command[j]))
	    j++;
	  while (j < e && isspace (cf->current_command[j]))
	    j++;
	  unix_vlib_cli_output_cooked (cf, uf,
				       cf->current_command + cf->cursor,
				       j - cf->cursor);
	  cf->cursor = j;
	}

      cf->search_mode = 0;
      break;


    case UNIX_CLI_PARSE_ACTION_ERASE:
      if (vec_len (cf->current_command))
	{
	  if (cf->cursor == vec_len (cf->current_command))
	    {
	      unix_vlib_cli_output_cursor_left (cf, uf);
	      cf->cursor--;
	      unix_vlib_cli_output_cooked (cf, uf, (u8 *) " ", 1);
	      cf->cursor++;
	      unix_vlib_cli_output_cursor_left (cf, uf);
	      cf->cursor--;
	      _vec_len (cf->current_command)--;
	    }
	  else if (cf->cursor > 0)
	    {
	      /* shift everything at & to the right of the cursor left by 1 */
	      j = vec_len (cf->current_command) - cf->cursor;
	      memmove (cf->current_command + cf->cursor - 1,
		       cf->current_command + cf->cursor, j);
	      _vec_len (cf->current_command)--;

	      /* redraw the rest of the line */
	      unix_vlib_cli_output_cursor_left (cf, uf);
	      cf->cursor--;
	      unix_vlib_cli_output_cooked (cf, uf,
					   cf->current_command + cf->cursor,
					   j);
	      cf->cursor += j;
	      /* erase last char */
	      unix_vlib_cli_output_cooked (cf, uf, (u8 *) " ", 1);
	      cf->cursor++;

	      /* and shift the terminal cursor back where it should be */
	      j += 2;		/* account for old string length and offset position */
	      while (--j)
		{
		  unix_vlib_cli_output_cursor_left (cf, uf);
		  cf->cursor--;
		}
	    }
	}
      cf->search_mode = 0;
      cf->excursion = 0;
      vec_reset_length (cf->search_key);
      break;

    case UNIX_CLI_PARSE_ACTION_ERASERIGHT:
      if (vec_len (cf->current_command))
	{
	  if (cf->cursor < vec_len (cf->current_command))
	    {
	      /* shift everything to the right of the cursor left by 1 */
	      j = vec_len (cf->current_command) - cf->cursor - 1;
	      memmove (cf->current_command + cf->cursor,
		       cf->current_command + cf->cursor + 1, j);
	      _vec_len (cf->current_command)--;
	      /* redraw the rest of the line */
	      unix_vlib_cli_output_cooked (cf, uf,
					   cf->current_command + cf->cursor,
					   j);
	      cf->cursor += j;
	      unix_vlib_cli_output_cooked (cf, uf, (u8 *) " ", 1);
	      cf->cursor++;
	      unix_vlib_cli_output_cursor_left (cf, uf);
	      cf->cursor--;
	      /* and shift the terminal cursor back where it should be */
	      if (j)
		{
		  unix_vlib_cli_output_cursor_left (cf, uf);
		  cf->cursor--;
		  while (--j)
		    {
		      unix_vlib_cli_output_cursor_left (cf, uf);
		      cf->cursor--;
		    }
		}
	    }
	}
      else if (input == 'D' - '@')
	{
	  /* ^D with no command entered = quit */
	  unix_vlib_cli_output_cooked (cf, uf, (u8 *) "quit\n", 5);
	  vlib_process_signal_event (um->vlib_main,
				     vlib_current_process (um->vlib_main),
				     UNIX_CLI_PROCESS_EVENT_QUIT,
				     cf - cm->cli_file_pool);
	}
      cf->search_mode = 0;
      cf->excursion = 0;
      vec_reset_length (cf->search_key);
      break;

    case UNIX_CLI_PARSE_ACTION_CLEAR:
      /* If we're in ANSI mode, clear the screen.
       * Then redraw the prompt and any existing command input, then put
       * the cursor back where it was in that line.
       */
      if (cf->ansi_capable)
	unix_vlib_cli_output_cooked (cf, uf,
				     (u8 *) ANSI_CLEAR,
				     sizeof (ANSI_CLEAR) - 1);
      else
	unix_vlib_cli_output_cooked (cf, uf, (u8 *) "\n", 1);

      unix_vlib_cli_output_raw (cf, uf,
				cm->cli_prompt, vec_len (cm->cli_prompt));
      unix_vlib_cli_output_cooked (cf, uf,
				   cf->current_command,
				   vec_len (cf->current_command));
      j = cf->cursor;
      cf->cursor = vec_len (cf->current_command);
      for (; cf->cursor > j; cf->cursor--)
	unix_vlib_cli_output_cursor_left (cf, uf);

      break;

    case UNIX_CLI_PARSE_ACTION_TAB:
      if (cf->cursor < vec_len (cf->current_command))
	{
	  /* if we are in the middle of a line, complete only if
	   * the cursor points to whitespace */
	  if (isspace (cf->current_command[cf->cursor]))
	    {
	      /* save and clear any input that is after the cursor */
	      vec_resize (save, vec_len (cf->current_command) - cf->cursor);
	      clib_memcpy (save, cf->current_command + cf->cursor,
			   vec_len (cf->current_command) - cf->cursor);
	      _vec_len (cf->current_command) = cf->cursor;
	    }
	  else
	    {
	      unix_vlib_cli_output_raw (cf, uf, (u8 *) "\a", 1);
	      break;
	    }
	}
      possible_commands =
	vlib_cli_get_possible_completions (cf->current_command);
      if (vec_len (possible_commands) == 1)
	{
	  u8 *completed = possible_commands[0];
	  j = cf->cursor;

	  /* find the last word of current_command */
	  while (j >= 1 && !isspace (cf->current_command[j - 1]))
	    {
	      unix_vlib_cli_output_cursor_left (cf, uf);
	      cf->cursor--;
	      j--;
	    }
	  _vec_len (cf->current_command) = j;

	  /* replace it with the newly expanded command */
	  vec_append (cf->current_command, completed);

	  /* echo to the terminal */
	  unix_vlib_cli_output_cooked (cf, uf, completed,
				       vec_len (completed));

	  /* add one trailing space if needed */
	  if (vec_len (save) == 0)
	    {
	      vec_add1 (cf->current_command, ' ');
	      unix_vlib_cli_output_cooked (cf, uf, (u8 *) " ", 1);
	    }

	  cf->cursor = vec_len (cf->current_command);

	}
      else if (vec_len (possible_commands) >= 2)
	{
	  u8 **possible_command;
	  uword max_command_len = 0, min_command_len = ~0;
	  u32 i;

	  vec_foreach (possible_command, possible_commands)
	  {
	    if (vec_len (*possible_command) > max_command_len)
	      max_command_len = vec_len (*possible_command);
	    if (vec_len (*possible_command) < min_command_len)
	      min_command_len = vec_len (*possible_command);
	  }

	  unix_vlib_cli_output_cooked (cf, uf, (u8 *) "\n", 1);

	  i = 0;
	  vec_foreach (possible_command, possible_commands)
	  {
	    if (i + max_command_len >= cf->width)
	      {
		unix_vlib_cli_output_cooked (cf, uf, (u8 *) "\n", 1);
		i = 0;
	      }
	    unix_vlib_cli_output_cooked (cf, uf, *possible_command,
					 vec_len (*possible_command));
	    for (j = vec_len (*possible_command); j < max_command_len + 2;
		 j++)
	      {
		unix_vlib_cli_output_cooked (cf, uf, (u8 *) " ", 1);
	      }
	    i += max_command_len + 2;
	  }

	  unix_vlib_cli_output_cooked (cf, uf, (u8 *) "\n", 1);

	  /* rewrite prompt */
	  unix_cli_cli_prompt (cf, uf);
	  unix_vlib_cli_output_cooked (cf, uf, cf->current_command,
				       vec_len (cf->current_command));

	  /* count length of last word */
	  j = cf->cursor;
	  i = 0;
	  while (j >= 1 && !isspace (cf->current_command[j - 1]))
	    {
	      j--;
	      i++;
	    }

	  /* determine smallest common command */
	  for (; i < min_command_len; i++)
	    {
	      u8 common = '\0';
	      int stop = 0;

	      vec_foreach (possible_command, possible_commands)
	      {
		if (common == '\0')
		  {
		    common = (*possible_command)[i];
		  }
		else if (common != (*possible_command)[i])
		  {
		    stop = 1;
		    break;
		  }
	      }

	      if (!stop)
		{
		  vec_add1 (cf->current_command, common);
		  cf->cursor++;
		  unix_vlib_cli_output_cooked (cf, uf, (u8 *) & common, 1);
		}
	      else
		{
		  break;
		}
	    }
	}
      else
	{
	  unix_vlib_cli_output_raw (cf, uf, (u8 *) "\a", 1);
	}

      if (vec_len (save) > 0)
	{
	  /* restore remaining input if tab was hit in the middle of a line */
	  unix_vlib_cli_output_cooked (cf, uf, save, vec_len (save));
	  cf->cursor += vec_len (save);
	  for (j = 0; j < vec_len (save); j++, cf->cursor--)
	    unix_vlib_cli_output_cursor_left (cf, uf);
	  vec_append (cf->current_command, save);
	  vec_free (save);
	}
      vec_free (possible_commands);

      break;
    case UNIX_CLI_PARSE_ACTION_YANK:
      /* TODO */
      break;


    case UNIX_CLI_PARSE_ACTION_PAGER_QUIT:
    pager_quit:
      unix_cli_pager_prompt_erase (cf, uf);
      unix_cli_pager_reset (cf);
      unix_cli_cli_prompt (cf, uf);
      break;

    case UNIX_CLI_PARSE_ACTION_PAGER_NEXT:
    case UNIX_CLI_PARSE_ACTION_PAGER_PGDN:
      /* show next page of the buffer */
      if (cf->height + cf->pager_start <= vec_len (cf->pager_index))
	{
	  u8 *line = NULL;
	  unix_cli_pager_index_t *pi = NULL;

	  int m = cf->pager_start + (cf->height - 1);
	  unix_cli_pager_prompt_erase (cf, uf);
	  for (j = m;
	       j < vec_len (cf->pager_index) && cf->pager_start < m;
	       j++, cf->pager_start++)
	    {
	      pi = &cf->pager_index[j];
	      line = cf->pager_vector[pi->line] + pi->offset;
	      unix_vlib_cli_output_cooked (cf, uf, line, pi->length);
	    }
	  /* if the last line didn't end in newline, add a newline */
	  if (pi && line[pi->length - 1] != '\n')
	    unix_vlib_cli_output_cooked (cf, uf, (u8 *) "\n", 1);
	  unix_cli_pager_prompt (cf, uf);
	}
      else
	{
	  if (action == UNIX_CLI_PARSE_ACTION_PAGER_NEXT)
	    /* no more in buffer, exit, but only if it was <space> */
	    goto pager_quit;
	}
      break;

    case UNIX_CLI_PARSE_ACTION_PAGER_DN:
    case UNIX_CLI_PARSE_ACTION_PAGER_CRLF:
      /* display the next line of the buffer */
      if (cf->height + cf->pager_start <= vec_len (cf->pager_index))
	{
	  u8 *line;
	  unix_cli_pager_index_t *pi;

	  unix_cli_pager_prompt_erase (cf, uf);
	  pi = &cf->pager_index[cf->pager_start + (cf->height - 1)];
	  line = cf->pager_vector[pi->line] + pi->offset;
	  unix_vlib_cli_output_cooked (cf, uf, line, pi->length);
	  cf->pager_start++;
	  /* if the last line didn't end in newline, add a newline */
	  if (line[pi->length - 1] != '\n')
	    unix_vlib_cli_output_cooked (cf, uf, (u8 *) "\n", 1);
	  unix_cli_pager_prompt (cf, uf);
	}
      else
	{
	  if (action == UNIX_CLI_PARSE_ACTION_PAGER_CRLF)
	    /* no more in buffer, exit, but only if it was <enter> */
	    goto pager_quit;
	}

      break;

    case UNIX_CLI_PARSE_ACTION_PAGER_UP:
      /* scroll the page back one line */
      if (cf->pager_start > 0)
	{
	  u8 *line = NULL;
	  unix_cli_pager_index_t *pi = NULL;

	  cf->pager_start--;
	  if (cf->ansi_capable)
	    {
	      pi = &cf->pager_index[cf->pager_start];
	      line = cf->pager_vector[pi->line] + pi->offset;
	      unix_cli_pager_prompt_erase (cf, uf);
	      unix_vlib_cli_output_cooked (cf, uf, (u8 *) ANSI_SCROLLDN,
					   sizeof (ANSI_SCROLLDN) - 1);
	      unix_vlib_cli_output_cooked (cf, uf, (u8 *) ANSI_SAVECURSOR,
					   sizeof (ANSI_SAVECURSOR) - 1);
	      unix_cli_ansi_cursor (cf, uf, 1, 1);
	      unix_vlib_cli_output_cooked (cf, uf, (u8 *) ANSI_CLEARLINE,
					   sizeof (ANSI_CLEARLINE) - 1);
	      unix_vlib_cli_output_cooked (cf, uf, line, pi->length);
	      unix_vlib_cli_output_cooked (cf, uf, (u8 *) ANSI_RESTCURSOR,
					   sizeof (ANSI_RESTCURSOR) - 1);
	      unix_cli_pager_prompt_erase (cf, uf);
	      unix_cli_pager_prompt (cf, uf);
	    }
	  else
	    {
	      int m = cf->pager_start + (cf->height - 1);
	      unix_cli_pager_prompt_erase (cf, uf);
	      for (j = cf->pager_start;
		   j < vec_len (cf->pager_index) && j < m; j++)
		{
		  pi = &cf->pager_index[j];
		  line = cf->pager_vector[pi->line] + pi->offset;
		  unix_vlib_cli_output_cooked (cf, uf, line, pi->length);
		}
	      /* if the last line didn't end in newline, add a newline */
	      if (pi && line[pi->length - 1] != '\n')
		unix_vlib_cli_output_cooked (cf, uf, (u8 *) "\n", 1);
	      unix_cli_pager_prompt (cf, uf);
	    }
	}
      break;

    case UNIX_CLI_PARSE_ACTION_PAGER_TOP:
      /* back to the first page of the buffer */
      if (cf->pager_start > 0)
	{
	  u8 *line = NULL;
	  unix_cli_pager_index_t *pi = NULL;

	  cf->pager_start = 0;
	  int m = cf->pager_start + (cf->height - 1);
	  unix_cli_pager_prompt_erase (cf, uf);
	  for (j = cf->pager_start; j < vec_len (cf->pager_index) && j < m;
	       j++)
	    {
	      pi = &cf->pager_index[j];
	      line = cf->pager_vector[pi->line] + pi->offset;
	      unix_vlib_cli_output_cooked (cf, uf, line, pi->length);
	    }
	  /* if the last line didn't end in newline, add a newline */
	  if (pi && line[pi->length - 1] != '\n')
	    unix_vlib_cli_output_cooked (cf, uf, (u8 *) "\n", 1);
	  unix_cli_pager_prompt (cf, uf);
	}
      break;

    case UNIX_CLI_PARSE_ACTION_PAGER_BOTTOM:
      /* skip to the last page of the buffer */
      if (cf->pager_start < vec_len (cf->pager_index) - (cf->height - 1))
	{
	  u8 *line = NULL;
	  unix_cli_pager_index_t *pi = NULL;

	  cf->pager_start = vec_len (cf->pager_index) - (cf->height - 1);
	  unix_cli_pager_prompt_erase (cf, uf);
	  unix_cli_pager_message (cf, uf, "skipping", "\n");
	  for (j = cf->pager_start; j < vec_len (cf->pager_index); j++)
	    {
	      pi = &cf->pager_index[j];
	      line = cf->pager_vector[pi->line] + pi->offset;
	      unix_vlib_cli_output_cooked (cf, uf, line, pi->length);
	    }
	  /* if the last line didn't end in newline, add a newline */
	  if (pi && line[pi->length - 1] != '\n')
	    unix_vlib_cli_output_cooked (cf, uf, (u8 *) "\n", 1);
	  unix_cli_pager_prompt (cf, uf);
	}
      break;

    case UNIX_CLI_PARSE_ACTION_PAGER_PGUP:
      /* wander back one page in the buffer */
      if (cf->pager_start > 0)
	{
	  u8 *line = NULL;
	  unix_cli_pager_index_t *pi = NULL;
	  int m;

	  if (cf->pager_start >= cf->height)
	    cf->pager_start -= cf->height - 1;
	  else
	    cf->pager_start = 0;
	  m = cf->pager_start + cf->height - 1;
	  unix_cli_pager_prompt_erase (cf, uf);
	  for (j = cf->pager_start; j < vec_len (cf->pager_index) && j < m;
	       j++)
	    {
	      pi = &cf->pager_index[j];
	      line = cf->pager_vector[pi->line] + pi->offset;
	      unix_vlib_cli_output_cooked (cf, uf, line, pi->length);
	    }
	  /* if the last line didn't end in newline, add a newline */
	  if (pi && line[pi->length - 1] != '\n')
	    unix_vlib_cli_output_cooked (cf, uf, (u8 *) "\n", 1);
	  unix_cli_pager_prompt (cf, uf);
	}
      break;

    case UNIX_CLI_PARSE_ACTION_PAGER_REDRAW:
      /* Redraw the current pager screen */
      unix_cli_pager_redraw (cf, uf);
      break;

    case UNIX_CLI_PARSE_ACTION_PAGER_SEARCH:
      /* search forwards in the buffer */
      break;


    case UNIX_CLI_PARSE_ACTION_CRLF:
    crlf:
      unix_vlib_cli_output_cooked (cf, uf, (u8 *) "\n", 1);

      if (cf->has_history && cf->history_limit)
	{
	  if (cf->command_history
	      && vec_len (cf->command_history) >= cf->history_limit)
	    {
	      vec_free (cf->command_history[0]);
	      vec_delete (cf->command_history, 1, 0);
	    }
	  /* Don't add blank lines to the cmd history */
	  if (vec_len (cf->current_command))
	    {
	      /* Don't duplicate the previous command */
	      j = vec_len (cf->command_history);
	      if (j == 0 ||
		  (vec_len (cf->current_command) !=
		   vec_len (cf->command_history[j - 1])
		   || memcmp (cf->current_command, cf->command_history[j - 1],
			      vec_len (cf->current_command)) != 0))
		{
		  /* copy the command to the history */
		  u8 *c = 0;
		  vec_append (c, cf->current_command);
		  vec_add1 (cf->command_history, c);
		  cf->command_number++;
		}
	    }
	  cf->excursion = vec_len (cf->command_history);
	}

      cf->search_mode = 0;
      vec_reset_length (cf->search_key);
      cf->cursor = 0;

      return 0;

    case UNIX_CLI_PARSE_ACTION_PARTIALMATCH:
    case UNIX_CLI_PARSE_ACTION_NOMATCH:
      if (vec_len (cf->pager_index))
	{
	  /* no-op for now */
	}
      else if (cf->has_history && cf->search_mode != 0 && isprint (input))
	{
	  int k, limit, offset;
	  u8 *item;

	  vec_add1 (cf->search_key, input);

	search_again:
	  for (j = 0; j < vec_len (cf->command_history); j++)
	    {
	      if (cf->excursion > (i32) vec_len (cf->command_history) - 1)
		cf->excursion = 0;
	      else if (cf->excursion < 0)
		cf->excursion = vec_len (cf->command_history) - 1;

	      item = cf->command_history[cf->excursion];

	      limit = (vec_len (cf->search_key) > vec_len (item)) ?
		vec_len (item) : vec_len (cf->search_key);

	      for (offset = 0; offset <= vec_len (item) - limit; offset++)
		{
		  for (k = 0; k < limit; k++)
		    {
		      if (item[k + offset] != cf->search_key[k])
			goto next_offset;
		    }
		  goto found_at_offset;

		next_offset:
		  ;
		}
	      goto next;

	    found_at_offset:
	      for (; cf->cursor > 0; cf->cursor--)
		{
		  unix_vlib_cli_output_cursor_left (cf, uf);
		  unix_vlib_cli_output_cooked (cf, uf, (u8 *) " ", 1);
		  unix_vlib_cli_output_cursor_left (cf, uf);
		}

	      vec_validate (cf->current_command, vec_len (item) - 1);
	      clib_memcpy (cf->current_command, item, vec_len (item));
	      _vec_len (cf->current_command) = vec_len (item);

	      unix_vlib_cli_output_cooked (cf, uf, cf->current_command,
					   vec_len (cf->current_command));
	      cf->cursor = vec_len (cf->current_command);
	      goto found;

	    next:
	      cf->excursion += cf->search_mode;
	    }

	  unix_vlib_cli_output_cooked (cf, uf, (u8 *) "\nNo match...", 12);
	  vec_reset_length (cf->search_key);
	  vec_reset_length (cf->current_command);
	  cf->search_mode = 0;
	  cf->cursor = 0;
	  goto crlf;
	}
      else if (isprint (input))	/* skip any errant control codes */
	{
	  if (cf->cursor == vec_len (cf->current_command))
	    {
	      /* Append to end */
	      vec_add1 (cf->current_command, input);
	      cf->cursor++;

	      /* Echo the character back to the client */
	      unix_vlib_cli_output_cooked (cf, uf, &input, 1);
	    }
	  else
	    {
	      /* Insert at cursor: resize +1 byte, move everything over */
	      j = vec_len (cf->current_command) - cf->cursor;
	      vec_add1 (cf->current_command, (u8) 'A');
	      memmove (cf->current_command + cf->cursor + 1,
		       cf->current_command + cf->cursor, j);
	      cf->current_command[cf->cursor] = input;
	      /* Redraw the line */
	      j++;
	      unix_vlib_cli_output_cooked (cf, uf,
					   cf->current_command + cf->cursor,
					   j);
	      cf->cursor += j;
	      j--;
	      /* Put terminal cursor back */
	      for (; j > 0; j--, cf->cursor--)
		unix_vlib_cli_output_cursor_left (cf, uf);
	    }
	}
      else
	{
	  /* no-op - not printable or otherwise not actionable */
	}

    found:

      break;

    case UNIX_CLI_PARSE_ACTION_TELNETIAC:
      break;
    }
  return 1;
}

/** @brief Process input bytes on a stream to provide line editing and
 * command history in the CLI. */
static int
unix_cli_line_edit (unix_cli_main_t * cm, unix_main_t * um,
		    clib_file_main_t * fm, unix_cli_file_t * cf)
{
  clib_file_t *uf = pool_elt_at_index (fm->file_pool, cf->clib_file_index);
  int i;

  for (i = 0; i < vec_len (cf->input_vector); i++)
    {
      unix_cli_parse_action_t action;
      i32 matched = 0;
      unix_cli_parse_actions_t *a;

      /* If we're in the pager mode, search the pager actions */
      a =
	vec_len (cf->pager_index) ? unix_cli_parse_pager :
	unix_cli_parse_strings;

      /* See if the input buffer is some sort of control code */
      action = unix_cli_match_action (a, &cf->input_vector[i],
				      vec_len (cf->input_vector) - i,
				      &matched);

      switch (action)
	{
	case UNIX_CLI_PARSE_ACTION_PARTIALMATCH:
	  if (i)
	    {
	      /* There was a partial match which means we need more bytes
	       * than the input buffer currently has.
	       * Since the bytes before here have been processed, shift
	       * the remaining contents to the start of the input buffer.
	       */
	      vec_delete (cf->input_vector, i, 0);
	    }
	  return 1;		/* wait for more */

	case UNIX_CLI_PARSE_ACTION_TELNETIAC:
	  /* process telnet options */
	  matched = unix_cli_process_telnet (um, cf, uf,
					     cf->input_vector + i,
					     vec_len (cf->input_vector) - i);
	  if (matched < 0)
	    {
	      /* There was a partial match which means we need more bytes
	       * than the input buffer currently has.
	       */
	      if (i)
		{
		  /*
		   * Since the bytes before here have been processed, shift
		   * the remaining contents to the start of the input buffer.
		   */
		  vec_delete (cf->input_vector, i, 0);
		}
	      return 1;		/* wait for more */
	    }
	  break;

	default:
	  /* If telnet option processing switched us to line mode, get us
	   * out of here!
	   */
	  if (cf->line_mode)
	    {
	      vec_delete (cf->input_vector, i, 0);
	      cf->current_command = cf->input_vector;
	      return 0;
	    }

	  /* process the action */
	  if (!unix_cli_line_process_one (cm, um, cf, uf,
					  cf->input_vector[i], action))
	    {
	      /* CRLF found. Consume the bytes from the input_vector */
	      vec_delete (cf->input_vector, i + matched, 0);
	      /* And tell our caller to execute cf->input_command */
	      return 0;
	    }
	}

      i += matched;
    }

  vec_reset_length (cf->input_vector);
  return 1;
}

/** @brief Process input to a CLI session. */
static void
unix_cli_process_input (unix_cli_main_t * cm, uword cli_file_index)
{
  unix_main_t *um = &unix_main;
  clib_file_main_t *fm = &file_main;
  clib_file_t *uf;
  unix_cli_file_t *cf = pool_elt_at_index (cm->cli_file_pool, cli_file_index);
  unformat_input_t input;
  int vlib_parse_eval (u8 *);

  cm->current_input_file_index = cli_file_index;

more:
  /* Try vlibplex first.  Someday... */
  if (0 && vlib_parse_eval (cf->input_vector) == 0)
    goto done;


  if (cf->line_mode)
    {
      /* just treat whatever we got as a complete line of input */
      cf->current_command = cf->input_vector;
    }
  else
    {
      /* Line edit, echo, etc. */
      if (unix_cli_line_edit (cm, um, fm, cf))
	/* want more input */
	return;
    }

  if (um->log_fd)
    {
      static u8 *lv;
      vec_reset_length (lv);
      lv = format (lv, "%U[%d]: %v",
		   format_timeval, 0 /* current bat-time */ ,
		   0 /* current bat-format */ ,
		   cli_file_index, cf->current_command);
      int rv __attribute__ ((unused)) = write (um->log_fd, lv, vec_len (lv));
    }

  /* Build an unformat structure around our command */
  unformat_init_vector (&input, cf->current_command);

  /* Remove leading white space from input. */
  (void) unformat (&input, "");

  cf->pager_start = 0;		/* start a new pager session */

  if (unformat_check_input (&input) != UNFORMAT_END_OF_INPUT)
    vlib_cli_input (um->vlib_main, &input, unix_vlib_cli_output,
		    cli_file_index);

  /* Zero buffer since otherwise unformat_free will call vec_free on it. */
  input.buffer = 0;

  unformat_free (&input);

  /* Re-fetch pointer since pool may have moved. */
  cf = pool_elt_at_index (cm->cli_file_pool, cli_file_index);
  uf = pool_elt_at_index (fm->file_pool, cf->clib_file_index);

done:
  /* reset vector; we'll re-use it later  */
  if (cf->line_mode)
    {
      vec_reset_length (cf->input_vector);
      cf->current_command = 0;
    }
  else
    {
      vec_reset_length (cf->current_command);
    }

  if (cf->no_pager == 2)
    {
      /* Pager was programmatically disabled */
      unix_cli_pager_message (cf, uf, "pager buffer overflowed", "\n");
      cf->no_pager = um->cli_no_pager;
    }

  if (vec_len (cf->pager_index) == 0
      || vec_len (cf->pager_index) < cf->height)
    {
      /* There was no need for the pager */
      unix_cli_pager_reset (cf);

      /* Prompt. */
      unix_cli_cli_prompt (cf, uf);
    }
  else
    {
      /* Display the pager prompt */
      unix_cli_pager_prompt (cf, uf);
    }

  /* Any residual data in the input vector? */
  if (vec_len (cf->input_vector))
    goto more;

  /* For non-interactive sessions send a NUL byte.
   * Specifically this is because vppctl needs to see some traffic in
   * order to move on to closing the session. Commands with no output
   * would thus cause vppctl to hang indefinitely in non-interactive mode
   * since there is also no prompt sent after the command completes.
   */
  if (!cf->is_interactive)
    unix_vlib_cli_output_raw (cf, uf, (u8 *) "\0", 1);
}

/** Destroy a CLI session.
 * @note If we destroy the @c stdin session this additionally signals
 *       the shutdown of VPP.
 */
static void
unix_cli_kill (unix_cli_main_t * cm, uword cli_file_index)
{
  unix_main_t *um = &unix_main;
  clib_file_main_t *fm = &file_main;
  unix_cli_file_t *cf;
  clib_file_t *uf;
  int i;

  /* Validate cli_file_index */
  if (pool_is_free_index (cm->cli_file_pool, cli_file_index))
    return;

  cf = pool_elt_at_index (cm->cli_file_pool, cli_file_index);
  uf = pool_elt_at_index (fm->file_pool, cf->clib_file_index);

  /* Quit/EOF on stdin means quit program. */
  if (uf->file_descriptor == STDIN_FILENO)
    clib_longjmp (&um->vlib_main->main_loop_exit, VLIB_MAIN_LOOP_EXIT_CLI);

  vec_free (cf->current_command);
  vec_free (cf->search_key);

  for (i = 0; i < vec_len (cf->command_history); i++)
    vec_free (cf->command_history[i]);

  vec_free (cf->command_history);

  clib_file_del (fm, uf);

  unix_cli_file_free (cf);
  pool_put (cm->cli_file_pool, cf);
}

/** Handle system events. */
static uword
unix_cli_process (vlib_main_t * vm,
		  vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  unix_cli_main_t *cm = &unix_cli_main;
  uword i, *data = 0;

  while (1)
    {
      unix_cli_process_event_type_t event_type;
      vlib_process_wait_for_event (vm);
      event_type = vlib_process_get_events (vm, &data);

      switch (event_type)
	{
	case UNIX_CLI_PROCESS_EVENT_READ_READY:
	  for (i = 0; i < vec_len (data); i++)
	    unix_cli_process_input (cm, data[i]);
	  break;

	case UNIX_CLI_PROCESS_EVENT_QUIT:
	  /* Kill this process. */
	  for (i = 0; i < vec_len (data); i++)
	    unix_cli_kill (cm, data[i]);
	  goto done;
	}

      if (data)
	_vec_len (data) = 0;
    }

done:
  vec_free (data);

  vlib_node_set_state (vm, rt->node_index, VLIB_NODE_STATE_DISABLED);

  /* Add node index so we can re-use this process later. */
  vec_add1 (cm->unused_cli_process_node_indices, rt->node_index);

  return 0;
}

/** Called when a CLI session file descriptor can be written to without
 * blocking. */
static clib_error_t *
unix_cli_write_ready (clib_file_t * uf)
{
  unix_cli_main_t *cm = &unix_cli_main;
  unix_cli_file_t *cf;
  int n;

  cf = pool_elt_at_index (cm->cli_file_pool, uf->private_data);

  /* Flush output vector. */
  if (cf->is_socket)
    /* If it's a socket we use MSG_NOSIGNAL to prevent SIGPIPE */
    n = send (uf->file_descriptor,
	      cf->output_vector, vec_len (cf->output_vector), MSG_NOSIGNAL);
  else
    n = write (uf->file_descriptor,
	       cf->output_vector, vec_len (cf->output_vector));

  if (n < 0 && errno != EAGAIN)
    {
      if (errno == EPIPE)
	{
	  /* connection closed on us */
	  unix_main_t *um = &unix_main;
	  cf->has_epipe = 1;
	  vlib_process_signal_event (um->vlib_main, cf->process_node_index,
				     UNIX_CLI_PROCESS_EVENT_QUIT,
				     uf->private_data);
	}
      else
	{
	  return clib_error_return_unix (0, "write");
	}
    }

  else if (n > 0)
    unix_cli_del_pending_output (uf, cf, n);

  return /* no error */ 0;
}

/** Called when a CLI session file descriptor has data to be read. */
static clib_error_t *
unix_cli_read_ready (clib_file_t * uf)
{
  unix_main_t *um = &unix_main;
  unix_cli_main_t *cm = &unix_cli_main;
  unix_cli_file_t *cf;
  uword l;
  int n, n_read, n_try;

  cf = pool_elt_at_index (cm->cli_file_pool, uf->private_data);

  n = n_try = 4096;
  while (n == n_try)
    {
      l = vec_len (cf->input_vector);
      vec_resize (cf->input_vector, l + n_try);

      n = read (uf->file_descriptor, cf->input_vector + l, n_try);

      /* Error? */
      if (n < 0 && errno != EAGAIN)
	return clib_error_return_unix (0, "read");

      n_read = n < 0 ? 0 : n;
      _vec_len (cf->input_vector) = l + n_read;
    }

  if (!(n < 0))
    vlib_process_signal_event (um->vlib_main,
			       cf->process_node_index,
			       (n_read == 0
				? UNIX_CLI_PROCESS_EVENT_QUIT
				: UNIX_CLI_PROCESS_EVENT_READ_READY),
			       /* event data */ uf->private_data);

  return /* no error */ 0;
}

/** Called when a CLI session file descriptor has an error condition. */
static clib_error_t *
unix_cli_error_detected (clib_file_t * uf)
{
  unix_main_t *um = &unix_main;
  unix_cli_main_t *cm = &unix_cli_main;
  unix_cli_file_t *cf;

  cf = pool_elt_at_index (cm->cli_file_pool, uf->private_data);
  cf->has_epipe = 1;		/* prevent writes while the close is pending */
  vlib_process_signal_event (um->vlib_main,
			     cf->process_node_index,
			     UNIX_CLI_PROCESS_EVENT_QUIT,
			     /* event data */ uf->private_data);

  return /* no error */ 0;
}

/** Store a new CLI session.
 * @param name The name of the session.
 * @param fd   The file descriptor for the session I/O.
 * @return The session ID.
 */
static u32
unix_cli_file_add (unix_cli_main_t * cm, char *name, int fd)
{
  unix_main_t *um = &unix_main;
  clib_file_main_t *fm = &file_main;
  unix_cli_file_t *cf;
  clib_file_t template = { 0 };
  vlib_main_t *vm = um->vlib_main;
  vlib_node_t *n = 0;
  u8 *file_desc = 0;

  file_desc = format (0, "%s", name);

  name = (char *) format (0, "unix-cli-%s", name);

  if (vec_len (cm->unused_cli_process_node_indices) > 0)
    {
      uword l = vec_len (cm->unused_cli_process_node_indices);
      int i;
      vlib_main_t *this_vlib_main;
      u8 *old_name = 0;

      /*
       * Nodes are bulk-copied, so node name pointers are shared.
       * Find the cli node in all graph replicas, and give all of them
       * the same new name.
       * Then, throw away the old shared name-vector.
       */
      for (i = 0; i < vec_len (vlib_mains); i++)
	{
	  this_vlib_main = vlib_mains[i];
	  if (this_vlib_main == 0)
	    continue;
	  n = vlib_get_node (this_vlib_main,
			     cm->unused_cli_process_node_indices[l - 1]);
	  old_name = n->name;
	  n->name = (u8 *) name;
	}
      vec_free (old_name);

      vlib_node_set_state (vm, n->index, VLIB_NODE_STATE_POLLING);

      _vec_len (cm->unused_cli_process_node_indices) = l - 1;
    }
  else
    {
      static vlib_node_registration_t r = {
	.function = unix_cli_process,
	.type = VLIB_NODE_TYPE_PROCESS,
	.process_log2_n_stack_bytes = 16,
      };

      r.name = name;

      vlib_worker_thread_barrier_sync (vm);

      vlib_register_node (vm, &r);
      vec_free (name);

      n = vlib_get_node (vm, r.index);
      vlib_worker_thread_node_runtime_update ();
      vlib_worker_thread_barrier_release (vm);
    }

  pool_get (cm->cli_file_pool, cf);
  memset (cf, 0, sizeof (*cf));

  template.read_function = unix_cli_read_ready;
  template.write_function = unix_cli_write_ready;
  template.error_function = unix_cli_error_detected;
  template.file_descriptor = fd;
  template.private_data = cf - cm->cli_file_pool;
  template.description = file_desc;

  cf->process_node_index = n->index;
  cf->clib_file_index = clib_file_add (fm, &template);
  cf->output_vector = 0;
  cf->input_vector = 0;

  vlib_start_process (vm, n->runtime_index);

  vlib_process_t *p = vlib_get_process_from_node (vm, n);
  p->output_function = unix_vlib_cli_output;
  p->output_function_arg = cf - cm->cli_file_pool;

  return cf - cm->cli_file_pool;
}

/** Telnet listening socket has a new connection. */
static clib_error_t *
unix_cli_listen_read_ready (clib_file_t * uf)
{
  unix_main_t *um = &unix_main;
  clib_file_main_t *fm = &file_main;
  unix_cli_main_t *cm = &unix_cli_main;
  clib_socket_t *s = &um->cli_listen_socket;
  clib_socket_t client;
  char *client_name;
  clib_error_t *error;
  unix_cli_file_t *cf;
  u32 cf_index;
  int one;

  error = clib_socket_accept (s, &client);
  if (error)
    return error;

  /* Disable Nagle, ignore any errors doing so eg on PF_LOCAL socket */
  one = 1;
  (void) setsockopt (client.fd, IPPROTO_TCP, TCP_NODELAY,
		     (void *) &one, sizeof (one));

  client_name = (char *) format (0, "%U%c", format_sockaddr, &client.peer, 0);

  cf_index = unix_cli_file_add (cm, client_name, client.fd);
  cf = pool_elt_at_index (cm->cli_file_pool, cf_index);
  cf->is_socket = 1;

  /* No longer need CLIB version of socket. */
  clib_socket_free (&client);
  vec_free (client_name);

  /* if we're supposed to run telnet session in character mode (default) */
  if (um->cli_line_mode == 0)
    {
      /*
       * Set telnet client character mode, echo on, suppress "go-ahead".
       * Technically these should be negotiated, but this works.
       */
      u8 charmode_option[] = {
	IAC, WONT, TELOPT_LINEMODE,	/* server will do char-by-char */
	IAC, DONT, TELOPT_LINEMODE,	/* client should do char-by-char */
	IAC, WILL, TELOPT_SGA,	/* server willl supress GA */
	IAC, DO, TELOPT_SGA,	/* client should supress Go Ahead */
	IAC, WILL, TELOPT_ECHO,	/* server will do echo */
	IAC, DONT, TELOPT_ECHO,	/* client should not echo */
	IAC, DO, TELOPT_TTYPE,	/* client should tell us its term type */
	IAC, SB, TELOPT_TTYPE, 1, IAC, SE,	/* now tell me ttype */
	IAC, DO, TELOPT_NAWS,	/* client should tell us its window sz */
	IAC, SB, TELOPT_NAWS, 1, IAC, SE,	/* now tell me window size */
      };

      /* Enable history on this CLI */
      cf->history_limit = um->cli_history_limit;
      cf->has_history = cf->history_limit != 0;

      /* This is an interactive session until we decide otherwise */
      cf->is_interactive = 1;

      /* Make sure this session is in line mode */
      cf->line_mode = 0;

      /* We need CRLF */
      cf->crlf_mode = 1;

      /* Setup the pager */
      cf->no_pager = um->cli_no_pager;

      /* Default terminal dimensions, should the terminal
       * fail to provide any.
       */
      cf->width = UNIX_CLI_DEFAULT_TERMINAL_WIDTH;
      cf->height = UNIX_CLI_DEFAULT_TERMINAL_HEIGHT;

      /* Send the telnet options */
      uf = pool_elt_at_index (fm->file_pool, cf->clib_file_index);
      unix_vlib_cli_output_raw (cf, uf, charmode_option,
				ARRAY_LEN (charmode_option));

      /* In case the client doesn't negotiate terminal type, use
       * a timer to kick off the initial prompt. */
      timer_call (unix_cli_file_welcome_timer, cf_index, 1);
    }

  return error;
}

/** The system terminal has informed us that the window size
 * has changed.
 */
static void
unix_cli_resize_interrupt (int signum)
{
  clib_file_main_t *fm = &file_main;
  unix_cli_main_t *cm = &unix_cli_main;
  unix_cli_file_t *cf = pool_elt_at_index (cm->cli_file_pool,
					   cm->stdin_cli_file_index);
  clib_file_t *uf = pool_elt_at_index (fm->file_pool, cf->clib_file_index);
  struct winsize ws;
  (void) signum;

  /* Terminal resized, fetch the new size */
  if (ioctl (STDIN_FILENO, TIOCGWINSZ, &ws) < 0)
    {
      /* "Should never happen..." */
      clib_unix_warning ("TIOCGWINSZ");
      /* We can't trust ws.XXX... */
      return;
    }

  cf->width = ws.ws_col;
  if (cf->width > UNIX_CLI_MAX_TERMINAL_WIDTH)
    cf->width = UNIX_CLI_MAX_TERMINAL_WIDTH;
  if (cf->width == 0)
    cf->width = UNIX_CLI_DEFAULT_TERMINAL_WIDTH;

  cf->height = ws.ws_row;
  if (cf->height > UNIX_CLI_MAX_TERMINAL_HEIGHT)
    cf->height = UNIX_CLI_MAX_TERMINAL_HEIGHT;
  if (cf->height == 0)
    cf->height = UNIX_CLI_DEFAULT_TERMINAL_HEIGHT;

  /* Reindex the pager buffer */
  unix_cli_pager_reindex (cf);

  /* Redraw the page */
  unix_cli_pager_redraw (cf, uf);
}

/** Handle configuration directives in the @em unix section. */
static clib_error_t *
unix_cli_config (vlib_main_t * vm, unformat_input_t * input)
{
  unix_main_t *um = &unix_main;
  clib_file_main_t *fm = &file_main;
  unix_cli_main_t *cm = &unix_cli_main;
  int flags;
  clib_error_t *error = 0;
  unix_cli_file_t *cf;
  u32 cf_index;
  struct termios tio;
  struct sigaction sa;
  struct winsize ws;
  u8 *term;

  /* We depend on unix flags being set. */
  if ((error = vlib_call_config_function (vm, unix_config)))
    return error;

  if (um->flags & UNIX_FLAG_INTERACTIVE)
    {
      /* Set stdin to be non-blocking. */
      if ((flags = fcntl (STDIN_FILENO, F_GETFL, 0)) < 0)
	flags = 0;
      (void) fcntl (STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);

      cf_index = unix_cli_file_add (cm, "stdin", STDIN_FILENO);
      cf = pool_elt_at_index (cm->cli_file_pool, cf_index);
      cm->stdin_cli_file_index = cf_index;

      /* If stdin is a tty and we are using chacracter mode, enable
       * history on the CLI and set the tty line discipline accordingly. */
      if (isatty (STDIN_FILENO) && um->cli_line_mode == 0)
	{
	  /* Capture terminal resize events */
	  memset (&sa, 0, sizeof (sa));
	  sa.sa_handler = unix_cli_resize_interrupt;
	  if (sigaction (SIGWINCH, &sa, 0) < 0)
	    clib_panic ("sigaction");

	  /* Retrieve the current terminal size */
	  ioctl (STDIN_FILENO, TIOCGWINSZ, &ws);
	  cf->width = ws.ws_col;
	  cf->height = ws.ws_row;

	  if (cf->width == 0 || cf->height == 0)
	    {
	      /*
	       * We have a tty, but no size. Use defaults.
	       * vpp "unix interactive" inside emacs + gdb ends up here.
	       */
	      cf->width = UNIX_CLI_DEFAULT_TERMINAL_WIDTH;
	      cf->height = UNIX_CLI_DEFAULT_TERMINAL_HEIGHT;
	    }

	  /* Setup the history */
	  cf->history_limit = um->cli_history_limit;
	  cf->has_history = cf->history_limit != 0;

	  /* Setup the pager */
	  cf->no_pager = um->cli_no_pager;

	  /* This is an interactive session until we decide otherwise */
	  cf->is_interactive = 1;

	  /* We're going to be in char by char mode */
	  cf->line_mode = 0;

	  /* Save the original tty state so we can restore it later */
	  tcgetattr (STDIN_FILENO, &um->tio_stdin);
	  um->tio_isset = 1;

	  /* Tweak the tty settings */
	  tio = um->tio_stdin;
	  /* echo off, canonical mode off, ext'd input processing off */
	  tio.c_lflag &= ~(ECHO | ICANON | IEXTEN);
	  /* disable XON/XOFF, so ^S invokes the history search */
	  tio.c_iflag &= ~(IXON | IXOFF);
	  tio.c_cc[VMIN] = 1;	/* 1 byte at a time */
	  tio.c_cc[VTIME] = 0;	/* no timer */
	  tio.c_cc[VSTOP] = _POSIX_VDISABLE;	/* not ^S */
	  tio.c_cc[VSTART] = _POSIX_VDISABLE;	/* not ^Q */
	  tcsetattr (STDIN_FILENO, TCSAFLUSH, &tio);

	  /* See if we can do ANSI/VT100 output */
	  term = (u8 *) getenv ("TERM");
	  if (term != NULL)
	    {
	      int len = strlen ((char *) term);
	      cf->ansi_capable = unix_cli_terminal_type_ansi (term, len);
	      if (unix_cli_terminal_type_noninteractive (term, len))
		unix_cli_set_session_noninteractive (cf);
	    }
	}
      else
	{
	  /* No tty, so make sure the session doesn't have tty-like features */
	  unix_cli_set_session_noninteractive (cf);
	}

      /* Send banner and initial prompt */
      unix_cli_file_welcome (cm, cf);
    }

  /* If we have socket config, LISTEN, otherwise, don't */
  clib_socket_t *s = &um->cli_listen_socket;
  if (s->config && s->config[0] != 0)
    {
      /* CLI listen. */
      clib_file_t template = { 0 };

      /* mkdir of file socketu, only under /run  */
      if (strncmp (s->config, "/run", 4) == 0)
	{
	  u8 *tmp = format (0, "%s", s->config);
	  int i = vec_len (tmp);
	  while (i && tmp[--i] != '/')
	    ;

	  tmp[i] = 0;

	  if (i)
	    vlib_unix_recursive_mkdir ((char *) tmp);
	  vec_free (tmp);
	}

      s->flags = CLIB_SOCKET_F_IS_SERVER |	/* listen, don't connect */
	CLIB_SOCKET_F_ALLOW_GROUP_WRITE;	/* PF_LOCAL socket only */
      error = clib_socket_init (s);

      if (error)
	return error;

      template.read_function = unix_cli_listen_read_ready;
      template.file_descriptor = s->fd;
      template.description = format (0, "cli listener %s", s->config);

      clib_file_add (fm, &template);
    }

  /* Set CLI prompt. */
  if (!cm->cli_prompt)
    cm->cli_prompt = format (0, "VLIB: ");

  return 0;
}

/*?
 * This module has no configurable parameters.
?*/
VLIB_CONFIG_FUNCTION (unix_cli_config, "unix-cli");

/** Called when VPP is shutting down, this restores the system
 * terminal state if previously saved.
 */
static clib_error_t *
unix_cli_exit (vlib_main_t * vm)
{
  unix_main_t *um = &unix_main;

  /* If stdin is a tty and we saved the tty state, reset the tty state */
  if (isatty (STDIN_FILENO) && um->tio_isset)
    tcsetattr (STDIN_FILENO, TCSAFLUSH, &um->tio_stdin);

  return 0;
}

VLIB_MAIN_LOOP_EXIT_FUNCTION (unix_cli_exit);

/** Set the CLI prompt.
 * @param prompt The C string to set the prompt to.
 * @note This setting is global; it impacts all current
 *       and future CLI sessions.
 */
void
vlib_unix_cli_set_prompt (char *prompt)
{
  char *fmt = (prompt[strlen (prompt) - 1] == ' ') ? "%s" : "%s ";
  unix_cli_main_t *cm = &unix_cli_main;
  if (cm->cli_prompt)
    vec_free (cm->cli_prompt);
  cm->cli_prompt = format (0, fmt, prompt);
}

/** CLI command to quit the terminal session.
 * @note If this is a stdin session then this will
 *       shutdown VPP also.
 */
static clib_error_t *
unix_cli_quit (vlib_main_t * vm,
	       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unix_cli_main_t *cm = &unix_cli_main;
  unix_cli_file_t *cf = pool_elt_at_index (cm->cli_file_pool,
					   cm->current_input_file_index);

  /* Cosmetic: suppress the final prompt from appearing before we die */
  cf->is_interactive = 0;
  cf->started = 1;

  vlib_process_signal_event (vm,
			     vlib_current_process (vm),
			     UNIX_CLI_PROCESS_EVENT_QUIT,
			     cm->current_input_file_index);
  return 0;
}

/*?
 * Terminates the current CLI session.
 *
 * If VPP is running in @em interactive mode and this is the console session
 * (that is, the session on @c stdin) then this will also terminate VPP.
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (unix_cli_quit_command, static) = {
  .path = "quit",
  .short_help = "Exit CLI",
  .function = unix_cli_quit,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (unix_cli_q_command, static) = {
  .path = "q",
  .short_help = "Exit CLI",
  .function = unix_cli_quit,
};
/* *INDENT-ON* */

/** CLI command to execute a VPP command script. */
static clib_error_t *
unix_cli_exec (vlib_main_t * vm,
	       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  char *file_name;
  int fd;
  unformat_input_t sub_input;
  clib_error_t *error;

  file_name = 0;
  fd = -1;
  error = 0;

  if (!unformat (input, "%s", &file_name))
    {
      error = clib_error_return (0, "expecting file name, got `%U'",
				 format_unformat_error, input);
      goto done;
    }

  fd = open (file_name, O_RDONLY);
  if (fd < 0)
    {
      error = clib_error_return_unix (0, "failed to open `%s'", file_name);
      goto done;
    }

  /* Make sure its a regular file. */
  {
    struct stat s;

    if (fstat (fd, &s) < 0)
      {
	error = clib_error_return_unix (0, "failed to stat `%s'", file_name);
	goto done;
      }

    if (!(S_ISREG (s.st_mode) || S_ISLNK (s.st_mode)))
      {
	error = clib_error_return (0, "not a regular file `%s'", file_name);
	goto done;
      }
  }

  unformat_init_clib_file (&sub_input, fd);

  vlib_cli_input (vm, &sub_input, 0, 0);
  unformat_free (&sub_input);

done:
  if (fd > 0)
    close (fd);
  vec_free (file_name);

  return error;
}

/*?
 * Executes a sequence of CLI commands which are read from a file. If
 * a command is unrecognised or otherwise invalid then the usual CLI
 * feedback will be generated, however execution of subsequent commands
 * from the file will continue.
 *
 * The VPP code is indifferent to the file location. However, if SELinux
 * is enabled, then the file needs to have an SELinux label the VPP
 * process is allowed to access. For example, if a file is created in
 * '<em>/usr/share/vpp/</em>', it will be allowed. However, files manually
 * created in '/tmp/' or '/home/<user>/' will not be accessible by the VPP
 * process when SELinux is enabled.
 *
 * @cliexpar
 * Sample file:
 * @clistart
 * <b><em>$ cat /usr/share/vpp/scripts/gigup.txt</em></b>
 * set interface state GigabitEthernet0/8/0 up
 * set interface state GigabitEthernet0/9/0 up
 * @cliend
 * Example of how to execute a set of CLI commands from a file:
 * @cliexcmd{exec /usr/share/vpp/scripts/gigup.txt}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_exec, static) = {
  .path = "exec",
  .short_help = "exec <filename>",
  .function = unix_cli_exec,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

/** CLI command to show various unix error statistics. */
static clib_error_t *
unix_show_errors (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unix_main_t *um = &unix_main;
  clib_error_t *error = 0;
  int i, n_errors_to_show;
  unix_error_history_t *unix_errors = 0;

  n_errors_to_show = 1 << 30;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (!unformat (input, "%d", &n_errors_to_show))
	{
	  error =
	    clib_error_return (0,
			       "expecting integer number of errors to show, got `%U'",
			       format_unformat_error, input);
	  goto done;
	}
    }

  n_errors_to_show =
    clib_min (ARRAY_LEN (um->error_history), n_errors_to_show);

  i =
    um->error_history_index >
    0 ? um->error_history_index - 1 : ARRAY_LEN (um->error_history) - 1;

  while (n_errors_to_show > 0)
    {
      unix_error_history_t *eh = um->error_history + i;

      if (!eh->error)
	break;

      vec_add1 (unix_errors, eh[0]);
      n_errors_to_show -= 1;
      if (i == 0)
	i = ARRAY_LEN (um->error_history) - 1;
      else
	i--;
    }

  if (vec_len (unix_errors) == 0)
    vlib_cli_output (vm, "no Unix errors so far");
  else
    {
      vlib_cli_output (vm, "%Ld total errors seen", um->n_total_errors);
      for (i = vec_len (unix_errors) - 1; i >= 0; i--)
	{
	  unix_error_history_t *eh = vec_elt_at_index (unix_errors, i);
	  vlib_cli_output (vm, "%U: %U",
			   format_time_interval, "h:m:s:u", eh->time,
			   format_clib_error, eh->error);
	}
      vlib_cli_output (vm, "%U: time now",
		       format_time_interval, "h:m:s:u", vlib_time_now (vm));
    }

done:
  vec_free (unix_errors);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_unix_show_errors, static) = {
  .path = "show unix errors",
  .short_help = "Show Unix system call error history",
  .function = unix_show_errors,
};
/* *INDENT-ON* */

/** CLI command to show various unix error statistics. */
static clib_error_t *
unix_show_files (vlib_main_t * vm,
		 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  clib_file_main_t *fm = &file_main;
  clib_file_t *f;
  char path[PATH_MAX];
  u8 *s = 0;

  vlib_cli_output (vm, "%3s %6s %12s %12s %12s %-32s %s", "FD", "Thread",
		   "Read", "Write", "Error", "File Name", "Description");

  /* *INDENT-OFF* */
  pool_foreach (f, fm->file_pool,(
   {
      int rv;
      s = format (s, "/proc/self/fd/%d%c", f->file_descriptor, 0);
      rv = readlink((char *) s, path, PATH_MAX - 1);

      path[rv < 0 ? 0 : rv] = 0;

      vlib_cli_output (vm, "%3d %6d %12d %12d %12d %-32s %v",
		       f->file_descriptor, f->polling_thread_index,
		       f->read_events, f->write_events, f->error_events,
		       path, f->description);
      vec_reset_length (s);
    }));
  /* *INDENT-ON* */
  vec_free (s);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_unix_show_files, static) = {
  .path = "show unix files",
  .short_help = "Show Unix files in use",
  .function = unix_show_files,
};
/* *INDENT-ON* */

/** CLI command to show session command history. */
static clib_error_t *
unix_cli_show_history (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unix_cli_main_t *cm = &unix_cli_main;
  unix_cli_file_t *cf;
  int i, j;

  cf = pool_elt_at_index (cm->cli_file_pool, cm->current_input_file_index);

  if (!cf->is_interactive)
    return clib_error_return (0, "invalid for non-interactive sessions");

  if (cf->has_history && cf->history_limit)
    {
      i = 1 + cf->command_number - vec_len (cf->command_history);
      for (j = 0; j < vec_len (cf->command_history); j++)
	vlib_cli_output (vm, "%d  %v\n", i + j, cf->command_history[j]);
    }
  else
    {
      vlib_cli_output (vm, "History not enabled.\n");
    }

  return 0;
}

/*?
 * Displays the command history for the current session, if any.
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_unix_cli_show_history, static) = {
  .path = "history",
  .short_help = "Show current session command history",
  .function = unix_cli_show_history,
};
/* *INDENT-ON* */

/** CLI command to show terminal status. */
static clib_error_t *
unix_cli_show_terminal (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unix_main_t *um = &unix_main;
  unix_cli_main_t *cm = &unix_cli_main;
  unix_cli_file_t *cf;
  vlib_node_t *n;

  cf = pool_elt_at_index (cm->cli_file_pool, cm->current_input_file_index);
  n = vlib_get_node (vm, cf->process_node_index);

  vlib_cli_output (vm, "Terminal name:   %v\n", n->name);
  vlib_cli_output (vm, "Terminal mode:   %s\n", cf->line_mode ?
		   "line-by-line" : "char-by-char");
  vlib_cli_output (vm, "Terminal width:  %d\n", cf->width);
  vlib_cli_output (vm, "Terminal height: %d\n", cf->height);
  vlib_cli_output (vm, "ANSI capable:    %s\n",
		   cf->ansi_capable ? "yes" : "no");
  vlib_cli_output (vm, "Interactive:     %s\n",
		   cf->is_interactive ? "yes" : "no");
  vlib_cli_output (vm, "History enabled: %s%s\n",
		   cf->has_history ? "yes" : "no", !cf->has_history
		   || cf->history_limit ? "" :
		   " (disabled by history limit)");
  if (cf->has_history)
    vlib_cli_output (vm, "History limit:   %d\n", cf->history_limit);
  vlib_cli_output (vm, "Pager enabled:   %s%s%s\n",
		   cf->no_pager ? "no" : "yes",
		   cf->no_pager
		   || cf->height ? "" : " (disabled by terminal height)",
		   cf->no_pager
		   || um->cli_pager_buffer_limit ? "" :
		   " (disabled by buffer limit)");
  if (!cf->no_pager)
    vlib_cli_output (vm, "Pager limit:     %d\n", um->cli_pager_buffer_limit);
  vlib_cli_output (vm, "CRLF mode:       %s\n",
		   cf->crlf_mode ? "CR+LF" : "LF");

  return 0;
}

/*?
 * Displays various information about the state of the current terminal
 * session.
 *
 * @cliexpar
 * @cliexstart{show terminal}
 * Terminal name:   unix-cli-stdin
 * Terminal mode:   char-by-char
 * Terminal width:  123
 * Terminal height: 48
 * ANSI capable:    yes
 * Interactive:     yes
 * History enabled: yes
 * History limit:   50
 * Pager enabled:   yes
 * Pager limit:     100000
 * CRLF mode:       LF
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_unix_cli_show_terminal, static) = {
  .path = "show terminal",
  .short_help = "Show current session terminal settings",
  .function = unix_cli_show_terminal,
};
/* *INDENT-ON* */

/** CLI command to display a list of CLI sessions. */
static clib_error_t *
unix_cli_show_cli_sessions (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  unix_cli_main_t *cm = &unix_cli_main;
  clib_file_main_t *fm = &file_main;
  unix_cli_file_t *cf;
  clib_file_t *uf;
  vlib_node_t *n;

  vlib_cli_output (vm, "%-5s %-5s %-20s %s", "PNI", "FD", "Name", "Flags");

#define fl(x, y) ( (x) ? toupper((y)) : tolower((y)) )
  /* *INDENT-OFF* */
  pool_foreach (cf, cm->cli_file_pool, ({
    uf = pool_elt_at_index (fm->file_pool, cf->clib_file_index);
    n = vlib_get_node (vm, cf->process_node_index);
    vlib_cli_output (vm,
		     "%-5d %-5d %-20v %c%c%c%c%c\n",
		     cf->process_node_index,
		     uf->file_descriptor,
		     n->name,
		     fl (cf->is_interactive, 'i'),
		     fl (cf->is_socket, 's'),
		     fl (cf->line_mode, 'l'),
		     fl (cf->has_epipe, 'p'),
		     fl (cf->ansi_capable, 'a'));
  }));
  /* *INDENT-ON* */
#undef fl

  return 0;
}

/*?
 * Displays a summary of all the current CLI sessions.
 *
 * Typically used to diagnose connection issues with the CLI
 * socket.
 *
 * @cliexpar
 * @cliexstart{show cli-sessions}
 * PNI   FD    Name                 Flags
 * 343   0     unix-cli-stdin       IslpA
 * 344   7     unix-cli-local:20    ISlpA
 * 346   8     unix-cli-local:21    iSLpa
 * @cliexend

 * In this example we have the debug console of the running process
 * on stdin/out, we have an interactive socket session and we also
 * have a non-interactive socket session.
 *
 * Fields:
 *
 * - @em PNI: Process node index.
 * - @em FD: Unix file descriptor.
 * - @em Name: Name of the session.
 * - @em Flags: Various flags that describe the state of the session.
 *
 * @em Flags have the following meanings; lower-case typically negates
 * upper-case:
 *
 * - @em I Interactive session.
 * - @em S Connected by socket.
 * - @em s Not a socket, likely stdin.
 * - @em L Line-by-line mode.
 * - @em l Char-by-char mode.
 * - @em P EPIPE detected on connection; it will close soon.
 * - @em A ANSI-capable terminal.
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_unix_cli_show_cli_sessions, static) = {
  .path = "show cli-sessions",
  .short_help = "Show current CLI sessions",
  .function = unix_cli_show_cli_sessions,
};
/* *INDENT-ON* */

/** CLI command to set terminal pager settings. */
static clib_error_t *
unix_cli_set_terminal_pager (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  unix_main_t *um = &unix_main;
  unix_cli_main_t *cm = &unix_cli_main;
  unix_cli_file_t *cf;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;

  cf = pool_elt_at_index (cm->cli_file_pool, cm->current_input_file_index);

  if (!cf->is_interactive)
    return clib_error_return (0, "invalid for non-interactive sessions");

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "on"))
	cf->no_pager = 0;
      else if (unformat (line_input, "off"))
	cf->no_pager = 1;
      else if (unformat (line_input, "limit %u", &um->cli_pager_buffer_limit))
	vlib_cli_output (vm,
			 "Pager limit set to %u lines; note, this is global.\n",
			 um->cli_pager_buffer_limit);
      else
	{
	  error = clib_error_return (0, "unknown parameter: `%U`",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

done:
  unformat_free (line_input);

  return error;
}

/*?
 * Enables or disables the terminal pager for this session. Generally
 * this defaults to enabled.
 *
 * Additionally allows the pager buffer size to be set; though note that
 * this value is set globally and not per session.
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_unix_cli_set_terminal_pager, static) = {
  .path = "set terminal pager",
  .short_help = "set terminal pager [on|off] [limit <lines>]",
  .function = unix_cli_set_terminal_pager,
};
/* *INDENT-ON* */

/** CLI command to set terminal history settings. */
static clib_error_t *
unix_cli_set_terminal_history (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  unix_cli_main_t *cm = &unix_cli_main;
  unix_cli_file_t *cf;
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 limit;
  clib_error_t *error = 0;

  cf = pool_elt_at_index (cm->cli_file_pool, cm->current_input_file_index);

  if (!cf->is_interactive)
    return clib_error_return (0, "invalid for non-interactive sessions");

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "on"))
	cf->has_history = 1;
      else if (unformat (line_input, "off"))
	cf->has_history = 0;
      else if (unformat (line_input, "limit %u", &cf->history_limit))
	;
      else
	{
	  error = clib_error_return (0, "unknown parameter: `%U`",
				     format_unformat_error, line_input);
	  goto done;
	}

      /* If we reduced history size, or turned it off, purge the history */
      limit = cf->has_history ? cf->history_limit : 0;

      while (cf->command_history && vec_len (cf->command_history) >= limit)
	{
	  vec_free (cf->command_history[0]);
	  vec_delete (cf->command_history, 1, 0);
	}
    }

done:
  unformat_free (line_input);

  return error;
}

/*?
 * Enables or disables the command history function of the current
 * terminal. Generally this defaults to enabled.
 *
 * This command also allows the maximum size of the history buffer for
 * this session to be altered.
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_unix_cli_set_terminal_history, static) = {
  .path = "set terminal history",
  .short_help = "set terminal history [on|off] [limit <lines>]",
  .function = unix_cli_set_terminal_history,
};
/* *INDENT-ON* */

/** CLI command to set terminal ANSI settings. */
static clib_error_t *
unix_cli_set_terminal_ansi (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  unix_cli_main_t *cm = &unix_cli_main;
  unix_cli_file_t *cf;

  cf = pool_elt_at_index (cm->cli_file_pool, cm->current_input_file_index);

  if (!cf->is_interactive)
    return clib_error_return (0, "invalid for non-interactive sessions");

  if (unformat (input, "on"))
    cf->ansi_capable = 1;
  else if (unformat (input, "off"))
    cf->ansi_capable = 0;
  else
    return clib_error_return (0, "unknown parameter: `%U`",
			      format_unformat_error, input);

  return 0;
}

/*?
 * Enables or disables the use of ANSI control sequences by this terminal.
 * The default will vary based on terminal detection at the start of the
 * session.
 *
 * ANSI control sequences are used in a small number of places to provide,
 * for example, color text output and to control the cursor in the pager.
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_unix_cli_set_terminal_ansi, static) = {
  .path = "set terminal ansi",
  .short_help = "set terminal ansi [on|off]",
  .function = unix_cli_set_terminal_ansi,
};
/* *INDENT-ON* */

static clib_error_t *
unix_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (unix_cli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
