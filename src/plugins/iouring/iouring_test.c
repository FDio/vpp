/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Moinak Bhattacharyya <moinakb001@gmail.com>
 */

#include <vlib/vlib.h>
#include <fcntl.h>

#include "iouring_input.h"

typedef enum
{
  IOURING_TEST_OP_OPENAT,
  IOURING_TEST_OP_READ,
  IOURING_TEST_OP_CLOSE,
} iouring_test_op_t;

typedef struct
{
  iouring_test_op_t op;
  int res;
  union
  {
    u8 *path;	/* for openat */
    u8 *buffer; /* for read */
    int fd;	/* for close */
  };
} iouring_test_ctx_t;

static u32 iouring_test_reg_id = ~0;
static iouring_test_ctx_t pending_op;
static u32 completions = 0;

static uword
iouring_test_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  iouring_frame_scalar_t *sc = vlib_frame_scalar_args (frame);
  u32 *from = vlib_frame_vector_args (frame);

  ASSERT (sc->n_cqes == 1);
  ASSERT (frame->n_vectors == 1);

  vlib_buffer_t *b = vlib_get_buffer (vm, from[0]);
  iouring_node_cqe_t *cqe = vlib_buffer_get_current (b);

  pending_op.res = ((struct io_uring_cqe *) cqe)->res;
  clib_atomic_fetch_add (&completions, 1);

  vlib_buffer_free (vm, from, 1);
  return 1;
}

VLIB_REGISTER_NODE (iouring_test_node) = {
  .function = iouring_test_node_fn,
  .name = "iouring-test",
  .type = VLIB_NODE_TYPE_INTERNAL,
  .scalar_size = sizeof (iouring_frame_scalar_t),
};

static clib_error_t *
iouring_test_init (vlib_main_t *vm)
{
  iouring_test_reg_id = iouring_register_node (iouring_test_node.index);
  return 0;
}

VLIB_INIT_FUNCTION (iouring_test_init) = {
  .runs_after = VLIB_INITS ("iouring_init"),
};

static clib_error_t *
iouring_test_command_internal (vlib_main_t *vm, struct io_uring_sqe *sqe)
{
  u32 wait_for = clib_atomic_load_acq_n (&completions) + 1;

  iouring_sqe_set_user_data (sqe, iouring_test_reg_id, 0);
  io_uring_submit (iouring_get_ring (vm->thread_index));

  while (clib_atomic_load_acq_n (&completions) < wait_for)
    vlib_process_suspend (vm, 0.001);

  int res = pending_op.res;

  switch (pending_op.op)
    {
    case IOURING_TEST_OP_OPENAT:
      if (res < 0)
	vlib_cli_output (vm, "openat '%s' failed: %s", pending_op.path, strerror (-res));
      else
	vlib_cli_output (vm, "openat '%s' succeeded, fd = %d", pending_op.path, res);
      vec_free (pending_op.path);
      break;
    case IOURING_TEST_OP_READ:
      if (res < 0)
	vlib_cli_output (vm, "read failed: %s", strerror (-res));
      else
	vlib_cli_output (vm, "read succeeded, %d bytes:\n%.*s", res, res, pending_op.buffer);
      vec_free (pending_op.buffer);
      break;
    case IOURING_TEST_OP_CLOSE:
      if (res < 0)
	vlib_cli_output (vm, "close fd %d failed: %s", pending_op.fd, strerror (-res));
      else
	vlib_cli_output (vm, "close fd %d succeeded", pending_op.fd);
      break;
    }

  return 0;
}

static clib_error_t *
iouring_test_openat_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  struct io_uring *ring = iouring_get_ring (vm->thread_index);
  if (!ring)
    return clib_error_return (0, "io_uring not available");

  u8 *path = 0;
  if (!unformat (input, "%s", &path))
    path = format (0, "/dev/zero%c", 0);
  else
    vec_add1 (path, 0);

  struct io_uring_sqe *sqe = io_uring_get_sqe (ring);
  if (!sqe)
    {
      vec_free (path);
      return clib_error_return (0, "failed to get SQE");
    }

  pending_op.op = IOURING_TEST_OP_OPENAT;
  pending_op.path = path;
  io_uring_prep_openat (sqe, AT_FDCWD, (char *) path, O_RDONLY, 0);

  return iouring_test_command_internal (vm, sqe);
}

static clib_error_t *
iouring_test_read_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  struct io_uring *ring = iouring_get_ring (vm->thread_index);
  if (!ring)
    return clib_error_return (0, "io_uring not available");

  int fd = -1;
  u32 size = 4096;

  if (!unformat (input, "%d", &fd))
    return clib_error_return (0, "usage: test iouring read <fd> [size]");
  unformat (input, "%u", &size);

  if (fd < 0)
    return clib_error_return (0, "invalid fd %d", fd);

  struct io_uring_sqe *sqe = io_uring_get_sqe (ring);
  if (!sqe)
    return clib_error_return (0, "failed to get SQE");

  u8 *buffer = 0;
  vec_validate (buffer, size - 1);

  pending_op.op = IOURING_TEST_OP_READ;
  pending_op.buffer = buffer;
  io_uring_prep_read (sqe, fd, buffer, size, 0);

  return iouring_test_command_internal (vm, sqe);
}

static clib_error_t *
iouring_test_close_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  struct io_uring *ring = iouring_get_ring (vm->thread_index);
  if (!ring)
    return clib_error_return (0, "io_uring not available");

  int fd = -1;

  if (!unformat (input, "%d", &fd))
    return clib_error_return (0, "usage: test iouring close <fd>");

  if (fd < 0)
    return clib_error_return (0, "invalid fd %d", fd);

  struct io_uring_sqe *sqe = io_uring_get_sqe (ring);
  if (!sqe)
    return clib_error_return (0, "failed to get SQE");

  pending_op.op = IOURING_TEST_OP_CLOSE;
  pending_op.fd = fd;
  io_uring_prep_close (sqe, fd);

  return iouring_test_command_internal (vm, sqe);
}

VLIB_CLI_COMMAND (iouring_test_openat_command, static) = {
  .path = "test iouring openat",
  .short_help = "test iouring openat [<path>]",
  .function = iouring_test_openat_command_fn,
};

VLIB_CLI_COMMAND (iouring_test_read_command, static) = {
  .path = "test iouring read",
  .short_help = "test iouring read <fd> [<size>]",
  .function = iouring_test_read_command_fn,
};

VLIB_CLI_COMMAND (iouring_test_close_command, static) = {
  .path = "test iouring close",
  .short_help = "test iouring close <fd>",
  .function = iouring_test_close_command_fn,
};