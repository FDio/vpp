/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <svm/ssvm.h>
#include <svm/message_queue.h>

#define test1_error(_fmt, _args...)			\
{							\
    ssvm_pop_heap (oldheap);				\
    error = clib_error_return (0, _fmt, ##_args);	\
    goto done;						\
}

clib_error_t *
test1 (int verbose)
{
  ssvm_private_t _ssvm, *ssvm = &_ssvm;
  svm_msg_q_cfg_t _cfg, *cfg = &_cfg;
  svm_msg_q_msg_t msg1, msg2, msg[12];
  ssvm_shared_header_t *sh;
  clib_error_t *error = 0;
  svm_msg_q_t *mq;
  void *oldheap;
  int i;

  memset (ssvm, 0, sizeof (*ssvm));

  ssvm->ssvm_size = 1 << 20;
  ssvm->i_am_master = 1;
  ssvm->my_pid = getpid ();
  ssvm->name = format (0, "%s%c", "test", 0);
  ssvm->requested_va = 0;

  if (ssvm_master_init (ssvm, SSVM_SEGMENT_SHM))
    return clib_error_return (0, "failed: segment allocation");
  sh = ssvm->sh;

  svm_msg_q_ring_cfg_t rc[2]= {{8, 8, 0}, {8, 16, 0}};
  cfg->consumer_pid = ~0;
  cfg->n_rings = 2;
  cfg->q_nitems = 16;
  cfg->ring_cfgs = rc;

  oldheap = ssvm_push_heap (sh);
  mq = svm_msg_q_alloc (cfg);
  if (!mq)
    test1_error ("failed: alloc");

  if (vec_len (mq->rings) != 2)
      test1_error ("failed: ring allocation");

  msg1 = svm_msg_q_alloc_msg (mq, 8);
  if (mq->rings[0].cursize != 1
      || msg1.ring_index != 0
      || msg1.elt_index != 0)
    test1_error ("failed: msg alloc1");

  msg2 = svm_msg_q_alloc_msg (mq, 15);
  if (mq->rings[1].cursize != 1
      || msg2.ring_index != 1
      || msg2.elt_index != 0)
      test1_error ("failed: msg alloc2");

  svm_msg_q_free_msg (mq, &msg1);
  if (mq->rings[0].cursize != 0)
    test1_error("failed: free msg");

  for (i = 0; i < 12; i++)
    {
      msg[i] = svm_msg_q_alloc_msg (mq, 7);
      *(u32 *)svm_msg_q_msg_data (mq, &msg[i]) = i;
    }

  if (mq->rings[0].cursize != 8
      || mq->rings[1].cursize != 5)
      test1_error ("failed: msg alloc3");

  *(u32 *)svm_msg_q_msg_data (mq, &msg2) = 123;
  svm_msg_q_add (mq, &msg2, SVM_Q_NOWAIT);
  for (i = 0; i < 12; i++)
    svm_msg_q_add (mq, &msg[i], SVM_Q_NOWAIT);

  if (svm_msg_q_sub (mq, &msg2, SVM_Q_NOWAIT, 0))
    test1_error ("failed: dequeue1");

  if (msg2.ring_index != 1 || msg2.elt_index != 0)
    test1_error ("failed: dequeue1 result");
  if (*(u32 *)svm_msg_q_msg_data (mq, &msg2) != 123)
    test1_error ("failed: dequeue1 wrong data");

  svm_msg_q_free_msg (mq, &msg2);

  for (i = 0; i < 12; i++)
    {
      if (svm_msg_q_sub (mq, &msg[i], SVM_Q_NOWAIT, 0))
	test1_error ("failed: dequeue2");
      if (i < 8)
	{
	  if (msg[i].ring_index != 0 || msg[i].elt_index != (i + 1) % 8)
	    test1_error ("failed: dequeue2 result2");
	}
      else
	{
	  if (msg[i].ring_index != 1 || msg[i].elt_index != (i - 8) + 1)
	    test1_error ("failed: dequeue2 result3");
	}
      if (*(u32 *)svm_msg_q_msg_data (mq, &msg[i]) != i)
        test1_error ("failed: dequeue2 wrong data");
      svm_msg_q_free_msg (mq, &msg[i]);
    }
  if (mq->rings[0].cursize != 0 || mq->rings[1].cursize != 0)
    test1_error ("failed: post dequeue");

  ssvm_pop_heap (oldheap);

done:
  ssvm_delete (ssvm);
  return error;
}

int
test_svm_message_queue (unformat_input_t * input)
{
  clib_error_t *error = 0;
  int verbose = 0;
  int test_id = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "test1"))
      	test_id = 1;
      else
	{
	  error = clib_error_create ("unknown input `%U'\n",
				     format_unformat_error, input);
	  goto out;
	}
    }

  switch (test_id)
    {
    case 1:
      error = test1 (verbose);
    }
out:
  if (error)
    clib_error_report (error);
  else
    clib_warning ("success");

  return 0;
}

int
main (int argc, char *argv[])
{
  unformat_input_t i;
  int r;

  clib_mem_init_thread_safe (0, 256 << 20);
  unformat_init_command_line (&i, argv);
  r = test_svm_message_queue (&i);
  unformat_free (&i);
  return r;
}
