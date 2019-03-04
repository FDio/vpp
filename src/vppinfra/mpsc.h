/* multi producer single consumer queue */

typedef struct mpscq_node_t_
{
  struct mpscq_node_t_ * volatile  next;
  void * data;
} mpscq_node_t;

typedef struct mpscq_t_
{
  mpscq_node_t * volatile head;
  mpscq_node_t * tail;
  mpscq_node_t stub;
  int init;
} mpscq_t;

always_inline
void mpscq_create (mpscq_t * self)
{
  self->init = 1;
  self->stub.next = 0;
  self->head = &self->stub;
  self->tail = &self->stub;
}

always_inline
void mpscq_push (mpscq_t * self, mpscq_node_t * n)
{
  n->next = 0;
  mpscq_node_t *prev = __atomic_exchange_n (&self->head, n, __ATOMIC_ACQ_REL);
  prev->next = n;
}

always_inline
mpscq_node_t * mpscq_pop (mpscq_t * self)
{
  mpscq_node_t * tail = self->tail;
  mpscq_node_t * next = tail->next;

  if (tail == &self->stub)
  {
    if (next == 0)
        return 0;
    self->tail = next;
    tail = next;
    next = next->next;
  }

  if (next)
  {
    self->tail = next;
    return tail;
  }

  mpscq_node_t * stub = &self->stub;
  stub->next = 0;

  if (clib_atomic_bool_cmp_and_swap(&self->head, tail, stub))
  {
    self->tail = &self->stub;
    return tail;
  }

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
