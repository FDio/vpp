/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
 * Algorithm from:
 * Cormen, T. H., Leiserson, C. E., Rivest, R. L., & Stein, C. (2009).
 * Introduction to algorithms. MIT press, 3rd Edition, Ch. 13
 */

#include <vppinfra/rbtree.h>

static inline void
rb_tree_rotate_left (rb_tree_t * rt, rb_node_t * x)
{
  rb_node_t *y, *tmp, *xp;
  rb_node_index_t xi, yi;

  xi = rb_node_index (rt, x);
  yi = x->right;
  y = rb_node_right (rt, x);
  x->right = y->left;
  if (y->left != RBTREE_TNIL_INDEX)
    {
      tmp = rb_node_left (rt, y);
      tmp->parent = xi;
    }
  xp = rb_node_parent (rt, x);
  y->parent = x->parent;
  if (x->parent == RBTREE_TNIL_INDEX)
    rt->root = rb_node_index (rt, y);
  else if (xp->left == xi)
    xp->left = yi;
  else
    xp->right = yi;
  y->left = xi;
  x->parent = yi;
}

static inline void
rb_tree_rotate_right (rb_tree_t * rt, rb_node_t * y)
{
  rb_node_index_t yi, xi;
  rb_node_t *x, *yp;

  yi = rb_node_index (rt, y);
  xi = y->left;
  x = rb_node_left (rt, y);
  y->left = x->right;
  if (x->right != RBTREE_TNIL_INDEX)
    {
      rb_node_t *tmp = rb_node_right (rt, x);
      tmp->parent = yi;
    }
  yp = rb_node_parent (rt, y);
  x->parent = y->parent;
  if (y->parent == RBTREE_TNIL_INDEX)
    rt->root = rb_node_index (rt, x);
  else if (yp->right == yi)
    yp->right = xi;
  else
    yp->left = xi;
  x->right = yi;
  y->parent = xi;
}

static void
rb_tree_insert (rb_tree_t * rt, rb_node_t * z)
{
  rb_node_index_t yi = 0, xi = rt->root, zi;
  rb_node_t *y, *zpp, *x, *zp;

  y = rb_node (rt, RBTREE_TNIL_INDEX);
  while (xi != RBTREE_TNIL_INDEX)
    {
      x = rb_node (rt, xi);
      y = x;
      if (z->key < x->key)
	xi = x->left;
      else
	xi = x->right;
    }
  yi = rb_node_index (rt, y);
  z->parent = yi;
  if (yi == RBTREE_TNIL_INDEX)
    rt->root = rb_node_index (rt, z);
  else if (z->key < y->key)
    y->left = rb_node_index (rt, z);
  else
    y->right = rb_node_index (rt, z);

  /* Tree fixup stage */
  while (y->color == RBTREE_RED)
    {
      zi = rb_node_index (rt, z);
      zp = rb_node_parent (rt, z);
      zpp = rb_node_parent (rt, zp);
      if (z->parent == zpp->left)
	{
	  y = rb_node_right (rt, zpp);
	  if (y->color == RBTREE_RED)
	    {
	      zp->color = RBTREE_BLACK;
	      y->color = RBTREE_BLACK;
	      zpp->color = RBTREE_RED;
	      z = zpp;
	    }
	  else
	    {
	      if (zi == zp->right)
		{
		  z = zp;
		  rb_tree_rotate_left (rt, z);
		  zp = rb_node (rt, z->parent);
		  zpp = rb_node (rt, zp->parent);
		}
	      zp->color = RBTREE_BLACK;
	      zpp->color = RBTREE_RED;
	      rb_tree_rotate_right (rt, zpp);
	    }
	}
      else
	{
	  y = rb_node (rt, zpp->left);
	  if (y->color == RBTREE_RED)
	    {
	      zp->color = RBTREE_BLACK;
	      y->color = RBTREE_BLACK;
	      zpp->color = RBTREE_RED;
	      z = zpp;
	    }
	  else
	    {
	      if (zi == zp->left)
		{
		  z = zp;
		  rb_tree_rotate_right (rt, z);
		  zp = rb_node (rt, z->parent);
		  zpp = rb_node (rt, zp->parent);
		}
	      zp->color = RBTREE_BLACK;
	      zpp->color = RBTREE_RED;
	      rb_tree_rotate_left (rt, zpp);
	    }
	}
    }
  rb_node (rt, rt->root)->color = RBTREE_BLACK;
}

rb_node_index_t
rb_tree_add (rb_tree_t * rt, u32 key)
{
  rb_node_t *n;

  pool_get_zero (rt->nodes, n);
  n->key = key;
  n->color = RBTREE_RED;
  rb_tree_insert (rt, n);
  return rb_node_index (rt, n);
}

rb_node_index_t
rb_tree_add2 (rb_tree_t * rt, u32 key, uword opaque)
{
  rb_node_t *n;

  pool_get_zero (rt->nodes, n);
  n->key = key;
  n->color = RBTREE_RED;
  n->opaque = opaque;
  rb_tree_insert (rt, n);
  return rb_node_index (rt, n);
}

rb_node_t *
rb_tree_search_subtree (rb_tree_t * rt, rb_node_t * x, u32 key)
{
  while (rb_node_index (rt, x) != RBTREE_TNIL_INDEX && key != x->key)
    if (key < x->key)
      x = rb_node_left (rt, x);
    else
      x = rb_node_right (rt, x);
  return x;
}

rb_node_t *
rb_tree_min_subtree (rb_tree_t * rt, rb_node_t * x)
{
  while (x->left != RBTREE_TNIL_INDEX)
    x = rb_node_left (rt, x);
  return x;
}

rb_node_t *
rb_tree_max_subtree (rb_tree_t * rt, rb_node_t * x)
{
  while (x->right != RBTREE_TNIL_INDEX)
    x = rb_node_right (rt, x);
  return x;
}

rb_node_t *
rb_tree_successor (rb_tree_t * rt, rb_node_t * x)
{
  rb_node_t *y;

  if (x->right != RBTREE_TNIL_INDEX)
    return rb_tree_min_subtree (rt, rb_node_right (rt, x));

  y = rb_node_parent (rt, x);
  while (!rb_node_is_tnil (rt, y) && y->right == rb_node_index (rt, x))
    {
      x = y;
      y = rb_node_parent (rt, y);
    }
  return y;
}

rb_node_t *
rb_tree_predecessor (rb_tree_t * rt, rb_node_t * x)
{
  rb_node_t *y;

  if (x->left != RBTREE_TNIL_INDEX)
    return rb_tree_max_subtree (rt, rb_node_left (rt, x));

  y = rb_node_parent (rt, x);
  while (!rb_node_is_tnil (rt, y) && y->left == rb_node_index (rt, x))
    {
      x = y;
      y = rb_node_parent (rt, y);
    }
  return y;
}

static inline void
rb_tree_transplant (rb_tree_t * rt, rb_node_t * u, rb_node_t * v)
{
  rb_node_t *up;

  up = rb_node_parent (rt, u);
  if (u->parent == RBTREE_TNIL_INDEX)
    rt->root = rb_node_index (rt, v);
  else if (rb_node_index (rt, u) == up->left)
    up->left = rb_node_index (rt, v);
  else
    up->right = rb_node_index (rt, v);
  v->parent = u->parent;
}

void
rb_tree_del_node (rb_tree_t * rt, rb_node_t * z)
{
  rb_node_color_t y_original_color;
  rb_node_t *x, *y, *yr, *yl, *xp, *w, *wl, *wr;
  rb_node_index_t xi, yi;

  y = z;
  y_original_color = y->color;

  if (z->left == RBTREE_TNIL_INDEX)
    {
      x = rb_node_right (rt, z);
      rb_tree_transplant (rt, z, x);
    }
  else if (z->right == RBTREE_TNIL_INDEX)
    {
      x = rb_node_left (rt, z);
      rb_tree_transplant (rt, z, x);
    }
  else
    {
      y = rb_tree_min_subtree (rt, rb_node_right (rt, z));
      y_original_color = y->color;
      x = rb_node_right (rt, y);
      yi = rb_node_index (rt, y);
      if (y->parent == rb_node_index (rt, z))
	x->parent = yi;
      else
	{
	  rb_tree_transplant (rt, y, rb_node_right (rt, y));
	  y->right = z->right;
	  yr = rb_node_right (rt, y);
	  yr->parent = yi;
	}
      rb_tree_transplant (rt, z, y);
      y->left = z->left;
      yl = rb_node_left (rt, y);
      yl->parent = yi;
      y->color = z->color;
    }

  if (y_original_color == RBTREE_RED)
    return;

  /* Tree fixup needed */

  xi = rb_node_index (rt, x);
  while (xi != rt->root && x->color == RBTREE_BLACK)
    {
      xp = rb_node_parent (rt, x);
      if (xi == xp->left)
	{
	  w = rb_node_right (rt, xp);
	  if (w->color == RBTREE_RED)
	    {
	      w->color = RBTREE_BLACK;
	      xp->color = RBTREE_RED;
	      rb_tree_rotate_left (rt, xp);
	      w = rb_node_right (rt, xp);
	    }
	  wl = rb_node_left (rt, w);
	  wr = rb_node_right (rt, w);
	  if (wl->color == RBTREE_BLACK && wr->color == RBTREE_BLACK)
	    {
	      w->color = RBTREE_RED;
	      x = xp;
	    }
	  else
	    {
	      if (wr->color == RBTREE_BLACK)
		{
		  wl->color = RBTREE_BLACK;
		  w->color = RBTREE_RED;
		  rb_tree_rotate_right (rt, w);
		  w = rb_node_right (rt, xp);
		}
	      w->color = xp->color;
	      xp->color = RBTREE_BLACK;
	      wr->color = RBTREE_BLACK;
	      rb_tree_rotate_left (rt, xp);
	      x = rb_node (rt, rt->root);
	    }
	}
      else
	{
	  w = rb_node_left (rt, xp);
	  if (w->color == RBTREE_RED)
	    {
	      w->color = RBTREE_BLACK;
	      xp->color = RBTREE_RED;
	      rb_tree_rotate_right (rt, xp);
	      w = rb_node_left (rt, xp);
	    }
	  wl = rb_node_left (rt, w);
	  wr = rb_node_right (rt, w);
	  if (wl->color == RBTREE_BLACK && wr->color == RBTREE_BLACK)
	    {
	      w->color = RBTREE_RED;
	      x = xp;
	    }
	  else
	    {
	      if (wl->color == RBTREE_BLACK)
		{
		  wr->color = RBTREE_BLACK;
		  w->color = RBTREE_RED;
		  rb_tree_rotate_left (rt, w);
		  w = rb_node_left (rt, xp);
		}
	      w->color = xp->color;
	      xp->color = RBTREE_BLACK;
	      wl->color = RBTREE_BLACK;
	      rb_tree_rotate_right (rt, xp);
	      x = rb_node (rt, rt->root);
	    }
	}
      xi = rb_node_index (rt, x);
    }
  x->color = RBTREE_BLACK;
}

void
rb_tree_del (rb_tree_t * rt, u32 key)
{
  rb_node_t *n;
  n = rb_tree_search_subtree (rt, rb_node (rt, rt->root), key);
  if (rb_node_index (rt, n) != RBTREE_TNIL_INDEX)
    {
      rb_tree_del_node (rt, n);
      pool_put (rt->nodes, n);
    }
}

u32
rb_tree_n_nodes (rb_tree_t * rt)
{
  return pool_elts (rt->nodes);
}

void
rb_tree_free_nodes (rb_tree_t * rt)
{
  pool_free (rt->nodes);
  rt->root = RBTREE_TNIL_INDEX;
}

void
rb_tree_init (rb_tree_t * rt)
{
  rb_node_t *tnil;

  rt->nodes = 0;
  rt->root = RBTREE_TNIL_INDEX;

  /* By convention first node, index 0, is the T.nil sentinel */
  pool_get_zero (rt->nodes, tnil);
  tnil->color = RBTREE_BLACK;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
