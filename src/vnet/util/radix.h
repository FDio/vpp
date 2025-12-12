/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 1988, 1989, 1993 The Regents of the University of California.
 */

/*	$NetBSD: radix.h,v 1.23 2016/11/15 01:50:06 ozaki-r Exp $	*/

#ifndef _NET_RADIX_H_
#define	_NET_RADIX_H_

#include <vlib/vlib.h>

/*
 * Radix search tree node layout.
 */

struct radix_node {
	struct	radix_mask *rn_mklist;	/* list of masks contained in subtree */
	struct	radix_node *rn_p;	/* parent */
	i16	rn_b;			/* bit offset; -1-index(netmask) */
	u8	rn_bmask;		/* node: mask for bit test*/
	u8	rn_flags;		/* enumerated next */
#define RNF_NORMAL	1		/* leaf contains normal route */
#define RNF_ROOT	2		/* leaf is root leaf for tree */
#define RNF_ACTIVE	4		/* This node is alive (for rtfree) */
	union {
		struct {			/* leaf only data: */
			const char *rn_Key;	/* object of search */
			const char *rn_Mask;	/* netmask, if present */
			struct	radix_node *rn_Dupedkey;
		} rn_leaf;
		struct {			/* node only data: */
			int	rn_Off;		/* where to start compare */
			struct	radix_node *rn_L;/* progeny */
			struct	radix_node *rn_R;/* progeny */
		} rn_node;
	} rn_u;
#ifdef RN_DEBUG
	i32 rn_info;
	struct radix_node *rn_twin;
	struct radix_node *rn_ybro;
#endif
};

#define rn_dupedkey rn_u.rn_leaf.rn_Dupedkey
#define rn_key rn_u.rn_leaf.rn_Key
#define rn_mask rn_u.rn_leaf.rn_Mask
#define rn_off rn_u.rn_node.rn_Off
#define rn_l rn_u.rn_node.rn_L
#define rn_r rn_u.rn_node.rn_R

/*
 * Annotations to tree concerning potential routes applying to subtrees.
 */

struct radix_mask {
	i16	rm_b;			/* bit offset; -1-index(netmask) */
	i8	rm_unused;		/* cf. rn_bmask */
	u8	rm_flags;		/* cf. rn_flags */
	struct	radix_mask *rm_mklist;	/* more masks to try */
	union	{
		const char *rmu_mask;		/* the mask */
		struct	radix_node *rmu_leaf;	/* for normal routes */
	}	rm_rmu;
	i32	rm_refs;		/* # of references to this struct */
};

#define rm_mask rm_rmu.rmu_mask
#define rm_leaf rm_rmu.rmu_leaf		/* extra field would make 32 bytes */

struct radix_node_head {
	struct	radix_node *rnh_treetop;
	i32	rnh_addrsize;		/* permit, but not require fixed keys */
	i32	rnh_pktsize;		/* permit, but not require fixed keys */
	struct	radix_node *(*rnh_addaddr)	/* add based on sockaddr */
		(const void *v, const void *mask,
		     struct radix_node_head *head, struct radix_node nodes[]);
	struct	radix_node *(*rnh_addpkt)	/* add based on packet hdr */
		(const void *v, const void *mask,
		     struct radix_node_head *head, struct radix_node nodes[]);
	struct	radix_node *(*rnh_deladdr)	/* remove based on sockaddr */
		(const void *v, const void *mask, struct radix_node_head *head);
	struct	radix_node *(*rnh_delpkt)	/* remove based on packet hdr */
		(const void *v, const void *mask, struct radix_node_head *head);
	struct	radix_node *(*rnh_matchaddr)	/* locate based on sockaddr */
		(const void *v, struct radix_node_head *head);
	struct	radix_node *(*rnh_lookup)	/* locate based on sockaddr */
		(const void *v, const void *mask, struct radix_node_head *head);
	struct	radix_node *(*rnh_matchpkt)	/* locate based on packet hdr */
		(const void *v, struct radix_node_head *head);
	struct	radix_node rnh_nodes[3];	/* empty tree for common case */
};

void	rn_init(void);
int	rn_inithead(void **, int);
void	rn_delayedinit(void **, int);
int	rn_inithead0(struct radix_node_head *, int);
int	rn_refines(const void *, const void *);
int	rn_walktree(struct radix_node_head *,
	            int (*)(struct radix_node *, void *),
		    void *);
struct radix_node *
	rn_search_matched(struct radix_node_head *,
	                  int (*)(struct radix_node *, void *),
		          void *);
struct radix_node
	 *rn_addmask(const void *, int, int),
	 *rn_addroute(const void *, const void *, struct radix_node_head *,
			struct radix_node [2]),
	 *rn_delete1(const void *, const void *, struct radix_node_head *,
			struct radix_node *),
	 *rn_delete(const void *, const void *, struct radix_node_head *),
	 *rn_insert(const void *, struct radix_node_head *, int *,
			struct radix_node [2]),
	 *rn_lookup(const void *, const void *, struct radix_node_head *),
	 *rn_match(const void *, struct radix_node_head *),
	 *rn_newpair(const void *, int, struct radix_node[2]),
	 *rn_search(const void *, struct radix_node *),
	 *rn_search_m(const void *, struct radix_node *, const void *);

#endif /* !_NET_RADIX_H_ */
