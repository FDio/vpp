/*
 *------------------------------------------------------------------
 * Copyright (c) 2020 Intel and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifndef _IAVF_FDIR_LIB_H_
#define _IAVF_FDIR_LIB_H_

#define IAVF_SUCCESS (0)
#define IAVF_FAILURE (-1)

/* These macros are used to generate compilation errors if a structure/union
 * is not exactly the correct length. It gives a divide by zero error if the
 * structure/union is not of the correct size, otherwise it creates an enum
 * that is never used.
 */
#define VIRTCHNL_CHECK_STRUCT_LEN(n, X)                                     \
  enum virtchnl_static_assert_enum_##X                                      \
  {                                                                         \
    virtchnl_static_assert_##X = (n) / ((sizeof (struct X) == (n)) ? 1 : 0) \
  }
#define VIRTCHNL_CHECK_UNION_LEN(n, X)                                     \
  enum virtchnl_static_asset_enum_##X                                      \
  {                                                                        \
    virtchnl_static_assert_##X = (n) / ((sizeof (union X) == (n)) ? 1 : 0) \
  }

struct virtchnl_proto_hdr
{
  enum virtchnl_proto_hdr_type type;
  u32 field_selector;		/* a bit mask to select field for header type */
  u8 buffer[64];
  /**
   * binary buffer in network order for specific header type.
   * For example, if type = VIRTCHNL_PROTO_HDR_IPV4, a IPv4
   * header is expected to be copied into the buffer.
   */
};

VIRTCHNL_CHECK_STRUCT_LEN (72, virtchnl_proto_hdr);

struct virtchnl_proto_hdrs
{
  u8 tunnel_level;
  /**
   * specify where protocol header start from.
   * 0 - from the outer layer
   * 1 - from the first inner layer
   * 2 - from the second inner layer
   * ....
   **/
  int count;			/* the proto layers must < VIRTCHNL_MAX_NUM_PROTO_HDRS */
  struct virtchnl_proto_hdr proto_hdr[VIRTCHNL_MAX_NUM_PROTO_HDRS];
};

VIRTCHNL_CHECK_STRUCT_LEN (2312, virtchnl_proto_hdrs);

/* VIRTCHNL_OP_CONFIG_RSS_KEY
 * VIRTCHNL_OP_CONFIG_RSS_LUT
 * VF sends these messages to configure RSS. Only supported if both PF
 * and VF drivers set the VIRTCHNL_VF_OFFLOAD_RSS_PF bit during
 * configuration negotiation. If this is the case, then the RSS fields in
 * the VF resource struct are valid.
 * Both the key and LUT are initialized to 0 by the PF, meaning that
 * RSS is effectively disabled until set up by the VF.
 */
struct virtchnl_rss_key
{
  u16 vsi_id;
  u16 key_len;
  u8 key[1];			/* RSS hash key, packed bytes */
};

VIRTCHNL_CHECK_STRUCT_LEN (6, virtchnl_rss_key);

struct virtchnl_rss_lut
{
  u16 vsi_id;
  u16 lut_entries;
  u8 lut[1];			/* RSS lookup table */
};

VIRTCHNL_CHECK_STRUCT_LEN (6, virtchnl_rss_lut);

/* VIRTCHNL_OP_GET_RSS_HENA_CAPS
 * VIRTCHNL_OP_SET_RSS_HENA
 * VF sends these messages to get and set the hash filter enable bits for RSS.
 * By default, the PF sets these to all possible traffic types that the
 * hardware supports. The VF can query this value if it wants to change the
 * traffic types that are hashed by the hardware.
 */
struct virtchnl_rss_hena
{
  u64 hena;
};

VIRTCHNL_CHECK_STRUCT_LEN (8, virtchnl_rss_hena);

/* Type of RSS algorithm */
enum virtchnl_rss_algorithm
{
  VIRTCHNL_RSS_ALG_TOEPLITZ_ASYMMETRIC = 0,
  VIRTCHNL_RSS_ALG_XOR_ASYMMETRIC = 1,
  VIRTCHNL_RSS_ALG_TOEPLITZ_SYMMETRIC = 2,
  VIRTCHNL_RSS_ALG_XOR_SYMMETRIC = 3,
};

struct virtchnl_rss_cfg
{
  struct virtchnl_proto_hdrs proto_hdrs;	/* protocol headers */
  enum virtchnl_rss_algorithm rss_algorithm;	/* rss algorithm type */
  u8 reserved[128];		/* reserve for future */
};

VIRTCHNL_CHECK_STRUCT_LEN (2444, virtchnl_rss_cfg);

enum virtchnl_action
{
  /* action types */
  VIRTCHNL_ACTION_DROP = 0,
  VIRTCHNL_ACTION_TC_REDIRECT,
  VIRTCHNL_ACTION_PASSTHRU,
  VIRTCHNL_ACTION_QUEUE,
  VIRTCHNL_ACTION_Q_REGION,
  VIRTCHNL_ACTION_MARK,
  VIRTCHNL_ACTION_COUNT,
  VIRTCHNL_ACTION_NONE,
};

/* action configuration for FDIR */
struct virtchnl_filter_action
{
  enum virtchnl_action type;
  union
  {
    /* used for queue and qgroup action */
    struct
    {
      u16 index;
      u8 region;
    } queue;
    /* used for count action */
    struct
    {
      /* share counter ID with other flow rules */
      u8 shared;
      u32 id;			/* counter ID */
    } count;
    /* used for mark action */
    u32 mark_id;
    u8 reserve[32];
  } act_conf;
};

VIRTCHNL_CHECK_STRUCT_LEN (36, virtchnl_filter_action);

#define VIRTCHNL_MAX_NUM_ACTIONS 8

struct virtchnl_filter_action_set
{
  /* action number must be less then VIRTCHNL_MAX_NUM_ACTIONS */
  int count;
  struct virtchnl_filter_action actions[VIRTCHNL_MAX_NUM_ACTIONS];
};

VIRTCHNL_CHECK_STRUCT_LEN (292, virtchnl_filter_action_set);

/* pattern and action for FDIR rule */
struct virtchnl_fdir_rule
{
  struct virtchnl_proto_hdrs proto_hdrs;
  struct virtchnl_filter_action_set action_set;
};

VIRTCHNL_CHECK_STRUCT_LEN (2604, virtchnl_fdir_rule);

/* query information to retrieve fdir rule counters.
 * PF will fill out this structure to reset counter.
 */
struct virtchnl_fdir_query_info
{
  u32 match_packets_valid:1;
  u32 match_bytes_valid:1;
  u32 reserved:30;		/* Reserved, must be zero. */
  u32 pad;
  u64 matched_packets;		/* Number of packets for this rule. */
  u64 matched_bytes;		/* Number of bytes through this rule. */
};

VIRTCHNL_CHECK_STRUCT_LEN (24, virtchnl_fdir_query_info);

/* Status returned to VF after VF requests FDIR commands
 * VIRTCHNL_FDIR_SUCCESS
 * VF FDIR related request is successfully done by PF
 * The request can be OP_ADD/DEL/QUERY_FDIR_FILTER.
 *
 * VIRTCHNL_FDIR_FAILURE_RULE_NORESOURCE
 * OP_ADD_FDIR_FILTER request is failed due to no Hardware resource.
 *
 * VIRTCHNL_FDIR_FAILURE_RULE_EXIST
 * OP_ADD_FDIR_FILTER request is failed due to the rule is already existed.
 *
 * VIRTCHNL_FDIR_FAILURE_RULE_CONFLICT
 * OP_ADD_FDIR_FILTER request is failed due to conflict with existing rule.
 *
 * VIRTCHNL_FDIR_FAILURE_RULE_NONEXIST
 * OP_DEL_FDIR_FILTER request is failed due to this rule doesn't exist.
 *
 * VIRTCHNL_FDIR_FAILURE_RULE_INVALID
 * OP_ADD_FDIR_FILTER request is failed due to parameters validation
 * or HW doesn't support.
 *
 * VIRTCHNL_FDIR_FAILURE_RULE_TIMEOUT
 * OP_ADD/DEL_FDIR_FILTER request is failed due to timing out
 * for programming.
 *
 * VIRTCHNL_FDIR_FAILURE_QUERY_INVALID
 * OP_QUERY_FDIR_FILTER request is failed due to parameters validation,
 * for example, VF query counter of a rule who has no counter action.
 */
enum virtchnl_fdir_prgm_status
{
  VIRTCHNL_FDIR_SUCCESS = 0,
  VIRTCHNL_FDIR_FAILURE_RULE_NORESOURCE,
  VIRTCHNL_FDIR_FAILURE_RULE_EXIST,
  VIRTCHNL_FDIR_FAILURE_RULE_CONFLICT,
  VIRTCHNL_FDIR_FAILURE_RULE_NONEXIST,
  VIRTCHNL_FDIR_FAILURE_RULE_INVALID,
  VIRTCHNL_FDIR_FAILURE_RULE_TIMEOUT,
  VIRTCHNL_FDIR_FAILURE_QUERY_INVALID,
  VIRTCHNL_FDIR_FAILURE_MAX,
};

/* VIRTCHNL_OP_ADD_FDIR_FILTER
 * VF sends this request to PF by filling out vsi_id,
 * validate_only and rule_cfg. PF will return flow_id
 * if the request is successfully done and return add_status to VF.
 */
struct virtchnl_fdir_add
{
  u16 vsi_id;			/* INPUT */
  /*
   * 1 for validating a fdir rule, 0 for creating a fdir rule.
   * Validate and create share one ops: VIRTCHNL_OP_ADD_FDIR_FILTER.
   */
  u16 validate_only;		/* INPUT */
  u32 flow_id;			/* OUTPUT */
  struct virtchnl_fdir_rule rule_cfg;	/* INPUT */
  enum virtchnl_fdir_prgm_status status;	/* OUTPUT */
};

VIRTCHNL_CHECK_STRUCT_LEN (2616, virtchnl_fdir_add);

/* VIRTCHNL_OP_DEL_FDIR_FILTER
 * VF sends this request to PF by filling out vsi_id
 * and flow_id. PF will return del_status to VF.
 */
struct virtchnl_fdir_del
{
  u16 vsi_id;			/* INPUT */
  u16 pad;
  u32 flow_id;			/* INPUT */
  enum virtchnl_fdir_prgm_status status;	/* OUTPUT */
};

VIRTCHNL_CHECK_STRUCT_LEN (12, virtchnl_fdir_del);

/* VIRTCHNL_OP_QUERY_FDIR_FILTER
 * VF sends this request to PF by filling out vsi_id,
 * flow_id and reset_counter. PF will return query_info
 * and query_status to VF.
 */
struct virtchnl_fdir_query
{
  u16 vsi_id;			/* INPUT */
  u16 pad1[3];
  u32 flow_id;			/* INPUT */
  u32 reset_counter:1;		/* INPUT */
  struct virtchnl_fdir_query_info query_info;	/* OUTPUT */
  enum virtchnl_fdir_prgm_status status;	/* OUTPUT */
  u32 pad2;
};

VIRTCHNL_CHECK_STRUCT_LEN (48, virtchnl_fdir_query);

/**
 * Those headers used temporary, maybe OS packet
 * definition can replace. Add flow error, pattern
 * and action definition.
 */

/**
 * Verbose error types.
 *
 * Most of them provide the type of the object referenced by struct
 * rte_flow_error.cause.
 */
enum iavf_flow_error_type
{
  IAVF_FLOW_ERROR_TYPE_NONE,	      /**< No error. */
  IAVF_FLOW_ERROR_TYPE_UNSPECIFIED,   /**< Cause unspecified. */
  IAVF_FLOW_ERROR_TYPE_HANDLE,	      /**< Flow rule (handle). */
  IAVF_FLOW_ERROR_TYPE_ATTR_GROUP,    /**< Group field. */
  IAVF_FLOW_ERROR_TYPE_ATTR_PRIORITY, /**< Priority field. */
  IAVF_FLOW_ERROR_TYPE_ATTR_INGRESS,  /**< Ingress field. */
  IAVF_FLOW_ERROR_TYPE_ATTR_EGRESS,   /**< Egress field. */
  IAVF_FLOW_ERROR_TYPE_ATTR_TRANSFER, /**< Transfer field. */
  IAVF_FLOW_ERROR_TYPE_ATTR,	      /**< Attributes structure. */
  IAVF_FLOW_ERROR_TYPE_ITEM_NUM,      /**< Pattern length. */
  IAVF_FLOW_ERROR_TYPE_ITEM_SPEC,     /**< Item specification. */
  IAVF_FLOW_ERROR_TYPE_ITEM_LAST,     /**< Item specification range. */
  IAVF_FLOW_ERROR_TYPE_ITEM_MASK,     /**< Item specification mask. */
  IAVF_FLOW_ERROR_TYPE_ITEM,	      /**< Specific pattern item. */
  IAVF_FLOW_ERROR_TYPE_ACTION_NUM,    /**< Number of actions. */
  IAVF_FLOW_ERROR_TYPE_ACTION_CONF,   /**< Action configuration. */
  IAVF_FLOW_ERROR_TYPE_ACTION,	      /**< Specific action. */
};

/**
 * Verbose error structure definition.
 * Both cause and message may be NULL regardless of the error type.
 */
struct iavf_flow_error
{
  enum iavf_flow_error_type type; /**< Cause field and error types. */
  const void *cause;		  /**< Object responsible for the error. */
  const char *message;		  /**< Human-readable error message. */
};

/**
 * Hash function types.
 */
enum iavf_eth_hash_function
{
  IAVF_ETH_HASH_FUNCTION_DEFAULT = 0,
  IAVF_ETH_HASH_FUNCTION_TOEPLITZ,   /**< Toeplitz */
  IAVF_ETH_HASH_FUNCTION_SIMPLE_XOR, /**< Simple XOR */
  /**
   * Symmetric Toeplitz: src, dst will be replaced by
   * xor(src, dst). For the case with src/dst only,
   * src or dst address will xor with zero pair.
   */
  IAVF_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ,
  IAVF_ETH_HASH_FUNCTION_MAX,
};

struct iavf_flow_action_rss
{
  enum iavf_eth_hash_function func; /**< RSS hash function to apply. */

  u32 level;
  u64 types;	    /**< Specific RSS hash types (see ETH_RSS_*). */
  u32 key_len;	    /**< Hash key length in bytes. */
  u32 queue_num;    /**< Number of entries in @p queue. */
  const u8 *key;    /**< Hash key. */
  const u16 *queue; /**< Queue indices to use. */
};

struct iavf_flow_action_queue
{
  u16 index; /**< Queue index to use. */
};

struct iavf_flow_item
{
  enum virtchnl_proto_hdr_type type; /**< Item type. */
  const void *spec; /**< Pointer to item specification structure. */
  const void *mask; /**< Bit-mask applied to spec and last. */
};

struct iavf_flow_action
{
  enum virtchnl_action type; /**< Action type. */
  const void *conf;	     /**< Pointer to action configuration object. */
};

struct iavf_fdir_conf
{
  struct virtchnl_fdir_add add_fltr;
  struct virtchnl_fdir_del del_fltr;
  u64 input_set;
  u32 flow_id;
  u32 mark_flag;
  u32 vsi;
  u32 nb_rx_queues;
};

/**
 * Create a rule cfg object.
 *
 * @param rcfg
 * 	created rule cfg object.
 * @param tunnel
 * 	tunnel level where protocol header start from
 * 	0 from moster outer layer.
 * 	1 from first inner layer.
 * 	2 form second inner layer.
 * 	...
 * @param vsi
 * 	avf vsi id
 *
 * @param nrxq
 * 	the rx queue number of the avf
 *
 * @return
 * 	0 = successful.
 * 	< 0 = failure.
 */
int iavf_fdir_rcfg_create (struct iavf_fdir_conf **rcfg, int tunnel_level,
			   u16 vsi, u16 nrxq);

/**
 * Destroy a rule cfg object.
 *
 * @param rcfg
 * 	the cfg object to destroy.
 *
 * @return
 * 	0 = successful.
 * 	< 0 = failure.
 */
int iavf_fdir_rcfg_destroy (struct iavf_fdir_conf *rcfg);

/**
 * Set match potocol header on specific layer, it will overwrite is already be
 * set.
 *
 * @param rcfg
 * 	the rule cfg object
 * @param layer
 * 	layer of the protocol header.
 * @param hdr
 * 	protocol header type.
 *
 * @return
 * 	0 = successful.
 * 	< 0 = failure.
 */
int iavf_fdir_rcfg_set_hdr (struct iavf_fdir_conf *rcfg, int layer,
			    enum virtchnl_proto_hdr_type hdr);

/**
 * Set a match field on specific protocol layer, if any match field already be
 * set on this layer, it will be overwritten.
 *
 * @param rcfg
 * 	the rule cfg object
 * @param layer
 * 	layer of the protocol header.
 * @param item
 * 	flow item
 * @param error
 *	save error cause
 *
 * @return
 * 	0 = successful.
 * 	< 0 = failure.
 */
int iavf_fdir_rcfg_set_field (struct iavf_fdir_conf *rcfg, int layer,
			      struct iavf_flow_item *item,
			      struct iavf_flow_error *error);

/**
 * Set action as to queue(group), conflict with drop action.
 *
 * @param rcfg
 * 	rule cfg object
 * @param queue
 * 	queue id.
 * @param size
 *	queue group size, must be 2^n. 1 means only to single queue.
 * @param act_idx
 * 	action index
 *
 * @return
 * 	0 = successful.
 * 	< 0 = failure.
 */
int iavf_fdir_rcfg_act_queue (struct iavf_fdir_conf *rcfg, int queue,
			      int size, int act_idx);

/**
 * Set action as to queue group, conflict with drop action.
 *
 * @param rcfg
 * 	the rule cfg object
 * @param act
 * 	flow actions
 * @param act_idx
 * 	action index
 * @error
 *	save error cause
 *
 * @return
 * 	0 = successful.
 * 	< 0 = failure.
 */
int iavf_fdir_parse_action_qregion (struct iavf_fdir_conf *rcfg,
				    const struct iavf_flow_action *act,
				    int act_idx,
				    struct iavf_flow_error *error);

/**
 * Set action as as drop, conflict with to queue(gropu) action.
 *
 * @param rcfg
 * 	the rule cfg object
 * @param act_idx
 * 	action index
 *
 * @return
 * 	0 = successful.
 * 	< 0 = failure.
 */
int iavf_fdir_rcfg_act_drop (struct iavf_fdir_conf *rcfg, int act_idx);

/**
 * Set action as mark, it can co-exist with to queue(group) or drop action.
 *
 * @param rcfg
 * 	the rule cfg object
 * @param mark
 * 	a 32 bit flow mark
 * @param act_idx
 * 	action index
 *
 * @return
 * 	0 = successful.
 * 	< 0 = failure.
 */
int iavf_fdir_rcfg_act_mark (struct iavf_fdir_conf *rcfg, const u32 mark,
			     int act_idx);

/**
 * Validate a flow rule cfg, check with PF driver if the rule cfg is supportted
 *or not.
 *
 * @param ctx
 *	 virtual channel context
 * @param rcfg
 * 	the rule cfg object.
 *
 * @return
 * 	0 = successful.
 * 	< 0 = failure.
 */
int iavf_fdir_rcfg_validate (struct iavf_fdir_vc_ctx *ctx,
			     struct iavf_fdir_conf *rcfg);

/**
 * Create a flow rule, a FDIR rule is expected to be programmed into hardware
 *if return success.
 *
 * @param ctx
 *	 virtual channel context
 * @param rcfg
 * 	rule cfg object.
 *
 * @return
 * 	0 = successfule.
 * 	< 0 = failure.
 */
int iavf_fdir_rule_create (struct iavf_fdir_vc_ctx *ctx,
			   struct iavf_fdir_conf *rcfg);

/**
 * Destroy a flow rule.
 *
 * @param ctx
 *	 virtual channel context
 * @param rcfg
 * 	the rule cfg object.
 *
 * @return
 * 	0 = successfule.
 * 	< 0 = failure.
 */
int iavf_fdir_rule_destroy (struct iavf_fdir_vc_ctx *ctx,
			    struct iavf_fdir_conf *rcfg);

/*
 * Parse iavf patterns and set pattern fields.
 *
 * @param rcfg
 * 	flow config
 * @param iavf_items
 * 	pattern items
 * @param error
 * 	save error cause
 *
 * @return
 *	0 = successful.
 *	< 0 = failure
 */
int iavf_fdir_parse_pattern (struct iavf_fdir_conf *rcfg,
			     struct iavf_flow_item iavf_items[],
			     struct iavf_flow_error *error);

/*
 * Parse flow actions, set actions.
 *
 * @param actions
 * 	flow actions
 * @param rcfg
 * 	flow config
 * @param error
 * 	save error cause
 *
 * @return
 *  0 = successful.
 *  < 0 = failure
 */
int iavf_fdir_parse_action (const struct iavf_flow_action actions[],
			    struct iavf_fdir_conf *rcfg,
			    struct iavf_flow_error *error);

/**
 * Initialize flow error structure.
 *
 * @param[out] error
 *   Pointer to flow error structure (may be NULL).
 * @param code
 *   Related error code
 * @param type
 *   Cause field and error types.
 * @param cause
 *   Object responsible for the error.
 * @param message
 *   Human-readable error message.
 *
 * @return
 *   Negative error code (errno value)
 */
int iavf_flow_error_set (struct iavf_flow_error *error, int code,
			 enum iavf_flow_error_type type, const void *cause,
			 const char *message);

/*
 * decode the error number to Verbose error string
 *
 * @param err_no
 *  error number
 *
 * @return
 *  Verbose error string
 */
char *iavf_fdir_prgm_error_decode (int err_no);

#endif /* _IAVF_FDIR_LIB_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
