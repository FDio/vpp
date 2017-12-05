#ifndef included_vnet_pfcp_h
#define included_vnet_pfcp_h

#include <features.h>
#include <stdbool.h>
#include <sys/types.h>

#include <vnet/ethernet/mac_address.h>
#include <vnet/ip/ip.h>

#define BIT(n)              (1LLU << (n))
#define SET_BIT(mask, n)    ((mask) |= BIT(n))
#define RESET_BIT(mask, n)  ((mask) &= ~BIT(n))
#define ISSET_BIT(mask, n)  (!!((mask) & BIT(n)))

typedef struct __attribute__ ((packed))
{
  u8 sequence[3];
  u8 spare;
  u8 ies[];
} pfcp_node_msg_header_t;

typedef struct __attribute__ ((packed))
{
  u64 seid;
  u8 sequence[3];
#if __BYTE_ORDER == __LITTLE_ENDIAN
  u8 spare:4;
  u8 priority:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
  u8 priority:4;
  u8 spare:4;
#else
# error "Please fix <bits/endian.h>"
#endif
  u8 ies[];
} pfcp_session_msg_header_t;

typedef struct __attribute__ ((packed))
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
  u8 s_flag:1;
  u8 mp_flag:1;
  u8 spare:3;
  u8 version:3;
#elif __BYTE_ORDER == __BIG_ENDIAN
  u8 version:3;
  u8 spare:3;
  u8 mp_flag:1;
  u8 s_flag:1;
#else
# error "Please fix <bits/endian.h>"
#endif
  u8 type;
  u16 length;                   /* length in octets of the payload */
  union {
    pfcp_node_msg_header_t msg_hdr;
    pfcp_session_msg_header_t session_hdr;
  };
} pfcp_header_t;

#define NODE_MSG_HDR_LEN (offsetof(pfcp_header_t, msg_hdr.ies))
#define SESSION_MSG_HDR_LEN (offsetof(pfcp_header_t, session_hdr.ies))

typedef struct __attribute__ ((packed))
{
  u16 type;
  u16 length;
} pfcp_ie_t;

typedef struct __attribute__ ((packed))
{
  u16 type;
  u16 length;
  u16 vendor;
} pfcp_ie_vendor_t;

struct pfcp_group {
  u32 fields;
  pfcp_ie_t **ies;
};

struct pfcp_group_ie_def {
  u16 type;
  bool is_array;
  ptrdiff_t offset;
};

struct pfcp_ie_def {
  ssize_t length;
  u8 size;
  union {
    struct {
      u32 mandatory;
      struct pfcp_group_ie_def *group;
    };
    struct {
      u8 * (* format)(u8 *, va_list *);
      int (* decode)(u8 *, u16 length, void *);
      int (* encode)(void *, u8 **);
      void (* free)(void *);
    };
  };
};

typedef struct {
  u8 fields;
  u64 total;
  u64 ul;
  u64 dl;
} pfcp_volume_ie_t;

typedef struct {
  u8 unit;
  u8 value;
} pfcp_timer_ie_t;

/* PFCP Information Elements */

#define PFCP_IE_CREATE_PDR				1
#define PFCP_IE_PDI					2
#define PFCP_IE_CREATE_FAR				3
#define PFCP_IE_FORWARDING_PARAMETERS			4
#define PFCP_IE_DUPLICATING_PARAMETERS			5
#define PFCP_IE_CREATE_URR				6
#define PFCP_IE_CREATE_QER				7
#define PFCP_IE_CREATED_PDR				8
#define PFCP_IE_UPDATE_PDR				9
#define PFCP_IE_UPDATE_FAR				10
#define PFCP_IE_UPDATE_FORWARDING_PARAMETERS		11
#define PFCP_IE_UPDATE_BAR_RESPONSE			12
#define PFCP_IE_UPDATE_URR				13
#define PFCP_IE_UPDATE_QER				14
#define PFCP_IE_REMOVE_PDR				15
#define PFCP_IE_REMOVE_FAR				16
#define PFCP_IE_REMOVE_URR				17
#define PFCP_IE_REMOVE_QER				18

#define PFCP_IE_CAUSE					19
typedef u8 pfcp_cause_t;
#define PFCP_CAUSE_RESERVED				0
#define PFCP_CAUSE_REQUEST_ACCEPTED			1
#define PFCP_CAUSE_REQUEST_REJECTED			64
#define PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND		65
#define PFCP_CAUSE_MANDATORY_IE_MISSING			66
#define PFCP_CAUSE_CONDITIONAL_IE_MISSING		67
#define PFCP_CAUSE_INVALID_LENGTH			68
#define PFCP_CAUSE_MANDATORY_IE_INCORRECT		69
#define PFCP_CAUSE_INVALID_FORWARDING_POLICY		70
#define PFCP_CAUSE_INVALID_F_TEID_ALLOCATION_OPTION	71
#define PFCP_CAUSE_NO_ESTABLISHED_SX_ASSOCIATION	72
#define PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE	73
#define PFCP_CAUSE_PFCP_ENTITY_IN_CONGESTION		74
#define PFCP_CAUSE_NO_RESOURCES_AVAILABLE		75
#define PFCP_CAUSE_SERVICE_NOT_SUPPORTED		76
#define PFCP_CAUSE_SYSTEM_FAILURE			77

#define PFCP_IE_SOURCE_INTERFACE			20
typedef u8 pfcp_source_interface_t;

#define SRC_INTF_ACCESS		0
#define SRC_INTF_CORE		1
#define SRC_INTF_SGI_LAN	2
#define SRC_INTF_CP		3
#define SRC_INTF_NUM		(SRC_INTF_CP + 1)

#define PFCP_IE_F_TEID					21
typedef struct {
  u8 flags;
#define F_TEID_V4					BIT(0)
#define F_TEID_V6					BIT(1)
#define F_TEID_CH					BIT(2)
#define F_TEID_CHID					BIT(3)

  u32 teid;
  ip4_address_t ip4;
  ip6_address_t ip6;
  u8 choose_id;
} pfcp_f_teid_t;

#define PFCP_IE_NETWORK_INSTANCE			22
typedef u8 * pfcp_network_instance_t;

#define PFCP_IE_SDF_FILTER				23
typedef struct {
    u8 flags;
#define F_SDF_FD					BIT(0)
#define F_SDF_TTC					BIT(1)
#define F_SDF_SPI					BIT(2)
#define F_SDF_FL					BIT(3)
#define F_SDF_BID					BIT(4)

  u8 * flow;
  u16 tos_traffic_class;
  u32 spi;
  u32 flow_label;
  u32 sdf_filter_id;
} pfcp_sdf_filter_t;

#define PFCP_IE_APPLICATION_ID				24
typedef u8 * pfcp_application_id_t;

#define PFCP_IE_GATE_STATUS				25
typedef struct {
  u8 ul;
  u8 dl;
} pfcp_gate_status_t;

typedef struct {
  u32 ul;
  u32 dl;
} pfcp_bit_rate_t;

#define PFCP_IE_MBR					26
typedef pfcp_bit_rate_t pfcp_mbr_t;

#define PFCP_IE_GBR					27
typedef pfcp_bit_rate_t pfcp_gbr_t;

#define PFCP_IE_QER_CORRELATION_ID			28
typedef u32 pfcp_qer_correlation_id_t;

#define PFCP_IE_PRECEDENCE				29
typedef u32 pfcp_precedence_t;

#define PFCP_IE_TRANSPORT_LEVEL_MARKING			30
typedef u16 pfcp_transport_level_marking_t;

#define PFCP_IE_VOLUME_THRESHOLD			31
typedef pfcp_volume_ie_t pfcp_volume_threshold_t;

#define PFCP_IE_TIME_THRESHOLD				32
typedef u32 pfcp_time_threshold_t;

#define PFCP_IE_MONITORING_TIME				33
typedef u32 pfcp_monitoring_time_t;

#define PFCP_IE_SUBSEQUENT_VOLUME_THRESHOLD		34
typedef u32 pfcp_subsequent_volume_threshold_t;

#define PFCP_IE_SUBSEQUENT_TIME_THRESHOLD		35
typedef u32 pfcp_subsequent_time_threshold_t;

#define PFCP_IE_INACTIVITY_DETECTION_TIME		36
typedef u32 pfcp_inactivity_detection_time_t;

#define PFCP_IE_REPORTING_TRIGGERS			37
typedef u32 pfcp_reporting_triggers_t;

#define REPORTING_TRIGGER_PERIODIC_REPORTING		BIT(0)
#define REPORTING_TRIGGER_VOLUME_THRESHOLD		BIT(1)
#define REPORTING_TRIGGER_TIME_THRESHOLD		BIT(2)
#define REPORTING_TRIGGER_QUOTA_HOLDING_TIME		BIT(3)
#define REPORTING_TRIGGER_START_OF_TRAFFIC		BIT(4)
#define REPORTING_TRIGGER_STOP_OF_TRAFFIC		BIT(5)
#define REPORTING_TRIGGER_DROPPED_DL_TRAFFIC_THRESHOLD	BIT(6)
#define REPORTING_TRIGGER_LINKED_USAGE_REPORTING	BIT(7)
#define REPORTING_TRIGGER_VOLUME_QUOTA			BIT(8)
#define REPORTING_TRIGGER_TIME_QUOTA			BIT(9)
#define REPORTING_TRIGGER_ENVELOPE_CLOSURE		BIT(10)
#define REPORTING_TRIGGER_MAC_ADDRESSES_REPORTING	BIT(11)

#define PFCP_IE_REDIRECT_INFORMATION			38
typedef struct {
  u8 type;
#define REDIRECT_INFORMATION_IPv4 0
#define REDIRECT_INFORMATION_IPv6 1
#define REDIRECT_INFORMATION_HTTP 2
#define REDIRECT_INFORMATION_SIP  3

  union {
    ip46_address_t ip;
    u8 *uri;
  };
} pfcp_redirect_information_t;

#define PFCP_IE_REPORT_TYPE				39
typedef u8 pfcp_report_type_t;

#define REPORT_TYPE_DLDR				BIT(0)
#define REPORT_TYPE_USAR				BIT(1)
#define REPORT_TYPE_ERIR				BIT(2)
#define REPORT_TYPE_UPIR				BIT(3)

#define PFCP_IE_OFFENDING_IE				40
typedef u32 pfcp_offending_ie_t;

#define PFCP_IE_FORWARDING_POLICY			41
typedef struct {
  u8 * identifier;
} pfcp_forwarding_policy_t;

#define PFCP_IE_DESTINATION_INTERFACE			42
typedef u8 pfcp_destination_interface_t;

#define PFCP_IE_UP_FUNCTION_FEATURES			43
typedef u16 pfcp_up_function_features_t;
#define F_UPFF_BUCP					BIT(0)
#define F_UPFF_DDND					BIT(1)
#define F_UPFF_DLBD					BIT(2)
#define F_UPFF_TRST					BIT(3)
#define F_UPFF_FTUP					BIT(4)
#define F_UPFF_PFDM					BIT(5)
#define F_UPFF_HEEU					BIT(6)
#define F_UPFF_TREU					BIT(7)
#define F_UPFF_EMPU					BIT(8)
#define F_UPFF_PDIU					BIT(9)
#define F_UPFF_UDBC					BIT(10)
#define F_UPFF_QUOAC					BIT(11)

#define PFCP_IE_APPLY_ACTION				44
typedef u8 pfcp_apply_action_t;
#define F_APPLY_DROP					BIT(0)
#define F_APPLY_FORW					BIT(1)
#define F_APPLY_BUFF					BIT(2)
#define F_APPLY_NOCP					BIT(3)
#define F_APPLY_DUPL					BIT(4)


#define PFCP_IE_DOWNLINK_DATA_SERVICE_INFORMATION	45
typedef struct {
  u8 flags;
#define F_DDSI_PPI					BIT(0)

  u8 paging_policy_indication;
} pfcp_downlink_data_service_information_t;

#define PFCP_IE_DOWNLINK_DATA_NOTIFICATION_DELAY	46
typedef u8 pfcp_downlink_data_notification_delay_t;

#define PFCP_IE_DL_BUFFERING_DURATION			47
typedef pfcp_timer_ie_t pfcp_dl_buffering_duration_t;

#define PFCP_IE_DL_BUFFERING_SUGGESTED_PACKET_COUNT	48
typedef u16 pfcp_dl_buffering_suggested_packet_count_t;

#define PFCP_IE_SXSMREQ_FLAGS				49
typedef u8 pfcp_sxsmreq_flags_t;
#define SXSMREQ_DROBU					BIT(0)
#define SXSMREQ_SNDEM					BIT(1)
#define SXSMREQ_QAURR					BIT(2)

#define PFCP_IE_SXSRRSP_FLAGS				50
typedef u8 pfcp_sxsrrsp_flags_t;
#define SXSRRSP_DROBU					BIT(0)

#define PFCP_IE_LOAD_CONTROL_INFORMATION		51

#define PFCP_IE_SEQUENCE_NUMBER				52
typedef u32 pfcp_sequence_number_t;

#define PFCP_IE_METRIC					53
typedef u32 pfcp_metric_t;

#define PFCP_IE_OVERLOAD_CONTROL_INFORMATION		54

#define PFCP_IE_TIMER					55
typedef u32 pfcp_timer_t;

#define PFCP_IE_PDR_ID					56
typedef u16 pfcp_pdr_id_t;

#define PFCP_IE_F_SEID					57
typedef struct {
  u8 flags;
#define IE_F_SEID_IP_ADDRESS_V4				BIT(1)
#define IE_F_SEID_IP_ADDRESS_V6				BIT(0)

  u64 seid;
  ip4_address_t ip4;
  ip6_address_t ip6;
} pfcp_f_seid_t;

#define PFCP_IE_APPLICATION_ID_PFDS			58
#define PFCP_IE_PFD					59

#define PFCP_IE_NODE_ID					60
typedef struct {
  u8 type;
#define NID_IPv4 0
#define NID_IPv6 1
#define NID_FQDN 2

  union {
    ip46_address_t ip;
    u8 *fqdn;
  };
} pfcp_node_id_t;

#define PFCP_IE_PFD_CONTENTS				61
typedef struct {
  u8 flags;
#define F_PFD_C_FD					BIT(0)
#define F_PFD_C_URL					BIT(1)
#define F_PFD_C_DN					BIT(2)
#define F_PFD_C_CP					BIT(3)

  u8 * flow_description;
  u8 * url;
  u8 * domain;
  u8 * custom;
} pfcp_pfd_contents_t;

#define PFCP_IE_MEASUREMENT_METHOD			62
typedef u8 pfcp_measurement_method_t;

#define MEASUREMENT_METHOD_DURATION			BIT(0)
#define MEASUREMENT_METHOD_VOLUME			BIT(1)
#define MEASUREMENT_METHOD_EVENT			BIT(2)

#define PFCP_IE_USAGE_REPORT_TRIGGER			63
typedef u32 pfcp_usage_report_trigger_t;

#define USAGE_REPORT_TRIGGER_PERIODIC_REPORTING			BIT(0)
#define USAGE_REPORT_TRIGGER_VOLUME_THRESHOLD			BIT(1)
#define USAGE_REPORT_TRIGGER_TIME_THRESHOLD			BIT(2)
#define USAGE_REPORT_TRIGGER_QUOTA_HOLDING_TIME			BIT(3)
#define USAGE_REPORT_TRIGGER_START_OF_TRAFFIC			BIT(4)
#define USAGE_REPORT_TRIGGER_STOP_OF_TRAFFIC			BIT(5)
#define USAGE_REPORT_TRIGGER_DROPPED_DL_TRAFFIC_THRESHOLD	BIT(6)
#define USAGE_REPORT_TRIGGER_IMMEDIATE_REPORT			BIT(7)
#define USAGE_REPORT_TRIGGER_VOLUME_QUOTA			BIT(8)
#define USAGE_REPORT_TRIGGER_TIME_QUOTA				BIT(9)
#define USAGE_REPORT_TRIGGER_LINKED_USAGE_REPORTING		BIT(10)
#define USAGE_REPORT_TRIGGER_TERMINATION_REPORT			BIT(11)
#define USAGE_REPORT_TRIGGER_MONITORING_TIME			BIT(12)
#define USAGE_REPORT_TRIGGER_ENVELOPE_CLOSURE			BIT(13)

#define PFCP_IE_MEASUREMENT_PERIOD			64
typedef u32 pfcp_measurement_period_t;

#define PFCP_IE_FQ_CSID					65
typedef struct {
  u8 node_id_type;
#define FQ_CSID_NID_IP4					0
#define FQ_CSID_NID_IP6					1
#define FQ_CSID_NID_NID					2
  union {
    ip46_address_t ip;
    struct {
      u16 mcc;
      u16 mnc;
      u16 nid;
    };
  } node_id;
  u16 * csid;
} pfcp_fq_csid_t;

#define PFCP_IE_VOLUME_MEASUREMENT			66
typedef pfcp_volume_threshold_t pfcp_volume_measurement_t;

#define PFCP_IE_DURATION_MEASUREMENT			67
typedef u32 pfcp_duration_measurement_t;

#define PFCP_IE_APPLICATION_DETECTION_INFORMATION	68

#define PFCP_IE_TIME_OF_FIRST_PACKET			69
typedef u32 pfcp_time_of_first_packet_t;

#define PFCP_IE_TIME_OF_LAST_PACKET			70
typedef u32 pfcp_time_of_last_packet_t;

#define PFCP_IE_QUOTA_HOLDING_TIME			71
typedef u32 pfcp_quota_holding_time_t;

#define PFCP_IE_DROPPED_DL_TRAFFIC_THRESHOLD		72
typedef struct {
  u16 flags;
#define DDTT_DLPA					BIT(0)

  u64 downlink_packets;
} pfcp_dropped_dl_traffic_threshold_t;

#define PFCP_IE_VOLUME_QUOTA				73
typedef pfcp_volume_ie_t pfcp_volume_quota_t;

#define PFCP_IE_TIME_QUOTA				74
typedef u32 pfcp_time_quota_t;

#define PFCP_IE_START_TIME				75
typedef u32 pfcp_start_time_t;

#define PFCP_IE_END_TIME				76
typedef u32 pfcp_end_time_t;

#define PFCP_IE_QUERY_URR				77
#define PFCP_IE_USAGE_REPORT_SMR			78
#define PFCP_IE_USAGE_REPORT_SDR			79
#define PFCP_IE_USAGE_REPORT_SRR			80

#define PFCP_IE_URR_ID					81
typedef u32 pfcp_urr_id_t;

#define PFCP_IE_LINKED_URR_ID				82
typedef u32 pfcp_linked_urr_id_t;

#define PFCP_IE_DOWNLINK_DATA_REPORT			83

#define PFCP_IE_OUTER_HEADER_CREATION			84
typedef struct {
  u16 description;
#define OUTER_HEADER_CREATION_GTP_IP4			BIT(0)
#define OUTER_HEADER_CREATION_GTP_IP6			BIT(1)
#define OUTER_HEADER_CREATION_UDP_IP4			BIT(2)
#define OUTER_HEADER_CREATION_UDP_IP6			BIT(3)
#define OUTER_HEADER_CREATION_GTP		\
  (OUTER_HEADER_CREATION_GTP_IP4 | OUTER_HEADER_CREATION_GTP_IP6)
#define OUTER_HEADER_CREATION_UDP		\
  (OUTER_HEADER_CREATION_UDP_IP4 | OUTER_HEADER_CREATION_UDP_IP6)
#define OUTER_HEADER_CREATION_IP4		\
  (OUTER_HEADER_CREATION_GTP_IP4 | OUTER_HEADER_CREATION_UDP_IP4)
#define OUTER_HEADER_CREATION_IP6		\
  (OUTER_HEADER_CREATION_GTP_IP6 | OUTER_HEADER_CREATION_UDP_IP6)

  u32 teid;
  ip4_address_t ip4;
  ip6_address_t ip6;
  u16 port;
} pfcp_outer_header_creation_t;

#define PFCP_IE_CREATE_BAR				85
#define PFCP_IE_UPDATE_BAR_REQUEST			86
#define PFCP_IE_REMOVE_BAR				87

#define PFCP_IE_BAR_ID					88
typedef u8 pfcp_bar_id_t;

#define PFCP_IE_CP_FUNCTION_FEATURES			89
typedef u8 pfcp_cp_function_features_t;
#define F_CPFF_LOAD					BIT(0)
#define F_CPFF_OVRL					BIT(1)

#define PFCP_IE_USAGE_INFORMATION			90
typedef u8 pfcp_usage_information_t;
#define USAGE_INFORMATION_BEFORE			BIT(0)
#define USAGE_INFORMATION_AFTER				BIT(1)
#define USAGE_INFORMATION_AFTER_QoS_ENFORCEMENT		BIT(2)
#define USAGE_INFORMATION_BEFORE_QoS_ENFORCEMENT	BIT(3)

#define PFCP_IE_APPLICATION_INSTANCE_ID			91
typedef u8 * pfcp_application_instance_id_t;

#define PFCP_IE_FLOW_INFORMATION			92
typedef struct {
  u8 direction;
  u8 * flow_description;
} pfcp_flow_information_t;

#define PFCP_IE_UE_IP_ADDRESS				93
typedef struct {
  u8 flags;
#define IE_UE_IP_ADDRESS_SD				BIT(2)
#define IE_UE_IP_ADDRESS_V4				BIT(1)
#define IE_UE_IP_ADDRESS_V6				BIT(0)

  ip4_address_t ip4;
  ip6_address_t ip6;
} pfcp_ue_ip_address_t;

typedef struct {
  u8 unit;
  u16 max;
} packet_rate_t;

#define PFCP_IE_PACKET_RATE				94
typedef struct {
  u8 flags;
#define PACKET_RATE_ULPR				BIT(0)
#define PACKET_RATE_DLPR				BIT(1)

  packet_rate_t ul;
  packet_rate_t dl;
} pfcp_packet_rate_t;

#define PFCP_IE_OUTER_HEADER_REMOVAL			95
typedef u8 pfcp_outer_header_removal_t;

#define PFCP_IE_RECOVERY_TIME_STAMP			96
typedef u32 pfcp_recovery_time_stamp_t;

#define PFCP_IE_DL_FLOW_LEVEL_MARKING			97
typedef struct {
  u8 flags;
#define DL_FLM_TTC					BIT(0)
#define DL_FLM_SCI					BIT(1)

  u16 tos_traffic_class;
  u16 service_class_indicator;
} pfcp_dl_flow_level_marking_t;

#define PFCP_IE_HEADER_ENRICHMENT			98
typedef struct {
  u8 type;
  u8 * name;
  u8 * value;
} pfcp_header_enrichment_t;

#define PFCP_IE_ERROR_INDICATION_REPORT			99

#define PFCP_IE_MEASUREMENT_INFORMATION			100
typedef struct {
  u8 flags;
#define MEASUREMENT_INFORMATION_MBQE			BIT(0)
#define MEASUREMENT_INFORMATION_INAM			BIT(1)
#define MEASUREMENT_INFORMATION_RADI			BIT(2)
} pfcp_measurement_information_t;

#define PFCP_IE_NODE_REPORT_TYPE			101
typedef struct {
  u8 flags;
#define NRT_USER_PLANE_PATH_FAILURE_REPORT		BIT(0)
} pfcp_node_report_type_t;

#define PFCP_IE_USER_PLANE_PATH_FAILURE_REPORT		102

#define PFCP_IE_REMOTE_GTP_U_PEER			103
typedef struct {
#define REMOTE_GTP_U_PEER_IP6				BIT(0)
#define REMOTE_GTP_U_PEER_IP4				BIT(1)

  ip46_address_t ip;
} pfcp_remote_gtp_u_peer_t;

#define PFCP_IE_UR_SEQN					104
typedef u32 pfcp_ur_seqn_t;

#define PFCP_IE_UPDATE_DUPLICATING_PARAMETERS		105

#define PFCP_IE_ACTIVATE_PREDEFINED_RULES		106
typedef u8 * pfcp_activate_predefined_rules_t;

#define PFCP_IE_DEACTIVATE_PREDEFINED_RULES		107
typedef u8 * pfcp_deactivate_predefined_rules_t;

#define PFCP_IE_FAR_ID					108
typedef u32 pfcp_far_id_t;

#define PFCP_IE_QER_ID					109
typedef u32 pfcp_qer_id_t;

#define PFCP_IE_OCI_FLAGS				110
typedef struct {
  u8 flags;
#define OCI_ASSOCIATE_OCI_WITH_NODE_ID			BIT(0)
} pfcp_oci_flags_t;

#define PFCP_IE_SX_ASSOCIATION_RELEASE_REQUEST		111
typedef struct {
  u8 flags;
#define F_SX_ASSOCIATION_RELEASE_REQUEST		BIT(0)
} pfcp_sx_association_release_request_t;

#define PFCP_IE_GRACEFUL_RELEASE_PERIOD			112
typedef u32 pfcp_graceful_release_period_t;

#define PFCP_IE_PDN_TYPE				113
typedef struct {
  u8 type;
#define PDN_TYPE_IPv4					1
#define PDN_TYPE_IPv6					2
#define PDN_TYPE_IPv4v6					3
#define PDN_TYPE_NON_IP					4
#define PDN_TYPE_ETHERNET				5
} pfcp_pdn_type_t;

#define PFCP_IE_FAILED_RULE_ID				114
typedef struct {
  u8 type;
#define FAILED_RULE_TYPE_PDR		0
#define FAILED_RULE_TYPE_FAR		1
#define FAILED_RULE_TYPE_QER		2
#define FAILED_RULE_TYPE_URR		3
#define FAILED_RULE_TYPE_BAR		4

  u32 id;
} pfcp_failed_rule_id_t;

#define PFCP_IE_TIME_QUOTA_MECHANISM			115
typedef struct {
  u8 base_time_interval_type;
  u32 base_time_interval;
} pfcp_time_quota_mechanism_t;

#define PFCP_IE_USER_PLANE_IP_RESOURCE_INFORMATION	116
typedef struct {
  u8 flags;
#define USER_PLANE_IP_RESOURCE_INFORMATION_V4		BIT(0)
#define USER_PLANE_IP_RESOURCE_INFORMATION_V6		BIT(1)
#define USER_PLANE_IP_RESOURCE_INFORMATION_ASSOCNI	BIT(5)

  pfcp_network_instance_t network_instance;
  u8 teid_range_indication;
  u8 teid_range;
  ip4_address_t ip4;
  ip6_address_t ip6;
} pfcp_user_plane_ip_resource_information_t;

#define PFCP_IE_USER_PLANE_INACTIVITY_TIMER		117
typedef u32 pfcp_user_plane_inactivity_timer_t;

#define PFCP_IE_AGGREGATED_URRS				118

#define PFCP_IE_MULTIPLIER				119
typedef struct {
  u64 digits;
  i32 exponent;
} pfcp_multiplier_t;

#define PFCP_IE_AGGREGATED_URR_ID			120
typedef u32 pfcp_aggregated_urr_id_t;

#define PFCP_IE_SUBSEQUENT_VOLUME_QUOTA			121
typedef pfcp_volume_ie_t pfcp_subsequent_volume_quota_t;

#define PFCP_IE_SUBSEQUENT_TIME_QUOTA			122
typedef u32 pfcp_subsequent_time_quota_t;

#define PFCP_IE_RQI					123
typedef struct {
  u8 flags;
#define RQI_FLAG					BIT(0)
} pfcp_rqi_t;

#define PFCP_IE_QFI					124
typedef u8 pfcp_qfi_t;

#define PFCP_IE_QUERY_URR_REFERENCE			125
typedef u32 pfcp_query_urr_reference_t;

#define PFCP_IE_ADDITIONAL_USAGE_REPORTS_INFORMATION	126
typedef u16 pfcp_additional_usage_reports_information_t;
#define AURI_FLAG					BIT(15)

#define PFCP_IE_CREATE_TRAFFIC_ENDPOINT			127
#define PFCP_IE_CREATED_TRAFFIC_ENDPOINT		128
#define PFCP_IE_UPDATE_TRAFFIC_ENDPOINT			129
#define PFCP_IE_REMOVE_TRAFFIC_ENDPOINT			130

#define PFCP_IE_TRAFFIC_ENDPOINT_ID			131
typedef u8 pfcp_traffic_endpoint_id_t;

#define PFCP_IE_ETHERNET_PACKET_FILTER			132

#define PFCP_IE_MAC_ADDRESS				133
typedef struct {
  u8 flags;
#define F_SOURCE_MAC					BIT(0)
#define F_DESTINATION_MAC				BIT(1)
#define F_UPPER_SOURCE_MAC				BIT(2)
#define F_UPPER_DESTINATION_MAC				BIT(3)

  mac_address_t src_mac;
  mac_address_t dst_mac;
  mac_address_t upper_src_mac;
  mac_address_t upper_dst_mac;
} pfcp_mac_address_t;

typedef struct {
  u16 mask;
#define VLAN_MASK_PCP	0xe000
#define VLAN_MASK_DEI	0x1000
#define VLAN_MASK_VID	0x0fff
  u16 tci;
} pfcp_vlan_tag_t;

#define PFCP_IE_C_TAG					134
typedef pfcp_vlan_tag_t pfcp_c_tag_t;

#define PFCP_IE_S_TAG					135
typedef pfcp_vlan_tag_t pfcp_s_tag_t;

#define PFCP_IE_ETHERTYPE				136
typedef u16 pfcp_ethertype_t;

#define PFCP_IE_PROXYING				137
typedef struct {
  u8 flags;
#define F_PROXY_ARP					BIT(0)
#define F_PROXY_IP6_NS					BIT(1)
} pfcp_proxying_t;

#define PFCP_IE_ETHERNET_FILTER_ID			138
typedef u32 pfcp_ethernet_filter_id_t;

#define PFCP_IE_ETHERNET_FILTER_PROPERTIES		139
typedef struct {
  u8 flags;
#define F_BIDIRECTIONAL_ETHERNET_FILTER			BIT(0)
} pfcp_ethernet_filter_properties_t;

#define PFCP_IE_SUGGESTED_BUFFERING_PACKETS_COUNT	140
typedef u8 pfcp_suggested_buffering_packets_count_t;

#define PFCP_IE_USER_ID					141
typedef struct {
  u8 flags;
#define USER_ID_IMEI					BIT(0)
#define USER_ID_IMSI					BIT(1)

  u8 imei_len;		/* length in bytes, not in digits */
  u8 imei[8];
  u8 imsi_len;		/* length in bytes, not in digits */
  u8 imsi[8];
} pfcp_user_id_t;

#define PFCP_IE_ETHERNET_PDU_SESSION_INFORMATION	142
typedef struct {
  u8 flags;
#define F_ETHERNET_INDICATION				BIT(0)
} pfcp_ethernet_pdu_session_information_t;

#define PFCP_IE_ETHERNET_TRAFFIC_INFORMATION		143

typedef mac_address_t * pfcp_mac_addresses_vec_t;

#define PFCP_IE_MAC_ADDRESSES_DETECTED			144
typedef pfcp_mac_addresses_vec_t pfcp_mac_addresses_detected_t;

#define PFCP_IE_MAC_ADDRESSES_REMOVED			145
typedef pfcp_mac_addresses_vec_t pfcp_mac_addresses_removed_t;

#define PFCP_IE_ETHERNET_INACTIVITY_TIMER		146
typedef u32 pfcp_ethernet_inactivity_timer_t;

/* Grouped PFCP Information Elements */

enum {
  USER_PLANE_PATH_FAILURE_REPORT_REMOTE_GTP_U_PEER,
  USER_PLANE_PATH_FAILURE_REPORT_LAST = USER_PLANE_PATH_FAILURE_REPORT_REMOTE_GTP_U_PEER
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_remote_gtp_u_peer_t *remote_gtp_u_peer;
} pfcp_user_plane_path_failure_report_t;

enum {
  PFD_PFD_CONTENTS,
  PFD_LAST = PFD_PFD_CONTENTS
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_pfd_contents_t *pfd_contents;
} pfcp_pfd_t;

enum {
  APPLICATION_ID_PFDS_APPLICATION_ID,
  APPLICATION_ID_PFDS_PFD,
  APPLICATION_ID_PFDS_LAST = APPLICATION_ID_PFDS_APPLICATION_ID
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_application_id_t application_id;
  pfcp_pfd_t *pfd;
} pfcp_application_id_pfds_t;

enum {
  QUERY_URR_URR_ID,
  QUERY_URR_LAST = QUERY_URR_URR_ID
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_urr_id_t urr_id;
} pfcp_query_urr_t;

/* load and overload control IEs */
enum {
  LOAD_CONTROL_INFORMATION_SEQUENCE_NUMBER,
  LOAD_CONTROL_INFORMATION_METRIC,
  LOAD_CONTROL_INFORMATION_LAST = LOAD_CONTROL_INFORMATION_METRIC
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_sequence_number_t sequence_number;
  pfcp_metric_t metric;
} pfcp_load_control_information_t;

enum {
  OVERLOAD_CONTROL_INFORMATION_SEQUENCE_NUMBER,
  OVERLOAD_CONTROL_INFORMATION_METRIC,
  OVERLOAD_CONTROL_INFORMATION_TIMER,
  OVERLOAD_CONTROL_INFORMATION_OCI_FLAGS,
  OVERLOAD_CONTROL_INFORMATION_LAST = OVERLOAD_CONTROL_INFORMATION_OCI_FLAGS
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_sequence_number_t sequence_number;
  pfcp_metric_t metric;
  pfcp_timer_t timer;
  pfcp_oci_flags_t oci_flags;
} pfcp_overload_control_information_t;

/* PDR related IEs */

enum {
  ETHERNET_PACKET_FILTER_ETHERNET_FILTER_ID,
  ETHERNET_PACKET_FILTER_ETHERNET_FILTER_PROPERTIES,
  ETHERNET_PACKET_FILTER_MAC_ADDRESS,
  ETHERNET_PACKET_FILTER_ETHERTYPE,
  ETHERNET_PACKET_FILTER_C_TAG,
  ETHERNET_PACKET_FILTER_S_TAG,
  ETHERNET_PACKET_FILTER_SDF_FILTER,
  ETHERNET_PACKET_FILTER_LAST = ETHERNET_PACKET_FILTER_SDF_FILTER
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_ethernet_filter_id_t ethernet_filter_id;
  pfcp_ethernet_filter_properties_t ethernet_filter_properties;
  pfcp_mac_address_t mac_address;
  pfcp_ethertype_t ethertype;
  pfcp_c_tag_t c_tag;
  pfcp_s_tag_t s_tag;
  pfcp_sdf_filter_t sdf_filter;
} pfcp_ethernet_packet_filter_t;

enum {
  PDI_SOURCE_INTERFACE,
  PDI_F_TEID,
  PDI_NETWORK_INSTANCE,
  PDI_UE_IP_ADDRESS,
  PDI_SDF_FILTER,
  PDI_APPLICATION_ID,
  PDI_ETHERNET_PDU_SESSION_INFORMATION,
  PDI_ETHERNET_PACKET_FILTER,
  PDI_QFI,
  PDI_LAST = PDI_APPLICATION_ID
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_source_interface_t source_interface;
  pfcp_f_teid_t f_teid;
  pfcp_network_instance_t network_instance;
  pfcp_ue_ip_address_t ue_ip_address;
  pfcp_sdf_filter_t sdf_filter;
  pfcp_application_id_t application_id;
  pfcp_ethernet_pdu_session_information_t ethernet_pdu_session_information;
  pfcp_ethernet_packet_filter_t ethernet_packet_filter;
  pfcp_qfi_t qfi;
} pfcp_pdi_t;

enum {
  CREATE_PDR_PDR_ID,
  CREATE_PDR_PRECEDENCE,
  CREATE_PDR_PDI,
  CREATE_PDR_OUTER_HEADER_REMOVAL,
  CREATE_PDR_FAR_ID,
  CREATE_PDR_URR_ID,
  CREATE_PDR_QER_ID,
  CREATE_PDR_ACTIVATE_PREDEFINED_RULES,
  CREATE_PDR_LAST = CREATE_PDR_ACTIVATE_PREDEFINED_RULES
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_pdr_id_t pdr_id;
  pfcp_precedence_t precedence;
  pfcp_pdi_t pdi;
  pfcp_outer_header_removal_t outer_header_removal;
  pfcp_far_id_t far_id;
  pfcp_urr_id_t *urr_id;
  pfcp_qer_id_t *qer_id;
  pfcp_activate_predefined_rules_t activate_predefined_rules;
} pfcp_create_pdr_t;

enum {
  CREATED_PDR_PDR_ID,
  CREATED_PDR_F_TEID,
  CREATED_PDR_LAST = CREATED_PDR_F_TEID
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_pdr_id_t pdr_id;
  pfcp_f_teid_t f_teid;
} pfcp_created_pdr_t;

enum {
  UPDATE_PDR_PDR_ID,
  UPDATE_PDR_OUTER_HEADER_REMOVAL,
  UPDATE_PDR_PRECEDENCE,
  UPDATE_PDR_PDI,
  UPDATE_PDR_FAR_ID,
  UPDATE_PDR_URR_ID,
  UPDATE_PDR_QER_ID,
  UPDATE_PDR_ACTIVATE_PREDEFINED_RULES,
  UPDATE_PDR_DEACTIVATE_PREDEFINED_RULES,
  UPDATE_PDR_LAST = UPDATE_PDR_DEACTIVATE_PREDEFINED_RULES
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_pdr_id_t pdr_id;
  pfcp_outer_header_removal_t outer_header_removal;
  pfcp_precedence_t precedence;
  pfcp_pdi_t pdi;
  pfcp_far_id_t far_id;
  pfcp_urr_id_t *urr_id;
  pfcp_qer_id_t *qer_id;
  pfcp_activate_predefined_rules_t activate_predefined_rules;
  pfcp_deactivate_predefined_rules_t deactivate_predefined_rules;
} pfcp_update_pdr_t;

enum {
  REMOVE_PDR_PDR_ID,
  REMOVE_PDR_LAST = REMOVE_PDR_PDR_ID
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_pdr_id_t pdr_id;
} pfcp_remove_pdr_t;

/* FAR related IEs */

enum {
  FORWARDING_PARAMETERS_DESTINATION_INTERFACE,
  FORWARDING_PARAMETERS_NETWORK_INSTANCE,
  FORWARDING_PARAMETERS_REDIRECT_INFORMATION,
  FORWARDING_PARAMETERS_OUTER_HEADER_CREATION,
  FORWARDING_PARAMETERS_TRANSPORT_LEVEL_MARKING,
  FORWARDING_PARAMETERS_FORWARDING_POLICY,
  FORWARDING_PARAMETERS_HEADER_ENRICHMENT,
  FORWARDING_PARAMETERS_LINKED_TRAFFIC_ENDPOINT_ID,
  FORWARDING_PARAMETERS_PROXYING,
  FORWARDING_PARAMETERS_LAST = FORWARDING_PARAMETERS_PROXYING
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_destination_interface_t destination_interface;
  pfcp_network_instance_t network_instance;
  pfcp_redirect_information_t redirect_information;
  pfcp_outer_header_creation_t outer_header_creation;
  pfcp_transport_level_marking_t transport_level_marking;
  pfcp_forwarding_policy_t forwarding_policy;
  pfcp_header_enrichment_t header_enrichment;
  pfcp_traffic_endpoint_id_t linked_traffic_endpoint_id;
  pfcp_proxying_t proxying;
} pfcp_forwarding_parameters_t;

enum {
  UPDATE_FORWARDING_PARAMETERS_DESTINATION_INTERFACE,
  UPDATE_FORWARDING_PARAMETERS_NETWORK_INSTANCE,
  UPDATE_FORWARDING_PARAMETERS_REDIRECT_INFORMATION,
  UPDATE_FORWARDING_PARAMETERS_OUTER_HEADER_CREATION,
  UPDATE_FORWARDING_PARAMETERS_TRANSPORT_LEVEL_MARKING,
  UPDATE_FORWARDING_PARAMETERS_FORWARDING_POLICY,
  UPDATE_FORWARDING_PARAMETERS_HEADER_ENRICHMENT,
  UPDATE_FORWARDING_PARAMETERS_SXSMREQ_FLAGS,
  UPDATE_FORWARDING_PARAMETERS_LINKED_TRAFFIC_ENDPOINT_ID,
  UPDATE_FORWARDING_PARAMETERS_LAST = UPDATE_FORWARDING_PARAMETERS_LINKED_TRAFFIC_ENDPOINT_ID
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_destination_interface_t destination_interface;
  pfcp_network_instance_t network_instance;
  pfcp_redirect_information_t redirect_information;
  pfcp_outer_header_creation_t outer_header_creation;
  pfcp_transport_level_marking_t transport_level_marking;
  pfcp_forwarding_policy_t forwarding_policy;
  pfcp_header_enrichment_t header_enrichment;
  pfcp_sxsmreq_flags_t sxsmreq_flags;
  pfcp_traffic_endpoint_id_t linked_traffic_endpoint_id;
} pfcp_update_forwarding_parameters_t;

enum {
  DUPLICATING_PARAMETERS_DESTINATION_INTERFACE,
  DUPLICATING_PARAMETERS_OUTER_HEADER_CREATION,
  DUPLICATING_PARAMETERS_TRANSPORT_LEVEL_MARKING,
  DUPLICATING_PARAMETERS_FORWARDING_POLICY,
  DUPLICATING_PARAMETERS_LAST = DUPLICATING_PARAMETERS_FORWARDING_POLICY
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_destination_interface_t destination_interface;
  pfcp_outer_header_creation_t outer_header_creation;
  pfcp_transport_level_marking_t transport_level_marking;
  pfcp_forwarding_policy_t forwarding_policy;
} pfcp_duplicating_parameters_t;

enum {
  UPDATE_DUPLICATING_PARAMETERS_DESTINATION_INTERFACE,
  UPDATE_DUPLICATING_PARAMETERS_OUTER_HEADER_CREATION,
  UPDATE_DUPLICATING_PARAMETERS_TRANSPORT_LEVEL_MARKING,
  UPDATE_DUPLICATING_PARAMETERS_FORWARDING_POLICY,
  UPDATE_DUPLICATING_PARAMETERS_LAST = UPDATE_DUPLICATING_PARAMETERS_FORWARDING_POLICY
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_destination_interface_t destination_interface;
  pfcp_outer_header_creation_t outer_header_creation;
  pfcp_transport_level_marking_t transport_level_marking;
  pfcp_forwarding_policy_t forwarding_policy;
} pfcp_update_duplicating_parameters_t;

enum {
  CREATE_FAR_FAR_ID,
  CREATE_FAR_APPLY_ACTION,
  CREATE_FAR_FORWARDING_PARAMETERS,
  CREATE_FAR_DUPLICATING_PARAMETERS,
  CREATE_FAR_BAR_ID,
  CREATE_FAR_LAST = CREATE_FAR_BAR_ID
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_far_id_t far_id;
  pfcp_apply_action_t apply_action;
  pfcp_forwarding_parameters_t forwarding_parameters;
  pfcp_duplicating_parameters_t duplicating_parameters;
  pfcp_bar_id_t bar_id;
} pfcp_create_far_t;

enum {
  UPDATE_FAR_FAR_ID,
  UPDATE_FAR_APPLY_ACTION,
  UPDATE_FAR_UPDATE_FORWARDING_PARAMETERS,
  UPDATE_FAR_UPDATE_DUPLICATING_PARAMETERS,
  UPDATE_FAR_BAR_ID,
  UPDATE_FAR_LAST = UPDATE_FAR_BAR_ID
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_far_id_t far_id;
  pfcp_apply_action_t apply_action;
  pfcp_update_forwarding_parameters_t update_forwarding_parameters;
  pfcp_update_duplicating_parameters_t update_duplicating_parameters;
  pfcp_bar_id_t bar_id;
} pfcp_update_far_t;

enum {
  REMOVE_FAR_FAR_ID,
  REMOVE_FAR_LAST = REMOVE_FAR_FAR_ID
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_far_id_t far_id;
} pfcp_remove_far_t;

/* URR related IEs */

enum {
  AGGREGATED_URRS_AGGREGATED_URR_ID,
  AGGREGATED_URRS_MULTIPLIER,
  AGGREGATED_URRS_LAST = AGGREGATED_URRS_MULTIPLIER
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_aggregated_urr_id_t aggregated_urr_id;
  pfcp_multiplier_t multiplier;
} pfcp_aggregated_urrs_t;

enum {
  CREATE_URR_URR_ID,
  CREATE_URR_MEASUREMENT_METHOD,
  CREATE_URR_REPORTING_TRIGGERS,
  CREATE_URR_MEASUREMENT_PERIOD,
  CREATE_URR_VOLUME_THRESHOLD,
  CREATE_URR_VOLUME_QUOTA,
  CREATE_URR_TIME_THRESHOLD,
  CREATE_URR_TIME_QUOTA,
  CREATE_URR_QUOTA_HOLDING_TIME,
  CREATE_URR_DROPPED_DL_TRAFFIC_THRESHOLD,
  CREATE_URR_MONITORING_TIME,
  CREATE_URR_SUBSEQUENT_VOLUME_THRESHOLD,
  CREATE_URR_SUBSEQUENT_TIME_THRESHOLD,
  CREATE_URR_INACTIVITY_DETECTION_TIME,
  CREATE_URR_LINKED_URR_ID,
  CREATE_URR_MEASUREMENT_INFORMATION,
  CREATE_URR_TIME_QUOTA_MECHANISM,
  CREATE_URR_AGGREGATED_URRS,
  CREATE_URR_FAR_ID_FOR_QUOTE_ACTION,
  CREATE_URR_ETHERNET_INACTIVITY_TIMER,
  CREATE_URR_LAST = CREATE_URR_ETHERNET_INACTIVITY_TIMER
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_urr_id_t urr_id;
  pfcp_measurement_method_t measurement_method;
  pfcp_reporting_triggers_t reporting_triggers;
  pfcp_measurement_period_t measurement_period;
  pfcp_volume_threshold_t volume_threshold;
  pfcp_volume_quota_t volume_quota;
  pfcp_time_threshold_t time_threshold;
  pfcp_time_quota_t time_quota;
  pfcp_quota_holding_time_t quota_holding_time;
  pfcp_dropped_dl_traffic_threshold_t dropped_dl_traffic_threshold;
  pfcp_monitoring_time_t monitoring_time;
  pfcp_subsequent_volume_threshold_t subsequent_volume_threshold;
  pfcp_subsequent_time_threshold_t subsequent_time_threshold;
  pfcp_inactivity_detection_time_t inactivity_detection_time;
  pfcp_linked_urr_id_t linked_urr_id;
  pfcp_measurement_information_t measurement_information;
  pfcp_time_quota_mechanism_t time_quota_mechanism;
  pfcp_aggregated_urrs_t aggregated_urrs;
  pfcp_far_id_t far_id_for_quota_action;
  pfcp_ethernet_inactivity_timer_t ethernet_inactivity_timer;
} pfcp_create_urr_t;

enum {
  UPDATE_URR_URR_ID,
  UPDATE_URR_MEASUREMENT_METHOD,
  UPDATE_URR_REPORTING_TRIGGERS,
  UPDATE_URR_MEASUREMENT_PERIOD,
  UPDATE_URR_VOLUME_THRESHOLD,
  UPDATE_URR_VOLUME_QUOTA,
  UPDATE_URR_TIME_THRESHOLD,
  UPDATE_URR_TIME_QUOTA,
  UPDATE_URR_QUOTA_HOLDING_TIME,
  UPDATE_URR_DROPPED_DL_TRAFFIC_THRESHOLD,
  UPDATE_URR_MONITORING_TIME,
  UPDATE_URR_SUBSEQUENT_VOLUME_THRESHOLD,
  UPDATE_URR_SUBSEQUENT_TIME_THRESHOLD,
  UPDATE_URR_INACTIVITY_DETECTION_TIME,
  UPDATE_URR_LINKED_URR_ID,
  UPDATE_URR_MEASUREMENT_INFORMATION,
  UPDATE_URR_TIME_QUOTA_MECHANISM,
  UPDATE_URR_AGGREGATED_URRS,
  UPDATE_URR_FAR_ID_FOR_QUOTE_ACTION,
  UPDATE_URR_ETHERNET_INACTIVITY_TIMER,
  UPDATE_URR_LAST = UPDATE_URR_ETHERNET_INACTIVITY_TIMER
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_urr_id_t urr_id;
  pfcp_measurement_method_t measurement_method;
  pfcp_reporting_triggers_t reporting_triggers;
  pfcp_measurement_period_t measurement_period;
  pfcp_volume_threshold_t volume_threshold;
  pfcp_volume_quota_t volume_quota;
  pfcp_time_threshold_t time_threshold;
  pfcp_time_quota_t time_quota;
  pfcp_quota_holding_time_t quota_holding_time;
  pfcp_dropped_dl_traffic_threshold_t dropped_dl_traffic_threshold;
  pfcp_monitoring_time_t monitoring_time;
  pfcp_subsequent_volume_threshold_t subsequent_volume_threshold;
  pfcp_subsequent_time_threshold_t subsequent_time_threshold;
  pfcp_inactivity_detection_time_t inactivity_detection_time;
  pfcp_linked_urr_id_t linked_urr_id;
  pfcp_measurement_information_t measurement_information;
  pfcp_time_quota_mechanism_t time_quota_mechanism;
  pfcp_aggregated_urrs_t aggregated_urrs;
  pfcp_far_id_t far_id_for_quota_action;
  pfcp_ethernet_inactivity_timer_t ethernet_inactivity_timer;
} pfcp_update_urr_t;

enum {
  REMOVE_URR_URR_ID,
  REMOVE_URR_LAST = REMOVE_URR_URR_ID
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_urr_id_t urr_id;
} pfcp_remove_urr_t;

/* QER related IEs */

enum {
  CREATE_QER_QER_ID,
  CREATE_QER_QER_CORRELATION_ID,
  CREATE_QER_GATE_STATUS,
  CREATE_QER_MBR,
  CREATE_QER_GBR,
  CREATE_QER_PACKET_RATE,
  CREATE_QER_DL_FLOW_LEVEL_MARKING,
  CREATE_QER_QOS_FLOW_IDENTIFIER,
  CREATE_QER_REFLECTIVE_QOS,
  CREATE_QER_LAST = CREATE_QER_REFLECTIVE_QOS
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_qer_id_t qer_id;
  pfcp_qer_correlation_id_t qer_correlation_id;
  pfcp_gate_status_t gate_status;
  pfcp_mbr_t mbr;
  pfcp_gbr_t gbr;
  pfcp_packet_rate_t packet_rate;
  pfcp_dl_flow_level_marking_t dl_flow_level_marking;
  pfcp_qfi_t qos_flow_identifier;
  pfcp_rqi_t reflective_qos;
} pfcp_create_qer_t;

enum {
  UPDATE_QER_QER_ID,
  UPDATE_QER_QER_CORRELATION_ID,
  UPDATE_QER_GATE_STATUS,
  UPDATE_QER_MBR,
  UPDATE_QER_GBR,
  UPDATE_QER_PACKET_RATE,
  UPDATE_QER_DL_FLOW_LEVEL_MARKING,
  UPDATE_QER_QOS_FLOW_IDENTIFIER,
  UPDATE_QER_REFLECTIVE_QOS,
  UPDATE_QER_LAST = UPDATE_QER_REFLECTIVE_QOS
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_qer_id_t qer_id;
  pfcp_qer_correlation_id_t qer_correlation_id;
  pfcp_gate_status_t gate_status;
  pfcp_mbr_t mbr;
  pfcp_gbr_t gbr;
  pfcp_packet_rate_t packet_rate;
  pfcp_dl_flow_level_marking_t dl_flow_level_marking;
  pfcp_qfi_t qos_flow_identifier;
  pfcp_rqi_t reflective_qos;
} pfcp_update_qer_t;

enum {
  REMOVE_QER_QER_ID,
  REMOVE_QER_LAST = REMOVE_QER_QER_ID
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_qer_id_t qer_id;
} pfcp_remove_qer_t;

/* BAR related IEs */

enum {
  CREATE_BAR_BAR_ID,
  CREATE_BAR_DOWNLINK_DATA_NOTIFICATION_DELAY,
  CREATE_BAR_SUGGESTED_BUFFERING_PACKETS_COUNT,
  CREATE_BAR_LAST = CREATE_BAR_SUGGESTED_BUFFERING_PACKETS_COUNT
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_bar_id_t bar_id;
  pfcp_downlink_data_notification_delay_t downlink_data_notification_delay;
  pfcp_suggested_buffering_packets_count_t suggested_buffering_packets_count;
} pfcp_create_bar_t;

enum {
  UPDATE_BAR_REQUEST_BAR_ID,
  UPDATE_BAR_REQUEST_DOWNLINK_DATA_NOTIFICATION_DELAY,
  UPDATE_BAR_REQUEST_SUGGESTED_BUFFERING_PACKETS_COUNT,
  UPDATE_BAR_LAST = UPDATE_BAR_REQUEST_SUGGESTED_BUFFERING_PACKETS_COUNT
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_bar_id_t bar_id;
  pfcp_downlink_data_notification_delay_t downlink_data_notification_delay;
  pfcp_suggested_buffering_packets_count_t suggested_buffering_packets_count;
} pfcp_update_bar_request_t;

enum {
  UPDATE_BAR_RESPONSE_BAR_ID,
  UPDATE_BAR_RESPONSE_DOWNLINK_DATA_NOTIFICATION_DELAY,
  UPDATE_BAR_RESPONSE_DL_BUFFERING_DURATION,
  UPDATE_BAR_RESPONSE_DL_BUFFERING_SUGGESTED_PACKET_COUNT,
  UPDATE_BAR_RESPONSE_SUGGESTED_BUFFERING_PACKETS_COUNT,
  UPDATE_BAR_RESPONSE_LAST = UPDATE_BAR_RESPONSE_SUGGESTED_BUFFERING_PACKETS_COUNT
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_bar_id_t bar_id;
  pfcp_downlink_data_notification_delay_t downlink_data_notification_delay;
  pfcp_dl_buffering_duration_t dl_buffering_duration;
  pfcp_dl_buffering_suggested_packet_count_t dl_buffering_suggested_packet_count;
  pfcp_suggested_buffering_packets_count_t suggested_buffering_packets_count;
} pfcp_update_bar_response_t;

enum {
  REMOVE_BAR_BAR_ID,
  REMOVE_BAR_LAST = REMOVE_BAR_BAR_ID
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_bar_id_t bar_id;
} pfcp_remove_bar_t;

enum {
  CREATE_TRAFFIC_ENDPOINT_TRAFFIC_ENDPOINT_ID,
  CREATE_TRAFFIC_ENDPOINT_F_TEID,
  CREATE_TRAFFIC_ENDPOINT_NETWORK_INSTANCE,
  CREATE_TRAFFIC_ENDPOINT_UE_IP_ADDRESS,
  CREATE_TRAFFIC_ENDPOINT_ETHERNET_PDU_SESSION_INFORMATION,
  CREATE_TRAFFIC_ENDPOINT_LAST = CREATE_TRAFFIC_ENDPOINT_ETHERNET_PDU_SESSION_INFORMATION
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_traffic_endpoint_id_t traffic_endpoint_id;
  pfcp_f_teid_t f_teid;
  pfcp_network_instance_t network_instance;
  pfcp_ue_ip_address_t ue_ip_address;
  pfcp_ethernet_pdu_session_information_t ethernet_pdu_session_information;
} pfcp_create_traffic_endpoint_t;

enum {
  CREATED_TRAFFIC_ENDPOINT_TRAFFIC_ENDPOINT_ID,
  CREATED_TRAFFIC_ENDPOINT_F_TEID,
  CREATED_TRAFFIC_ENDPOINT_LAST = CREATED_TRAFFIC_ENDPOINT_F_TEID
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_traffic_endpoint_id_t traffic_endpoint_id;
  pfcp_f_teid_t f_teid;
} pfcp_created_traffic_endpoint_t;

enum {
  UPDATE_TRAFFIC_ENDPOINT_TRAFFIC_ENDPOINT_ID,
  UPDATE_TRAFFIC_ENDPOINT_F_TEID,
  UPDATE_TRAFFIC_ENDPOINT_NETWORK_INSTANCE,
  UPDATE_TRAFFIC_ENDPOINT_UE_IP_ADDRESS,
  UPDATE_TRAFFIC_ENDPOINT_LAST = UPDATE_TRAFFIC_ENDPOINT_UE_IP_ADDRESS
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_traffic_endpoint_id_t traffic_endpoint_id;
  pfcp_f_teid_t f_teid;
  pfcp_network_instance_t network_instance;
  pfcp_ue_ip_address_t ue_ip_address;
} pfcp_update_traffic_endpoint_t;

enum {
  REMOVE_TRAFFIC_ENDPOINT_TRAFFIC_ENDPOINT_ID,
  REMOVE_TRAFFIC_ENDPOINT_LAST = REMOVE_TRAFFIC_ENDPOINT_TRAFFIC_ENDPOINT_ID
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_traffic_endpoint_id_t traffic_endpoint_id;
} pfcp_remove_traffic_endpoint_t;

/* Sx Session Report IEs */

enum {
  APPLICATION_DETECTION_INFORMATION_APPLICATION_ID,
  APPLICATION_DETECTION_INFORMATION_APPLICATION_INSTANCE_ID,
  APPLICATION_DETECTION_INFORMATION_FLOW_INFORMATION,
  APPLICATION_DETECTION_INFORMATION_LAST = APPLICATION_DETECTION_INFORMATION_FLOW_INFORMATION
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_application_id_t application_id;
  pfcp_application_instance_id_t application_instance_id;
  pfcp_flow_information_t flow_information;
} pfcp_application_detection_information_t;

enum {
  DOWNLINK_DATA_REPORT_PDR_ID,
  DOWNLINK_DATA_REPORT_DOWNLINK_DATA_SERVICE_INFORMATION,
  DOWNLINK_DATA_REPORT_LAST = DOWNLINK_DATA_REPORT_DOWNLINK_DATA_SERVICE_INFORMATION
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_pdr_id_t *pdr_id;
  pfcp_downlink_data_service_information_t *downlink_data_service_information;
} pfcp_downlink_data_report_t;

enum {
  ERROR_INDICATION_REPORT_F_TEID,
  ERROR_INDICATION_REPORT_LAST = ERROR_INDICATION_REPORT_F_TEID
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_f_teid_t *f_teid;
} pfcp_error_indication_report_t;

enum {
  ETHERNET_TRAFFIC_INFORMATION_MAC_ADDRESSES_DETECTED,
  ETHERNET_TRAFFIC_INFORMATION_MAC_ADDRESSES_REMOVED,
  ETHERNET_TRAFFIC_INFORMATION_LAST = ETHERNET_TRAFFIC_INFORMATION_MAC_ADDRESSES_REMOVED
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_mac_addresses_detected_t mac_addresses_detected;
  pfcp_mac_addresses_removed_t mac_addresses_removed;
} pfcp_ethernet_traffic_information_t;

/* Usage Report IEs */

enum {
  USAGE_REPORT_URR_ID,
  USAGE_REPORT_UR_SEQN,
  USAGE_REPORT_USAGE_REPORT_TRIGGER,
  USAGE_REPORT_START_TIME,
  USAGE_REPORT_END_TIME,
  USAGE_REPORT_VOLUME_MEASUREMENT,
  USAGE_REPORT_DURATION_MEASUREMENT,
  USAGE_REPORT_APPLICATION_DETECTION_INFORMATION,
  USAGE_REPORT_UE_IP_ADDRESS,
  USAGE_REPORT_NETWORK_INSTANCE,
  USAGE_REPORT_TIME_OF_FIRST_PACKET,
  USAGE_REPORT_TIME_OF_LAST_PACKET,
  USAGE_REPORT_USAGE_INFORMATION,
  USAGE_REPORT_QUERY_URR_REFERENCE,
  USAGE_REPORT_ETHERNET_TRAFFIC_INFORMATION,
  USAGE_REPORT_LAST = USAGE_REPORT_ETHERNET_TRAFFIC_INFORMATION
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_urr_id_t urr_id;
  pfcp_ur_seqn_t ur_seqn;
  pfcp_usage_report_trigger_t usage_report_trigger;
  pfcp_start_time_t start_time;
  pfcp_end_time_t end_time;
  pfcp_volume_measurement_t volume_measurement;
  pfcp_duration_measurement_t duration_measurement;
  pfcp_application_detection_information_t application_detection_information;
  pfcp_ue_ip_address_t ue_ip_address;
  pfcp_network_instance_t network_instance;
  pfcp_time_of_first_packet_t time_of_first_packet;
  pfcp_time_of_last_packet_t time_of_last_packet;
  pfcp_usage_information_t usage_information;
  pfcp_query_urr_reference_t query_urr_reference;
  pfcp_ethernet_traffic_information_t ethernet_traffic_information;
} pfcp_usage_report_t;


/* PFCP Methods */

#define PFCP_HEARTBEAT_REQUEST			 1
#define PFCP_HEARTBEAT_RESPONSE			 2
#define PFCP_PFD_MANAGEMENT_REQUEST		 3
#define PFCP_PFD_MANAGEMENT_RESPONSE		 4
#define PFCP_ASSOCIATION_SETUP_REQUEST		 5
#define PFCP_ASSOCIATION_SETUP_RESPONSE		 6
#define PFCP_ASSOCIATION_UPDATE_REQUEST		 7
#define PFCP_ASSOCIATION_UPDATE_RESPONSE	 8
#define PFCP_ASSOCIATION_RELEASE_REQUEST	 9
#define PFCP_ASSOCIATION_RELEASE_RESPONSE	10
#define PFCP_VERSION_NOT_SUPPORTED_RESPONSE	11
#define PFCP_NODE_REPORT_REQUEST		12
#define PFCP_NODE_REPORT_RESPONSE		13
#define PFCP_SESSION_SET_DELETION_REQUEST	14
#define PFCP_SESSION_SET_DELETION_RESPONSE	15
#define PFCP_SESSION_ESTABLISHMENT_REQUEST	50
#define PFCP_SESSION_ESTABLISHMENT_RESPONSE	51
#define PFCP_SESSION_MODIFICATION_REQUEST	52
#define PFCP_SESSION_MODIFICATION_RESPONSE	53
#define PFCP_SESSION_DELETION_REQUEST		54
#define PFCP_SESSION_DELETION_RESPONSE		55
#define PFCP_SESSION_REPORT_REQUEST		56
#define PFCP_SESSION_REPORT_RESPONSE		57

enum {
  PFCP_RESPONSE_NODE_ID,
  PFCP_RESPONSE_CAUSE,
  PFCP_RESPONSE_OFFENDING_IE,
};

struct pfcp_response
{
  pfcp_node_id_t node_id;
  pfcp_cause_t cause;
  pfcp_offending_ie_t offending_ie;
};

enum {
  PFCP_REQUEST_NODE_ID,
};

struct pfcp_request
{
  pfcp_node_id_t node_id;
};

enum {
  HEARTBEAT_REQUEST_RECOVERY_TIME_STAMP,
  HEARTBEAT_REQUEST_LAST = HEARTBEAT_REQUEST_RECOVERY_TIME_STAMP
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_recovery_time_stamp_t recovery_time_stamp;
} pfcp_heartbeat_request_t;

enum {
  HEARTBEAT_RESPONSE_RECOVERY_TIME_STAMP,
  HEARTBEAT_RESPONSE_LAST = HEARTBEAT_RESPONSE_RECOVERY_TIME_STAMP
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_recovery_time_stamp_t recovery_time_stamp;
} pfcp_heartbeat_response_t;

enum {
  PFD_MANAGEMENT_REQUEST_APPLICATION_ID_PFDS,
  PFD_MANAGEMENT_REQUEST_LAST = PFD_MANAGEMENT_REQUEST_APPLICATION_ID_PFDS
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_application_id_pfds_t *application_id_pfds;
} pfcp_pfd_management_request_t;

enum {
  PFD_MANAGEMENT_RESPONSE_CAUSE = PFCP_RESPONSE_CAUSE,
  PFD_MANAGEMENT_RESPONSE_OFFENDING_IE = PFCP_RESPONSE_OFFENDING_IE,
  PFD_MANAGEMENT_RESPONSE_LAST = PFD_MANAGEMENT_RESPONSE_OFFENDING_IE
};

typedef struct
{
  struct pfcp_group grp;
  struct pfcp_response response;
} pfcp_pfd_management_response_t;

enum {
  ASSOCIATION_SETUP_REQUEST_NODE_ID = PFCP_REQUEST_NODE_ID,
  ASSOCIATION_SETUP_REQUEST_RECOVERY_TIME_STAMP,
  ASSOCIATION_SETUP_REQUEST_UP_FUNCTION_FEATURES,
  ASSOCIATION_SETUP_REQUEST_CP_FUNCTION_FEATURES,
  ASSOCIATION_SETUP_REQUEST_USER_PLANE_IP_RESOURCE_INFORMATION,
  ASSOCIATION_SETUP_REQUEST_LAST = ASSOCIATION_SETUP_REQUEST_USER_PLANE_IP_RESOURCE_INFORMATION
};

typedef struct
{
  struct pfcp_group grp;
  struct pfcp_request request;

  pfcp_recovery_time_stamp_t recovery_time_stamp;
  pfcp_cp_function_features_t cp_function_features;
  pfcp_up_function_features_t up_function_features;
  pfcp_user_plane_ip_resource_information_t *user_plane_ip_resource_information;
} pfcp_association_setup_request_t;

enum {
  ASSOCIATION_SETUP_RESPONSE_NODE_ID = PFCP_RESPONSE_NODE_ID,
  ASSOCIATION_SETUP_RESPONSE_CAUSE = PFCP_RESPONSE_CAUSE,
  ASSOCIATION_SETUP_RESPONSE_RECOVERY_TIME_STAMP,
  ASSOCIATION_SETUP_RESPONSE_UP_FUNCTION_FEATURES,
  ASSOCIATION_SETUP_RESPONSE_CP_FUNCTION_FEATURES,
  ASSOCIATION_SETUP_RESPONSE_USER_PLANE_IP_RESOURCE_INFORMATION,
  ASSOCIATION_SETUP_RESPONSE_LAST = ASSOCIATION_SETUP_RESPONSE_USER_PLANE_IP_RESOURCE_INFORMATION
};

typedef struct
{
  struct pfcp_group grp;
  struct pfcp_response response;

  pfcp_recovery_time_stamp_t recovery_time_stamp;
  pfcp_cp_function_features_t cp_function_features;
  pfcp_up_function_features_t up_function_features;
  pfcp_user_plane_ip_resource_information_t *user_plane_ip_resource_information;
} pfcp_association_setup_response_t;

enum {
  ASSOCIATION_UPDATE_REQUEST_NODE_ID = PFCP_REQUEST_NODE_ID,
  ASSOCIATION_UPDATE_REQUEST_CP_FUNCTION_FEATURES,
  ASSOCIATION_UPDATE_REQUEST_UP_FUNCTION_FEATURES,
  ASSOCIATION_UPDATE_REQUEST_SX_ASSOCIATION_RELEASE_REQUEST,
  ASSOCIATION_UPDATE_REQUEST_GRACEFUL_RELEASE_PERIOD,
  ASSOCIATION_UPDATE_REQUEST_USER_PLANE_IP_RESOURCE_INFORMATION,
  ASSOCIATION_UPDATE_REQUEST_LAST = ASSOCIATION_UPDATE_REQUEST_USER_PLANE_IP_RESOURCE_INFORMATION
};

typedef struct
{
  struct pfcp_group grp;
  struct pfcp_request request;

  pfcp_cp_function_features_t cp_function_features;
  pfcp_up_function_features_t up_function_features;
  pfcp_sx_association_release_request_t sx_association_release_request;
  pfcp_graceful_release_period_t graceful_release_period;
  pfcp_user_plane_ip_resource_information_t *user_plane_ip_resource_information;
} pfcp_association_update_request_t;

enum {
  ASSOCIATION_UPDATE_RESPONSE_NODE_ID = PFCP_RESPONSE_NODE_ID,
  ASSOCIATION_UPDATE_RESPONSE_CAUSE = PFCP_RESPONSE_CAUSE,
  ASSOCIATION_UPDATE_RESPONSE_UP_FUNCTION_FEATURES,
  ASSOCIATION_UPDATE_RESPONSE_CP_FUNCTION_FEATURES,
  ASSOCIATION_UPDATE_RESPONSE_LAST = ASSOCIATION_UPDATE_RESPONSE_CP_FUNCTION_FEATURES
};

typedef struct
{
  struct pfcp_group grp;
  struct pfcp_response response;

  pfcp_cp_function_features_t cp_function_features;
  pfcp_up_function_features_t up_function_features;
} pfcp_association_update_response_t;

enum {
  ASSOCIATION_RELEASE_REQUEST_NODE_ID = PFCP_REQUEST_NODE_ID,
  ASSOCIATION_RELEASE_REQUEST_LAST = ASSOCIATION_RELEASE_REQUEST_NODE_ID
};

typedef struct
{
  struct pfcp_group grp;
  struct pfcp_request request;

} pfcp_association_release_request_t;

enum {
  ASSOCIATION_RELEASE_RESPONSE_NODE_ID = PFCP_RESPONSE_NODE_ID,
  ASSOCIATION_RELEASE_RESPONSE_CAUSE = PFCP_RESPONSE_CAUSE,
  ASSOCIATION_RELEASE_RESPONSE_LAST = ASSOCIATION_RELEASE_RESPONSE_CAUSE
};

typedef struct
{
  struct pfcp_group grp;
  struct pfcp_response response;
} pfcp_association_release_response_t;

enum {
  NODE_REPORT_REQUEST_NODE_ID = PFCP_REQUEST_NODE_ID,
  NODE_REPORT_REQUEST_NODE_REPORT_TYPE,
  NODE_REPORT_REQUEST_USER_PLANE_PATH_FAILURE_REPORT,
  NODE_REPORT_REQUEST_LAST = NODE_REPORT_REQUEST_USER_PLANE_PATH_FAILURE_REPORT
};

typedef struct
{
  struct pfcp_group grp;
  struct pfcp_request request;

  pfcp_node_report_type_t node_report_type;
  pfcp_user_plane_path_failure_report_t user_plane_path_failure_report;
} pfcp_node_report_request_t;

enum {
  NODE_REPORT_RESPONSE_NODE_ID = PFCP_RESPONSE_NODE_ID,
  NODE_REPORT_RESPONSE_CAUSE = PFCP_RESPONSE_CAUSE,
  NODE_REPORT_RESPONSE_OFFENDING_IE = PFCP_RESPONSE_OFFENDING_IE,
  NODE_REPORT_RESPONSE_LAST = NODE_REPORT_RESPONSE_OFFENDING_IE
};

typedef struct
{
  struct pfcp_group grp;
  struct pfcp_response response;
} pfcp_node_report_response_t;

enum {
  SESSION_SET_DELETION_REQUEST_NODE_ID = PFCP_REQUEST_NODE_ID,
  SESSION_SET_DELETION_REQUEST_FQ_CSID,
  SESSION_SET_DELETION_REQUEST_LAST = SESSION_SET_DELETION_REQUEST_FQ_CSID
};

typedef struct
{
  struct pfcp_group grp;
  struct pfcp_request request;

  pfcp_fq_csid_t *fq_csid;
} pfcp_session_set_deletion_request_t;

enum {
  SESSION_SET_DELETION_RESPONSE_NODE_ID = PFCP_RESPONSE_NODE_ID,
  SESSION_SET_DELETION_RESPONSE_CAUSE = PFCP_RESPONSE_CAUSE,
  SESSION_SET_DELETION_RESPONSE_OFFENDING_IE = PFCP_RESPONSE_OFFENDING_IE,
  SESSION_SET_DELETION_RESPONSE_LAST = SESSION_SET_DELETION_RESPONSE_OFFENDING_IE
};

typedef struct
{
  struct pfcp_group grp;
  struct pfcp_response response;
} pfcp_session_set_deletion_response_t;

enum {
  SESSION_ESTABLISHMENT_REQUEST_NODE_ID = PFCP_REQUEST_NODE_ID,
  SESSION_ESTABLISHMENT_REQUEST_F_SEID,
  SESSION_ESTABLISHMENT_REQUEST_CREATE_PDR,
  SESSION_ESTABLISHMENT_REQUEST_CREATE_FAR,
  SESSION_ESTABLISHMENT_REQUEST_CREATE_URR,
  SESSION_ESTABLISHMENT_REQUEST_CREATE_QER,
  SESSION_ESTABLISHMENT_REQUEST_CREATE_BAR,
  SESSION_ESTABLISHMENT_REQUEST_CREATE_TRAFFIC_ENDPOINT,
  SESSION_ESTABLISHMENT_REQUEST_PDN_TYPE,
  SESSION_ESTABLISHMENT_REQUEST_FQ_CSID,
  SESSION_ESTABLISHMENT_REQUEST_USER_PLANE_INACTIVITY_TIMER,
  SESSION_ESTABLISHMENT_REQUEST_USER_ID,
  SESSION_ESTABLISHMENT_REQUEST_LAST = SESSION_ESTABLISHMENT_REQUEST_USER_ID
};

typedef struct
{
  struct pfcp_group grp;
  struct pfcp_request request;

  pfcp_f_seid_t f_seid;
  pfcp_create_pdr_t *create_pdr;
  pfcp_create_far_t *create_far;
  pfcp_create_urr_t *create_urr;
  pfcp_create_qer_t *create_qer;
  pfcp_create_bar_t *create_bar;
  pfcp_create_traffic_endpoint_t *create_traffic_endpoint;
  pfcp_pdn_type_t pdn_type;
  pfcp_fq_csid_t *fq_csid;
  pfcp_user_plane_inactivity_timer_t user_plane_inactivity_timer;
  pfcp_user_id_t user_id;
} pfcp_session_establishment_request_t;

enum {
  SESSION_ESTABLISHMENT_RESPONSE_NODE_ID = PFCP_RESPONSE_NODE_ID,
  SESSION_ESTABLISHMENT_RESPONSE_CAUSE = PFCP_RESPONSE_CAUSE,
  SESSION_ESTABLISHMENT_RESPONSE_OFFENDING_IE = PFCP_RESPONSE_OFFENDING_IE,
  SESSION_ESTABLISHMENT_RESPONSE_UP_F_SEID,
  SESSION_ESTABLISHMENT_RESPONSE_CREATED_PDR,
  SESSION_ESTABLISHMENT_RESPONSE_LOAD_CONTROL_INFORMATION,
  SESSION_ESTABLISHMENT_RESPONSE_OVERLOAD_CONTROL_INFORMATION,
  SESSION_ESTABLISHMENT_RESPONSE_FQ_CSID,
  SESSION_ESTABLISHMENT_RESPONSE_FAILED_RULE_ID,
  SESSION_ESTABLISHMENT_RESPONSE_CREATED_TRAFFIC_ENDPOINT,
  SESSION_ESTABLISHMENT_RESPONSE_LAST = SESSION_ESTABLISHMENT_RESPONSE_CREATED_TRAFFIC_ENDPOINT
};

typedef struct
{
  struct pfcp_group grp;
  struct pfcp_response response;

  pfcp_f_seid_t up_f_seid;
  pfcp_created_pdr_t *created_pdr;
  pfcp_load_control_information_t load_control_information;
  pfcp_overload_control_information_t overload_control_information;
  pfcp_fq_csid_t *fq_csid;
  pfcp_failed_rule_id_t failed_rule_id;
  pfcp_created_traffic_endpoint_t *created_traffic_endpoint;
} pfcp_session_establishment_response_t;

enum {
  SESSION_MODIFICATION_REQUEST_F_SEID,
  SESSION_MODIFICATION_REQUEST_REMOVE_PDR,
  SESSION_MODIFICATION_REQUEST_REMOVE_FAR,
  SESSION_MODIFICATION_REQUEST_REMOVE_URR,
  SESSION_MODIFICATION_REQUEST_REMOVE_QER,
  SESSION_MODIFICATION_REQUEST_REMOVE_BAR,
  SESSION_MODIFICATION_REQUEST_REMOVE_TRAFFIC_ENDPOINT,
  SESSION_MODIFICATION_REQUEST_CREATE_PDR,
  SESSION_MODIFICATION_REQUEST_CREATE_FAR,
  SESSION_MODIFICATION_REQUEST_CREATE_URR,
  SESSION_MODIFICATION_REQUEST_CREATE_QER,
  SESSION_MODIFICATION_REQUEST_CREATE_BAR,
  SESSION_MODIFICATION_REQUEST_CREATE_TRAFFIC_ENDPOINT,
  SESSION_MODIFICATION_REQUEST_UPDATE_PDR,
  SESSION_MODIFICATION_REQUEST_UPDATE_FAR,
  SESSION_MODIFICATION_REQUEST_UPDATE_URR,
  SESSION_MODIFICATION_REQUEST_UPDATE_QER,
  SESSION_MODIFICATION_REQUEST_UPDATE_BAR,
  SESSION_MODIFICATION_REQUEST_UPDATE_TRAFFIC_ENDPOINT,
  SESSION_MODIFICATION_REQUEST_SXSMREQ_FLAGS,
  SESSION_MODIFICATION_REQUEST_QUERY_URR,
  SESSION_MODIFICATION_REQUEST_FQ_CSID,
  SESSION_MODIFICATION_REQUEST_USER_PLANE_INACTIVITY_TIMER,
  SESSION_MODIFICATION_REQUEST_QUERY_URR_REFERENCE,
  SESSION_MODIFICATION_REQUEST_LAST = SESSION_MODIFICATION_REQUEST_QUERY_URR_REFERENCE
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_f_seid_t f_seid;
  pfcp_remove_pdr_t *remove_pdr;
  pfcp_remove_far_t *remove_far;
  pfcp_remove_urr_t *remove_urr;
  pfcp_remove_qer_t *remove_qer;
  pfcp_remove_bar_t *remove_bar;
  pfcp_remove_traffic_endpoint_t *remove_traffic_endpoint;
  pfcp_create_pdr_t *create_pdr;
  pfcp_create_far_t *create_far;
  pfcp_create_urr_t *create_urr;
  pfcp_create_qer_t *create_qer;
  pfcp_create_bar_t *create_bar;
  pfcp_create_traffic_endpoint_t *create_traffic_endpoint;
  pfcp_update_pdr_t *update_pdr;
  pfcp_update_far_t *update_far;
  pfcp_update_urr_t *update_urr;
  pfcp_update_qer_t *update_qer;
  pfcp_update_bar_request_t *update_bar;
  pfcp_update_traffic_endpoint_t *update_traffic_endpoint;
  pfcp_sxsmreq_flags_t sxsmreq_flags;
  pfcp_query_urr_t *query_urr;
  pfcp_fq_csid_t *fq_csid;
  pfcp_user_plane_inactivity_timer_t user_plane_inactivity_timer;
  pfcp_query_urr_reference_t query_urr_reference;
} pfcp_session_modification_request_t;

enum {
  SESSION_MODIFICATION_RESPONSE_CAUSE = PFCP_RESPONSE_CAUSE,
  SESSION_MODIFICATION_RESPONSE_OFFENDING_IE = PFCP_RESPONSE_OFFENDING_IE,
  SESSION_MODIFICATION_RESPONSE_CREATED_PDR,
  SESSION_MODIFICATION_RESPONSE_LOAD_CONTROL_INFORMATION,
  SESSION_MODIFICATION_RESPONSE_OVERLOAD_CONTROL_INFORMATION,
  SESSION_MODIFICATION_RESPONSE_USAGE_REPORT,
  SESSION_MODIFICATION_RESPONSE_FAILED_RULE_ID,
  SESSION_MODIFICATION_RESPONSE_ADDITIONAL_USAGE_REPORTS_INFORMATION,
  SESSION_MODIFICATION_RESPONSE_CREATED_TRAFFIC_ENDPOINT,
  SESSION_MODIFICATION_RESPONSE_LAST = SESSION_MODIFICATION_RESPONSE_FAILED_RULE_ID
};

typedef struct
{
  struct pfcp_group grp;
  struct pfcp_response response;

  pfcp_created_pdr_t created_pdr;
  pfcp_load_control_information_t load_control_information;
  pfcp_overload_control_information_t overload_control_information;
  pfcp_usage_report_t *usage_report;
  pfcp_failed_rule_id_t failed_rule_id;
  pfcp_additional_usage_reports_information_t additional_usage_reports_information;
  pfcp_created_traffic_endpoint_t *created_traffic_endpoint;
} pfcp_session_modification_response_t;

typedef struct
{
  struct pfcp_group grp;
} pfcp_session_deletion_request_t;

enum {
  SESSION_DELETION_RESPONSE_CAUSE = PFCP_RESPONSE_CAUSE,
  SESSION_DELETION_RESPONSE_OFFENDING_IE = PFCP_RESPONSE_OFFENDING_IE,
  SESSION_DELETION_RESPONSE_LOAD_CONTROL_INFORMATION,
  SESSION_DELETION_RESPONSE_OVERLOAD_CONTROL_INFORMATION,
  SESSION_DELETION_RESPONSE_USAGE_REPORT,
  SESSION_DELETION_RESPONSE_LAST = SESSION_DELETION_RESPONSE_USAGE_REPORT
};

typedef struct
{
  struct pfcp_group grp;
  struct pfcp_response response;

  pfcp_load_control_information_t load_control_information;
  pfcp_overload_control_information_t overload_control_information;
  pfcp_usage_report_t *usage_report;
} pfcp_session_deletion_response_t;

enum {
  SESSION_REPORT_REQUEST_REPORT_TYPE,
  SESSION_REPORT_REQUEST_DOWNLINK_DATA_REPORT,
  SESSION_REPORT_REQUEST_USAGE_REPORT,
  SESSION_REPORT_REQUEST_ERROR_INDICATION_REPORT,
  SESSION_REPORT_REQUEST_LOAD_CONTROL_INFORMATION,
  SESSION_REPORT_REQUEST_OVERLOAD_CONTROL_INFORMATION,
  SESSION_REPORT_REQUEST_ADDITIONAL_USAGE_REPORTS_INFORMATION,
  SESSION_REPORT_REQUEST_LAST = SESSION_REPORT_REQUEST_ADDITIONAL_USAGE_REPORTS_INFORMATION
};

typedef struct
{
  struct pfcp_group grp;

  pfcp_report_type_t report_type;
  pfcp_downlink_data_report_t downlink_data_report;
  pfcp_usage_report_t *usage_report;
  pfcp_error_indication_report_t error_indication_report;
  pfcp_load_control_information_t load_control_information;
  pfcp_overload_control_information_t overload_control_information;
  pfcp_additional_usage_reports_information_t additional_usage_reports_information;
} pfcp_session_report_request_t;

enum {
  SESSION_REPORT_RESPONSE_CAUSE = PFCP_RESPONSE_CAUSE,
  SESSION_REPORT_RESPONSE_OFFENDING_IE = PFCP_RESPONSE_OFFENDING_IE,
  SESSION_REPORT_RESPONSE_UPDATE_BAR,
  SESSION_REPORT_RESPONSE_SXSRRSP_FLAGS,
  SESSION_REPORT_RESPONSE_LAST = SESSION_REPORT_RESPONSE_SXSRRSP_FLAGS
};

typedef struct
{
  struct pfcp_group grp;
  struct pfcp_response response;

  pfcp_update_bar_response_t *update_bar;
  pfcp_sxsrrsp_flags_t sxsrrsp_flags;
} pfcp_session_report_response_t;

u8 * format_flags(u8 * s, va_list * args);
u8 * format_enum(u8 * s, va_list * args);
u8 * format_network_instance(u8 * s, va_list * args);
u8 * format_pfcp_msg_hdr(u8 * s, va_list * args);
u8 * format_user_plane_ip_resource_information(u8 * s, va_list * args);
u8 * format_redirect_information(u8 * s, va_list * args);
u8 * format_node_id(u8 * s, va_list * args);
u8 * format_outer_header_creation(u8 * s, va_list * args);

void cpy_redirect_information(pfcp_redirect_information_t *dst,
			      pfcp_redirect_information_t *src);
void free_redirect_information(void *p);

int pfcp_decode_msg(u16 type, u8 *p, int len, struct pfcp_group *grp);
int pfcp_encode_msg(u16 type, struct pfcp_group *grp, u8 **vec);
void pfcp_free_msg(u16 type, struct pfcp_group *grp);

#endif // included_vnet_pfcp_h

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
