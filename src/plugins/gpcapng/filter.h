/* Geneve-specific constants */
#define GENEVE_UDP_DST_PORT 6081
#define GENEVE_VERSION_SHIFT 6
#define GENEVE_VERSION_MASK 0xC0
#define GENEVE_OPT_LEN_SHIFT 1
#define GENEVE_OPT_LEN_MASK 0x3E

/* Filter scope */
#define FILTER_SCOPE_INTERFACE    0
#define FILTER_SCOPE_GLOBAL       1

typedef struct geneve_option_def_t geneve_option_def_t;
typedef struct geneve_capture_filter_t geneve_capture_filter_t;
typedef struct geneve_option_filter_t geneve_option_filter_t;
typedef struct geneve_tuple_filter_t geneve_tuple_filter_t;


/* 
 * Option data types for GENEVE options
 */
typedef enum {
  GENEVE_OPT_TYPE_RAW = 0,     /* Raw bytes */
  GENEVE_OPT_TYPE_IPV4,        /* IPv4 address */
  GENEVE_OPT_TYPE_IPV6,        /* IPv6 address */
  GENEVE_OPT_TYPE_UINT8,       /* 8-bit integer */
  GENEVE_OPT_TYPE_UINT16,       /* 16-bit integer */
  GENEVE_OPT_TYPE_UINT32,       /* 32-bit integer */
  GENEVE_OPT_TYPE_STRING,       /* String */
} geneve_opt_data_type_t;

/* 5-tuple filter structure for IP/transport layer filtering */
struct geneve_tuple_filter_t {
  u8 *value;              /* Byte vector with exact values to match */
  u8 *mask;               /* Byte vector with masks for matching (1 bits are checked) */
  u32 length;             /* Length of the vectors */
};

/* Enhanced option definition for user-friendly filtering */
struct geneve_option_def_t {
  char *option_name;                   /* Friendly name for the option */
  u16 opt_class;                /* Class field */
  u8 type;                      /* Type field */
  u8 length;                    /* Length in bytes of the option data */
  geneve_opt_data_type_t preferred_type; /* Preferred input type for this option */
  format_function_t *format_fn; /* Optional format function for displaying option */
};


/* API declarations */
// static clib_error_t *gpcapng_init (vlib_main_t * vm);
void gpcapng_register_option_def (const char *name, u16 class, u8 type, u8 length, geneve_opt_data_type_t preferred_type);
int gpcapng_add_filter (u32 sw_if_index, const geneve_capture_filter_t *filter, u8 is_global);
int gpcapng_del_filter (u32 sw_if_index, u32 filter_id, u8 is_global);
//int gpcapng_enable_capture (u32 sw_if_index, u8 enable);

/* Geneve option filters */
struct geneve_option_filter_t {
    u8 present;            /* 1 if this option filter is active */
    
    /* Option can be specified by name or by direct class/type */
    union {
      char *option_name;   /* Reference to registered option by name */
      struct {
        u16 opt_class;     /* Option class */
        u8 type;           /* Option type */
      };
    };
    
    u8 match_any;          /* If 1, just match the presence of the option */
    u8 data_len;           /* Length of data to match (can be shorter than actual option) */
    u8 *data;              /* Data to match against option value */
    u8 *mask;              /* Optional mask for data matching (NULL = exact match) */
};

/* Filter structure with matching criteria */
struct geneve_capture_filter_t {
  u32 filter_id;           /* Unique filter identifier */
  char *name;              /* filter name */
  u32 destination_index;        /* output destination index for the filter, 0 = first */
  
  /* Basic Geneve header filters */
  u8 ver_present;          /* 1 if version field should be matched */
  u8 ver;                  /* Version to match */
  
  u8 opt_len_present;      /* 1 if option length should be matched */
  u8 opt_len;              /* Option length to match */
  
  u8 proto_present;        /* 1 if protocol should be matched */
  u16 protocol;            /* Inner protocol to match */
  
  u8 vni_present;          /* 1 if VNI should be matched */
  u32 vni;                 /* VNI to match */
  
  /* 5-tuple filters for outer and inner headers */
  u8 outer_tuple_present;  /* 1 if outer 5-tuple filter is active */
  geneve_tuple_filter_t outer_tuple;  /* Outer 5-tuple filter */
  
  u8 inner_tuple_present;  /* 1 if inner 5-tuple filter is active */
  geneve_tuple_filter_t inner_tuple;  /* Inner 5-tuple filter */
  
  geneve_option_filter_t *option_filters;       /* Vector of option filters */
};

