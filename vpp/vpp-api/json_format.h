/*
 *------------------------------------------------------------------
 * json_format.h
 *
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
 *------------------------------------------------------------------
 */

#ifndef __JSON_FORMAT_H__
#define __JSON_FORMAT_H__

#include <vppinfra/clib.h>
#include <vppinfra/format.h>
#include <netinet/ip.h>

/* JSON value type */
typedef enum
{
  VAT_JSON_NONE,
  VAT_JSON_OBJECT,
  VAT_JSON_ARRAY,
  VAT_JSON_STRING,
  VAT_JSON_REAL,
  VAT_JSON_UINT,
  VAT_JSON_INT,
  VAT_JSON_IPV4,
  VAT_JSON_IPV6,
  VAT_JSON_MAX
} vat_json_val_type_t;

typedef struct vat_json_node_s vat_json_node_t;
typedef struct vat_json_pair_s vat_json_pair_t;

/* JSON object structure */
struct vat_json_node_s
{
  vat_json_val_type_t type;
  union
  {
    vat_json_pair_t *pairs;
    vat_json_node_t *array;
    u8 *string;
    struct in_addr ip4;
    struct in6_addr ip6;
    u64 uint;
    i64 sint;
    f64 real;
  };
};

struct vat_json_pair_s
{
  const char *name;
  vat_json_node_t value;
};

void vat_json_print (FILE * ofp, vat_json_node_t * node);
void vat_json_free (vat_json_node_t * node);

static_always_inline void
vat_json_init_object (vat_json_node_t * json)
{
  json->type = VAT_JSON_OBJECT;
  json->pairs = NULL;
}

static_always_inline void
vat_json_init_array (vat_json_node_t * json)
{
  json->type = VAT_JSON_ARRAY;
  json->array = NULL;
}

static_always_inline void
vat_json_set_string (vat_json_node_t * json, u8 * str)
{
  json->type = VAT_JSON_STRING;
  json->string = str;
}

static_always_inline void
vat_json_set_string_copy (vat_json_node_t * json, const u8 * str)
{
  u8 *ns = NULL;
  vec_validate (ns, strlen ((const char *) str));
  strcpy ((char *) ns, (const char *) str);
  vec_add1 (ns, '\0');
  vat_json_set_string (json, ns);
}

static_always_inline void
vat_json_set_int (vat_json_node_t * json, i64 num)
{
  json->type = VAT_JSON_INT;
  json->sint = num;
}

static_always_inline void
vat_json_set_uint (vat_json_node_t * json, u64 num)
{
  json->type = VAT_JSON_UINT;
  json->uint = num;
}

static_always_inline void
vat_json_set_real (vat_json_node_t * json, f64 real)
{
  json->type = VAT_JSON_REAL;
  json->real = real;
}

static_always_inline void
vat_json_set_ip4 (vat_json_node_t * json, struct in_addr ip4)
{
  json->type = VAT_JSON_IPV4;
  json->ip4 = ip4;
}

static_always_inline void
vat_json_set_ip6 (vat_json_node_t * json, struct in6_addr ip6)
{
  json->type = VAT_JSON_IPV6;
  json->ip6 = ip6;
}

static_always_inline vat_json_node_t *
vat_json_object_add (vat_json_node_t * json, const char *name)
{
  ASSERT (VAT_JSON_OBJECT == json->type);
  uword pos = vec_len (json->pairs);
  vec_validate (json->pairs, pos);
  json->pairs[pos].name = name;
  return &json->pairs[pos].value;
}

static_always_inline vat_json_node_t *
vat_json_array_add (vat_json_node_t * json)
{
  ASSERT (VAT_JSON_ARRAY == json->type);
  uword pos = vec_len (json->array);
  vec_validate (json->array, pos);
  return &json->array[pos];
}

static_always_inline vat_json_node_t *
vat_json_object_add_list (vat_json_node_t * json, const char *name)
{
  vat_json_node_t *array_node = vat_json_object_add (json, name);
  vat_json_init_array (array_node);
  return array_node;
}

static_always_inline void
vat_json_object_add_string_copy (vat_json_node_t * json,
				 const char *name, u8 * str)
{
  vat_json_set_string_copy (vat_json_object_add (json, name), str);
}

static_always_inline void
vat_json_object_add_uint (vat_json_node_t * json,
			  const char *name, u64 number)
{
  vat_json_set_uint (vat_json_object_add (json, name), number);
}

static_always_inline void
vat_json_object_add_int (vat_json_node_t * json, const char *name, i64 number)
{
  vat_json_set_int (vat_json_object_add (json, name), number);
}

static_always_inline void
vat_json_object_add_real (vat_json_node_t * json, const char *name, f64 real)
{
  vat_json_set_real (vat_json_object_add (json, name), real);
}

static_always_inline void
vat_json_object_add_ip4 (vat_json_node_t * json,
			 const char *name, struct in_addr ip4)
{
  vat_json_set_ip4 (vat_json_object_add (json, name), ip4);
}

static_always_inline void
vat_json_object_add_ip6 (vat_json_node_t * json,
			 const char *name, struct in6_addr ip6)
{
  vat_json_set_ip6 (vat_json_object_add (json, name), ip6);
}

static_always_inline void
vat_json_array_add_int (vat_json_node_t * json, i64 number)
{
  vat_json_set_int (vat_json_array_add (json), number);
}

static_always_inline void
vat_json_array_add_uint (vat_json_node_t * json, u64 number)
{
  vat_json_set_uint (vat_json_array_add (json), number);
}

static_always_inline void
vat_json_object_add_bytes (vat_json_node_t * json,
			   const char *name, u8 * array, uword size)
{
  ASSERT (VAT_JSON_OBJECT == json->type);
  vat_json_node_t *json_array = vat_json_object_add (json, name);
  vat_json_init_array (json_array);
  int i;
  for (i = 0; i < size; i++)
    {
      vat_json_array_add_uint (json_array, array[i]);
    }
}

static_always_inline vat_json_node_t *
vat_json_object_get_element (vat_json_node_t * json, const char *name)
{
  int i = 0;

  ASSERT (VAT_JSON_OBJECT == json->type);
  for (i = 0; i < vec_len (json->pairs); i++)
    {
      if (0 == strcmp (json->pairs[i].name, name))
	{
	  return &json->pairs[i].value;
	}
    }
  return NULL;
}

#endif /* __JSON_FORMAT_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
