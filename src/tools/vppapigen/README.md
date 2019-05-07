# VPP API Language

## Scalar Value Types

.api type|size|C type|Python type
---------|----|------------------
i8       |   1|i8    |int
u8       |   1|u8    |int
i16      |   2|i16   |int
u16      |   2|u16   |int
i32      |   4|i32   |int
u32      |   4|u32   |int
i64      |   8|i64   |int
u64      |   8|u64   |int
f64      |   8|f64   |float
bool     |   1|bool  |boolean
string   |   -|vl_api_string_t|str

## User Defined Types
### vnet/ip/ip_types.api

.api type|size|C type|Python type
---------|----|------|-----------
vl_api_address_t|20|vl_api_address_t|IPv4Address or IPv6 address
vl_api_ip4_address_t|4|vl_api_ip4_address_t|IPv4Address
vl_api_ip6_address_t|16|vl_api_ip6_address_t|IPv6Address
vl_api_prefix_t|21|vl_api_prefix_t|IPv4Network or IPv6Network
vl_api_ip4_prefix_t|5|vl_api_ip4_prefix_t|IPv4Network
vl_api_ip6_prefix_t|17|vl_api_ip6_prefix_t|IPv6Network

### vnet/ethernet/ethernet_types.api
.api type|size|C type|Python type
---------|----|------|-----------
vl_api_mac_address_t|6|vl_api_mac_address_t|MACAddress

### vnet/interface_types.api
.api type|size|C type|Python type
---------|----|------|-----------
vl_api_interface_index_t|4|vl_api_interface_index_t|int

## More explicit types

### String versus bytes
A byte string with a maximum length of 64:
```
u8 name[64];
```
Before the "string" type was added, text string were defined like this. The implications of that was the user would have to know if the field represented a \0 ended C-string or a fixed length byte string.

An IPv4 or IPv6 address was previously defined like:
```
u8 is_ip6;
u8 address[16];
```

Which made it hard for language bindings to represent the address as anything but a byte string. The new explicit address types are shown above.
