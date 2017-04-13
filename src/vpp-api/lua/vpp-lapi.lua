--[[
/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
]]

-- json decode/encode from https://gist.github.com/tylerneylon/59f4bcf316be525b30ab
-- licensed by the author tylerneylon into public domain. Thanks!

local json = {}

-- Internal functions.

local function kind_of(obj)
  if type(obj) ~= 'table' then return type(obj) end
  local i = 1
  for _ in pairs(obj) do
    if obj[i] ~= nil then i = i + 1 else return 'table' end
  end
  if i == 1 then return 'table' else return 'array' end
end

local function escape_str(s)
  local in_char  = {'\\', '"', '/', '\b', '\f', '\n', '\r', '\t'}
  local out_char = {'\\', '"', '/',  'b',  'f',  'n',  'r',  't'}
  for i, c in ipairs(in_char) do
    s = s:gsub(c, '\\' .. out_char[i])
  end
  return s
end

-- Returns pos, did_find; there are two cases:
-- 1. Delimiter found: pos = pos after leading space + delim; did_find = true.
-- 2. Delimiter not found: pos = pos after leading space;     did_find = false.
-- This throws an error if err_if_missing is true and the delim is not found.
local function skip_delim(str, pos, delim, err_if_missing)
  pos = pos + #str:match('^%s*', pos)
  if str:sub(pos, pos) ~= delim then
    if err_if_missing then
      error('Expected ' .. delim .. ' near position ' .. pos)
    end
    return pos, false
  end
  return pos + 1, true
end

-- Expects the given pos to be the first character after the opening quote.
-- Returns val, pos; the returned pos is after the closing quote character.
local function parse_str_val(str, pos, val)
  val = val or ''
  local early_end_error = 'End of input found while parsing string.'
  if pos > #str then error(early_end_error) end
  local c = str:sub(pos, pos)
  if c == '"'  then return val, pos + 1 end
  if c ~= '\\' then return parse_str_val(str, pos + 1, val .. c) end
  -- We must have a \ character.
  local esc_map = {b = '\b', f = '\f', n = '\n', r = '\r', t = '\t'}
  local nextc = str:sub(pos + 1, pos + 1)
  if not nextc then error(early_end_error) end
  return parse_str_val(str, pos + 2, val .. (esc_map[nextc] or nextc))
end

-- Returns val, pos; the returned pos is after the number's final character.
local function parse_num_val(str, pos)
  local num_str = str:match('^-?%d+%.?%d*[eE]?[+-]?%d*', pos)
  local val = tonumber(num_str)
  if not val then error('Error parsing number at position ' .. pos .. '.') end
  return val, pos + #num_str
end


-- Public values and functions.

function json.stringify(obj, as_key)
  local s = {}  -- We'll build the string as an array of strings to be concatenated.
  local kind = kind_of(obj)  -- This is 'array' if it's an array or type(obj) otherwise.
  if kind == 'array' then
    if as_key then error('Can\'t encode array as key.') end
    s[#s + 1] = '['
    for i, val in ipairs(obj) do
      if i > 1 then s[#s + 1] = ', ' end
      s[#s + 1] = json.stringify(val)
    end
    s[#s + 1] = ']'
  elseif kind == 'table' then
    if as_key then error('Can\'t encode table as key.') end
    s[#s + 1] = '{'
    for k, v in pairs(obj) do
      if #s > 1 then s[#s + 1] = ', ' end
      s[#s + 1] = json.stringify(k, true)
      s[#s + 1] = ':'
      s[#s + 1] = json.stringify(v)
    end
    s[#s + 1] = '}'
  elseif kind == 'string' then
    return '"' .. escape_str(obj) .. '"'
  elseif kind == 'number' then
    if as_key then return '"' .. tostring(obj) .. '"' end
    return tostring(obj)
  elseif kind == 'boolean' then
    return tostring(obj)
  elseif kind == 'nil' then
    return 'null'
  else
    error('Unjsonifiable type: ' .. kind .. '.')
  end
  return table.concat(s)
end

json.null = {}  -- This is a one-off table to represent the null value.

function json.parse(str, pos, end_delim)
  pos = pos or 1
  if pos > #str then error('Reached unexpected end of input.') end
  local pos = pos + #str:match('^%s*', pos)  -- Skip whitespace.
  local first = str:sub(pos, pos)
  if first == '{' then  -- Parse an object.
    local obj, key, delim_found = {}, true, true
    pos = pos + 1
    while true do
      key, pos = json.parse(str, pos, '}')
      if key == nil then return obj, pos end
      if not delim_found then error('Comma missing between object items.') end
      pos = skip_delim(str, pos, ':', true)  -- true -> error if missing.
      obj[key], pos = json.parse(str, pos)
      pos, delim_found = skip_delim(str, pos, ',')
    end
  elseif first == '[' then  -- Parse an array.
    local arr, val, delim_found = {}, true, true
    pos = pos + 1
    while true do
      val, pos = json.parse(str, pos, ']')
      if val == nil then return arr, pos end
      if not delim_found then error('Comma missing between array items.') end
      arr[#arr + 1] = val
      pos, delim_found = skip_delim(str, pos, ',')
    end
  elseif first == '"' then  -- Parse a string.
    return parse_str_val(str, pos + 1)
  elseif first == '-' or first:match('%d') then  -- Parse a number.
    return parse_num_val(str, pos)
  elseif first == end_delim then  -- End of an object or array.
    return nil, pos + 1
  else  -- Parse true, false, or null.
    local literals = {['true'] = true, ['false'] = false, ['null'] = json.null}
    for lit_str, lit_val in pairs(literals) do
      local lit_end = pos + #lit_str - 1
      if str:sub(pos, lit_end) == lit_str then return lit_val, lit_end + 1 end
    end
    local pos_info_str = 'position ' .. pos .. ': ' .. str:sub(pos, pos + 10)
    error('Invalid json syntax starting at ' .. pos_info_str)
  end
end


local vpp = {}

local ffi = require("ffi")

--[[

The basic type definitions. A bit of weird gymnastic with
unionization of the hton* and ntoh* functions results
is to make handling of signed and unsigned types a bit cleaner,
essentially building typecasting into a C union.

The vl_api_opaque_message_t is a synthetic type assumed to have
enough storage to hold the entire API message regardless of the type.
During the operation it is casted to the specific message struct types.

]]


ffi.cdef([[

typedef uint8_t u8;
typedef int8_t i8;
typedef uint16_t u16;
typedef int16_t i16;
typedef uint32_t u32;
typedef int32_t i32;
typedef uint64_t u64;
typedef int64_t i64;
typedef double f64;
typedef float f32;

#pragma pack(1)
typedef union {
  u16 u16;
  i16 i16;
} lua_ui16t;

#pragma pack(1)
typedef union {
  u32 u32;
  i32 i32;
} lua_ui32t;

u16 ntohs(uint16_t hostshort);
u16 htons(uint16_t hostshort);
u32 htonl(uint32_t along);
u32 ntohl(uint32_t along);
void *memset(void *s, int c, size_t n);
void *memcpy(void *dest, void *src, size_t n);

#pragma pack(1)
typedef struct _vl_api_opaque_message {
  u16 _vl_msg_id;
  u8  data[65536];
} vl_api_opaque_message_t;
]])


-- CRC-based version stuff

local crc32c_table = ffi.new('const uint32_t[256]',
  { 0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4,
  0xC79A971F, 0x35F1141C, 0x26A1E7E8, 0xD4CA64EB,
  0x8AD958CF, 0x78B2DBCC, 0x6BE22838, 0x9989AB3B,
  0x4D43CFD0, 0xBF284CD3, 0xAC78BF27, 0x5E133C24,
  0x105EC76F, 0xE235446C, 0xF165B798, 0x030E349B,
  0xD7C45070, 0x25AFD373, 0x36FF2087, 0xC494A384,
  0x9A879FA0, 0x68EC1CA3, 0x7BBCEF57, 0x89D76C54,
  0x5D1D08BF, 0xAF768BBC, 0xBC267848, 0x4E4DFB4B,
  0x20BD8EDE, 0xD2D60DDD, 0xC186FE29, 0x33ED7D2A,
  0xE72719C1, 0x154C9AC2, 0x061C6936, 0xF477EA35,
  0xAA64D611, 0x580F5512, 0x4B5FA6E6, 0xB93425E5,
  0x6DFE410E, 0x9F95C20D, 0x8CC531F9, 0x7EAEB2FA,
  0x30E349B1, 0xC288CAB2, 0xD1D83946, 0x23B3BA45,
  0xF779DEAE, 0x05125DAD, 0x1642AE59, 0xE4292D5A,
  0xBA3A117E, 0x4851927D, 0x5B016189, 0xA96AE28A,
  0x7DA08661, 0x8FCB0562, 0x9C9BF696, 0x6EF07595,
  0x417B1DBC, 0xB3109EBF, 0xA0406D4B, 0x522BEE48,
  0x86E18AA3, 0x748A09A0, 0x67DAFA54, 0x95B17957,
  0xCBA24573, 0x39C9C670, 0x2A993584, 0xD8F2B687,
  0x0C38D26C, 0xFE53516F, 0xED03A29B, 0x1F682198,
  0x5125DAD3, 0xA34E59D0, 0xB01EAA24, 0x42752927,
  0x96BF4DCC, 0x64D4CECF, 0x77843D3B, 0x85EFBE38,
  0xDBFC821C, 0x2997011F, 0x3AC7F2EB, 0xC8AC71E8,
  0x1C661503, 0xEE0D9600, 0xFD5D65F4, 0x0F36E6F7,
  0x61C69362, 0x93AD1061, 0x80FDE395, 0x72966096,
  0xA65C047D, 0x5437877E, 0x4767748A, 0xB50CF789,
  0xEB1FCBAD, 0x197448AE, 0x0A24BB5A, 0xF84F3859,
  0x2C855CB2, 0xDEEEDFB1, 0xCDBE2C45, 0x3FD5AF46,
  0x7198540D, 0x83F3D70E, 0x90A324FA, 0x62C8A7F9,
  0xB602C312, 0x44694011, 0x5739B3E5, 0xA55230E6,
  0xFB410CC2, 0x092A8FC1, 0x1A7A7C35, 0xE811FF36,
  0x3CDB9BDD, 0xCEB018DE, 0xDDE0EB2A, 0x2F8B6829,
  0x82F63B78, 0x709DB87B, 0x63CD4B8F, 0x91A6C88C,
  0x456CAC67, 0xB7072F64, 0xA457DC90, 0x563C5F93,
  0x082F63B7, 0xFA44E0B4, 0xE9141340, 0x1B7F9043,
  0xCFB5F4A8, 0x3DDE77AB, 0x2E8E845F, 0xDCE5075C,
  0x92A8FC17, 0x60C37F14, 0x73938CE0, 0x81F80FE3,
  0x55326B08, 0xA759E80B, 0xB4091BFF, 0x466298FC,
  0x1871A4D8, 0xEA1A27DB, 0xF94AD42F, 0x0B21572C,
  0xDFEB33C7, 0x2D80B0C4, 0x3ED04330, 0xCCBBC033,
  0xA24BB5A6, 0x502036A5, 0x4370C551, 0xB11B4652,
  0x65D122B9, 0x97BAA1BA, 0x84EA524E, 0x7681D14D,
  0x2892ED69, 0xDAF96E6A, 0xC9A99D9E, 0x3BC21E9D,
  0xEF087A76, 0x1D63F975, 0x0E330A81, 0xFC588982,
  0xB21572C9, 0x407EF1CA, 0x532E023E, 0xA145813D,
  0x758FE5D6, 0x87E466D5, 0x94B49521, 0x66DF1622,
  0x38CC2A06, 0xCAA7A905, 0xD9F75AF1, 0x2B9CD9F2,
  0xFF56BD19, 0x0D3D3E1A, 0x1E6DCDEE, 0xEC064EED,
  0xC38D26C4, 0x31E6A5C7, 0x22B65633, 0xD0DDD530,
  0x0417B1DB, 0xF67C32D8, 0xE52CC12C, 0x1747422F,
  0x49547E0B, 0xBB3FFD08, 0xA86F0EFC, 0x5A048DFF,
  0x8ECEE914, 0x7CA56A17, 0x6FF599E3, 0x9D9E1AE0,
  0xD3D3E1AB, 0x21B862A8, 0x32E8915C, 0xC083125F,
  0x144976B4, 0xE622F5B7, 0xF5720643, 0x07198540,
  0x590AB964, 0xAB613A67, 0xB831C993, 0x4A5A4A90,
  0x9E902E7B, 0x6CFBAD78, 0x7FAB5E8C, 0x8DC0DD8F,
  0xE330A81A, 0x115B2B19, 0x020BD8ED, 0xF0605BEE,
  0x24AA3F05, 0xD6C1BC06, 0xC5914FF2, 0x37FACCF1,
  0x69E9F0D5, 0x9B8273D6, 0x88D28022, 0x7AB90321,
  0xAE7367CA, 0x5C18E4C9, 0x4F48173D, 0xBD23943E,
  0xF36E6F75, 0x0105EC76, 0x12551F82, 0xE03E9C81,
  0x34F4F86A, 0xC69F7B69, 0xD5CF889D, 0x27A40B9E,
  0x79B737BA, 0x8BDCB4B9, 0x988C474D, 0x6AE7C44E,
  0xBE2DA0A5, 0x4C4623A6, 0x5F16D052, 0xAD7D5351 }
);

local function CRC8(crc, d)
  return bit.bxor(bit.rshift(crc, 8), crc32c_table[bit.band(0xff, bit.bxor(crc, d))])
end

local function CRC16(crc, d)
  crc = CRC8(crc, bit.band(d, 0xFF))
  d = bit.rshift(d, 8)
  crc = CRC8(crc, bit.band(d, 0xFF))
  return crc
end

local function string_crc(str, crc)
  for i=1,#str do
    -- print("S", i, string.byte(str, i), string.char(string.byte(str, i)))
    crc = CRC8(crc, string.byte(str, i))
  end
  return crc
end

local tokens = {
  { ["match"] =' ', ["act"]             = { }  },
  { ["match"] ='\n', ["act"]             = { }  },
  { ["match"] ="manual_endian", ["act"]  = { "NODE_MANUAL_ENDIAN", "MANUAL_ENDIAN",    276 } },
  { ["match"] ="define", ["act"]         = { "NODE_DEFINE",        "DEFINE",           267 } },
  { ["match"] ="dont_trace", ["act"]     = { "NODE_DONT_TRACE",    "DONT_TRACE",       279 } },
  { ["match"] ="f64", ["act"]            = { "NODE_F64",           "PRIMTYPE",         string_crc } },
  { ["match"] ="i16", ["act"]            = { "NODE_I16",           "PRIMTYPE",         string_crc } },
  { ["match"] ="i32", ["act"]            = { "NODE_I32",           "PRIMTYPE",         string_crc } },
  { ["match"] ="i64", ["act"]            = { "NODE_I64",           "PRIMTYPE",         string_crc } },
  { ["match"] ="i8", ["act"]             = { "NODE_I8",            "PRIMTYPE",         string_crc } },
  { ["match"] ="manual_print", ["act"]   = { "NODE_MANUAL_PRINT",  "MANUAL_PRINT",     275 } },
  { ["match"] ="noversion", ["act"]      = { "NODE_NOVERSION",     "NOVERSION",        274 } },
  { ["match"] ="packed", ["act"]         = { "NODE_PACKED",        "TPACKED",          266 } },
  { ["match"] ="typeonly", ["act"]       = { "NODE_TYPEONLY",      "TYPEONLY",         278 } },
  { ["match"] ="u16", ["act"]            = { "NODE_U16",           "PRIMTYPE",         string_crc } },
  { ["match"] ="u32", ["act"]            = { "NODE_U32",           "PRIMTYPE",         string_crc } },
  { ["match"] ="u64", ["act"]            = { "NODE_U64",           "PRIMTYPE",         string_crc } },
  { ["match"] ="u8", ["act"]             = { "NODE_U8",            "PRIMTYPE",         string_crc } },
  { ["match"] ="union", ["act"]          = { "NODE_UNION",         "UNION",            271 } },
  { ["match"] ="uword", ["act"]          = { "NODE_UWORD",         "PRIMTYPE",         string_crc } },
  { ["match"] ="%(", ["act"]             = { "NODE_LPAR",          "LPAR",             259 } },
  { ["match"] ="%)", ["act"]             = { "NODE_RPAR",          "RPAR",             258 } },
  { ["match"] =";", ["act"]              = { "NODE_SEMI",          "SEMI",             260 } },
  { ["match"] ="%[", ["act"]             = { "NODE_LBRACK",        "LBRACK",           261 } },
  { ["match"] ="%]", ["act"]             = { "NODE_RBRACK",        "RBRACK",           262 } },
  { ["match"] ="%{", ["act"]             = { "NODE_LCURLY",        "LCURLY",           268 } },
  { ["match"] ="%}", ["act"]             = { "NODE_RCURLY",        "RCURLY",           269 } },
  { ["match"] ='%b""', ["act"]           = { "NODE_STRING",        "STRING",           string_crc } },
  { ["match"] ='%b@@', ["act"]           = { "NODE_HELPER",        "HELPER_STRING",    string_crc } },
  -- TODO: \ must be consumed
  { ["match"] ='[_a-zA-Z][_a-zA-Z0-9]*',
                       ["act"]           = { "NODE_NAME",          "NAME",             string_crc } },
  { ["match"] ='[0-9]+', ["act"]         = { "NODE_NUMBER",        "NUMBER",           string_crc } },
  { ["match"] ='#[^\n]+', ["act"]            = { "NODE_PRAGMA",        "PRAGMA",           nil } },
}


function vpp.crc_version_string(data)
  local input_crc = 0
  -- Get rid of comments
  data = data:gsub("/%*.-%*/", "")
  data = data:gsub("//[^\n]+", "")
  -- print(data)
  idx = 1
  while (true) do
    local matched = nil
    for k, v in ipairs(tokens) do
      if not matched then
        local x, y, cap = string.find(data, v["match"], idx)
        if x == idx then
          matched = { ["node"] = v["act"], ["x"] = x, ["y"] = y, ["cap"] = cap, ["chars"] = string.sub(data, x, y)  }
          -- print(k, v, x, y, cap, matched.chars, matched.node[0] )
        end
      end
    end
    if matched then
      idx = idx + (matched.y - matched.x + 1)
      if matched.node[1] then
        local act = matched.node[3]
        if type(act) == "function" then
          input_crc = act(matched.chars, input_crc)
        elseif type(act) == "number" then
          input_crc = CRC16(input_crc, act)
        end
        -- print(vpp.dump(matched))
      end
    else
      -- print("NOT MATCHED!")
      local crc = CRC16(input_crc, 0xFFFFFFFF)
      return string.sub(string.format("%x", crc), -8)
    end
  end
end


function vpp.dump(o)
   if type(o) == 'table' then
      local s = '{ '
      for k,v in pairs(o) do
         if type(k) ~= 'number' then k = '"'..k..'"' end
         s = s .. '['..k..'] = ' .. vpp.dump(v) .. ','
      end
      return s .. '} '
   else
      return tostring(o)
   end
end

function vpp.hex_dump(buf)
  local ret = {}
  for i=1,math.ceil(#buf/16) * 16 do
    if (i-1) % 16 == 0 then table.insert(ret, string.format('%08X  ', i-1)) end
    table.insert(ret, ( i > #buf and '   ' or string.format('%02X ', buf:byte(i)) ))
    if i %  8 == 0 then table.insert(ret, ' ') end
    if i % 16 == 0 then table.insert(ret, buf:sub(i-16+1, i):gsub('%c','.')..'\n' ) end
  end
  return table.concat(ret)
end


function vpp.c_str(text_in)
  local text = text_in -- \000 will be helpfully added by ffi.copy
  local c_str = ffi.new("char[?]", #text+1)
  ffi.copy(c_str, text)
  return c_str
end


function vpp.init(vpp, args)
  local vac_api = args.vac_api or [[
 int cough_vac_attach(char *vac_path, char *cough_path);
 int vac_connect(char *name, char *chroot_prefix, void *cb);
 int vac_disconnect(void);
 int vac_read(char **data, int *l);
 int vac_write(char *data, int len);
 void vac_free(char *data);
 uint32_t vac_get_msg_index(unsigned char * name);
]]

  vpp.vac_path = args.vac_path
  ffi.cdef(vac_api)
  local init_res = 0
  vpp.vac = ffi.load(vpp.vac_path)
  if (init_res < 0) then
    return nil
  end

  vpp.next_msg_num = 1
  vpp.msg_name_to_number = {}
  vpp.msg_name_to_fields = {}
  vpp.msg_number_to_name = {}
  vpp.msg_number_to_type = {}
  vpp.msg_number_to_pointer_type = {}
  vpp.msg_name_to_crc = {}
  vpp.c_type_to_fields = {}
  vpp.events = {}
  vpp.plugin_version = {}
  vpp.is_connected = false


  vpp.t_lua2c = {}
  vpp.t_c2lua = {}
  vpp.t_lua2c["u8"] = function(c_type, src, dst_c_ptr)
    if type(src) == "string" then
      -- ffi.copy adds a zero byte at the end. Grrr.
      -- ffi.copy(dst_c_ptr, src)
      ffi.C.memcpy(dst_c_ptr, vpp.c_str(src), #src)
      return(#src)
    elseif type(src) == "table" then
      for i,v in ipairs(src) do
        ffi.cast("u8 *", dst_c_ptr)[i-1] = v
      end
      return(#src)
    else
      return 1, src -- ffi.cast("u8", src)
    end
  end
  vpp.t_c2lua["u8"] = function(c_type, src_ptr, src_len)
    if src_len then
      return ffi.string(src_ptr, src_len)
    else
      return (tonumber(src_ptr))
    end
  end

  vpp.t_lua2c["u16"] = function(c_type, src, dst_c_ptr)
    if type(src) == "table" then
      for i,v in ipairs(src) do
        ffi.cast("u16 *", dst_c_ptr)[i-1] = ffi.C.htons(v)
      end
      return(2 * #src)
    else
      return 2, (ffi.C.htons(src))
    end
  end
  vpp.t_c2lua["u16"] = function(c_type, src_ptr, src_len)
    if src_len then
      local out = {}
      for i = 0,src_len-1 do
        out[i+1] = tonumber(ffi.C.ntohs(src_ptr[i]))
      end
      return out
    else
      return (tonumber(ffi.C.ntohs(src_ptr)))
    end
  end

  vpp.t_lua2c["u32"] = function(c_type, src, dst_c_ptr)
    if type(src) == "table" then
      for i,v in ipairs(src) do
        ffi.cast("u32 *", dst_c_ptr)[i-1] = ffi.C.htonl(v)
      end
      return(4 * #src)
    else
      return 4, (ffi.C.htonl(src))
    end
  end
  vpp.t_c2lua["u32"] = function(c_type, src_ptr, src_len)
    if src_len then
      local out = {}
      for i = 0,src_len-1 do
        out[i+1] = tonumber(ffi.C.ntohl(src_ptr[i]))
      end
      return out
    else
      return (tonumber(ffi.C.ntohl(src_ptr)))
    end
  end
  vpp.t_lua2c["i32"] = function(c_type, src, dst_c_ptr)
    if type(src) == "table" then
      for i,v in ipairs(src) do
        ffi.cast("i32 *", dst_c_ptr)[i-1] = ffi.C.htonl(v)
      end
      return(4 * #src)
    else
      return 4, (ffi.C.htonl(src))
    end
  end
  vpp.t_c2lua["i32"] = function(c_type, src_ptr, src_len)
    local ntohl = function(src)
      local u32val = ffi.cast("u32", src)
      local ntohlval = (ffi.C.ntohl(u32val))
      local out = tonumber(ffi.cast("i32", ntohlval + 0LL))
      return out
    end
    if src_len then
      local out = {}
      for i = 0,src_len-1 do
        out[i+1] = tonumber(ntohl(src_ptr[i]))
      end
    else
      return (tonumber(ntohl(src_ptr)))
    end
  end

  vpp.t_lua2c["u64"] = function(c_type, src, dst_c_ptr)
    if type(src) == "table" then
      for i,v in ipairs(src) do
        ffi.cast("u64 *", dst_c_ptr)[i-1] = v --- FIXME ENDIAN
      end
      return(8 * #src)
    else
      return 8, ffi.cast("u64", src) --- FIXME ENDIAN
    end
  end
  vpp.t_c2lua["u64"] = function(c_type, src_ptr, src_len)
    if src_len then
      local out = {}
      for i = 0,src_len-1 do
        out[i+1] = tonumber(src_ptr[i]) -- FIXME ENDIAN
      end
      return out
    else
      return (tonumber(src_ptr)) --FIXME ENDIAN
    end
  end




  vpp.t_lua2c["__MSG__"] = function(c_type, src, dst_c_ptr)
    local dst = ffi.cast(c_type .. " *", dst_c_ptr)
    local additional_len = 0
    local fields_info = vpp.c_type_to_fields[c_type]
    -- print("__MSG__ type: " .. tostring(c_type))
    ffi.C.memset(dst_c_ptr, 0, ffi.sizeof(dst[0]))
    -- print(vpp.dump(fields_info))
    -- print(vpp.dump(src))
    for k,v in pairs(src) do
      local field = fields_info[k]
      if not field then
        print("ERROR: field " .. tostring(k) .. " in message " .. tostring(c_type) .. " is unknown")
      end
      local lua2c = vpp.t_lua2c[field.c_type]
      -- print("__MSG__ field " .. tostring(k) .. " : " .. vpp.dump(field))
      -- if the field is not an array type, try to coerce the argument to a number
      if not field.array and type(v) == "string" then
        v = tonumber(v)
      end
      if not lua2c then
        print("__MSG__ " .. tostring(c_type) .. " t_lua2c: can not store field " .. field.name ..
              " type " .. field.c_type .. " dst " .. tostring(dst[k]))
        return 0
      end
      local len = 0
      local val = nil
      if field.array and (type(v) == "table") then
        -- print("NTFY: field " .. tostring(k) .. " in message " .. tostring(c_type) .. " is an array")
        for field_i, field_v in ipairs(v) do
          -- print("NTFY: setting member#" .. tostring(field_i) .. " to value " .. vpp.dump(field_v))
          local field_len, field_val = lua2c(field.c_type, field_v, dst[k][field_i-1])
          len = len + field_len
        end
      else
        len, val = lua2c(field.c_type, v, dst[k])
      end
      if not field.array then
        dst[k] = val
      else
        if 0 == field.array then
          additional_len = additional_len + len
          -- print("Adding " .. tostring(len) .. " bytes due to field " .. tostring(field.name))
          -- If there is a variable storing the length
          -- and the input table does not set it, do magic
          if field.array_size and not src[field.array_size] then
            local size_field = fields_info[field.array_size]
            if size_field then
              dst[field.array_size] = vpp.t_c2lua[size_field.c_type](size_field.c_type, len)
            end
          end
        end
      end
      -- print("Full message:\n" .. vpp.hex_dump(ffi.string(ffi.cast('void *', req_store_cache), 64)))
    end
    return (ffi.sizeof(dst[0])+additional_len)
  end

  vpp.t_c2lua["__MSG__"] = function(c_type, src_ptr, src_len)
    local out = {}
    local reply_typed_ptr = ffi.cast(c_type .. " *", src_ptr)
    local field_desc = vpp.c_type_to_fields[c_type]
    if src_len then
      for i = 0,src_len-1 do
        out[i+1] = vpp.t_c2lua[c_type](c_type, src_ptr[i])
      end
      return out
    end

    for k, v in pairs(field_desc) do
      local v_c2lua = vpp.t_c2lua[v.c_type]
      if v_c2lua then
        local len = v.array
        -- print(dump(v))
        if len then
          local len_field_name = k .. "_length"
          local len_field = field_desc[len_field_name]
          if (len_field) then
            local real_len = vpp.t_c2lua[len_field.c_type](len_field.c_type, reply_typed_ptr[len_field_name])
            out[k] =  v_c2lua(v.c_type, reply_typed_ptr[k], real_len)
          elseif len == 0 then
            -- check if len = 0, then must be a field which contains the size
            len_field =  field_desc[v.array_size]
            local real_len = vpp.t_c2lua[len_field.c_type](len_field.c_type, reply_typed_ptr[v.array_size])
            -- print("REAL length: " .. vpp.dump(v) .. " : " .. tostring(real_len))
            out[k] = v_c2lua(v.c_type, reply_typed_ptr[k], real_len)
          else
            -- alas, just stuff the entire array
            out[k] = v_c2lua(v.c_type, reply_typed_ptr[k], len)
          end
        else
          out[k] =  v_c2lua(v.c_type, reply_typed_ptr[k])
        end
      else
        out[k] = "<no accessor function for type " .. tostring(v.c_type) .. ">"
      end
      -- print(k, out[k])
    end
    return out
  end

  return vpp
end

function vpp.resolve_message_number(msgname)
  local name = msgname .. "_" .. vpp.msg_name_to_crc[msgname]
  local idx = vpp.vac.vac_get_msg_index(vpp.c_str(name))
  if vpp.debug_dump then
    print("Index for " .. tostring(name) .. " is " .. tostring(idx))
  end
  vpp.msg_name_to_number[msgname] = idx
  vpp.msg_number_to_name[idx] = msgname
  vpp.msg_number_to_type[idx] = "vl_api_" .. msgname .. "_t"
  vpp.msg_number_to_pointer_type[idx] = vpp.msg_number_to_type[idx] .. " *"
  ffi.cdef("\n\n enum { vl_msg_" .. msgname .. " = " .. idx .. " };\n\n")
end

function vpp.connect(vpp, client_name)
    local name = "lua_client"
    if client_name then
      name = client_name
    end
    local ret = vpp.vac.vac_connect(vpp.c_str(client_name), nil, nil)
    if tonumber(ret) == 0 then
      vpp.is_connected = true
    end
    for k, v in pairs(vpp.msg_name_to_number) do
      vpp.resolve_message_number(k)
    end
  end

function vpp.disconnect(vpp)
    vpp.vac.vac_disconnect()
  end

function vpp.json_api(vpp, path, plugin_name)
    -- print("Consuming the VPP api from "..path)
    local ffii = {}
    local f = io.open(path, "r")
    if not f then
      print("Could not open " .. path)
      return nil
    end
    local data = f:read("*all")
    local json = json.parse(data)
    if not (json.types or json.messages) then
      print("Can not parse " .. path)
      return nil
    end

    local all_types = {}

    for i, v in ipairs(json.types) do
      table.insert(all_types, { typeonly = 1, desc = v })
    end
    for i, v in ipairs(json.messages) do
      table.insert(all_types, { typeonly = 0, desc = v })
    end
    for i, v in ipairs(all_types) do
      local typeonly = v.typeonly
      local name = v.desc[1]
      local c_type = "vl_api_" .. name .. "_t"

      local fields = {}
      -- vpp.msg_name_to_fields[name] = fields
      -- print("CTYPE " .. c_type)
      vpp.c_type_to_fields[c_type] = fields
      vpp.t_lua2c[c_type] = vpp.t_lua2c["__MSG__"]
      vpp.t_c2lua[c_type] = vpp.t_c2lua["__MSG__"]

      local cdef = { "\n\n#pragma pack(1)\ntypedef struct _vl_api_", name, " {\n" }
      for ii, vv in ipairs(v.desc) do
        if type(vv) == "table" then
          if vv.crc then
            vpp.msg_name_to_crc[name] = string.sub(vv.crc, 3) -- strip the leading 0x
          else
            local fieldtype = vv[1]
            local fieldname = vv[2]
            local fieldcount = vv[3]
            local fieldcountvar = vv[4]
            local fieldrec = { name = fieldname, c_type = fieldtype, array = fieldcount, array_size = fieldcountvar }
            if fieldcount then
              table.insert(cdef, "  " .. fieldtype .. " " .. fieldname .. "[" .. fieldcount .. "];\n")
              if fieldtype == "u8" then
                -- any array of bytes is treated as a string
              elseif vpp.t_lua2c[fieldtype] then
                -- print("Array of " .. fieldtype .. " is ok!")
              else
                print("Unknown array type: ", name,  " : " , fieldname, " : ", fieldtype, ":", fieldcount, ":", fieldcountvar)
              end
            else
              table.insert(cdef, "  " .. fieldtype .. " " .. fieldname .. ";\n")
            end
            fields[fieldname] = fieldrec
          end
        end
      end

      table.insert(cdef, "} vl_api_" .. name .. "_t;")
      table.insert(ffii, table.concat(cdef))

      if typeonly == 0 then
        -- we will want to resolve this later
        if vpp.debug_dump then
          print("Remember to resolve " .. name)
        end
        vpp.msg_name_to_number[name] = -1
        if vpp.is_connected then
          vpp.resolve_message_number(name)
        end
      end

    end
    local cdef_full = table.concat(ffii)
    ffi.cdef(cdef_full)
end

function vpp.consume_api(vpp, path, plugin_name)
    -- print("Consuming the VPP api from "..path)
    local ffii = {}
    local f = io.open(path, "r")
    if not f then
      print("Could not open " .. path)
      return nil
    end
    local data = f:read("*all")
    -- Remove all C comments
    data = data:gsub("/%*.-%*/", "")
    if vpp.is_connected and not plugin_name then
      print(path .. ": must specify plugin name!")
      return
    end
    if plugin_name then
      vpp.plugin_version[plugin_name] = vpp.crc_version_string(data)
      local full_plugin_name = plugin_name .. "_" .. vpp.plugin_version[plugin_name]
      local reply = vpp:api_call("get_first_msg_id", { name = full_plugin_name } )
      vpp.next_msg_num = tonumber(reply[1].first_msg_id)
      print("Plugin " .. full_plugin_name .. " first message is " .. tostring(vpp.next_msg_num))
    end
    -- print ("data len: ", #data)
    data = data:gsub("\n(.-)(%S+)%s*{([^}]*)}", function (preamble, name, members)
      local _, typeonly = preamble:gsub("typeonly", "")
      local maybe_msg_id_field = { [0] = "u16 _vl_msg_id;", "" }
      local onedef = "\n\n#pragma pack(1)\ntypedef struct _vl_api_"..name.. " {\n" ..
	   -- "   u16 _vl_msg_id;" ..
           maybe_msg_id_field[typeonly] ..
	   members:gsub("%[[a-zA-Z_]+]", "[0]") ..
	   "} vl_api_" .. name .. "_t;"

      local c_type = "vl_api_" .. name .. "_t"

      local fields = {}
      -- vpp.msg_name_to_fields[name] = fields
      -- print("CTYPE " .. c_type)
      vpp.c_type_to_fields[c_type] = fields
      vpp.t_lua2c[c_type] = vpp.t_lua2c["__MSG__"]
      vpp.t_c2lua[c_type] = vpp.t_c2lua["__MSG__"]
      local mirec = { name = "_vl_msg_id", c_type = "u16", array = nil, array_size = nil }
      if typeonly == 0 then
        fields[mirec.name] = mirec
      end

      -- populate the field reflection table for the message
      -- sets the various type information as well as the accessors for lua<->C conversion
      members:gsub("(%S+)%s+(%S+);", function (fieldtype, fieldname)
          local fieldcount = nil
          local fieldcountvar = nil
          -- data = data:gsub("%[[a-zA-Z_]+]", "[0]")
          fieldname = fieldname:gsub("(%b[])", function(cnt)
              fieldcount = tonumber(cnt:sub(2, -2));
              if not fieldcount then
                fieldcount = 0
                fieldcountvar = cnt:sub(2, -2)
              end
              return ""
            end)
	  local fieldrec = { name = fieldname, c_type = fieldtype, array = fieldcount, array_size = fieldcountvar }
          if fieldcount then
            if fieldtype == "u8" then
              -- any array of bytes is treated as a string
            elseif vpp.t_lua2c[fieldtype] then
              -- print("Array of " .. fieldtype .. " is ok!")
            else
              print("Unknown array type: ", name,  " : " , fieldname, " : ", fieldtype, ":", fieldcount, ":", fieldcountvar)
            end
          end
	  fields[fieldname] = fieldrec
	end)

      -- print(dump(fields))

      if typeonly == 0 then
	local this_message_number = vpp.next_msg_num
	vpp.next_msg_num = vpp.next_msg_num + 1
	vpp.msg_name_to_number[name] = this_message_number
	vpp.msg_number_to_name[this_message_number] = name
	vpp.msg_number_to_type[this_message_number] = "vl_api_" .. name .. "_t"
	vpp.msg_number_to_pointer_type[this_message_number] = vpp.msg_number_to_type[this_message_number] .. " *"
	onedef = onedef .. "\n\n enum { vl_msg_" .. name .. " = " .. this_message_number .. " };\n\n"
      end
      table.insert(ffii, onedef);
      return "";
      end)
    local cdef = table.concat(ffii)
    -- print(cdef)
    ffi.cdef(cdef)
  end


function vpp.lua2c(vpp, c_type, src, dst_c_ptr)
  -- returns the number of bytes written to memory pointed by dst
  local lua2c = vpp.t_lua2c[c_type]
  if lua2c then
    return(lua2c(c_type, src, dst_c_ptr))
  else
    print("vpp.lua2c: do not know how to store type " .. tostring(c_type))
    local x = "a" .. nil
    return 0
  end
end

function vpp.c2lua(vpp, c_type, src_ptr, src_len)
  -- returns the lua data structure
  local c2lua = vpp.t_c2lua[c_type]
  if c2lua then
    return(c2lua(c_type, src_ptr, src_len))
  else
    print("vpp.c2lua: do not know how to load type " .. c_type)
    return nil
  end
end

local req_store_cache = ffi.new("vl_api_opaque_message_t[1]")

function vpp.api_write(vpp, api_name, req_table)
    local msg_num = vpp.msg_name_to_number[api_name]
    if not msg_num then
      print ("API call "..api_name.." is not known")
      return nil
    end

    if not req_table then
      req_table = {}
    end
    req_table._vl_msg_id = msg_num

    local packed_len = vpp:lua2c(vpp.msg_number_to_type[msg_num], req_table, req_store_cache)
    if vpp.debug_dump then
      print("Write Message length: " .. tostring(packed_len) .. "\n" .. vpp.hex_dump(ffi.string(ffi.cast('void *', req_store_cache), packed_len)))
    end

    res = vpp.vac.vac_write(ffi.cast('void *', req_store_cache), packed_len)
    return res
  end

local rep_store_cache = ffi.new("vl_api_opaque_message_t *[1]")
local rep_len_cache = ffi.new("int[1]")

function vpp.api_read(vpp)
    local rep_type = "vl_api_opaque_message_t"
    local rep = rep_store_cache
    local replen = rep_len_cache
    res = vpp.vac.vac_read(ffi.cast("void *", rep), replen)
    if vpp.debug_dump then
      print("Read Message length: " .. tostring(replen[0]) .. "\n" .. vpp.hex_dump(ffi.string(ffi.cast('void *', rep[0]), replen[0])))
    end

    local reply_msg_num = ffi.C.ntohs(rep[0]._vl_msg_id)
    local reply_msg_name = vpp.msg_number_to_name[reply_msg_num]

    local reply_typed_ptr = ffi.cast(vpp.msg_number_to_pointer_type[reply_msg_num], rep[0])
    local out = vpp:c2lua(vpp.msg_number_to_type[reply_msg_num], rep[0], nil, replen[0])
    if type(out) == "table" then
      out["luaapi_message_name"] = reply_msg_name
    end

    vpp.vac.vac_free(ffi.cast('void *',rep[0]))

    return reply_msg_name, out
  end

function vpp.api_call(vpp, api_name, req_table, options_in)
    local msg_num = vpp.msg_name_to_number[api_name]
    local end_message_name = api_name .."_reply"
    local replies = {}
    local cstruct = ""
    local options = options_in or {}
    if msg_num then
      if vpp.debug_dump then
        print("Message #" .. tostring(msg_num) .. " for name " .. tostring(api_name))
      end
      vpp:api_write(api_name, req_table)
      if not vpp.msg_name_to_number[end_message_name] or options.force_ping then
        end_message_name = "control_ping_reply"
        vpp:api_write("control_ping")
      end
      repeat
        reply_message_name, reply = vpp:api_read()
        if reply and not reply.context then
          -- there may be async events inbetween
          table.insert(vpp.events, reply)
        else
          if reply_message_name ~= "control_ping_reply" then
            -- do not insert the control ping encapsulation
            table.insert(replies, reply)
          end
        end
        -- print(reply)
      until reply_message_name == end_message_name
    else
      print(api_name .. " is an unknown API call")
      return nil
    end
    return replies
  end

return vpp
