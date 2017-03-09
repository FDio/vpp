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

-- Experimental prototype CLI using API to VPP, with tab completion
--
-- Written by Andrew Yourtchenko (ayourtch@cisco.com) 2010,2016
--

vpp = require "vpp-lapi"


local dotdotdot = "..."

-- First the "readline" routine

readln = {
split = function(str, pat)
  local t = {}  -- NOTE: use {n = 0} in Lua-5.0
  local fpat = "(.-)" .. pat
  local last_end = 1
  if str then
    local s, e, cap = str:find(fpat, 1)
    while s do
      if s ~= 1 or cap ~= "" then
        table.insert(t,cap)
      end
      last_end = e+1
      s, e, cap = str:find(fpat, last_end)
    end
    if last_end <= #str then
      cap = str:sub(last_end)
      table.insert(t, cap)
    end
  end
  return t
end,

reader = function()
  local rl = {}

  rl.init = function()
    os.execute("stty -icanon min 1 -echo")
    rl.rawmode = true
  end

  rl.done = function()
    os.execute("stty icanon echo")
    rl.rawmode = false
  end

  rl.prompt = ">"
  rl.history = { "" }
  rl.history_index = 1
  rl.history_length = 1

  rl.hide_cmd = function()
    local bs = string.char(8) .. " " .. string.char(8)
    for i = 1, #rl.command do
      io.stdout:write(bs)
    end
  end

  rl.show_cmd = function()
    if rl.command then
      io.stdout:write(rl.command)
    end
  end

  rl.store_history = function(cmd)
    if cmd == "" then
      return
    end
    rl.history[rl.history_length] = cmd
    rl.history_length = rl.history_length + 1
    rl.history_index = rl.history_length
    rl.history[rl.history_length] = ""
  end

  rl.readln = function()
    local done = false
    local need_prompt = true
    rl.command = ""

    if not rl.rawmode then
      rl.init()
    end

    while not done do
      if need_prompt then
        io.stdout:write(rl.prompt)
	io.stdout:write(rl.command)
        need_prompt = false
      end

      local ch = io.stdin:read(1)
      if ch:byte(1) == 27 then
        -- CONTROL
        local ch2 = io.stdin:read(1)
        -- arrows
        if ch2:byte(1) == 91 then
          local ch3 = io.stdin:read(1)
          local b = ch3:byte(1)
          if b == 65 then
            ch = "UP"
          elseif b == 66 then
            ch = "DOWN"
          elseif b == 67 then
            ch = "RIGHT"
          elseif b == 68 then
            ch = "LEFT"
          end
          -- print("Byte: " .. ch3:byte(1))
          -- if ch3:byte(1)
        end
      end

      if ch == "?" then
        io.stdout:write(ch)
        io.stdout:write("\n")
        if rl.help then
          rl.help(rl)
        end
        need_prompt = true
      elseif ch == "\t" then
        if rl.tab_complete then
          rl.tab_complete(rl)
        end
        io.stdout:write("\n")
        need_prompt = true
      elseif ch == "\n" then
        io.stdout:write(ch)
        done = true
      elseif ch == "\004" then
        io.stdout:write("\n")
        rl.command = nil
	done = true
      elseif ch == string.char(127) then
        if rl.command ~= "" then
          io.stdout:write(string.char(8) .. " " .. string.char(8))
          rl.command = string.sub(rl.command, 1, -2)
        end
      elseif #ch > 1 then
        -- control char
        if ch == "UP" then
          rl.hide_cmd()
          if rl.history_index == #rl.history then
            rl.history[rl.history_index] = rl.command
          end
          if rl.history_index > 1 then
            rl.history_index = rl.history_index - 1
            rl.command = rl.history[rl.history_index]
          end
          rl.show_cmd()
        elseif ch == "DOWN" then
          rl.hide_cmd()
          if rl.history_index < rl.history_length then
            rl.history_index = rl.history_index + 1
            rl.command = rl.history[rl.history_index]
          end
          rl.show_cmd()
        end
      else
        io.stdout:write(ch)
        rl.command = rl.command .. ch
      end
    end
    if rl.command then
      rl.store_history(rl.command)
    end
    return rl.command
  end
  return rl
end

}

--[[

r = reader()

local done = false

while not done do
  local cmd = r.readln()
  print("Command: " .. tostring(cmd))
  if not cmd or cmd == "quit" then
    done = true
  end
end

r.done()

]]

--------- MDS show tech parser

local print_section = nil
local list_sections = false

local curr_section = "---"
local curr_parser = nil

-- by default operate in batch mode
local batch_mode = true

local db = {}
local device = {}
device.output = {}
local seen_section = {}

function start_collection(name)
  device = {}
  seen_section = {}
end

function print_error(errmsg)
  print("@#$:" .. errmsg)
end

function keys(tbl)
  local t = {}
  for k, v in pairs(tbl) do
    table.insert(t, k)
  end
  return t
end

function tset (parent, ...)

  -- print ('set', ...)

  local len = select ('#', ...)
  local key, value = select (len-1, ...)
  local cutpoint, cutkey

  for i=1,len-2 do

    local key = select (i, ...)
    local child = parent[key]

    if value == nil then
      if child == nil then  return
      elseif next (child, next (child)) then  cutpoint = nil  cutkey = nil
      elseif cutpoint == nil then  cutpoint = parent  cutkey = key  end

    elseif child == nil then  child = {}  parent[key] = child  end

    parent = child
    end

  if value == nil and cutpoint then  cutpoint[cutkey] = nil
  else  parent[key] = value  return value  end
  end


function tget (parent, ...)
  local len = select ('#', ...)
  for i=1,len do
    parent = parent[select (i, ...)]
    if parent == nil then  break  end
    end
  return parent
  end


local pager_lines = 23
local pager_printed = 0
local pager_skipping = false
local pager_filter_pipe = nil

function pager_reset()
  pager_printed = 0
  pager_skipping = false
  if pager_filter_pipe then
    pager_filter_pipe:close()
    pager_filter_pipe = nil
  end
end


function print_more()
  io.stdout:write(" --More-- ")
end

function print_nomore()
  local bs = string.char(8)
  local bs10 = bs ..  bs ..  bs ..  bs ..  bs ..  bs ..  bs ..  bs ..  bs ..  bs
  io.stdout:write(bs10 .. "          " .. bs10)
end

function print_line(txt)
  if pager_filter_pipe then
    pager_filter_pipe:write(txt .. "\n")
    return
  end
  if pager_printed >= pager_lines then
    print_more()
    local ch = io.stdin:read(1)
    if ch == " " then
      pager_printed = 0
    elseif ch == "\n" then
      pager_printed = pager_printed - 1
    elseif ch == "q" then
      pager_printed = 0
      pager_skipping = true
    end
    print_nomore()
  end
  if not pager_skipping then
    print(txt)
    pager_printed = pager_printed + 1
  else
    -- skip printing
  end
end

function paged_write(text)
  local t = readln.split(text, "[\n]")
  if string.sub(text, -1) == "\n" then
    table.insert(t, "")
  end
  for i, v in ipairs(t) do
    if i < #t then
      print_line(v)
    else
      if pager_filter_pipe then
        pager_filter_pipe:write(v)
      else
        io.stdout:write(v)
      end
    end
  end
end





function get_choices(tbl, key)
  local res = {}
  for k, v in pairs(tbl) do
    if string.sub(k, 1, #key) == key then
      table.insert(res, k)
    elseif 0 < #key and dotdotdot == k then
      table.insert(res, k)
    end
  end
  return res
end

function get_exact_choice(choices, val)
  local exact_idx = nil
  local substr_idx = nil
  local substr_seen = false

  if #choices == 1 then
    if choices[1] == dotdotdot then
      return 1
    elseif string.sub(choices[1], 1, #val) == val then
      return 1
    else
      return nil
    end
  else
    for i, v in ipairs(choices) do
      if v == val then
        exact_idx = i
        substr_seen = true
      elseif choices[i] ~= dotdotdot and string.sub(choices[i], 1, #val) == val then
        if substr_seen then
          substr_idx = nil
        else
          substr_idx = i
          substr_seen = true
        end
      elseif choices[i] == dotdotdot then
        if substr_seen then
          substr_idx = nil
        else
          substr_idx = i
          substr_seen = true
        end
      end
    end
  end
  return exact_idx or substr_idx
end

function device_cli_help(rl)
  local key = readln.split(rl.command, "[ ]+")
  local tree = rl.tree
  local keylen = #key
  local fullcmd = ""
  local error = false
  local terse = true

  if ((#rl.command >= 1) and (string.sub(rl.command, -1) == " ")) or (#rl.command == 0) then
    table.insert(key, "")
    terse = false
  end

  for i, v in ipairs(key) do
    local choices = get_choices(tree, v)
    local idx = get_exact_choice(choices, v)
    if idx then
      local choice = choices[idx]
      tree = tree[choice]
      fullcmd = fullcmd .. choice .. " "
    else
      if i < #key then
        error = true
      end
    end

    if i == #key and not error then
      for j, w in ipairs(choices) do
        if terse then
          paged_write(w .. "\t")
        else
          paged_write("  " .. w .. "\n")
        end
      end
      paged_write("\n")
      if terse then
        paged_write(" \n")
      end
    end
  end
  pager_reset()
end

function device_cli_tab_complete(rl)
  local key = readln.split(rl.command, "[ ]+")
  local tree = rl.tree
  local keylen = #key
  local fullcmd = ""
  local error = false

  for i, v in ipairs(key) do
    local choices = get_choices(tree, v)
    local idx = get_exact_choice(choices, v)
    if idx and choices[idx] ~= dotdotdot then
      local choice = choices[idx]
      tree = tree[choice]
      -- print("level " .. i .. " '" .. choice .. "'")
      fullcmd = fullcmd .. choice .. " "
    else
      -- print("level " .. i .. " : " .. table.concat(choices, " ") .. " ")
      error = true
    end
  end
  if not error then
    rl.command = fullcmd
  else
    -- print("\n\nerror\n")
  end
  pager_reset()
end

function device_cli_exec(rl)

  local cmd_nopipe = rl.command
  local cmd_pipe = nil

  local pipe1, pipe2 = string.find(rl.command, "[|]")
  if pipe1 then
    cmd_nopipe = string.sub(rl.command, 1, pipe1-1)
    cmd_pipe = string.sub(rl.command, pipe2+1, -1)
  end

  local key = readln.split(cmd_nopipe .. " <cr>", "[ ]+")
  local tree = rl.tree
  local keylen = #key
  local fullcmd = ""
  local error = false
  local func = nil

  if cmd_pipe then
    pager_filter_pipe = io.popen(cmd_pipe, "w")
  end


  rl.choices = {}

  for i, v in ipairs(key) do
    local choices = get_choices(tree, v)
    local idx = get_exact_choice(choices, v)
    if idx then
      local choice = choices[idx]
      if i == #key then
        func = tree[choice]
      else
        if choice == dotdotdot then
          -- keep the tree the same, update the choice value to match the input string
          choices[idx] = v
          choice = v
        else
          tree = tree[choice]
        end
      end
      -- print("level " .. i .. " '" .. choice .. "'")
      table.insert(rl.choices, choice)
    else
      -- print("level " .. i .. " : " .. table.concat(choices, " ") .. " ")
      error = true
      return nil
    end
  end
  return func
end

function populate_tree(commands)
  local tree = {}

  for k, v in pairs(commands) do
    local key = readln.split(k .. " <cr>", "[ ]+")
    local xtree = tree
    for i, kk in ipairs(key) do
      if i == 1 and kk == "sh" then
        kk = "show"
      end
      if i == #key then
        if type(v) == "function" then
          xtree[kk] = v
        else
          xtree[kk] = function(rl) paged_write(table.concat(v, "\n") .. "\n") end
        end
      else
        if not xtree[kk] then
          xtree[kk] = {}
        end
        xtree = xtree[kk]
      end
    end
  end
  return tree
end

function trim (s)
  return (string.gsub(s, "^%s*(.-)%s*$", "%1"))
end


function init_vpp(vpp)
  local root_dir = "/home/ubuntu/vpp"
  local pneum_path = root_dir .. "/build-root/install-vpp_debug-native/vpp-api/lib64/libpneum.so"

  vpp:init({ pneum_path = pneum_path })

  vpp:init({ pneum_path = pneum_path })
  vpp:json_api(root_dir .. "/build-root/install-vpp_debug-native/vpp/vpp-api/vpe.api.json")



  vpp:connect("lua_cli")
end

function run_cli(vpp, cli)
  local reply = vpp:api_call("cli_inband", { cmd = cli })
  if reply and #reply == 1 then
    local rep = reply[1]
    if 0 == rep.retval then
      return rep.reply
    else
      return "XXXXXLUACLI: API RETVAL ERROR : " .. tostring(rep.retval)
    end
  else
    return "XXXXXLUACLI ERROR, RAW REPLY: " .. vpp.dump(reply)
  end
end


function toprintablestring(s)
  if type(s) == "string" then
    return "\n"..vpp.hex_dump(s)
  else
    return tostring(s)
  end
end

function interactive_cli(r)
  while not done do
    pager_reset()
    local cmd = r.readln()
    if not cmd then
      done = true
    elseif cmd == "quit" or cmd == "exit" then
      done = true
    else
      local func = device_cli_exec(r)
      if func then
	func(r)
      else
	if trim(cmd) == "" then
	else
	  for i = 1, #r.prompt do
	    paged_write(" ")
	  end
	  paged_write("^\n% Invalid input detected at '^' marker.\n\n")
	end
      end
    end
  end
end

device = {}
device.output = {}

init_vpp(vpp)
cmds_str = run_cli(vpp, "?")
vpp_cmds = readln.split(cmds_str, "\n")
vpp_clis = {}

for linenum, line in ipairs(vpp_cmds) do
  local m,h = string.match(line, "^  (.-)  (.*)$")
  if m and #m > 0 then
    table.insert(vpp_clis, m)
    device.output["vpp debug cli " .. m] = function(rl)
      -- print("ARBITRARY CLI" .. vpp.dump(rl.choices))
      print("LUACLI command: " .. table.concat(rl.choices, " "))
      local sub = {}
      --
      for i=4, #rl.choices -1 do
        table.insert(sub, rl.choices[i])
      end
      local cli = table.concat(sub, " ")
      print("Running CLI: " .. tostring(cli))
      paged_write(run_cli(vpp, cli))
    end
    device.output["vpp debug cli " .. m .. " " .. dotdotdot] = function(rl)
      print("ARGH")
    end

    local ret = run_cli(vpp, "help " .. m)
    device.output["help vpp debug cli " .. m] = { ret }
  end
end

for linenum, line in ipairs(vpp_clis) do
  -- print(line, ret)
end

for msgnum, msgname in pairs(vpp.msg_number_to_name) do
  local cli, numspaces = string.gsub(msgname, "_", " ")
  device.output["call " .. cli .. " " .. dotdotdot] = function(rl)
    print("ARGH")
  end
  device.output["call " .. cli] = function(rl)
    print("LUACLI command: " .. table.concat(rl.choices, " "))
    print("Running API: " .. msgname) -- vpp.dump(rl.choices))
    local out = {}
    local args = {}
    local ntaken = 0
    local argname = ""
    for i=(1+1+numspaces+1), #rl.choices-1 do
      -- print(i, rl.choices[i])
      if ntaken > 0 then
        ntaken = ntaken -1
      else
        local fieldname = rl.choices[i]
        local field = vpp.msg_name_to_fields[msgname][fieldname]
        if field then
          local s = rl.choices[i+1]
          s=s:gsub("\\x(%x%x)",function (x) return string.char(tonumber(x,16)) end)
          args[fieldname] = s
          ntaken = 1
        end
      end
    end
    -- print("ARGS: ", vpp.dump(args))
    local ret = vpp:api_call(msgname, args)
    for i, reply in ipairs(ret) do
      table.insert(out, "=================== Entry #" .. tostring(i))
      for k, v in pairs(reply) do
        table.insert(out, "   " .. tostring(k) .. " : " .. toprintablestring(v))
      end
    end
    -- paged_write(vpp.dump(ret) .. "\n\n")
    paged_write(table.concat(out, "\n").."\n\n")
  end
  device.output["call " .. cli .. " help"] = function(rl)
    local out = {}
    for k, v in pairs(vpp.msg_name_to_fields[msgname]) do
      table.insert(out, tostring(k) .. " : " .. v["ctype"] .. " ; " .. tostring(vpp.dump(v)) )
    end
    -- paged_write(vpp.dump(vpp.msg_name_to_fields[msgname]) .. "\n\n")
    paged_write(table.concat(out, "\n").."\n\n")
  end
-- vpp.msg_name_to_number = {}
end



local r = readln.reader()
local done = false

r.prompt = "VPP(luaCLI)#"

r.help = device_cli_help
r.tab_complete = device_cli_tab_complete
print("===== CLI view, use ^D to end =====")

r.tree = populate_tree(device.output)
-- readln.pretty("xxxx", r.tree)


for idx, an_arg in ipairs(arg) do
  local fname = an_arg
  if fname == "-i" then
    pager_lines = 23
    interactive_cli(r)
  else
    pager_lines = 100000000
    for line in io.lines(fname) do
      r.command = line
      local func = device_cli_exec(r)
      if func then
	func(r)
      end
    end
  end
end

if #arg == 0 then
  print("You should specify '-i' as an argument for the interactive session,")
  print("but with no other sources of commands, we start interactive session now anyway")
   interactive_cli(r)
end

vpp:disconnect()
r.done()


