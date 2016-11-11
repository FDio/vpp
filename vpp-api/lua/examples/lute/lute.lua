--[[
version = 1
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

-- LUTE: Lua Unit Test Environment
-- AKA what happens when screen tries to marry with lua and expect,
-- but escapes mid-ceremony.
--
-- comments: @ayourtch

ffi = require("ffi")

vpp = {}
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


ffi.cdef([[

int posix_openpt(int flags);
int grantpt(int fd);
int unlockpt(int fd);
char *ptsname(int fd);

typedef long pid_t;
typedef long ssize_t;
typedef long size_t;
typedef int nfds_t;
typedef long time_t;
typedef long suseconds_t;

pid_t fork(void);
pid_t setsid(void);

int close(int fd);
int open(char *pathname, int flags);

int dup2(int oldfd, int newfd);

ssize_t read(int fd, void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count);

struct pollfd {
               int   fd;         /* file descriptor */
               short events;     /* requested events */
               short revents;    /* returned events */
           };

int poll(struct pollfd *fds, nfds_t nfds, int timeout);

struct timeval {
               time_t      tv_sec;     /* seconds */
               suseconds_t tv_usec;    /* microseconds */
           };

int gettimeofday(struct timeval *tv, struct timezone *tz);

int inet_pton(int af, const char *src, void *dst);

]])

ffi.cdef([[
void *memset(void *s, int c, size_t n);
void *memcpy(void *dest, void *src, size_t n);
void *memmove(void *dest, const void *src, size_t n);
void *memmem(const void *haystack, size_t haystacklen,
        const void *needle, size_t needlelen);
]])



local O_RDWR = 2


function os_time()
  local tv = ffi.new("struct timeval[1]")
  local ret = ffi.C.gettimeofday(tv, nil)
  return tonumber(tv[0].tv_sec) + (tonumber(tv[0].tv_usec)/1000000.0)
end

function sleep(n)
  local when_wakeup = os_time() + n
  while os_time() <= when_wakeup do
    ffi.C.poll(nil, 0, 10)
  end
end


function c_str(text_in)
  local text = text_in 
  local c_str = ffi.new("char[?]", #text+1)
  ffi.copy(c_str, text)
  return c_str
end

function ip46(addr_text)
  local out = ffi.new("char [200]")
  local AF_INET6 = 10
  local AF_INET = 2
  local is_ip6 = ffi.C.inet_pton(AF_INET6, c_str(addr_text), out)
  if is_ip6 == 1 then
    return ffi.string(out, 16), true
  end
  local is_ip4 = ffi.C.inet_pton(AF_INET, c_str(addr_text), out)
  if is_ip4 then
    return (string.rep("4", 12).. ffi.string(out, 4)), false
  end
end

function pty_master_open()
  local fd = ffi.C.posix_openpt(O_RDWR)
  ffi.C.grantpt(fd)
  ffi.C.unlockpt(fd)
  local p = ffi.C.ptsname(fd)
  print("PTS:" .. ffi.string(p))
  return fd, ffi.string(p)
end

function pty_run(cmd)
  local master_fd, pts_name = pty_master_open()
  local child_pid = ffi.C.fork()
  if (child_pid == -1) then
    print("Error fork()ing")
    return -1
  end 
 
  if child_pid ~= 0 then
    -- print("Parent")
    return master_fd, child_pid
  end

  -- print("Child")
  if (ffi.C.setsid() == -1) then
    print("Child error setsid")
    os.exit(-1)
  end

  ffi.C.close(master_fd)

  local slave_fd = ffi.C.open(c_str(pts_name), O_RDWR)
  if slave_fd == -1 then
    print("Child can not open slave fd")
    os.exit(-2)
  end

  ffi.C.dup2(slave_fd, 0)
  ffi.C.dup2(slave_fd, 1)
  ffi.C.dup2(slave_fd, 2)
  os.execute(cmd)
end

function readch()
  local buf = ffi.new("char[1]")
  local nread= ffi.C.read(0, buf, 1)
  -- print("\nREADCH : " .. string.char(buf[0]))
  return string.char(buf[0])
end

function stdout_write(str)
  ffi.C.write(1, c_str(str), #str)
end


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
      stdout_write(bs)
    end
  end

  rl.show_cmd = function()
    if rl.command then
      stdout_write(rl.command)
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

  rl.readln = function(stdin_select_fn, batch_cmd, batch_when, batch_expect)
    local done = false
    local need_prompt = true
    rl.command = ""

    if not rl.rawmode then
      rl.init()
    end

    while not done do
      local indent_value = #rl.prompt + #rl.command
      if need_prompt then
        stdout_write(rl.prompt)
        stdout_write(rl.command)
        need_prompt = false
      end
      if type(stdin_select_fn) == "function" then
        while not stdin_select_fn(indent_value, batch_cmd, batch_when, batch_expect) do
          stdout_write(rl.prompt)
          stdout_write(rl.command)
          indent_value = #rl.prompt + #rl.command
        end
        if batch_cmd and ((os_time() > batch_when) or (batch_expect and expect_success(batch_expect, buf, 0))) then
          stdout_write("\n" .. rl.prompt .. batch_cmd .. "\n")
          if batch_expect then
            expect_done(batch_expect)
          end
          return batch_cmd, batch_expect
        end
      end
      local ch = readch()
      if ch:byte(1) == 27 then
        -- CONTROL
        local ch2 = readch()
        -- arrows
        if ch2:byte(1) == 91 then
          local ch3 = readch()
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
        stdout_write(ch)
        stdout_write("\n")
        if rl.help then
          rl.help(rl)
        end
        need_prompt = true
      elseif ch == "\t" then
        if rl.tab_complete then
          rl.tab_complete(rl)
        end
        stdout_write("\n")
        need_prompt = true
      elseif ch == "\n" then
        stdout_write(ch)
        done = true
      elseif ch == "\004" then
        stdout_write("\n")
        rl.command = nil
        done = true
      elseif ch == string.char(127) then
        if rl.command ~= "" then
          stdout_write(string.char(8) .. " " .. string.char(8))
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
        stdout_write(ch)
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

local select_fds = {}
local sessions = {}

local line_erased = false

function erase_line(indent)
  if not line_erased then
    line_erased = true
    stdout_write(string.rep(string.char(8), indent)..string.rep(" ", indent)..string.rep(string.char(8), indent))
  end
end

function do_select_stdin(indent, batch_cmd, batch_when, batch_expect)
  while true do
    local nfds = 1+#select_fds
    local pfds = ffi.new("struct pollfd[?]", nfds)
    pfds[0].fd = 0;
    pfds[0].events = 1;
    pfds[0].revents = 0;
    for i = 1,#select_fds do
      pfds[i].fd = select_fds[i].fd
      pfds[i].events = 1
      pfds[i].revents = 0
    end
    if batch_cmd and ((os_time() > batch_when) or (batch_expect and expect_success(batch_expect, buf, 0))) then
      return true
    end
    while ffi.C.poll(pfds, nfds, 10) == 0 do
      if batch_cmd and ((os_time() > batch_when) or (batch_expect and expect_success(batch_expect, buf, 0))) then
        return true
      end
      if line_erased then
        line_erased = false
        return false
      end
    end
    if pfds[0].revents == 1 then
      return true
    end
    for i = 1,#select_fds do
      if(pfds[i].revents > 0) then
        if pfds[i].fd ~= select_fds[i].fd then
          print("File descriptors unequal", pfds[i].fd, select_fds[i].fd)
        end
        select_fds[i].cb(select_fds[i], pfds[i].revents, indent)
      end
    end
  end
end

local buf = ffi.new("char [32768]")

function session_stdout_write(prefix, data)
  data = prefix .. data:gsub("\n", "\n"..prefix):gsub("\n"..prefix.."$", "\n")
  
  stdout_write(data)
end

function expect_success(sok, buf, nread)
  local expect_buf_sz = ffi.sizeof(sok.expect_buf) - 128
  local expect_buf_avail = expect_buf_sz - sok.expect_buf_idx
  -- print("EXPECT_SUCCESS: nread ".. tostring(nread).. " expect_buf_idx: " .. tostring(sok.expect_buf_idx) .. " expect_buf_avail: " .. tostring(expect_buf_avail) )
  if expect_buf_avail < 0 then
    print "EXPECT BUFFER OVERRUN ALREADY"
    os.exit(1)
  end
  if expect_buf_avail < nread then
    if (nread >= ffi.sizeof(sok.expect_buf)) then
      print("Read too large of a chunk to fit into expect buffer")
      return nil
    end
    local delta = nread - expect_buf_avail

    ffi.C.memmove(sok.expect_buf, sok.expect_buf + delta, expect_buf_sz - delta)
    sok.expect_buf_idx = sok.expect_buf_idx - delta
    expect_buf_avail = nread 
  end
  if sok.expect_buf_idx + nread > expect_buf_sz then
    print("ERROR, I have just overrun the buffer !")
    os.exit(1)
  end
  ffi.C.memcpy(sok.expect_buf + sok.expect_buf_idx, buf, nread)
  sok.expect_buf_idx = sok.expect_buf_idx + nread
  if sok.expect_str == nil then
    return true
  end
  local match_p = ffi.C.memmem(sok.expect_buf, sok.expect_buf_idx, sok.expect_str, sok.expect_str_len)
  if match_p ~= nil then
    return true
  end
  return false
end

function expect_done(sok)
  local expect_buf_sz = ffi.sizeof(sok.expect_buf) - 128
  if not sok.expect_str then 
    return false
  end
  local match_p = ffi.C.memmem(sok.expect_buf, sok.expect_buf_idx, sok.expect_str, sok.expect_str_len)
  if match_p ~= nil then
    if sok.expect_cb then
      sok.expect_cb(sok)
    end
    local match_idx = ffi.cast("char *", match_p) - ffi.cast("char *", sok.expect_buf)
    ffi.C.memmove(sok.expect_buf, ffi.cast("char *", match_p) + sok.expect_str_len, expect_buf_sz - match_idx - sok.expect_str_len)
    sok.expect_buf_idx = match_idx + sok.expect_str_len
    sok.expect_success = true

    sok.expect_str = nil
    sok.expect_str_len = 0
    return true
  end
end

function slave_events(sok, revents, indent)
  local fd = sok.fd
  local nread = ffi.C.read(fd, buf, ffi.sizeof(buf)-128)
  local idx = nread - 1
  while idx >= 0 and buf[idx] ~= 10 do
    idx = idx - 1
  end
  if idx >= 0 then
    erase_line(indent)
    session_stdout_write(sok.prefix, sok.buf .. ffi.string(buf, idx+1))
    sok.buf = ""
  end
  sok.buf = sok.buf .. ffi.string(buf+idx+1, nread-idx-1)
  -- print("\nRead: " .. tostring(nread))
  -- stdout_write(ffi.string(buf, nread))
  if expect_success(sok, buf, nread) then
    return true
  end
  return false
end


function start_session(name)
  local mfd, cpid = pty_run("/bin/bash")
  local sok =  { ["fd"] = mfd, ["cb"] = slave_events, ["buf"] = "", ["prefix"] = name .. ":", ["expect_buf"] = ffi.new("char [165536]"), ["expect_buf_idx"] = 0, ["expect_str"] = nil }
  table.insert(select_fds, sok)
  sessions[name] = sok
end

function command_transform(exe)
  if exe == "break" then
    exe = string.char(3)
  end
  return exe
end

function session_write(a_session, a_str)
  if has_session(a_session) then
    return tonumber(ffi.C.write(sessions[a_session].fd, c_str(a_str), #a_str))
  else
    return 0
  end
end

function session_exec(a_session, a_cmd)
  local exe = command_transform(a_cmd) .. "\n"
  session_write(a_session, exe)
end

function session_cmd(ui, a_session, a_cmd)
  if not has_session(a_session) then
    stdout_write("ERR: No such session '" .. tostring(a_session) .. "'\n")
    return nil
  end
  if a_session == "lua" then
    local func, msg = loadstring(ui.lua_acc .. a_cmd)
    -- stdout_write("LOADSTR: " .. vpp.dump({ ret, msg }) .. "\n")
    if not func and string.match(msg, "<eof>") then
      if a_session ~= ui.in_session then
         stdout_write("ERR LOADSTR: " .. tostring(msg) .. "\n")
         return nil
      end
      ui.lua_acc = ui.lua_acc .. a_cmd  .. "\n"
      return true
    end
    ui.lua_acc = ""
    local ret, msg = pcall(func)
    if ret then
      return true
    else
      stdout_write("ERR: " .. msg .. "\n") 
      return nil
    end
  else
    session_exec(a_session, a_cmd)
    if ui.session_cmd_delay then
      return { "delay", ui.session_cmd_delay }
    end
    return true
  end
end

function has_session(a_session)
  if a_session == "lua" then
    return true
  end
  return (sessions[a_session] ~= nil)
end

function command_match(list, input, output)
  for i, v in ipairs(list) do
    local m = {}
    m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8], m[9] = string.match(input, v[1])
    -- print("MATCH: ", vpp.dump(m))
    if m[1] then
       output["result"] = m
       output["result_index"] = i
       return m
    end 
  end
  return nil
end

function cmd_spawn_shell(ui, a_arg)
  start_session(a_arg[1])
  return true
end

function cmd_run_cmd(ui, a_arg)
  local a_sess = a_arg[1]
  local a_cmd = a_arg[2]
  return session_cmd(ui, a_sess, a_cmd)
end

function cmd_cd(ui, a_arg)
  local a_sess = a_arg[1]
  if has_session(a_sess) then
    ui.in_session = a_sess
    return true
  else
    stdout_write("ERR: Unknown session '".. tostring(a_sess) .. "'\n")
    return nil
  end
end

function cmd_sleep(ui, a_arg)
  return { "delay", tonumber(a_arg[1]) }
end

function cmd_expect(ui, a_arg)
  local a_sess = a_arg[1]
  local a_expect = a_arg[2]
  local sok = sessions[a_sess]
  if not sok then
    stdout_write("ERR: unknown session '" .. tostring(a_sess) .. "'\n")
    return nil
  end
  sok.expect_str = c_str(a_expect)
  sok.expect_str_len = #a_expect
  return { "expect", a_sess }
end

function cmd_info(ui, a_arg)
  local a_sess = a_arg[1]
  local sok = sessions[a_sess]
  if not sok then
    stdout_write("ERR: unknown session '" .. tostring(a_sess) .. "'\n")
    return nil
  end
  print("Info for session " .. tostring(a_sess) .. "\n")
  print("Expect buffer index: " .. tostring(sok.expect_buf_idx))
  print("Expect buffer: '" .. tostring(ffi.string(sok.expect_buf, sok.expect_buf_idx)) .. "'\n")
  if sok.expect_str then
    print("Expect string: '" .. tostring(ffi.string(sok.expect_str, sok.expect_str_len)) .. "'\n")
  else
    print("Expect string not set\n")
  end
end

function cmd_echo(ui, a_arg)
  local a_data = a_arg[1]
  print("ECHO: " .. tostring(a_data))
end

main_command_table = {
  { "^shell ([a-zA-Z0-9_]+)$", cmd_spawn_shell },
  { "^run ([a-zA-Z0-9_]+) (.+)$", cmd_run_cmd },
  { "^cd ([a-zA-Z0-9_]+)$", cmd_cd  },
  { "^sleep ([0-9]+)$", cmd_sleep },
  { "^expect ([a-zA-Z0-9_]+) (.-)$", cmd_expect },
  { "^info ([a-zA-Z0-9_]+)$", cmd_info },
  { "^echo (.-)$", cmd_echo }
}



function ui_set_prompt(ui)
  if ui.in_session then 
    if ui.in_session == "lua" then
      if #ui.lua_acc > 0 then
        ui.r.prompt = ui.in_session .. ">>"
      else
        ui.r.prompt = ui.in_session .. ">"
      end 
    else
      ui.r.prompt = ui.in_session .. "> "
    end
  else
    ui.r.prompt = "> "
  end
  return ui.r.prompt
end

function ui_run_command(ui, cmd)
  -- stdout_write("Command: " .. tostring(cmd) .. "\n")
  local ret = false
  if ui.in_session then
    if cmd then
      if cmd == "^D^D^D" then
        ui.in_session = nil
        ret = true
      else
        ret = session_cmd(ui, ui.in_session, cmd)
      end
    else
      ui.in_session = nil
      ret = true
    end
  else  
    if cmd then
      local out = {}
      if cmd == "" then
        ret = true
      end
      if command_match(main_command_table, cmd, out) then
        local i = out.result_index
        local m = out.result
        if main_command_table[i][2] then
          ret = main_command_table[i][2](ui, m)
        end
      end
    end
    if not cmd or cmd == "quit" then
      return "quit"
    end
  end
  return ret
end

local ui = {}
ui.in_session = nil
ui.r = readln.reader() 
ui.lua_acc = ""
ui.session_cmd_delay = 0.3

local lines = ""

local done = false
-- a helper function which always returns nil
local no_next_line = function() return nil end

-- a function which returns the next batch line
local next_line = no_next_line

local batchfile = arg[1]

if batchfile then
  local f = io.lines(batchfile)
  next_line = function() 
    local line = f()
    if line then 
      return line
    else 
      next_line = no_next_line
      session_stdout_write(batchfile .. ":", "End of batch\n")
      return nil
    end
  end
end


local batch_when = 0
local batch_expect = nil
while not done do
  local prompt = ui_set_prompt(ui)
  local batch_cmd = next_line() 
  local cmd, expect_sok = ui.r.readln(do_select_stdin, batch_cmd, batch_when, batch_expect)
  if expect_sok and not expect_success(expect_sok, buf, 0) then
    if not cmd_ret and next_line ~= no_next_line then
      print("ERR: expect timeout\n")
      next_line = no_next_line
    end
  else 
    local cmd_ret = ui_run_command(ui, cmd)
    if not cmd_ret and next_line ~= no_next_line then
      print("ERR: Error during batch execution\n")
      next_line = no_next_line
    end

    if cmd_ret  == "quit" then
      done = true
    end
    batch_expect = nil
    batch_when = 0
    if type(cmd_ret) == "table" then
      if cmd_ret[1] == "delay" then
	batch_when = os_time() + tonumber(cmd_ret[2])
      end
      if cmd_ret[1] == "expect" then
	batch_expect = sessions[cmd_ret[2]]
	batch_when = os_time() + 15
      end
    end
  end
end
ui.r.done()

os.exit(1)



