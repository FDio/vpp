
#!/usr/bin/env bash
reset
printf '\033[3J'
sudo rmmod vpp_kdi
sudo insmod kdi/vpp_kdi.ko debug=0
sudo sync
log=run.log
gdbcmd=$(mktemp)
trap 'rm -f "$gdbcmd"' EXIT
cat > "$gdbcmd" <<'EOF'
set confirm off
run
if $_isvoid ($_exitcode)
bt
else
quit
end
EOF
script -qefc "sudo gdb -q -x '$gdbcmd' --args bin/vpp -c startup.conf" "$log"
sudo dmesg -c | tee -a "$log"

