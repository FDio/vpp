
#!/usr/bin/env bash
sudo rmmod vpp_kdi
sudo insmod kdi/vpp_kdi.ko debug=1
sudo sync
sudo bin/vpp -c startup.conf
sudo dmesg -c 

