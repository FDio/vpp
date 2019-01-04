sudo rm -r build-root/build-vpp_debug-native/
sudo rm -r build-root/build-vpp-native/
sudo rm -r build-root/install-vpp-native/
sudo rm -r build-root/install-vpp_debug-native/
sudo rm build-root/*.deb
sudo rm build-root/*.buildinfo
sudo rm build-root/*.changes
sudo make wipe
sudo make wipe-release
sudo make build-release
sudo make pkg-deb
