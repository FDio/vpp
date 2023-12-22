#!/bin/bash

wget https://github.com/stunnel/static-curl/releases/download/8.5.0/curl-static-amd64-8.5.0.tar.xz
tar -xvf ./curl-static-amd64-8.5.0.tar.xz
cp curl /usr/bin/curl