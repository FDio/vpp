#!/usr/bin/bash 

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Cisco Systems, Inc.

# Generate ca private key and certificate
openssl genrsa -out ca-key.pem 2048
openssl req -new -x509 -key ca-key.pem -out ca-cert.pem -days 3650 -subj "/C=US/ST=CA/L=San Jose/O=Cisco/CN=Fd.io Test Root CA"

# Generate intermediate CA key
openssl genrsa -out intermediate-key.pem 2048

# Create intermediate CA certificate request
openssl req -new -key intermediate-key.pem -out intermediate.csr -subj "/C=US/ST=CA/L=San Jose/O=Cisco/CN=Fd.io Test Intermediate CA"

# Sign intermediate certificate with root CA
openssl x509 -req -in intermediate.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out intermediate-cert.pem -days 3650

# Create a chain file (root + intermediate)
cat ca-cert.pem intermediate-cert.pem > ca-chain.pem

# Create CRL configuration
cat > crl.conf << EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
database = index.txt
serial = serial
crlnumber = crlnumber
default_crl_days = 30
default_md = sha256
EOF

# Initialize files
touch index.txt
echo 01 > serial
echo 01 > crlnumber

# Generate empty CRL
openssl ca -config crl.conf -gencrl -keyfile ca-key.pem -cert ca-cert.pem -out ca-crl.pem