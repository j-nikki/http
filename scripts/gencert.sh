#!/bin/env zsh

set -e

# generate pkey.pem
openssl genrsa -out "$1/pkey.pem" 2048

# generate cert.pem
openssl req -new -x509 -key "$1/pkey.pem" -out "$1/cert.pem" -days 3650 -subj "/C=US/ST=YourState/L=YourCity/O=YourOrganization/OU=YourUnit/CN=www.yourdomain.com"
