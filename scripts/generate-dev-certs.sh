#!/bin/bash
set -euo pipefail
CERT_DIR="./certs"
mkdir -p "$CERT_DIR"
openssl req -new -x509 -days 3650 -nodes \
    -keyout "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.crt" \
    -subj "/CN=Zovark Internal CA"
openssl req -new -nodes \
    -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" \
    -subj "/CN=zovark-postgres"
openssl x509 -req -days 365 -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
    -out "$CERT_DIR/server.crt"
chmod 600 "$CERT_DIR/server.key"
echo "Dev certs generated in $CERT_DIR/"
