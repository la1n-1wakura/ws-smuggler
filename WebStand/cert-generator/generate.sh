#!/bin/sh
set -eu

rm -f /certs/server.crt /certs/server.key /certs/server.pem

openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -keyout /certs/server.key \
  -out /certs/server.crt \
  -days 365 \
  -subj "/C=RU/ST=State/L=City/O=WebStand/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

cat /certs/server.crt /certs/server.key > /certs/server.pem
# HAProxy runs as a non-root user and must read the combined certificate.
# This certificate volume is local lab-only material, not a production secret.
chmod 644 /certs/server.key /certs/server.pem

echo "Generated a new WebStand TLS certificate"
tail -f /dev/null
