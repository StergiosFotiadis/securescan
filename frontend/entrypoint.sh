#!/bin/sh
set -e

if [ -z "$BASIC_AUTH_USER" ] || [ -z "$BASIC_AUTH_PASSWORD" ]; then
    echo "ERROR: BASIC_AUTH_USER and BASIC_AUTH_PASSWORD must be set"
    exit 1
fi

PASSWORD_HASH=$(openssl passwd -apr1 "$BASIC_AUTH_PASSWORD")
echo "${BASIC_AUTH_USER}:${PASSWORD_HASH}" > /etc/nginx/.htpasswd

exec nginx -g 'daemon off;'
