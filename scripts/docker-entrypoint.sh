#!/bin/sh
# Starts the API inside the container.
# Runs as the owner of the bind-mounted ./outbox directory (the user who cloned
# the repo), so outbox/sms.jsonl on the host is readable without sudo.
set -e
mkdir -p /app/outbox
if [ "$(id -u)" = "0" ]; then
  uid=$(stat -c %u /app/outbox)
  gid=$(stat -c %g /app/outbox)
  if [ "$uid" != "0" ]; then
    exec setpriv --reuid="$uid" --regid="$gid" --clear-groups "$@"
  fi
fi
exec "$@"
