#!/bin/sh

export ZEEK_INTERFACE=${ZEEK_INTERFACE:-eth0}

if [ "$#" != "0" ]; then
  echo executing user-provided command: $@ 1>&2
  exec "$@"
fi

echo "Waiting zeek interface to be UP ($ZEEK_INTERFACE)..."
until [ -n "$ZEEK_INTERFACE" ] && ip link show dev $ZEEK_INTERFACE | grep -q "state UP"; do
	sleep 5
done

sed -r -i "s/^interface=.*/interface=$ZEEK_INTERFACE/g" /usr/local/zeek/etc/node.cfg

echo "executing command: zeekctl deploy" 1>&2
zeekctl deploy
sleep 5
tail -f /dev/null /usr/local/zeek/logs/current/*log
