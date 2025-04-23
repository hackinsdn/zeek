#!/bin/sh

if [ "$#" != "0" ]; then
  echo executing user-provided command: $@ 1>&2
  exec "$@"
fi

ZEEK="/usr/local/zeek/bin/zeek"

if [ -n "$ZEEK_DISABLE_CHECKSUMS" ]; then
  ZEEK="$ZEEK -C"
fi

echo "Waiting zeek interface to be UP ($ZEEK_INTERFACE)..."
until [ -n "$ZEEK_INTERFACE" ] && ip link show dev $ZEEK_INTERFACE | grep -q "state UP"; do
	sleep 5
done

sed -r -i "s/^interface=.*/interface=$ZEEK_INTERFACE/g" /usr/local/zeek/etc/node.cfg

if zeek -NN Zeek::AF_Packet > /dev/null 2>&1; then
  ZEEK="$ZEEK -i af_packet::$ZEEK_INTERFACE"
else
  ZEEK="$ZEEK -i $ZEEK_INTERFACE"
fi

# Append user-provided arguments.
if [ -n "$ZEEK_ARGS" ]; then
  ZEEK="$ZEEK $ZEEK_ARGS"
fi

# Append user-provided scripts.
if [ -n "$ZEEK_SCRIPTS" ]; then
  ZEEK="$ZEEK $ZEEK_SCRIPTS"
fi

echo "executing command: $ZEEK" 1>&2
eval "$ZEEK"
