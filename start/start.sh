#!/bin/sh

TAYGA=/home/azryve/src/tayga/tayga
DYNPOOL=172.16.0.0/22
TUN=tun2612
TUN4ADDR=172.16.0.1
TUN6ADDR=fdde::1/64
PREFIX=fdde::/96
CONF=tayga_${TUN}.conf

killall tayga 2> /dev/null
cat > ${CONF} << EOF
tun-device ${TUN}
ipv4-addr ${TUN4ADDR}
prefix ${PREFIX}
dynamic-pool ${DYNPOOL}
data-dir /var/db/tayga-${TUN}
writer-count 4
EOF

[ -e /var/db/tayga-${TUN} ] || mkdir /var/db/tayga-${TUN}

ifconfig $TUN destroy
ifconfig $TUN create mtu 9000 up
ifconfig $TUN inet6 -nud
route add -inet ${DYNPOOL} -iface ${TUN} > /dev/null
ifconfig ${TUN} inet6 ${TUN6ADDR} up

gdb --args ${TAYGA} -d -c ${CONF}
