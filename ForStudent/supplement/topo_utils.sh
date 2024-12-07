#!/bin/bash
#set -x

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

# Creates a veth pair
# params: endpoint1 endpoint2
function create_veth_pair {
    ip link add $1 type veth peer name $2
    ip link set $1 up
    ip link set $2 up
}

# Add a container with a certain image
# params: image_name container_name
function add_container {
	docker run -dit --network=none --privileged --cap-add NET_ADMIN --cap-add SYS_MODULE \
		 --hostname $2 --name $2 ${@:3} $1
	pid=$(docker inspect -f '{{.State.Pid}}' $(docker ps -aqf "name=$2"))
	mkdir -p /var/run/netns
	ln -s /proc/$pid/ns/net /var/run/netns/$pid
}

# Set container interface's ip address and gateway
# params: container_name infname [ipaddress] [gw addr]
function set_intf_container {
    pid=$(docker inspect -f '{{.State.Pid}}' $(docker ps -aqf "name=$1"))
    ifname=$2
    ipaddr=$3
    echo "Add interface $ifname with ip $ipaddr to container $1"

    ip link set "$ifname" netns "$pid"
    if [ $# -ge 3 ]
    then
        ip netns exec "$pid" ip addr add "$ipaddr" dev "$ifname"
    fi
    ip netns exec "$pid" ip link set "$ifname" up
    if [ $# -ge 4 ]
    then
        ip netns exec "$pid" route add default gw $4
    fi
}

# Set container interface's ipv6 address and gateway
# params: container_name infname [ipaddress] [gw addr]
function set_v6intf_container {
    pid=$(docker inspect -f '{{.State.Pid}}' $(docker ps -aqf "name=$1"))
    ifname=$2
    ipaddr=$3
    echo "Add interface $ifname with ip $ipaddr to container $1"

    if [ $# -ge 3 ]
    then
        ip netns exec "$pid" ip addr add "$ipaddr" dev "$ifname"
    fi
    ip netns exec "$pid" ip link set "$ifname" up
    if [ $# -ge 4 ]
    then
        ip netns exec "$pid" route -6 add default gw $4
    fi
}

# Connects the bridge and the container
# params: bridge_name container_name [ipaddress] [gw addr]
function build_bridge_container_path {
    br_inf="veth$1$2"
    container_inf="veth$2$1"
    create_veth_pair $br_inf $container_inf
    brctl addif $1 $br_inf
    set_intf_container $2 $container_inf $3 $4
}

# Connects two ovsswitches
# params: ovs1 ovs2
function build_ovs_path {
    inf1="veth$1$2"
    inf2="veth$2$1"
    create_veth_pair $inf1 $inf2
    ovs-vsctl add-port $1 $inf1
    ovs-vsctl add-port $2 $inf2
}

# Connects a container to an ovsswitch
# params: ovs container [ipaddress] [gw addr]
function build_ovs_container_path {
    ovs_inf="veth$1$2"
    container_inf="veth$2$1"
    create_veth_pair $ovs_inf $container_inf
    ovs-vsctl add-port $1 $ovs_inf
    set_intf_container $2 $container_inf $3 $4
}

HOSTIMAGE="sdnfv-final-host"
ROUTERIMAGE="sdnfv-final-frr"

# Build host base image
docker build containers/host -t "$HOSTIMAGE"
docker build containers/frr -t "$ROUTERIMAGE"

# TODO Write your own code