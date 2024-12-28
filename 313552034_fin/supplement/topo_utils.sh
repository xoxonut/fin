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

    ip link set "$ifname" netns "$pid"
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

# creates a soft link to the network namespace of a container
# params: container_name
function soft_link {
	pid=$(docker inspect -f '{{.State.Pid}}' $(docker ps -aqf "name=$1"))
	mkdir -p /var/run/netns
	ln -s /proc/$pid/ns/net /var/run/netns/$pid
}

function docker-add-port-v6 {
    BRIDGE=$1
    INTERFACE=$2
    CONTAINER=$3
    IPADDRESS=$4
    PID=$(docker inspect -f '{{.State.Pid}}' $CONTAINER)
    ID=`uuidgen | sed 's/-//g'`
    PORTNAME="${ID:0:13}"
    ip link add "${PORTNAME}_l" type veth peer name "${PORTNAME}_c"
    ovs-vsctl --may-exist add-port "$BRIDGE" "${PORTNAME}_l" \
        -- set interface "${PORTNAME}_l" \
        external_ids:container_id="$CONTAINER" \
        external_ids:container_iface="$INTERFACE";
    ip link set "${PORTNAME}_l" up
    ip link set "${PORTNAME}_c" netns $PID
    ip netns exec $PID ip link set dev "${PORTNAME}_c" name $INTERFACE
    ip netns exec $PID ip link set $INTERFACE up
    ip netns exec $PID ip addr add $IPADDRESS dev $INTERFACE
}
# HOSTIMAGE="sdnfv-final-host"
# ROUTERIMAGE="sdnfv-final-frr"

# Build host base image
# docker build /home/sdn/Desktop/fin/313552034_fin/supplement/containers/host -t sdnfv-final-host
# docker build /home/sdn/Desktop/fin/313552034_fin/supplement/containers/frr -t sdnfv-final-frr

# TODO Write your own code
soft_link h1
soft_link h2
soft_link R1
soft_link R2
# ovs1 to ovs2
build_ovs_path ovs1 ovs2
# ipv4
# h2 to R2
# create_veth_pair vethh2R2 vethR2h2
# set_intf_container h2 vethh2R2 172.17.82.2/24 172.17.82.1
# set_intf_container R2 vethR2h2 172.17.82.1/24
# #R2 to R1
# ovs-docker add-port ovs1 ovs1R1_R1R2 R1 --ipaddress=192.168.63.1/24
# ovs-docker add-port ovs1 ovs1R2_R2R1 R2 --ipaddress=192.168.63.2/24
# # h1 to ovs R1
# build_ovs_container_path ovs2 h1 172.16.82.2/24 172.16.82.69
# ovs-docker add-port ovs2 ovs1h1_h1R1 R1 --ipaddress=172.16.82.69/24
# # R1 to onos
# ovs-docker add-port ovs1 ovs1onos onos  --ipaddress=192.168.100.2/24
# ovs-docker add-port ovs1 ovs1R1_R1onos R1  --ipaddress=192.168.100.3/24
# # R1 to vxlan
# # ovs-vsctl add-port ovs2 wg0 -- set interface wg0 type=vxlan options:remote_ip=192.168.60.82 \
# #     -- set interface wg0 ofport_request=10
# ovs-docker add-port ovs1 ovs1R1_vxlan R1 --ipaddress=192.168.70.82/24   

# onos to ovs1 and ovs2
ovs-vsctl set bridge ovs1 protocol=OpenFlow14
ovs-vsctl set-controller ovs1 tcp:127.0.0.1:6653
# ovs-vsctl set bridge ovs2 protocol=OpenFlow14
# ovs-vsctl set-controller ovs2 tcp:127.0.0.1:6653
# ipv6
# h2 to R2
# create_veth_pair vethh2R2_v6 vethR2h2_v6
# set_v6intf_container h2 vethh2R2_v6 2a0b:4e07:c4:182::2/64 2a0b:4e07:c4:182::1
# set_v6intf_container R2 vethR2h2_v6 2a0b:4e07:c4:182::1/64
#R2 to R1
docker-add-port-v6 ovs1 R1ovs1_v6 R1 fd63::1/64
docker-add-port-v6 ovs1 R2ovs1_v6 R2 fd63::2/64