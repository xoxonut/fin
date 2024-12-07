all:
	sudo wg-quick up wg0
	docker compose up -d
	sudo ovs-vsctl add-br ovs1
	sudo ovs-vsctl add-br ovs2
	sudo ovs-vsctl add-port ovs1 patch-ovs2 -- set interface patch-ovs2 type=patch options:peer=patch-ovs1
	sudo ovs-vsctl add-port ovs2 patch-ovs1 -- set interface patch-ovs1 type=patch options:peer=patch-ovs2
	sudo ovs-vsctl set bridge ovs1 protocol=OpenFlow14
	sudo ovs-vsctl set-controller ovs1 tcp:192.168.100.2:6653
	sudo ovs-vsctl set bridge ovs2 protocol=OpenFlow14
	sudo ovs-vsctl set-controller ovs2 tcp:192.168.100.2:6653
	sudo ovs-vsctl add-port ovs2 vxlan0 -- set interface vxlan0 type=vxlan options:remote_ip=192.168.60.1
	sudo ovs-docker add-port ovs2 eth1 h1 --ipaddress=172.16.1.2/24
	sudo ovs-docker add-port ovs1 eth1 R2 --ipaddress=192.168.63.2/24
	sudo ip link add dev h2_veth type veth peer name R2_veth
	{ \
	h2_PID=$$(docker inspect -f '{{.State.Pid}}' h2); \
	R2_PID=$$(docker inspect -f '{{.State.Pid}}' R2); \
	sudo ip link set h2_veth netns $$h2_PID; \
	sudo ip link set R2_veth netns $$R2_PID; \
	sudo nsenter -t $$h2_PID -n ip addr add 172.17.1.2/24 dev h2_veth; \
	sudo nsenter -t $$h2_PID -n ip link set h2_veth up; \
	sudo nsenter -t $$R2_PID -n ip addr add 172.17.1.1/24 dev R2_veth; \
	sudo nsenter -t $$R2_PID -n ip link set R2_veth up; \
	}
	sudo ovs-docker add-port ovs1 eth1 R1 --ipaddress=192.168.63.1/24
	sudo ovs-docker add-port ovs1 eth2 R1 --ipaddress=192.168.70.1/24
	sudo ovs-docker add-port ovs1 eth3 R1 --ipaddress=172.16.1.69/24

	docker exec -it h2 ip route add default via 172.17.1.1
	docker exec -it h1 ip route add default via 172.16.1.69
clean:
	sudo wg-quick down wg0
	docker compose down
	sudo ovs-vsctl del-br ovs1
	sudo ovs-vsctl del-br ovs2
