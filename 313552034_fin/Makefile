SHELL := /bin/bash

all:
	docker compose up -d
	sudo ovs-vsctl add-br ovs1
	sudo ovs-vsctl add-br ovs2
	sudo ./supplement/topo_utils.sh


clean:
	docker compose down
	sudo ovs-vsctl del-br ovs1
	sudo ovs-vsctl del-br ovs2
	sudo ip link del vethovs1ovs2
onos:
	ssh -o "StrictHostKeyChecking=no" \
    -o GlobalKnownHostsFile=/dev/null \
    -o UserKnownHostsFile=/dev/null \
    onos@localhost -p 8101
