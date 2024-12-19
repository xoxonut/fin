SHELL := /bin/bash

all:
	sudo wg-quick up wg0
	sudo ovs-vsctl add-br ovs1 -- set bridge ovs1 other-config:datapath-id=0000000000000001
	sudo ovs-vsctl add-br ovs2 -- set bridge ovs2 other-config:datapath-id=0000000000000002
	docker compose up -d
	sudo ./supplement/topo_utils.sh
	sleep 20
	# onos-app onos@localhost install! ./supplement/bridge-1.0-SNAPSHOT.oar 
	# onos-app onos@localhost install! ./supplement/proxyarp-1.0-SNAPSHOT.oar 
	mvn -f ./vrouter clean install -DskipTests
	onos-netcfg onos@localhost ./config.json
	onos-app onos@localhost install! ./vrouter/target/vrouter-1.0-SNAPSHOT.oar
clean:
	sudo wg-quick down wg0
	sudo ovs-vsctl del-br ovs1
	sudo ovs-vsctl del-br ovs2
	sudo ip link del vethovs1ovs2
	docker compose down
onos:
	ssh -o "StrictHostKeyChecking=no" \
    -o GlobalKnownHostsFile=/dev/null \
    -o UserKnownHostsFile=/dev/null \
    onos@localhost -p 8101
log:
	docker logs onos