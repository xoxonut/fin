SHELL := /bin/bash
.PHONY: clean

all:
	sudo wg-quick up wg0
	sudo ovs-vsctl add-br ovs1 -- set bridge ovs1 other-config:datapath-id=0000000000000001
	sudo ovs-vsctl add-br ovs2 -- set bridge ovs2 other-config:datapath-id=0000000000000002
	docker compose up -d
	sudo ./supplement/topo_utils.sh
clean:
	sudo wg-quick down wg0
	sudo ovs-vsctl del-br ovs1
	sudo ovs-vsctl del-br ovs2
	sudo ip link del vethovs1ovs2
	docker compose down
	sleep 1
	@ip link show | awk -F': ' '/_l/ {print $$2}' | cut -d'@' -f1 | while read -r iface; do \
		echo "Deleting interface: $$iface"; \
		sudo ip link del $$iface || echo "Failed to delete interface: $$iface"; \
	done

onos:
	ssh -o "StrictHostKeyChecking=no" \
    -o GlobalKnownHostsFile=/dev/null \
    -o UserKnownHostsFile=/dev/null \
    onos@localhost -p 8101
log:
	docker logs onos --since 1s -f
install:
	onos-app onos@localhost install! ./supplement/flow_objective_sample/target/bridge-1.0-SNAPSHOT.oar
	onos-app onos@localhost install! ./vrouter/target/vrouter-1.0-SNAPSHOT.oar
	onos-app onos@localhost install! ./supplement/project5_311555026/target/ProxyArp-1.0-SNAPSHOT.oar
uninstall:
	onos-app onos@localhost uninstall nycu.winlab.bridge
	onos-app onos@localhost uninstall nycu.winlab.ProxyArp
	onos-app onos@localhost uninstall nycu.winlab.vrouter
	# onos onos@localhost remove-intent nycu.winlab.vrouter
	# onos onos@localhost purge-intents
build:
	mvn -f ./vrouter clean install -DskipTests
	mvn -f ./supplement/flow_objective_sample clean install -DskipTests
	mvn -f ./supplement/project5_311555026 clean install -DskipTests
env:
	onos-app onos@localhost install! ./supplement/project5_311555026/target/ProxyArp-1.0-SNAPSHOT.oar
	onos-app onos@localhost install! ./supplement/flow_objective_sample/target/bridge-1.0-SNAPSHOT.oar
ping:
	docker exec -it h1 ping6 2a0b:4e07:c4:82::69
b:
	onos-app onos@localhost install! ./supplement/flow_objective_sample/target/bridge-1.0-SNAPSHOT.oar
v:
	onos-netcfg onos@localhost ./config.json
	onos-app onos@localhost install! ./vrouter/target/vrouter-1.0-SNAPSHOT.oar
p:
	onos-app onos@localhost install! ./supplement/project5_311555026/target/ProxyArp-1.0-SNAPSHOT.oar
