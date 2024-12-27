package nctu.winlab.bridge;

import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Component(
    immediate = true,
    service = LearningBridge.class
)
public class LearningBridge {
    private final Logger log = LoggerFactory.getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @SuppressWarnings("UnstableApiUsage")
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    private ApplicationId appId;

    private Processor processor;

    @Activate
    protected void activate() {
        registerApp();
        addProcessor();
        requestIntercepts();
    }

    private void registerApp() {
        appId = coreService.registerApplication("nctu.winlab.bridge");
    }

    private void addProcessor() {
        processor = new Processor();
        packetService.addProcessor(processor, PacketProcessor.director(2));
    }

    private void requestIntercepts() {
        packetService.requestPackets(ipv4EthTypeSelector(), PacketPriority.LOWEST, appId);
        packetService.requestPackets(ipv6EthTypeSelector(), PacketPriority.LOWEST, appId);
    }

    private TrafficSelector ipv4EthTypeSelector() {
        return DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_IPV4)
            .build();
    }
    private TrafficSelector ipv6EthTypeSelector() {
        return DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_IPV6)
            .build();
    }
    @Deactivate
    protected void deactivate() {
        withdrawIntercepts();
        removeProcessor();
    }

    private void withdrawIntercepts() {
        packetService.cancelPackets(ipv4EthTypeSelector(), PacketPriority.LOWEST, appId);
        packetService.cancelPackets(ipv6EthTypeSelector(), PacketPriority.LOWEST, appId);
    }

    private void removeProcessor() {
        packetService.removeProcessor(processor);
        processor = null;
    }

    @SuppressWarnings("UnstableApiUsage")
    private class Processor implements PacketProcessor {
        private final Map<DeviceId, PortTable> portTables = new HashMap<>();

        @Override
        public void process(PacketContext context) {
            if (isNotProcessable(context)) {
                return;
            }

            recordSourcePort(context.inPacket());
            log.info("IPV6 {}",context.inPacket().parsed().getPayload().getPayload());
            Optional<PortNumber> dstPort = getDestinationPort(context.inPacket());
            if (dstPort.isEmpty()) {
                flood(context);
            } else {
                installRule(context, dstPort.get());
            }
        }

        private boolean isNotProcessable(PacketContext context) {
            Ethernet ethernetPkt = context.inPacket().parsed();

            return context.isHandled()
                || ethernetPkt == null
                || isControlPacket(ethernetPkt)
                || ethernetPkt.getDestinationMAC().isLldp();
        }

        private boolean isControlPacket(Ethernet pkt) {
            short type = pkt.getEtherType();
            return type == Ethernet.TYPE_LLDP || type == Ethernet.TYPE_BSN;
        }

        private void recordSourcePort(InboundPacket pkt) {
            DeviceId deviceId = pkt.receivedFrom().deviceId();
            MacAddress mac = pkt.parsed().getSourceMAC();
            PortNumber port = pkt.receivedFrom().port();

            getPortTable(deviceId).put(mac, port);

            // log.info(
            //     "Add an entry to the port table of `{}`. MAC address: `{}` => Port: `{}`.",
            //     deviceId,
            //     mac,
            //     port
            // );
        }

        private Optional<PortNumber> getDestinationPort(InboundPacket pkt) {
            return getPortTable(pkt.receivedFrom().deviceId())
                .getPort(pkt.parsed().getDestinationMAC());
        }

        private PortTable getPortTable(DeviceId deviceId) {
            if (!portTables.containsKey(deviceId)) {
                portTables.put(deviceId, new PortTable());
            }

            return portTables.get(deviceId);
        }

        private void flood(PacketContext context) {
            send(context, PortNumber.FLOOD);

            // log.info(
            //     "MAC address `{}` is missed on `{}`. Flood the packet.",
            //     context.inPacket().parsed().getDestinationMAC(),
            //     context.inPacket().receivedFrom().deviceId()
            // );
        }

        private void send(PacketContext context, PortNumber dstPort) {
            context.treatmentBuilder().setOutput(dstPort);
            context.send();
        }

        private void installRule(PacketContext context, PortNumber dstPort) {
            InboundPacket pkt = context.inPacket();

            flowObjectiveService.forward(
                pkt.receivedFrom().deviceId(),
                buildForwardingObjective(pkt, dstPort)
            );

            // log.info(
            //     "MAC address `{}` is matched on `{}`. Install a flow rule.",
            //     pkt.parsed().getDestinationMAC(),
            //     pkt.receivedFrom().deviceId()
            // );

            send(context, dstPort);
        }

        private ForwardingObjective buildForwardingObjective(
            InboundPacket pkt,
            PortNumber dstPort
        ) {
            return DefaultForwardingObjective.builder()
                .withSelector(buildSelector(pkt.parsed()))
                .withTreatment(buildTreatment(dstPort))
                .withPriority(30)
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .fromApp(appId)
                .makeTemporary(30)
                .add();
        }

        private TrafficSelector buildSelector(Ethernet ethernetPkt) {
            return DefaultTrafficSelector.builder()
                .matchEthSrc(ethernetPkt.getSourceMAC())
                .matchEthDst(ethernetPkt.getDestinationMAC())
                .build();
        }

        private TrafficTreatment buildTreatment(PortNumber dstPort) {
            return DefaultTrafficTreatment.builder()
                .setOutput(dstPort)
                .build();
        }
    }
}
