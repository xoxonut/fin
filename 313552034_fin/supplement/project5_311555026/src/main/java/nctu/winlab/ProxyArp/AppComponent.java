/*
 * Copyright 2022-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nctu.winlab.ProxyArp;

import org.onosproject.cfg.ComponentConfigService;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onlab.packet.Ethernet;
import org.onlab.packet.ICMP6;
import org.onlab.packet.IP;
import org.onlab.packet.IPv6;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip6Address;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;
import org.onlab.packet.ndp.NeighborAdvertisement;
import org.onlab.packet.ndp.NeighborSolicitation;
import org.onlab.packet.ndp.NeighborDiscoveryOptions;

import com.google.common.collect.Maps;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.onlab.packet.ARP;
// import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.host.HostService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.PortNumber;
import org.onosproject.net.DeviceId;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficTreatment;
import java.nio.ByteBuffer;
import org.onosproject.core.CoreService;
import org.onosproject.net.edge.EdgePortService;
import java.util.*;

import java.util.Dictionary;
import java.util.Properties;

import javax.crypto.Mac;

import static org.onlab.util.Tools.get;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true,
           service = {SomeInterface.class},
           property = {
               "someProperty=Some Default String Value",
           })
public class AppComponent implements SomeInterface {

    private final Logger log = LoggerFactory.getLogger(getClass());

    /** Some configurable property. */
    private String someProperty;

    private ApplicationId appId;

    // new a LearningBridgePacketProcessor
    private ProxyArpPacketProcessor processor = new ProxyArpPacketProcessor();
    private V6ArpPacketProcessor v6Processor = new V6ArpPacketProcessor();
    // new a Map
    protected Map<IpAddress, MacAddress> table = Maps.newConcurrentMap();

    // new a location map
    protected Map<IpAddress, ConnectPoint> locationTable = Maps.newConcurrentMap();

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected EdgePortService edgePortService;

    @Activate
    protected void activate() {
        cfgService.registerProperties(getClass());
        appId = coreService.registerApplication("nctu.winlab.ProxyArp");
        packetService.addProcessor(processor, PacketProcessor.director(1));
        packetService.addProcessor(v6Processor, PacketProcessor.director(1));
        requestPacketIn();
        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        cfgService.unregisterProperties(getClass(), false);
        packetService.removeProcessor(processor);
        packetService.removeProcessor(v6Processor);
        withdrawPacketIn();
        log.info("Stopped");
    }

    @Modified
    public void modified(ComponentContext context) {
        Dictionary<?, ?> properties = context != null ? context.getProperties() : new Properties();
        if (context != null) {
            someProperty = get(properties, "someProperty");
        }
        log.info("Reconfigured");
    }

    @Override
    public void someMethod() {
        log.info("Invoked");
    }

    private void requestPacketIn() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_ARP);
        TrafficSelector.Builder v6Selector = DefaultTrafficSelector.builder();
        v6Selector.matchEthType(Ethernet.TYPE_IPV6).matchIPProtocol(IPv6.PROTOCOL_ICMP6);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
        packetService.requestPackets(v6Selector.build(), PacketPriority.REACTIVE, appId);
    }

    private void withdrawPacketIn() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_ARP);
        TrafficSelector.Builder v6Selector = DefaultTrafficSelector.builder();
        v6Selector.matchEthType(Ethernet.TYPE_IPV6).matchIPProtocol(IPv6.PROTOCOL_ICMP6);
        packetService.cancelPackets(v6Selector.build(), PacketPriority.REACTIVE, appId);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    /**
     * Packet processor responsible for forwarding packets along their paths.
     */
    private class ProxyArpPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) {
                return;
            }
            // First take things out from packet
            Ethernet ethPkt = context.inPacket().parsed();

            if (ethPkt == null) {
                return;
            }

            // Bail if this is deemed to be a control packet.
            if (isControlPacket(ethPkt)) {
                return;
            }

            if (ethPkt.getEtherType() != Ethernet.TYPE_ARP) {
                return;
            }

            ARP arpPacket = (ARP) ethPkt.getPayload();
            // log.info("{}", arpPacket);
            MacAddress srcMac = MacAddress.valueOf(arpPacket.getSenderHardwareAddress());
            MacAddress dstMac = MacAddress.valueOf(arpPacket.getTargetHardwareAddress());

            HostId id = HostId.hostId(dstMac); // get Dst host id

            // Do not process LLDP MAC address in any way
            if (id.mac().isLldp()) {
                return;
            }

            IpAddress srcIp = IpAddress.valueOf(IpAddress.Version.INET, arpPacket.getSenderProtocolAddress());
            IpAddress dstIp = IpAddress.valueOf(IpAddress.Version.INET, arpPacket.getTargetProtocolAddress());
            table.putIfAbsent(srcIp, srcMac); // add an antry into table
            locationTable.putIfAbsent(srcIp, new ConnectPoint(context.inPacket().receivedFrom().deviceId(), context.inPacket().receivedFrom().port()));
            
            MacAddress targetMac = table.get(dstIp);
            if (targetMac == null) {
                // table miss
                // log.info("TABLE MISS. Send request to edge ports");

                ConnectPoint senderConnectPoint = locationTable.get(srcIp);

                // First, flood the ethPkt to other switch
                edgePortService.getEdgePoints().forEach((connectPoint) -> {
                    if (!senderConnectPoint.equals(connectPoint)) {
                        sendArpPacket(connectPoint, ethPkt);
                    }
                });
            } else {
                // table hit
                if (arpPacket.getOpCode() == 1) {
                    // log.info("TABLE HIT. Requested MAC = {}", targetMac);
                } else {
                    // log.info("RECV REPLY. Requested MAC = {}", srcMac);
                }
                
                Ethernet ethReply = ARP.buildArpReply(dstIp.getIp4Address(), targetMac, ethPkt);

                ConnectPoint targetConnectPoint = locationTable.get(srcIp);
                PortNumber port = targetConnectPoint.port();
                DeviceId deviceId = targetConnectPoint.deviceId();

                TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                                            .setOutput(port).build();
                packetService.emit(new DefaultOutboundPacket(deviceId, treatment,
                                ByteBuffer.wrap(ethReply.serialize())));
            }
            // log.info("{}", srcIp);
            // log.info("srcMac : {}", srcMac);
            // log.info("eth getSourceMac : {}", ethPkt.getSourceMAC());
            // log.info("{}", dstIp);
            // log.info("dstMac : {}", dstMac); // 00:00...
            // log.info("eth ge[tDestinationMac : {}", ethPkt.getDestinationMAC()); // FF:FF...

        }
    }
    private class V6ArpPacketProcessor implements PacketProcessor{
        @Override
        public void process(PacketContext ctx){
            if(ctx.isHandled()){
                return;
            }
            Ethernet ethPkt = ctx.inPacket().parsed();
            if(ethPkt == null){
                return;
            }
            if(ethPkt.getEtherType() != Ethernet.TYPE_IPV6){
                return;
            }
            IPv6 ipv6Packet = (IPv6) ethPkt.getPayload();
            if(ipv6Packet.getNextHeader() != IPv6.PROTOCOL_ICMP6){
                return;
            }
            ICMP6 icmp6Packet = (ICMP6) ipv6Packet.getPayload();
            if(icmp6Packet.getIcmpType() != ICMP6.NEIGHBOR_SOLICITATION &&
                icmp6Packet.getIcmpType() != ICMP6.NEIGHBOR_ADVERTISEMENT){
                return;
            }
            if(icmp6Packet.getIcmpType() == ICMP6.NEIGHBOR_SOLICITATION){
                handleNeighborSolicitation(ctx);
            }else if(icmp6Packet.getIcmpType() == ICMP6.NEIGHBOR_ADVERTISEMENT){
                handleNeighborAdvertisement(ctx);
            }
        }
        private void handleNeighborSolicitation(PacketContext ctx){
            log.info("[proxy] handleNeighborSolicitation");
            Ethernet ethPkt = ctx.inPacket().parsed();
            IPv6 ipv6Packet = (IPv6) ethPkt.getPayload();
            ICMP6 icmp6Packet = (ICMP6) ipv6Packet.getPayload();
            NeighborSolicitation ns = (NeighborSolicitation) icmp6Packet.getPayload();
            MacAddress srcMac = ns.getOptions().stream()
                                .filter(options -> options.type() == NeighborDiscoveryOptions.TYPE_SOURCE_LL_ADDRESS)
                                .map(options -> MacAddress.valueOf(options.data()))
                                .findFirst()
                                .orElse(null);
            if (srcMac == null) {
                log.info("[proxy] ns srcMac is null");
                return;
            }
            Ip6Address srcIp = Ip6Address.valueOf(ipv6Packet.getSourceAddress());
            Ip6Address dstIp = Ip6Address.valueOf(ns.getTargetAddress());
            table.putIfAbsent(srcIp, srcMac);
            locationTable.putIfAbsent(srcIp, ctx.inPacket().receivedFrom());
            MacAddress targetMac = table.get(dstIp);
            log.info("[proxy] ns from {} to {}", srcIp, dstIp);
            if (targetMac == null){
                ConnectPoint senderConnectPoint = locationTable.get(srcIp);
                log.info("[proxy] table miss. Send request to edge ports");
                // First, flood the ethPkt to other switch
                edgePortService.getEdgePoints().forEach((connectPoint) -> {
                    if (!senderConnectPoint.equals(connectPoint)) {
                        sendNDP(connectPoint, ethPkt);
                    }
                });
            }else{
                log.info("[proxy] table hit. Requested MAC = {}", targetMac);
                log.info("[proxy] ns table hit. IP / MAC -> {} / {}", dstIp, targetMac);
                Ethernet ethReply = NeighborAdvertisement.buildNdpAdv(dstIp, targetMac, ethPkt);
                ConnectPoint reply2Cp = locationTable.get(srcIp);
                PortNumber port = reply2Cp.port();
                DeviceId deviceId = reply2Cp.deviceId();
                TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                                            .setOutput(port).build();
                log.info("[proxy] na of {} to {}/{}",dstIp, deviceId, port);
                packetService.emit(new DefaultOutboundPacket(deviceId, treatment,
                                ByteBuffer.wrap(ethReply.serialize())));
            }
        }
        private void handleNeighborAdvertisement(PacketContext ctx){
            log.info("[proxy] handleNeighborAdvertisement");
            Ethernet ethPkt = ctx.inPacket().parsed();
            IPv6 ipv6Packet = (IPv6) ethPkt.getPayload();
            ICMP6 icmp6Packet = (ICMP6) ipv6Packet.getPayload();
            NeighborAdvertisement na = (NeighborAdvertisement) icmp6Packet.getPayload();
            MacAddress srcMac = na.getOptions().stream()
                                .filter(options -> options.type() == NeighborDiscoveryOptions.TYPE_TARGET_LL_ADDRESS)
                                .map(options -> MacAddress.valueOf(options.data()))
                                .findFirst()
                                .orElse(null);
            if (srcMac == null) {
                return;
            }
            Ip6Address srcIp = Ip6Address.valueOf(ipv6Packet.getSourceAddress());
            table.putIfAbsent(srcIp, srcMac);
            locationTable.putIfAbsent(srcIp, ctx.inPacket().receivedFrom());
            MacAddress dstMac = table.get(srcIp);
            if (dstMac == null){
                log.info("[proxy] na table miss ERROR");
                return;
            }else{;
                log.info("[proxy] na table hit. Dst MAC = {}", dstMac);
                Ethernet ethReply = ctx.inPacket().parsed();
                Ip6Address dstIp = Ip6Address.valueOf(ipv6Packet.getDestinationAddress());
                ConnectPoint targetConnectPoint = locationTable.get(dstIp);
                log.info("[proxy] na from {} to {}", srcIp, dstIp);
                PortNumber port = targetConnectPoint.port();
                DeviceId deviceId = targetConnectPoint.deviceId();
                TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                                            .setOutput(port).build();
                packetService.emit(new DefaultOutboundPacket(deviceId, treatment,
                                ByteBuffer.wrap(ethReply.serialize())));
            }
            for (Map.Entry<IpAddress, MacAddress> entry : table.entrySet()) {
                log.info("[proxy] table: {} -> {}", entry.getKey(), entry.getValue());
            }
            for (Map.Entry<IpAddress, ConnectPoint> entry : locationTable.entrySet()) {
                log.info("[proxy] locationTable: {} -> {}", entry.getKey(), entry.getValue());
            }
        }
        private void sendNDP(ConnectPoint connectPoint, Ethernet packet){
            PortNumber port = connectPoint.port();
            DeviceId deviceId = connectPoint.deviceId();
            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                                        .setOutput(port).build();
            packetService.emit(new DefaultOutboundPacket(deviceId, treatment,
                                ByteBuffer.wrap(packet.serialize())));
        }
    }
    // Indicates whether this is a control packet, e.g. LLDP, BDDP
    private boolean isControlPacket(Ethernet eth) {
        short type = eth.getEtherType();
        return type == Ethernet.TYPE_LLDP || type == Ethernet.TYPE_BSN;
    }

    private void sendArpPacket(ConnectPoint connectPoint, Ethernet packet) {
        // send the packet to the ConnectPoint
        // log.info("{}", connect);
        PortNumber port = connectPoint.port();
        DeviceId deviceId = connectPoint.deviceId();

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                                    .setOutput(port).build();
        packetService.emit(new DefaultOutboundPacket(deviceId, treatment,
                            ByteBuffer.wrap(packet.serialize())));
    }

}
