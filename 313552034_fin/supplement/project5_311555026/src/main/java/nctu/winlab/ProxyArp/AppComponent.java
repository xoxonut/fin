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
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onlab.packet.Ethernet;
import org.onlab.packet.ICMP;
import org.onlab.packet.ICMP6;
import org.onlab.packet.IP;
import org.onlab.packet.IPacket;
import org.onlab.packet.IPv6;
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
import java.util.stream.Stream;
import static org.onlab.packet.IPv6.PROTOCOL_ICMP6;


import static org.onlab.util.Tools.get;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class AppComponent {

    private final Logger log = LoggerFactory.getLogger(getClass());

    /** Some configurable property. */

    private ApplicationId appId;

    // new a LearningBridgePacketProcessor
    private ProxyArpPacketProcessor processor = new ProxyArpPacketProcessor();

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
        appId = coreService.registerApplication("nctu.winlab.ProxyArp");
        packetService.addProcessor(processor, 2);
        requestPacketIn();
        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(processor);
        withdrawPacketIn();
        log.info("Stopped");
    }


    private void requestPacketIn() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
        TrafficSelector.Builder neighborSolicitationSelector = DefaultTrafficSelector.builder()
        .matchEthType(Ethernet.TYPE_IPV6)
        .matchIPProtocol(PROTOCOL_ICMP6)
        .matchIcmpv6Type(ICMP6.NEIGHBOR_SOLICITATION);
        packetService.requestPackets(neighborSolicitationSelector.build(), PacketPriority.REACTIVE, appId);
        TrafficSelector.Builder neighborAdvertisementSelector = DefaultTrafficSelector.builder()
        .matchEthType(Ethernet.TYPE_IPV6)
        .matchIPProtocol(PROTOCOL_ICMP6)
        .matchIcmpv6Type(ICMP6.NEIGHBOR_ADVERTISEMENT);
        packetService.requestPackets(neighborAdvertisementSelector.build(), PacketPriority.REACTIVE, appId);

    }

    private void withdrawPacketIn() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
        TrafficSelector.Builder neighborSolicitationSelector = DefaultTrafficSelector.builder()
        .matchEthType(Ethernet.TYPE_IPV6)
        .matchIPProtocol(PROTOCOL_ICMP6)
        .matchIcmpv6Type(ICMP6.NEIGHBOR_SOLICITATION);
        packetService.cancelPackets(neighborSolicitationSelector.build(), PacketPriority.REACTIVE, appId);
        TrafficSelector.Builder neighborAdvertisementSelector = DefaultTrafficSelector.builder()
        .matchEthType(Ethernet.TYPE_IPV6)
        .matchIPProtocol(PROTOCOL_ICMP6)
        .matchIcmpv6Type(ICMP6.NEIGHBOR_ADVERTISEMENT);
        packetService.cancelPackets(neighborAdvertisementSelector.build(), PacketPriority.REACTIVE, appId);
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
            if (ethPkt.getEtherType() == Ethernet.TYPE_ARP) {
                
            
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
                            sendPacket(connectPoint, ethPkt);
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
            }else if (isNeighborSolicitation(ethPkt)){
                log.info("neighbor solicitation");
                NeighborSolicitation ns  = (NeighborSolicitation) ethPkt.getPayload().getPayload().getPayload();
                // check options has soruce mac or not
                MacAddress srcMac = MacAddress.valueOf(ns.getOptions().get(0).data());
                log.info("icmp6 type {}, icmp6 data {}",ns.getOptions().get(0).type(),ns.getOptions().get(0).data());
                IPv6 ipv6 = (IPv6) ethPkt.getPayload();
                IpAddress srcIp = IpAddress.valueOf(IpAddress.Version.INET6, ipv6.getSourceAddress());
                IpAddress dstIp = IpAddress.valueOf(
                    IpAddress.Version.INET6, ipv6.getDestinationAddress());
                log.info("srcIP {}, dstIP {}",srcIp,dstIp);
                table.putIfAbsent(srcIp, srcMac);
                log.info("put srcIP {}, srcMac {} to table",srcIp,srcMac);
                locationTable.putIfAbsent(srcIp, new ConnectPoint(context.inPacket().receivedFrom().deviceId(), context.inPacket().receivedFrom().port()));
                MacAddress targetMac = table.get(dstIp);
                log.info("target IP {}, target Mac", dstIp, targetMac);
                if (targetMac == null) {
                    log.info("target IP {} TABLE MISS. Send request to edge ports",dstIp);
                    ConnectPoint senderCp = locationTable.get(srcIp);
                    log.info("srcIP {}'s connect point {}",srcIp,senderCp);
                    edgePortService.getEdgePoints().forEach((connectPoint) -> {
                        if (!senderCp.equals(connectPoint)) {
                            log.info("{} send to {}",senderCp,ethPkt);
                            sendPacket(connectPoint, ethPkt);
                        }
                    });
                    log.info("table");
                    for (Map.Entry<IpAddress, MacAddress> entry : table.entrySet()) {
                        log.info("ip {}, mac {}", entry.getKey(), entry.getValue());
                    }
                    log.info("logcation table");
                    for (Map.Entry<IpAddress, ConnectPoint> entry : locationTable.entrySet()) {
                        log.info("ip {}, cp {]}", entry.getKey(),entry.getValue());
                    }
    
                } else {
                    log.info("TABLE HIT. Requested MAC = {}", targetMac);
                    log.info("proxy from dstIp {}, dstMac {} to srcIp {}, srcMac {}",dstIp,targetMac,srcIp,srcMac);
                    Ethernet na = NeighborAdvertisement.buildNdpAdv(dstIp.getIp6Address(), targetMac, ethPkt);
                    ConnectPoint targetCp = locationTable.get(srcIp);
                    log.info("srcIP {}'s connect point {}",srcIp,targetCp);
                    PortNumber port = targetCp.port();
                    DeviceId deviceId = targetCp.deviceId();
                    TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                                                .setOutput(port).build();
                    packetService.emit(new DefaultOutboundPacket(deviceId, treatment,
                                    ByteBuffer.wrap(na.serialize())));
                }
            }else if(isNeighborAdvertisement(ethPkt)){
                
                log.info("{}", ethPkt);
                log.info("IPv6 Neighbor Advertisement");
                NeighborAdvertisement na = (NeighborAdvertisement) ethPkt.getPayload().getPayload().getPayload();
                MacAddress srcMac =MacAddress.valueOf(na.getOptions().get(0).data());
                IPv6 ipv6 = (IPv6) ethPkt.getPayload();
                IpAddress srcIp = IpAddress.valueOf(
                    IpAddress.Version.INET6, ipv6.getSourceAddress());
                IpAddress dstIp = IpAddress.valueOf(
                    IpAddress.Version.INET6, ipv6.getDestinationAddress());
                log.info("src ip {}, dst ip {}",srcIp,dstIp);
                    table.putIfAbsent(srcIp, srcMac);
                log.info("src IP{}, src Mac {}",srcIp,srcMac);
                locationTable.putIfAbsent(srcIp, new ConnectPoint(context.inPacket().receivedFrom().deviceId(), context.inPacket().receivedFrom().port()));
                ConnectPoint targetCp = locationTable.get(dstIp);
                PortNumber port = targetCp.port();
                DeviceId deviceId = targetCp.deviceId();
                TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                                            .setOutput(port).build();
                packetService.emit(
                    new DefaultOutboundPacket(deviceId, treatment, ByteBuffer.wrap(ethPkt.serialize()))
                );

            }
        }
    }

    // Indicates whether this is a control packet, e.g. LLDP, BDDP
    private boolean isControlPacket(Ethernet eth) {
        short type = eth.getEtherType();
        return type == Ethernet.TYPE_LLDP || type == Ethernet.TYPE_BSN;
    }

    private void sendPacket(ConnectPoint connectPoint, Ethernet packet) {
        // send the packet to the ConnectPoint
        // log.info("{}", connect);
        PortNumber port = connectPoint.port();
        DeviceId deviceId = connectPoint.deviceId();

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                                    .setOutput(port).build();
        packetService.emit(new DefaultOutboundPacket(deviceId, treatment,
                            ByteBuffer.wrap(packet.serialize())));
    }

    private boolean isNeighborSolicitation (Ethernet eth) {
        IPv6 ipv6 = (IPv6)eth.getPayload();
        if (ipv6.getNextHeader() != IPv6.PROTOCOL_ICMP6) {
            return false;
        }
        ICMP6 icmp6 = (ICMP6)ipv6.getPayload();
        return icmp6.getIcmpType() == ICMP6.NEIGHBOR_SOLICITATION;
    }
    private boolean isNeighborAdvertisement (Ethernet eth) {
        IPv6 ipv6 = (IPv6)eth.getPayload();
        if (ipv6.getNextHeader() != IPv6.PROTOCOL_ICMP6) {
            return false;
        }
        ICMP6 icmp6 = (ICMP6)ipv6.getPayload();
        return icmp6.getIcmpType() == ICMP6.NEIGHBOR_ADVERTISEMENT;
    }

}
