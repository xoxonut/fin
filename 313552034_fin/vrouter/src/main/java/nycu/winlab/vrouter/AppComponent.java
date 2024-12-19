/*
 * Copyright 2024-present Open Networking Foundation
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
package nycu.winlab.vrouter;
import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_ADDED;
import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_UPDATED;
import static org.onosproject.net.config.basics.SubjectFactories.APP_SUBJECT_FACTORY;

import org.onlab.packet.ARP;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.TpPort;
import org.onlab.packet.EthType.EtherType;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.host.HostService;
import org.onosproject.net.intent.IntentService;
import org.onosproject.net.intent.PointToPointIntent;
import org.onosproject.net.intf.Interface;
import org.onosproject.net.intf.InterfaceEvent;
import org.onosproject.net.intf.InterfaceListener;
import org.onosproject.net.intf.InterfaceService;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.routeservice.RouteService;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class AppComponent {

    private final Logger log = LoggerFactory.getLogger(getClass());
    private ApplicationId appId;
    private static final IpPrefix domainIP = IpPrefix.valueOf("172.16.82.0/24");

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected RouteService routeService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected InterfaceService intfService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected IntentService intentService;

    private ReactivePacketProcessor processor = new ReactivePacketProcessor();
    
    @Activate
    protected void activate() {
        // add listener to connect BGP traffic
        appId = coreService.registerApplication("nycu.winlab.vrouter");
        log.info("vrouter Started");
        packetService.addProcessor(processor, PacketProcessor.director(2));
        setBGPIntent();
    }

    @Deactivate
    protected void deactivate() {
        log.info("Stopped");
    }
    private class ReactivePacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            ConnectPoint wanCp = intfService.getMatchingInterface(
                Ip4Address.valueOf("192.168.70.82/32")).connectPoint();
            if (wanCp == null) return;
            log.info("WAN connect point: {}", wanCp);
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();
            if (context.isHandled() || 
            ethPkt.getEtherType() == Ethernet.TYPE_ARP ||
            ethPkt.getEtherType() != Ethernet.TYPE_IPV4) return;
            IPv4 ipv4Pkt = (IPv4) ethPkt.getPayload();
            Ip4Address dstIp = Ip4Address.valueOf(ipv4Pkt.getDestinationAddress());
            Ip4Address srcIp = Ip4Address.valueOf(ipv4Pkt.getSourceAddress());
            log.info("Received packet from {} to {}", srcIp, dstIp);
            // TODO: Implement how non BGP packet traffic
        }

    }
    void setBGPIntent(){
        ConnectPoint wanCp = intfService.getMatchingInterface(
            Ip4Address.valueOf("192.168.70.82/32")).connectPoint();
        if (wanCp == null) {
            log.warn("WAN connect point not found");
            return;
        }
        log.info("WAN connect point: {}", wanCp);
        Ip4Address peerIp = Ip4Address.valueOf("192.168.70.253");
        TrafficSelector.Builder dstSelector = dstSelectorBuilder(peerIp);
        
        TrafficSelector.Builder srcSelector = srcSelecBuilder(peerIp);
        ConnectPoint peerCp = findConnectPoint(peerIp);
        // form local to peer
        installIntent(wanCp, peerCp, dstSelector.build());
        installIntent(wanCp, peerCp, srcSelector.build());
        // form peer to local
        Ip4Address wanIp = Ip4Address.valueOf("192.168.70.82");
        TrafficSelector.Builder dstSelector2 = dstSelectorBuilder(wanIp);
        TrafficSelector.Builder srcSelector2 = srcSelecBuilder(wanIp);
        installIntent(peerCp, wanCp, dstSelector2.build());
        installIntent(peerCp, wanCp, srcSelector2.build());

        

    }
    void installIntent(ConnectPoint src, ConnectPoint dst, TrafficSelector selector){
    }
    void installIntent(ConnectPoint src, ConnectPoint dst, TrafficSelector selector,
     TrafficTreatment treatment){
    }
    ConnectPoint findConnectPoint(Ip4Address ip){
        return hostService.getHostsByIp(ip).stream().filter(
            host -> host.ipAddresses().contains(ip)).findFirst().map(
                host -> host.location()).orElse(null);
    }
    TrafficSelector.Builder dstSelectorBuilder(Ip4Address ip){
        return DefaultTrafficSelector.builder()
        .matchIPDst(IpPrefix.valueOf(ip,32))
        .matchEthType(Ethernet.TYPE_IPV4)
        .matchIPProtocol(IPv4.PROTOCOL_TCP)
        .matchTcpDst(TpPort.tpPort(179));
    }
    TrafficSelector.Builder srcSelecBuilder(Ip4Address ip){
        return DefaultTrafficSelector.builder()
        .matchIPDst(IpPrefix.valueOf(ip,32))
        .matchEthType(Ethernet.TYPE_IPV4)
        .matchIPProtocol(IPv4.PROTOCOL_TCP)
        .matchTcpSrc(TpPort.tpPort(179));
    }
}
