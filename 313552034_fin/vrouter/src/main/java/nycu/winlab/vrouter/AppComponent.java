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
import org.onlab.packet.MacAddress;
import org.onlab.packet.IPv4;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.TpPort;
import org.onlab.packet.EthType.EtherType;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.FilteredConnectPoint;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.host.HostService;
import org.onosproject.net.intent.IntentService;
import org.onosproject.net.intent.PointToPointIntent;
import org.onosproject.net.intent.Key;
import java.util.Optional;

import javax.crypto.Mac;

import org.onosproject.net.intf.Interface;
import org.onosproject.net.intf.InterfaceEvent;
import org.onosproject.net.intf.InterfaceListener;
import org.onosproject.net.intf.InterfaceService;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.routeservice.ResolvedRoute;
import org.onosproject.routeservice.Route;
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
        packetService.addProcessor(processor, PacketProcessor.director(6));
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);

        // setBGPIntent();
    }

    @Deactivate
    protected void deactivate() {
        log.info("Stopped");
    }
    private class ReactivePacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            ConnectPoint wanCp = intfService.getMatchingInterface(
                Ip4Address.valueOf("192.168.70.82")).connectPoint();
            if (wanCp == null) return;
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();
            if (context.isHandled() || 
            ethPkt.getEtherType() == Ethernet.TYPE_ARP ||
            ethPkt.getEtherType() != Ethernet.TYPE_IPV4) return;
            IPv4 ipv4Pkt = (IPv4) ethPkt.getPayload();
            Ip4Address dstIp = Ip4Address.valueOf(ipv4Pkt.getDestinationAddress());
            Ip4Address srcIp = Ip4Address.valueOf(ipv4Pkt.getSourceAddress());
            // TODO: Implement how non BGP packet traffic
            if(domainIP.contains(dstIp)){
                exteranl2Sdn(context);
            }else{
                sdn2External(context);
            }
            context.treatmentBuilder().setOutput(PortNumber.TABLE);
            context.send();
        }

    }
    void setBGPIntent(){
        ConnectPoint wanCp = intfService.getMatchingInterface(
            Ip4Address.valueOf("192.168.70.82")).connectPoint();
        if (wanCp == null) {
            log.warn("WAN connect point not found");
            return;
        }
        log.info("WAN connect point: {}", wanCp);
        Ip4Address speakerIp = Ip4Address.valueOf("192.168.70.82");
        Ip4Address ixpIP = Ip4Address.valueOf("192.168.70.253");
        TrafficSelector.Builder dstSelector = dstBGPSelectorBuilder(speakerIp,ixpIP);
        TrafficSelector.Builder srcSelector = srcBGPSelecBuilder(speakerIp,ixpIP);
        ConnectPoint ixpCP = findConnectPoint(ixpIP);
        ConnectPoint speakerCP = ConnectPoint.deviceConnectPoint("of:0000000000000001/5");
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
        .setOutput(ixpCP.port()).build();
        // form local to peer
        installIntent(speakerCP, ixpCP, dstSelector.build(), treatment,10);
        installIntent(speakerCP, ixpCP, srcSelector.build(), treatment,10);
        // form peer to local
        TrafficSelector.Builder dstSelector2 = dstBGPSelectorBuilder(ixpIP,speakerIp);
        TrafficSelector.Builder srcSelector2 = srcBGPSelecBuilder(ixpIP,speakerIp);
        TrafficTreatment treatment2 = DefaultTrafficTreatment.builder()
        .setOutput(speakerCP.port()).build();
        installIntent(ixpCP, speakerCP, dstSelector2.build(),treatment2,10);
        installIntent(ixpCP, speakerCP, srcSelector2.build(),treatment2,10);

    }
    void installIntent(ConnectPoint src, ConnectPoint dst, TrafficSelector selector,
     TrafficTreatment treatment){
        PointToPointIntent intent = PointToPointIntent.builder()
        .appId(appId)
        .selector(selector)
        .treatment(treatment)
        .filteredIngressPoint(new FilteredConnectPoint(src))
        .filteredEgressPoint(new FilteredConnectPoint(dst))
        .build();
        intentService.submit(intent);
    }
    void installIntent(ConnectPoint src, ConnectPoint dst, TrafficSelector selector,
    TrafficTreatment treatment,int priority){
       PointToPointIntent intent = PointToPointIntent.builder()
       .appId(appId)
       .selector(selector)
       .treatment(treatment)
       .filteredIngressPoint(new FilteredConnectPoint(src))
       .filteredEgressPoint(new FilteredConnectPoint(dst))
       .priority(priority)
       .build();
       intentService.submit(intent);
   }

    ConnectPoint findConnectPoint(Ip4Address ip){
        return hostService.getHostsByIp(ip).stream().filter(
            host -> host.ipAddresses().contains(ip)).findFirst().map(
                host -> host.location()).orElse(null);
    }
    TrafficSelector.Builder dstBGPSelectorBuilder(Ip4Address src, Ip4Address dst){
        return DefaultTrafficSelector.builder()
        .matchIPSrc(IpPrefix.valueOf(src,32))
        .matchIPDst(IpPrefix.valueOf(dst,32))
        .matchEthType(Ethernet.TYPE_IPV4)
        .matchIPProtocol(IPv4.PROTOCOL_TCP)
        .matchTcpDst(TpPort.tpPort(179));
    }
    TrafficSelector.Builder srcBGPSelecBuilder(Ip4Address src, Ip4Address dst){
        return DefaultTrafficSelector.builder()
        .matchIPSrc(IpPrefix.valueOf(src,32))
        .matchIPDst(IpPrefix.valueOf(dst,32))
        .matchEthType(Ethernet.TYPE_IPV4)
        .matchIPProtocol(IPv4.PROTOCOL_TCP)
        .matchTcpSrc(TpPort.tpPort(179));
    }
    void exteranl2Sdn(PacketContext context){
        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();
        IPv4 ipv4Pkt = (IPv4) ethPkt.getPayload();
        Ip4Address dstIp = Ip4Address.valueOf(ipv4Pkt.getDestinationAddress());

        ConnectPoint receivedPoint = pkt.receivedFrom();
        hostService.requestMac(dstIp);
        Host dstHost =getHostByIp(dstIp);
        MacAddress dstMac = dstHost.mac();
        ConnectPoint dstPoint = dstHost.location();

        TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
        .matchEthType(Ethernet.TYPE_IPV4)
        .matchIPDst(IpPrefix.valueOf(dstIp,32));
        Host routerHost = getHostByIp(Ip4Address.valueOf("192.168.100.3"));
        MacAddress routerMac = routerHost.mac();
        TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder()
        .setEthDst(dstMac)
        .setEthSrc(routerMac);
        log.info("vrouter Received packet from {} to {}", receivedPoint, dstPoint);
        installIntent(receivedPoint, dstPoint, selector.build(), treatment.build());
    }
    void sdn2External(PacketContext context){
        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();
        IPv4 ipv4Pkt = (IPv4) ethPkt.getPayload();
        Ip4Address dstIp = Ip4Address.valueOf(ipv4Pkt.getDestinationAddress());

        ConnectPoint receivedPoint = pkt.receivedFrom();
        Optional<ResolvedRoute> optionalRoute = routeService.longestPrefixLookup(dstIp);
        if (!optionalRoute.isPresent()) {
            return;
        }
        Route route = optionalRoute.get().route();
        log.debug("Route: {}", route);
        Ip4Address nextHop = route.nextHop().getIp4Address();
        MacAddress nextHopMac = getHostByIp(nextHop).mac();
        ConnectPoint nextHopPoint = getHostByIp(nextHop).location();
        log.debug("Next hop mac: {}", nextHopMac);
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
        .matchEthType(Ethernet.TYPE_IPV4)
        .matchIPDst(IpPrefix.valueOf(dstIp,32));
        Host routerhost = getHostByIp(Ip4Address.valueOf("192.168.100.3"));
        MacAddress routerMac = routerhost.mac();
        TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder()
        .setEthDst(nextHopMac)
        .setEthSrc(routerMac);
        log.info("vrouter Received packet from {} to {}", receivedPoint, nextHopPoint);
        installIntent(receivedPoint, nextHopPoint, selector.build(), treatment.build());
    }
    Host getHostByIp(Ip4Address ip){
        Host ret = null;
        hostService.requestMac(ip);
        for(Host host : hostService.getHosts()){
            if(host.ipAddresses().contains(ip)){
                ret = host;
                break;
            }
        }
        return ret;
    }
}
