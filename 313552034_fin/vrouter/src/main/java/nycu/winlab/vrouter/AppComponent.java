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

import org.glassfish.jersey.server.spi.internal.ValueParamProvider.Priority;
import org.onlab.packet.ARP;
import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
import org.onlab.packet.IPv4;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.TpPort;
import org.onlab.packet.EthType.EtherType;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.FilteredConnectPoint;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.host.HostService;
import org.onosproject.net.intent.IntentService;
import org.onosproject.net.intent.PointToPointIntent;
import org.onosproject.net.intent.Key;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import javax.crypto.Mac;

import org.onosproject.net.intf.Interface;
import org.onosproject.net.intf.InterfaceEvent;
import org.onosproject.net.intf.InterfaceListener;
import org.onosproject.net.intf.InterfaceService;
import org.onosproject.net.meter.Band;
import org.onosproject.net.meter.DefaultBand;
import org.onosproject.net.meter.DefaultMeterRequest;
import org.onosproject.net.meter.MeterRequest;
import org.onosproject.net.meter.Meter;
import org.onosproject.net.meter.Meter.Unit;
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
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.meter.MeterService;



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
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected MeterService meterService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    private ReactivePacketProcessor processor = new ReactivePacketProcessor();
    
    @Activate
    protected void activate() {
        // add listener to connect BGP traffic
        appId = coreService.registerApplication("nycu.winlab.vrouter");
        log.info("vrouter Started");
        packetService.addProcessor(processor, PacketProcessor.director(0));
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);

        Band band = DefaultBand.builder()
        .ofType(Band.Type.DROP)
        .withRate(1048576)
        .burstSize(1048576)
        .build();
        List<Band> bands = new ArrayList<>();
        bands.add(band);
        MeterRequest meterRequest = DefaultMeterRequest.builder()
        .forDevice(DeviceId.deviceId("of:0000000000000001"))
        .fromApp(appId)
        .withBands(bands)
        .withUnit(Unit.KB_PER_SEC).add();
        Meter meter = meterService.submit(meterRequest);
        setBGPIntent();
        // of:0000000000000001/2
        if (meter == null) {
            log.info("Meter is null");
            return;
        }
        TrafficSelector.Builder meterSelector = DefaultTrafficSelector.builder()
        .matchInPort(PortNumber.portNumber(2));
        TrafficTreatment.Builder meterTreatment = DefaultTrafficTreatment.builder()
        .setOutput(PortNumber.portNumber(3))
        .meter(meter.id());

        FlowRule meterFlowRule = DefaultFlowRule.builder()
        .forDevice(DeviceId.deviceId("of:0000000000000001"))
        .withSelector(meterSelector.build())
        .withTreatment(meterTreatment.build())
        .withPriority(30000)
        .fromApp(appId)
        .makePermanent()
        .build();
        flowRuleService.applyFlowRules(meterFlowRule);


    }

    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(processor);
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
        intentService.getIntentsByAppId(appId).forEach(intentService::withdraw);
        log.info("Stopped");
    }
    private class ReactivePacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();
            if (ethPkt == null) {
                log.info("ethPkt is null");
                return;
            }
            if(ethPkt.getEtherType() != Ethernet.TYPE_IPV4){
                log.info("ethPkt is not ipv4");
                return;
            }
            IPv4 ipv4Pkt = (IPv4) ethPkt.getPayload();
            Ip4Address dstIp = Ip4Address.valueOf(ipv4Pkt.getDestinationAddress());
            Ip4Address srcIp = Ip4Address.valueOf(ipv4Pkt.getSourceAddress());
            // TODO: Implement how non BGP packet traffic
            if(ipv4Pkt.getProtocol() ==  IPv4.PROTOCOL_ICMP){
                log.info("It's icmp from {} to {}", srcIp, dstIp);
            }
            if (context.isHandled()) {
                return;
            }

            if(domainIP.contains(dstIp) && domainIP.contains(srcIp)){
                log.info("domain to domain");
                return;
            }
            if(domainIP.contains(dstIp)){
                log.info("external to domain");
                exteranl2Sdn(context);
            }else{
                log.info("domain to external");
                sdn2External(context);
            }
            context.treatmentBuilder().setOutput(pkt.receivedFrom().port());
            context.send();    
            return;
        }
    }
    void setBGPIntent(){
        Ip4Address speakerIp = Ip4Address.valueOf("192.168.70.82");
        Ip4Address ixpIP = Ip4Address.valueOf("192.168.70.253");
        TrafficSelector.Builder dstSelector = dstBGPSelectorBuilder(speakerIp,ixpIP);
        TrafficSelector.Builder srcSelector = srcBGPSelecBuilder(speakerIp,ixpIP);
        ConnectPoint speakerCP = ConnectPoint.deviceConnectPoint("of:0000000000000001/7");
        ConnectPoint ixpCP = ConnectPoint.deviceConnectPoint("of:00005e8f1d94de46/3");
        TrafficTreatment treatment = DefaultTrafficTreatment.builder().build();
        // form local to peer
        installIntent(speakerCP, ixpCP, dstSelector.build(), treatment,10);
        installIntent(ixpCP, speakerCP, srcSelector.build(), treatment,10);
        // form peer to local
        TrafficSelector.Builder dstSelector2 = dstBGPSelectorBuilder(ixpIP,speakerIp);
        TrafficSelector.Builder srcSelector2 = srcBGPSelecBuilder(ixpIP,speakerIp);
        TrafficTreatment treatment2 = DefaultTrafficTreatment.builder().build();
        installIntent(ixpCP, speakerCP, dstSelector2.build(),treatment2,10);
        installIntent(speakerCP, ixpCP, srcSelector2.build(),treatment2,10);

        Ip4Address speakerIp2 = Ip4Address.valueOf("192.168.63.1");
        Ip4Address asIP = Ip4Address.valueOf("192.168.63.2");
        TrafficSelector.Builder dstSelector3 = dstBGPSelectorBuilder(speakerIp2,asIP);
        TrafficSelector.Builder srcSelector3 = srcBGPSelecBuilder(speakerIp2,asIP);
        ConnectPoint asCP = ConnectPoint.deviceConnectPoint("of:0000000000000001/3");
        ConnectPoint speakerCP2 = ConnectPoint.deviceConnectPoint("of:0000000000000001/2");
        TrafficTreatment treatment3 = DefaultTrafficTreatment.builder().build();
        // form local to peer
        installIntent(speakerCP2, asCP, dstSelector3.build(), treatment3,11);
        installIntent(asCP, speakerCP2, srcSelector3.build(), treatment3,12);
        // form peer to local
        TrafficSelector.Builder dstSelector4 = dstBGPSelectorBuilder(asIP,speakerIp2);
        TrafficSelector.Builder srcSelector4 = srcBGPSelecBuilder(asIP,speakerIp2);
        TrafficTreatment treatment4 = DefaultTrafficTreatment.builder().build();
        installIntent(asCP, speakerCP2, dstSelector4.build(),treatment4,13);
        installIntent(speakerCP2, asCP, srcSelector4.build(),treatment4,14);

        Ip4Address peerIp = Ip4Address.valueOf("192.168.70.80");
        TrafficSelector.Builder dstSelector5 = dstBGPSelectorBuilder(speakerIp,peerIp);
        TrafficSelector.Builder srcSelector5 = srcBGPSelecBuilder(speakerIp,peerIp);
        ConnectPoint peerCP = ConnectPoint.deviceConnectPoint("of:0000000000000002/11");
        TrafficTreatment treatment5 = DefaultTrafficTreatment.builder().build();
        // form local to peer
        installIntent(speakerCP, peerCP, dstSelector5.build(), treatment5,10);
        installIntent(peerCP, speakerCP, srcSelector5.build(), treatment5,10);
        // form peer to local
        TrafficSelector.Builder dstSelector6 = dstBGPSelectorBuilder(peerIp,speakerIp);
        TrafficSelector.Builder srcSelector6 = srcBGPSelecBuilder(peerIp,speakerIp);
        TrafficTreatment treatment6 = DefaultTrafficTreatment.builder().build();
        installIntent(peerCP, speakerCP, dstSelector6.build(),treatment6,10);
        installIntent(speakerCP, peerCP, srcSelector6.build(),treatment6,10);

        
    }
    void installIntent(ConnectPoint src, ConnectPoint dst, TrafficSelector selector,
     TrafficTreatment treatment){
        PointToPointIntent intent = PointToPointIntent.builder()
        .key(Key.of(src.toString() + dst.toString()+selector.toString()+treatment.toString(), appId))
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
       .key(Key.of(src.toString() + dst.toString()+selector.toString()+treatment.toString()+priority, appId))
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
        .matchEthType(Ethernet.TYPE_IPV4);
    }
    TrafficSelector.Builder srcBGPSelecBuilder(Ip4Address src, Ip4Address dst){
        return DefaultTrafficSelector.builder()
        .matchIPSrc(IpPrefix.valueOf(src,32))
        .matchIPDst(IpPrefix.valueOf(dst,32))
        .matchEthType(Ethernet.TYPE_IPV4);
    }
    void exteranl2Sdn(PacketContext context){
        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();
        IPv4 ipv4Pkt = (IPv4) ethPkt.getPayload();
        Ip4Address dstIp = Ip4Address.valueOf(ipv4Pkt.getDestinationAddress());
        Ip4Address srcIp = Ip4Address.valueOf(ipv4Pkt.getSourceAddress());
        ConnectPoint receivedPoint = pkt.receivedFrom();
        hostService.requestMac(dstIp);
        Host dstHost =getHostByIp(dstIp);
        MacAddress dstMac = dstHost.mac();
        ConnectPoint dstPoint = dstHost.location();

        TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
        .matchEthType(Ethernet.TYPE_IPV4)
        .matchIPDst(IpPrefix.valueOf(dstIp,32));
        Host routerHost = getHostByIp(Ip4Address.valueOf("172.16.82.69"));
        MacAddress routerMac = routerHost.mac();
        TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder()
        .setEthDst(dstMac)
        .setEthSrc(routerMac);
        
        log.info("srcip: {} dstIp: {}", srcIp, dstIp);
        log.info("vrouter Received packet from {} to {}", receivedPoint, dstPoint);
        installIntent(receivedPoint, dstPoint, selector.build(), treatment.build(),30001);
    }
    void sdn2External(PacketContext context){
        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();
        IPv4 ipv4Pkt = (IPv4) ethPkt.getPayload();
        Ip4Address dstIp = Ip4Address.valueOf(ipv4Pkt.getDestinationAddress());

        ConnectPoint receivedPoint = pkt.receivedFrom();
        Optional<ResolvedRoute> optionalRoute = routeService.longestPrefixLookup(dstIp);
        if (!optionalRoute.isPresent()) {
            log.info("No route found for {}", dstIp);
            return;
        }
        Route route = optionalRoute.get().route();
        log.info("Route: {}", route);
        Ip4Address nextHop = route.nextHop().getIp4Address();
        MacAddress nextHopMac = getHostByIp(nextHop).mac();
        ConnectPoint nextHopPoint = getHostByIp(nextHop).location();
        log.info("Next hop mac: {}", nextHopMac);
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
        .matchEthType(Ethernet.TYPE_IPV4)
        .matchIPDst(IpPrefix.valueOf(dstIp,32));
        Host routerhost = getHostByIp(Ip4Address.valueOf("172.16.82.69"));
        MacAddress routerMac = routerhost.mac();
        TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder()
        .setEthDst(nextHopMac)
        .setEthSrc(routerMac);
        log.info("vrouter Received packet from {} to {}", receivedPoint, nextHopPoint);
        if (receivedPoint.equals(nextHopPoint)) {
            return;
        }
        installIntent(receivedPoint, nextHopPoint, selector.build(), treatment.build(),30001);
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
