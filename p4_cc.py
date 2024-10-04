import struct
import time
from ryu.base import app_manager
from ryu.controller import ofp_event, event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ether_types, lldp, arp
from ryu.ofproto import ether
from ryu.topology import event
from ryu.topology.api import get_all_switch, get_all_link, get_all_host
from heapq import heappush, heappop

class SimpleController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleController, self).__init__(*args, **kwargs)
        # Global data structures for switches, hosts, and links
        self.switches = {}
        self.hosts = {}
        self.host_links = {}      # Store hosts by MAC address
        self.switch_links = {}
        self.link_delays = {}
        self.graph = {}
        self.shortest_paths = {}

        self.mac_to_port = {}
        self.tree = {}      
        
        # self.LLDP_INTERVAL = 10  # Time interval to send LLDP packets
        self.LLDP_PERIOD = 5
        self.start_time = time.time()
        self.lldp_thread = None

    def create_shortest_path_tree(self):
        graph = {}
        switch_links = {}
        host_links = {}
        host_dict = {}
        switch_dict = {}

        switch_dps = get_all_switch(self)
        self.process_switches(switch_dps, graph, switch_dict)
        switches = [switch.dp.id for switch in switch_dps]
        links = get_all_link(self)
        self.process_links(links, graph, switch_links)
        hosts = get_all_host(self)
        self.process_hosts(hosts, graph, host_links, host_dict)

        self.graph = graph
        self.switches = switch_dict
        self.hosts = host_dict
        self.host_links = host_links
        self.switch_links = switch_links

        # self.logger.info(f"Graph: {self.graph}")
        
        for src in self.hosts.keys():
            dist = {src: 0}
            path = {src: []}
            pq = []

            heappush(pq, (0, src))
            while pq:
                delay, node = heappop(pq)
                try:
                    node = int(node)
                except:
                    pass
                if node in dist and delay > dist[node]:
                    continue
                for neighbor in graph[node]:
                    new_delay = delay
                    if (node, neighbor) in self.link_delays:
                        new_delay = delay + self.link_delays[(node, neighbor)]
                    if neighbor not in dist or new_delay < dist[neighbor]:
                        dist[neighbor] = new_delay
                        if neighbor in self.hosts.keys():
                            path[neighbor] = path[node]
                        else:
                            path[neighbor] = path[node] + [neighbor]
                        heappush(pq, (new_delay, str(neighbor)))
            
            for dst in path.keys():
                self.shortest_paths[(src, dst)] = path[dst]

        # self.logger.info(f"Shortest paths: {self.shortest_paths}")

    def process_hosts(self, hosts, graph, host_links, host_dict):
        for host in hosts:
            self.logger.info(f"Host added: {host.mac} at {host.port.dpid}")
            host_dict[host.mac] = host
            if (host.mac, host.port.dpid) not in host_links:
                host_links[(host.mac, host.port.dpid)] = host
                host_links[(host.port.dpid, host.mac)] = host

            if host.mac in graph:
                graph[host.mac].append(host.port.dpid)
            else:
                graph[host.mac] = [host.port.dpid]
            
            if host.port.dpid in graph:
                graph[host.port.dpid].append(host.mac)
            else:
                graph[host.port.dpid] = [host.mac]

    def process_switches(self, switches, graph, switch_dict):
        for switch in switches:
            switch_dict[switch.dp.id] = switch

    def process_links(self, links, graph, switch_links):
        for link in links:
            src = link.src
            dst = link.dst
            if (src.dpid, dst.dpid) not in switch_links:
                switch_links[(src.dpid, dst.dpid)] = link
                switch_links[(dst.dpid, src.dpid)] = link
                self.logger.info(f"Link added: {src.dpid} -> {dst.dpid}")
                self.logger.info(f"Link added: {dst.dpid} -> {src.dpid}")
            
            if src.dpid not in graph:
                graph[src.dpid] = [dst.dpid]
            elif dst.dpid not in graph[src.dpid]:
                graph[src.dpid].append(dst.dpid)
            
            if dst.dpid not in graph:
                graph[dst.dpid] = [src.dpid]
            elif src.dpid not in graph[dst.dpid]:
                graph[dst.dpid].append(src.dpid)
        
    @set_ev_cls(event.EventSwitchEnter)
    def _switch_enter_handler(self, ev):
        dpid = ev.switch.dp.id
        if not self.lldp_thread:
            # Start LLDP process after the first switch connects
            self.lldp_thread = hub.spawn(self._send_lldp_packets)
        
        # self.switches[dpid] = ev.switch.dp
        self.logger.info(f"Switch entered: {dpid}")

    @set_ev_cls(event.EventHostAdd)
    def host_add_handler(self, ev):
        host = ev.host
        # self.hosts[host.mac] = host
        if not self.lldp_thread:
            # Start LLDP process after the first switch connects
            self.lldp_thread = hub.spawn(self._send_lldp_packets)
        self.logger.info(f"Host entered: {host}")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info("Calling switch features handler")
        # install the table-miss flow entry.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
    
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # self.logger.info(f"Packet handler called, tree is {self.tree}")
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # self.logger.info("LLDP packet")
            self._handle_lldp(pkt, msg)
            return
        
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        in_port = msg.match['in_port']
        out_port = None
        next_dpid = None

        try:
            arp_pkt = pkt.get_protocol(arp.arp)
            if arp_pkt:
                tim = time.time()
                # self.logger.info(f"Flooding ARP packet: {arp_pkt} at time {tim}")
                out_port = ofproto.OFPP_FLOOD
                actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data
                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
                    actions=actions, data=data)
                datapath.send_msg(out)
                return
        except:
            pass

        if (src, dst) not in self.shortest_paths:
            return

        # self.logger.info(f"Packet in: {src} -> {dst} on switch {dpid}")
        shortest_path = self.shortest_paths[(src, dst)]
        for i, id in enumerate(shortest_path):
            if id == dpid and i < len(shortest_path) - 1:
                next_dpid = shortest_path[i + 1]
                link = self.switch_links[(dpid, next_dpid)]
                if link.src.dpid == dpid:
                    out_port = link.src.port_no
                else:
                    out_port = link.dst.port_no
                break
        
        if next_dpid is None:
            next_dpid = dst
            out_port = self.host_links[(dpid, dst)].port.port_no  
        
        match = datapath.ofproto_parser.OFPMatch(eth_dst=dst, eth_src=src)
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        
        datapath.send_msg(out)

    def update_actions(self, datapath, in_port):
        dpid = datapath.id
        neighbors = self.tree[dpid]

        out_ports = []
        # self.logger.info(f"On switch {dpid}, neighbors are {neighbors}")

        for neighbor in neighbors:
            if neighbor in self.switches:
                link = self.switch_links[(dpid, neighbor)]
                if link.src.dpid == dpid:
                    out_ports.append(link.src.port_no)
                else:
                    out_ports.append(link.dst.port_no)
            elif neighbor in self.hosts:
                link = self.host_links[(dpid, neighbor)]
                out_ports.append(link.port.port_no)

        # self.logger.info("Outports:", out_ports)
        actions = []
        for out_port in out_ports:
            if out_port != in_port:
                actions.append(datapath.ofproto_parser.OFPActionOutput(out_port))
        # print(actions)
        return actions

    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.switches[dp.id] = dp
        # elif ev.state == DEAD_DISPATCHER:
        #     if dp.id in self.switches:
        #         del self.switches[dp.id]

    def _send_lldp_packets(self):
        while True:
            self.logger.info(f"Sending LLDP packets at time {time.time() - self.start_time}")
            switches = get_all_switch(self)
            for switch in switches:
                self._send_lldp(switch.dp)
            hub.sleep(self.LLDP_PERIOD)
            self.create_shortest_path_tree()

    def _send_lldp(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        dpid = datapath.id

        for port in datapath.ports.values():
            # Create an LLDP packet with a timestamp
            pkt = packet.Packet()
            eth = ethernet.ethernet(dst=lldp.LLDP_MAC_NEAREST_BRIDGE, ethertype=ether_types.ETH_TYPE_LLDP)
            pkt.add_protocol(eth)

            dpid_bytes = str(dpid).encode('utf-8')

            # Create LLDP packet components
            chassis_id = lldp.ChassisID(
                subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED,
                chassis_id=dpid_bytes  # Use the DPID as the chassis ID
            )

            port_id_tlv = lldp.PortID(
                subtype=lldp.PortID.SUB_LOCALLY_ASSIGNED,
                port_id=str(port.port_no).encode('utf-8')  # Use the port ID as necessary
            )

            ttl = lldp.TTL(ttl=120)

            # Pack the current timestamp as a double (8 bytes)
            timestamp = struct.pack('!d', time.time()) 
            oui_bytes = struct.pack('!I', 0x123456)[1:]
            # Create the custom TLV with the packed timestamp
            custom_tlv = lldp.OrganizationallySpecific(
                oui=oui_bytes,  # Use a valid OUI for your organization
                subtype=0x01,  # Subtype for this TLV
                info=timestamp  # Use the packed timestamp directly
            )

            # Create the full LLDP packet with the custom TLV
            lldp_pkt = lldp.lldp(tlvs=[chassis_id, port_id_tlv, ttl, custom_tlv, lldp.End()])

            pkt.add_protocol(lldp_pkt)
            pkt.serialize()

            # Send the LLDP packet out of the switch port
            data = pkt.data
            actions = [parser.OFPActionOutput(port.port_no)]
            out = parser.OFPPacketOut(
                datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER,
                actions=actions, data=data
            )
            datapath.send_msg(out)

    def _handle_lldp(self, pkt, msg):
        # Extract the LLDP packet from the received packet
        lldp_pkt = pkt.get_protocol(lldp.lldp)

        # Verify that we have a valid LLDP packet
        if lldp_pkt is None:
            self.logger.warning("Received packet is not an LLDP packet")
            return
        
        src_dpid = msg.datapath.id
        neighbor_add = None
        timestamp = None

        for tlv in lldp_pkt.tlvs:
            if isinstance(tlv, lldp.ChassisID):
                try:
                    neighbor_add = int(tlv.chassis_id.decode('utf-8'))
                except ValueError:
                    # self.logger.warning(f"Failed to decode chassis_id: {tlv.chassis_id}")
                    break
            elif isinstance(tlv, lldp.OrganizationallySpecific):
                try:
                    # Unpack the timestamp from the custom TLV
                    timestamp = struct.unpack('!d', tlv.info)[0]
                except:
                    # self.logger.warning("Failed to unpack timestamp from custom TLV")
                    pass

        if neighbor_add is not None and timestamp is not None:
            delay = float(time.time() - timestamp)

            # Determine if neighbor_add is a DPID (switch) or a host MAC
            try:
                # Try to convert neighbor_add to an integer (DPID)
                neighbor_dpid = int(neighbor_add)
                # Switch-to-switch link
                self.link_delays[(src_dpid, neighbor_dpid)] = delay
                self.link_delays[(neighbor_dpid, src_dpid)] = delay
                # self.logger.info(f"Stored link delay for switches {src_dpid} and {neighbor_dpid}: {delay} seconds")
            except ValueError:
                # If conversion to int fails, it's a host MAC address
                host_mac = neighbor_add
                # Host-to-switch link
                self.link_delays[(host_mac, src_dpid)] = delay
                self.link_delays[(src_dpid, host_mac)] = delay
                # self.logger.info(f"Stored link delay for host {host_mac} and switch {src_dpid}: {delay} seconds")

            

            
