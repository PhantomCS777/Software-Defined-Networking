from ryu.base import app_manager
from ryu.controller import ofp_event, event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.app import simple_switch_13
from ryu.topology import event
from ryu.topology.api import get_all_switch, get_all_link, get_all_host

class SimpleController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleController, self).__init__(*args, **kwargs)
        # Global data structures for switches, hosts, and links
        self.switches = {}
        self.hosts = {}
        self.host_links = {}      # Store hosts by MAC address
        self.switch_links = {}
        self.graph = {}

        self.mac_to_port = {}
        self.tree = {}      
        # self.timeout = 1

    def create_spanning_tree(self):
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

        root = switches[0]
        queue = [root]
        tree = {root: []}
        visited = set([root])

        while queue:
            node = queue.pop(0)
            for neighbor in graph[node]:
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)

                    if node in tree:
                        tree[node].append(neighbor)
                    else:
                        tree[node] = [neighbor]

                    if neighbor in tree:
                        tree[neighbor].append(node)
                    else:
                        tree[neighbor] = [node]
        
        self.logger.info(tree)

        self.tree = tree
        self.graph = graph
        self.switches = switch_dict
        self.hosts = host_dict
        self.host_links = host_links
        self.switch_links = switch_links

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
            if switch.dp.id not in graph:
                graph[switch.dp.id] = []

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
            else:
                graph[src.dpid].append(dst.dpid)
            
            if dst.dpid not in graph:
                graph[dst.dpid] = [src.dpid]
            else:
                graph[dst.dpid].append(src.dpid)

    def add_switch_flow(self, datapath, neighbor_dp, neighbor_type, link_info):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dp_id = datapath.id  # Get the DPID of the current switch

        # Match and action details
        match = None
        actions = None

        if neighbor_type == 'switch':
            self.logger.info(f"Adding switch flow between {dp_id} and {neighbor_dp.id}")
            # Determine the correct input and output ports based on whether datapath is link.src or link.dst
            if dp_id == link_info.src.dpid:
                in_port = link_info.src.port_no
                out_port = link_info.dst.port_no
            elif dp_id == link_info.dst.dpid:
                in_port = link_info.dst.port_no
                out_port = link_info.src.port_no
            else:
                self.logger.error(f"Link mismatch for datapath {dp_id}")
                return  # Exit if the datapath is neither the source nor the destination
            # Match all traffic coming from in_port and forward it to out_port
            match = parser.OFPMatch(in_port=in_port)  # Match traffic from this input port
            actions = [parser.OFPActionOutput(out_port)]  # Forward to output port

        elif neighbor_type == 'host':
            self.logger.info(f"Adding host flow between {dp_id} and {link_info.mac}")
            out_port = link_info.port.port_no
            # Neighbor is a host, forward traffic to the host's port
            host_mac = link_info.mac
            match = parser.OFPMatch(eth_dst=host_mac)  # Match traffic destined for the host
            actions = [parser.OFPActionOutput(out_port)]

        # Install the flow to forward traffic through the appropriate port
        if match and actions:
            self.install_flow(datapath, match, actions)

    def install_flow(self, datapath, match, actions, priority=1):
        """Helper function to install flows on the switch."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Instruction to apply actions (forward traffic)
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        # Create and send the flow modification message to the switch
        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst
        )

        datapath.send_msg(flow_mod)
        self.logger.info(f"Flow installed on switch {datapath.id} for match {match}")

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        dpid = ev.switch.dp.id
        self.logger.info(f"Switch entered: {dpid}")
        self.create_spanning_tree()

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

    @set_ev_cls(event.EventHostAdd)
    def host_add_handler(self, ev):
        host = ev.host
        # self.switches[dpid] = datapath
        self.logger.info(f"Host entered: {host}")
        self.create_spanning_tree()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # self.logger.info(f"Packet handler called, tree is {self.tree}")
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            # self.logger.info("LLDP packet")
            return
        
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        in_port = msg.match['in_port']

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        dst_found = True

        if dst in self.mac_to_port[dpid]:
            # self.logger.info("Found match in dict")
            out_port = self.mac_to_port[dpid][dst]
            match = datapath.ofproto_parser.OFPMatch(eth_src=src, eth_dst=dst, in_port=in_port)
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        else:
            # self.logger.info("Trying to flood the tree")
            dst_found = False
            match = datapath.ofproto_parser.OFPMatch(in_port = in_port)
            actions = self.update_actions(datapath, in_port)

        # install a flow to avoid packet_in next time
        if dst_found:
            self.logger.info(f"Adding flow with actions: {actions}")
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
