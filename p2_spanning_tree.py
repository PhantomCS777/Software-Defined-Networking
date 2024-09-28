from ryu.base import app_manager
# from ryu.controller import ofp_event, event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.controller.controller as ryu_controller
from ryu.ofproto import ofproto_v1_3
from ryu.lib import dpid as dpid_lib
from ryu.lib import stplib
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.app import simple_switch_13
from ryu.topology import event

class SimpleController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleController, self).__init__(*args, **kwargs)
        # Global data structures for switches, hosts, and links
        self.switches = {}
        self.hosts = set()
        self.host_links = {}      # Store hosts by MAC address
        self.switch_links = {}
        self.graph = {}      
        # self.timeout = 1
    
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct the instruction based on actions
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        # If buffer_id is specified, use it to avoid buffering
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)

        # Send the FlowMod message to the switch (datapath)
        datapath.send_msg(mod)

    def delete_all_flows(self, datapath):
        """
        Deletes all flow entries on the specified switch (datapath).
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Create a FlowMod message to delete all flows by using an empty match
        match = parser.OFPMatch()  # Empty match means match all flows
        instructions = []  # No instructions are needed for deleting flows

        # Create the FlowMod message for deleting all flows
        flow_mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE,
                                    out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                                    priority=0, match=match, instructions=instructions)

        # Send the FlowMod message to the switch
        datapath.send_msg(flow_mod)

    def create_spanning_tree(self):
        root = list(self.switches.keys())[0]
        queue = [root]
        tree = {root: []}
        visited = set([root])

        while queue:
            node = queue.pop(0)
            for neighbor in self.graph[node]:
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
        
        for _, dp in self.switches.items():
            self.delete_all_flows(dp)
        
        for node, neighbors in tree.items():
            if node in self.switches:
                dp = self.switches[node]
                ofp = dp.ofproto
                ofp_parser = dp.ofproto_parser

                for neighbor in neighbors:
                    if neighbor in self.switches:
                        switch_link = self.switch_links[(node, neighbor)]
                        match = ofp_parser.OFPMatch(in_port=switch_link.src.port_no, eth_dst=switch_link.dst.hw_addr)
                        self.add_flow(self.switches[node], 0, match, 
                                      [dp.ofproto_parser.OFPActionOutput(dp.ofproto.OFPP_CONTROLLER)])
                    elif neighbor in self.hosts:
                        h_link = self.host_links[(node, neighbor)]
                        match = ofp_parser.OFPMatch(in_port=h_link.port.port_no, eth_dst=h_link.mac)
                        self.add_flow(self.switches[node], 0, match, 
                                      [h_link.port.dpid.ofproto_parser.OFPActionOutput(h_link.port.port_no)])

    def add_host_flows(self):
        for host in self.host_links.values():
            switch = host.port.dpid
            port = host.port.port_no
            mac = host.mac
            if switch in self.switches:
                self.add_flow(switch, port, mac)
        self.logger.info("Host flows added.")

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        datapath = ev.switch.dp
        dpid = datapath.id
        self.switches[dpid] = datapath
        self.logger.info(f"Switch entered: {dpid}")

    # @set_ev_cls(event.EventSwitchLeave)
    # def switch_leave_handler(self, ev):
    #     datapath = ev.switch.dp
    #     dpid = datapath.id
    #     if dpid in self.switches:
    #         del self.switches[dpid]
    #         self.logger.info(f"Switch left: {dpid}")

    @set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self, ev):
        link = ev.link
        src = link.src
        dst = link.dst
        if (src.dpid, dst.dpid) not in self.switch_links:
            self.switch_links[(src.dpid, dst.dpid)] = link
            self.switch_links[(dst.dpid, src.dpid)] = link
            self.logger.info(f"Link added: {src.dpid} -> {dst.dpid}")
            self.logger.info(f"Link added: {dst.dpid} -> {src.dpid}")
        
        if src.dpid not in self.graph:
            self.graph[src.dpid] = [dst.dpid]
        else:
            self.graph[src.dpid].append(dst.dpid)
        
        if dst.dpid not in self.graph:
            self.graph[dst.dpid] = [src.dpid]
        else:
            self.graph[dst.dpid].append(src.dpid)
        
        self.create_spanning_tree()

        # if self.is_topology_complete() and not self.spanned_tree:
        #     self.create_spanning_tree()
        #     self.logger.info("Topology is complete. Spanning tree created.")
        #     self.add_host_flows()

    # @set_ev_cls(event.EventLinkDelete)
    # def link_del_handler(self, ev):
    #     link = ev.link
    #     src = link.src
    #     dst = link.dst
    #     del self.links[(src.dpid, dst.dpid)]
    #     del self.links[(dst.dpid, src.dpid)]  # Remove bi-directional link
    #     self.logger.info(f"Link deleted: {src.dpid} -> {dst.dpid}")

    @set_ev_cls(event.EventHostAdd)
    def host_add_handler(self, ev):
        host = ev.host
        self.logger.info(f"Host added: {host.mac} at {host.port.dpid}")
        self.hosts.add(host.mac)
        self.host_links[(host.mac, host.port.dpid)] = host
        self.host_links[(host.port.dpid, host.mac)] = host

        if host.mac in self.graph:
            self.graph[host.mac].append(host.port.dpid)
        else:
            self.graph[host.mac] = [host.port.dpid]
        
        if host.port.dpid in self.graph:
            self.graph[host.port.dpid].append(host.mac)
        else:
            self.graph[host.port.dpid] = [host.mac]

        # self.create_spanning_tree()
    
    # @set_ev_cls(event.EventHostDelete)
    # def host_del_handler(self, ev):
    #     host = ev.host
    #     if host.mac in self.hosts:
    #         del self.hosts[host.mac]
    #         self.logger.info(f"Host deleted: {host.mac}")

    def is_topology_complete(self):
        return len(self.switches) == 4 and len(self.switch_links) == 8

    def print_network_topology(self):
        # Print the current global view of the switches, hosts, and links
        self.logger.info("Current network topology:")
        self.logger.info(f"Switches: {self.switches.keys()}")
        self.logger.info(f"Hosts: {self.host_links.keys()}")
        self.logger.info(f"Links: {[(src, dst) for src, dst in self.switch_links.keys()]}")