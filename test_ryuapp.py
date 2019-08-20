from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER,MAIN_DISPATCHER,DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import tcp
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from operator import attrgetter
from ryu.lib import hub

class test_RyuApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    SA_struct = {}

    def __init__(self,*args,**kwargs):
        super(test_RyuApp,self).__init__(*args,**kwargs)
        self.mac_to_port = {}
        #self.tcp_info = {}
        
        self.datapaths = {}     

        self.syn_table = {}
        self.sa_table = {}
        self.ack_table = {}
        ## Monitor
        self.time = 10
        self.monitor_thread = hub.spawn(self._monitor)
 
        ## Clean
        self.clean_time = 120
        self.clean_thread = hub.spawn(self._clean)

    @set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]
    
    # TODO : Clean
    def _clean(self):
        while True:
            for dp in self.datapaths.values():
                if dp.id == 1:
                    self.sa_table.clear()
                    self.ack_table.clear()
                    self.syn_table.clear()
                    self.del_flow(dp,1,1,0xFFFFFFFFFFFFFFFF)
                    self.del_flow(dp,2,1,0xFFFFFFFFFFFFFFFF)
                    self.del_flow(dp,3,1,0xFFFFFFFFFFFFFFFF)

            hub.sleep(self.clean_time)

    # TODO : Monitor
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                if dp.id == 1:
                    self._request_stats(dp)
            hub.sleep(self.time)

    # TODO : Request flow stats
    def _request_stats(self,datapath):
        self.logger.debug('send flow stats request : %016x',datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath = datapath,table_id = 2)
        datapath.send_msg(req)
        req = parser.OFPFlowStatsRequest(datapath = datapath,table_id = 3)
        datapath.send_msg(req)

    # TODO : Reply flow stats
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        
        if ev.msg.datapath.id == 1:

            self.logger.info("datapath "
                  "table_id "
                  "ip               "
                  "packet_count ")
            self.logger.info("-------- "
                  "-------- "
                  "---------------- "
                  "------------ ")

            if body[0].table_id==2 and ev.msg.datapath.id == 1:
                for stat in sorted([flow for flow in body if flow.priority > 0],
                                   key=lambda flow: (flow.match['ipv4_dst'])):
                    self._collect(stat.table_id,stat.match['ipv4_dst'],stat.packet_count)
                    self.logger.info("%08d %08d %16s %08d " %(ev.msg.datapath.id,stat.table_id,stat.match['ipv4_dst'],stat.packet_count))
            elif body[0].table_id==3 and ev.msg.datapath.id == 1:
                for stat in sorted([flow for flow in body if flow.priority > 0],
                                   key=lambda flow: (flow.match['ipv4_src'])):
                    self._collect(stat.table_id,stat.match['ipv4_src'],stat.packet_count)
                    self.logger.info("%08d %08d %16s %08d " %(ev.msg.datapath.id,stat.table_id,stat.match['ipv4_src'],stat.packet_count))
     
            self._detect(ev.msg.datapath)

    # TODO : Calculate Syn/ack & ACK
    def _collect(self,table_id,ipv4,packet_count):
        if table_id == 2:
            self.sa_table.setdefault(ipv4,None)
            self.sa_table[ipv4]=packet_count
            #self.logger.info('sa_table',self.sa_table)
        elif table_id == 3:
            self.ack_table.setdefault(ipv4,None)
            self.ack_table[ipv4]=packet_count
            #self.logger.info('ack_table',self.ack_table)


    # TODO : Detect & drop packets
    def _detect(self,datapath):
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        keys = self.ack_table.keys()
        for ip in keys:
            if self.syn_table.has_key(ip) == False and self.ack_table[ip] == 0 and self.sa_table[ip] > 0:
                self.syn_table.setdefault(ip,None)
                print(datapath.id)
                match = parser.OFPMatch(eth_type = 0x0800,ip_proto=6,tcp_flags=0x02,ipv4_src=ip)
                inst = []
                mod = parser.OFPFlowMod(datapath = datapath,table_id=1,cookie=1,cookie_mask=0,priority = 1,match = match,instructions = inst)
                datapath.send_msg(mod)

    # TODO : Add rules.
    def add_flow(self,datapath,table_id,cookie,cookie_mask,priority,match,actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        mod = parser.OFPFlowMod(datapath = datapath,table_id=table_id,cookie=cookie,cookie_mask=cookie_mask,priority = priority,match = match,instructions = inst)
        datapath.send_msg(mod)

    # TODO : Delete rules.
    def del_flow(self,datapath,table_id,cookie,cookie_mask):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        mod = parser.OFPFlowMod(datapath = datapath,command=ofproto.OFPFC_DELETE,cookie=cookie,cookie_mask=cookie_mask,table_id=table_id,out_port=ofproto.OFPP_ANY,out_group=ofproto.OFPG_ANY)
        #table_id=ofproto.OFPTT_ALL
        datapath.send_msg(mod)
    
    # TODO : Modify rules.
    def mod_flow(self,datapath,cookie,cookie_mask,priority,match,actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        mod = parser.OFPFlowMod(datapath = datapath,command=ofproto.OFPFC_MODIFY,cookie=cookie,cookie_mask=cookie_mask,instructions = [])

        datapath.send_msg(mod)


    # TODO : add rules.
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures,CONFIG_DISPATCHER)
    def switch_features_handler(self,ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # TODO: Match SYN SYN/ACK ACK packets.
        if datapath.id == 1:
            # SYN
            match = parser.OFPMatch(eth_type = 0x0800,ip_proto=6,tcp_flags=0x02)
            inst = [parser.OFPInstructionGotoTable(table_id=1)]
            mod = parser.OFPFlowMod(datapath = datapath,table_id=0,priority = 3,match = match,instructions = inst)
            datapath.send_msg(mod)

            # SYN/ACK
            match = parser.OFPMatch(eth_type = 0x0800,ip_proto=6,tcp_flags=0x12)
            inst = [parser.OFPInstructionGotoTable(table_id=2)]
            mod = parser.OFPFlowMod(datapath = datapath,table_id=0,priority = 3,match = match,instructions = inst)
            datapath.send_msg(mod)
 
            # ACK
            match = parser.OFPMatch(eth_type = 0x0800,ip_proto=6,tcp_flags=0x10)
            inst = [parser.OFPInstructionGotoTable(table_id=3)]
            mod = parser.OFPFlowMod(datapath = datapath,table_id=0,priority = 1,match = match,instructions = inst)
            datapath.send_msg(mod)

            match = parser.OFPMatch()
            inst = [parser.OFPInstructionGotoTable(table_id=4)]
            mod = parser.OFPFlowMod(datapath = datapath,table_id=0,priority = 0,match = match,instructions = inst)
            datapath.send_msg(mod)

            # TODO: syn table.
            match = parser.OFPMatch()
            inst = [parser.OFPInstructionGotoTable(table_id=4)]
            mod = parser.OFPFlowMod(datapath = datapath,table_id=1,priority = 0,match = match,instructions = inst)
            datapath.send_msg(mod)

            # TODO: syn/ack table.
            match = parser.OFPMatch() 
            action = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                         ofproto.OFPCML_NO_BUFFER)]
            self.add_flow(datapath,2,0,0,0,match,action)
 
            # TODO: ack table.
            match = parser.OFPMatch()
            inst = [parser.OFPInstructionGotoTable(table_id=4)]
            mod = parser.OFPFlowMod(datapath = datapath,table_id=3,priority = 0,match = match,instructions = inst)
            datapath.send_msg(mod)
        
        # TODO: table-miss flow entry
        match = parser.OFPMatch()
        action = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                         ofproto.OFPCML_NO_BUFFER)]
        if datapath.id == 1:
            self.add_flow(datapath,4,0,0,0,match,action)
        else :
            self.add_flow(datapath,0,0,0,0,match,action)
    
    @set_ev_cls(ofp_event.EventOFPPacketIn,MAIN_DISPATCHER)
    def packet_in_handler(self,ev):
        
        # TODO : handle packets.
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(data=msg.data)
        pkt_ether = pkt.get_protocol(ethernet.ethernet)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4) 
        
        if not pkt_ether:
            return

        if datapath.id == 1 and pkt_ipv4:
            protocol = pkt_ipv4.proto
            if protocol == 6:
                pkt_tcp = pkt.get_protocol(tcp.tcp)
                # SYN/ACK : add rule & record the SA_struct.
                if pkt_tcp.bits == 18:                
                    
                    self.SA_struct.setdefault(pkt_ipv4.dst,{})
                    
                    match = parser.OFPMatch(eth_type = 0x0800,ip_proto=6,tcp_flags=0x12,ipv4_dst=pkt_ipv4.dst)
                    inst = [parser.OFPInstructionGotoTable(table_id=4)]
                    mod = parser.OFPFlowMod(datapath = datapath,table_id=2,cookie=1,cookie_mask=0,priority = 1,match = match,instructions = inst)
                    datapath.send_msg(mod)

                    #print(self.SA_struct)
                    
                    match = parser.OFPMatch(eth_type = 0x0800,ip_proto=6,tcp_flags=0x10,ipv4_src=pkt_ipv4.dst)
                    inst = [parser.OFPInstructionGotoTable(table_id=4)]
                    mod = parser.OFPFlowMod(datapath = datapath,table_id=3,cookie=1,cookie_mask=0,priority = 1,match = match,instructions = inst)
                    datapath.send_msg(mod)

                    #print(datapath.id,pkt_ipv4.src,pkt_ipv4.dst,pkt_tcp.bits)

        dst = pkt_ether.dst
        src = pkt_ether.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid,{})
        
        self.mac_to_port[dpid][src] = in_port
        
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port = in_port,eth_dst=dst)
            if datapath.id == 1:
                self.add_flow(datapath,4,0,0,1,match,actions)
            else:
                self.add_flow(datapath,0,0,0,1,match,actions)
           
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath = datapath,buffer_id = msg.buffer_id,in_port = in_port,actions = actions,data=data)
        datapath.send_msg(out)
    
