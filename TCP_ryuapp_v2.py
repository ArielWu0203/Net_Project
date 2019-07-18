from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
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

class TCP_RyuApp_v2(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self,*args,**kwargs):
        super(TCP_RyuApp_v2,self).__init__(*args,**kwargs)
        self.mac_to_port = {}
        self.tcp_info = {}
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

    # TODO : update the states of switchs
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
    
    ## TODO : every 10 secs,send request for switches,in order to get flow statistic.
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)
    
    ## TODO : Reqest flow_states
    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        ## OFPFlowStatsRequest : get the information of all flow entries from switches.
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    ## TODO : Get flow_states
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body   
        self.logger.info('-----------------------------------')
        self.logger.info('datapath=%d' % ev.msg.datapath.id)
        for stat in ev.msg.body:
            self.logger.info('table_id = %s '
                             'priority = %d '
                             'match = %s instructions = %s '
                             'packet_count = %d byte_count = %d '
                             'duration_sec = %d duration_nesc = %d '
                             'idle_timeout = %d hard_timeout = %d ' %
                             (stat.table_id, 
                              stat.priority,
                              stat.match, stat.instructions,
                              stat.packet_count, stat.byte_count,
                              stat.duration_sec, stat.duration_nsec,
                              stat.idle_timeout, stat.hard_timeout))
    

    # TODO : Add rules.
    def add_flow(self,datapath,priority,match,actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        mod = parser.OFPFlowMod(datapath = datapath,priority = priority,match = match,instructions = inst)
        datapath.send_msg(mod)

    # TODO : add rules.
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures,CONFIG_DISPATCHER)
    def switch_features_handler(self,ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # TODO: SYN packets to CP rule.
        match = parser.OFPMatch(eth_type = 0x0800,ip_proto=6,tcp_flags = 0x02)
        action = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath,2,match,action)
        # TODO: table-miss flow entry
        match2 = parser.OFPMatch()
        action2 = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath,0,match2,action2)
 
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

        if pkt_ipv4:
            protocol = pkt_ipv4.proto
            if protocol == 6:
                pkt_tcp = pkt.get_protocol(tcp.tcp)
                if pkt_tcp.has_flags(tcp.TCP_SYN):
                    self.handle_tcp(msg,datapath,in_port,pkt_ether,pkt_tcp)
                    return
                    
        dst = pkt_ether.dst
        src = pkt_ether.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid,{})
        
        #self.logger.info("dpid=%s src=%s dst=%s in_port=%s\n",dpid,src,dst,in_port)
        self.mac_to_port[dpid][src] = in_port
        
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port = in_port,eth_dst=dst)
            self.add_flow(datapath,1,match,actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath = datapath,buffer_id = msg.buffer_id,in_port = in_port,actions = actions,data=data)
        datapath.send_msg(out)
    
    def handle_tcp(self,msg,datapath,in_port,pkt_ether,pkt_tcp):
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
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
            match = parser.OFPMatch(eth_type = 0x0800,ip_proto=6,tcp_flags = 0x02,in_port = in_port,eth_dst=dst)
            self.add_flow(datapath,3,match,actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath = datapath,buffer_id = msg.buffer_id,in_port = in_port,actions = actions,data=data)
        datapath.send_msg(out)
                           
