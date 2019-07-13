from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER,MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import lldp
from ryu.lib.packet import packet

class TCP_RyuApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    lldp_struct = {}

    def __init__(self,*args,**kwargs):
        super(TCP_RyuApp,self).__init__(*args,**kwargs)
        self.mac_to_port = {}

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
        match = parser.OFPMatch(eth_type = 0x0800,tcp_flags = 'SYN')
        action = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath,100,match,action)
        # TODO: table-miss flow entry
        match2 = parser.OFPMatch()
        action2 = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapatch,0,match2,action2)
 
    @set_ev_cls(ofp_event.EventOFPPacketIn,MAIN_DISPATCHER)
    def packet_in_handler(self,ev):
        # TODO : handle packets.
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        pkt_ether = pkt.get_protocol(ethernet.ethernet)

        dst = rth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid,{})
        
        self.logger.info("packet in %s %s %s %s",dpid,src,dst,in_port)
        self.mac_to_port[dpid][src] = in_port
        
        if dst in 
        
        """
        if not pkt_ether:
            return
        lldp_pkt = pkt.get_protocol(lldp.lldp)
        if lldp_pkt:
            self.lldp_struct.setdefault(datapath.id,{})
            self.lldp_struct[datapath.id].setdefault(ev.msg.match['in_port'],[lldp_pkt.tlvs[0].chassis_id,lldp_pkt.tlvs[1].port_id])
            print (self.lldp_struct)
        """
