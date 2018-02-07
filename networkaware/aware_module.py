from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.topology import api
from ryu.topology import event
from ryu.ofproto import ofproto_v1_3

from common_function import add_miss_flow

EventToListened = [event.EventSwitchEnter, event.EventSwitchLeave, event.EventSwitchReconnected,
                   event.EventLinkAdd,
                   event.EventLinkDelete,
                   event.EventPortAdd, event.EventPortDelete, event.EventPortModify, event.EventHostAdd,
                   event.EventHostDelete]


class Aware(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Aware, self).__init__(*args, **kwargs)

        # self.logger.info(self.sw)
        self.name = "aware"
        self.switches = []
        self.port_of_switches = {}  # (sw.id)--->port_np
        self.LinkBetweenSwitches = {}  # (src.id,dst.id)----->src_port_no,dst_port_no
        self.monitor = hub.spawn(self._monitor)
        self.HostSwitches = {}  # (sw.dpid,port)---->host_ip,host_mac

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        '''
        :param ev: 收到的事件
        :return: 无
        在配置阶段下发miss-flow流表
        '''
        msg = ev.msg
        datapath = msg.datapath
        self.logger.info("switch {} is connected".format(datapath.id))
        add_miss_flow(datapath)

    def _monitor(self):
        i = 0
        while True:
            if i == 1000000000:
                self.topo(None)
                i = 0
            hub.sleep(1)
            i += 1

    @set_ev_cls(EventToListened)
    def topo(self, ev):
        self.getSwitch()
        self.getPortOfSwitches()
        self.getLinkBetweenSwitches()
        self.getHosts()
        # self.logger.info(self.switches)
        # self.logger.info(self.LinkBetweenSwitches)
        # self.logger.info(self.HostSwitches)


    def getSwitch(self):
        '''

        :return:switches:dp,port  port:dpid,port_no
        '''
        self.switches = api.get_all_switch(self)

    def getPortOfSwitches(self):
        for sw in self.switches:
            datapath = sw.dp
            id = datapath.id
            self.port_of_switches.setdefault(id, set())

            for port in sw.ports:
                self.port_of_switches[id].add(port.port_no)

    def getLinkBetweenSwitches(self):
        AllLink = api.get_all_link(self)
        for Link in AllLink:
            src_port = Link.src
            dst_port = Link.dst
            src_sw_dpid = src_port.dpid
            dst_sw_dpid = dst_port.dpid
            self.LinkBetweenSwitches[(src_sw_dpid, dst_sw_dpid)] = (src_port.port_no, dst_port.port_no)

    def getHosts(self):
        hosts = api.get_host(self)

        for host in hosts:
            self.HostSwitches[(host.port.dpid, host.port.port_no)] = (host.ipv4, host.mac)
        #self.logger.info(self.HostSwitches)


