from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER
from ryu.lib import hub
from ryu.lib.packet import packet, ipv4
from ryu.ofproto import ofproto_v1_3
from ryu.base.app_manager import lookup_service_brick
import networkx as nx
from CHANG_LIANG import distance


class NetResource(app_manager.RyuApp):
    '''
        利用aware_module 中的拓扑信息创建图
    '''
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(NetResource, self).__init__(*args, **kwargs)
        self.name = "resource"
        self.topo = lookup_service_brick("aware")
        # self.logger.info(self.topo)
        self.distance_between_nodes = distance
        self.remainSlots = {key: [i for i in range(126)] for key in self.distance_between_nodes}

        self.weight = {key: (self.distance_between_nodes[key] / len(self.remainSlots[key])) for key in
                       self.distance_between_nodes}

        self.monitor = hub.spawn(self._monitor)

        self.graph = nx.DiGraph()

    def _monitor(self):
        i = 0
        while True:
            if i == 5:
                self.creat_graph()
                self.logger.info("{}".format(self.k_shortest_paths(1, 4, k=3)))
                self.logger.info("{}".format(self.k_shortest_paths(4, 1, k=3)))
                self.logger.info("{}".format(self.weight))
                i = 0
            hub.sleep(1)
            i += 1

    def creat_graph(self):
        self._calc_weight()
        self._creat_graph_by_weight()

    def _calc_weight(self):
        try:
            for key in self.distance_between_nodes:
                self.weight[key] = self.distance_between_nodes[key] / len(self.remainSlots[key])
        except ZeroDivisionError:
            # 某条链路上的剩余资源为0的时候，给这条链路设置一个足够大的权重
            self.weight[key] = 65535000

    def _creat_graph_by_weight(self):
        '''
             self.name = "aware"
            self.switches = []  (sw 对象，dp Port)
            self.port_of_switches = {}  # (sw.id)--->port_np
            self.LinkBetweenSwitches = {}  # (src.id,dst.id)----->src_port_no,dst_port_no
            self.monitor = hub.spawn(self._monitor)
            self.HostSwitches = {}  # (sw.dpid,port)---->host_ip,host_mac
        :return:
        '''
        for src_sw in self.topo.switches:
            for dst_sw in self.topo.switches:
                # self.logger.info("src{},dst{}".format(src_sw.dp.id, dst_sw.dp.id))
                if src_sw.dp.id == dst_sw.dp.id:
                    # self.logger.info("src,dst相等")
                    self.graph.add_edge(src_sw.dp.id, dst_sw.dp.id, weight=0)
                    continue
                if (src_sw.dp.id, dst_sw.dp.id) in self.topo.LinkBetweenSwitches:
                    # self.logger.info("源节点是：{} 目标节点是：{}".format(src_sw.dp.id, dst_sw.dp.id))
                    weight = self.weight.get((src_sw.dp.id, dst_sw.dp.id))
                    self.graph.add_edge(src_sw.dp.id, dst_sw.dp.id, weight=weight)

        self.logger.info("{}".format(len(list(self.graph.adjacency()))))

    def k_shortest_paths(self, src, dst, weight='weight', k=1):
        """
            Great K shortest paths of src to dst.
        """
        generator = nx.shortest_simple_paths(self.graph, source=src,
                                             target=dst, weight=weight)
        shortest_paths = []
        try:
            for path in generator:
                if k <= 0:
                    break
                shortest_paths.append(path)
                k -= 1
            return shortest_paths
        except:
            self.logger.debug("No path between %s and %s" % (src, dst))
    @set_ev_cls(ofp_event.EventOFPPacketIn,MAIN_DISPATCHER)
    def packet_in_handler(self,ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(msg.data)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            self.logger.info("ipv4 processing")
            self.shortest_forward(msg,ip_pkt)
        else:
            return

    def shortest_forward(self, msg, ip_pkt):
        ip_src = ip_pkt.src
        ip_dst = ip_pkt.dst
        self.logger.info("源ip地址是{}，目的ip地址是{}".format(ip_src,ip_dst))
        self.logger.info(self.topo.HostSwitches)

