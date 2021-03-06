from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, arp, ipv4
from ryu.lib.packet.ethernet import ethernet
from ryu.ofproto import ofproto_v1_3


# from ryu.ofproto.ofproto_v1_3_parser import OFPAction


class TestLib(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    eth_type = None

    def __init__(self, *args, **kwargs):
        super(TestLib, self).__init__(*args, **kwargs)
        self.port = {}  # (in_port)--->ip

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
        self.add_flow(datapath)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _handler_packet_in(self, ev):
        msg = ev.msg

        pkt = packet.Packet(msg.data)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if arp_pkt:
            self.logger.info("arp request")
            self.arp_handler(msg, arp_pkt)
        elif ip_pkt:
            TestLib.eth_type = pkt.get_protocol(ethernet).ethertype
            self.logger.info("ip request")
            self.ip_handler(msg, ip_pkt)

    def arp_handler(self, msg, arp_pkt):
        '''

        :param msg:传递给controller 的message
        :param arp_pkt: 解析出来的arp报文
        :return: 无

        检查交换机的主机表，for循环遍历完毕如果找到了就转发，如果没有找到就做flood处理
        '''
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]
        src_ip = arp_pkt.src_ip
        dst_ip = arp_pkt.dst_ip
        self.port.setdefault(in_port, src_ip)
        for port in self.port:
            self.logger.info('{} {}'.format(self.port[port], dst_ip))
            if self.port[port] == dst_ip:
                self.logger.info("no flood")
                actions = [parser.OFPActionOutput(port=port)]
                packet_out_message = self._build_packet_out(datapath, actions, msg.data)
                datapath.send_msg(packet_out_message)
                break
        else:
            self.logger.info("flood,{}".format(self.port))
            self.flood(msg)

    def _build_packet_out(self, datapath, actions, data):
        '''

        :param datapath:这个packout消息要发送到的交换机
        :param actions: 动作必须是可迭代的
        :param data: packetout消息要封装的数据
        :return: 无
        '''
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # actions = [parser.OFPActionOutput(port)]
        packet_out_msg = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                             in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
        return packet_out_msg

    def flood(self, msg):
        '''

        :param msg:对arp请求做泛洪处理
        :return: None
        '''
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        message = self._build_packet_out(datapath, actions, msg.data)
        datapath.send_msg(message)

    def add_flow(self, datapath):
        '''

        :param datapath:添加miss-flow流表的函数
        :return: None
        '''
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(port=ofproto.OFPP_CONTROLLER, max_len=ofproto.OFPCML_MAX)]
        self.send_flow_mod(datapath, actions, pri=0, match=parser.OFPMatch())

    def send_flow_mod(self, datapath, actions, pri, match, idle_time=0, hard_time=0):
        '''
        下发正常流表的函数
        :param datapath: 要将流表发送到的交换机
        :param actions: 动作
        :param pri: 优先级
        :param match: 匹配域，注意必须写上eth_type
        :param idle_time: 空闲失效时间
        :param hard_time: 没有合适的中文翻译。。。。
        :return: None
        '''
        # self.logger.info("anzhuangliubiao")
        # if pri == 1:
        #     self.logger.info("addliubiao")
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        ins = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        message = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_ADD, priority=pri,
                                    match=match, idle_timeout=idle_time, hard_timeout=hard_time, instructions=ins)

        datapath.send_msg(message)

    def ip_handler(self, msg, ip_pkt):
        '''

        :param msg:
        :param ip_pkt:
        :return:
        转发ip报文。注意下发流表后还要处理发送到控制器的报文，用packetout消息转发出去
        '''
        datapath = msg.datapath
        # ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        self.logger.info(self.port)
        for port in self.port:
            if self.port[port] == dst_ip:
                dst_port = port
                break

        for port in self.port:
            if self.port[port] == src_ip:
                src_port = port
                break
        try:
            self.logger.info("{} {}".format(src_port, dst_port))
            match = parser.OFPMatch(in_port=src_port, eth_type=TestLib.eth_type, ipv4_src=src_ip, ipv4_dst=dst_ip)
            actions = [parser.OFPActionOutput(port=dst_port)]
            self.send_flow_mod(datapath, actions=actions, pri=1, match=match, idle_time=60, hard_time=0)

            # 下发流表之后还要处理这一个数据包，从端口转发出去就行了
            actions = [parser.OFPActionOutput(port=datapath.ofproto.OFPP_TABLE)]
            packet_out_message = self._build_packet_out(datapath, actions=actions, data=msg.data)
            datapath.send_msg(packet_out_message)
        except Exception as e:
            print(e)
