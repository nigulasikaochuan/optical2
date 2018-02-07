def add_miss_flow(datapath):
        '''

        :param datapath:添加miss-flow流表的函数
        :return: None
        '''
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(port=ofproto.OFPP_CONTROLLER, max_len=ofproto.OFPCML_MAX)]
        send_flow_mod(datapath, actions, pri=0, match=parser.OFPMatch())



def send_flow_mod(datapath, actions, pri, match, idle_time=0, hard_time=0):
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