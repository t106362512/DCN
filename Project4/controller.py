from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, lldp
from pathlib import Path
import json

CONFIG_FILE_PATH="utils/config.json"

class SimpleSwitch13(app_manager.RyuApp):
    '''
    1. 初次建立連接時, 新增table-miss flow entry, 作為前置作業
    2. 使用Flooding機制得知host MAC address 對應的port, 並存入mac_to_port table中
    3. flow流經switch時有來源位址(eth_src)和目的位址(eth_dst)和來源port(in_port), 新增至flow entry
    '''

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)

        # data path ID -> data path
        self.data_paths = {}

        # data path ID -> list of available ports
        self.data_path_to_ports = {}

        # Learning bridge for background traffic
        self.mac_to_port = {}

        # Tenancy
        # group ID -> MAC addresses
        self.groups = {}
        # MAC address -> belonged group
        self.mac_to_group = {}

        # Leaf and host connection
        # MAC address -> connected leaf ID and port
        self.mac_to_leaf = {}
        # Leaf ID -> port number -> MAC address
        self.leaf_to_macs = {}

        conf = json.loads(Path(CONFIG_FILE_PATH).read_bytes())
        self.groups = conf['groups']
        for key, macs in conf['groups'].items():
            for mac in macs:
                self.mac_to_group[mac] = key
        self.mac_to_leaf = conf['links']
        for mac, switch in conf['links'].items():
            if switch['switch_id'] in self.leaf_to_macs:
                self.leaf_to_macs[switch['switch_id']][switch['port']] = mac
            else:
                self.leaf_to_macs[switch['switch_id']] = {switch['port']: mac}

    # 綁定事件
    # The switch responds with a features reply message to a features request.
    # 交換機以功能回复消息響應功能請求。
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Handle initial installation after handshake between switch and controller
        :param ev: received event
        :return: None
        """
        # ev.msg 是用來儲存對應事件的 OpenFlow 訊息類別實體
        # msg.datapath 這個訊息是用來儲存 OpenFlow 交換器的 ryu.controller.controller.Datapath 類別所對應的實體
        # Datapath 類別是用來處理 OpenFlow 交換器重要的訊息，例如執行與交換器的通訊和觸發接收訊息相關的事件。
        data_path = ev.msg.datapath
        data_path_id = str(data_path.id)
        of_proto = data_path.ofproto
        parser = data_path.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.

        # 空的 match 將被產生為了 match 所有的封包。match 表示於 OFPMatch 類別中。
        match = parser.OFPMatch() 

        # 為了轉送到 Controller 連接埠， OUTPUT action 類別（ OFPActionOutput ）的實例將會被產生。Controller 會被指定為封包的目的地，OFPCML_NO_BUFFER 會被設定為 max_len 以便接下來的封包傳送。
        actions = [parser.OFPActionOutput(of_proto.OFPP_CONTROLLER, of_proto.OFPCML_NO_BUFFER)]

        # 執行 add_flow() 方法以發送 Flow Mod 訊息。
        self.add_flow(data_path, 0, match, actions)

        self.data_paths[data_path_id] = data_path
        self.data_path_to_ports[data_path_id] = []
        self.request_ports(data_path)

    @staticmethod
    def add_flow(data_path, priority, match, actions, buffer_id=None):
        """
        Add flow entry to the target switch
        :param data_path: target switch
        :param priority: priority of the flow entry
        :param match: match requirement
        :param actions: applied actions
        :param buffer_id: buffer ID of the frame
        :return: None
        # 對於 Flow Entry 來說, 設定 match 條件以分辨目標封包、設定 instruction 以處理封包以及 Entry 的優先權和有效時間。
        # 對於交換器的的實作, Apply Actions 是用來設定那些必須立即執行的 action 所使用。
        # 最後透過 Flow Mod 訊息將 Flow Entry 新增到 Flow table 中。
        """
        of_proto = data_path.ofproto
        parser = data_path.ofproto_parser

        # Apply Actions 是用來設定那些必須立即執行的 action 所使用
        inst = [parser.OFPInstructionActions(of_proto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=data_path, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=data_path, priority=priority,
                                    match=match, instructions=inst)
        # 生成 flow 並加到特定的 switch
        data_path.send_msg(mod)

    # 保持通信已啟動啊
    @staticmethod
    def request_ports(data_path):
        """
        Send port description request to the switch
        :param data_path: the target switch
        :return: None
        """
        parser = data_path.ofproto_parser

        req = parser.OFPPortDescStatsRequest(data_path, 0)
        data_path.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_reply_handler(self, ev):
        """
        Collect all ports belong to the data path
        :param ev: received event
        :return: None
        """
        msg = ev.msg
        body = msg.body
        data_path = msg.datapath
        data_path_id = str(data_path.id)
        of_proto = data_path.ofproto

        for stat in body:
            port_no = int(stat.port_no)
            hw_addr = str(stat.hw_addr)
            if stat.port_no < of_proto.OFPP_MAX:
                self.data_path_to_ports[data_path_id].append({'port_no': port_no,
                                                              'hw_addr': hw_addr})

    # 設定 app 收 packet, 為了接收處理未知目的地的封包，需要 Packet-In 事件管理。
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Packet-in handler
        :param ev: received event
        :return: None

        在Ryu 中當有未知的封包流經switch時, 便會觸發PacketIn 事件, 也就是此段程式區塊所做的事情
        目的 MAC 位址若存在于 MAC 位址表, 則判斷該連接埠的號碼為輸出。反之若不存在于 MAC 位址表則 OUTPUT action 類別的實體並生成 flooding(OFPP_FLOOD)給目的連接埠使用
        對於 Flow Entry 來說, 設定 match 條件以分辨目標封包、設定 instruction 以處理封包以及 Entry 的優先權和有效時間。
        對於交換器的的實作, Apply Actions 是用來設定那些必須立即執行的 action 所使用。
        最後透過 Flow Mod 訊息將 Flow Entry 新增到 Flow table 中。
        """
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        data_path = msg.datapath
        of_proto = data_path.ofproto
        parser = data_path.ofproto_parser

        # 從 OFPPacketIn 類別的 match 得到接收埠（ in_port ）的資訊, 更新 MAC 位址表。
        in_port = int(msg.match['in_port'])

        pkt = packet.Packet(msg.data)   # 收到的 packet

        # 收到的 packet 的 protocol, eg. ARP, ICMP, IPv4...
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            # 把發送到 33:33:00:00:00:XX 的 lldp 協議封包給無視
            return
        else:
            self.normal_pkt_handler(data_path, msg, of_proto, parser, in_port, eth)

    def normal_pkt_handler(self, data_path, msg, of_proto, parser, in_port, eth):
        """
        Normal packet handler
        :param data_path: switch that sent the packet-in
        :param msg: message in the received event
        :param of_proto: OpenFlow protocol used on the data path
        :param parser: OpenFlow parser
        :param in_port: port which received the frame
        :param eth: Ethernet frame
        :return: None

        由於每個 switch 都有獨立的轉發表, 所以先拿著 datapath id
        所以控制器得知道每一個控制器在哪裡轉發
        1. 我們需要知道唯一識別 id 來辨識 openflow switch 並存起來
        2. 解析和分析收到的封包
        3. 確認是否為同組租戶
        4. 學會 mac 地址以避免下一次(每一次) flood
        5. 如果已經學到 mac 地址了, 那提取目的主機 mac 地址。如果沒有的話, 就 flood
        6. 建立對應動作
          a. install a flow and msg
          b. send a packet out        
        """

        # 從 header 抽取資料
        dst = eth.dst
        src = eth.src

        data_path_id = str(data_path.id)

        output_ports = []
        if src in self.mac_to_group and dst in self.mac_to_group:
            if self.mac_to_group[src] != self.mac_to_group[dst]:
                # Src and Dst belong to different groups
                # 這裡的 value 會確認是否為同個租戶, 若不是就不幫送資料
                return

            # 目的 MAC 位址若存在于 MAC 位址表，則判斷該連接埠的號碼為輸出。反之若不存在于 MAC 位址表則 OUTPUT action 類別的實體並生成 flooding（ OFPP_FLOOD ）給目的連接埠使用。
            if dst in self.mac_to_port[data_path_id]:
                output_ports += [self.mac_to_port[data_path_id][dst]]
            else:
                output_ports += [of_proto.OFPP_FLOOD]
        elif src in self.mac_to_group:
            # Unknown/broadcast destination
            output_ports += self.find_suitable_ports(src=src,
                                                     dst=dst,
                                                     data_path_id=data_path_id,
                                                     in_port=in_port,
                                                     of_proto=of_proto)
        else:
            # Background traffic
            output_ports += self.handle_background_traffic(src=src,
                                                           dst=dst,
                                                           data_path_id=data_path_id,
                                                           in_port=in_port,
                                                           of_proto=of_proto)

        if len(output_ports) == 0:
            # Should not forward the frame
            return

        actions = [parser.OFPActionOutput(out_port) for out_port in output_ports]

        # install a flow to avoid packet_in next time
        if output_ports[0] != of_proto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != of_proto.OFP_NO_BUFFER:
                self.add_flow(data_path, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(data_path, 1, match, actions)

        # 在 MAC 位址表中找尋目的 MAC 位址，若是有找到則發送 Packet-Out 訊息，並且轉送封包。
        data = None
        if msg.buffer_id == of_proto.OFP_NO_BUFFER:
            data = msg.data

        # 建造 output 的 packet
        out = parser.OFPPacketOut(datapath=data_path, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)

        # 傳 packet 給 switch
        data_path.send_msg(out)

    def find_suitable_ports(self, src, dst, data_path_id, in_port, of_proto):
        """
        Find suitable ports that do not belong
        :param src: source MAC address
        :param dst: destination MAC address
        :param data_path_id: target data path ID
        :param in_port: port which received the frame
        :param of_proto: OpenFLow protocol used on the data path
        :return: ports
        """
        # Unknown/broadcast destination
        ports = []
        if dst == 'ff:ff:ff:ff:ff:ff':
            # Broadcast
            for port in self.data_path_to_ports[data_path_id]:
                if port['port_no'] == in_port:
                    # Do not send frame to ingress port
                    continue
                if data_path_id in self.leaf_to_macs:
                    if port['port_no'] not in self.leaf_to_macs[data_path_id] or self.mac_to_group[self.leaf_to_macs[data_path_id][port['port_no']]] == self.mac_to_group[src]:
                        ports.append(port['port_no'])
                else:
                    ports.append(port['port_no'])
        else:
            # Unknown destination
            ports += self.handle_background_traffic(src=src,
                                                    dst=dst,
                                                    data_path_id=data_path_id,
                                                    in_port=in_port,
                                                    of_proto=of_proto)

        return ports

    def handle_background_traffic(self, src, dst, data_path_id, in_port, of_proto):
        """
        Handle background traffic
        :param src: source MAC address
        :param dst: destination MAC address
        :param data_path_id: target data path ID
        :param in_port: port which received the frame
        :param of_proto: OpenFLow protocol used on the data path
        :return: ports
        """
        # Background traffic
        ports = []
        # 為了可以對應連接到多個 OpenFlow 交換器，MAC 位址表和每一個交換器之間的識別，就使用 datapath ID 來進行確認。
        self.mac_to_port.setdefault(data_path_id, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[data_path_id][src] = in_port

        if dst in self.mac_to_port[data_path_id]:
            ports.append(self.mac_to_port[data_path_id][dst])
        else:
            ports.append(of_proto.OFPP_FLOOD)

        return ports
