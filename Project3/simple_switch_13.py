from pprint import pp, pprint
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


class SimpleSwitch13(app_manager.RyuApp):
    '''
    1. 初次建立連接時, 新增table-miss flow entry, 作為前置作業
    2. 使用Flooding機制得知host MAC address 對應的port, 並存入mac_to_port table中
    3. flow流經switch時有來源位址(eth_src)和目的位址(eth_dst)和來源port(in_port), 新增至flow entry
    '''

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    ### 就是去繼承已經寫好的(ryu.base.app_manager.RyuApp), 然後 MAC 位址也已經被定義了。
    def __init__(self, *args, **kwargs):
        '''為了下面的 switch 自學習, 先初始化一個字典, 以儲存 mac 地址到 port 的關係'''
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    # 對於 Ryu 來說, 接受到任何一個 OpenFlow 訊息即會產生一個相對應的事件。而 Ryu 應用程式則是必須實作事件管理以處理相對應發生的事件。
    # 事件管理（ Event Handler ）是一個擁有事件物件（ Event Object ）做為參數, 並且使用``ryu.controller.handler.set_ev_cls`` 修飾（ Decorator ）的函數。
    # set_ev_cls 則指定事件類別得以接受訊息和交換器狀態作為參數。
    # 件類別名稱的規則為 ryu.controller.ofp_event.EventOFP + <OpenFlow訊息名稱>

    # OpenFlow 交換器的握手協議完成之後, 新增 Table-miss Flow Entry 到 Flow table 中為接收 Packet-In 訊息  做準備。
    # 具體來說, 接收到 Switch features（ Features reply ）訊息後就會新增 Table-miss Flow Entry。
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        '''
        該程式碼區塊主要負責監控關於switch的各種狀態, 包含初次建立連接時的握手訊息交換, 目前該switch的連線狀態（連接還是斷線）等
        OpenFlow 交換器的握手協議完成之後, 新增 Table-miss Flow Entry 到 Flow table 中為接收 Packet-In 訊息做準備。
        Table-miss Flow Entry 的優先權為 0 即最低的優先權, 而且此 Entry 可以 match 所有的封包。 這個 Entry 的 Instruction 通常指定為 output action , 並且輸出的連接埠將指向 Controller。
        '''
        datapath = ev.msg.datapath
        # 是用來儲存對應事件的 OpenFlow 訊息類別實體。 在這個例子中則是 ryu.ofproto.ofproto_v1_3_parser.OFPSwitchFeatures 。
        # 這個訊息是用來儲存 OpenFlow 交換器的 ryu.controller.controller.Datapath 類別所對應的實體。
        # Datapath 類別是用來處理 OpenFlow 交換器重要的訊息, 例如執行與交換器的通訊和觸發接收訊息相關的事件。
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table-miss Flow Entry 的優先權為 0 即最低的優先權, 而且此 Entry 可以 match 所有的封包。 這個 Entry 的 Instruction 通常指定為 output action , 並且輸出的連接埠將指向 Controller。
        # 因此當封包沒有 match 任何一個普通 Flow Entry 時, 則觸發 Packet-In。
        match = parser.OFPMatch()
        # Controller 會被指定為封包的目的地, OFPCML_NO_BUFFER 會被設定為 max_len 以便接下來的封包傳送。
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        # 最後將優先權設定為 0（ 最低優先權 ）, 然後執行 add_flow() 方法以發送 Flow Mod 訊息。
        # pprint("==========================")
        # pprint("| Table-miss Flow Entry |")
        # pprint("==========================")
        # pprint(f"datapath => {datapath}")
        # pprint(f"priority => {0}")
        # pprint(f"match => {match}")
        # pprint(f"actions => {actions}")
        # pprint("--------------------------")
        # pprint("..")
        # pprint("..")
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ''' '''
        # 對於 Flow Entry 來說, 設定 match 條件以分辨目標封包、設定 instruction 以處理封包以及 Entry 的優先權和有效時間。
        # 對於交換器的的實作, Apply Actions 是用來設定那些必須立即執行的 action 所使用。
        # 最後透過 Flow Mod 訊息將 Flow Entry 新增到 Flow table 中。
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=inst,
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=priority, match=match, instructions=inst
            )
        datapath.send_msg(mod)

    # 為了接收處理未知目的地的封包, 需要 Packet-In 事件管理。
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        '''
        在Ryu 中當有未知的封包流經switch時, 便會觸發PacketIn 事件, 也就是此段程式區塊所做的事情

        目的 MAC 位址若存在于 MAC 位址表, 則判斷該連接埠的號碼為輸出。反之若不存在于 MAC 位址表則 OUTPUT action 類別的實體並生成 flooding（ OFPP_FLOOD）給目的連接埠使用
        對於 Flow Entry 來說, 設定 match 條件以分辨目標封包、設定 instruction 以處理封包以及 Entry 的優先權和有效時間。
        對於交換器的的實作, Apply Actions 是用來設定那些必須立即執行的 action 所使用。
        最後透過 Flow Mod 訊息將 Flow Entry 新增到 Flow table 中。
        '''
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug(
                "packet truncated: only %s of %s bytes",
                ev.msg.msg_len,
                ev.msg.total_len,
            )
        # 從 openflow 把版本等資訊給幹出來
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # 以下 imp switch logic(實作 switch 自學習)

        # 從 OFPPacketIn 類別的 match 得到接收埠（ in_port ）的資訊。 目的 MAC 位址和來源 MAC 位址使用 Ryu 的封包函式庫, 從接收到封包的 Ethernet header 取得。
        # 藉由得知目的 MAC 位址和來源 Mac 位址, 更新 MAC 位址表。
        # 為了可以對應連接到多個 OpenFlow 交換器, MAC 位址表和每一個交換器之間的識別, 就使用 datapath ID 來進行確認。
        in_port = msg.match['in_port']

        # 存儲資訊, 並依據協定取得以太網數據包
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            # 把發送到 33:33:00:00:00:XX 的 lldp 協議封包給無視調
            return
        # 從數據包取得來源及目的
        dst = eth.dst
        src = eth.src

        """
        由於每個 switch 都有獨立的轉發表, 所以先拿著 datapath id
        所以控制器得知道每一個控制器在哪裡轉發
        1. 我們需要知道唯一識別 id 來辨識 openflow switch 並存起來
        2. 解析和分析收到的封包
        3. 學會 mac 地址以避免下一次(每一次) flood
        4. 如果已經學到 mac 地址了, 那提取目的主機 mac 地址。如果沒有的話, 就 flood
        5. 建立對應動作
          a. install a flow and msg
          b. send a packet out
        """

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        # 將 switch<dpid> 寫入 mac_to_port table 中
        pprint("--------------------------")
        pprint(f"Add switch_{dpid} to mac_to_port table")
        pprint("--------------------------")

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # 觸發 packet In 事件
        pprint("==========================")
        pprint("| Packet in Event |")
        pprint("==========================")
        pprint(f"dpid => {dpid}")
        pprint(f"src => {src}")
        pprint(f"dst => {dst}")
        pprint(f"in_port => {in_port}")
        pprint("--------------------------")
        pprint("..")
        pprint("..")

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        # 列印 mac_to_port Table|
        pprint("==========================")
        pprint("| mac_to_port Table|")
        pprint("==========================")
        pprint(self.mac_to_port)
        pprint("--------------------------")
        pprint("..")
        pprint("..")

        # 目的 MAC 位址若存在于 MAC 位址表, 則判斷該連接埠的號碼為輸出。
        # 反之若不存在于 MAC 位址表則 OUTPUT action 類別的實體並生成 flooding（ OFPP_FLOOD ）給目的連接埠使用。
        # 若是找到了目的 MAC 位址, 則在交換器的 Flow table 中新增。
        # Table-miss Flow Entry 包含 match 和 action, 並透過 add_flow() 來新增。

        # 不同於平常的 Table-miss Flow Entry , 這次將加上設定 match 條件。 本次交換器實作中, 接收埠（ in_port ）和目的 MAC 位址（ eth_dst ）已指定。例如, 接收到來自連接埠 1 的封包就傳送到 host B。
        # 在這邊指定 Flow Entry 優先權為 1, 而優先權的值越大, 表示有更高的優先權。因此, 這邊新增的 Flow Entry 將會先於 Table-miss Flow Entry 而被執行。
        # 上述的內容包含 action 整理如下, 這些 Entry 會被新增至 Flow Entry：
        # 連接埠 1 接收到的封包, 若是要轉送至 host B（ 目的 MAC 位址 B) 的封包則轉送至連接埠 4。
        if dst in self.mac_to_port[dpid]:
            # 如果目的地地址已經在字典了, 那就直接讀。
            out_port = self.mac_to_port[dpid][dst]
        else:
            # 如果沒有, 就做 flood
            # 他會送一個封包到 ff:ff:ff:ff:ff:ff, 以去找到目的 mac address
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        # 如果他不是 flood,就下發一個優先級為第一的 flow 到 flow table
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                # pprint("==========================")
                # pprint("| Add Flow Entry |")
                # pprint("==========================")
                # pprint(f"datapath => {datapath}")
                # pprint(f"priority => {1}")
                # pprint(f"match => {match}")
                # pprint(f"actions => {actions}")
                # pprint(f"bufferId => {msg.buffer_id}")
                # pprint("--------------------------")
                # pprint("..")
                # pprint("..")
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                # pprint("==========================")
                # pprint("| Add Flow Entry |")
                # pprint("==========================")
                # pprint(f"datapath => {datapath}")
                # pprint(f"priority => {1}")
                # pprint(f"match => {match}")
                # pprint(f"actions => {actions}")
                # pprint("--------------------------")
                # pprint("..")
                # pprint("..")
                self.add_flow(datapath, 1, match, actions)

        # 在 MAC 位址表中找尋目的 MAC 位址, 若是有找到則發送 Packet-Out 訊息, 並且轉送封包。
        # 交換器的實作時, 在 Packet-In 訊息中指定 buffer_id。若是 Packet-In 訊息中 buffer_id 被設定為無效時。Packet-In 的封包必須指定 data 以便傳送。
        # buffer_id 是因為有些 openswitch 可以存儲 data 在 queue, 所以如果 switch 可以做的話, 它就只送 id 出去, 然後 switch 再把資料送到目的, 以節省整體流量
        # 倘若沒有, 就由 controller 自己去送
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        # 最後給他送出去
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)


class SimpleMonitor13(SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.data_paths = {}
        self.monitor_thread = hub.spawn(self.monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        data_path = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if data_path.id not in self.data_paths:
                self.logger.debug('register data path: %016x', data_path.id)
                self.data_paths[data_path.id] = data_path
        elif ev.state == DEAD_DISPATCHER:
            if data_path.id in self.data_paths:
                self.logger.debug('unregister data path: %016x', data_path.id)
                del self.data_paths[data_path.id]

    def monitor(self):
        """
        Send state request every 5 seconds
        :return: None
        """
        while True:
            for data_path in self.data_paths.values():
                self.request_states(data_path)
            hub.sleep(5)

    @staticmethod
    def request_states(data_path):
        """
        Send all port state request to the switch
        :param data_path: the target switch
        :return: None
        """
        of_proto = data_path.ofproto
        parser = data_path.ofproto_parser

        req = parser.OFPPortStatsRequest(data_path, 0, of_proto.OFPP_ANY)
        data_path.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info('****************************')
        self.logger.info('Switch ID: %s', str(ev.msg.datapath.id).strip())
        self.logger.info(' Port No  Tx-Bytes  Rx-Bytes')
        self.logger.info('--------  --------  --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            self.logger.info('%8x  %8d  %8d',
                             stat.port_no, stat.rx_bytes, stat.tx_bytes)
        self.logger.info('')
        self.logger.info('Mac Address Table    Port No')
        self.logger.info('----------------------------')
        for mac, port in self.mac_to_port[format(ev.msg.datapath.id, "d").zfill(16)].items():
            self.logger.info('%s%11d', mac, port)
        self.logger.info('****************************\n')
