# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager  # 代表 valid ryu application
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet # 用來 decode packet
from ryu.lib.packet import ethernet # 同上
from ryu.lib.packet import ether_types

# 以 MAC address 和 Flow table 紀錄
class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION] # 將 OFP_VERSIONS 指定為 OpenFlow 1.3

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.host = ["00:00:00:00:00:01", "00:00:00:00:00:02", "00:00:00:00:00:03", "00:00:00:00:00:04", "00:00:00:00:00:05", "00:00:00:00:00:06", "00:00:00:00:00:07", "00:00:00:00:00:08", "00:00:00:00:00:09", "00:00:00:00:00:0a", "00:00:00:00:00:0b", "00:00:00:00:00:0c", "00:00:00:00:00:0d", "00:00:00:00:00:0e", "00:00:00:00:00:0f", "00:00:00:00:00:10"]
        self.dpids = ["0000000000000001", "0000000000000002", "0000000000000003", "0000000000000004", "0000000000000005", "0000000000000006", "0000000000000007", "0000000000000008", "0000000000000009", "0000000000000010", "0000000000000011", "0000000000000012", "0000000000000013", "0000000000000014", "0000000000000015"]
        self.leaf = ["0000000000000004", "0000000000000005", "0000000000000007", "0000000000000008", "0000000000000011", "0000000000000012", "0000000000000014", "0000000000000015"]

        for i in self.dpids:
            self.mac_to_port.setdefault(i, {}) # 為了可以對應連接到多個 OpenFlow 交換器，MAC 位址表和每一個交換器之間的識別，就使用 datapath ID 來進行確認。
        for i in self.host:
            if(i == "00:00:00:00:00:01"):
                self.mac_to_port["0000000000000004"][i] = 1
            elif(i == "00:00:00:00:00:02"):
                self.mac_to_port["0000000000000004"][i] = 2
            else:
                self.mac_to_port["0000000000000004"][i] = 3
        for i in self.host:
            if(i == "00:00:00:00:00:03"):
                self.mac_to_port["0000000000000005"][i] = 1
            elif(i == "00:00:00:00:00:04"):
                self.mac_to_port["0000000000000005"][i] = 2
            else:
                self.mac_to_port["0000000000000005"][i] = 3
        for i in self.host:
            if(i == "00:00:00:00:00:05"):
                self.mac_to_port["0000000000000007"][i] = 1
            elif(i == "00:00:00:00:00:06"):
                self.mac_to_port["0000000000000007"][i] = 2
            else:
                self.mac_to_port["0000000000000007"][i] = 3
        for i in self.host:
            if(i == "00:00:00:00:00:07"):
                self.mac_to_port["0000000000000008"][i] = 1
            elif(i == "00:00:00:00:00:08"):
                self.mac_to_port["0000000000000008"][i] = 2
            else:
                self.mac_to_port["0000000000000008"][i] = 3
        for i in self.host:
            if(i == "00:00:00:00:00:09"):
                self.mac_to_port["0000000000000011"][i] = 1
            elif(i == "00:00:00:00:00:0a"):
                self.mac_to_port["0000000000000011"][i] = 2
            else:
                self.mac_to_port["0000000000000011"][i] = 3
        for i in self.host:
            if(i == "00:00:00:00:00:0b"):
                self.mac_to_port["0000000000000012"][i] = 1
            elif(i == "00:00:00:00:00:0c"):
                self.mac_to_port["0000000000000012"][i] = 2
            else:
                self.mac_to_port["0000000000000012"][i] = 3
        for i in self.host:
            if(i == "00:00:00:00:00:0d"):
                self.mac_to_port["0000000000000014"][i] = 1
            elif(i == "00:00:00:00:00:0e"):
                self.mac_to_port["0000000000000014"][i] = 2
            else:
                self.mac_to_port["0000000000000014"][i] = 3
        for i in self.host:
            if(i == "00:00:00:00:00:0f"):
                self.mac_to_port["0000000000000015"][i] = 1
            elif(i == "00:00:00:00:00:10"):
                self.mac_to_port["0000000000000015"][i] = 2
            else:
                self.mac_to_port["0000000000000015"][i] = 3


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER) # 設定 app 功能吧
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath # ev.msg 是用來儲存對應事件的 OpenFlow 訊息類別實體
        ofproto = datapath.ofproto # msg.datapath 這個訊息是用來儲存 OpenFlow 交換器的 ryu.controller.controller.Datapath 類別所對應的實體
        # Datapath 類別是用來處理 OpenFlow 交換器重要的訊息，例如執行與交換器的通訊和觸發接收訊息相關的事件。
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch() # 空的 match 將被產生為了 match 所有的封包。match 表示於 OFPMatch 類別中。
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        # 為了轉送到 Controller 連接埠， OUTPUT action 類別（ OFPActionOutput ）的實例將會被產生。Controller 會被指定為封包的目的地，OFPCML_NO_BUFFER 會被設定為 max_len 以便接下來的封包傳送。
        self.add_flow(datapath, 0, match, actions) # 執行 add_flow() 方法以發送 Flow Mod 訊息。

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)] # Apply Actions 是用來設定那些必須立即執行的 action 所使用
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        # generate flow and add to a particular switch
        datapath.send_msg(mod)

    def check_tenancy(self, mac):
        if mac == "00:00:00:00:00:01" or mac == "00:00:00:00:00:04" or mac == "00:00:00:00:00:07" or mac == "00:00:00:00:00:0a" or mac == "00:00:00:00:00:0d" or mac == "00:00:00:00:00:10":
            return 1
        elif mac == "00:00:00:00:00:02" or mac == "00:00:00:00:00:05" or mac == "00:00:00:00:00:08" or mac == "00:00:00:00:00:0b" or mac == "00:00:00:00:00:0e":
            return 2
        elif mac == "00:00:00:00:00:03" or mac == "00:00:00:00:00:06" or mac == "00:00:00:00:00:09" or mac == "00:00:00:00:00:0c" or mac == "00:00:00:00:00:0f":
            return 3
 
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER) # 設定 app 收 packet, 為了接收處理未知目的地的封包，需要 Packet-In 事件管理。
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        # if ev.msg.msg_len < ev.msg.total_len:
        #     self.logger.debug("packet truncated: only %s of %s bytes",
        #                       ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port'] # 從 OFPPacketIn 類別的 match 得到接收埠（ in_port ）的資訊, 更新 MAC 位址表。

        pkt = packet.Packet(msg.data) # 收到的 packet
        eth = pkt.get_protocols(ethernet.ethernet)[0] # 收到的 packet 的 protocol, eg. ARP, ICMP, IPv4...

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst # 從 header 抽取資料
        src = eth.src # 同上

        dpid = format(datapath.id, "d").zfill(16)

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst == "ff:ff:ff:ff:ff:ff" and dpid in self.leaf:
            # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
            for i in self.mac_to_port[dpid]:
                if self.check_tenancy(src) == self.check_tenancy(i):
                    out_port = self.mac_to_port[dpid][i]
                    actions = [parser.OFPActionOutput(out_port)]
                    data = None
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data

                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                              in_port=in_port, actions=actions, data=data) # 建造 output 的 packet
                    datapath.send_msg(out) # 傳 packet 給 switch
                else:
                    actions = []
                    data = None
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data

                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                              in_port=in_port, actions=actions, data=data) # 建造 output 的 packet
                    datapath.send_msg(out) # 傳 packet 給 switch

        elif self.check_tenancy(src) == self.check_tenancy(dst) or dst == "ff:ff:ff:ff:ff:ff":
            # 目的 MAC 位址若存在于 MAC 位址表，則判斷該連接埠的號碼為輸出。反之若不存在于 MAC 位址表則 OUTPUT action 類別的實體並生成 flooding（ OFPP_FLOOD ）給目的連接埠使用。
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)

            # 在 MAC 位址表中找尋目的 MAC 位址，若是有找到則發送 Packet-Out 訊息，並且轉送封包。
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data) # 建造 output 的 packet
            datapath.send_msg(out) # 傳 packet 給 switch
        else:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            actions = []
            self.add_flow(datapath, 1, match, actions)
            # 在 MAC 位址表中找尋目的 MAC 位址，若是有找到則發送 Packet-Out 訊息，並且轉送封包。
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data) # 建造 output 的 packet
            datapath.send_msg(out) # 傳 packet 給 switch