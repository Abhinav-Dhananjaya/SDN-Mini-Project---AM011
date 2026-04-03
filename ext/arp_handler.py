from pox.core import core
import pox.lib.packet as pkt
import pox.openflow.libopenflow_01 as of 
from pox.lib.addresses import EthAddr

log = core.getLogger()
arp_table = {}

def _handle_PacketIn (event):
    packet = event.parsed
    if packet.type == packet.ARP_TYPE:
        arp_pkt = packet.payload
        arp_table[arp_pkt.protosrc] = arp_pkt.hwsrc
        log.info("Learned: %s at %s", arp_pkt.protosrc, arp_pkt.hwsrc)

        if arp_pkt.protodst in arp_table:
            log.info("Proxying ARP reply for %s", arp_pkt.protodst)
            
            res = pkt.arp()
            res.hwsrc = arp_table[arp_pkt.protodst]
            res.hwdst = arp_pkt.hwsrc
            res.opcode = pkt.arp.REPLY
            res.protosrc = arp_pkt.protodst
            res.protodst = arp_pkt.protosrc

            eth = pkt.ethernet()
            eth.type = pkt.ethernet.ARP_TYPE
            eth.src = arp_table[arp_pkt.protodst]
            eth.dst = arp_pkt.hwsrc
            eth.set_payload(res)

            msg = of.ofp_packet_out()
            msg.data = eth.pack()
            msg.actions.append(of.ofp_action_output(port = event.port))
            event.connection.send(msg)

def launch ():
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    log.info("ARP Proxy Controller is active.")
