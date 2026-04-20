from pox.core import core
import pox.lib.packet as pkt
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import EthAddr

log = core.getLogger()
arp_table = {}
known_hosts = set()

def _handle_PacketIn(event):
    packet = event.parsed

    if packet.type == packet.ARP_TYPE:
        arp_pkt = packet.payload

        # — 1. Detect if this is a NEW host (re-enter learning phase) ——————
        if arp_pkt.protosrc not in arp_table:
            log.info("=" * 60)
            log.info("[NEW HOST DETECTED] Unknown host joined the network!")
            log.info("    ∟ IP=%s MAC=%s on port %s",
                     arp_pkt.protosrc, arp_pkt.hwsrc, event.port)
            log.info("[LEARNING PHASE] Controller re-entering learning phase...")
            log.info("=" * 60)

        # — 2. Intercept notice ——————————————————————————————————————————
        op_name = "REQUEST" if arp_pkt.opcode == pkt.arp.REQUEST else "REPLY"
        log.info("=" * 60)
        log.info("[INTERCEPT] ARP %s packet intercepted on port %s",
                 op_name, event.port)
        log.info("    ├─ From  : IP=%s MAC=%s", arp_pkt.protosrc, arp_pkt.hwsrc)
        log.info("    └─ To    : IP=%s", arp_pkt.protodst)

        # — 3. Learn the sender ——————————————————————————————————————————
        if arp_pkt.protosrc not in arp_table:
            log.info("[LEARN] New entry added to ARP table:")
        else:
            log.info("[LEARN] ARP table entry refreshed:")

        arp_table[arp_pkt.protosrc] = arp_pkt.hwsrc
        known_hosts.add(str(arp_pkt.protosrc))

        # — 4. Print current ARP table ——————————————————————————————————
        log.info("[ARP TABLE] Current snapshot (%d entries):", len(arp_table))
        for ip, mac in arp_table.items():
            log.info("    └─ %s -> %s", ip, mac)
        log.info("[KNOWN HOSTS] Total hosts learned: %d -> %s",
                 len(known_hosts), ", ".join(sorted(known_hosts)))

        # — 5. Lookup: can we proxy? ————————————————————————————————————
        if arp_pkt.opcode == pkt.arp.REQUEST:
            log.info("[LOOKUP] Searching ARP table for destination IP: %s",
                     arp_pkt.protodst)

            if arp_pkt.protodst in arp_table:
                resolved_mac = arp_table[arp_pkt.protodst]
                log.info("[LOOKUP] HIT! %s is at %s - proxy reply will be sent.",
                         arp_pkt.protodst, resolved_mac)

                # — 6. Build ARP reply ——————————————————————————————————
                log.info("[BUILD] Constructing proxy ARP REPLY:")
                res = pkt.arp()
                res.hwsrc = resolved_mac
                res.hwdst = arp_pkt.hwsrc
                res.opcode = pkt.arp.REPLY
                res.protosrc = arp_pkt.protodst
                res.protodst = arp_pkt.protosrc

                log.info("    ├─ ARP Reply : opcode=REPLY")
                log.info("    ├─ hwsrc     : %s (MAC of %s)", res.hwsrc, arp_pkt.protodst)
                log.info("    ├─ hwdst     : %s (MAC of %s)", res.hwdst, arp_pkt.protosrc)
                log.info("    ├─ protosrc  : %s (answering as this IP)", res.protosrc)
                log.info("    └─ protodst  : %s (reply going to this IP)", res.protodst)

                # — 7. Wrap in Ethernet frame ———————————————————————————
                eth = pkt.ethernet()
                eth.type = pkt.ethernet.ARP_TYPE
                eth.src = resolved_mac
                eth.dst = arp_pkt.hwsrc
                eth.set_payload(res)

                log.info("[BUILD] Ethernet frame wrapping:")
                log.info("    ├─ eth.src : %s", eth.src)
                log.info("    └─ eth.dst : %s", eth.dst)

                # — 8. Send out —————————————————————————————————————————
                msg = of.ofp_packet_out()
                msg.data = eth.pack()
                msg.actions.append(of.ofp_action_output(port=event.port))
                event.connection.send(msg)

                log.info("[SEND] Proxy ARP reply dispatched on port %s", event.port)
                log.info("    ∟ Flow: %s (%s) -> %s (%s)",
                         arp_pkt.protodst, resolved_mac,
                         arp_pkt.protosrc, arp_pkt.hwsrc)

                # — 9. Validation summary ———————————————————————————————
                log.info("[VALIDATE] Response integrity check:")
                ok_op = res.opcode == pkt.arp.REPLY
                ok_src = res.hwsrc == resolved_mac
                ok_dst = res.hwdst == arp_pkt.hwsrc
                ok_ipsrc = res.protosrc == arp_pkt.protodst
                ok_ipdst = res.protodst == arp_pkt.protosrc

                log.info("    ├─ opcode  is REPLY       : %s", "✅ PASS" if ok_op else "❌ FAIL")
                log.info("    ├─ hwsrc   matches target : %s", "✅ PASS" if ok_src else "❌ FAIL")
                log.info("    ├─ hwdst   matches sender : %s", "✅ PASS" if ok_dst else "❌ FAIL")
                log.info("    ├─ protosrc = target IP   : %s", "✅ PASS" if ok_ipsrc else "❌ FAIL")
                log.info("    └─ protodst = sender IP   : %s", "✅ PASS" if ok_ipdst else "❌ FAIL")

                if all([ok_op, ok_src, ok_dst, ok_ipsrc, ok_ipdst]):
                    log.info("[VALIDATE] ✅ ALL CHECKS PASSED - reply is valid.")
                else:
                    log.warning("[VALIDATE] ❌ ONE OR MORE CHECKS FAILED!")

            else:
                log.info("[LOOKUP] MISS - %s not in ARP table yet. "
                         "Packet will be flooded normally.", arp_pkt.protodst)

        log.info("=" * 60)

def launch():
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    log.info("ARP Proxy Controller is active - waiting for hosts...")
