
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import AsyncSniffer, sendp
from os import urandom
from nodpi import config
import asyncio
from random import randint

ports = []
packets = {}
ttl = {}

async def send_packet(data, to_port):
    await asyncio.sleep(0.2)
    
    if not packets.get(to_port) or not ttl.get(to_port):
        return False

    if ttl.get(to_port):
        if ttl[to_port] > 64:
            distance=128-ttl[to_port]
        else:
            distance=64-ttl[to_port]
    else:
        return False


    packets[to_port]["p"].payload.chksum=None
    packets[to_port]["p"].payload.len=None

    packets[to_port]["p"].payload.payload.chksum= None
    packets[to_port]["p"].payload.payload.flags = packets[to_port]["p"].payload.payload.flags.value | 8
    packets[to_port]["p"].payload.payload.seq = packets[to_port]["ack"]
    packets[to_port]["p"].payload.payload.payload = Raw(data)

    

    if 3 in config["fake_mode"]:
        packets[to_port]["p"].payload.payload.dataofs = packets[to_port]["p"].payload.payload.dataofs + 5

    if 1 in config["fake_mode"]:
        packets[to_port]["p"].payload.ttl=distance-3

    if 2 in config["fake_mode"]:
        packets[to_port]["p"].payload.payload.seq += 2000



    sendp(packets[to_port]["p"].build(), verbose=False)

    ports.remove(to_port)
    del packets[to_port]

    if config["debug"]:
        print("Фейковый пакет отправлен")

    return True

def listen_interface(p):

        ip = p.payload
        tcp = ip.payload


        if ip.name != "IP":
            return

        if tcp.name != "TCP":
            return
        
        if tcp.sport in ports:
            packets[tcp.sport] = {}
            packets[tcp.sport]["p"] = p
            packets[tcp.sport]["ack"] = tcp.seq + len(tcp.payload)
            
        
        ttl[tcp.dport] = ip.ttl
            
        del tcp
        del ip
