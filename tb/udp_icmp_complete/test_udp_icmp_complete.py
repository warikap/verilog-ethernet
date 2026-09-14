#!/usr/bin/env python
"""

Copyright (c) 2026 Marcin Zaremba <marcin.zaremba@fuw.edu.pl>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

"""

import itertools
import logging
import os

from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, ICMP, UDP
from scapy.utils import mac2str, atol

import cocotb_test.simulator

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge


LOCAL_MAC = '02:00:00:00:00:00'
LOCAL_IP = '192.168.1.1'
GATEWAY_IP = '192.168.1.1'
SUBNET_MASK = '255.255.255.0'

PEER_MAC = '5a:51:52:53:54:55'
PEER_IP = '192.168.1.100'

# small on purpose: arp_cache.v clears 2**ARP_CACHE_ADDR_WIDTH entries
# (one per cycle) after reset before it accepts writes, and this test
# only ever needs to hold a single entry
ARP_CACHE_ADDR_WIDTH = 4


class TB:
    """
    Manual (non cocotbext-axi) driver, for the same reason as
    tb/ip_complete_icmp/test_ip_complete_icmp.py: this DUT chains the same
    deep ip_complete_icmp hierarchy (eth_arb_mux -> arbiter ->
    priority_encoder, ip.v, arp.v, arp_cache.v) plus udp.v/udp_checksum_gen.v
    on top, and cocotbext-axi's AxiStreamSource/Sink sample tready/tvalid
    immediately on construction, before such a deep combinational network
    has settled out of its power-on X state.
    """

    def __init__(self, dut):
        self.dut = dut

        self.log = logging.getLogger("cocotb.tb")
        self.log.setLevel(logging.DEBUG)

        cocotb.start_soon(Clock(dut.clk, 8, units="ns").start())

    async def reset(self):
        dut = self.dut

        dut.rst.value = 1

        dut.s_eth_hdr_valid.value = 0
        dut.s_eth_dest_mac.value = 0
        dut.s_eth_src_mac.value = 0
        dut.s_eth_type.value = 0
        dut.s_eth_payload_axis_tvalid.value = 0
        dut.s_eth_payload_axis_tdata.value = 0
        dut.s_eth_payload_axis_tlast.value = 0
        dut.s_eth_payload_axis_tuser.value = 0

        dut.m_eth_hdr_ready.value = 1
        dut.m_eth_payload_axis_tready.value = 1

        dut.local_mac.value = int.from_bytes(mac2str(LOCAL_MAC), 'big')
        dut.local_ip.value = atol(LOCAL_IP)
        dut.gateway_ip.value = atol(GATEWAY_IP)
        dut.subnet_mask.value = atol(SUBNET_MASK)
        dut.clear_arp_cache.value = 0

        # external "raw IP" bypass in/out - unused in this test, but must
        # still be driven to a defined value
        dut.s_ip_hdr_valid.value = 0
        dut.s_ip_dscp.value = 0
        dut.s_ip_ecn.value = 0
        dut.s_ip_length.value = 0
        dut.s_ip_ttl.value = 0
        dut.s_ip_protocol.value = 0
        dut.s_ip_source_ip.value = 0
        dut.s_ip_dest_ip.value = 0
        dut.s_ip_payload_axis_tdata.value = 0
        dut.s_ip_payload_axis_tvalid.value = 0
        dut.s_ip_payload_axis_tlast.value = 0
        dut.s_ip_payload_axis_tuser.value = 0
        dut.m_ip_hdr_ready.value = 1
        dut.m_ip_payload_axis_tready.value = 1

        # UDP application input/output
        dut.s_udp_hdr_valid.value = 0
        dut.s_udp_ip_dscp.value = 0
        dut.s_udp_ip_ecn.value = 0
        dut.s_udp_ip_ttl.value = 0
        dut.s_udp_ip_source_ip.value = 0
        dut.s_udp_ip_dest_ip.value = 0
        dut.s_udp_source_port.value = 0
        dut.s_udp_dest_port.value = 0
        dut.s_udp_length.value = 0
        dut.s_udp_checksum.value = 0
        dut.s_udp_payload_axis_tdata.value = 0
        dut.s_udp_payload_axis_tvalid.value = 0
        dut.s_udp_payload_axis_tlast.value = 0
        dut.s_udp_payload_axis_tuser.value = 0
        dut.m_udp_hdr_ready.value = 1
        dut.m_udp_payload_axis_tready.value = 1

        for _ in range(10):
            await RisingEdge(dut.clk)

        dut.rst.value = 0

        # arp_cache.v scans and clears its whole memory after reset
        # (2**ARP_CACHE_ADDR_WIDTH entries, one per cycle) and rejects
        # cache writes until that finishes; ARP_CACHE_ADDR_WIDTH is
        # overridden down to a small value for this test (see
        # test_udp_icmp_complete() below) specifically so this settles
        # quickly, but still wait comfortably past it before relying on
        # the cache.
        for _ in range(2 ** ARP_CACHE_ADDR_WIDTH + 10):
            await RisingEdge(dut.clk)

    async def send(self, pkt):
        dut = self.dut
        payload = bytes(pkt[Ether].payload)

        dut.s_eth_dest_mac.value = int.from_bytes(mac2str(pkt[Ether].dst), 'big')
        dut.s_eth_src_mac.value = int.from_bytes(mac2str(pkt[Ether].src), 'big')
        dut.s_eth_type.value = pkt[Ether].type
        dut.s_eth_hdr_valid.value = 1

        while True:
            await RisingEdge(dut.clk)
            if dut.s_eth_hdr_ready.value:
                break

        dut.s_eth_hdr_valid.value = 0

        for i, byte in enumerate(payload):
            dut.s_eth_payload_axis_tdata.value = byte
            dut.s_eth_payload_axis_tlast.value = 1 if i == len(payload) - 1 else 0
            dut.s_eth_payload_axis_tuser.value = 0
            dut.s_eth_payload_axis_tvalid.value = 1

            while True:
                await RisingEdge(dut.clk)
                if dut.s_eth_payload_axis_tready.value:
                    break

        dut.s_eth_payload_axis_tvalid.value = 0

    async def recv(self):
        dut = self.dut

        # The header and the first payload byte can both become valid on
        # the very same clock edge, so header capture and payload
        # accumulation must be checked in the same per-edge sample rather
        # than in two sequential wait loops.
        header_captured = False
        dest_mac = src_mac = eth_type = None
        data = bytearray()

        while True:
            await RisingEdge(dut.clk)

            if not header_captured and dut.m_eth_hdr_valid.value:
                dest_mac = int(dut.m_eth_dest_mac.value)
                src_mac = int(dut.m_eth_src_mac.value)
                eth_type = int(dut.m_eth_type.value)
                header_captured = True

            if dut.m_eth_payload_axis_tvalid.value:
                data.append(int(dut.m_eth_payload_axis_tdata.value))
                if dut.m_eth_payload_axis_tuser.value:
                    raise AssertionError("received frame with tuser (error) asserted")
                if dut.m_eth_payload_axis_tlast.value:
                    break

        assert header_captured

        eth = Ether()
        eth.dst = dest_mac.to_bytes(6, 'big')
        eth.src = src_mac.to_bytes(6, 'big')
        eth.type = eth_type
        rx_pkt = eth / bytes(data)

        return Ether(bytes(rx_pkt))

    async def send_udp(self, pkt):
        dut = self.dut
        ip = pkt[IP]
        udp = pkt[UDP]
        payload = bytes(udp.payload)

        dut.s_udp_ip_dscp.value = ip.tos >> 2
        dut.s_udp_ip_ecn.value = ip.tos & 0x3
        dut.s_udp_ip_ttl.value = ip.ttl
        dut.s_udp_ip_source_ip.value = atol(ip.src)
        dut.s_udp_ip_dest_ip.value = atol(ip.dst)
        dut.s_udp_source_port.value = udp.sport
        dut.s_udp_dest_port.value = udp.dport
        # checksum generation is enabled (UDP_CHECKSUM_GEN_ENABLE default),
        # so udp.v recomputes length/checksum itself - these two are ignored
        dut.s_udp_length.value = 0
        dut.s_udp_checksum.value = 0
        dut.s_udp_hdr_valid.value = 1

        while True:
            await RisingEdge(dut.clk)
            if dut.s_udp_hdr_ready.value:
                break

        dut.s_udp_hdr_valid.value = 0

        for i, byte in enumerate(payload):
            dut.s_udp_payload_axis_tdata.value = byte
            dut.s_udp_payload_axis_tlast.value = 1 if i == len(payload) - 1 else 0
            dut.s_udp_payload_axis_tuser.value = 0
            dut.s_udp_payload_axis_tvalid.value = 1

            while True:
                await RisingEdge(dut.clk)
                if dut.s_udp_payload_axis_tready.value:
                    break

        dut.s_udp_payload_axis_tvalid.value = 0

    async def prime_arp_cache(self):
        # Send an ARP request as if it came from the peer; arp.v caches the
        # sender's IP/MAC on any received ARP frame (request or reply), so
        # this lets subsequent ICMP/UDP traffic resolve the peer's MAC from
        # the cache immediately instead of having to issue its own ARP
        # request and wait for a reply.
        arp_req = Ether(src=PEER_MAC, dst='ff:ff:ff:ff:ff:ff', type=0x0806) / \
            ARP(hwtype=1, ptype=0x0800, hwlen=6, plen=4, op=1,
                hwsrc=PEER_MAC, psrc=PEER_IP, hwdst='00:00:00:00:00:00', pdst=LOCAL_IP)

        await self.send(arp_req)

        arp_reply = await self.recv()

        assert arp_reply[Ether].dst == PEER_MAC
        assert arp_reply[Ether].src == LOCAL_MAC
        assert arp_reply[ARP].op == 2
        assert arp_reply[ARP].hwsrc == LOCAL_MAC
        assert arp_reply[ARP].psrc == LOCAL_IP
        assert arp_reply[ARP].hwdst == PEER_MAC
        assert arp_reply[ARP].pdst == PEER_IP

        for _ in range(20):
            await RisingEdge(self.dut.clk)


def incrementing_payload(length):
    return bytes(itertools.islice(itertools.cycle(range(256)), length))


def build_echo_request(payload, ip_id=0, icmp_id=1, icmp_seq=1):
    eth = Ether(src=PEER_MAC, dst=LOCAL_MAC, type=0x0800)
    ip = IP(version=4, ihl=5, tos=0, id=ip_id, flags=2, frag=0, ttl=64, proto=1,
        src=PEER_IP, dst=LOCAL_IP)
    icmp = ICMP(type=8, code=0, id=icmp_id, seq=icmp_seq)
    pkt = eth / ip / icmp / payload

    return Ether(bytes(pkt))


def build_expected_echo_reply(test_pkt):
    eth = Ether(src=LOCAL_MAC, dst=PEER_MAC, type=0x0800)
    # ip.v hardcodes identification=0, flags=2 (DF), fragment_offset=0 for
    # every frame it transmits, regardless of which protocol wrapper (udp
    # or icmp) fed it - see rtl/ip.v.
    ip = IP(version=4, ihl=5, tos=0, id=0, flags=2, frag=0, ttl=64, proto=1,
        src=LOCAL_IP, dst=PEER_IP)
    icmp = ICMP(type=0, code=0, id=test_pkt[ICMP].id, seq=test_pkt[ICMP].seq)
    pkt = eth / ip / icmp / bytes(test_pkt[ICMP].payload)

    return Ether(bytes(pkt))


def build_udp_datagram(payload, sport=1234, dport=5678, ip_id=0):
    eth = Ether(src=LOCAL_MAC, dst=PEER_MAC, type=0x0800)
    ip = IP(version=4, ihl=5, tos=0, id=ip_id, flags=2, frag=0, ttl=64, proto=17,
        src=LOCAL_IP, dst=PEER_IP)
    udp = UDP(sport=sport, dport=dport)
    pkt = eth / ip / udp / payload

    return Ether(bytes(pkt))


def build_expected_udp_frame(test_pkt):
    eth = Ether(src=LOCAL_MAC, dst=PEER_MAC, type=0x0800)
    ip = IP(version=4, ihl=5, tos=0, id=0, flags=2, frag=0, ttl=64, proto=17,
        src=LOCAL_IP, dst=PEER_IP)
    udp = UDP(sport=test_pkt[UDP].sport, dport=test_pkt[UDP].dport)
    pkt = eth / ip / udp / bytes(test_pkt[UDP].payload)

    return Ether(bytes(pkt))


@cocotb.test()
async def run_test_icmp_echo(dut):
    """ICMP Echo Request frames are answered with a matching Echo Reply"""

    tb = TB(dut)

    await tb.reset()

    await tb.prime_arp_cache()

    for length in range(1, 6):
        test_pkt = build_echo_request(incrementing_payload(length))

        await tb.send(test_pkt)

        rx_pkt = await tb.recv()

        tb.log.info("RX echo reply packet: %s", repr(rx_pkt))

        expected = build_expected_echo_reply(test_pkt)

        assert bytes(rx_pkt) == bytes(expected)


@cocotb.test()
async def run_test_udp_send(dut):
    """UDP datagrams originated on s_udp_* still reach m_eth_* correctly

    This is the actual point of udp_icmp_complete: UDP and the ICMP echo
    responder share a single ip_complete_icmp instance (one ip/arp engine,
    one ARP cache) instead of each wrapping its own ip_complete - so this
    confirms UDP still works correctly when combined this way.
    """

    tb = TB(dut)

    await tb.reset()

    await tb.prime_arp_cache()

    for length in range(1, 6):
        test_pkt = build_udp_datagram(incrementing_payload(length))

        await tb.send_udp(test_pkt)

        rx_pkt = await tb.recv()

        tb.log.info("RX UDP frame: %s", repr(rx_pkt))

        expected = build_expected_udp_frame(test_pkt)

        assert bytes(rx_pkt) == bytes(expected)


@cocotb.test()
async def run_test_icmp_and_udp_interleaved(dut):
    """ICMP echo and UDP send share the same underlying ip/arp engine

    without interfering with each other when interleaved back-to-back.
    """

    tb = TB(dut)

    await tb.reset()

    await tb.prime_arp_cache()

    echo_pkt = build_echo_request(incrementing_payload(4))
    await tb.send(echo_pkt)
    rx_pkt = await tb.recv()
    assert bytes(rx_pkt) == bytes(build_expected_echo_reply(echo_pkt))

    udp_pkt = build_udp_datagram(incrementing_payload(4))
    await tb.send_udp(udp_pkt)
    rx_pkt = await tb.recv()
    assert bytes(rx_pkt) == bytes(build_expected_udp_frame(udp_pkt))

    echo_pkt = build_echo_request(incrementing_payload(6), icmp_seq=2)
    await tb.send(echo_pkt)
    rx_pkt = await tb.recv()
    assert bytes(rx_pkt) == bytes(build_expected_echo_reply(echo_pkt))


@cocotb.test()
async def run_test_icmp_drop(dut):
    """Non-Echo-Request ICMP messages must be discarded without a reply"""

    tb = TB(dut)

    await tb.reset()

    await tb.prime_arp_cache()

    eth = Ether(src=PEER_MAC, dst=LOCAL_MAC, type=0x0800)
    ip = IP(version=4, ihl=5, tos=0, id=0, flags=2, frag=0, ttl=64, proto=1,
        src=PEER_IP, dst=LOCAL_IP)
    icmp = ICMP(type=3, code=1)  # Destination Unreachable - not an Echo Request
    test_pkt = Ether(bytes(eth / ip / icmp / incrementing_payload(8)))

    await tb.send(test_pkt)

    for _ in range(200):
        await RisingEdge(dut.clk)
        assert dut.m_eth_hdr_valid.value == 0

    assert dut.icmp_busy.value == 0


# cocotb-test

tests_dir = os.path.abspath(os.path.dirname(__file__))
rtl_dir = os.path.abspath(os.path.join(tests_dir, '..', '..', 'rtl'))
lib_dir = os.path.abspath(os.path.join(rtl_dir, '..', 'lib'))
axis_rtl_dir = os.path.abspath(os.path.join(lib_dir, 'axis', 'rtl'))


def test_udp_icmp_complete(request):
    dut = "udp_icmp_complete"
    module = os.path.splitext(os.path.basename(__file__))[0]
    toplevel = dut

    verilog_sources = [
        os.path.join(rtl_dir, f"{dut}.v"),
        os.path.join(rtl_dir, "ip_complete_icmp.v"),
        os.path.join(rtl_dir, "ip.v"),
        os.path.join(rtl_dir, "ip_eth_rx.v"),
        os.path.join(rtl_dir, "ip_eth_tx.v"),
        os.path.join(rtl_dir, "ip_arb_mux.v"),
        os.path.join(rtl_dir, "eth_arb_mux.v"),
        os.path.join(axis_rtl_dir, "arbiter.v"),
        os.path.join(axis_rtl_dir, "priority_encoder.v"),
        os.path.join(rtl_dir, "arp.v"),
        os.path.join(rtl_dir, "arp_cache.v"),
        os.path.join(rtl_dir, "arp_eth_rx.v"),
        os.path.join(rtl_dir, "arp_eth_tx.v"),
        os.path.join(rtl_dir, "icmp.v"),
        os.path.join(rtl_dir, "icmp_ip_rx.v"),
        os.path.join(rtl_dir, "icmp_ip_tx.v"),
        os.path.join(rtl_dir, "lfsr.v"),
        os.path.join(axis_rtl_dir, "axis_fifo.v"),
        os.path.join(rtl_dir, "udp.v"),
        os.path.join(rtl_dir, "udp_ip_rx.v"),
        os.path.join(rtl_dir, "udp_ip_tx.v"),
        os.path.join(rtl_dir, "udp_checksum_gen.v"),
    ]

    parameters = {'ARP_CACHE_ADDR_WIDTH': ARP_CACHE_ADDR_WIDTH}
    extra_env = {f'PARAM_{k}': str(v) for k, v in parameters.items()}

    sim_build = os.path.join(tests_dir, "sim_build",
        request.node.name.replace('[', '-').replace(']', ''))

    cocotb_test.simulator.run(
        python_search=[tests_dir],
        verilog_sources=verilog_sources,
        toplevel=toplevel,
        module=module,
        parameters=parameters,
        sim_build=sim_build,
        extra_env=extra_env,
    )
