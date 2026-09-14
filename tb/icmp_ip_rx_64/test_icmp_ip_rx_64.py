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

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, ICMP
from scapy.utils import mac2str, atol, ltoa

import cocotb_test.simulator

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge
from cocotb.regression import TestFactory

from cocotbext.axi import AxiStreamBus, AxiStreamSource, AxiStreamSink
from cocotbext.axi.stream import define_stream


IpHdrBus, IpHdrTransaction, IpHdrSource, IpHdrSink, IpHdrMonitor = define_stream("IpHdr",
    signals=["ip_hdr_valid", "ip_hdr_ready", "eth_dest_mac", "eth_src_mac", "eth_type",
        "ip_version", "ip_ihl", "ip_dscp", "ip_ecn", "ip_length", "ip_identification",
        "ip_flags", "ip_fragment_offset", "ip_ttl", "ip_protocol", "ip_header_checksum",
        "ip_source_ip", "ip_dest_ip"]
)

IcmpHdrBus, IcmpHdrTransaction, IcmpHdrSource, IcmpHdrSink, IcmpHdrMonitor = define_stream("IcmpHdr",
    signals=["icmp_hdr_valid", "icmp_hdr_ready", "eth_dest_mac", "eth_src_mac", "eth_type",
        "ip_version", "ip_ihl", "ip_dscp", "ip_ecn", "ip_length", "ip_identification",
        "ip_flags", "ip_fragment_offset", "ip_ttl", "ip_protocol", "ip_header_checksum",
        "ip_source_ip", "ip_dest_ip", "icmp_type", "icmp_code", "icmp_checksum",
        "icmp_identifier", "icmp_sequence_number"]
)


class TB:
    def __init__(self, dut):
        self.dut = dut

        self.log = logging.getLogger("cocotb.tb")
        self.log.setLevel(logging.DEBUG)

        cocotb.start_soon(Clock(dut.clk, 8, units="ns").start())

        self.header_source = IpHdrSource(IpHdrBus.from_prefix(dut, "s"), dut.clk, dut.rst)
        self.payload_source = AxiStreamSource(AxiStreamBus.from_prefix(dut, "s_ip_payload_axis"), dut.clk, dut.rst)

        self.header_sink = IcmpHdrSink(IcmpHdrBus.from_prefix(dut, "m"), dut.clk, dut.rst)
        self.payload_sink = AxiStreamSink(AxiStreamBus.from_prefix(dut, "m_icmp_payload_axis"), dut.clk, dut.rst)

    def set_idle_generator(self, generator=None):
        if generator:
            self.header_source.set_pause_generator(generator())
            self.payload_source.set_pause_generator(generator())

    def set_backpressure_generator(self, generator=None):
        if generator:
            self.header_sink.set_pause_generator(generator())
            self.payload_sink.set_pause_generator(generator())

    async def reset(self):
        self.dut.rst.setimmediatevalue(0)
        await RisingEdge(self.dut.clk)
        await RisingEdge(self.dut.clk)
        self.dut.rst.value = 1
        await RisingEdge(self.dut.clk)
        await RisingEdge(self.dut.clk)
        self.dut.rst.value = 0
        await RisingEdge(self.dut.clk)
        await RisingEdge(self.dut.clk)

    async def send(self, pkt):
        hdr = IpHdrTransaction()
        hdr.eth_dest_mac = int.from_bytes(mac2str(pkt[Ether].dst), 'big')
        hdr.eth_src_mac = int.from_bytes(mac2str(pkt[Ether].src), 'big')
        hdr.eth_type = pkt[Ether].type
        hdr.ip_version = pkt[IP].version
        hdr.ip_ihl = pkt[IP].ihl
        hdr.ip_dscp = pkt[IP].tos >> 2
        hdr.ip_ecn = pkt[IP].tos & 0x3
        hdr.ip_length = pkt[IP].len
        hdr.ip_identification = pkt[IP].id
        hdr.ip_flags = int(pkt[IP].flags)
        hdr.ip_fragment_offset = pkt[IP].frag
        hdr.ip_ttl = pkt[IP].ttl
        hdr.ip_protocol = pkt[IP].proto
        hdr.ip_header_checksum = pkt[IP].chksum
        hdr.ip_source_ip = atol(pkt[IP].src)
        hdr.ip_dest_ip = atol(pkt[IP].dst)

        await self.header_source.send(hdr)
        await self.payload_source.send(bytes(pkt[IP].payload))

    async def recv(self):
        rx_header = await self.header_sink.recv()
        rx_payload = await self.payload_sink.recv()

        assert not rx_payload.tuser

        eth = Ether()
        eth.dst = rx_header.eth_dest_mac.integer.to_bytes(6, 'big')
        eth.src = rx_header.eth_src_mac.integer.to_bytes(6, 'big')
        eth.type = rx_header.eth_type.integer

        ip = IP()
        ip.version = rx_header.ip_version.integer
        ip.ihl = rx_header.ip_ihl.integer
        ip.tos = (rx_header.ip_dscp.integer << 2) | rx_header.ip_ecn.integer
        ip.len = rx_header.ip_length.integer
        ip.id = rx_header.ip_identification.integer
        ip.flags = rx_header.ip_flags.integer
        ip.frag = rx_header.ip_fragment_offset.integer
        ip.ttl = rx_header.ip_ttl.integer
        ip.proto = rx_header.ip_protocol.integer
        ip.chksum = rx_header.ip_header_checksum.integer
        ip.src = ltoa(rx_header.ip_source_ip.integer)
        ip.dst = ltoa(rx_header.ip_dest_ip.integer)

        icmp = ICMP()
        icmp.type = rx_header.icmp_type.integer
        icmp.code = rx_header.icmp_code.integer
        icmp.chksum = rx_header.icmp_checksum.integer
        icmp.id = rx_header.icmp_identifier.integer
        icmp.seq = rx_header.icmp_sequence_number.integer

        rx_pkt = eth / ip / icmp / bytes(rx_payload.tdata)

        return Ether(bytes(rx_pkt))


async def run_test(dut, payload_lengths=None, payload_data=None, idle_inserter=None, backpressure_inserter=None):

    tb = TB(dut)

    await tb.reset()

    tb.set_idle_generator(idle_inserter)
    tb.set_backpressure_generator(backpressure_inserter)

    test_pkts = []

    for length in payload_lengths():
        eth = Ether(src='5A:51:52:53:54:55', dst='DA:D1:D2:D3:D4:D5')
        ip = IP(version=4, ihl=5, tos=0, id=0, flags=2, frag=0, ttl=64, proto=1,
            src='192.168.1.100', dst='192.168.1.101')
        icmp = ICMP(type=8, code=0, id=1, seq=1)
        test_pkt = eth / ip / icmp / payload_data(length)

        test_pkt = Ether(bytes(test_pkt))

        test_pkts.append(test_pkt.copy())

        await tb.send(test_pkt)

    for test_pkt in test_pkts:
        rx_pkt = await tb.recv()

        tb.log.info("RX packet: %s", repr(rx_pkt))

        assert bytes(rx_pkt) == bytes(test_pkt)

    assert tb.header_sink.empty()
    assert tb.payload_sink.empty()

    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)


def cycle_pause():
    return itertools.cycle([1, 1, 1, 0])


def size_list():
    # exercise sub-beat, single-beat, and multi-beat (with partial last
    # beat) payloads on the 64-bit (8 byte lane) datapath
    return list(range(1, 30))


def incrementing_payload(length):
    return bytes(itertools.islice(itertools.cycle(range(256)), length))


if cocotb.SIM_NAME:

    factory = TestFactory(run_test)
    factory.add_option("payload_lengths", [size_list])
    factory.add_option("payload_data", [incrementing_payload])
    factory.add_option("idle_inserter", [None, cycle_pause])
    factory.add_option("backpressure_inserter", [None, cycle_pause])
    factory.generate_tests()


# cocotb-test

tests_dir = os.path.abspath(os.path.dirname(__file__))
rtl_dir = os.path.abspath(os.path.join(tests_dir, '..', '..', 'rtl'))


def test_icmp_ip_rx_64(request):
    dut = "icmp_ip_rx_64"
    module = os.path.splitext(os.path.basename(__file__))[0]
    toplevel = dut

    verilog_sources = [
        os.path.join(rtl_dir, f"{dut}.v"),
    ]

    sim_build = os.path.join(tests_dir, "sim_build",
        request.node.name.replace('[', '-').replace(']', ''))

    cocotb_test.simulator.run(
        python_search=[tests_dir],
        verilog_sources=verilog_sources,
        toplevel=toplevel,
        module=module,
        sim_build=sim_build,
    )
