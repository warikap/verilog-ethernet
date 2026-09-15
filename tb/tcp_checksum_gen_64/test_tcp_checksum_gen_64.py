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
from scapy.layers.inet import IP, TCP
from scapy.utils import mac2str, atol

import cocotb_test.simulator

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge
from cocotb.regression import TestFactory

from cocotbext.axi import AxiStreamBus, AxiStreamSource, AxiStreamSink
from cocotbext.axi.stream import define_stream


TcpHdrInBus, TcpHdrInTransaction, TcpHdrInSource, TcpHdrInSink, TcpHdrInMonitor = define_stream("TcpHdrIn",
    signals=["tcp_hdr_valid", "tcp_hdr_ready", "eth_dest_mac", "eth_src_mac", "eth_type",
        "ip_version", "ip_ihl", "ip_dscp", "ip_ecn", "ip_identification", "ip_flags",
        "ip_fragment_offset", "ip_ttl", "ip_header_checksum", "ip_source_ip", "ip_dest_ip",
        "tcp_source_port", "tcp_dest_port", "tcp_seq_num", "tcp_ack_num", "tcp_data_offset",
        "tcp_reserved", "tcp_flags", "tcp_window", "tcp_urgent_pointer"]
)

TcpHdrOutBus, TcpHdrOutTransaction, TcpHdrOutSource, TcpHdrOutSink, TcpHdrOutMonitor = define_stream("TcpHdrOut",
    signals=["tcp_hdr_valid", "tcp_hdr_ready", "eth_dest_mac", "eth_src_mac", "eth_type",
        "ip_version", "ip_ihl", "ip_dscp", "ip_ecn", "ip_length", "ip_identification",
        "ip_flags", "ip_fragment_offset", "ip_ttl", "ip_protocol", "ip_header_checksum",
        "ip_source_ip", "ip_dest_ip", "tcp_source_port", "tcp_dest_port", "tcp_seq_num",
        "tcp_ack_num", "tcp_data_offset", "tcp_reserved", "tcp_flags", "tcp_window",
        "tcp_checksum", "tcp_urgent_pointer", "tcp_length"]
)


class TB:
    def __init__(self, dut):
        self.dut = dut

        self.log = logging.getLogger("cocotb.tb")
        self.log.setLevel(logging.DEBUG)

        cocotb.start_soon(Clock(dut.clk, 8, units="ns").start())

        self.header_source = TcpHdrInSource(TcpHdrInBus.from_prefix(dut, "s"), dut.clk, dut.rst)
        self.payload_source = AxiStreamSource(AxiStreamBus.from_prefix(dut, "s_tcp_payload_axis"), dut.clk, dut.rst)

        self.header_sink = TcpHdrOutSink(TcpHdrOutBus.from_prefix(dut, "m"), dut.clk, dut.rst)
        self.payload_sink = AxiStreamSink(AxiStreamBus.from_prefix(dut, "m_tcp_payload_axis"), dut.clk, dut.rst)

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
        hdr = TcpHdrInTransaction()
        hdr.eth_dest_mac = int.from_bytes(mac2str(pkt[Ether].dst), 'big')
        hdr.eth_src_mac = int.from_bytes(mac2str(pkt[Ether].src), 'big')
        hdr.eth_type = pkt[Ether].type
        hdr.ip_version = pkt[IP].version
        hdr.ip_ihl = pkt[IP].ihl
        hdr.ip_dscp = pkt[IP].tos >> 2
        hdr.ip_ecn = pkt[IP].tos & 0x3
        hdr.ip_identification = pkt[IP].id
        hdr.ip_flags = int(pkt[IP].flags)
        hdr.ip_fragment_offset = pkt[IP].frag
        hdr.ip_ttl = pkt[IP].ttl
        hdr.ip_header_checksum = pkt[IP].chksum
        hdr.ip_source_ip = atol(pkt[IP].src)
        hdr.ip_dest_ip = atol(pkt[IP].dst)
        hdr.tcp_source_port = pkt[TCP].sport
        hdr.tcp_dest_port = pkt[TCP].dport
        hdr.tcp_seq_num = pkt[TCP].seq
        hdr.tcp_ack_num = pkt[TCP].ack
        hdr.tcp_data_offset = pkt[TCP].dataofs
        hdr.tcp_reserved = pkt[TCP].reserved
        hdr.tcp_flags = int(pkt[TCP].flags)
        hdr.tcp_window = pkt[TCP].window
        hdr.tcp_urgent_pointer = pkt[TCP].urgptr

        await self.header_source.send(hdr)
        await self.payload_source.send(bytes(pkt[TCP].payload))

    async def recv(self):
        rx_header = await self.header_sink.recv()
        rx_payload = await self.payload_sink.recv()

        assert not rx_payload.tuser

        return rx_header, bytes(rx_payload.tdata)


def build_test_packet(payload, sport=1234, dport=5678, seq=0x12345678,
        ack=0x87654321, flags=0x1ff, window=0x2000, urgptr=0):
    eth = Ether(src='5A:51:52:53:54:55', dst='DA:D1:D2:D3:D4:D5')
    ip = IP(version=4, ihl=5, tos=0, id=0, flags=2, frag=0, ttl=64, proto=6,
        src='192.168.1.100', dst='192.168.1.101')
    # flags=0x1ff exercises every bit of the 9 bit flags field (FIN, SYN,
    # RST, PSH, ACK, URG, ECE, CWR, NS), catching any bit-order mistake in
    # the data_offset/reserved/flags checksum word.
    tcp = TCP(sport=sport, dport=dport, seq=seq, ack=ack, dataofs=5,
        reserved=0, flags=flags, window=window, urgptr=urgptr)
    pkt = eth / ip / tcp / payload

    # force scapy to compute the real TCP checksum (over the IP pseudo
    # header, the TCP header, and the payload) and re-parse it back into
    # a concrete integer field, to compare against the DUT's own
    # computation
    return Ether(bytes(pkt))


async def run_test(dut, payload_lengths=None, payload_data=None, idle_inserter=None, backpressure_inserter=None):

    tb = TB(dut)

    await tb.reset()

    tb.set_idle_generator(idle_inserter)
    tb.set_backpressure_generator(backpressure_inserter)

    test_pkts = []

    for length in payload_lengths():
        test_pkt = build_test_packet(payload_data(length))
        test_pkts.append(test_pkt.copy())
        await tb.send(test_pkt)

    for test_pkt in test_pkts:
        rx_header, rx_payload = await tb.recv()

        expected_checksum = test_pkt[TCP].chksum
        expected_length = len(bytes(test_pkt[TCP]))

        tb.log.info("expected checksum: 0x%04x, got: 0x%04x", expected_checksum, rx_header.tcp_checksum.integer)
        tb.log.info("expected tcp_length: %d, got: %d", expected_length, rx_header.tcp_length.integer)

        assert rx_header.tcp_checksum.integer == expected_checksum
        assert rx_header.tcp_length.integer == expected_length
        assert rx_header.ip_length.integer == expected_length + 20
        assert rx_header.ip_protocol.integer == 6
        assert rx_header.tcp_source_port.integer == test_pkt[TCP].sport
        assert rx_header.tcp_dest_port.integer == test_pkt[TCP].dport
        assert rx_header.tcp_seq_num.integer == test_pkt[TCP].seq
        assert rx_header.tcp_ack_num.integer == test_pkt[TCP].ack
        assert rx_header.tcp_data_offset.integer == test_pkt[TCP].dataofs
        assert rx_header.tcp_flags.integer == int(test_pkt[TCP].flags)
        assert rx_header.tcp_window.integer == test_pkt[TCP].window
        assert rx_payload == bytes(test_pkt[TCP].payload)

    assert tb.header_sink.empty()
    assert tb.payload_sink.empty()

    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)


def cycle_pause():
    return itertools.cycle([1, 1, 1, 0])


def size_list():
    # a zero-length payload cannot be represented as an AXI stream frame
    # (a frame needs at least one beat), so this starts at 1. Range chosen
    # to exercise sub-beat, single-beat, and multi-beat (with partial last
    # beat) payloads on the 64-bit (8 byte lane) datapath, also crossing
    # the default HEADER_FIFO_DEPTH (8).
    return list(range(1, 40))


def incrementing_payload(length):
    return bytes(itertools.islice(itertools.cycle(range(256)), length))


if getattr(cocotb, "SIM_NAME", None):

    factory = TestFactory(run_test)
    factory.add_option("payload_lengths", [size_list])
    factory.add_option("payload_data", [incrementing_payload])
    factory.add_option("idle_inserter", [None, cycle_pause])
    factory.add_option("backpressure_inserter", [None, cycle_pause])
    factory.generate_tests()


# cocotb-test

tests_dir = os.path.abspath(os.path.dirname(__file__))
rtl_dir = os.path.abspath(os.path.join(tests_dir, '..', '..', 'rtl'))
lib_dir = os.path.abspath(os.path.join(rtl_dir, '..', 'lib'))
axis_rtl_dir = os.path.abspath(os.path.join(lib_dir, 'axis', 'rtl'))


def test_tcp_checksum_gen_64(request):
    dut = "tcp_checksum_gen_64"
    module = os.path.splitext(os.path.basename(__file__))[0]
    toplevel = dut

    verilog_sources = [
        os.path.join(rtl_dir, f"{dut}.v"),
        os.path.join(axis_rtl_dir, "axis_fifo.v"),
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
