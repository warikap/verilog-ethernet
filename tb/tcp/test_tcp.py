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
from scapy.utils import mac2str, atol, ltoa

import cocotb_test.simulator

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge

from cocotbext.axi import AxiStreamBus, AxiStreamSource, AxiStreamSink
from cocotbext.axi.stream import define_stream


IpHdrBus, IpHdrTransaction, IpHdrSource, IpHdrSink, IpHdrMonitor = define_stream("IpHdr",
    signals=["ip_hdr_valid", "ip_hdr_ready", "ip_eth_dest_mac", "ip_eth_src_mac", "ip_eth_type",
        "ip_version", "ip_ihl", "ip_dscp", "ip_ecn", "ip_length", "ip_identification",
        "ip_flags", "ip_fragment_offset", "ip_ttl", "ip_protocol", "ip_header_checksum",
        "ip_source_ip", "ip_dest_ip"]
)

TcpHdrInBus, TcpHdrInTransaction, TcpHdrInSource, TcpHdrInSink, TcpHdrInMonitor = define_stream("TcpHdrIn",
    signals=["tcp_hdr_valid", "tcp_hdr_ready", "tcp_eth_dest_mac", "tcp_eth_src_mac", "tcp_eth_type",
        "tcp_ip_version", "tcp_ip_ihl", "tcp_ip_dscp", "tcp_ip_ecn", "tcp_ip_identification",
        "tcp_ip_flags", "tcp_ip_fragment_offset", "tcp_ip_ttl", "tcp_ip_header_checksum",
        "tcp_ip_source_ip", "tcp_ip_dest_ip", "tcp_source_port", "tcp_dest_port", "tcp_seq_num",
        "tcp_ack_num", "tcp_data_offset", "tcp_reserved", "tcp_flags", "tcp_window",
        "tcp_checksum", "tcp_urgent_pointer", "tcp_length"]
)

TcpHdrOutBus, TcpHdrOutTransaction, TcpHdrOutSource, TcpHdrOutSink, TcpHdrOutMonitor = define_stream("TcpHdrOut",
    signals=["tcp_hdr_valid", "tcp_hdr_ready", "tcp_eth_dest_mac", "tcp_eth_src_mac", "tcp_eth_type",
        "tcp_ip_version", "tcp_ip_ihl", "tcp_ip_dscp", "tcp_ip_ecn", "tcp_ip_length",
        "tcp_ip_identification", "tcp_ip_flags", "tcp_ip_fragment_offset", "tcp_ip_ttl",
        "tcp_ip_protocol", "tcp_ip_header_checksum", "tcp_ip_source_ip", "tcp_ip_dest_ip",
        "tcp_source_port", "tcp_dest_port", "tcp_seq_num", "tcp_ack_num", "tcp_data_offset",
        "tcp_reserved", "tcp_flags", "tcp_window", "tcp_checksum", "tcp_urgent_pointer"]
)


class TB:
    def __init__(self, dut):
        self.dut = dut

        self.log = logging.getLogger("cocotb.tb")
        self.log.setLevel(logging.DEBUG)

        cocotb.start_soon(Clock(dut.clk, 8, units="ns").start())

        self.ip_header_source = IpHdrSource(IpHdrBus.from_prefix(dut, "s"), dut.clk, dut.rst)
        self.ip_payload_source = AxiStreamSource(AxiStreamBus.from_prefix(dut, "s_ip_payload_axis"), dut.clk, dut.rst)

        self.tcp_header_sink = TcpHdrOutSink(TcpHdrOutBus.from_prefix(dut, "m"), dut.clk, dut.rst)
        self.tcp_payload_sink = AxiStreamSink(AxiStreamBus.from_prefix(dut, "m_tcp_payload_axis"), dut.clk, dut.rst)

        self.tcp_header_source = TcpHdrInSource(TcpHdrInBus.from_prefix(dut, "s"), dut.clk, dut.rst)
        self.tcp_payload_source = AxiStreamSource(AxiStreamBus.from_prefix(dut, "s_tcp_payload_axis"), dut.clk, dut.rst)

        self.ip_header_sink = IpHdrSink(IpHdrBus.from_prefix(dut, "m"), dut.clk, dut.rst)
        self.ip_payload_sink = AxiStreamSink(AxiStreamBus.from_prefix(dut, "m_ip_payload_axis"), dut.clk, dut.rst)

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

    async def send_ip(self, pkt):
        hdr = IpHdrTransaction()
        hdr.ip_eth_dest_mac = int.from_bytes(mac2str(pkt[Ether].dst), 'big')
        hdr.ip_eth_src_mac = int.from_bytes(mac2str(pkt[Ether].src), 'big')
        hdr.ip_eth_type = pkt[Ether].type
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

        await self.ip_header_source.send(hdr)
        await self.ip_payload_source.send(bytes(pkt[IP].payload))

    async def recv_tcp(self):
        rx_header = await self.tcp_header_sink.recv()
        rx_payload = await self.tcp_payload_sink.recv()

        assert not rx_payload.tuser

        eth = Ether()
        eth.dst = rx_header.tcp_eth_dest_mac.integer.to_bytes(6, 'big')
        eth.src = rx_header.tcp_eth_src_mac.integer.to_bytes(6, 'big')
        eth.type = rx_header.tcp_eth_type.integer

        ip = IP()
        ip.version = rx_header.tcp_ip_version.integer
        ip.ihl = rx_header.tcp_ip_ihl.integer
        ip.tos = (rx_header.tcp_ip_dscp.integer << 2) | rx_header.tcp_ip_ecn.integer
        ip.len = rx_header.tcp_ip_length.integer
        ip.id = rx_header.tcp_ip_identification.integer
        ip.flags = rx_header.tcp_ip_flags.integer
        ip.frag = rx_header.tcp_ip_fragment_offset.integer
        ip.ttl = rx_header.tcp_ip_ttl.integer
        ip.proto = rx_header.tcp_ip_protocol.integer
        ip.chksum = rx_header.tcp_ip_header_checksum.integer
        ip.src = ltoa(rx_header.tcp_ip_source_ip.integer)
        ip.dst = ltoa(rx_header.tcp_ip_dest_ip.integer)

        tcp = TCP()
        tcp.sport = rx_header.tcp_source_port.integer
        tcp.dport = rx_header.tcp_dest_port.integer
        tcp.seq = rx_header.tcp_seq_num.integer
        tcp.ack = rx_header.tcp_ack_num.integer
        tcp.dataofs = rx_header.tcp_data_offset.integer
        tcp.reserved = rx_header.tcp_reserved.integer
        tcp.flags = rx_header.tcp_flags.integer
        tcp.window = rx_header.tcp_window.integer
        tcp.chksum = rx_header.tcp_checksum.integer
        tcp.urgptr = rx_header.tcp_urgent_pointer.integer

        rx_pkt = eth / ip / tcp / bytes(rx_payload.tdata)

        return Ether(bytes(rx_pkt))

    async def send_tcp(self, pkt, tcp_checksum=0, tcp_length=None):
        hdr = TcpHdrInTransaction()
        hdr.tcp_eth_dest_mac = int.from_bytes(mac2str(pkt[Ether].dst), 'big')
        hdr.tcp_eth_src_mac = int.from_bytes(mac2str(pkt[Ether].src), 'big')
        hdr.tcp_eth_type = pkt[Ether].type
        hdr.tcp_ip_version = pkt[IP].version
        hdr.tcp_ip_ihl = pkt[IP].ihl
        hdr.tcp_ip_dscp = pkt[IP].tos >> 2
        hdr.tcp_ip_ecn = pkt[IP].tos & 0x3
        hdr.tcp_ip_identification = pkt[IP].id
        hdr.tcp_ip_flags = int(pkt[IP].flags)
        hdr.tcp_ip_fragment_offset = pkt[IP].frag
        hdr.tcp_ip_ttl = pkt[IP].ttl
        hdr.tcp_ip_header_checksum = pkt[IP].chksum
        hdr.tcp_ip_source_ip = atol(pkt[IP].src)
        hdr.tcp_ip_dest_ip = atol(pkt[IP].dst)
        hdr.tcp_source_port = pkt[TCP].sport
        hdr.tcp_dest_port = pkt[TCP].dport
        hdr.tcp_seq_num = pkt[TCP].seq
        hdr.tcp_ack_num = pkt[TCP].ack
        hdr.tcp_data_offset = pkt[TCP].dataofs
        hdr.tcp_reserved = pkt[TCP].reserved
        hdr.tcp_flags = int(pkt[TCP].flags)
        hdr.tcp_window = pkt[TCP].window
        hdr.tcp_checksum = tcp_checksum
        hdr.tcp_urgent_pointer = pkt[TCP].urgptr
        # TCP has no length field of its own; tcp_length carries the TCP
        # header (20 octets, no options) plus payload byte count.
        hdr.tcp_length = tcp_length if tcp_length is not None else len(bytes(pkt[TCP]))

        await self.tcp_header_source.send(hdr)
        await self.tcp_payload_source.send(bytes(pkt[TCP].payload))

    async def recv_ip(self):
        rx_header = await self.ip_header_sink.recv()
        rx_payload = await self.ip_payload_sink.recv()

        assert not rx_payload.tuser

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

        # IP.proto == 6 makes scapy dissect the payload as TCP automatically,
        # but only once the packet is re-parsed from raw bytes (the "/"
        # operator alone just attaches a Raw layer, it does not dissect)
        rx_pkt = IP(bytes(ip / bytes(rx_payload.tdata)))

        return rx_header, rx_pkt


def build_test_packet(payload, sport=1234, dport=5678, seq=0x12345678,
        ack=0x87654321, flags=0x1ff, window=0x2000, urgptr=0):
    eth = Ether(src='5A:51:52:53:54:55', dst='DA:D1:D2:D3:D4:D5')
    ip = IP(version=4, ihl=5, tos=0, id=0, flags=2, frag=0, ttl=64, proto=6,
        src='192.168.1.100', dst='192.168.1.101')
    tcp = TCP(sport=sport, dport=dport, seq=seq, ack=ack, dataofs=5,
        reserved=0, flags=flags, window=window, urgptr=urgptr)
    pkt = eth / ip / tcp / payload

    return Ether(bytes(pkt))


def incrementing_payload(length):
    return bytes(itertools.islice(itertools.cycle(range(256)), length))


@cocotb.test()
async def run_test(dut):
    """IP-in -> TCP-out decode, and TCP-in -> IP-out framing (with or
    without real checksum generation, depending on CHECKSUM_GEN_ENABLE)"""

    tb = TB(dut)

    await tb.reset()

    # IP frame in -> TCP frame out (rx path; checksum is only decoded here,
    # never verified or recomputed, regardless of CHECKSUM_GEN_ENABLE)
    for length in range(1, 10):
        test_pkt = build_test_packet(incrementing_payload(length))

        await tb.send_ip(test_pkt)

        rx_pkt = await tb.recv_tcp()

        tb.log.info("RX TCP frame: %s", repr(rx_pkt))

        assert bytes(rx_pkt) == bytes(test_pkt)

    checksum_gen_enable = os.environ.get('TCP_TEST_CHECKSUM_GEN_ENABLE', '1') != '0'

    for length in range(1, 10):
        test_pkt = build_test_packet(incrementing_payload(length))

        if checksum_gen_enable:
            # TCP frame in -> IP frame out (tx path with real checksum
            # generation); tcp_checksum/tcp_length inputs are ignored and
            # recomputed from scratch
            await tb.send_tcp(test_pkt, tcp_checksum=0, tcp_length=0)

            rx_header, rx_pkt = await tb.recv_ip()

            expected = build_test_packet(incrementing_payload(length))

            assert bytes(rx_pkt) == bytes(expected[IP])
        else:
            # bypass path (CHECKSUM_GEN_ENABLE=0): tcp_checksum/tcp_length
            # pass straight through untouched
            explicit_checksum = 0xbeef
            explicit_length = len(bytes(test_pkt[TCP]))

            await tb.send_tcp(test_pkt, tcp_checksum=explicit_checksum, tcp_length=explicit_length)

            rx_header, rx_pkt = await tb.recv_ip()

            assert rx_pkt[TCP].chksum == explicit_checksum
            assert rx_header.ip_length.integer == explicit_length + 20
            assert bytes(rx_pkt[TCP].payload) == bytes(test_pkt[TCP].payload)

    # zero-payload TCP segment (e.g. SYN/ACK/FIN/RST) - regression test for
    # the tcp_ip_tx.v/tcp_checksum_gen.v fix that lets a genuinely
    # zero-byte-payload segment be sent at all (previously the TX state
    # machine always fell through to a payload phase that would only
    # complete on a tlast beat, which a zero-byte payload never provides)
    test_pkt = build_test_packet(b'')

    if checksum_gen_enable:
        # real length (20, header only) must be correct here - unlike the
        # nonzero-payload case above, tcp_length now also gates whether the
        # zero-payload fast path is taken, it is not purely ignored/recomputed
        await tb.send_tcp(test_pkt, tcp_checksum=0)

        rx_header, rx_pkt = await tb.recv_ip()

        expected = build_test_packet(b'')

        assert bytes(rx_pkt) == bytes(expected[IP])
    else:
        explicit_checksum = 0xbeef
        explicit_length = len(bytes(test_pkt[TCP]))

        assert explicit_length == 20

        await tb.send_tcp(test_pkt, tcp_checksum=explicit_checksum, tcp_length=explicit_length)

        rx_header, rx_pkt = await tb.recv_ip()

        assert rx_pkt[TCP].chksum == explicit_checksum
        assert rx_header.ip_length.integer == explicit_length + 20
        assert bytes(rx_pkt[TCP].payload) == b''

    assert tb.tcp_header_sink.empty()
    assert tb.tcp_payload_sink.empty()
    assert tb.ip_header_sink.empty()
    assert tb.ip_payload_sink.empty()

    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)


# cocotb-test

tests_dir = os.path.abspath(os.path.dirname(__file__))
rtl_dir = os.path.abspath(os.path.join(tests_dir, '..', '..', 'rtl'))
lib_dir = os.path.abspath(os.path.join(rtl_dir, '..', 'lib'))
axis_rtl_dir = os.path.abspath(os.path.join(lib_dir, 'axis', 'rtl'))


def run(request, checksum_gen_enable):
    dut = "tcp"
    module = os.path.splitext(os.path.basename(__file__))[0]
    toplevel = dut

    verilog_sources = [
        os.path.join(rtl_dir, f"{dut}.v"),
        os.path.join(rtl_dir, "tcp_ip_rx.v"),
        os.path.join(rtl_dir, "tcp_ip_tx.v"),
        os.path.join(rtl_dir, "tcp_checksum_gen.v"),
        os.path.join(axis_rtl_dir, "axis_fifo.v"),
    ]

    parameters = {'CHECKSUM_GEN_ENABLE': checksum_gen_enable}
    extra_env = {f'PARAM_{k}': str(v) for k, v in parameters.items()}
    extra_env['TCP_TEST_CHECKSUM_GEN_ENABLE'] = str(checksum_gen_enable)

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


def test_tcp(request):
    run(request, checksum_gen_enable=1)


def test_tcp_no_checksum(request):
    run(request, checksum_gen_enable=0)
