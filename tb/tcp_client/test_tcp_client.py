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

import logging
import os

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.utils import mac2str, atol, ltoa

import cocotb_test.simulator

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, ClockCycles
from cocotb.utils import get_sim_time

from cocotbext.axi import AxiStreamBus, AxiStreamSource, AxiStreamSink
from cocotbext.axi.stream import define_stream


IpHdrBus, IpHdrTransaction, IpHdrSource, IpHdrSink, IpHdrMonitor = define_stream("IpHdr",
    signals=["ip_hdr_valid", "ip_hdr_ready", "ip_eth_dest_mac", "ip_eth_src_mac", "ip_eth_type",
        "ip_version", "ip_ihl", "ip_dscp", "ip_ecn", "ip_length", "ip_identification",
        "ip_flags", "ip_fragment_offset", "ip_ttl", "ip_protocol", "ip_header_checksum",
        "ip_source_ip", "ip_dest_ip"]
)

LOCAL_IP = 0xc0a80164
LOCAL_PORT = 1234
PEER_IP_STR = '192.168.1.200'
PEER_PORT = 80

CLOCK_PERIOD_NS = 8


class TB:
    def __init__(self, dut):
        self.dut = dut

        self.log = logging.getLogger("cocotb.tb")
        self.log.setLevel(logging.DEBUG)

        cocotb.start_soon(Clock(dut.clk, CLOCK_PERIOD_NS, units="ns").start())

        self.ip_header_source = IpHdrSource(IpHdrBus.from_prefix(dut, "s"), dut.clk, dut.rst)
        self.ip_payload_source = AxiStreamSource(AxiStreamBus.from_prefix(dut, "s_ip_payload_axis"), dut.clk, dut.rst)

        self.ip_header_sink = IpHdrSink(IpHdrBus.from_prefix(dut, "m"), dut.clk, dut.rst)
        self.ip_payload_sink = AxiStreamSink(AxiStreamBus.from_prefix(dut, "m_ip_payload_axis"), dut.clk, dut.rst)

        self.data_source = AxiStreamSource(AxiStreamBus.from_prefix(dut, "s_axis"), dut.clk, dut.rst)
        self.data_sink = AxiStreamSink(AxiStreamBus.from_prefix(dut, "m_axis"), dut.clk, dut.rst)

    async def reset(self):
        self.dut.rst.setimmediatevalue(0)
        self.dut.s_config_axis_tvalid.setimmediatevalue(0)
        self.dut.s_config_axis_tdata.setimmediatevalue(0)
        await RisingEdge(self.dut.clk)
        await RisingEdge(self.dut.clk)
        self.dut.rst.value = 1
        await RisingEdge(self.dut.clk)
        await RisingEdge(self.dut.clk)
        self.dut.rst.value = 0
        await RisingEdge(self.dut.clk)
        await RisingEdge(self.dut.clk)

    async def send_config(self, dest_ip, dest_port, cmd):
        word = ((dest_ip & 0xffffffff) << 32) | ((dest_port & 0xffff) << 16) | (cmd & 0xffff)
        self.dut.s_config_axis_tdata.value = word
        self.dut.s_config_axis_tvalid.value = 1
        await RisingEdge(self.dut.clk)
        self.dut.s_config_axis_tvalid.value = 0

    async def peer_send_segment(self, flags, seq, ack, payload=b'', window=0x2000):
        eth = Ether(src='DA:D1:D2:D3:D4:D5', dst='5A:51:52:53:54:55')
        ip = IP(version=4, ihl=5, tos=0, id=0, flags=2, frag=0, ttl=64, proto=6,
            src=PEER_IP_STR, dst=ltoa(LOCAL_IP))
        tcp = TCP(sport=PEER_PORT, dport=LOCAL_PORT, seq=seq, ack=ack, dataofs=5,
            reserved=0, flags=flags, window=window, urgptr=0)
        pkt = Ether(bytes(eth / ip / tcp / payload))

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

    async def peer_recv_segment(self):
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

        rx_pkt = IP(bytes(ip / bytes(rx_payload.tdata)))

        return rx_pkt


CMD_CONNECT = 0x0001
CMD_DISCONNECT = 0x0002


@cocotb.test()
async def test_happy_path(dut):
    tb = TB(dut)

    await tb.reset()

    await tb.send_config(atol(PEER_IP_STR), PEER_PORT, CMD_CONNECT)

    syn_pkt = await tb.peer_recv_segment()
    assert syn_pkt[TCP].flags == 'S'
    syn_seq = syn_pkt[TCP].seq

    peer_isn = 0x10000000

    await tb.peer_send_segment(flags='SA', seq=peer_isn, ack=syn_seq + 1)

    ack_pkt = await tb.peer_recv_segment()
    assert ack_pkt[TCP].flags == 'A'
    assert ack_pkt[TCP].seq == syn_seq + 1
    assert ack_pkt[TCP].ack == peer_isn + 1

    await RisingEdge(dut.clk)
    assert dut.connected.value == 1

    payload = b'hello'
    await tb.data_source.send(payload)

    data_pkt = await tb.peer_recv_segment()
    assert data_pkt[TCP].flags == 'PA'
    assert data_pkt[TCP].seq == syn_seq + 1
    assert data_pkt[TCP].ack == peer_isn + 1
    assert bytes(data_pkt[TCP].payload) == payload

    await tb.peer_send_segment(flags='A', seq=peer_isn + 1, ack=syn_seq + 1 + len(payload))

    inbound_payload = b'world'
    await tb.peer_send_segment(flags='PA', seq=peer_isn + 1, ack=syn_seq + 1 + len(payload),
        payload=inbound_payload)

    rx_data = await tb.data_sink.recv()
    assert bytes(rx_data.tdata) == inbound_payload

    inbound_ack_pkt = await tb.peer_recv_segment()
    assert inbound_ack_pkt[TCP].flags == 'A'
    assert inbound_ack_pkt[TCP].ack == peer_isn + 1 + len(inbound_payload)

    await tb.send_config(0, 0, CMD_DISCONNECT)

    fin_pkt = await tb.peer_recv_segment()
    assert fin_pkt[TCP].flags == 'FA'
    fin_seq = fin_pkt[TCP].seq
    assert fin_seq == syn_seq + 1 + len(payload)

    await tb.peer_send_segment(flags='A', seq=peer_isn + 1 + len(inbound_payload), ack=fin_seq + 1)
    await tb.peer_send_segment(flags='FA', seq=peer_isn + 1 + len(inbound_payload), ack=fin_seq + 1)

    final_ack_pkt = await tb.peer_recv_segment()
    assert final_ack_pkt[TCP].flags == 'A'
    assert final_ack_pkt[TCP].seq == fin_seq + 1
    assert final_ack_pkt[TCP].ack == peer_isn + 2 + len(inbound_payload)

    await ClockCycles(dut.clk, 5)
    assert dut.connected.value == 0
    assert dut.closing.value == 0
    assert dut.connecting.value == 0


@cocotb.test()
async def test_syn_retransmit_timeout(dut):
    tb = TB(dut)

    await tb.reset()

    await tb.send_config(atol(PEER_IP_STR), PEER_PORT, CMD_CONNECT)

    retry_count = int(os.environ.get('PARAM_RETRY_COUNT', 3))
    retry_interval = int(os.environ.get('PARAM_RETRY_INTERVAL', 50))
    retry_timeout = int(os.environ.get('PARAM_RETRY_TIMEOUT', 100))

    syn_pkt = await tb.peer_recv_segment()
    assert syn_pkt[TCP].flags == 'S'
    syn_seq = syn_pkt[TCP].seq
    t_prev = get_sim_time(units='step')

    for i in range(retry_count):
        retry_pkt = await tb.peer_recv_segment()
        assert retry_pkt[TCP].flags == 'S'
        assert retry_pkt[TCP].seq == syn_seq
        t_now = get_sim_time(units='step')
        delta_cycles = (t_now - t_prev) / (CLOCK_PERIOD_NS * 1000)
        assert delta_cycles >= retry_interval - 2
        t_prev = t_now

    # after the last retry, the RTL waits RETRY_TIMEOUT (not RETRY_INTERVAL)
    # cycles before declaring retries exhausted; error is a one-cycle pulse,
    # so watch for it rather than sampling at a single fixed point
    error_seen = False
    for i in range(retry_timeout + 20):
        await RisingEdge(dut.clk)
        if dut.error.value:
            error_seen = True
            break
    assert error_seen

    await ClockCycles(dut.clk, 5)
    assert dut.connecting.value == 0
    assert dut.connected.value == 0

    assert tb.ip_header_sink.empty()


@cocotb.test()
async def test_data_retransmit(dut):
    tb = TB(dut)

    await tb.reset()

    retry_interval = int(os.environ.get('PARAM_RETRY_INTERVAL', 300))

    await tb.send_config(atol(PEER_IP_STR), PEER_PORT, CMD_CONNECT)

    syn_pkt = await tb.peer_recv_segment()
    syn_seq = syn_pkt[TCP].seq
    peer_isn = 0x20000000

    await tb.peer_send_segment(flags='SA', seq=peer_isn, ack=syn_seq + 1)
    await tb.peer_recv_segment()

    payload = b'retry-me'
    await tb.data_source.send(payload)

    first_pkt = await tb.peer_recv_segment()
    assert first_pkt[TCP].flags == 'PA'
    assert bytes(first_pkt[TCP].payload) == payload
    data_seq = first_pkt[TCP].seq

    retry_pkt = await tb.peer_recv_segment()
    assert retry_pkt[TCP].flags == 'PA'
    assert retry_pkt[TCP].seq == data_seq
    assert bytes(retry_pkt[TCP].payload) == payload

    await tb.peer_send_segment(flags='A', seq=peer_isn + 1, ack=data_seq + len(payload))

    await ClockCycles(dut.clk, retry_interval * 2)
    assert tb.ip_header_sink.empty()


# cocotb-test

tests_dir = os.path.abspath(os.path.dirname(__file__))
rtl_dir = os.path.abspath(os.path.join(tests_dir, '..', '..', 'rtl'))
lib_dir = os.path.abspath(os.path.join(rtl_dir, '..', 'lib'))
axis_rtl_dir = os.path.abspath(os.path.join(lib_dir, 'axis', 'rtl'))


def run(request, testcase, parameters=None):
    dut = "tcp_client"
    module = os.path.splitext(os.path.basename(__file__))[0]
    toplevel = dut

    verilog_sources = [
        os.path.join(rtl_dir, f"{dut}.v"),
        os.path.join(rtl_dir, "tcp.v"),
        os.path.join(rtl_dir, "tcp_ip_rx.v"),
        os.path.join(rtl_dir, "tcp_ip_tx.v"),
        os.path.join(rtl_dir, "tcp_checksum_gen.v"),
        os.path.join(axis_rtl_dir, "axis_fifo.v"),
    ]

    parameters = dict(parameters or {})
    extra_env = {f'PARAM_{k}': str(v) for k, v in parameters.items()}
    # cocotb_test 0.2.6's testcase= kwarg sets env var TESTCASE, but the
    # installed cocotb 2.0.1 only honors COCOTB_TESTCASE/COCOTB_TEST_FILTER -
    # without this, every @cocotb.test() in the module runs on every
    # invocation regardless of the testcase= kwarg below
    extra_env['COCOTB_TESTCASE'] = testcase

    sim_build = os.path.join(tests_dir, "sim_build",
        request.node.name.replace('[', '-').replace(']', ''))

    cocotb_test.simulator.run(
        python_search=[tests_dir],
        verilog_sources=verilog_sources,
        toplevel=toplevel,
        module=module,
        testcase=testcase,
        parameters=parameters,
        sim_build=sim_build,
        extra_env=extra_env,
    )


def test_tcp_client_happy_path(request):
    run(request, testcase='test_happy_path')


def test_tcp_client_syn_retransmit(request):
    run(request, testcase='test_syn_retransmit_timeout',
        parameters={'RETRY_COUNT': 3, 'RETRY_INTERVAL': 50, 'RETRY_TIMEOUT': 100})


def test_tcp_client_data_retransmit(request):
    run(request, testcase='test_data_retransmit',
        parameters={'RETRY_COUNT': 3, 'RETRY_INTERVAL': 300, 'RETRY_TIMEOUT': 400})


