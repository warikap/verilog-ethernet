/*

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

*/

// Language: Verilog 2001

`resetall
`timescale 1ns / 1ps
`default_nettype none

/*
 * IPv4 and ARP block with TCP support and an ICMP echo (ping) responder,
 * single AXI stream interface carrying whole Ethernet frames (64 bit
 * datapath)
 *
 * Same shape as eth_tcp_icmp_complete.v, but wraps eth_axis_rx/eth_axis_tx
 * at DATA_WIDTH=64 around tcp_icmp_complete_64 instead of DATA_WIDTH=8
 * around tcp_icmp_complete - so, unlike the 8-bit version, the raw AXI
 * stream in/out here does carry a real tkeep signal (KEEP_WIDTH=8),
 * matching tcp_icmp_complete_64's own tkeep-carrying Ethernet frame
 * interface. Every other port (raw IP bypass, TCP application interface,
 * status, configuration) is unchanged from tcp_icmp_complete_64.
 */
module eth_tcp_icmp_complete_64 #(
    parameter ARP_CACHE_ADDR_WIDTH = 9,
    parameter ARP_REQUEST_RETRY_COUNT = 4,
    parameter ARP_REQUEST_RETRY_INTERVAL = 125000000*2,
    parameter ARP_REQUEST_TIMEOUT = 125000000*30,
    parameter TCP_CHECKSUM_GEN_ENABLE = 1,
    parameter TCP_CHECKSUM_PAYLOAD_FIFO_DEPTH = 2048,
    parameter TCP_CHECKSUM_HEADER_FIFO_DEPTH = 8,
    parameter ICMP_PAYLOAD_FIFO_DEPTH = 2048,
    parameter ICMP_REPLY_TTL = 8'd64
)
(
    input  wire        clk,
    input  wire        rst,

    /*
     * Ethernet frame input (raw AXI stream, whole frames)
     */
    input  wire [63:0] s_axis_tdata,
    input  wire [7:0]  s_axis_tkeep,
    input  wire        s_axis_tvalid,
    output wire        s_axis_tready,
    input  wire        s_axis_tlast,
    input  wire        s_axis_tuser,

    /*
     * Ethernet frame output (raw AXI stream, whole frames)
     */
    output wire [63:0] m_axis_tdata,
    output wire [7:0]  m_axis_tkeep,
    output wire        m_axis_tvalid,
    input  wire        m_axis_tready,
    output wire        m_axis_tlast,
    output wire        m_axis_tuser,

    /*
     * IP input
     */
    input  wire        s_ip_hdr_valid,
    output wire        s_ip_hdr_ready,
    input  wire [5:0]  s_ip_dscp,
    input  wire [1:0]  s_ip_ecn,
    input  wire [15:0] s_ip_length,
    input  wire [7:0]  s_ip_ttl,
    input  wire [7:0]  s_ip_protocol,
    input  wire [31:0] s_ip_source_ip,
    input  wire [31:0] s_ip_dest_ip,
    input  wire [63:0] s_ip_payload_axis_tdata,
    input  wire [7:0]  s_ip_payload_axis_tkeep,
    input  wire        s_ip_payload_axis_tvalid,
    output wire        s_ip_payload_axis_tready,
    input  wire        s_ip_payload_axis_tlast,
    input  wire        s_ip_payload_axis_tuser,

    /*
     * IP output
     */
    output wire        m_ip_hdr_valid,
    input  wire        m_ip_hdr_ready,
    output wire [47:0] m_ip_eth_dest_mac,
    output wire [47:0] m_ip_eth_src_mac,
    output wire [15:0] m_ip_eth_type,
    output wire [3:0]  m_ip_version,
    output wire [3:0]  m_ip_ihl,
    output wire [5:0]  m_ip_dscp,
    output wire [1:0]  m_ip_ecn,
    output wire [15:0] m_ip_length,
    output wire [15:0] m_ip_identification,
    output wire [2:0]  m_ip_flags,
    output wire [12:0] m_ip_fragment_offset,
    output wire [7:0]  m_ip_ttl,
    output wire [7:0]  m_ip_protocol,
    output wire [15:0] m_ip_header_checksum,
    output wire [31:0] m_ip_source_ip,
    output wire [31:0] m_ip_dest_ip,
    output wire [63:0] m_ip_payload_axis_tdata,
    output wire [7:0]  m_ip_payload_axis_tkeep,
    output wire        m_ip_payload_axis_tvalid,
    input  wire        m_ip_payload_axis_tready,
    output wire        m_ip_payload_axis_tlast,
    output wire        m_ip_payload_axis_tuser,

    /*
     * TCP input
     */
    input  wire        s_tcp_hdr_valid,
    output wire        s_tcp_hdr_ready,
    input  wire [5:0]  s_tcp_ip_dscp,
    input  wire [1:0]  s_tcp_ip_ecn,
    input  wire [7:0]  s_tcp_ip_ttl,
    input  wire [31:0] s_tcp_ip_source_ip,
    input  wire [31:0] s_tcp_ip_dest_ip,
    input  wire [15:0] s_tcp_source_port,
    input  wire [15:0] s_tcp_dest_port,
    input  wire [31:0] s_tcp_seq_num,
    input  wire [31:0] s_tcp_ack_num,
    input  wire [3:0]  s_tcp_data_offset,
    input  wire [2:0]  s_tcp_reserved,
    input  wire [8:0]  s_tcp_flags,
    input  wire [15:0] s_tcp_window,
    input  wire [15:0] s_tcp_checksum,
    input  wire [15:0] s_tcp_urgent_pointer,
    input  wire [15:0] s_tcp_length,
    input  wire [63:0] s_tcp_payload_axis_tdata,
    input  wire [7:0]  s_tcp_payload_axis_tkeep,
    input  wire        s_tcp_payload_axis_tvalid,
    output wire        s_tcp_payload_axis_tready,
    input  wire        s_tcp_payload_axis_tlast,
    input  wire        s_tcp_payload_axis_tuser,

    /*
     * TCP output
     */
    output wire        m_tcp_hdr_valid,
    input  wire        m_tcp_hdr_ready,
    output wire [47:0] m_tcp_eth_dest_mac,
    output wire [47:0] m_tcp_eth_src_mac,
    output wire [15:0] m_tcp_eth_type,
    output wire [3:0]  m_tcp_ip_version,
    output wire [3:0]  m_tcp_ip_ihl,
    output wire [5:0]  m_tcp_ip_dscp,
    output wire [1:0]  m_tcp_ip_ecn,
    output wire [15:0] m_tcp_ip_length,
    output wire [15:0] m_tcp_ip_identification,
    output wire [2:0]  m_tcp_ip_flags,
    output wire [12:0] m_tcp_ip_fragment_offset,
    output wire [7:0]  m_tcp_ip_ttl,
    output wire [7:0]  m_tcp_ip_protocol,
    output wire [15:0] m_tcp_ip_header_checksum,
    output wire [31:0] m_tcp_ip_source_ip,
    output wire [31:0] m_tcp_ip_dest_ip,
    output wire [15:0] m_tcp_source_port,
    output wire [15:0] m_tcp_dest_port,
    output wire [31:0] m_tcp_seq_num,
    output wire [31:0] m_tcp_ack_num,
    output wire [3:0]  m_tcp_data_offset,
    output wire [2:0]  m_tcp_reserved,
    output wire [8:0]  m_tcp_flags,
    output wire [15:0] m_tcp_window,
    output wire [15:0] m_tcp_checksum,
    output wire [15:0] m_tcp_urgent_pointer,
    output wire [63:0] m_tcp_payload_axis_tdata,
    output wire [7:0]  m_tcp_payload_axis_tkeep,
    output wire        m_tcp_payload_axis_tvalid,
    input  wire        m_tcp_payload_axis_tready,
    output wire        m_tcp_payload_axis_tlast,
    output wire        m_tcp_payload_axis_tuser,

    /*
     * Status
     */
    output wire        eth_rx_busy,
    output wire        eth_rx_error_header_early_termination,
    output wire        eth_tx_busy,
    output wire        ip_rx_busy,
    output wire        ip_tx_busy,
    output wire        tcp_rx_busy,
    output wire        tcp_tx_busy,
    output wire        ip_rx_error_header_early_termination,
    output wire        ip_rx_error_payload_early_termination,
    output wire        ip_rx_error_invalid_header,
    output wire        ip_rx_error_invalid_checksum,
    output wire        ip_tx_error_payload_early_termination,
    output wire        ip_tx_error_arp_failed,
    output wire        tcp_rx_error_header_early_termination,
    output wire        tcp_rx_error_payload_early_termination,
    output wire        tcp_tx_error_payload_early_termination,
    output wire        icmp_busy,
    output wire        icmp_error_header_early_termination,
    output wire        icmp_error_payload_early_termination,

    /*
     * Configuration
     */
    input  wire [47:0] local_mac,
    input  wire [31:0] local_ip,
    input  wire [31:0] gateway_ip,
    input  wire [31:0] subnet_mask,
    input  wire        clear_arp_cache
);

wire        rx_eth_hdr_valid;
wire        rx_eth_hdr_ready;
wire [47:0] rx_eth_dest_mac;
wire [47:0] rx_eth_src_mac;
wire [15:0] rx_eth_type;
wire [63:0] rx_eth_payload_axis_tdata;
wire [7:0]  rx_eth_payload_axis_tkeep;
wire        rx_eth_payload_axis_tvalid;
wire        rx_eth_payload_axis_tready;
wire        rx_eth_payload_axis_tlast;
wire        rx_eth_payload_axis_tuser;

wire        tx_eth_hdr_valid;
wire        tx_eth_hdr_ready;
wire [47:0] tx_eth_dest_mac;
wire [47:0] tx_eth_src_mac;
wire [15:0] tx_eth_type;
wire [63:0] tx_eth_payload_axis_tdata;
wire [7:0]  tx_eth_payload_axis_tkeep;
wire        tx_eth_payload_axis_tvalid;
wire        tx_eth_payload_axis_tready;
wire        tx_eth_payload_axis_tlast;
wire        tx_eth_payload_axis_tuser;

/*
 * Ethernet frame receiver (raw AXI stream in, decoded header + payload out)
 */
eth_axis_rx #(
    .DATA_WIDTH(64)
)
eth_axis_rx_inst (
    .clk(clk),
    .rst(rst),
    // AXI input
    .s_axis_tdata(s_axis_tdata),
    .s_axis_tkeep(s_axis_tkeep),
    .s_axis_tvalid(s_axis_tvalid),
    .s_axis_tready(s_axis_tready),
    .s_axis_tlast(s_axis_tlast),
    .s_axis_tuser(s_axis_tuser),
    // Ethernet frame output
    .m_eth_hdr_valid(rx_eth_hdr_valid),
    .m_eth_hdr_ready(rx_eth_hdr_ready),
    .m_eth_dest_mac(rx_eth_dest_mac),
    .m_eth_src_mac(rx_eth_src_mac),
    .m_eth_type(rx_eth_type),
    .m_eth_payload_axis_tdata(rx_eth_payload_axis_tdata),
    .m_eth_payload_axis_tkeep(rx_eth_payload_axis_tkeep),
    .m_eth_payload_axis_tvalid(rx_eth_payload_axis_tvalid),
    .m_eth_payload_axis_tready(rx_eth_payload_axis_tready),
    .m_eth_payload_axis_tlast(rx_eth_payload_axis_tlast),
    .m_eth_payload_axis_tuser(rx_eth_payload_axis_tuser),
    // Status signals
    .busy(eth_rx_busy),
    .error_header_early_termination(eth_rx_error_header_early_termination)
);

/*
 * IPv4/ARP/TCP/ICMP stack
 */
tcp_icmp_complete_64 #(
    .ARP_CACHE_ADDR_WIDTH(ARP_CACHE_ADDR_WIDTH),
    .ARP_REQUEST_RETRY_COUNT(ARP_REQUEST_RETRY_COUNT),
    .ARP_REQUEST_RETRY_INTERVAL(ARP_REQUEST_RETRY_INTERVAL),
    .ARP_REQUEST_TIMEOUT(ARP_REQUEST_TIMEOUT),
    .TCP_CHECKSUM_GEN_ENABLE(TCP_CHECKSUM_GEN_ENABLE),
    .TCP_CHECKSUM_PAYLOAD_FIFO_DEPTH(TCP_CHECKSUM_PAYLOAD_FIFO_DEPTH),
    .TCP_CHECKSUM_HEADER_FIFO_DEPTH(TCP_CHECKSUM_HEADER_FIFO_DEPTH),
    .ICMP_PAYLOAD_FIFO_DEPTH(ICMP_PAYLOAD_FIFO_DEPTH),
    .ICMP_REPLY_TTL(ICMP_REPLY_TTL)
)
tcp_icmp_complete_64_inst (
    .clk(clk),
    .rst(rst),
    // Ethernet frame input
    .s_eth_hdr_valid(rx_eth_hdr_valid),
    .s_eth_hdr_ready(rx_eth_hdr_ready),
    .s_eth_dest_mac(rx_eth_dest_mac),
    .s_eth_src_mac(rx_eth_src_mac),
    .s_eth_type(rx_eth_type),
    .s_eth_payload_axis_tdata(rx_eth_payload_axis_tdata),
    .s_eth_payload_axis_tkeep(rx_eth_payload_axis_tkeep),
    .s_eth_payload_axis_tvalid(rx_eth_payload_axis_tvalid),
    .s_eth_payload_axis_tready(rx_eth_payload_axis_tready),
    .s_eth_payload_axis_tlast(rx_eth_payload_axis_tlast),
    .s_eth_payload_axis_tuser(rx_eth_payload_axis_tuser),
    // Ethernet frame output
    .m_eth_hdr_valid(tx_eth_hdr_valid),
    .m_eth_hdr_ready(tx_eth_hdr_ready),
    .m_eth_dest_mac(tx_eth_dest_mac),
    .m_eth_src_mac(tx_eth_src_mac),
    .m_eth_type(tx_eth_type),
    .m_eth_payload_axis_tdata(tx_eth_payload_axis_tdata),
    .m_eth_payload_axis_tkeep(tx_eth_payload_axis_tkeep),
    .m_eth_payload_axis_tvalid(tx_eth_payload_axis_tvalid),
    .m_eth_payload_axis_tready(tx_eth_payload_axis_tready),
    .m_eth_payload_axis_tlast(tx_eth_payload_axis_tlast),
    .m_eth_payload_axis_tuser(tx_eth_payload_axis_tuser),
    // IP frame input
    .s_ip_hdr_valid(s_ip_hdr_valid),
    .s_ip_hdr_ready(s_ip_hdr_ready),
    .s_ip_dscp(s_ip_dscp),
    .s_ip_ecn(s_ip_ecn),
    .s_ip_length(s_ip_length),
    .s_ip_ttl(s_ip_ttl),
    .s_ip_protocol(s_ip_protocol),
    .s_ip_source_ip(s_ip_source_ip),
    .s_ip_dest_ip(s_ip_dest_ip),
    .s_ip_payload_axis_tdata(s_ip_payload_axis_tdata),
    .s_ip_payload_axis_tkeep(s_ip_payload_axis_tkeep),
    .s_ip_payload_axis_tvalid(s_ip_payload_axis_tvalid),
    .s_ip_payload_axis_tready(s_ip_payload_axis_tready),
    .s_ip_payload_axis_tlast(s_ip_payload_axis_tlast),
    .s_ip_payload_axis_tuser(s_ip_payload_axis_tuser),
    // IP frame output
    .m_ip_hdr_valid(m_ip_hdr_valid),
    .m_ip_hdr_ready(m_ip_hdr_ready),
    .m_ip_eth_dest_mac(m_ip_eth_dest_mac),
    .m_ip_eth_src_mac(m_ip_eth_src_mac),
    .m_ip_eth_type(m_ip_eth_type),
    .m_ip_version(m_ip_version),
    .m_ip_ihl(m_ip_ihl),
    .m_ip_dscp(m_ip_dscp),
    .m_ip_ecn(m_ip_ecn),
    .m_ip_length(m_ip_length),
    .m_ip_identification(m_ip_identification),
    .m_ip_flags(m_ip_flags),
    .m_ip_fragment_offset(m_ip_fragment_offset),
    .m_ip_ttl(m_ip_ttl),
    .m_ip_protocol(m_ip_protocol),
    .m_ip_header_checksum(m_ip_header_checksum),
    .m_ip_source_ip(m_ip_source_ip),
    .m_ip_dest_ip(m_ip_dest_ip),
    .m_ip_payload_axis_tdata(m_ip_payload_axis_tdata),
    .m_ip_payload_axis_tkeep(m_ip_payload_axis_tkeep),
    .m_ip_payload_axis_tvalid(m_ip_payload_axis_tvalid),
    .m_ip_payload_axis_tready(m_ip_payload_axis_tready),
    .m_ip_payload_axis_tlast(m_ip_payload_axis_tlast),
    .m_ip_payload_axis_tuser(m_ip_payload_axis_tuser),
    // TCP frame input
    .s_tcp_hdr_valid(s_tcp_hdr_valid),
    .s_tcp_hdr_ready(s_tcp_hdr_ready),
    .s_tcp_ip_dscp(s_tcp_ip_dscp),
    .s_tcp_ip_ecn(s_tcp_ip_ecn),
    .s_tcp_ip_ttl(s_tcp_ip_ttl),
    .s_tcp_ip_source_ip(s_tcp_ip_source_ip),
    .s_tcp_ip_dest_ip(s_tcp_ip_dest_ip),
    .s_tcp_source_port(s_tcp_source_port),
    .s_tcp_dest_port(s_tcp_dest_port),
    .s_tcp_seq_num(s_tcp_seq_num),
    .s_tcp_ack_num(s_tcp_ack_num),
    .s_tcp_data_offset(s_tcp_data_offset),
    .s_tcp_reserved(s_tcp_reserved),
    .s_tcp_flags(s_tcp_flags),
    .s_tcp_window(s_tcp_window),
    .s_tcp_checksum(s_tcp_checksum),
    .s_tcp_urgent_pointer(s_tcp_urgent_pointer),
    .s_tcp_length(s_tcp_length),
    .s_tcp_payload_axis_tdata(s_tcp_payload_axis_tdata),
    .s_tcp_payload_axis_tkeep(s_tcp_payload_axis_tkeep),
    .s_tcp_payload_axis_tvalid(s_tcp_payload_axis_tvalid),
    .s_tcp_payload_axis_tready(s_tcp_payload_axis_tready),
    .s_tcp_payload_axis_tlast(s_tcp_payload_axis_tlast),
    .s_tcp_payload_axis_tuser(s_tcp_payload_axis_tuser),
    // TCP frame output
    .m_tcp_hdr_valid(m_tcp_hdr_valid),
    .m_tcp_hdr_ready(m_tcp_hdr_ready),
    .m_tcp_eth_dest_mac(m_tcp_eth_dest_mac),
    .m_tcp_eth_src_mac(m_tcp_eth_src_mac),
    .m_tcp_eth_type(m_tcp_eth_type),
    .m_tcp_ip_version(m_tcp_ip_version),
    .m_tcp_ip_ihl(m_tcp_ip_ihl),
    .m_tcp_ip_dscp(m_tcp_ip_dscp),
    .m_tcp_ip_ecn(m_tcp_ip_ecn),
    .m_tcp_ip_length(m_tcp_ip_length),
    .m_tcp_ip_identification(m_tcp_ip_identification),
    .m_tcp_ip_flags(m_tcp_ip_flags),
    .m_tcp_ip_fragment_offset(m_tcp_ip_fragment_offset),
    .m_tcp_ip_ttl(m_tcp_ip_ttl),
    .m_tcp_ip_protocol(m_tcp_ip_protocol),
    .m_tcp_ip_header_checksum(m_tcp_ip_header_checksum),
    .m_tcp_ip_source_ip(m_tcp_ip_source_ip),
    .m_tcp_ip_dest_ip(m_tcp_ip_dest_ip),
    .m_tcp_source_port(m_tcp_source_port),
    .m_tcp_dest_port(m_tcp_dest_port),
    .m_tcp_seq_num(m_tcp_seq_num),
    .m_tcp_ack_num(m_tcp_ack_num),
    .m_tcp_data_offset(m_tcp_data_offset),
    .m_tcp_reserved(m_tcp_reserved),
    .m_tcp_flags(m_tcp_flags),
    .m_tcp_window(m_tcp_window),
    .m_tcp_checksum(m_tcp_checksum),
    .m_tcp_urgent_pointer(m_tcp_urgent_pointer),
    .m_tcp_payload_axis_tdata(m_tcp_payload_axis_tdata),
    .m_tcp_payload_axis_tkeep(m_tcp_payload_axis_tkeep),
    .m_tcp_payload_axis_tvalid(m_tcp_payload_axis_tvalid),
    .m_tcp_payload_axis_tready(m_tcp_payload_axis_tready),
    .m_tcp_payload_axis_tlast(m_tcp_payload_axis_tlast),
    .m_tcp_payload_axis_tuser(m_tcp_payload_axis_tuser),
    // Status
    .ip_rx_busy(ip_rx_busy),
    .ip_tx_busy(ip_tx_busy),
    .tcp_rx_busy(tcp_rx_busy),
    .tcp_tx_busy(tcp_tx_busy),
    .ip_rx_error_header_early_termination(ip_rx_error_header_early_termination),
    .ip_rx_error_payload_early_termination(ip_rx_error_payload_early_termination),
    .ip_rx_error_invalid_header(ip_rx_error_invalid_header),
    .ip_rx_error_invalid_checksum(ip_rx_error_invalid_checksum),
    .ip_tx_error_payload_early_termination(ip_tx_error_payload_early_termination),
    .ip_tx_error_arp_failed(ip_tx_error_arp_failed),
    .tcp_rx_error_header_early_termination(tcp_rx_error_header_early_termination),
    .tcp_rx_error_payload_early_termination(tcp_rx_error_payload_early_termination),
    .tcp_tx_error_payload_early_termination(tcp_tx_error_payload_early_termination),
    .icmp_busy(icmp_busy),
    .icmp_error_header_early_termination(icmp_error_header_early_termination),
    .icmp_error_payload_early_termination(icmp_error_payload_early_termination),
    // Configuration
    .local_mac(local_mac),
    .local_ip(local_ip),
    .gateway_ip(gateway_ip),
    .subnet_mask(subnet_mask),
    .clear_arp_cache(clear_arp_cache)
);

/*
 * Ethernet frame transmitter (decoded header + payload in, raw AXI stream out)
 */
eth_axis_tx #(
    .DATA_WIDTH(64)
)
eth_axis_tx_inst (
    .clk(clk),
    .rst(rst),
    // Ethernet frame input
    .s_eth_hdr_valid(tx_eth_hdr_valid),
    .s_eth_hdr_ready(tx_eth_hdr_ready),
    .s_eth_dest_mac(tx_eth_dest_mac),
    .s_eth_src_mac(tx_eth_src_mac),
    .s_eth_type(tx_eth_type),
    .s_eth_payload_axis_tdata(tx_eth_payload_axis_tdata),
    .s_eth_payload_axis_tkeep(tx_eth_payload_axis_tkeep),
    .s_eth_payload_axis_tvalid(tx_eth_payload_axis_tvalid),
    .s_eth_payload_axis_tready(tx_eth_payload_axis_tready),
    .s_eth_payload_axis_tlast(tx_eth_payload_axis_tlast),
    .s_eth_payload_axis_tuser(tx_eth_payload_axis_tuser),
    // AXI output
    .m_axis_tdata(m_axis_tdata),
    .m_axis_tkeep(m_axis_tkeep),
    .m_axis_tvalid(m_axis_tvalid),
    .m_axis_tready(m_axis_tready),
    .m_axis_tlast(m_axis_tlast),
    .m_axis_tuser(m_axis_tuser),
    // Status signals
    .busy(eth_tx_busy)
);

endmodule

`resetall
