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
 * ethernet frame interface
 *
 * Same shape as udp_icmp_complete.v, but built on ip_complete_icmp instead
 * of ip_complete, so TCP and the ICMP echo responder share a single ip/arp
 * engine instead of each wrapping its own (which is what would happen if
 * a separate TCP-only and ICMP-only wrapper were each used side by side,
 * each with its own ip_complete instance).
 */
module tcp_icmp_complete #(
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
     * Ethernet frame input
     */
    input  wire        s_eth_hdr_valid,
    output wire        s_eth_hdr_ready,
    input  wire [47:0] s_eth_dest_mac,
    input  wire [47:0] s_eth_src_mac,
    input  wire [15:0] s_eth_type,
    input  wire [7:0]  s_eth_payload_axis_tdata,
    input  wire        s_eth_payload_axis_tvalid,
    output wire        s_eth_payload_axis_tready,
    input  wire        s_eth_payload_axis_tlast,
    input  wire        s_eth_payload_axis_tuser,

    /*
     * Ethernet frame output
     */
    output wire        m_eth_hdr_valid,
    input  wire        m_eth_hdr_ready,
    output wire [47:0] m_eth_dest_mac,
    output wire [47:0] m_eth_src_mac,
    output wire [15:0] m_eth_type,
    output wire [7:0]  m_eth_payload_axis_tdata,
    output wire        m_eth_payload_axis_tvalid,
    input  wire        m_eth_payload_axis_tready,
    output wire        m_eth_payload_axis_tlast,
    output wire        m_eth_payload_axis_tuser,

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
    input  wire [7:0]  s_ip_payload_axis_tdata,
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
    output wire [7:0]  m_ip_payload_axis_tdata,
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
    input  wire [7:0]  s_tcp_payload_axis_tdata,
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
    output wire [7:0]  m_tcp_payload_axis_tdata,
    output wire        m_tcp_payload_axis_tvalid,
    input  wire        m_tcp_payload_axis_tready,
    output wire        m_tcp_payload_axis_tlast,
    output wire        m_tcp_payload_axis_tuser,

    /*
     * Status
     */
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

wire ip_rx_ip_hdr_valid;
wire ip_rx_ip_hdr_ready;
wire [47:0] ip_rx_ip_eth_dest_mac;
wire [47:0] ip_rx_ip_eth_src_mac;
wire [15:0] ip_rx_ip_eth_type;
wire [3:0] ip_rx_ip_version;
wire [3:0] ip_rx_ip_ihl;
wire [5:0] ip_rx_ip_dscp;
wire [1:0] ip_rx_ip_ecn;
wire [15:0] ip_rx_ip_length;
wire [15:0] ip_rx_ip_identification;
wire [2:0] ip_rx_ip_flags;
wire [12:0] ip_rx_ip_fragment_offset;
wire [7:0] ip_rx_ip_ttl;
wire [7:0] ip_rx_ip_protocol;
wire [15:0] ip_rx_ip_header_checksum;
wire [31:0] ip_rx_ip_source_ip;
wire [31:0] ip_rx_ip_dest_ip;
wire [7:0] ip_rx_ip_payload_axis_tdata;
wire ip_rx_ip_payload_axis_tvalid;
wire ip_rx_ip_payload_axis_tlast;
wire ip_rx_ip_payload_axis_tuser;
wire ip_rx_ip_payload_axis_tready;

wire ip_tx_ip_hdr_valid;
wire ip_tx_ip_hdr_ready;
wire [5:0] ip_tx_ip_dscp;
wire [1:0] ip_tx_ip_ecn;
wire [15:0] ip_tx_ip_length;
wire [7:0] ip_tx_ip_ttl;
wire [7:0] ip_tx_ip_protocol;
wire [31:0] ip_tx_ip_source_ip;
wire [31:0] ip_tx_ip_dest_ip;
wire [7:0] ip_tx_ip_payload_axis_tdata;
wire ip_tx_ip_payload_axis_tvalid;
wire ip_tx_ip_payload_axis_tlast;
wire ip_tx_ip_payload_axis_tuser;
wire ip_tx_ip_payload_axis_tready;

wire tcp_rx_ip_hdr_valid;
wire tcp_rx_ip_hdr_ready;
wire [47:0] tcp_rx_ip_eth_dest_mac;
wire [47:0] tcp_rx_ip_eth_src_mac;
wire [15:0] tcp_rx_ip_eth_type;
wire [3:0] tcp_rx_ip_version;
wire [3:0] tcp_rx_ip_ihl;
wire [5:0] tcp_rx_ip_dscp;
wire [1:0] tcp_rx_ip_ecn;
wire [15:0] tcp_rx_ip_length;
wire [15:0] tcp_rx_ip_identification;
wire [2:0] tcp_rx_ip_flags;
wire [12:0] tcp_rx_ip_fragment_offset;
wire [7:0] tcp_rx_ip_ttl;
wire [7:0] tcp_rx_ip_protocol;
wire [15:0] tcp_rx_ip_header_checksum;
wire [31:0] tcp_rx_ip_source_ip;
wire [31:0] tcp_rx_ip_dest_ip;
wire [7:0] tcp_rx_ip_payload_axis_tdata;
wire tcp_rx_ip_payload_axis_tvalid;
wire tcp_rx_ip_payload_axis_tlast;
wire tcp_rx_ip_payload_axis_tuser;
wire tcp_rx_ip_payload_axis_tready;

wire tcp_tx_ip_hdr_valid;
wire tcp_tx_ip_hdr_ready;
wire [5:0] tcp_tx_ip_dscp;
wire [1:0] tcp_tx_ip_ecn;
wire [15:0] tcp_tx_ip_length;
wire [7:0] tcp_tx_ip_ttl;
wire [7:0] tcp_tx_ip_protocol;
wire [31:0] tcp_tx_ip_source_ip;
wire [31:0] tcp_tx_ip_dest_ip;
wire [7:0] tcp_tx_ip_payload_axis_tdata;
wire tcp_tx_ip_payload_axis_tvalid;
wire tcp_tx_ip_payload_axis_tlast;
wire tcp_tx_ip_payload_axis_tuser;
wire tcp_tx_ip_payload_axis_tready;

/*
 * Input classifier (ip_protocol)
 */
wire s_select_tcp = (ip_rx_ip_protocol == 8'h06);
wire s_select_ip = !s_select_tcp;

reg s_select_tcp_reg = 1'b0;
reg s_select_ip_reg = 1'b0;

always @(posedge clk) begin
    if (rst) begin
        s_select_tcp_reg <= 1'b0;
        s_select_ip_reg <= 1'b0;
    end else begin
        if (ip_rx_ip_payload_axis_tvalid) begin
            if ((!s_select_tcp_reg && !s_select_ip_reg) ||
                (ip_rx_ip_payload_axis_tvalid && ip_rx_ip_payload_axis_tready && ip_rx_ip_payload_axis_tlast)) begin
                s_select_tcp_reg <= s_select_tcp;
                s_select_ip_reg <= s_select_ip;
            end
        end else begin
            s_select_tcp_reg <= 1'b0;
            s_select_ip_reg <= 1'b0;
        end
    end
end

// IP frame to TCP module
assign tcp_rx_ip_hdr_valid = s_select_tcp && ip_rx_ip_hdr_valid;
assign tcp_rx_ip_eth_dest_mac = ip_rx_ip_eth_dest_mac;
assign tcp_rx_ip_eth_src_mac = ip_rx_ip_eth_src_mac;
assign tcp_rx_ip_eth_type = ip_rx_ip_eth_type;
assign tcp_rx_ip_version = ip_rx_ip_version;
assign tcp_rx_ip_ihl = ip_rx_ip_ihl;
assign tcp_rx_ip_dscp = ip_rx_ip_dscp;
assign tcp_rx_ip_ecn = ip_rx_ip_ecn;
assign tcp_rx_ip_length = ip_rx_ip_length;
assign tcp_rx_ip_identification = ip_rx_ip_identification;
assign tcp_rx_ip_flags = ip_rx_ip_flags;
assign tcp_rx_ip_fragment_offset = ip_rx_ip_fragment_offset;
assign tcp_rx_ip_ttl = ip_rx_ip_ttl;
assign tcp_rx_ip_protocol = 8'h06;
assign tcp_rx_ip_header_checksum = ip_rx_ip_header_checksum;
assign tcp_rx_ip_source_ip = ip_rx_ip_source_ip;
assign tcp_rx_ip_dest_ip = ip_rx_ip_dest_ip;
assign tcp_rx_ip_payload_axis_tdata = ip_rx_ip_payload_axis_tdata;
assign tcp_rx_ip_payload_axis_tvalid = s_select_tcp_reg && ip_rx_ip_payload_axis_tvalid;
assign tcp_rx_ip_payload_axis_tlast = ip_rx_ip_payload_axis_tlast;
assign tcp_rx_ip_payload_axis_tuser = ip_rx_ip_payload_axis_tuser;

// External IP frame output
assign m_ip_hdr_valid = s_select_ip && ip_rx_ip_hdr_valid;
assign m_ip_eth_dest_mac = ip_rx_ip_eth_dest_mac;
assign m_ip_eth_src_mac = ip_rx_ip_eth_src_mac;
assign m_ip_eth_type = ip_rx_ip_eth_type;
assign m_ip_version = ip_rx_ip_version;
assign m_ip_ihl = ip_rx_ip_ihl;
assign m_ip_dscp = ip_rx_ip_dscp;
assign m_ip_ecn = ip_rx_ip_ecn;
assign m_ip_length = ip_rx_ip_length;
assign m_ip_identification = ip_rx_ip_identification;
assign m_ip_flags = ip_rx_ip_flags;
assign m_ip_fragment_offset = ip_rx_ip_fragment_offset;
assign m_ip_ttl = ip_rx_ip_ttl;
assign m_ip_protocol = ip_rx_ip_protocol;
assign m_ip_header_checksum = ip_rx_ip_header_checksum;
assign m_ip_source_ip = ip_rx_ip_source_ip;
assign m_ip_dest_ip = ip_rx_ip_dest_ip;
assign m_ip_payload_axis_tdata = ip_rx_ip_payload_axis_tdata;
assign m_ip_payload_axis_tvalid = s_select_ip_reg && ip_rx_ip_payload_axis_tvalid;
assign m_ip_payload_axis_tlast = ip_rx_ip_payload_axis_tlast;
assign m_ip_payload_axis_tuser = ip_rx_ip_payload_axis_tuser;

// ip_rx_ip_protocol (and the rest of the header) is only meaningful once
// ip_rx_ip_hdr_valid is asserted - the underlying header capture registers
// (e.g. in ip_eth_rx.v) are not reset, only updated when a header is
// actually latched, so s_select_tcp/s_select_ip read as X before the
// first real frame. Fall back to a defined ready value while idle so this
// never depends on that stale/undefined classification.
assign ip_rx_ip_hdr_ready = !ip_rx_ip_hdr_valid ||
                            (s_select_tcp && tcp_rx_ip_hdr_ready) ||
                            (s_select_ip && m_ip_hdr_ready);

assign ip_rx_ip_payload_axis_tready = (s_select_tcp_reg && tcp_rx_ip_payload_axis_tready) ||
                                      (s_select_ip_reg && m_ip_payload_axis_tready);

/*
 * Output arbiter
 */
ip_arb_mux #(
    .S_COUNT(2),
    .DATA_WIDTH(8),
    .KEEP_ENABLE(0),
    .ID_ENABLE(0),
    .DEST_ENABLE(0),
    .USER_ENABLE(1),
    .USER_WIDTH(1),
    .ARB_TYPE_ROUND_ROBIN(0),
    .ARB_LSB_HIGH_PRIORITY(1)
)
ip_arb_mux_inst (
    .clk(clk),
    .rst(rst),
    // IP frame inputs
    .s_ip_hdr_valid({s_ip_hdr_valid, tcp_tx_ip_hdr_valid}),
    .s_ip_hdr_ready({s_ip_hdr_ready, tcp_tx_ip_hdr_ready}),
    .s_eth_dest_mac(0),
    .s_eth_src_mac(0),
    .s_eth_type(0),
    .s_ip_version(0),
    .s_ip_ihl(0),
    .s_ip_dscp({s_ip_dscp, tcp_tx_ip_dscp}),
    .s_ip_ecn({s_ip_ecn, tcp_tx_ip_ecn}),
    .s_ip_length({s_ip_length, tcp_tx_ip_length}),
    .s_ip_identification(0),
    .s_ip_flags(0),
    .s_ip_fragment_offset(0),
    .s_ip_ttl({s_ip_ttl, tcp_tx_ip_ttl}),
    .s_ip_protocol({s_ip_protocol, tcp_tx_ip_protocol}),
    .s_ip_header_checksum(0),
    .s_ip_source_ip({s_ip_source_ip, tcp_tx_ip_source_ip}),
    .s_ip_dest_ip({s_ip_dest_ip, tcp_tx_ip_dest_ip}),
    .s_ip_payload_axis_tdata({s_ip_payload_axis_tdata, tcp_tx_ip_payload_axis_tdata}),
    .s_ip_payload_axis_tkeep(0),
    .s_ip_payload_axis_tvalid({s_ip_payload_axis_tvalid, tcp_tx_ip_payload_axis_tvalid}),
    .s_ip_payload_axis_tready({s_ip_payload_axis_tready, tcp_tx_ip_payload_axis_tready}),
    .s_ip_payload_axis_tlast({s_ip_payload_axis_tlast, tcp_tx_ip_payload_axis_tlast}),
    .s_ip_payload_axis_tid(0),
    .s_ip_payload_axis_tdest(0),
    .s_ip_payload_axis_tuser({s_ip_payload_axis_tuser, tcp_tx_ip_payload_axis_tuser}),
    // IP frame output
    .m_ip_hdr_valid(ip_tx_ip_hdr_valid),
    .m_ip_hdr_ready(ip_tx_ip_hdr_ready),
    .m_eth_dest_mac(),
    .m_eth_src_mac(),
    .m_eth_type(),
    .m_ip_version(),
    .m_ip_ihl(),
    .m_ip_dscp(ip_tx_ip_dscp),
    .m_ip_ecn(ip_tx_ip_ecn),
    .m_ip_length(ip_tx_ip_length),
    .m_ip_identification(),
    .m_ip_flags(),
    .m_ip_fragment_offset(),
    .m_ip_ttl(ip_tx_ip_ttl),
    .m_ip_protocol(ip_tx_ip_protocol),
    .m_ip_header_checksum(),
    .m_ip_source_ip(ip_tx_ip_source_ip),
    .m_ip_dest_ip(ip_tx_ip_dest_ip),
    .m_ip_payload_axis_tdata(ip_tx_ip_payload_axis_tdata),
    .m_ip_payload_axis_tkeep(),
    .m_ip_payload_axis_tvalid(ip_tx_ip_payload_axis_tvalid),
    .m_ip_payload_axis_tready(ip_tx_ip_payload_axis_tready),
    .m_ip_payload_axis_tlast(ip_tx_ip_payload_axis_tlast),
    .m_ip_payload_axis_tid(),
    .m_ip_payload_axis_tdest(),
    .m_ip_payload_axis_tuser(ip_tx_ip_payload_axis_tuser)
);

/*
 * IP stack with a built-in ICMP echo responder (shared ip/arp engine)
 */
ip_complete_icmp #(
    .ARP_CACHE_ADDR_WIDTH(ARP_CACHE_ADDR_WIDTH),
    .ARP_REQUEST_RETRY_COUNT(ARP_REQUEST_RETRY_COUNT),
    .ARP_REQUEST_RETRY_INTERVAL(ARP_REQUEST_RETRY_INTERVAL),
    .ARP_REQUEST_TIMEOUT(ARP_REQUEST_TIMEOUT),
    .ICMP_PAYLOAD_FIFO_DEPTH(ICMP_PAYLOAD_FIFO_DEPTH),
    .ICMP_REPLY_TTL(ICMP_REPLY_TTL)
)
ip_complete_icmp_inst (
    .clk(clk),
    .rst(rst),
    // Ethernet frame input
    .s_eth_hdr_valid(s_eth_hdr_valid),
    .s_eth_hdr_ready(s_eth_hdr_ready),
    .s_eth_dest_mac(s_eth_dest_mac),
    .s_eth_src_mac(s_eth_src_mac),
    .s_eth_type(s_eth_type),
    .s_eth_payload_axis_tdata(s_eth_payload_axis_tdata),
    .s_eth_payload_axis_tvalid(s_eth_payload_axis_tvalid),
    .s_eth_payload_axis_tready(s_eth_payload_axis_tready),
    .s_eth_payload_axis_tlast(s_eth_payload_axis_tlast),
    .s_eth_payload_axis_tuser(s_eth_payload_axis_tuser),
    // Ethernet frame output
    .m_eth_hdr_valid(m_eth_hdr_valid),
    .m_eth_hdr_ready(m_eth_hdr_ready),
    .m_eth_dest_mac(m_eth_dest_mac),
    .m_eth_src_mac(m_eth_src_mac),
    .m_eth_type(m_eth_type),
    .m_eth_payload_axis_tdata(m_eth_payload_axis_tdata),
    .m_eth_payload_axis_tvalid(m_eth_payload_axis_tvalid),
    .m_eth_payload_axis_tready(m_eth_payload_axis_tready),
    .m_eth_payload_axis_tlast(m_eth_payload_axis_tlast),
    .m_eth_payload_axis_tuser(m_eth_payload_axis_tuser),
    // IP frame input
    .s_ip_hdr_valid(ip_tx_ip_hdr_valid),
    .s_ip_hdr_ready(ip_tx_ip_hdr_ready),
    .s_ip_dscp(ip_tx_ip_dscp),
    .s_ip_ecn(ip_tx_ip_ecn),
    .s_ip_length(ip_tx_ip_length),
    .s_ip_ttl(ip_tx_ip_ttl),
    .s_ip_protocol(ip_tx_ip_protocol),
    .s_ip_source_ip(ip_tx_ip_source_ip),
    .s_ip_dest_ip(ip_tx_ip_dest_ip),
    .s_ip_payload_axis_tdata(ip_tx_ip_payload_axis_tdata),
    .s_ip_payload_axis_tvalid(ip_tx_ip_payload_axis_tvalid),
    .s_ip_payload_axis_tready(ip_tx_ip_payload_axis_tready),
    .s_ip_payload_axis_tlast(ip_tx_ip_payload_axis_tlast),
    .s_ip_payload_axis_tuser(ip_tx_ip_payload_axis_tuser),
    // IP frame output
    .m_ip_hdr_valid(ip_rx_ip_hdr_valid),
    .m_ip_hdr_ready(ip_rx_ip_hdr_ready),
    .m_ip_eth_dest_mac(ip_rx_ip_eth_dest_mac),
    .m_ip_eth_src_mac(ip_rx_ip_eth_src_mac),
    .m_ip_eth_type(ip_rx_ip_eth_type),
    .m_ip_version(ip_rx_ip_version),
    .m_ip_ihl(ip_rx_ip_ihl),
    .m_ip_dscp(ip_rx_ip_dscp),
    .m_ip_ecn(ip_rx_ip_ecn),
    .m_ip_length(ip_rx_ip_length),
    .m_ip_identification(ip_rx_ip_identification),
    .m_ip_flags(ip_rx_ip_flags),
    .m_ip_fragment_offset(ip_rx_ip_fragment_offset),
    .m_ip_ttl(ip_rx_ip_ttl),
    .m_ip_protocol(ip_rx_ip_protocol),
    .m_ip_header_checksum(ip_rx_ip_header_checksum),
    .m_ip_source_ip(ip_rx_ip_source_ip),
    .m_ip_dest_ip(ip_rx_ip_dest_ip),
    .m_ip_payload_axis_tdata(ip_rx_ip_payload_axis_tdata),
    .m_ip_payload_axis_tvalid(ip_rx_ip_payload_axis_tvalid),
    .m_ip_payload_axis_tready(ip_rx_ip_payload_axis_tready),
    .m_ip_payload_axis_tlast(ip_rx_ip_payload_axis_tlast),
    .m_ip_payload_axis_tuser(ip_rx_ip_payload_axis_tuser),
    // Status
    .rx_busy(ip_rx_busy),
    .tx_busy(ip_tx_busy),
    .rx_error_header_early_termination(ip_rx_error_header_early_termination),
    .rx_error_payload_early_termination(ip_rx_error_payload_early_termination),
    .rx_error_invalid_header(ip_rx_error_invalid_header),
    .rx_error_invalid_checksum(ip_rx_error_invalid_checksum),
    .tx_error_payload_early_termination(ip_tx_error_payload_early_termination),
    .tx_error_arp_failed(ip_tx_error_arp_failed),
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
 * TCP interface
 */
tcp #(
    .CHECKSUM_GEN_ENABLE(TCP_CHECKSUM_GEN_ENABLE),
    .CHECKSUM_PAYLOAD_FIFO_DEPTH(TCP_CHECKSUM_PAYLOAD_FIFO_DEPTH),
    .CHECKSUM_HEADER_FIFO_DEPTH(TCP_CHECKSUM_HEADER_FIFO_DEPTH)
)
tcp_inst (
    .clk(clk),
    .rst(rst),
    // IP frame input
    .s_ip_hdr_valid(tcp_rx_ip_hdr_valid),
    .s_ip_hdr_ready(tcp_rx_ip_hdr_ready),
    .s_ip_eth_dest_mac(tcp_rx_ip_eth_dest_mac),
    .s_ip_eth_src_mac(tcp_rx_ip_eth_src_mac),
    .s_ip_eth_type(tcp_rx_ip_eth_type),
    .s_ip_version(tcp_rx_ip_version),
    .s_ip_ihl(tcp_rx_ip_ihl),
    .s_ip_dscp(tcp_rx_ip_dscp),
    .s_ip_ecn(tcp_rx_ip_ecn),
    .s_ip_length(tcp_rx_ip_length),
    .s_ip_identification(tcp_rx_ip_identification),
    .s_ip_flags(tcp_rx_ip_flags),
    .s_ip_fragment_offset(tcp_rx_ip_fragment_offset),
    .s_ip_ttl(tcp_rx_ip_ttl),
    .s_ip_protocol(tcp_rx_ip_protocol),
    .s_ip_header_checksum(tcp_rx_ip_header_checksum),
    .s_ip_source_ip(tcp_rx_ip_source_ip),
    .s_ip_dest_ip(tcp_rx_ip_dest_ip),
    .s_ip_payload_axis_tdata(tcp_rx_ip_payload_axis_tdata),
    .s_ip_payload_axis_tvalid(tcp_rx_ip_payload_axis_tvalid),
    .s_ip_payload_axis_tready(tcp_rx_ip_payload_axis_tready),
    .s_ip_payload_axis_tlast(tcp_rx_ip_payload_axis_tlast),
    .s_ip_payload_axis_tuser(tcp_rx_ip_payload_axis_tuser),
    // IP frame output
    .m_ip_hdr_valid(tcp_tx_ip_hdr_valid),
    .m_ip_hdr_ready(tcp_tx_ip_hdr_ready),
    .m_ip_eth_dest_mac(),
    .m_ip_eth_src_mac(),
    .m_ip_eth_type(),
    .m_ip_version(),
    .m_ip_ihl(),
    .m_ip_dscp(tcp_tx_ip_dscp),
    .m_ip_ecn(tcp_tx_ip_ecn),
    .m_ip_length(tcp_tx_ip_length),
    .m_ip_identification(),
    .m_ip_flags(),
    .m_ip_fragment_offset(),
    .m_ip_ttl(tcp_tx_ip_ttl),
    .m_ip_protocol(tcp_tx_ip_protocol),
    .m_ip_header_checksum(),
    .m_ip_source_ip(tcp_tx_ip_source_ip),
    .m_ip_dest_ip(tcp_tx_ip_dest_ip),
    .m_ip_payload_axis_tdata(tcp_tx_ip_payload_axis_tdata),
    .m_ip_payload_axis_tvalid(tcp_tx_ip_payload_axis_tvalid),
    .m_ip_payload_axis_tready(tcp_tx_ip_payload_axis_tready),
    .m_ip_payload_axis_tlast(tcp_tx_ip_payload_axis_tlast),
    .m_ip_payload_axis_tuser(tcp_tx_ip_payload_axis_tuser),
    // TCP frame input
    .s_tcp_hdr_valid(s_tcp_hdr_valid),
    .s_tcp_hdr_ready(s_tcp_hdr_ready),
    .s_tcp_eth_dest_mac(48'd0),
    .s_tcp_eth_src_mac(48'd0),
    .s_tcp_eth_type(16'd0),
    .s_tcp_ip_version(4'd0),
    .s_tcp_ip_ihl(4'd0),
    .s_tcp_ip_dscp(s_tcp_ip_dscp),
    .s_tcp_ip_ecn(s_tcp_ip_ecn),
    .s_tcp_ip_identification(16'd0),
    .s_tcp_ip_flags(3'd0),
    .s_tcp_ip_fragment_offset(13'd0),
    .s_tcp_ip_ttl(s_tcp_ip_ttl),
    .s_tcp_ip_header_checksum(16'd0),
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
    .m_tcp_payload_axis_tvalid(m_tcp_payload_axis_tvalid),
    .m_tcp_payload_axis_tready(m_tcp_payload_axis_tready),
    .m_tcp_payload_axis_tlast(m_tcp_payload_axis_tlast),
    .m_tcp_payload_axis_tuser(m_tcp_payload_axis_tuser),
    // Status
    .rx_busy(tcp_rx_busy),
    .tx_busy(tcp_tx_busy),
    .rx_error_header_early_termination(tcp_rx_error_header_early_termination),
    .rx_error_payload_early_termination(tcp_rx_error_payload_early_termination),
    .tx_error_payload_early_termination(tcp_tx_error_payload_early_termination)
);

endmodule

`resetall
