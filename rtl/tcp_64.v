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
 * TCP block, IP interface (64 bit datapath)
 *
 * Basic TCP segment framing and mandatory checksum generation only - no
 * connection state machine, retransmission, windowing/flow control, or
 * options support. Unlike UDP (where a checksum of zero legitimately
 * means "unused"), the TCP checksum is mandatory per RFC 793, so
 * CHECKSUM_GEN_ENABLE=0 is only a symmetry/testing escape hatch (to
 * isolate tcp_ip_rx_64/tcp_ip_tx_64 without tcp_checksum_gen_64) and
 * should not be used in a real integration.
 */
module tcp_64 #
(
    parameter CHECKSUM_GEN_ENABLE = 1,
    parameter CHECKSUM_PAYLOAD_FIFO_DEPTH = 2048,
    parameter CHECKSUM_HEADER_FIFO_DEPTH = 8
)
(
    input  wire        clk,
    input  wire        rst,

    /*
     * IP frame input
     */
    input  wire        s_ip_hdr_valid,
    output wire        s_ip_hdr_ready,
    input  wire [47:0] s_ip_eth_dest_mac,
    input  wire [47:0] s_ip_eth_src_mac,
    input  wire [15:0] s_ip_eth_type,
    input  wire [3:0]  s_ip_version,
    input  wire [3:0]  s_ip_ihl,
    input  wire [5:0]  s_ip_dscp,
    input  wire [1:0]  s_ip_ecn,
    input  wire [15:0] s_ip_length,
    input  wire [15:0] s_ip_identification,
    input  wire [2:0]  s_ip_flags,
    input  wire [12:0] s_ip_fragment_offset,
    input  wire [7:0]  s_ip_ttl,
    input  wire [7:0]  s_ip_protocol,
    input  wire [15:0] s_ip_header_checksum,
    input  wire [31:0] s_ip_source_ip,
    input  wire [31:0] s_ip_dest_ip,
    input  wire [63:0] s_ip_payload_axis_tdata,
    input  wire [7:0]  s_ip_payload_axis_tkeep,
    input  wire        s_ip_payload_axis_tvalid,
    output wire        s_ip_payload_axis_tready,
    input  wire        s_ip_payload_axis_tlast,
    input  wire        s_ip_payload_axis_tuser,

    /*
     * IP frame output
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
     * TCP frame input
     */
    input  wire        s_tcp_hdr_valid,
    output wire        s_tcp_hdr_ready,
    input  wire [47:0] s_tcp_eth_dest_mac,
    input  wire [47:0] s_tcp_eth_src_mac,
    input  wire [15:0] s_tcp_eth_type,
    input  wire [3:0]  s_tcp_ip_version,
    input  wire [3:0]  s_tcp_ip_ihl,
    input  wire [5:0]  s_tcp_ip_dscp,
    input  wire [1:0]  s_tcp_ip_ecn,
    input  wire [15:0] s_tcp_ip_identification,
    input  wire [2:0]  s_tcp_ip_flags,
    input  wire [12:0] s_tcp_ip_fragment_offset,
    input  wire [7:0]  s_tcp_ip_ttl,
    input  wire [15:0] s_tcp_ip_header_checksum,
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
     * TCP frame output
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
     * Status signals
     */
    output wire        rx_busy,
    output wire        tx_busy,
    output wire        rx_error_header_early_termination,
    output wire        rx_error_payload_early_termination,
    output wire        tx_error_payload_early_termination
);

wire        tx_tcp_hdr_valid;
wire        tx_tcp_hdr_ready;
wire [47:0] tx_tcp_eth_dest_mac;
wire [47:0] tx_tcp_eth_src_mac;
wire [15:0] tx_tcp_eth_type;
wire [3:0]  tx_tcp_ip_version;
wire [3:0]  tx_tcp_ip_ihl;
wire [5:0]  tx_tcp_ip_dscp;
wire [1:0]  tx_tcp_ip_ecn;
wire [15:0] tx_tcp_ip_identification;
wire [2:0]  tx_tcp_ip_flags;
wire [12:0] tx_tcp_ip_fragment_offset;
wire [7:0]  tx_tcp_ip_ttl;
wire [15:0] tx_tcp_ip_header_checksum;
wire [31:0] tx_tcp_ip_source_ip;
wire [31:0] tx_tcp_ip_dest_ip;
wire [15:0] tx_tcp_source_port;
wire [15:0] tx_tcp_dest_port;
wire [31:0] tx_tcp_seq_num;
wire [31:0] tx_tcp_ack_num;
wire [3:0]  tx_tcp_data_offset;
wire [2:0]  tx_tcp_reserved;
wire [8:0]  tx_tcp_flags;
wire [15:0] tx_tcp_window;
wire [15:0] tx_tcp_checksum;
wire [15:0] tx_tcp_urgent_pointer;
wire [15:0] tx_tcp_length;
wire [63:0] tx_tcp_payload_axis_tdata;
wire [7:0]  tx_tcp_payload_axis_tkeep;
wire        tx_tcp_payload_axis_tvalid;
wire        tx_tcp_payload_axis_tready;
wire        tx_tcp_payload_axis_tlast;
wire        tx_tcp_payload_axis_tuser;

tcp_ip_rx_64
tcp_ip_rx_64_inst (
    .clk(clk),
    .rst(rst),
    // IP frame input
    .s_ip_hdr_valid(s_ip_hdr_valid),
    .s_ip_hdr_ready(s_ip_hdr_ready),
    .s_eth_dest_mac(s_ip_eth_dest_mac),
    .s_eth_src_mac(s_ip_eth_src_mac),
    .s_eth_type(s_ip_eth_type),
    .s_ip_version(s_ip_version),
    .s_ip_ihl(s_ip_ihl),
    .s_ip_dscp(s_ip_dscp),
    .s_ip_ecn(s_ip_ecn),
    .s_ip_length(s_ip_length),
    .s_ip_identification(s_ip_identification),
    .s_ip_flags(s_ip_flags),
    .s_ip_fragment_offset(s_ip_fragment_offset),
    .s_ip_ttl(s_ip_ttl),
    .s_ip_protocol(s_ip_protocol),
    .s_ip_header_checksum(s_ip_header_checksum),
    .s_ip_source_ip(s_ip_source_ip),
    .s_ip_dest_ip(s_ip_dest_ip),
    .s_ip_payload_axis_tdata(s_ip_payload_axis_tdata),
    .s_ip_payload_axis_tkeep(s_ip_payload_axis_tkeep),
    .s_ip_payload_axis_tvalid(s_ip_payload_axis_tvalid),
    .s_ip_payload_axis_tready(s_ip_payload_axis_tready),
    .s_ip_payload_axis_tlast(s_ip_payload_axis_tlast),
    .s_ip_payload_axis_tuser(s_ip_payload_axis_tuser),
    // TCP frame output
    .m_tcp_hdr_valid(m_tcp_hdr_valid),
    .m_tcp_hdr_ready(m_tcp_hdr_ready),
    .m_eth_dest_mac(m_tcp_eth_dest_mac),
    .m_eth_src_mac(m_tcp_eth_src_mac),
    .m_eth_type(m_tcp_eth_type),
    .m_ip_version(m_tcp_ip_version),
    .m_ip_ihl(m_tcp_ip_ihl),
    .m_ip_dscp(m_tcp_ip_dscp),
    .m_ip_ecn(m_tcp_ip_ecn),
    .m_ip_length(m_tcp_ip_length),
    .m_ip_identification(m_tcp_ip_identification),
    .m_ip_flags(m_tcp_ip_flags),
    .m_ip_fragment_offset(m_tcp_ip_fragment_offset),
    .m_ip_ttl(m_tcp_ip_ttl),
    .m_ip_protocol(m_tcp_ip_protocol),
    .m_ip_header_checksum(m_tcp_ip_header_checksum),
    .m_ip_source_ip(m_tcp_ip_source_ip),
    .m_ip_dest_ip(m_tcp_ip_dest_ip),
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
    // Status signals
    .busy(rx_busy),
    .error_header_early_termination(rx_error_header_early_termination),
    .error_payload_early_termination(rx_error_payload_early_termination)
);

generate

if (CHECKSUM_GEN_ENABLE) begin

    tcp_checksum_gen_64 #(
        .PAYLOAD_FIFO_DEPTH(CHECKSUM_PAYLOAD_FIFO_DEPTH),
        .HEADER_FIFO_DEPTH(CHECKSUM_HEADER_FIFO_DEPTH)
    )
    tcp_checksum_gen_64_inst (
        .clk(clk),
        .rst(rst),
        // TCP frame input
        .s_tcp_hdr_valid(s_tcp_hdr_valid),
        .s_tcp_hdr_ready(s_tcp_hdr_ready),
        .s_eth_dest_mac(s_tcp_eth_dest_mac),
        .s_eth_src_mac(s_tcp_eth_src_mac),
        .s_eth_type(s_tcp_eth_type),
        .s_ip_version(s_tcp_ip_version),
        .s_ip_ihl(s_tcp_ip_ihl),
        .s_ip_dscp(s_tcp_ip_dscp),
        .s_ip_ecn(s_tcp_ip_ecn),
        .s_ip_identification(s_tcp_ip_identification),
        .s_ip_flags(s_tcp_ip_flags),
        .s_ip_fragment_offset(s_tcp_ip_fragment_offset),
        .s_ip_ttl(s_tcp_ip_ttl),
        .s_ip_header_checksum(s_tcp_ip_header_checksum),
        .s_ip_source_ip(s_tcp_ip_source_ip),
        .s_ip_dest_ip(s_tcp_ip_dest_ip),
        .s_tcp_source_port(s_tcp_source_port),
        .s_tcp_dest_port(s_tcp_dest_port),
        .s_tcp_seq_num(s_tcp_seq_num),
        .s_tcp_ack_num(s_tcp_ack_num),
        .s_tcp_data_offset(s_tcp_data_offset),
        .s_tcp_reserved(s_tcp_reserved),
        .s_tcp_flags(s_tcp_flags),
        .s_tcp_window(s_tcp_window),
        .s_tcp_urgent_pointer(s_tcp_urgent_pointer),
        .s_tcp_length(s_tcp_length),
        .s_tcp_payload_axis_tdata(s_tcp_payload_axis_tdata),
        .s_tcp_payload_axis_tkeep(s_tcp_payload_axis_tkeep),
        .s_tcp_payload_axis_tvalid(s_tcp_payload_axis_tvalid),
        .s_tcp_payload_axis_tready(s_tcp_payload_axis_tready),
        .s_tcp_payload_axis_tlast(s_tcp_payload_axis_tlast),
        .s_tcp_payload_axis_tuser(s_tcp_payload_axis_tuser),
        // TCP frame output
        .m_tcp_hdr_valid(tx_tcp_hdr_valid),
        .m_tcp_hdr_ready(tx_tcp_hdr_ready),
        .m_eth_dest_mac(tx_tcp_eth_dest_mac),
        .m_eth_src_mac(tx_tcp_eth_src_mac),
        .m_eth_type(tx_tcp_eth_type),
        .m_ip_version(tx_tcp_ip_version),
        .m_ip_ihl(tx_tcp_ip_ihl),
        .m_ip_dscp(tx_tcp_ip_dscp),
        .m_ip_ecn(tx_tcp_ip_ecn),
        .m_ip_length(),
        .m_ip_identification(tx_tcp_ip_identification),
        .m_ip_flags(tx_tcp_ip_flags),
        .m_ip_fragment_offset(tx_tcp_ip_fragment_offset),
        .m_ip_ttl(tx_tcp_ip_ttl),
        .m_ip_protocol(),
        .m_ip_header_checksum(tx_tcp_ip_header_checksum),
        .m_ip_source_ip(tx_tcp_ip_source_ip),
        .m_ip_dest_ip(tx_tcp_ip_dest_ip),
        .m_tcp_source_port(tx_tcp_source_port),
        .m_tcp_dest_port(tx_tcp_dest_port),
        .m_tcp_seq_num(tx_tcp_seq_num),
        .m_tcp_ack_num(tx_tcp_ack_num),
        .m_tcp_data_offset(tx_tcp_data_offset),
        .m_tcp_reserved(tx_tcp_reserved),
        .m_tcp_flags(tx_tcp_flags),
        .m_tcp_window(tx_tcp_window),
        .m_tcp_checksum(tx_tcp_checksum),
        .m_tcp_urgent_pointer(tx_tcp_urgent_pointer),
        .m_tcp_length(tx_tcp_length),
        .m_tcp_payload_axis_tdata(tx_tcp_payload_axis_tdata),
        .m_tcp_payload_axis_tkeep(tx_tcp_payload_axis_tkeep),
        .m_tcp_payload_axis_tvalid(tx_tcp_payload_axis_tvalid),
        .m_tcp_payload_axis_tready(tx_tcp_payload_axis_tready),
        .m_tcp_payload_axis_tlast(tx_tcp_payload_axis_tlast),
        .m_tcp_payload_axis_tuser(tx_tcp_payload_axis_tuser),
        // Status signals
        .busy()
    );

end else begin

    assign tx_tcp_hdr_valid = s_tcp_hdr_valid;
    assign s_tcp_hdr_ready = tx_tcp_hdr_ready;
    assign tx_tcp_eth_dest_mac = s_tcp_eth_dest_mac;
    assign tx_tcp_eth_src_mac = s_tcp_eth_src_mac;
    assign tx_tcp_eth_type = s_tcp_eth_type;
    assign tx_tcp_ip_version = s_tcp_ip_version;
    assign tx_tcp_ip_ihl = s_tcp_ip_ihl;
    assign tx_tcp_ip_dscp = s_tcp_ip_dscp;
    assign tx_tcp_ip_ecn = s_tcp_ip_ecn;
    assign tx_tcp_ip_identification = s_tcp_ip_identification;
    assign tx_tcp_ip_flags = s_tcp_ip_flags;
    assign tx_tcp_ip_fragment_offset = s_tcp_ip_fragment_offset;
    assign tx_tcp_ip_ttl = s_tcp_ip_ttl;
    assign tx_tcp_ip_header_checksum = s_tcp_ip_header_checksum;
    assign tx_tcp_ip_source_ip = s_tcp_ip_source_ip;
    assign tx_tcp_ip_dest_ip = s_tcp_ip_dest_ip;
    assign tx_tcp_source_port = s_tcp_source_port;
    assign tx_tcp_dest_port = s_tcp_dest_port;
    assign tx_tcp_seq_num = s_tcp_seq_num;
    assign tx_tcp_ack_num = s_tcp_ack_num;
    assign tx_tcp_data_offset = s_tcp_data_offset;
    assign tx_tcp_reserved = s_tcp_reserved;
    assign tx_tcp_flags = s_tcp_flags;
    assign tx_tcp_window = s_tcp_window;
    assign tx_tcp_checksum = s_tcp_checksum;
    assign tx_tcp_urgent_pointer = s_tcp_urgent_pointer;
    assign tx_tcp_length = s_tcp_length;
    assign tx_tcp_payload_axis_tdata = s_tcp_payload_axis_tdata;
    assign tx_tcp_payload_axis_tkeep = s_tcp_payload_axis_tkeep;
    assign tx_tcp_payload_axis_tvalid = s_tcp_payload_axis_tvalid;
    assign s_tcp_payload_axis_tready = tx_tcp_payload_axis_tready;
    assign tx_tcp_payload_axis_tlast = s_tcp_payload_axis_tlast;
    assign tx_tcp_payload_axis_tuser = s_tcp_payload_axis_tuser;

end

endgenerate

tcp_ip_tx_64
tcp_ip_tx_64_inst (
    .clk(clk),
    .rst(rst),
    // TCP frame input
    .s_tcp_hdr_valid(tx_tcp_hdr_valid),
    .s_tcp_hdr_ready(tx_tcp_hdr_ready),
    .s_eth_dest_mac(tx_tcp_eth_dest_mac),
    .s_eth_src_mac(tx_tcp_eth_src_mac),
    .s_eth_type(tx_tcp_eth_type),
    .s_ip_version(tx_tcp_ip_version),
    .s_ip_ihl(tx_tcp_ip_ihl),
    .s_ip_dscp(tx_tcp_ip_dscp),
    .s_ip_ecn(tx_tcp_ip_ecn),
    .s_ip_identification(tx_tcp_ip_identification),
    .s_ip_flags(tx_tcp_ip_flags),
    .s_ip_fragment_offset(tx_tcp_ip_fragment_offset),
    .s_ip_ttl(tx_tcp_ip_ttl),
    .s_ip_protocol(8'h06),
    .s_ip_header_checksum(tx_tcp_ip_header_checksum),
    .s_ip_source_ip(tx_tcp_ip_source_ip),
    .s_ip_dest_ip(tx_tcp_ip_dest_ip),
    .s_tcp_source_port(tx_tcp_source_port),
    .s_tcp_dest_port(tx_tcp_dest_port),
    .s_tcp_seq_num(tx_tcp_seq_num),
    .s_tcp_ack_num(tx_tcp_ack_num),
    .s_tcp_data_offset(tx_tcp_data_offset),
    .s_tcp_reserved(tx_tcp_reserved),
    .s_tcp_flags(tx_tcp_flags),
    .s_tcp_window(tx_tcp_window),
    .s_tcp_checksum(tx_tcp_checksum),
    .s_tcp_urgent_pointer(tx_tcp_urgent_pointer),
    .s_tcp_length(tx_tcp_length),
    .s_tcp_payload_axis_tdata(tx_tcp_payload_axis_tdata),
    .s_tcp_payload_axis_tkeep(tx_tcp_payload_axis_tkeep),
    .s_tcp_payload_axis_tvalid(tx_tcp_payload_axis_tvalid),
    .s_tcp_payload_axis_tready(tx_tcp_payload_axis_tready),
    .s_tcp_payload_axis_tlast(tx_tcp_payload_axis_tlast),
    .s_tcp_payload_axis_tuser(tx_tcp_payload_axis_tuser),
    // IP frame output
    .m_ip_hdr_valid(m_ip_hdr_valid),
    .m_ip_hdr_ready(m_ip_hdr_ready),
    .m_eth_dest_mac(m_ip_eth_dest_mac),
    .m_eth_src_mac(m_ip_eth_src_mac),
    .m_eth_type(m_ip_eth_type),
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
    // Status signals
    .busy(tx_busy),
    .error_payload_early_termination(tx_error_payload_early_termination)
);

endmodule

`resetall
