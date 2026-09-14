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
 * TCP checksum calculation module (64 bit datapath)
 */
module tcp_checksum_gen_64 #
(
    parameter PAYLOAD_FIFO_DEPTH = 2048,
    parameter HEADER_FIFO_DEPTH = 8
)
(
    input  wire        clk,
    input  wire        rst,

    /*
     * TCP frame input
     */
    input  wire        s_tcp_hdr_valid,
    output wire        s_tcp_hdr_ready,
    input  wire [47:0] s_eth_dest_mac,
    input  wire [47:0] s_eth_src_mac,
    input  wire [15:0] s_eth_type,
    input  wire [3:0]  s_ip_version,
    input  wire [3:0]  s_ip_ihl,
    input  wire [5:0]  s_ip_dscp,
    input  wire [1:0]  s_ip_ecn,
    input  wire [15:0] s_ip_identification,
    input  wire [2:0]  s_ip_flags,
    input  wire [12:0] s_ip_fragment_offset,
    input  wire [7:0]  s_ip_ttl,
    input  wire [15:0] s_ip_header_checksum,
    input  wire [31:0] s_ip_source_ip,
    input  wire [31:0] s_ip_dest_ip,
    input  wire [15:0] s_tcp_source_port,
    input  wire [15:0] s_tcp_dest_port,
    input  wire [31:0] s_tcp_seq_num,
    input  wire [31:0] s_tcp_ack_num,
    input  wire [3:0]  s_tcp_data_offset,
    input  wire [2:0]  s_tcp_reserved,
    input  wire [8:0]  s_tcp_flags,
    input  wire [15:0] s_tcp_window,
    input  wire [15:0] s_tcp_urgent_pointer,
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
    output wire [47:0] m_eth_dest_mac,
    output wire [47:0] m_eth_src_mac,
    output wire [15:0] m_eth_type,
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
    output wire [15:0] m_tcp_length,
    output wire [63:0] m_tcp_payload_axis_tdata,
    output wire [7:0]  m_tcp_payload_axis_tkeep,
    output wire        m_tcp_payload_axis_tvalid,
    input  wire        m_tcp_payload_axis_tready,
    output wire        m_tcp_payload_axis_tlast,
    output wire        m_tcp_payload_axis_tuser,

    /*
     * Status signals
     */
    output wire        busy
);

/*

TCP Frame

 Field                       Length
 Destination MAC address     6 octets
 Source MAC address          6 octets
 Ethertype (0x0800)          2 octets
 Version (4)                 4 bits
 IHL (5-15)                  4 bits
 DSCP (0)                    6 bits
 ECN (0)                     2 bits
 length                      2 octets
 identification (0?)         2 octets
 flags (010)                 3 bits
 fragment offset (0)         13 bits
 time to live (64?)          1 octet
 protocol                    1 octet
 header checksum             2 octets
 source IP                   4 octets
 destination IP              4 octets
 options                     (IHL-5)*4 octets

 source port                 2 octets
 destination port            2 octets
 sequence number              4 octets
 acknowledgment number       4 octets
 data offset (5)             4 bits
 reserved (0)                3 bits
 flags                       9 bits
 window                      2 octets
 checksum                    2 octets
 urgent pointer              2 octets

 payload                     length octets

This module receives a TCP frame with header fields in parallel and payload on
an AXI stream interface, calculates the TCP segment length (header plus
payload) and the mandatory TCP checksum over the IP pseudo header, the TCP
header, and the payload, then produces the header fields in parallel along
with the TCP payload in a separate AXI stream.

Unlike UDP, TCP's own header carries no self-declared length field, so
(unlike udp_checksum_gen_64.v, where the UDP length field is counted twice -
once in the pseudo header, once in the real header - requiring the payload
sum to add 2 per byte) the TCP segment length here is only counted once, in
the pseudo header, requiring only 1 per byte.

The header-field summation is done directly on the parallel header fields
(the same way it is done in tcp_checksum_gen.v, unaffected by datapath
width); only the payload summation loop is 64 bit datapath specific,
summing up to 8 tkeep-masked bytes per cycle instead of one byte per cycle.

*/

parameter HEADER_FIFO_ADDR_WIDTH = $clog2(HEADER_FIFO_DEPTH);

localparam [3:0]
    STATE_IDLE = 4'd0,
    STATE_SUM_HEADER_1 = 4'd1,
    STATE_SUM_HEADER_2 = 4'd2,
    STATE_SUM_HEADER_3 = 4'd3,
    STATE_SUM_HEADER_4 = 4'd4,
    STATE_SUM_HEADER_5 = 4'd5,
    STATE_SUM_HEADER_6 = 4'd6,
    STATE_SUM_HEADER_7 = 4'd7,
    STATE_SUM_PAYLOAD = 4'd8,
    STATE_FINISH_SUM = 4'd9;

reg [3:0] state_reg = STATE_IDLE, state_next;

// datapath control signals
reg store_tcp_hdr;
reg shift_payload_in;
reg [31:0] checksum_part;
reg [31:0] checksum_sum;

reg [15:0] frame_ptr_reg = 16'd0, frame_ptr_next;

reg [31:0] checksum_reg = 32'd0, checksum_next;

reg [47:0] eth_dest_mac_reg = 48'd0;
reg [47:0] eth_src_mac_reg = 48'd0;
reg [15:0] eth_type_reg = 16'd0;
reg [3:0]  ip_version_reg = 4'd0;
reg [3:0]  ip_ihl_reg = 4'd0;
reg [5:0]  ip_dscp_reg = 6'd0;
reg [1:0]  ip_ecn_reg = 2'd0;
reg [15:0] ip_identification_reg = 16'd0;
reg [2:0]  ip_flags_reg = 3'd0;
reg [12:0] ip_fragment_offset_reg = 13'd0;
reg [7:0]  ip_ttl_reg = 8'd0;
reg [15:0] ip_header_checksum_reg = 16'd0;
reg [31:0] ip_source_ip_reg = 32'd0;
reg [31:0] ip_dest_ip_reg = 32'd0;
reg [15:0] tcp_source_port_reg = 16'd0;
reg [15:0] tcp_dest_port_reg = 16'd0;
reg [31:0] tcp_seq_num_reg = 32'd0;
reg [31:0] tcp_ack_num_reg = 32'd0;
reg [3:0]  tcp_data_offset_reg = 4'd0;
reg [2:0]  tcp_reserved_reg = 3'd0;
reg [8:0]  tcp_flags_reg = 9'd0;
reg [15:0] tcp_window_reg = 16'd0;
reg [15:0] tcp_urgent_pointer_reg = 16'd0;

reg hdr_valid_reg = 0, hdr_valid_next;

reg s_tcp_hdr_ready_reg = 1'b0, s_tcp_hdr_ready_next;
reg s_tcp_payload_axis_tready_reg = 1'b0, s_tcp_payload_axis_tready_next;

reg busy_reg = 1'b0;

/*
 * TCP Payload FIFO
 */
wire [63:0] s_tcp_payload_fifo_tdata;
wire [7:0] s_tcp_payload_fifo_tkeep;
wire s_tcp_payload_fifo_tvalid;
wire s_tcp_payload_fifo_tready;
wire s_tcp_payload_fifo_tlast;
wire s_tcp_payload_fifo_tuser;

wire [63:0] m_tcp_payload_fifo_tdata;
wire [7:0] m_tcp_payload_fifo_tkeep;
wire m_tcp_payload_fifo_tvalid;
wire m_tcp_payload_fifo_tready;
wire m_tcp_payload_fifo_tlast;
wire m_tcp_payload_fifo_tuser;

axis_fifo #(
    .DEPTH(PAYLOAD_FIFO_DEPTH),
    .DATA_WIDTH(64),
    .KEEP_ENABLE(1),
    .KEEP_WIDTH(8),
    .LAST_ENABLE(1),
    .ID_ENABLE(0),
    .DEST_ENABLE(0),
    .USER_ENABLE(1),
    .USER_WIDTH(1),
    .FRAME_FIFO(0)
)
payload_fifo (
    .clk(clk),
    .rst(rst),
    // AXI input
    .s_axis_tdata(s_tcp_payload_fifo_tdata),
    .s_axis_tkeep(s_tcp_payload_fifo_tkeep),
    .s_axis_tvalid(s_tcp_payload_fifo_tvalid),
    .s_axis_tready(s_tcp_payload_fifo_tready),
    .s_axis_tlast(s_tcp_payload_fifo_tlast),
    .s_axis_tid(0),
    .s_axis_tdest(0),
    .s_axis_tuser(s_tcp_payload_fifo_tuser),
    // AXI output
    .m_axis_tdata(m_tcp_payload_fifo_tdata),
    .m_axis_tkeep(m_tcp_payload_fifo_tkeep),
    .m_axis_tvalid(m_tcp_payload_fifo_tvalid),
    .m_axis_tready(m_tcp_payload_fifo_tready),
    .m_axis_tlast(m_tcp_payload_fifo_tlast),
    .m_axis_tid(),
    .m_axis_tdest(),
    .m_axis_tuser(m_tcp_payload_fifo_tuser),
    // Status
    .status_overflow(),
    .status_bad_frame(),
    .status_good_frame()
);

assign s_tcp_payload_fifo_tdata = s_tcp_payload_axis_tdata;
assign s_tcp_payload_fifo_tkeep = s_tcp_payload_axis_tkeep;
assign s_tcp_payload_fifo_tvalid = s_tcp_payload_axis_tvalid && shift_payload_in;
assign s_tcp_payload_axis_tready = s_tcp_payload_fifo_tready && shift_payload_in;
assign s_tcp_payload_fifo_tlast = s_tcp_payload_axis_tlast;
assign s_tcp_payload_fifo_tuser = s_tcp_payload_axis_tuser;

assign m_tcp_payload_axis_tdata = m_tcp_payload_fifo_tdata;
assign m_tcp_payload_axis_tkeep = m_tcp_payload_fifo_tkeep;
assign m_tcp_payload_axis_tvalid = m_tcp_payload_fifo_tvalid;
assign m_tcp_payload_fifo_tready = m_tcp_payload_axis_tready;
assign m_tcp_payload_axis_tlast = m_tcp_payload_fifo_tlast;
assign m_tcp_payload_axis_tuser = m_tcp_payload_fifo_tuser;

/*
 * TCP Header FIFO
 */
reg [HEADER_FIFO_ADDR_WIDTH:0] header_fifo_wr_ptr_reg = {HEADER_FIFO_ADDR_WIDTH+1{1'b0}}, header_fifo_wr_ptr_next;
reg [HEADER_FIFO_ADDR_WIDTH:0] header_fifo_rd_ptr_reg = {HEADER_FIFO_ADDR_WIDTH+1{1'b0}}, header_fifo_rd_ptr_next;

reg [47:0] eth_dest_mac_mem[(2**HEADER_FIFO_ADDR_WIDTH)-1:0];
reg [47:0] eth_src_mac_mem[(2**HEADER_FIFO_ADDR_WIDTH)-1:0];
reg [15:0] eth_type_mem[(2**HEADER_FIFO_ADDR_WIDTH)-1:0];
reg [3:0] ip_version_mem[(2**HEADER_FIFO_ADDR_WIDTH)-1:0];
reg [3:0] ip_ihl_mem[(2**HEADER_FIFO_ADDR_WIDTH)-1:0];
reg [5:0] ip_dscp_mem[(2**HEADER_FIFO_ADDR_WIDTH)-1:0];
reg [1:0] ip_ecn_mem[(2**HEADER_FIFO_ADDR_WIDTH)-1:0];
reg [15:0] ip_identification_mem[(2**HEADER_FIFO_ADDR_WIDTH)-1:0];
reg [2:0] ip_flags_mem[(2**HEADER_FIFO_ADDR_WIDTH)-1:0];
reg [12:0] ip_fragment_offset_mem[(2**HEADER_FIFO_ADDR_WIDTH)-1:0];
reg [7:0] ip_ttl_mem[(2**HEADER_FIFO_ADDR_WIDTH)-1:0];
reg [15:0] ip_header_checksum_mem[(2**HEADER_FIFO_ADDR_WIDTH)-1:0];
reg [31:0] ip_source_ip_mem[(2**HEADER_FIFO_ADDR_WIDTH)-1:0];
reg [31:0] ip_dest_ip_mem[(2**HEADER_FIFO_ADDR_WIDTH)-1:0];
reg [15:0] tcp_source_port_mem[(2**HEADER_FIFO_ADDR_WIDTH)-1:0];
reg [15:0] tcp_dest_port_mem[(2**HEADER_FIFO_ADDR_WIDTH)-1:0];
reg [31:0] tcp_seq_num_mem[(2**HEADER_FIFO_ADDR_WIDTH)-1:0];
reg [31:0] tcp_ack_num_mem[(2**HEADER_FIFO_ADDR_WIDTH)-1:0];
reg [3:0] tcp_data_offset_mem[(2**HEADER_FIFO_ADDR_WIDTH)-1:0];
reg [2:0] tcp_reserved_mem[(2**HEADER_FIFO_ADDR_WIDTH)-1:0];
reg [8:0] tcp_flags_mem[(2**HEADER_FIFO_ADDR_WIDTH)-1:0];
reg [15:0] tcp_window_mem[(2**HEADER_FIFO_ADDR_WIDTH)-1:0];
reg [15:0] tcp_urgent_pointer_mem[(2**HEADER_FIFO_ADDR_WIDTH)-1:0];
reg [15:0] tcp_length_mem[(2**HEADER_FIFO_ADDR_WIDTH)-1:0];
reg [15:0] tcp_checksum_mem[(2**HEADER_FIFO_ADDR_WIDTH)-1:0];

reg [47:0] m_eth_dest_mac_reg = 48'd0;
reg [47:0] m_eth_src_mac_reg = 48'd0;
reg [15:0] m_eth_type_reg = 16'd0;
reg [3:0]  m_ip_version_reg = 4'd0;
reg [3:0]  m_ip_ihl_reg = 4'd0;
reg [5:0]  m_ip_dscp_reg = 6'd0;
reg [1:0]  m_ip_ecn_reg = 2'd0;
reg [15:0] m_ip_identification_reg = 16'd0;
reg [2:0]  m_ip_flags_reg = 3'd0;
reg [12:0] m_ip_fragment_offset_reg = 13'd0;
reg [7:0]  m_ip_ttl_reg = 8'd0;
reg [15:0] m_ip_header_checksum_reg = 16'd0;
reg [31:0] m_ip_source_ip_reg = 32'd0;
reg [31:0] m_ip_dest_ip_reg = 32'd0;
reg [15:0] m_tcp_source_port_reg = 16'd0;
reg [15:0] m_tcp_dest_port_reg = 16'd0;
reg [31:0] m_tcp_seq_num_reg = 32'd0;
reg [31:0] m_tcp_ack_num_reg = 32'd0;
reg [3:0]  m_tcp_data_offset_reg = 4'd0;
reg [2:0]  m_tcp_reserved_reg = 3'd0;
reg [8:0]  m_tcp_flags_reg = 9'd0;
reg [15:0] m_tcp_window_reg = 16'd0;
reg [15:0] m_tcp_urgent_pointer_reg = 16'd0;
reg [15:0] m_tcp_length_reg = 16'd0;
reg [15:0] m_tcp_checksum_reg = 16'd0;

reg m_tcp_hdr_valid_reg = 1'b0, m_tcp_hdr_valid_next;

// full when first MSB different but rest same
wire header_fifo_full = ((header_fifo_wr_ptr_reg[HEADER_FIFO_ADDR_WIDTH] != header_fifo_rd_ptr_reg[HEADER_FIFO_ADDR_WIDTH]) &&
                         (header_fifo_wr_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0] == header_fifo_rd_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]));
// empty when pointers match exactly
wire header_fifo_empty = header_fifo_wr_ptr_reg == header_fifo_rd_ptr_reg;

// control signals
reg header_fifo_write;
reg header_fifo_read;

wire header_fifo_ready = !header_fifo_full;

assign m_tcp_hdr_valid = m_tcp_hdr_valid_reg;

assign m_eth_dest_mac = m_eth_dest_mac_reg;
assign m_eth_src_mac = m_eth_src_mac_reg;
assign m_eth_type = m_eth_type_reg;
assign m_ip_version = m_ip_version_reg;
assign m_ip_ihl = m_ip_ihl_reg;
assign m_ip_dscp = m_ip_dscp_reg;
assign m_ip_ecn = m_ip_ecn_reg;
assign m_ip_length = m_tcp_length_reg + 16'd20;
assign m_ip_identification = m_ip_identification_reg;
assign m_ip_flags = m_ip_flags_reg;
assign m_ip_fragment_offset = m_ip_fragment_offset_reg;
assign m_ip_ttl = m_ip_ttl_reg;
assign m_ip_protocol = 8'h06;
assign m_ip_header_checksum = m_ip_header_checksum_reg;
assign m_ip_source_ip = m_ip_source_ip_reg;
assign m_ip_dest_ip = m_ip_dest_ip_reg;
assign m_tcp_source_port = m_tcp_source_port_reg;
assign m_tcp_dest_port = m_tcp_dest_port_reg;
assign m_tcp_seq_num = m_tcp_seq_num_reg;
assign m_tcp_ack_num = m_tcp_ack_num_reg;
assign m_tcp_data_offset = m_tcp_data_offset_reg;
assign m_tcp_reserved = m_tcp_reserved_reg;
assign m_tcp_flags = m_tcp_flags_reg;
assign m_tcp_window = m_tcp_window_reg;
assign m_tcp_urgent_pointer = m_tcp_urgent_pointer_reg;
assign m_tcp_length = m_tcp_length_reg;
assign m_tcp_checksum = m_tcp_checksum_reg;

// Write logic
always @* begin
    header_fifo_write = 1'b0;

    header_fifo_wr_ptr_next = header_fifo_wr_ptr_reg;

    if (hdr_valid_reg) begin
        // input data valid
        if (~header_fifo_full) begin
            // not full, perform write
            header_fifo_write = 1'b1;
            header_fifo_wr_ptr_next = header_fifo_wr_ptr_reg + 1;
        end
    end
end

always @(posedge clk) begin
    if (rst) begin
        header_fifo_wr_ptr_reg <= {HEADER_FIFO_ADDR_WIDTH+1{1'b0}};
    end else begin
        header_fifo_wr_ptr_reg <= header_fifo_wr_ptr_next;
    end

    if (header_fifo_write) begin
        eth_dest_mac_mem[header_fifo_wr_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]] <= eth_dest_mac_reg;
        eth_src_mac_mem[header_fifo_wr_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]] <= eth_src_mac_reg;
        eth_type_mem[header_fifo_wr_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]] <= eth_type_reg;
        ip_version_mem[header_fifo_wr_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]] <= ip_version_reg;
        ip_ihl_mem[header_fifo_wr_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]] <= ip_ihl_reg;
        ip_dscp_mem[header_fifo_wr_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]] <= ip_dscp_reg;
        ip_ecn_mem[header_fifo_wr_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]] <= ip_ecn_reg;
        ip_identification_mem[header_fifo_wr_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]] <= ip_identification_reg;
        ip_flags_mem[header_fifo_wr_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]] <= ip_flags_reg;
        ip_fragment_offset_mem[header_fifo_wr_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]] <= ip_fragment_offset_reg;
        ip_ttl_mem[header_fifo_wr_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]] <= ip_ttl_reg;
        ip_header_checksum_mem[header_fifo_wr_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]] <= ip_header_checksum_reg;
        ip_source_ip_mem[header_fifo_wr_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]] <= ip_source_ip_reg;
        ip_dest_ip_mem[header_fifo_wr_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]] <= ip_dest_ip_reg;
        tcp_source_port_mem[header_fifo_wr_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]] <= tcp_source_port_reg;
        tcp_dest_port_mem[header_fifo_wr_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]] <= tcp_dest_port_reg;
        tcp_seq_num_mem[header_fifo_wr_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]] <= tcp_seq_num_reg;
        tcp_ack_num_mem[header_fifo_wr_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]] <= tcp_ack_num_reg;
        tcp_data_offset_mem[header_fifo_wr_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]] <= tcp_data_offset_reg;
        tcp_reserved_mem[header_fifo_wr_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]] <= tcp_reserved_reg;
        tcp_flags_mem[header_fifo_wr_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]] <= tcp_flags_reg;
        tcp_window_mem[header_fifo_wr_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]] <= tcp_window_reg;
        tcp_urgent_pointer_mem[header_fifo_wr_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]] <= tcp_urgent_pointer_reg;
        tcp_length_mem[header_fifo_wr_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]] <= frame_ptr_reg;
        tcp_checksum_mem[header_fifo_wr_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]] <= checksum_reg[15:0];
    end
end

// Read logic
always @* begin
    header_fifo_read = 1'b0;

    header_fifo_rd_ptr_next = header_fifo_rd_ptr_reg;

    m_tcp_hdr_valid_next = m_tcp_hdr_valid_reg;

    if (m_tcp_hdr_ready || !m_tcp_hdr_valid) begin
        // output data not valid OR currently being transferred
        if (!header_fifo_empty) begin
            // not empty, perform read
            header_fifo_read = 1'b1;
            m_tcp_hdr_valid_next = 1'b1;
            header_fifo_rd_ptr_next = header_fifo_rd_ptr_reg + 1;
        end else begin
            // empty, invalidate
            m_tcp_hdr_valid_next = 1'b0;
        end
    end
end

always @(posedge clk) begin
    if (rst) begin
        header_fifo_rd_ptr_reg <= {HEADER_FIFO_ADDR_WIDTH+1{1'b0}};
        m_tcp_hdr_valid_reg <= 1'b0;
    end else begin
        header_fifo_rd_ptr_reg <= header_fifo_rd_ptr_next;
        m_tcp_hdr_valid_reg <= m_tcp_hdr_valid_next;
    end

    if (header_fifo_read) begin
        m_eth_dest_mac_reg <= eth_dest_mac_mem[header_fifo_rd_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]];
        m_eth_src_mac_reg <= eth_src_mac_mem[header_fifo_rd_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]];
        m_eth_type_reg <= eth_type_mem[header_fifo_rd_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]];
        m_ip_version_reg <= ip_version_mem[header_fifo_rd_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]];
        m_ip_ihl_reg <= ip_ihl_mem[header_fifo_rd_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]];
        m_ip_dscp_reg <= ip_dscp_mem[header_fifo_rd_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]];
        m_ip_ecn_reg <= ip_ecn_mem[header_fifo_rd_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]];
        m_ip_identification_reg <= ip_identification_mem[header_fifo_rd_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]];
        m_ip_flags_reg <= ip_flags_mem[header_fifo_rd_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]];
        m_ip_fragment_offset_reg <= ip_fragment_offset_mem[header_fifo_rd_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]];
        m_ip_ttl_reg <= ip_ttl_mem[header_fifo_rd_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]];
        m_ip_header_checksum_reg <= ip_header_checksum_mem[header_fifo_rd_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]];
        m_ip_source_ip_reg <= ip_source_ip_mem[header_fifo_rd_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]];
        m_ip_dest_ip_reg <= ip_dest_ip_mem[header_fifo_rd_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]];
        m_tcp_source_port_reg <= tcp_source_port_mem[header_fifo_rd_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]];
        m_tcp_dest_port_reg <= tcp_dest_port_mem[header_fifo_rd_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]];
        m_tcp_seq_num_reg <= tcp_seq_num_mem[header_fifo_rd_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]];
        m_tcp_ack_num_reg <= tcp_ack_num_mem[header_fifo_rd_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]];
        m_tcp_data_offset_reg <= tcp_data_offset_mem[header_fifo_rd_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]];
        m_tcp_reserved_reg <= tcp_reserved_mem[header_fifo_rd_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]];
        m_tcp_flags_reg <= tcp_flags_mem[header_fifo_rd_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]];
        m_tcp_window_reg <= tcp_window_mem[header_fifo_rd_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]];
        m_tcp_urgent_pointer_reg <= tcp_urgent_pointer_mem[header_fifo_rd_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]];
        m_tcp_length_reg <= tcp_length_mem[header_fifo_rd_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]];
        m_tcp_checksum_reg <= tcp_checksum_mem[header_fifo_rd_ptr_reg[HEADER_FIFO_ADDR_WIDTH-1:0]];
    end
end

assign s_tcp_hdr_ready = s_tcp_hdr_ready_reg;

assign busy = busy_reg;

integer i;
reg [3:0] word_cnt;

always @* begin
    state_next = STATE_IDLE;

    s_tcp_hdr_ready_next = 1'b0;
    s_tcp_payload_axis_tready_next = 1'b0;

    store_tcp_hdr = 1'b0;
    shift_payload_in = 1'b0;

    frame_ptr_next = frame_ptr_reg;
    checksum_next = checksum_reg;

    hdr_valid_next = 1'b0;

    case (state_reg)
        STATE_IDLE: begin
            // idle state
            s_tcp_hdr_ready_next = header_fifo_ready;

            if (s_tcp_hdr_ready && s_tcp_hdr_valid) begin
                store_tcp_hdr = 1'b1;
                frame_ptr_next = 0;
                // 16'h0006 = zero padded protocol field (6 = TCP)
                // 16'd20   = base TCP header length (no options) contribution
                //            to the pseudo header's TCP length field; unlike
                //            UDP, the real TCP header has no length field of
                //            its own, so this is counted only once here
                //            (see module header comment)
                checksum_next = 16'h0006 + 16'd20;
                s_tcp_hdr_ready_next = 1'b0;
                state_next = STATE_SUM_HEADER_1;
            end else begin
                state_next = STATE_IDLE;
            end
        end
        STATE_SUM_HEADER_1: begin
            // sum pseudo header: source IP
            checksum_next = checksum_reg + ip_source_ip_reg[31:16] + ip_source_ip_reg[15:0];
            state_next = STATE_SUM_HEADER_2;
        end
        STATE_SUM_HEADER_2: begin
            // sum pseudo header: destination IP
            checksum_next = checksum_reg + ip_dest_ip_reg[31:16] + ip_dest_ip_reg[15:0];
            state_next = STATE_SUM_HEADER_3;
        end
        STATE_SUM_HEADER_3: begin
            // sum header: source port, destination port
            checksum_next = checksum_reg + tcp_source_port_reg + tcp_dest_port_reg;
            state_next = STATE_SUM_HEADER_4;
        end
        STATE_SUM_HEADER_4: begin
            // sum header: sequence number
            checksum_next = checksum_reg + tcp_seq_num_reg[31:16] + tcp_seq_num_reg[15:0];
            state_next = STATE_SUM_HEADER_5;
        end
        STATE_SUM_HEADER_5: begin
            // sum header: acknowledgment number
            checksum_next = checksum_reg + tcp_ack_num_reg[31:16] + tcp_ack_num_reg[15:0];
            state_next = STATE_SUM_HEADER_6;
        end
        STATE_SUM_HEADER_6: begin
            // sum header: data offset/reserved/flags word, window
            checksum_next = checksum_reg + {tcp_data_offset_reg, tcp_reserved_reg, tcp_flags_reg} + tcp_window_reg;
            state_next = STATE_SUM_HEADER_7;
        end
        STATE_SUM_HEADER_7: begin
            // sum header: urgent pointer (checksum field itself is zero, not summed)
            checksum_next = checksum_reg + tcp_urgent_pointer_reg;
            frame_ptr_next = 20;
            state_next = STATE_SUM_PAYLOAD;
        end
        STATE_SUM_PAYLOAD: begin
            // sum payload
            shift_payload_in = 1'b1;

            if (s_tcp_payload_axis_tready && s_tcp_payload_axis_tvalid) begin
                word_cnt = 1;
                for (i = 1; i <= 8; i = i + 1) begin
                    if (s_tcp_payload_axis_tkeep == (8'hff >> (8-i))) word_cnt = i;
                end

                // alternate high/low byte based on absolute byte position
                // (frame_ptr_reg + i); frame_ptr_reg always starts even (20)
                // so (frame_ptr_reg[0] ^ i[0]) gives the correct parity for
                // every byte in this beat
                checksum_sum = checksum_reg;
                for (i = 0; i < 8; i = i + 1) begin
                    if (s_tcp_payload_axis_tkeep[i]) begin
                        if (frame_ptr_reg[0] ^ i[0]) begin
                            checksum_sum = checksum_sum + {8'h00, s_tcp_payload_axis_tdata[i*8 +: 8]};
                        end else begin
                            checksum_sum = checksum_sum + {s_tcp_payload_axis_tdata[i*8 +: 8], 8'h00};
                        end
                    end
                end

                // add 1 per byte for length calculation (single tcp_length
                // occurrence in the pseudo header - see module header comment)
                checksum_next = checksum_sum + word_cnt;

                frame_ptr_next = frame_ptr_reg + word_cnt;

                if (s_tcp_payload_axis_tlast) begin
                    state_next = STATE_FINISH_SUM;
                end else begin
                    state_next = STATE_SUM_PAYLOAD;
                end
            end else begin
                state_next = STATE_SUM_PAYLOAD;
            end
        end
        STATE_FINISH_SUM: begin
            // add MSW (twice!) for proper ones complement sum
            checksum_part = checksum_reg[15:0] + checksum_reg[31:16];
            checksum_next = ~(checksum_part[15:0] + checksum_part[16]);
            hdr_valid_next = 1;
            state_next = STATE_IDLE;
        end
    endcase
end

always @(posedge clk) begin
    if (rst) begin
        state_reg <= STATE_IDLE;
        s_tcp_hdr_ready_reg <= 1'b0;
        s_tcp_payload_axis_tready_reg <= 1'b0;
        hdr_valid_reg <= 1'b0;
        busy_reg <= 1'b0;
    end else begin
        state_reg <= state_next;

        s_tcp_hdr_ready_reg <= s_tcp_hdr_ready_next;
        s_tcp_payload_axis_tready_reg <= s_tcp_payload_axis_tready_next;

        hdr_valid_reg <= hdr_valid_next;

        busy_reg <= state_next != STATE_IDLE;
    end

    frame_ptr_reg <= frame_ptr_next;
    checksum_reg <= checksum_next;

    // datapath
    if (store_tcp_hdr) begin
        eth_dest_mac_reg <= s_eth_dest_mac;
        eth_src_mac_reg <= s_eth_src_mac;
        eth_type_reg <= s_eth_type;
        ip_version_reg <= s_ip_version;
        ip_ihl_reg <= s_ip_ihl;
        ip_dscp_reg <= s_ip_dscp;
        ip_ecn_reg <= s_ip_ecn;
        ip_identification_reg <= s_ip_identification;
        ip_flags_reg <= s_ip_flags;
        ip_fragment_offset_reg <= s_ip_fragment_offset;
        ip_ttl_reg <= s_ip_ttl;
        ip_header_checksum_reg <= s_ip_header_checksum;
        ip_source_ip_reg <= s_ip_source_ip;
        ip_dest_ip_reg <= s_ip_dest_ip;
        tcp_source_port_reg <= s_tcp_source_port;
        tcp_dest_port_reg <= s_tcp_dest_port;
        tcp_seq_num_reg <= s_tcp_seq_num;
        tcp_ack_num_reg <= s_tcp_ack_num;
        tcp_data_offset_reg <= s_tcp_data_offset;
        tcp_reserved_reg <= s_tcp_reserved;
        tcp_flags_reg <= s_tcp_flags;
        tcp_window_reg <= s_tcp_window;
        tcp_urgent_pointer_reg <= s_tcp_urgent_pointer;
    end
end

endmodule

`resetall
