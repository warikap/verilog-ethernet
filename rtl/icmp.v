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
 * ICMP echo (ping) responder (IP frame in, IP frame out)
 */
module icmp #
(
    parameter PAYLOAD_FIFO_DEPTH = 2048,
    parameter REPLY_TTL = 8'd64
)
(
    input  wire        clk,
    input  wire        rst,

    /*
     * IP frame input (ICMP)
     */
    input  wire        s_ip_hdr_valid,
    output wire        s_ip_hdr_ready,
    input  wire [47:0] s_eth_dest_mac,
    input  wire [47:0] s_eth_src_mac,
    input  wire [15:0] s_eth_type,
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
    input  wire [7:0]  s_ip_payload_axis_tdata,
    input  wire        s_ip_payload_axis_tvalid,
    output wire        s_ip_payload_axis_tready,
    input  wire        s_ip_payload_axis_tlast,
    input  wire        s_ip_payload_axis_tuser,

    /*
     * IP frame output (echo reply)
     */
    output wire        m_ip_hdr_valid,
    input  wire        m_ip_hdr_ready,
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
    output wire [7:0]  m_ip_payload_axis_tdata,
    output wire        m_ip_payload_axis_tvalid,
    input  wire        m_ip_payload_axis_tready,
    output wire        m_ip_payload_axis_tlast,
    output wire        m_ip_payload_axis_tuser,

    /*
     * Status signals
     */
    output wire        busy,
    output wire        error_header_early_termination,
    output wire        error_payload_early_termination
);

/*

ICMP Frame

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

 type                        1 octet
 code                        1 octet
 checksum                    2 octets
 identifier                  2 octets
 sequence number             2 octets

 payload                     length octets

This module implements an ICMP echo (ping) responder. It receives an IP
frame carrying an ICMP message; Echo Request messages (type 8, code 0) are
answered with an Echo Reply (type 0, code 0) carrying the same identifier,
sequence number and payload, with the Ethernet and IP source/destination
addresses swapped. Any other ICMP message is silently discarded. The
request payload is buffered in an AXI stream FIFO so that it can be
replayed unchanged into the reply once the full request has been received.

Since only the type byte changes between an Echo Request and an Echo Reply
(code, identifier, sequence number and payload are all unchanged), the
reply checksum is derived directly from the request checksum instead of
being recomputed over the whole message. Per RFC 1624, updating a 16-bit
one's complement checksum HC for a header word changing from m to m' is:

    HC' = ~(~HC + ~m + m')

with one's complement (end-around carry) addition throughout. Here
m = 16'h0800 (type=8, code=0) and m' = 16'h0000 (type=0, code=0), so
~m = 16'hF7FF and m' = 0. Using ~a = 16'hFFFF - a and the resulting
identity ~(~a - b) = a + b (valid modulo 16'hFFFF, i.e. in one's
complement arithmetic), this simplifies to:

    HC' = HC + 16'h0800

i.e. the reply checksum is simply the request checksum plus 0x0800, added
with end-around carry (add 1 back in if the 17-bit sum overflows 16 bits).

*/

localparam [1:0]
    STATE_IDLE    = 2'd0,
    STATE_PAYLOAD = 2'd1,
    STATE_SEND    = 2'd2;

reg [1:0] state_reg = STATE_IDLE, state_next;

// datapath control signals
reg store_req_hdr;

reg accept_reg = 1'b0, accept_next;

reg [47:0] req_eth_dest_mac_reg = 48'd0;
reg [47:0] req_eth_src_mac_reg = 48'd0;
reg [5:0]  req_ip_dscp_reg = 6'd0;
reg [1:0]  req_ip_ecn_reg = 2'd0;
reg [15:0] req_ip_identification_reg = 16'd0;
reg [2:0]  req_ip_flags_reg = 3'd0;
reg [12:0] req_ip_fragment_offset_reg = 13'd0;
reg [31:0] req_ip_source_ip_reg = 32'd0;
reg [31:0] req_ip_dest_ip_reg = 32'd0;
reg [15:0] req_icmp_identifier_reg = 16'd0;
reg [15:0] req_icmp_sequence_number_reg = 16'd0;
reg [15:0] icmp_length_reg = 16'd0;
reg [15:0] reply_checksum_reg = 16'd0;

reg s_icmp_hdr_valid_reg = 1'b0, s_icmp_hdr_valid_next;

reg busy_reg = 1'b0;

assign busy = busy_reg;

// icmp_ip_rx output (request header + payload)
wire        rx_hdr_valid;
wire [47:0] rx_eth_dest_mac;
wire [47:0] rx_eth_src_mac;
wire [15:0] rx_eth_type;
wire [3:0]  rx_ip_version;
wire [3:0]  rx_ip_ihl;
wire [5:0]  rx_ip_dscp;
wire [1:0]  rx_ip_ecn;
wire [15:0] rx_ip_length;
wire [15:0] rx_ip_identification;
wire [2:0]  rx_ip_flags;
wire [12:0] rx_ip_fragment_offset;
wire [7:0]  rx_ip_ttl;
wire [7:0]  rx_ip_protocol;
wire [15:0] rx_ip_header_checksum;
wire [31:0] rx_ip_source_ip;
wire [31:0] rx_ip_dest_ip;
wire [7:0]  rx_icmp_type;
wire [7:0]  rx_icmp_code;
wire [15:0] rx_icmp_checksum;
wire [15:0] rx_icmp_identifier;
wire [15:0] rx_icmp_sequence_number;
wire [7:0]  rx_payload_axis_tdata;
wire        rx_payload_axis_tvalid;
wire        rx_payload_axis_tready;
wire        rx_payload_axis_tlast;
wire        rx_payload_axis_tuser;

wire        rx_error_header_early_termination;
wire        rx_error_payload_early_termination;

assign error_header_early_termination = rx_error_header_early_termination;
assign error_payload_early_termination = rx_error_payload_early_termination;

// accept a new request header only while idle
wire rx_hdr_ready;
assign rx_hdr_ready = (state_reg == STATE_IDLE);

// echo request classification and reply checksum, valid while rx_hdr_valid is asserted
wire        accept_wire = (rx_icmp_type == 8'd8) && (rx_icmp_code == 8'd0);
wire [16:0] checksum_sum = {1'b0, rx_icmp_checksum} + 17'h00800;
wire [15:0] checksum_wire = checksum_sum[16] ? (checksum_sum[15:0] + 16'd1) : checksum_sum[15:0];
wire [15:0] icmp_length_wire = rx_ip_length - {10'd0, rx_ip_ihl, 2'b00};

icmp_ip_rx
icmp_ip_rx_inst (
    .clk(clk),
    .rst(rst),

    .s_ip_hdr_valid(s_ip_hdr_valid),
    .s_ip_hdr_ready(s_ip_hdr_ready),
    .s_eth_dest_mac(s_eth_dest_mac),
    .s_eth_src_mac(s_eth_src_mac),
    .s_eth_type(s_eth_type),
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
    .s_ip_payload_axis_tvalid(s_ip_payload_axis_tvalid),
    .s_ip_payload_axis_tready(s_ip_payload_axis_tready),
    .s_ip_payload_axis_tlast(s_ip_payload_axis_tlast),
    .s_ip_payload_axis_tuser(s_ip_payload_axis_tuser),

    .m_icmp_hdr_valid(rx_hdr_valid),
    .m_icmp_hdr_ready(rx_hdr_ready),
    .m_eth_dest_mac(rx_eth_dest_mac),
    .m_eth_src_mac(rx_eth_src_mac),
    .m_eth_type(rx_eth_type),
    .m_ip_version(rx_ip_version),
    .m_ip_ihl(rx_ip_ihl),
    .m_ip_dscp(rx_ip_dscp),
    .m_ip_ecn(rx_ip_ecn),
    .m_ip_length(rx_ip_length),
    .m_ip_identification(rx_ip_identification),
    .m_ip_flags(rx_ip_flags),
    .m_ip_fragment_offset(rx_ip_fragment_offset),
    .m_ip_ttl(rx_ip_ttl),
    .m_ip_protocol(rx_ip_protocol),
    .m_ip_header_checksum(rx_ip_header_checksum),
    .m_ip_source_ip(rx_ip_source_ip),
    .m_ip_dest_ip(rx_ip_dest_ip),
    .m_icmp_type(rx_icmp_type),
    .m_icmp_code(rx_icmp_code),
    .m_icmp_checksum(rx_icmp_checksum),
    .m_icmp_identifier(rx_icmp_identifier),
    .m_icmp_sequence_number(rx_icmp_sequence_number),
    .m_icmp_payload_axis_tdata(rx_payload_axis_tdata),
    .m_icmp_payload_axis_tvalid(rx_payload_axis_tvalid),
    .m_icmp_payload_axis_tready(rx_payload_axis_tready),
    .m_icmp_payload_axis_tlast(rx_payload_axis_tlast),
    .m_icmp_payload_axis_tuser(rx_payload_axis_tuser),

    .busy(),
    .error_header_early_termination(rx_error_header_early_termination),
    .error_payload_early_termination(rx_error_payload_early_termination)
);

// payload FIFO: buffers the request payload so it can be replayed into the reply
wire [7:0] fifo_s_axis_tdata;
wire       fifo_s_axis_tvalid;
wire       fifo_s_axis_tready;
wire       fifo_s_axis_tlast;
wire       fifo_s_axis_tuser;

wire [7:0] fifo_m_axis_tdata;
wire       fifo_m_axis_tvalid;
wire       fifo_m_axis_tready;
wire       fifo_m_axis_tlast;
wire       fifo_m_axis_tuser;

// while receiving the payload of an accepted (echo request) frame, feed the FIFO;
// while receiving the payload of a rejected frame, sink and discard it instead
wire shift_payload_in = (state_reg == STATE_PAYLOAD) && accept_reg;

assign fifo_s_axis_tdata = rx_payload_axis_tdata;
assign fifo_s_axis_tvalid = rx_payload_axis_tvalid && shift_payload_in;
assign fifo_s_axis_tlast = rx_payload_axis_tlast;
assign fifo_s_axis_tuser = rx_payload_axis_tuser;

assign rx_payload_axis_tready = (state_reg != STATE_PAYLOAD) ? 1'b0 :
    (accept_reg ? fifo_s_axis_tready : 1'b1);

axis_fifo #(
    .DEPTH(PAYLOAD_FIFO_DEPTH),
    .DATA_WIDTH(8),
    .KEEP_ENABLE(0),
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
    .s_axis_tdata(fifo_s_axis_tdata),
    .s_axis_tkeep(0),
    .s_axis_tvalid(fifo_s_axis_tvalid),
    .s_axis_tready(fifo_s_axis_tready),
    .s_axis_tlast(fifo_s_axis_tlast),
    .s_axis_tid(0),
    .s_axis_tdest(0),
    .s_axis_tuser(fifo_s_axis_tuser),

    // AXI output
    .m_axis_tdata(fifo_m_axis_tdata),
    .m_axis_tkeep(),
    .m_axis_tvalid(fifo_m_axis_tvalid),
    .m_axis_tready(fifo_m_axis_tready),
    .m_axis_tlast(fifo_m_axis_tlast),
    .m_axis_tid(),
    .m_axis_tdest(),
    .m_axis_tuser(fifo_m_axis_tuser),

    // Status
    .status_overflow(),
    .status_bad_frame(),
    .status_good_frame()
);

// icmp_ip_tx input (reply header + buffered payload)
// The FIFO output feeds icmp_ip_tx directly (fifo_m_axis_tready is driven by
// icmp_ip_tx's s_icmp_payload_axis_tready below): icmp_ip_tx only asserts its
// payload ready once the reply header has been accepted, so no extra gating
// against our own state machine is needed here.
wire tx_hdr_ready;

icmp_ip_tx
icmp_ip_tx_inst (
    .clk(clk),
    .rst(rst),

    .s_icmp_hdr_valid(s_icmp_hdr_valid_reg),
    .s_icmp_hdr_ready(tx_hdr_ready),
    .s_eth_dest_mac(req_eth_src_mac_reg),
    .s_eth_src_mac(req_eth_dest_mac_reg),
    .s_eth_type(16'h0800),
    .s_ip_version(4'd4),
    .s_ip_ihl(4'd5),
    .s_ip_dscp(req_ip_dscp_reg),
    .s_ip_ecn(req_ip_ecn_reg),
    .s_ip_identification(req_ip_identification_reg),
    .s_ip_flags(req_ip_flags_reg),
    .s_ip_fragment_offset(req_ip_fragment_offset_reg),
    .s_ip_ttl(REPLY_TTL),
    .s_ip_protocol(8'h01),
    .s_ip_header_checksum(16'd0),
    .s_ip_source_ip(req_ip_dest_ip_reg),
    .s_ip_dest_ip(req_ip_source_ip_reg),
    .s_icmp_type(8'd0),
    .s_icmp_code(8'd0),
    .s_icmp_checksum(reply_checksum_reg),
    .s_icmp_identifier(req_icmp_identifier_reg),
    .s_icmp_sequence_number(req_icmp_sequence_number_reg),
    .s_icmp_length(icmp_length_reg),
    .s_icmp_payload_axis_tdata(fifo_m_axis_tdata),
    .s_icmp_payload_axis_tvalid(fifo_m_axis_tvalid),
    .s_icmp_payload_axis_tready(fifo_m_axis_tready),
    .s_icmp_payload_axis_tlast(fifo_m_axis_tlast),
    .s_icmp_payload_axis_tuser(fifo_m_axis_tuser),

    .m_ip_hdr_valid(m_ip_hdr_valid),
    .m_ip_hdr_ready(m_ip_hdr_ready),
    .m_eth_dest_mac(m_eth_dest_mac),
    .m_eth_src_mac(m_eth_src_mac),
    .m_eth_type(m_eth_type),
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
    .m_ip_payload_axis_tvalid(m_ip_payload_axis_tvalid),
    .m_ip_payload_axis_tready(m_ip_payload_axis_tready),
    .m_ip_payload_axis_tlast(m_ip_payload_axis_tlast),
    .m_ip_payload_axis_tuser(m_ip_payload_axis_tuser),

    .busy(),
    .error_payload_early_termination()
);

wire payload_done = fifo_m_axis_tvalid && fifo_m_axis_tready && fifo_m_axis_tlast;

always @* begin
    state_next = state_reg;

    store_req_hdr = 1'b0;
    accept_next = accept_reg;

    s_icmp_hdr_valid_next = s_icmp_hdr_valid_reg && !tx_hdr_ready;

    case (state_reg)
        STATE_IDLE: begin
            // idle state - wait for request header
            if (rx_hdr_valid && rx_hdr_ready) begin
                store_req_hdr = 1'b1;
                accept_next = accept_wire;
                state_next = STATE_PAYLOAD;
            end
        end
        STATE_PAYLOAD: begin
            // request payload state - route to FIFO (accept) or discard (drop)
            if (rx_payload_axis_tvalid && rx_payload_axis_tready && rx_payload_axis_tlast) begin
                if (accept_reg) begin
                    s_icmp_hdr_valid_next = 1'b1;
                    state_next = STATE_SEND;
                end else begin
                    state_next = STATE_IDLE;
                end
            end
        end
        STATE_SEND: begin
            // reply state - header handshake plus buffered payload drain
            if (payload_done) begin
                state_next = STATE_IDLE;
            end
        end
    endcase
end

always @(posedge clk) begin
    if (rst) begin
        state_reg <= STATE_IDLE;
        s_icmp_hdr_valid_reg <= 1'b0;
        busy_reg <= 1'b0;
    end else begin
        state_reg <= state_next;
        s_icmp_hdr_valid_reg <= s_icmp_hdr_valid_next;
        busy_reg <= state_next != STATE_IDLE;
    end

    accept_reg <= accept_next;

    if (store_req_hdr) begin
        req_eth_dest_mac_reg <= rx_eth_dest_mac;
        req_eth_src_mac_reg <= rx_eth_src_mac;
        req_ip_dscp_reg <= rx_ip_dscp;
        req_ip_ecn_reg <= rx_ip_ecn;
        req_ip_identification_reg <= rx_ip_identification;
        req_ip_flags_reg <= rx_ip_flags;
        req_ip_fragment_offset_reg <= rx_ip_fragment_offset;
        req_ip_source_ip_reg <= rx_ip_source_ip;
        req_ip_dest_ip_reg <= rx_ip_dest_ip;
        req_icmp_identifier_reg <= rx_icmp_identifier;
        req_icmp_sequence_number_reg <= rx_icmp_sequence_number;
        icmp_length_reg <= icmp_length_wire;
        reply_checksum_reg <= checksum_wire;
    end
end

endmodule

`resetall
