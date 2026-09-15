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
 * TCP client TX packet buffer
 *
 * Ring buffer of PACKETS slots, each up to PACKET_SIZE bytes, holding
 * not-yet-fully-acknowledged application TX packets so they can be
 * replayed byte-for-byte on retransmission. Purely mechanical - no TCP
 * protocol knowledge. Three ring pointers: wr_ptr (application write
 * side), tx_ptr (first transmission), ack_ptr (oldest unacknowledged;
 * only here is a slot actually freed).
 *
 * Classic single-empty-slot ring buffer: usable capacity is PACKETS-1
 * segments in flight, not PACKETS, since pointer equality alone is used
 * to distinguish full from empty (no separate occupancy counter).
 *
 * A zero-length application packet cannot occur on s_axis (8-bit tdata,
 * no tkeep - a transfer only happens when tvalid && tready and always
 * carries one byte, so tlast always accompanies at least one byte). This
 * module therefore never needs to special-case slot_len==0.
 */
module tcp_client_pkt_buffer #
(
    parameter PACKETS = 4,
    parameter PACKET_SIZE = 1460
)
(
    input  wire        clk,
    input  wire        rst,

    input  wire        enable,

    /*
     * Application write side
     */
    input  wire [7:0]  s_axis_tdata,
    input  wire        s_axis_tvalid,
    output wire        s_axis_tready,
    input  wire        s_axis_tlast,

    output wire        full,
    output wire        empty,

    /*
     * New-segment (first transmission) read side
     */
    output wire         send_new_valid,
    output wire [15:0]  send_new_len,
    input  wire         send_new_start,
    input  wire [31:0]  send_new_base_seq,

    /*
     * Retry (retransmit oldest unacked) read side
     */
    output wire         send_retry_valid,
    output wire [15:0]  send_retry_len,
    output wire [31:0]  send_retry_base_seq,
    input  wire         send_retry_start,

    /*
     * Shared payload-out AXI stream, fed by whichever of
     * send_new_start / send_retry_start was last pulsed
     */
    output wire [7:0]  m_slot_axis_tdata,
    output wire        m_slot_axis_tvalid,
    input  wire        m_slot_axis_tready,
    output wire        m_slot_axis_tlast,

    /*
     * Cumulative-ack retirement - pops the oldest unacked slot
     */
    input  wire        ack_retire,

    input  wire        clear
);

localparam PTR_WIDTH = PACKETS > 1 ? $clog2(PACKETS) : 1;

function [PTR_WIDTH-1:0] ptr_incr;
    input [PTR_WIDTH-1:0] p;
    begin
        ptr_incr = (p == PACKETS-1) ? {PTR_WIDTH{1'b0}} : p + 1'b1;
    end
endfunction

reg [PTR_WIDTH-1:0] wr_ptr_reg = {PTR_WIDTH{1'b0}}, wr_ptr_next;
reg [PTR_WIDTH-1:0] tx_ptr_reg = {PTR_WIDTH{1'b0}}, tx_ptr_next;
reg [PTR_WIDTH-1:0] ack_ptr_reg = {PTR_WIDTH{1'b0}};

reg [15:0] slot_len[0:PACKETS-1];
reg [31:0] slot_base_seq[0:PACKETS-1];

reg [7:0] mem[0:PACKETS*PACKET_SIZE-1];

reg [15:0] wr_byte_reg = 16'd0, wr_byte_next;
reg wr_overflow_reg = 1'b0, wr_overflow_next;

reg mem_wr_en;
reg [31:0] mem_wr_addr;
reg [7:0] mem_wr_data;

reg slot_commit;
reg [15:0] slot_commit_len;

reg [15:0] rd_byte_reg = 16'd0, rd_byte_next;
reg rd_active_reg = 1'b0, rd_active_next;
reg rd_is_retry_reg = 1'b0, rd_is_retry_next;
reg [PTR_WIDTH-1:0] rd_ptr_reg = {PTR_WIDTH{1'b0}}, rd_ptr_next;

reg base_seq_wr_en;
reg [PTR_WIDTH-1:0] base_seq_wr_ptr;
reg [31:0] base_seq_wr_val;

wire [PTR_WIDTH-1:0] wr_ptr_next_val = ptr_incr(wr_ptr_reg);

assign full = (wr_ptr_next_val == ack_ptr_reg);
assign empty = (tx_ptr_reg == wr_ptr_reg) && (ack_ptr_reg == wr_ptr_reg);

assign s_axis_tready = enable && !full;

assign send_new_valid = (tx_ptr_reg != wr_ptr_reg) && !rd_active_reg;
assign send_new_len = slot_len[tx_ptr_reg];

assign send_retry_valid = (ack_ptr_reg != tx_ptr_reg) && !rd_active_reg;
assign send_retry_len = slot_len[ack_ptr_reg];
assign send_retry_base_seq = slot_base_seq[ack_ptr_reg];

assign m_slot_axis_tdata = mem[rd_ptr_reg*PACKET_SIZE + rd_byte_reg];
assign m_slot_axis_tvalid = rd_active_reg;
assign m_slot_axis_tlast = rd_active_reg && (rd_byte_reg == slot_len[rd_ptr_reg] - 16'd1);

// write side
always @* begin
    wr_ptr_next = wr_ptr_reg;
    wr_byte_next = wr_byte_reg;
    wr_overflow_next = wr_overflow_reg;

    mem_wr_en = 1'b0;
    mem_wr_addr = wr_ptr_reg*PACKET_SIZE + wr_byte_reg;
    mem_wr_data = s_axis_tdata;

    slot_commit = 1'b0;
    slot_commit_len = wr_byte_reg;

    if (s_axis_tvalid && s_axis_tready) begin
        if (wr_byte_reg < PACKET_SIZE) begin
            mem_wr_en = 1'b1;
        end else begin
            wr_overflow_next = 1'b1;
        end

        if (s_axis_tlast) begin
            if (!wr_overflow_reg && (wr_byte_reg < PACKET_SIZE)) begin
                slot_commit = 1'b1;
                slot_commit_len = wr_byte_reg + 16'd1;
                wr_ptr_next = ptr_incr(wr_ptr_reg);
            end
            wr_byte_next = 16'd0;
            wr_overflow_next = 1'b0;
        end else if (wr_byte_reg < PACKET_SIZE) begin
            wr_byte_next = wr_byte_reg + 16'd1;
        end
    end
end

// read side (new segment / retry)
always @* begin
    rd_active_next = rd_active_reg;
    rd_is_retry_next = rd_is_retry_reg;
    rd_ptr_next = rd_ptr_reg;
    rd_byte_next = rd_byte_reg;
    tx_ptr_next = tx_ptr_reg;

    base_seq_wr_en = 1'b0;
    base_seq_wr_ptr = tx_ptr_reg;
    base_seq_wr_val = send_new_base_seq;

    if (rd_active_reg) begin
        if (m_slot_axis_tvalid && m_slot_axis_tready) begin
            if (m_slot_axis_tlast) begin
                rd_active_next = 1'b0;
                if (!rd_is_retry_reg) begin
                    tx_ptr_next = ptr_incr(tx_ptr_reg);
                end
            end else begin
                rd_byte_next = rd_byte_reg + 16'd1;
            end
        end
    end else begin
        if (send_new_start && send_new_valid) begin
            rd_active_next = 1'b1;
            rd_is_retry_next = 1'b0;
            rd_ptr_next = tx_ptr_reg;
            rd_byte_next = 16'd0;
            base_seq_wr_en = 1'b1;
            base_seq_wr_ptr = tx_ptr_reg;
            base_seq_wr_val = send_new_base_seq;
        end else if (send_retry_start && send_retry_valid) begin
            rd_active_next = 1'b1;
            rd_is_retry_next = 1'b1;
            rd_ptr_next = ack_ptr_reg;
            rd_byte_next = 16'd0;
        end
    end
end

always @(posedge clk) begin
    if (rst || clear) begin
        wr_ptr_reg <= {PTR_WIDTH{1'b0}};
        tx_ptr_reg <= {PTR_WIDTH{1'b0}};
        ack_ptr_reg <= {PTR_WIDTH{1'b0}};
        wr_byte_reg <= 16'd0;
        wr_overflow_reg <= 1'b0;
        rd_active_reg <= 1'b0;
        rd_is_retry_reg <= 1'b0;
        rd_ptr_reg <= {PTR_WIDTH{1'b0}};
        rd_byte_reg <= 16'd0;
    end else begin
        wr_ptr_reg <= wr_ptr_next;
        tx_ptr_reg <= tx_ptr_next;
        wr_byte_reg <= wr_byte_next;
        wr_overflow_reg <= wr_overflow_next;
        rd_active_reg <= rd_active_next;
        rd_is_retry_reg <= rd_is_retry_next;
        rd_ptr_reg <= rd_ptr_next;
        rd_byte_reg <= rd_byte_next;

        // guard against retiring more slots than exist: the caller's
        // retry logic can pulse ack_retire one cycle too many since its
        // "is there another covered slot" check reads this same pointer
        // combinationally and only sees the update one cycle later
        if (ack_retire && (ack_ptr_reg != tx_ptr_reg)) begin
            ack_ptr_reg <= ptr_incr(ack_ptr_reg);
        end
    end

    if (mem_wr_en) begin
        mem[mem_wr_addr] <= mem_wr_data;
    end

    if (slot_commit) begin
        slot_len[wr_ptr_reg] <= slot_commit_len;
    end

    if (base_seq_wr_en) begin
        slot_base_seq[base_seq_wr_ptr] <= base_seq_wr_val;
    end
end

endmodule

/*
 * TCP client TX segment engine
 *
 * Builds and (re)sends TCP segments: drives the TCP-frame input side of
 * tcp (s_tcp_*), holds the send-side sequence number, runs a shared
 * arp.v-style retry timer for whichever segment is currently outstanding
 * (SYN, the oldest buffered data slot, or an outstanding FIN), and
 * retires acknowledged buffer slots via a wraparound-safe sequence
 * compare. It does not decide connection state transitions - it is
 * commanded by the top-level connection FSM via one-cycle pulses.
 *
 * Simplification: the shared retry timer is armed/disarmed at the level
 * of "is there any unacknowledged data outstanding" rather than being
 * reset to a fresh RETRY_INTERVAL on every partial cumulative-ack
 * retirement - after a partial ack the remaining timer duration just
 * continues counting down for whatever slot is now oldest, instead of
 * restarting. This keeps the timer state machine small; it still bounds
 * total retries via RETRY_COUNT/RETRY_TIMEOUT exactly as for SYN/FIN.
 */
module tcp_client_tx #
(
    parameter PACKETS = 4,
    parameter PACKET_SIZE = 1460,
    parameter RETRY_COUNT = 5,
    parameter RETRY_INTERVAL = 125000000/4,
    parameter RETRY_TIMEOUT = 125000000*2
)
(
    input  wire        clk,
    input  wire        rst,

    /*
     * Application TX data in, fed straight to the internal packet buffer
     */
    input  wire [7:0]  s_axis_tdata,
    input  wire        s_axis_tvalid,
    output wire        s_axis_tready,
    input  wire        s_axis_tlast,
    input  wire        buffer_enable,

    /*
     * Connection parameters from the top FSM
     */
    input  wire [15:0] local_port,
    input  wire [31:0] remote_ip,
    input  wire [15:0] remote_port,
    input  wire [31:0] isn,

    /*
     * Control requests from the top FSM (one-cycle pulses)
     */
    input  wire        syn_start,
    input  wire        syn_ack_seen,
    input  wire        send_ack,
    input  wire        fin_start,
    input  wire        rst_now,
    input  wire        clear,

    input  wire [31:0] snd_ack_num,
    input  wire [15:0] rcv_window,

    input  wire [31:0] peer_ack_num,
    input  wire        peer_ack_valid,

    output wire [31:0] snd_nxt,
    output wire        buffer_empty,
    output wire        retries_exhausted,
    output wire        fin_acked,

    /*
     * tcp.v TCP-frame-input side
     */
    output wire        s_tcp_hdr_valid,
    input  wire        s_tcp_hdr_ready,
    output wire [31:0] s_tcp_ip_dest_ip,
    output wire [15:0] s_tcp_source_port,
    output wire [15:0] s_tcp_dest_port,
    output wire [31:0] s_tcp_seq_num,
    output wire [31:0] s_tcp_ack_num,
    output wire [8:0]  s_tcp_flags,
    output wire [15:0] s_tcp_window,
    output wire [15:0] s_tcp_length,
    output wire [7:0]  s_tcp_payload_axis_tdata,
    output wire        s_tcp_payload_axis_tvalid,
    input  wire        s_tcp_payload_axis_tready,
    output wire        s_tcp_payload_axis_tlast
);

localparam [8:0]
    FLAGS_SYN = 9'b0_0000_0010,
    FLAGS_ACK = 9'b0_0001_0000,
    FLAGS_PSH_ACK = 9'b0_0001_1000,
    FLAGS_FIN_ACK = 9'b0_0001_0001,
    FLAGS_RST = 9'b0_0000_0100;

localparam [2:0]
    SEG_NONE = 3'd0,
    SEG_SYN = 3'd1,
    SEG_DATA_NEW = 3'd2,
    SEG_DATA_RETRY = 3'd3,
    SEG_ACK = 3'd4,
    SEG_FIN = 3'd5,
    SEG_RST = 3'd6;

localparam [1:0]
    SEND_IDLE = 2'd0,
    SEND_HDR = 2'd1;

function seq_ge; // true if a is >= b in circular 32-bit sequence space
    input [31:0] a, b;
    begin
        seq_ge = ($signed(a - b) >= 0);
    end
endfunction

// packet buffer
wire buf_full, buf_empty;
wire buf_send_new_valid;
wire [15:0] buf_send_new_len;
reg buf_send_new_start;
reg [31:0] buf_send_new_base_seq;
wire buf_send_retry_valid;
wire [15:0] buf_send_retry_len;
wire [31:0] buf_send_retry_base_seq;
reg buf_send_retry_start;
wire [7:0] buf_m_axis_tdata;
wire buf_m_axis_tvalid;
wire buf_m_axis_tready;
wire buf_m_axis_tlast;
reg buf_ack_retire;
wire buf_clear = clear;

tcp_client_pkt_buffer #(
    .PACKETS(PACKETS),
    .PACKET_SIZE(PACKET_SIZE)
)
pkt_buffer_inst (
    .clk(clk),
    .rst(rst),
    .enable(buffer_enable),
    .s_axis_tdata(s_axis_tdata),
    .s_axis_tvalid(s_axis_tvalid),
    .s_axis_tready(s_axis_tready),
    .s_axis_tlast(s_axis_tlast),
    .full(buf_full),
    .empty(buf_empty),
    .send_new_valid(buf_send_new_valid),
    .send_new_len(buf_send_new_len),
    .send_new_start(buf_send_new_start),
    .send_new_base_seq(buf_send_new_base_seq),
    .send_retry_valid(buf_send_retry_valid),
    .send_retry_len(buf_send_retry_len),
    .send_retry_base_seq(buf_send_retry_base_seq),
    .send_retry_start(buf_send_retry_start),
    .m_slot_axis_tdata(buf_m_axis_tdata),
    .m_slot_axis_tvalid(buf_m_axis_tvalid),
    .m_slot_axis_tready(buf_m_axis_tready),
    .m_slot_axis_tlast(buf_m_axis_tlast),
    .ack_retire(buf_ack_retire),
    .clear(buf_clear)
);

assign buffer_empty = buf_empty;

// send-side sequence state
reg [31:0] snd_nxt_reg = 32'd0;
reg [31:0] isn_latched_reg = 32'd0;
reg [31:0] fin_seq_base_reg = 32'd0;
reg [31:0] fin_ack_target_reg = 32'd0;

assign snd_nxt = snd_nxt_reg;

// phase / retry timer state
reg phase_syn_reg = 1'b0;
reg phase_fin_reg = 1'b0;
reg rst_pending_reg = 1'b0;
reg send_pending_reg = 1'b0;       // SYN/FIN (re)send due
reg data_retry_pending_reg = 1'b0; // data retransmit due
reg send_ack_pending_reg = 1'b0;

reg retry_active_reg = 1'b0;
reg [7:0] retry_cnt_reg = 8'd0;
reg [35:0] retry_timer_reg = 36'd0;

reg retries_exhausted_reg = 1'b0;
reg fin_acked_reg = 1'b0;

assign retries_exhausted = retries_exhausted_reg;
assign fin_acked = fin_acked_reg;

// small header+payload dispatch FSM
reg [1:0] send_state_reg = SEND_IDLE;
reg [2:0] seg_kind_reg = SEG_NONE;

reg s_tcp_hdr_valid_reg = 1'b0;
reg [31:0] s_tcp_ip_dest_ip_reg = 32'd0;
reg [15:0] s_tcp_source_port_reg = 16'd0;
reg [15:0] s_tcp_dest_port_reg = 16'd0;
reg [31:0] s_tcp_seq_num_reg = 32'd0;
reg [31:0] s_tcp_ack_num_reg = 32'd0;
reg [8:0]  s_tcp_flags_reg = 9'd0;
reg [15:0] s_tcp_window_reg = 16'd0;
reg [15:0] s_tcp_length_reg = 16'd0;

assign s_tcp_hdr_valid = s_tcp_hdr_valid_reg;
assign s_tcp_ip_dest_ip = s_tcp_ip_dest_ip_reg;
assign s_tcp_source_port = s_tcp_source_port_reg;
assign s_tcp_dest_port = s_tcp_dest_port_reg;
assign s_tcp_seq_num = s_tcp_seq_num_reg;
assign s_tcp_ack_num = s_tcp_ack_num_reg;
assign s_tcp_flags = s_tcp_flags_reg;
assign s_tcp_window = s_tcp_window_reg;
assign s_tcp_length = s_tcp_length_reg;

// payload pass-through from the packet buffer (only active/nonzero while
// a SEG_DATA_NEW/SEG_DATA_RETRY segment's payload phase is in progress -
// the buffer only asserts tvalid once we pulse one of its start signals)
assign s_tcp_payload_axis_tdata = buf_m_axis_tdata;
assign s_tcp_payload_axis_tvalid = buf_m_axis_tvalid;
assign s_tcp_payload_axis_tlast = buf_m_axis_tlast;
assign buf_m_axis_tready = s_tcp_payload_axis_tready;

// dispatch decision (combinational)
reg [2:0] next_kind;
reg use_retry_read;

always @* begin
    next_kind = SEG_NONE;
    use_retry_read = 1'b0;

    if (rst_pending_reg) begin
        next_kind = SEG_RST;
    end else if (phase_syn_reg && send_pending_reg) begin
        next_kind = SEG_SYN;
    end else if (!phase_syn_reg && phase_fin_reg && send_pending_reg) begin
        next_kind = SEG_FIN;
    end else if (!phase_syn_reg && !phase_fin_reg && data_retry_pending_reg && buf_send_retry_valid) begin
        next_kind = SEG_DATA_RETRY;
        use_retry_read = 1'b1;
    end else if (!phase_syn_reg && !phase_fin_reg && buf_send_new_valid) begin
        next_kind = SEG_DATA_NEW;
    end else if (send_ack_pending_reg) begin
        next_kind = SEG_ACK;
    end
end

// header/payload dispatch + sequence bookkeeping
always @(posedge clk) begin
    buf_send_new_start <= 1'b0;
    buf_send_retry_start <= 1'b0;

    if (rst) begin
        send_state_reg <= SEND_IDLE;
        seg_kind_reg <= SEG_NONE;
        s_tcp_hdr_valid_reg <= 1'b0;
        snd_nxt_reg <= 32'd0;
        isn_latched_reg <= 32'd0;
        fin_seq_base_reg <= 32'd0;
        fin_ack_target_reg <= 32'd0;
        rst_pending_reg <= 1'b0;
        send_pending_reg <= 1'b0;
        data_retry_pending_reg <= 1'b0;
        send_ack_pending_reg <= 1'b0;
    end else begin
        // soft clear - a same-cycle syn_start/fin_start/rst_now/send_ack
        // pulse (asserted alongside clear by the top FSM, e.g. on a fresh
        // CONNECT) must still take effect this cycle, so these resets are
        // written first and the explicit-event ifs below (which run later
        // in program order) win on any signal both touch
        if (clear) begin
            send_state_reg <= SEND_IDLE;
            seg_kind_reg <= SEG_NONE;
            s_tcp_hdr_valid_reg <= 1'b0;
            rst_pending_reg <= 1'b0;
            send_pending_reg <= 1'b0;
            data_retry_pending_reg <= 1'b0;
            send_ack_pending_reg <= 1'b0;
        end

        if (rst_now) begin
            rst_pending_reg <= 1'b1;
        end

        if (send_ack) begin
            send_ack_pending_reg <= 1'b1;
        end

        if (syn_start) begin
            isn_latched_reg <= isn;
            snd_nxt_reg <= isn + 32'd1;
        end

        if (fin_start) begin
            fin_seq_base_reg <= snd_nxt_reg;
            fin_ack_target_reg <= snd_nxt_reg + 32'd1;
            snd_nxt_reg <= snd_nxt_reg + 32'd1;
        end

        case (send_state_reg)
            SEND_IDLE: begin
                if (next_kind != SEG_NONE) begin
                    seg_kind_reg <= next_kind;
                    s_tcp_ip_dest_ip_reg <= remote_ip;
                    s_tcp_source_port_reg <= local_port;
                    s_tcp_dest_port_reg <= remote_port;
                    s_tcp_ack_num_reg <= snd_ack_num;
                    s_tcp_window_reg <= rcv_window;
                    s_tcp_hdr_valid_reg <= 1'b1;
                    send_state_reg <= SEND_HDR;

                    case (next_kind)
                        SEG_RST: begin
                            s_tcp_seq_num_reg <= snd_nxt_reg;
                            s_tcp_flags_reg <= FLAGS_RST;
                            s_tcp_length_reg <= 16'd20;
                            rst_pending_reg <= 1'b0;
                        end
                        SEG_SYN: begin
                            s_tcp_seq_num_reg <= isn_latched_reg;
                            s_tcp_flags_reg <= FLAGS_SYN;
                            s_tcp_length_reg <= 16'd20;
                            send_pending_reg <= 1'b0;
                        end
                        SEG_FIN: begin
                            s_tcp_seq_num_reg <= fin_seq_base_reg;
                            s_tcp_flags_reg <= FLAGS_FIN_ACK;
                            s_tcp_length_reg <= 16'd20;
                            send_pending_reg <= 1'b0;
                        end
                        SEG_DATA_NEW: begin
                            s_tcp_seq_num_reg <= snd_nxt_reg;
                            s_tcp_flags_reg <= FLAGS_PSH_ACK;
                            s_tcp_length_reg <= buf_send_new_len + 16'd20;
                            buf_send_new_start <= 1'b1;
                            buf_send_new_base_seq <= snd_nxt_reg;
                            snd_nxt_reg <= snd_nxt_reg + {16'd0, buf_send_new_len};
                        end
                        SEG_DATA_RETRY: begin
                            s_tcp_seq_num_reg <= buf_send_retry_base_seq;
                            s_tcp_flags_reg <= FLAGS_PSH_ACK;
                            s_tcp_length_reg <= buf_send_retry_len + 16'd20;
                            buf_send_retry_start <= 1'b1;
                            data_retry_pending_reg <= 1'b0;
                        end
                        SEG_ACK: begin
                            s_tcp_seq_num_reg <= snd_nxt_reg;
                            s_tcp_flags_reg <= FLAGS_ACK;
                            s_tcp_length_reg <= 16'd20;
                            send_ack_pending_reg <= 1'b0;
                        end
                    endcase
                end
            end

            SEND_HDR: begin
                if (s_tcp_hdr_valid_reg && s_tcp_hdr_ready) begin
                    s_tcp_hdr_valid_reg <= 1'b0;
                    send_state_reg <= SEND_IDLE;
                end
            end

            default: send_state_reg <= SEND_IDLE;
        endcase
    end
end

// retry timer / phase management
reg peer_ack_hold_active_reg = 1'b0;
reg [31:0] peer_ack_hold_reg = 32'd0;

// Combinational "value to check this cycle" - either the just-arrived
// peer_ack_num (peer_ack_valid pulses) or the held value from an earlier
// cycle (retiring further slots covered by the same cumulative ack).
// Using these wires (rather than reading peer_ack_hold_active_reg/_reg
// directly in the always block below) avoids a same-cycle race: on the
// exact cycle peer_ack_valid pulses, the _reg copies haven't been
// updated yet, so a check against the stale _reg would wrongly see
// "nothing to check" and immediately clear hold_active back down.
wire ack_check_active = peer_ack_valid || peer_ack_hold_active_reg;
wire [31:0] ack_check_val = peer_ack_valid ? peer_ack_num : peer_ack_hold_reg;
wire ack_covers_oldest = buf_send_retry_valid &&
    seq_ge(ack_check_val, buf_send_retry_base_seq + {16'd0, buf_send_retry_len});

always @(posedge clk) begin
    retries_exhausted_reg <= 1'b0;
    fin_acked_reg <= 1'b0;

    if (rst) begin
        phase_syn_reg <= 1'b0;
        phase_fin_reg <= 1'b0;
        retry_active_reg <= 1'b0;
        retry_cnt_reg <= 8'd0;
        retry_timer_reg <= 36'd0;
        peer_ack_hold_active_reg <= 1'b0;
        peer_ack_hold_reg <= 32'd0;
    end else begin
        // soft clear - written first so a same-cycle syn_start/fin_start
        // pulse (the top FSM asserts clear alongside syn_start on a fresh
        // CONNECT) still arms the new phase this cycle via the explicit
        // event ifs below, which run later in program order and win
        if (clear) begin
            phase_syn_reg <= 1'b0;
            phase_fin_reg <= 1'b0;
            retry_active_reg <= 1'b0;
            retry_cnt_reg <= 8'd0;
            retry_timer_reg <= 36'd0;
            peer_ack_hold_active_reg <= 1'b0;
        end

        // latch a new cumulative ack to retire against, one slot per cycle
        if (peer_ack_valid) begin
            peer_ack_hold_reg <= peer_ack_num;
        end

        buf_ack_retire <= 1'b0;

        if (ack_check_active && ack_covers_oldest) begin
            buf_ack_retire <= 1'b1;
            // stay active in case the same cumulative ack also covers the
            // next-oldest slot - re-checked next cycle against hold_reg
            peer_ack_hold_active_reg <= 1'b1;
        end else begin
            peer_ack_hold_active_reg <= 1'b0;
        end

        // fin acked?
        if (phase_fin_reg && peer_ack_valid && seq_ge(peer_ack_num, fin_ack_target_reg)) begin
            fin_acked_reg <= 1'b1;
        end

        // countdown / expiry (evaluated first, external events below can override)
        if (retry_active_reg) begin
            if (retry_timer_reg != 36'd0) begin
                retry_timer_reg <= retry_timer_reg - 36'd1;
            end else begin
                if (retry_cnt_reg > 8'd0) begin
                    retry_cnt_reg <= retry_cnt_reg - 8'd1;
                    retry_timer_reg <= (retry_cnt_reg > 8'd1) ? RETRY_INTERVAL : RETRY_TIMEOUT;
                    if (phase_syn_reg || phase_fin_reg) begin
                        send_pending_reg <= 1'b1;
                    end else begin
                        data_retry_pending_reg <= 1'b1;
                    end
                end else begin
                    retries_exhausted_reg <= 1'b1;
                    retry_active_reg <= 1'b0;
                    phase_syn_reg <= 1'b0;
                    phase_fin_reg <= 1'b0;
                end
            end
        end

        // data phase arm/disarm (level-triggered, see module header comment)
        if (!phase_syn_reg && !phase_fin_reg) begin
            if (!buf_empty && !retry_active_reg) begin
                retry_active_reg <= 1'b1;
                retry_cnt_reg <= RETRY_COUNT;
                retry_timer_reg <= RETRY_INTERVAL;
            end else if (buf_empty && retry_active_reg) begin
                retry_active_reg <= 1'b0;
            end
        end

        // explicit events take priority over the above
        if (syn_start) begin
            phase_syn_reg <= 1'b1;
            phase_fin_reg <= 1'b0;
            send_pending_reg <= 1'b1;
            retry_active_reg <= 1'b1;
            retry_cnt_reg <= RETRY_COUNT;
            retry_timer_reg <= RETRY_INTERVAL;
        end

        if (syn_ack_seen) begin
            phase_syn_reg <= 1'b0;
            retry_active_reg <= 1'b0;
            send_pending_reg <= 1'b0;
        end

        if (fin_start) begin
            phase_fin_reg <= 1'b1;
            send_pending_reg <= 1'b1;
            retry_active_reg <= 1'b1;
            retry_cnt_reg <= RETRY_COUNT;
            retry_timer_reg <= RETRY_INTERVAL;
        end

        if (phase_fin_reg && peer_ack_valid && seq_ge(peer_ack_num, fin_ack_target_reg)) begin
            phase_fin_reg <= 1'b0;
            retry_active_reg <= 1'b0;
        end
    end
end

endmodule

/*
 * TCP client RX segment decoder
 *
 * Filters tcp's decoded segments by 4-tuple, latches header fields on
 * the one-cycle m_tcp_hdr_valid pulse, and forwards accepted in-order
 * payload bytes to the user-facing RX stream. Segment completion is
 * detected via tcp's rx_busy falling edge rather than solely via tlast,
 * since a zero-payload segment (bare ACK, FIN, RST) never produces a
 * single m_tcp_payload_axis beat.
 *
 * No reassembly/reordering (v1 limitation): a segment that does not
 * begin exactly at rcv_nxt is dropped outright (drained so it never
 * stalls tcp's shared RX pipeline) and never forwarded to the user; no
 * duplicate ACK is generated to trigger fast retransmit, so recovery
 * relies solely on the peer's own retransmission timer.
 */
module tcp_client_rx
(
    input  wire        clk,
    input  wire        rst,

    input  wire        conn_active,
    input  wire [31:0] remote_ip,
    input  wire [15:0] remote_port,
    input  wire [15:0] local_port,
    input  wire [31:0] rcv_nxt,
    input  wire        accept_data,

    output wire        rx_seg_valid,
    output wire [31:0] rx_seg_seq_num,
    output wire [31:0] rx_seg_ack_num,
    output wire [8:0]  rx_seg_flags,
    output wire [15:0] rx_seg_window,
    output wire [15:0] rx_seg_payload_len,

    output wire [7:0]  m_axis_tdata,
    output wire        m_axis_tvalid,
    input  wire        m_axis_tready,
    output wire        m_axis_tlast,

    input  wire        m_tcp_hdr_valid,
    output wire        m_tcp_hdr_ready,
    input  wire [31:0] m_tcp_ip_source_ip,
    input  wire [15:0] m_tcp_source_port,
    input  wire [15:0] m_tcp_dest_port,
    input  wire [31:0] m_tcp_seq_num,
    input  wire [31:0] m_tcp_ack_num,
    input  wire [8:0]  m_tcp_flags,
    input  wire [15:0] m_tcp_window,
    input  wire [7:0]  m_tcp_payload_axis_tdata,
    input  wire        m_tcp_payload_axis_tvalid,
    output wire        m_tcp_payload_axis_tready,
    input  wire        m_tcp_payload_axis_tlast,

    input  wire        rx_busy
);

assign m_tcp_hdr_ready = 1'b1;

wire hdr_match = conn_active && (m_tcp_ip_source_ip == remote_ip) &&
                 (m_tcp_source_port == remote_port) && (m_tcp_dest_port == local_port);

reg hdr_match_reg = 1'b0;
reg accept_payload_reg = 1'b0;
reg [31:0] hdr_seq_reg = 32'd0, hdr_ack_reg = 32'd0;
reg [8:0] hdr_flags_reg = 9'd0;
reg [15:0] hdr_window_reg = 16'd0;
reg [15:0] payload_len_reg = 16'd0;
reg payload_seen_reg = 1'b0;

reg rx_busy_prev_reg = 1'b0;

reg rx_seg_valid_reg = 1'b0;
reg [31:0] rx_seg_seq_num_reg = 32'd0, rx_seg_ack_num_reg = 32'd0;
reg [8:0] rx_seg_flags_reg = 9'd0;
reg [15:0] rx_seg_window_reg = 16'd0, rx_seg_payload_len_reg = 16'd0;

assign rx_seg_valid = rx_seg_valid_reg;
assign rx_seg_seq_num = rx_seg_seq_num_reg;
assign rx_seg_ack_num = rx_seg_ack_num_reg;
assign rx_seg_flags = rx_seg_flags_reg;
assign rx_seg_window = rx_seg_window_reg;
assign rx_seg_payload_len = rx_seg_payload_len_reg;

assign m_axis_tdata = m_tcp_payload_axis_tdata;
assign m_axis_tvalid = m_tcp_payload_axis_tvalid && accept_payload_reg;
assign m_axis_tlast = m_tcp_payload_axis_tlast;
assign m_tcp_payload_axis_tready = accept_payload_reg ? m_axis_tready : 1'b1;

// For a zero-payload segment, m_tcp_hdr_valid pulses on the exact same
// cycle rx_busy falls (no payload phase to separate the two events), so
// the busy-falling-edge completion check below must not rely solely on
// hdr_match_reg/hdr_*_reg - those only get the fresh values on the NEXT
// cycle. Mux in the combinational just-arrived values whenever
// m_tcp_hdr_valid is high this same cycle.
wire hdr_match_now = m_tcp_hdr_valid ? hdr_match : hdr_match_reg;
wire [31:0] hdr_seq_now = m_tcp_hdr_valid ? m_tcp_seq_num : hdr_seq_reg;
wire [31:0] hdr_ack_now = m_tcp_hdr_valid ? m_tcp_ack_num : hdr_ack_reg;
wire [8:0] hdr_flags_now = m_tcp_hdr_valid ? m_tcp_flags : hdr_flags_reg;
wire [15:0] hdr_window_now = m_tcp_hdr_valid ? m_tcp_window : hdr_window_reg;

always @(posedge clk) begin
    rx_seg_valid_reg <= 1'b0;

    if (rst) begin
        hdr_match_reg <= 1'b0;
        accept_payload_reg <= 1'b0;
        payload_len_reg <= 16'd0;
        payload_seen_reg <= 1'b0;
        rx_busy_prev_reg <= 1'b0;
    end else begin
        rx_busy_prev_reg <= rx_busy;

        if (m_tcp_hdr_valid) begin
            hdr_match_reg <= hdr_match;
            hdr_seq_reg <= m_tcp_seq_num;
            hdr_ack_reg <= m_tcp_ack_num;
            hdr_flags_reg <= m_tcp_flags;
            hdr_window_reg <= m_tcp_window;
            accept_payload_reg <= hdr_match && accept_data && !m_tcp_flags[2] && (m_tcp_seq_num == rcv_nxt);
            payload_len_reg <= 16'd0;
            payload_seen_reg <= 1'b0;
        end else if (m_tcp_payload_axis_tvalid && m_tcp_payload_axis_tready) begin
            payload_len_reg <= payload_len_reg + 16'd1;
            payload_seen_reg <= 1'b1;
        end

        // Segment completion: tcp_ip_rx has its own 2-stage output skid
        // buffer on m_tcp_payload_axis, so rx_busy can fall a cycle or
        // more BEFORE the last payload byte actually reaches this module
        // (e.g. under m_axis_tready backpressure) - keying completion off
        // rx_busy alone would then read payload_len_reg before the final
        // byte is counted. So key off the payload stream's own tlast
        // whenever a payload is actually present, and fall back to the
        // rx_busy falling edge only for a genuinely zero-payload segment
        // (which produces no payload beats to key off at all).
        if (m_tcp_payload_axis_tvalid && m_tcp_payload_axis_tready && m_tcp_payload_axis_tlast) begin
            rx_seg_valid_reg <= hdr_match_reg;
            rx_seg_seq_num_reg <= hdr_seq_reg;
            rx_seg_ack_num_reg <= hdr_ack_reg;
            rx_seg_flags_reg <= hdr_flags_reg;
            rx_seg_window_reg <= hdr_window_reg;
            rx_seg_payload_len_reg <= payload_len_reg + 16'd1;
            accept_payload_reg <= 1'b0;
        end else if (rx_busy_prev_reg && !rx_busy && !payload_seen_reg) begin
            rx_seg_valid_reg <= hdr_match_now;
            rx_seg_seq_num_reg <= hdr_seq_now;
            rx_seg_ack_num_reg <= hdr_ack_now;
            rx_seg_flags_reg <= hdr_flags_now;
            rx_seg_window_reg <= hdr_window_now;
            rx_seg_payload_len_reg <= 16'd0;
            accept_payload_reg <= 1'b0;
        end
    end
end

endmodule

/*
 * TCP client
 *
 * Application-facing TCP client: a packed config command stream
 * (connect/disconnect to a given IP+port), a TX data stream (buffered,
 * backpressured until ESTABLISHED), an RX data stream, single-bit status
 * outputs, and a 3-way-handshake connection state machine with
 * retransmission. Sits at the same IP-frame level as tcp.v (identical
 * s_ip_hdr_/m_ip_hdr_ + s_ip_payload_axis_/m_ip_payload_axis_ (wildcard
 * suffixes) ports), instantiating tcp internally - its TCP-frame ports
 * are never
 * exposed at this module's boundary.
 *
 * Flow-control assumption (stated by design, not derived): the peer's
 * advertised TCP window is always larger than TX_BUFFER_PACKETS, so
 * sending is gated purely by packet-buffer slot credit (tcp_client_tx's
 * internal buf_full/buf_empty), not by byte-granular window tracking.
 */
module tcp_client #
(
    parameter LOCAL_IP = 32'hc0a80164,
    parameter LOCAL_PORT = 16'd1234,

    parameter TX_BUFFER_PACKETS = 4,
    parameter TX_BUFFER_PACKET_SIZE = 1460,

    parameter RETRY_COUNT = 5,
    parameter RETRY_INTERVAL = 125000000/4,
    parameter RETRY_TIMEOUT = 125000000*2,

    parameter ISN_INCREMENT_CYCLES = 1,

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
    input  wire [7:0]  s_ip_payload_axis_tdata,
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
    output wire [7:0]  m_ip_payload_axis_tdata,
    output wire        m_ip_payload_axis_tvalid,
    input  wire        m_ip_payload_axis_tready,
    output wire        m_ip_payload_axis_tlast,
    output wire        m_ip_payload_axis_tuser,

    /*
     * Application config command stream (packed, single tdata word per
     * command, no tlast): tdata[63:32]=dest IP, tdata[31:16]=dest port,
     * tdata[15:0]=command (CMD_CONNECT/CMD_DISCONNECT below)
     */
    input  wire [63:0] s_config_axis_tdata,
    input  wire        s_config_axis_tvalid,
    output wire        s_config_axis_tready,

    /*
     * Application TX data stream (tready held low until ESTABLISHED)
     */
    input  wire [7:0]  s_axis_tdata,
    input  wire        s_axis_tvalid,
    output wire        s_axis_tready,
    input  wire        s_axis_tlast,

    /*
     * Application RX data stream
     */
    output wire [7:0]  m_axis_tdata,
    output wire        m_axis_tvalid,
    input  wire        m_axis_tready,
    output wire        m_axis_tlast,

    /*
     * Status
     */
    output wire        connecting,
    output wire        connected,
    output wire        closing,
    output wire        error,
    output wire        config_error
);

localparam [15:0]
    CMD_CONNECT = 16'h0001,
    CMD_DISCONNECT = 16'h0002;

localparam [2:0]
    STATE_CLOSED = 3'd0,
    STATE_SYN_SENT = 3'd1,
    STATE_ESTABLISHED = 3'd2,
    STATE_FIN_WAIT = 3'd3,
    STATE_CLOSE_WAIT = 3'd4,
    STATE_LAST_ACK = 3'd5;

reg [2:0] state_reg = STATE_CLOSED, state_next;

reg [31:0] remote_ip_reg = 32'd0, remote_ip_next;
reg [15:0] remote_port_reg = 16'd0, remote_port_next;
reg [31:0] rcv_nxt_reg = 32'd0, rcv_nxt_next;
reg [31:0] isn_at_connect_reg = 32'd0;
reg pending_close_reg = 1'b0, pending_close_next;
reg peer_fin_seen_reg = 1'b0, peer_fin_seen_next;
reg our_fin_acked_reg = 1'b0, our_fin_acked_next;

reg error_reg = 1'b0, error_next;
reg config_error_reg = 1'b0, config_error_next;

reg syn_start_next, syn_ack_seen_next, send_ack_next, fin_start_next, rst_now_next, clear_next;
reg syn_start_reg = 1'b0, syn_ack_seen_reg = 1'b0, send_ack_reg = 1'b0;
reg fin_start_reg = 1'b0, rst_now_reg = 1'b0, clear_reg = 1'b0;

assign connecting = (state_reg == STATE_SYN_SENT);
assign connected = (state_reg == STATE_ESTABLISHED);
assign closing = (state_reg == STATE_FIN_WAIT) || (state_reg == STATE_CLOSE_WAIT) || (state_reg == STATE_LAST_ACK);
assign error = error_reg;
assign config_error = config_error_reg;

// free-running ISN counter (sampled on entering SYN_SENT)
reg [31:0] isn_counter_reg = 32'd0;
generate
if (ISN_INCREMENT_CYCLES <= 1) begin : isn_gen_fast
    always @(posedge clk) begin
        if (rst) begin
            isn_counter_reg <= 32'd0;
        end else begin
            isn_counter_reg <= isn_counter_reg + 32'd1;
        end
    end
end else begin : isn_gen_div
    reg [31:0] isn_div_reg = 32'd0;
    always @(posedge clk) begin
        if (rst) begin
            isn_counter_reg <= 32'd0;
            isn_div_reg <= 32'd0;
        end else if (isn_div_reg == ISN_INCREMENT_CYCLES-1) begin
            isn_div_reg <= 32'd0;
            isn_counter_reg <= isn_counter_reg + 32'd1;
        end else begin
            isn_div_reg <= isn_div_reg + 32'd1;
        end
    end
end
endgenerate

// config command decode - always accepted; inapplicable/unknown commands
// are consumed and dropped with a one-cycle config_error pulse
wire [15:0] cfg_cmd = s_config_axis_tdata[15:0];
wire [31:0] cfg_dest_ip = s_config_axis_tdata[63:32];
wire [15:0] cfg_dest_port = s_config_axis_tdata[31:16];
wire cmd_valid = s_config_axis_tvalid;
wire cmd_connect = cmd_valid && (cfg_cmd == CMD_CONNECT);
wire cmd_disconnect = cmd_valid && (cfg_cmd == CMD_DISCONNECT);
wire cmd_unknown = cmd_valid && (cfg_cmd != CMD_CONNECT) && (cfg_cmd != CMD_DISCONNECT);

assign s_config_axis_tready = 1'b1;

// tcp_client_tx / tcp_client_rx wiring
wire [31:0] tx_snd_nxt;
wire tx_buffer_empty, tx_retries_exhausted, tx_fin_acked;

wire rx_seg_valid;
wire [31:0] rx_seg_seq_num, rx_seg_ack_num;
wire [8:0] rx_seg_flags;
wire [15:0] rx_seg_window;
wire [15:0] rx_seg_payload_len;

wire conn_active = (state_reg != STATE_CLOSED);
wire accept_data = (state_reg == STATE_ESTABLISHED);
wire buffer_enable = (state_reg == STATE_ESTABLISHED) && !pending_close_reg;

// tcp instance TCP-frame side
wire tcp_s_tcp_hdr_valid, tcp_s_tcp_hdr_ready;
wire [31:0] tcp_s_tcp_ip_dest_ip;
wire [15:0] tcp_s_tcp_source_port, tcp_s_tcp_dest_port;
wire [31:0] tcp_s_tcp_seq_num, tcp_s_tcp_ack_num;
wire [8:0] tcp_s_tcp_flags;
wire [15:0] tcp_s_tcp_window, tcp_s_tcp_length;
wire [7:0] tcp_s_tcp_payload_axis_tdata;
wire tcp_s_tcp_payload_axis_tvalid, tcp_s_tcp_payload_axis_tready, tcp_s_tcp_payload_axis_tlast;

wire tcp_m_tcp_hdr_valid, tcp_m_tcp_hdr_ready;
wire [31:0] tcp_m_tcp_ip_source_ip;
wire [15:0] tcp_m_tcp_source_port, tcp_m_tcp_dest_port;
wire [31:0] tcp_m_tcp_seq_num, tcp_m_tcp_ack_num;
wire [8:0] tcp_m_tcp_flags;
wire [15:0] tcp_m_tcp_window;
wire [7:0] tcp_m_tcp_payload_axis_tdata;
wire tcp_m_tcp_payload_axis_tvalid, tcp_m_tcp_payload_axis_tready, tcp_m_tcp_payload_axis_tlast;

wire tcp_rx_busy;

// IP identification: free-running counter, advanced once per transmitted
// IP frame (each accepted outgoing TCP header)
reg [15:0] ip_id_counter_reg = 16'd0;
always @(posedge clk) begin
    if (rst) begin
        ip_id_counter_reg <= 16'd0;
    end else if (tcp_s_tcp_hdr_valid && tcp_s_tcp_hdr_ready) begin
        ip_id_counter_reg <= ip_id_counter_reg + 16'd1;
    end
end

tcp_client_tx #(
    .PACKETS(TX_BUFFER_PACKETS),
    .PACKET_SIZE(TX_BUFFER_PACKET_SIZE),
    .RETRY_COUNT(RETRY_COUNT),
    .RETRY_INTERVAL(RETRY_INTERVAL),
    .RETRY_TIMEOUT(RETRY_TIMEOUT)
)
tcp_client_tx_inst (
    .clk(clk),
    .rst(rst),
    .s_axis_tdata(s_axis_tdata),
    .s_axis_tvalid(s_axis_tvalid),
    .s_axis_tready(s_axis_tready),
    .s_axis_tlast(s_axis_tlast),
    .buffer_enable(buffer_enable),
    .local_port(LOCAL_PORT[15:0]),
    .remote_ip(remote_ip_reg),
    .remote_port(remote_port_reg),
    .isn(isn_at_connect_reg),
    .syn_start(syn_start_reg),
    .syn_ack_seen(syn_ack_seen_reg),
    .send_ack(send_ack_reg),
    .fin_start(fin_start_reg),
    .rst_now(rst_now_reg),
    .clear(clear_reg),
    .snd_ack_num(rcv_nxt_reg),
    .rcv_window(16'hffff),
    .peer_ack_num(rx_seg_ack_num),
    .peer_ack_valid(rx_seg_valid && rx_seg_flags[4]),
    .snd_nxt(tx_snd_nxt),
    .buffer_empty(tx_buffer_empty),
    .retries_exhausted(tx_retries_exhausted),
    .fin_acked(tx_fin_acked),
    .s_tcp_hdr_valid(tcp_s_tcp_hdr_valid),
    .s_tcp_hdr_ready(tcp_s_tcp_hdr_ready),
    .s_tcp_ip_dest_ip(tcp_s_tcp_ip_dest_ip),
    .s_tcp_source_port(tcp_s_tcp_source_port),
    .s_tcp_dest_port(tcp_s_tcp_dest_port),
    .s_tcp_seq_num(tcp_s_tcp_seq_num),
    .s_tcp_ack_num(tcp_s_tcp_ack_num),
    .s_tcp_flags(tcp_s_tcp_flags),
    .s_tcp_window(tcp_s_tcp_window),
    .s_tcp_length(tcp_s_tcp_length),
    .s_tcp_payload_axis_tdata(tcp_s_tcp_payload_axis_tdata),
    .s_tcp_payload_axis_tvalid(tcp_s_tcp_payload_axis_tvalid),
    .s_tcp_payload_axis_tready(tcp_s_tcp_payload_axis_tready),
    .s_tcp_payload_axis_tlast(tcp_s_tcp_payload_axis_tlast)
);

tcp_client_rx
tcp_client_rx_inst (
    .clk(clk),
    .rst(rst),
    .conn_active(conn_active),
    .remote_ip(remote_ip_reg),
    .remote_port(remote_port_reg),
    .local_port(LOCAL_PORT[15:0]),
    .rcv_nxt(rcv_nxt_reg),
    .accept_data(accept_data),
    .rx_seg_valid(rx_seg_valid),
    .rx_seg_seq_num(rx_seg_seq_num),
    .rx_seg_ack_num(rx_seg_ack_num),
    .rx_seg_flags(rx_seg_flags),
    .rx_seg_window(rx_seg_window),
    .rx_seg_payload_len(rx_seg_payload_len),
    .m_axis_tdata(m_axis_tdata),
    .m_axis_tvalid(m_axis_tvalid),
    .m_axis_tready(m_axis_tready),
    .m_axis_tlast(m_axis_tlast),
    .m_tcp_hdr_valid(tcp_m_tcp_hdr_valid),
    .m_tcp_hdr_ready(tcp_m_tcp_hdr_ready),
    .m_tcp_ip_source_ip(tcp_m_tcp_ip_source_ip),
    .m_tcp_source_port(tcp_m_tcp_source_port),
    .m_tcp_dest_port(tcp_m_tcp_dest_port),
    .m_tcp_seq_num(tcp_m_tcp_seq_num),
    .m_tcp_ack_num(tcp_m_tcp_ack_num),
    .m_tcp_flags(tcp_m_tcp_flags),
    .m_tcp_window(tcp_m_tcp_window),
    .m_tcp_payload_axis_tdata(tcp_m_tcp_payload_axis_tdata),
    .m_tcp_payload_axis_tvalid(tcp_m_tcp_payload_axis_tvalid),
    .m_tcp_payload_axis_tready(tcp_m_tcp_payload_axis_tready),
    .m_tcp_payload_axis_tlast(tcp_m_tcp_payload_axis_tlast),
    .rx_busy(tcp_rx_busy)
);

tcp #(
    .CHECKSUM_GEN_ENABLE(CHECKSUM_GEN_ENABLE),
    .CHECKSUM_PAYLOAD_FIFO_DEPTH(CHECKSUM_PAYLOAD_FIFO_DEPTH),
    .CHECKSUM_HEADER_FIFO_DEPTH(CHECKSUM_HEADER_FIFO_DEPTH)
)
tcp_inst (
    .clk(clk),
    .rst(rst),

    .s_ip_hdr_valid(s_ip_hdr_valid),
    .s_ip_hdr_ready(s_ip_hdr_ready),
    .s_ip_eth_dest_mac(s_ip_eth_dest_mac),
    .s_ip_eth_src_mac(s_ip_eth_src_mac),
    .s_ip_eth_type(s_ip_eth_type),
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
    .m_ip_payload_axis_tvalid(m_ip_payload_axis_tvalid),
    .m_ip_payload_axis_tready(m_ip_payload_axis_tready),
    .m_ip_payload_axis_tlast(m_ip_payload_axis_tlast),
    .m_ip_payload_axis_tuser(m_ip_payload_axis_tuser),

    .s_tcp_hdr_valid(tcp_s_tcp_hdr_valid),
    .s_tcp_hdr_ready(tcp_s_tcp_hdr_ready),
    .s_tcp_eth_dest_mac(48'd0),
    .s_tcp_eth_src_mac(48'd0),
    .s_tcp_eth_type(16'h0800),
    .s_tcp_ip_version(4'd4),
    .s_tcp_ip_ihl(4'd5),
    .s_tcp_ip_dscp(6'd0),
    .s_tcp_ip_ecn(2'd0),
    .s_tcp_ip_identification(ip_id_counter_reg),
    .s_tcp_ip_flags(3'd2),
    .s_tcp_ip_fragment_offset(13'd0),
    .s_tcp_ip_ttl(8'd64),
    .s_tcp_ip_header_checksum(16'd0),
    .s_tcp_ip_source_ip(LOCAL_IP),
    .s_tcp_ip_dest_ip(tcp_s_tcp_ip_dest_ip),
    .s_tcp_source_port(tcp_s_tcp_source_port),
    .s_tcp_dest_port(tcp_s_tcp_dest_port),
    .s_tcp_seq_num(tcp_s_tcp_seq_num),
    .s_tcp_ack_num(tcp_s_tcp_ack_num),
    .s_tcp_data_offset(4'd5),
    .s_tcp_reserved(3'd0),
    .s_tcp_flags(tcp_s_tcp_flags),
    .s_tcp_window(tcp_s_tcp_window),
    .s_tcp_checksum(16'd0),
    .s_tcp_urgent_pointer(16'd0),
    .s_tcp_length(tcp_s_tcp_length),
    .s_tcp_payload_axis_tdata(tcp_s_tcp_payload_axis_tdata),
    .s_tcp_payload_axis_tvalid(tcp_s_tcp_payload_axis_tvalid),
    .s_tcp_payload_axis_tready(tcp_s_tcp_payload_axis_tready),
    .s_tcp_payload_axis_tlast(tcp_s_tcp_payload_axis_tlast),
    .s_tcp_payload_axis_tuser(1'b0),

    .m_tcp_hdr_valid(tcp_m_tcp_hdr_valid),
    .m_tcp_hdr_ready(tcp_m_tcp_hdr_ready),
    .m_tcp_eth_dest_mac(),
    .m_tcp_eth_src_mac(),
    .m_tcp_eth_type(),
    .m_tcp_ip_version(),
    .m_tcp_ip_ihl(),
    .m_tcp_ip_dscp(),
    .m_tcp_ip_ecn(),
    .m_tcp_ip_length(),
    .m_tcp_ip_identification(),
    .m_tcp_ip_flags(),
    .m_tcp_ip_fragment_offset(),
    .m_tcp_ip_ttl(),
    .m_tcp_ip_protocol(),
    .m_tcp_ip_header_checksum(),
    .m_tcp_ip_source_ip(tcp_m_tcp_ip_source_ip),
    .m_tcp_ip_dest_ip(),
    .m_tcp_source_port(tcp_m_tcp_source_port),
    .m_tcp_dest_port(tcp_m_tcp_dest_port),
    .m_tcp_seq_num(tcp_m_tcp_seq_num),
    .m_tcp_ack_num(tcp_m_tcp_ack_num),
    .m_tcp_data_offset(),
    .m_tcp_reserved(),
    .m_tcp_flags(tcp_m_tcp_flags),
    .m_tcp_window(tcp_m_tcp_window),
    .m_tcp_checksum(),
    .m_tcp_urgent_pointer(),
    .m_tcp_payload_axis_tdata(tcp_m_tcp_payload_axis_tdata),
    .m_tcp_payload_axis_tvalid(tcp_m_tcp_payload_axis_tvalid),
    .m_tcp_payload_axis_tready(tcp_m_tcp_payload_axis_tready),
    .m_tcp_payload_axis_tlast(tcp_m_tcp_payload_axis_tlast),
    .m_tcp_payload_axis_tuser(),

    .rx_busy(tcp_rx_busy),
    .tx_busy(),
    .rx_error_header_early_termination(),
    .rx_error_payload_early_termination(),
    .tx_error_payload_early_termination()
);

// connection FSM
always @* begin
    state_next = state_reg;
    remote_ip_next = remote_ip_reg;
    remote_port_next = remote_port_reg;
    rcv_nxt_next = rcv_nxt_reg;
    pending_close_next = pending_close_reg;
    peer_fin_seen_next = peer_fin_seen_reg;
    our_fin_acked_next = our_fin_acked_reg;
    error_next = 1'b0;
    config_error_next = cmd_unknown;

    syn_start_next = 1'b0;
    syn_ack_seen_next = 1'b0;
    send_ack_next = 1'b0;
    fin_start_next = 1'b0;
    rst_now_next = 1'b0;
    clear_next = 1'b0;

    case (state_reg)
        STATE_CLOSED: begin
            if (cmd_connect) begin
                remote_ip_next = cfg_dest_ip;
                remote_port_next = cfg_dest_port;
                rcv_nxt_next = 32'd0;
                syn_start_next = 1'b1;
                clear_next = 1'b1;
                pending_close_next = 1'b0;
                state_next = STATE_SYN_SENT;
            end else if (cmd_disconnect) begin
                config_error_next = 1'b1;
            end
        end

        STATE_SYN_SENT: begin
            if (rx_seg_valid && rx_seg_flags[2]) begin
                clear_next = 1'b1;
                error_next = 1'b1;
                state_next = STATE_CLOSED;
            end else if (rx_seg_valid && rx_seg_flags[1] && rx_seg_flags[4] &&
                    (rx_seg_ack_num == isn_at_connect_reg + 32'd1)) begin
                rcv_nxt_next = rx_seg_seq_num + 32'd1;
                syn_ack_seen_next = 1'b1;
                send_ack_next = 1'b1;
                state_next = STATE_ESTABLISHED;
            end else if (tx_retries_exhausted) begin
                clear_next = 1'b1;
                error_next = 1'b1;
                state_next = STATE_CLOSED;
            end else if (cmd_connect || cmd_disconnect) begin
                config_error_next = 1'b1;
            end
        end

        STATE_ESTABLISHED: begin
            if (rx_seg_valid && rx_seg_flags[2]) begin
                clear_next = 1'b1;
                error_next = 1'b1;
                state_next = STATE_CLOSED;
            end else if (tx_retries_exhausted) begin
                rst_now_next = 1'b1;
                clear_next = 1'b1;
                error_next = 1'b1;
                state_next = STATE_CLOSED;
            end else begin
                if (rx_seg_valid && (rx_seg_seq_num == rcv_nxt_reg)) begin
                    if (rx_seg_payload_len != 16'd0) begin
                        rcv_nxt_next = rcv_nxt_reg + {16'd0, rx_seg_payload_len};
                        send_ack_next = 1'b1;
                    end
                    if (rx_seg_flags[0]) begin
                        rcv_nxt_next = rcv_nxt_reg + {16'd0, rx_seg_payload_len} + 32'd1;
                        send_ack_next = 1'b1;
                        state_next = STATE_CLOSE_WAIT;
                    end
                end

                if (cmd_connect) begin
                    config_error_next = 1'b1;
                end else if (cmd_disconnect && state_next == STATE_ESTABLISHED) begin
                    pending_close_next = 1'b1;
                end

                if (state_next == STATE_ESTABLISHED && pending_close_next && tx_buffer_empty) begin
                    fin_start_next = 1'b1;
                    pending_close_next = 1'b0;
                    peer_fin_seen_next = 1'b0;
                    our_fin_acked_next = 1'b0;
                    state_next = STATE_FIN_WAIT;
                end
            end
        end

        STATE_CLOSE_WAIT: begin
            if (rx_seg_valid && rx_seg_flags[2]) begin
                clear_next = 1'b1;
                error_next = 1'b1;
                state_next = STATE_CLOSED;
            end else if (tx_retries_exhausted) begin
                rst_now_next = 1'b1;
                clear_next = 1'b1;
                error_next = 1'b1;
                state_next = STATE_CLOSED;
            end else if (tx_buffer_empty) begin
                fin_start_next = 1'b1;
                state_next = STATE_LAST_ACK;
            end
        end

        STATE_LAST_ACK: begin
            if (rx_seg_valid && rx_seg_flags[2]) begin
                clear_next = 1'b1;
                error_next = 1'b1;
                state_next = STATE_CLOSED;
            end else if (tx_retries_exhausted) begin
                rst_now_next = 1'b1;
                clear_next = 1'b1;
                error_next = 1'b1;
                state_next = STATE_CLOSED;
            end else if (tx_fin_acked) begin
                clear_next = 1'b1;
                state_next = STATE_CLOSED;
            end
        end

        STATE_FIN_WAIT: begin
            if (rx_seg_valid && rx_seg_flags[2]) begin
                clear_next = 1'b1;
                error_next = 1'b1;
                state_next = STATE_CLOSED;
            end else if (tx_retries_exhausted) begin
                rst_now_next = 1'b1;
                clear_next = 1'b1;
                error_next = 1'b1;
                state_next = STATE_CLOSED;
            end else begin
                if (rx_seg_valid && rx_seg_flags[0] && (rx_seg_seq_num == rcv_nxt_reg)) begin
                    rcv_nxt_next = rcv_nxt_reg + {16'd0, rx_seg_payload_len} + 32'd1;
                    send_ack_next = 1'b1;
                    peer_fin_seen_next = 1'b1;
                end

                if (tx_fin_acked) begin
                    our_fin_acked_next = 1'b1;
                end

                if (peer_fin_seen_next && our_fin_acked_next) begin
                    clear_next = 1'b1;
                    state_next = STATE_CLOSED;
                end
            end
        end

        default: state_next = STATE_CLOSED;
    endcase
end

always @(posedge clk) begin
    if (rst) begin
        state_reg <= STATE_CLOSED;
        remote_ip_reg <= 32'd0;
        remote_port_reg <= 16'd0;
        rcv_nxt_reg <= 32'd0;
        pending_close_reg <= 1'b0;
        peer_fin_seen_reg <= 1'b0;
        our_fin_acked_reg <= 1'b0;
        error_reg <= 1'b0;
        config_error_reg <= 1'b0;
        syn_start_reg <= 1'b0;
        syn_ack_seen_reg <= 1'b0;
        send_ack_reg <= 1'b0;
        fin_start_reg <= 1'b0;
        rst_now_reg <= 1'b0;
        clear_reg <= 1'b0;
        isn_at_connect_reg <= 32'd0;
    end else begin
        state_reg <= state_next;
        remote_ip_reg <= remote_ip_next;
        remote_port_reg <= remote_port_next;
        rcv_nxt_reg <= rcv_nxt_next;
        pending_close_reg <= pending_close_next;
        peer_fin_seen_reg <= peer_fin_seen_next;
        our_fin_acked_reg <= our_fin_acked_next;
        error_reg <= error_next;
        config_error_reg <= config_error_next;
        syn_start_reg <= syn_start_next;
        syn_ack_seen_reg <= syn_ack_seen_next;
        send_ack_reg <= send_ack_next;
        fin_start_reg <= fin_start_next;
        rst_now_reg <= rst_now_next;
        clear_reg <= clear_next;

        if (syn_start_next) begin
            isn_at_connect_reg <= isn_counter_reg;
        end
    end
end

endmodule

`resetall
