`timescale 1ns/1ps
// GENERATED microcode ROM for the ECC datapath (do not edit by hand).
// Point addition / doubling use the complete projective formulas for prime-order
// short-Weierstrass curves with a = -3 (Renes-Costello-Batina 2016, Alg. 4 and 6):
// no exceptional cases, no data-dependent branches.
// Instruction = {op[2:0], dst[3:0], src1[3:0], src2[3:0]}; op: 0 MUL, 1 ADD, 2 SUB, 3 MOV
// Register map: R0..R2 = X1,Y1,Z1  R3..R5 = X2,Y2,Z2  R6..R8 = X3,Y3,Z3
//               R9..R13 = t0..t4   R14 = curve constant b   R15 = spare
module ecc_ucode (
    input  wire [6:0]  addr,
    output reg  [14:0] instr
);
  localparam [6:0] P_ADD_S = 7'd0, P_ADD_E = 7'd42;
  localparam [6:0] P_DBL_S = 7'd43, P_DBL_E = 7'd76;
  localparam [6:0] P_MOVB_S = 7'd77, P_MOVB_E = 7'd79;
  localparam [6:0] P_MOVA_S = 7'd80, P_MOVA_E = 7'd82;
  localparam [6:0] P_AFF_S = 7'd83, P_AFF_E = 7'd84;
  localparam [6:0] P_MULN_S = 7'd85, P_MULN_E = 7'd85;
  localparam [6:0] P_ADDN_S = 7'd86, P_ADDN_E = 7'd86;
  localparam [6:0] P_ONC_S = 7'd87, P_ONC_E = 7'd93;
  always @* begin
    case (addr)
      7'd0: instr = {3'd0, 4'd9, 4'd0, 4'd3};  // MUL R9, R0, R3
      7'd1: instr = {3'd0, 4'd10, 4'd1, 4'd4};  // MUL R10, R1, R4
      7'd2: instr = {3'd0, 4'd11, 4'd2, 4'd5};  // MUL R11, R2, R5
      7'd3: instr = {3'd1, 4'd12, 4'd0, 4'd1};  // ADD R12, R0, R1
      7'd4: instr = {3'd1, 4'd13, 4'd3, 4'd4};  // ADD R13, R3, R4
      7'd5: instr = {3'd0, 4'd12, 4'd12, 4'd13};  // MUL R12, R12, R13
      7'd6: instr = {3'd1, 4'd13, 4'd9, 4'd10};  // ADD R13, R9, R10
      7'd7: instr = {3'd2, 4'd12, 4'd12, 4'd13};  // SUB R12, R12, R13
      7'd8: instr = {3'd1, 4'd13, 4'd1, 4'd2};  // ADD R13, R1, R2
      7'd9: instr = {3'd1, 4'd6, 4'd4, 4'd5};  // ADD R6, R4, R5
      7'd10: instr = {3'd0, 4'd13, 4'd13, 4'd6};  // MUL R13, R13, R6
      7'd11: instr = {3'd1, 4'd6, 4'd10, 4'd11};  // ADD R6, R10, R11
      7'd12: instr = {3'd2, 4'd13, 4'd13, 4'd6};  // SUB R13, R13, R6
      7'd13: instr = {3'd1, 4'd6, 4'd0, 4'd2};  // ADD R6, R0, R2
      7'd14: instr = {3'd1, 4'd7, 4'd3, 4'd5};  // ADD R7, R3, R5
      7'd15: instr = {3'd0, 4'd6, 4'd6, 4'd7};  // MUL R6, R6, R7
      7'd16: instr = {3'd1, 4'd7, 4'd9, 4'd11};  // ADD R7, R9, R11
      7'd17: instr = {3'd2, 4'd7, 4'd6, 4'd7};  // SUB R7, R6, R7
      7'd18: instr = {3'd0, 4'd8, 4'd14, 4'd11};  // MUL R8, R14, R11
      7'd19: instr = {3'd2, 4'd6, 4'd7, 4'd8};  // SUB R6, R7, R8
      7'd20: instr = {3'd1, 4'd8, 4'd6, 4'd6};  // ADD R8, R6, R6
      7'd21: instr = {3'd1, 4'd6, 4'd6, 4'd8};  // ADD R6, R6, R8
      7'd22: instr = {3'd2, 4'd8, 4'd10, 4'd6};  // SUB R8, R10, R6
      7'd23: instr = {3'd1, 4'd6, 4'd10, 4'd6};  // ADD R6, R10, R6
      7'd24: instr = {3'd0, 4'd7, 4'd14, 4'd7};  // MUL R7, R14, R7
      7'd25: instr = {3'd1, 4'd10, 4'd11, 4'd11};  // ADD R10, R11, R11
      7'd26: instr = {3'd1, 4'd11, 4'd10, 4'd11};  // ADD R11, R10, R11
      7'd27: instr = {3'd2, 4'd7, 4'd7, 4'd11};  // SUB R7, R7, R11
      7'd28: instr = {3'd2, 4'd7, 4'd7, 4'd9};  // SUB R7, R7, R9
      7'd29: instr = {3'd1, 4'd10, 4'd7, 4'd7};  // ADD R10, R7, R7
      7'd30: instr = {3'd1, 4'd7, 4'd10, 4'd7};  // ADD R7, R10, R7
      7'd31: instr = {3'd1, 4'd10, 4'd9, 4'd9};  // ADD R10, R9, R9
      7'd32: instr = {3'd1, 4'd9, 4'd10, 4'd9};  // ADD R9, R10, R9
      7'd33: instr = {3'd2, 4'd9, 4'd9, 4'd11};  // SUB R9, R9, R11
      7'd34: instr = {3'd0, 4'd10, 4'd13, 4'd7};  // MUL R10, R13, R7
      7'd35: instr = {3'd0, 4'd11, 4'd9, 4'd7};  // MUL R11, R9, R7
      7'd36: instr = {3'd0, 4'd7, 4'd6, 4'd8};  // MUL R7, R6, R8
      7'd37: instr = {3'd1, 4'd7, 4'd7, 4'd11};  // ADD R7, R7, R11
      7'd38: instr = {3'd0, 4'd6, 4'd12, 4'd6};  // MUL R6, R12, R6
      7'd39: instr = {3'd2, 4'd6, 4'd6, 4'd10};  // SUB R6, R6, R10
      7'd40: instr = {3'd0, 4'd8, 4'd13, 4'd8};  // MUL R8, R13, R8
      7'd41: instr = {3'd0, 4'd10, 4'd12, 4'd9};  // MUL R10, R12, R9
      7'd42: instr = {3'd1, 4'd8, 4'd8, 4'd10};  // ADD R8, R8, R10
      7'd43: instr = {3'd0, 4'd9, 4'd0, 4'd0};  // MUL R9, R0, R0
      7'd44: instr = {3'd0, 4'd10, 4'd1, 4'd1};  // MUL R10, R1, R1
      7'd45: instr = {3'd0, 4'd11, 4'd2, 4'd2};  // MUL R11, R2, R2
      7'd46: instr = {3'd0, 4'd12, 4'd0, 4'd1};  // MUL R12, R0, R1
      7'd47: instr = {3'd1, 4'd12, 4'd12, 4'd12};  // ADD R12, R12, R12
      7'd48: instr = {3'd0, 4'd8, 4'd0, 4'd2};  // MUL R8, R0, R2
      7'd49: instr = {3'd1, 4'd8, 4'd8, 4'd8};  // ADD R8, R8, R8
      7'd50: instr = {3'd0, 4'd7, 4'd14, 4'd11};  // MUL R7, R14, R11
      7'd51: instr = {3'd2, 4'd7, 4'd7, 4'd8};  // SUB R7, R7, R8
      7'd52: instr = {3'd1, 4'd6, 4'd7, 4'd7};  // ADD R6, R7, R7
      7'd53: instr = {3'd1, 4'd7, 4'd6, 4'd7};  // ADD R7, R6, R7
      7'd54: instr = {3'd2, 4'd6, 4'd10, 4'd7};  // SUB R6, R10, R7
      7'd55: instr = {3'd1, 4'd7, 4'd10, 4'd7};  // ADD R7, R10, R7
      7'd56: instr = {3'd0, 4'd7, 4'd6, 4'd7};  // MUL R7, R6, R7
      7'd57: instr = {3'd0, 4'd6, 4'd6, 4'd12};  // MUL R6, R6, R12
      7'd58: instr = {3'd1, 4'd12, 4'd11, 4'd11};  // ADD R12, R11, R11
      7'd59: instr = {3'd1, 4'd11, 4'd11, 4'd12};  // ADD R11, R11, R12
      7'd60: instr = {3'd0, 4'd8, 4'd14, 4'd8};  // MUL R8, R14, R8
      7'd61: instr = {3'd2, 4'd8, 4'd8, 4'd11};  // SUB R8, R8, R11
      7'd62: instr = {3'd2, 4'd8, 4'd8, 4'd9};  // SUB R8, R8, R9
      7'd63: instr = {3'd1, 4'd12, 4'd8, 4'd8};  // ADD R12, R8, R8
      7'd64: instr = {3'd1, 4'd8, 4'd8, 4'd12};  // ADD R8, R8, R12
      7'd65: instr = {3'd1, 4'd12, 4'd9, 4'd9};  // ADD R12, R9, R9
      7'd66: instr = {3'd1, 4'd9, 4'd12, 4'd9};  // ADD R9, R12, R9
      7'd67: instr = {3'd2, 4'd9, 4'd9, 4'd11};  // SUB R9, R9, R11
      7'd68: instr = {3'd0, 4'd9, 4'd9, 4'd8};  // MUL R9, R9, R8
      7'd69: instr = {3'd1, 4'd7, 4'd7, 4'd9};  // ADD R7, R7, R9
      7'd70: instr = {3'd0, 4'd9, 4'd1, 4'd2};  // MUL R9, R1, R2
      7'd71: instr = {3'd1, 4'd9, 4'd9, 4'd9};  // ADD R9, R9, R9
      7'd72: instr = {3'd0, 4'd8, 4'd9, 4'd8};  // MUL R8, R9, R8
      7'd73: instr = {3'd2, 4'd6, 4'd6, 4'd8};  // SUB R6, R6, R8
      7'd74: instr = {3'd0, 4'd8, 4'd9, 4'd10};  // MUL R8, R9, R10
      7'd75: instr = {3'd1, 4'd8, 4'd8, 4'd8};  // ADD R8, R8, R8
      7'd76: instr = {3'd1, 4'd8, 4'd8, 4'd8};  // ADD R8, R8, R8
      7'd77: instr = {3'd3, 4'd3, 4'd6, 4'd6};  // MOV R3, R6, R6
      7'd78: instr = {3'd3, 4'd4, 4'd7, 4'd7};  // MOV R4, R7, R7
      7'd79: instr = {3'd3, 4'd5, 4'd8, 4'd8};  // MOV R5, R8, R8
      7'd80: instr = {3'd3, 4'd0, 4'd6, 4'd6};  // MOV R0, R6, R6
      7'd81: instr = {3'd3, 4'd1, 4'd7, 4'd7};  // MOV R1, R7, R7
      7'd82: instr = {3'd3, 4'd2, 4'd8, 4'd8};  // MOV R2, R8, R8
      7'd83: instr = {3'd0, 4'd12, 4'd0, 4'd11};  // MUL R12, R0, R11
      7'd84: instr = {3'd0, 4'd13, 4'd1, 4'd11};  // MUL R13, R1, R11
      7'd85: instr = {3'd0, 4'd2, 4'd0, 4'd1};  // MUL R2, R0, R1
      7'd86: instr = {3'd1, 4'd2, 4'd0, 4'd1};  // ADD R2, R0, R1
      7'd87: instr = {3'd0, 4'd9, 4'd0, 4'd0};  // MUL R9, R0, R0
      7'd88: instr = {3'd0, 4'd9, 4'd9, 4'd0};  // MUL R9, R9, R0
      7'd89: instr = {3'd1, 4'd10, 4'd0, 4'd0};  // ADD R10, R0, R0
      7'd90: instr = {3'd1, 4'd10, 4'd10, 4'd0};  // ADD R10, R10, R0
      7'd91: instr = {3'd2, 4'd9, 4'd9, 4'd10};  // SUB R9, R9, R10
      7'd92: instr = {3'd1, 4'd9, 4'd9, 4'd14};  // ADD R9, R9, R14
      7'd93: instr = {3'd0, 4'd11, 4'd1, 4'd1};  // MUL R11, R1, R1
      default: instr = {3'd3, 4'd0, 4'd0, 4'd0};
    endcase
  end
endmodule
