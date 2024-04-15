    logic [VLEN-1:0] first_operand_logic, second_operand_logic;
    logic [VLEN-1:0] result_and, result_or, result_xor, result_logic;

    always_comb begin
        automatic int i = 0;
        if (instruction_operation inside{vand, vor, vxor}) begin
            first_operand_logic  = first_operand;
            second_operand_logic = second_operand;
        end
        else begin
            first_operand_logic[(VLEN/2)-1:0]  = first_operand[(VLEN/2)-1:0];
            second_operand_logic[(VLEN/2)-1:0] = second_operand[VLEN-1:(VLEN/2)];

            first_operand_logic[((VLEN/4)*3)-1:(VLEN/2)]  = result_logic[(VLEN/4)-1:0];
            second_operand_logic[((VLEN/4)*3)-1:(VLEN/2)] = result_logic[(VLEN/2)-1:(VLEN/4)];

            first_operand_logic[VLEN-1:((VLEN/4)*3)]  = result_logic[(VLEN/2)-1:(VLEN/4)];
            second_operand_logic[VLEN-1:((VLEN/4)*3)] = result_logic[(VLEN/2)-1:(VLEN/4)];
        end
    end

    always_comb begin
        result_and = first_operand_logic & second_operand_logic;
        result_or  = first_operand_logic | second_operand_logic;
        result_xor = first_operand_logic ^ second_operand_logic;
    end

    always_comb begin
        unique case(vector_operation_i)
            vor:     result_logic = result_or;
            vxor:    result_logic = result_xor;
            default: result_logic = result_and;
        endcase
    end









//////////////////////////////////////////////////////////////////////////////
// Logical
//////////////////////////////////////////////////////////////////////////////

    logic [VLEN-1:0] second_operand_and, second_operand_or, second_operand_xor;

    logic [VLEN-1:0] result_and, result_or, result_xor;
    logic [31:0]     result_redand, result_redor, result_redxor;

    always_comb begin
        if (vector_operation_i inside {vredand, vredor, vredxor}) begin
            unique case (vsew)
                EW8:
                    for (int i = 0; i < VLENB; i++)
                        if (i == 0) begin
                            second_operand_and[7:0] = second_operand[7:0];
                            second_operand_or [7:0] = second_operand[7:0];
                            second_operand_xor[7:0] = second_operand[7:0];
                        end
                        else begin
                            second_operand_and[(8*(i+1))-1-:8] = result_and[(8*(i))-1-:8];
                            second_operand_or [(8*(i+1))-1-:8] = result_or [(8*(i))-1-:8];
                            second_operand_xor[(8*(i+1))-1-:8] = result_xor[(8*(i))-1-:8];
                        end
                EW16:
                    for (int i = 0; i < VLENB/2; i++)
                        if (i == 0) begin
                            second_operand_and[15:0] = second_operand[15:0];
                            second_operand_or [15:0] = second_operand[15:0];
                            second_operand_xor[15:0] = second_operand[15:0];
                        end
                        else begin
                            second_operand_and[(16*(i+1))-1-:16] = result_and[(16*(i))-1-:16];
                            second_operand_or [(16*(i+1))-1-:16] = result_or [(16*(i))-1-:16];
                            second_operand_xor[(16*(i+1))-1-:16] = result_xor[(16*(i))-1-:16];
                            
                        end
                default:
                    for (int i = 0; i < VLENB/4; i++)
                        if (i == 0) begin
                            second_operand_and[31:0] = second_operand[31:0];
                            second_operand_or [31:0] = second_operand[31:0];
                            second_operand_xor[31:0] = second_operand[31:0];
                        end
                        else begin
                            second_operand_and[(32*(i+1))-1-:32] = result_and[(32*(i))-1-:32];
                            second_operand_or [(32*(i+1))-1-:32] = result_or [(32*(i))-1-:32];
                            second_operand_xor[(32*(i+1))-1-:32] = result_xor[(32*(i))-1-:32];
                        end
            endcase
        end
        else begin
            second_operand_and = second_operand;
        end
    end

    always_comb begin
        result_and = first_operand & second_operand_and;
        result_or  = first_operand | second_operand_or;
        result_xor = first_operand ^ second_operand_xor;
    end

    always_comb begin
        unique case (vsew)
            EW8:     result_redand = {24'h000000, result_and[VLEN-1-:8]};
            EW16:    result_redand = {16'h0000,   result_and[VLEN-1-:16]};
            default: result_redand = {result_and[VLEN-1-:32]};
        endcase
         
    end