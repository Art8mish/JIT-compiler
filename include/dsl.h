#ifndef DSL_H_INCLUDED
#define DSL_H_INCLUDED

#define IR_ITM ir->buf[ir->ip]

#define IR_CMD_B1(ir) (ir->buf[ir->ip].cmd.b1)
#define IR_CMD_B2(ir) (ir->buf[ir->ip].cmd.b2)
#define IR_LEN(ir)    (ir->buf[ir->ip].instr_len)
#define IR_PRFX(ir)   (ir->buf[ir->ip].prfx)
#define IR_IP(ir)     (ir->ip)

#define IR_CNST32(ir) ((int32_t)ir->buf[ir->ip].cnst)
#define IR_CNST64(ir) (ir->buf[ir->ip].cnst)

#define IR_MODRM(ir)  (*((int8_t *)(&ir->buf[ir->ip].ModRM)))
#define IR_MODRM_MOD(ir) (IR_MODRM(ir) & 0b11000000)
#define IR_MODRM_REG(ir) (IR_MODRM(ir) & 0b111000)
#define IR_MODRM_RM(ir)  (IR_MODRM(ir) & 0b111)

#define IR_SIB(ir)    (*((int8_t *)(&ir->buf[ir->ip].SIB)))
#define IR_SIB_SCALE(ir) (IR_SIB(ir) & 0b11000000)
#define IR_SIB_INDEX(ir) (IR_SIB(ir) & 0b111000)
#define IR_SIB_BASE(ir)  (IR_SIB(ir) & 0b111)

#define IR_MODRM_MOD_IS_00(ir)       (IR_MODRM_MOD(ir) == (IRC_MODRM_MOD_00 << 6))
#define IR_MODRM_MOD_IS_REG_CNST(ir) (IR_MODRM_MOD(ir) == (IRC_MODRM_MOD_REG_CNST << 6))
#define IR_CMD_B1_IS_MEM(ir)         (IR_CMD_B1(ir) == IRC_POP_MEM  || IR_CMD_B1(ir) == IRC_MEM)
#define IR_ARG_IS_MEM_CNST(ir)       (IR_MODRM_MOD(ir) == (IRC_MODRM_MOD_00 << 6)  &&     \
                                      IR_MODRM_RM(ir)  == IRC_MODRM_RM_SIB  &&     \
                                      IR_SIB_BASE(ir)  == IRC_SIB_BASE_NONE)

#define IS_BCODE_JUMP(cmd)                \
           ((MSK16(cmd) == BCODE_JMP) ||  \
            (MSK16(cmd) == BCODE_JB)  ||  \
            (MSK16(cmd) == BCODE_JBE) ||  \
            (MSK16(cmd) == BCODE_JA)  ||  \
            (MSK16(cmd) == BCODE_JAE) ||  \
            (MSK16(cmd) == BCODE_JE)  ||  \
            (MSK16(cmd) == BCODE_JNE) ||  \
            (MSK16(cmd) == BCODE_CALL))

#define IS_BCODE_CND_JMP(cmd)             \
           ((MSK16(cmd) == BCODE_JB)  ||  \
            (MSK16(cmd) == BCODE_JBE) ||  \
            (MSK16(cmd) == BCODE_JA)  ||  \
            (MSK16(cmd) == BCODE_JAE) ||  \
            (MSK16(cmd) == BCODE_JE)  ||  \
            (MSK16(cmd) == BCODE_JNE))

#endif //DSL_H_INCLUDED