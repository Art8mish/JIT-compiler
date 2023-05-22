
#ifndef IR_CMD
#define IR_CMD(name, prefix, ModRMbyte, constant)  
#endif
//prfx  = 0/1 -> n/y prefix byte
//modrm = 0/1 -> n/y ModRM byte
//cnst  = 0/1/2 -> n/cnst32/cnst64 ModRM byte

IR_CMD(PUSH_RAX,  0, 0, 0)
IR_CMD(PUSH_RCX,  0, 0, 0)
IR_CMD(PUSH_RDX,  0, 0, 0)
IR_CMD(PUSH_RBX,  0, 0, 0)
IR_CMD(PUSH_RDI,  0, 0, 0)
IR_CMD(PUSH_CNST, 0, 0, 1)
IR_CMD(MEM,       0, 1, 0)

IR_CMD(POP_RAX, 0, 0, 0)
IR_CMD(POP_RCX, 0, 0, 0)
IR_CMD(POP_RDX, 0, 0, 0)
IR_CMD(POP_RBX, 0, 0, 0)
IR_CMD(POP_RDI, 0, 0, 0)
IR_CMD(POP_RSI, 0, 0, 0)
IR_CMD(POP_MEM, 0, 1, 0)

IR_CMD(CALL_REL, 0, 0, 1)
IR_CMD(RET, 0, 0, 0)
IR_CMD(HLT, 0, 0, 0)

IR_CMD(JMP, 0, 0, 1)
IR_CMD(TWO_BYTE, 0, 0, 0)
IR_CMD(JB,  0, 0, 1)
IR_CMD(JBE, 0, 0, 1)
IR_CMD(JA,  0, 0, 1)
IR_CMD(JAE, 0, 0, 1)
IR_CMD(JE,  0, 0, 1)
IR_CMD(JNE, 0, 0, 1)


IR_CMD(ADD,  1, 1, 0)
IR_CMD(SUB,  1, 1, 0)
IR_CMD(IMUL, 1, 1, 0)
IR_CMD(IDIV, 1, 1, 0)

IR_CMD(OP_CNST, 1, 1, 1)


IR_CMD(MOV_REG_MEM, 1, 1, 0)
IR_CMD(MOV_REG_REG, 1, 1, 0)
IR_CMD(MOVABS_RAX,  1, 0, 2)
IR_CMD(MOVABS_RDI,  1, 0, 2)
IR_CMD(MOVABS_RSI,  1, 0, 2)

IR_CMD(CMP_REG_REG, 1, 1, 0)

IR_CMD(LEA_REG_MEM, 1, 1, 0)







