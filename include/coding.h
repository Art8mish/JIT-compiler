#ifndef CODING_H_INCLUDED
#define CODING_H_INCLUDED

#include <stdint.h>


#define MSK16(cmd)         (cmd  & 0xFFFF)
#define MSK3(cmd)          (cmd  & 0b111)
#define MSK_CNST32(cnst)   (cnst & 0xFFFFFF00)


//BCODE_CODING///////////////////
////////////////////////////////

#define DEF_CMD(name, num, arg, code) \
                BCODE_##name = num,
enum AsmCode
{
    #include "../proc/cmd.h"
};

#undef DEF_CMD

enum ByteCodeMods
{
    BCODE_CNST = 1 << 16,
    BCODE_REG  = 1 << 17,
    BCODE_MEM  = 1 << 18,

    BCODE_MEM_REG      = BCODE_MEM | BCODE_REG,
    BCODE_MEM_CNST     = BCODE_MEM | BCODE_CNST,
    BCODE_MEM_REG_CNST = BCODE_MEM | BCODE_REG | BCODE_CNST
};

enum AsmRegNum
{
    BCODE_REG_RAX = 1,
    BCODE_REG_RBX = 2,
    BCODE_REG_RCX = 3,
    BCODE_REG_RDX = 4,
};

#define MSK_BCODE_MOD(cmd) (cmd  & BCODE_MEM_REG_CNST)

//IR_CODING/////////////////////
////////////////////////////////
//______________________________
//COMMANDS

const int8_t IRC_HLT = 0x00;

const int8_t IRC_PUSH      = 0x50;
const int8_t IRC_PUSH_RAX  = IRC_PUSH + IRC_RAX;
const int8_t IRC_PUSH_RCX  = IRC_PUSH + IRC_RCX;
const int8_t IRC_PUSH_RDX  = IRC_PUSH + IRC_RDX;
const int8_t IRC_PUSH_RBX  = IRC_PUSH + IRC_RBX;
const int8_t IRC_PUSH_RDI  = IRC_PUSH + IRC_RDI;
const int8_t IRC_PUSH_CNST = 0x68;
const int8_t IRC_PUSH_MEM  = 0xff;

const int8_t IRC_POP     = 0x58;
const int8_t IRC_POP_RAX = IRC_POP + IRC_RAX;
const int8_t IRC_POP_RCX = IRC_POP + IRC_RCX;
const int8_t IRC_POP_RDX = IRC_POP + IRC_RDX;
const int8_t IRC_POP_RBX = IRC_POP + IRC_RBX;
const int8_t IRC_POP_RDI = IRC_POP + IRC_RDI;
const int8_t IRC_POP_RSI = IRC_POP + IRC_RSI;
const int8_t IRC_POP_MEM = 0x8f;

const int8_t IRC_MOV = 0x89;

const int8_t IRC_JMP = 0xE9;
const int8_t IRC_JB  = 0x72;
const int8_t IRC_JBE = 0x76;
const int8_t IRC_JA  = 0x77;
const int8_t IRC_JAE = 0x73;
const int8_t IRC_JE  = 0x74;
const int8_t IRC_JNE = 0x75;

const int8_t IRC_CALL = 0xE8;
const int8_t IRC_RET  = 0xC3;

const int8_t IRC_ADD  = 0x01;
const int8_t IRC_SUB  = 0x29;
const int8_t IRC_IMUL = 0xAF;
const int8_t IRC_IDIV = 0xF7;

const int8_t IRC_OUT = 0x08;
const int8_t IRC_IN  = 0x09;

const int8_t IRC_DUMP = 0xA0;

const int8_t IRC_TWO_BYTE = 0x0F;

//_______________________________
//REGS

const int8_t IRC_RAX = 0b000;
const int8_t IRC_RCX = 0b001;
const int8_t IRC_RDX = 0b010;
const int8_t IRC_RBX = 0b011;

const int8_t IRC_RSI = 0b110;
const int8_t IRC_RDI = 0b111;
const int8_t IRC_RSP = 0b100;

//_______________________________
//MODRM

//mod
const int8_t IRC_MODRM_MOD_REG      = 0b00;
const int8_t IRC_MODRM_MOD_CNST     = 0b00;
const int8_t IRC_MODRM_MOD_REG_CNST = 0b10;
const int8_t IRC_MODRM_MOD_REG_REG  = 0b11;

const int8_t IRC_MODRM_REG_POP = 0b000;

//reg
const int8_t IRC_MODRM_REG_IDIV64 = 0b111;

//rm
const int8_t IRC_MODRM_RM_SIB = 0b100;

//_______________________________
//SIB

//scale
const int8_t IRC_SIB_SCLF1 = 0b00;
const int8_t IRC_SIB_SCLF2 = 0b01;
const int8_t IRC_SIB_SCLF4 = 0b10;
const int8_t IRC_SIB_SCLF8 = 0b11;

//index
const int8_t IRC_SIB_INDX_NONE = 0b100;

//base
const int8_t IRC_SIB_BASE_NONE = 0b101;

//_______________________________
//PREFIXES

const int8_t IRC_PRFX_OP64 = 0x48;


//_______________________________
const int8_t MOD_MEM_CODE  = 1 << 0;
const int8_t MOD_REG_CODE  = 1 << 1;
const int8_t MOD_CNST_CODE = 1 << 2;
const int8_t MOD_JUMP_CODE = 1 << 3;


#define MEM_MSK(arg)  (arg & MOD_MEM)
#define REG_MSK(arg)  (arg & MOD_REG)
#define CNST_MSK(arg) (arg & MOD_CNST)
#define JUMP_MSK(arg) (arg & MOD_JUMP)

//_________________________________________________
const int8_t MOD_REG          = MOD_REG;
const int8_t MOD_CNST         = MOD_CNST;
const uint8_t MOD_MEM_REG      = MOD_MEM | MOD_REG;
const uint8_t MOD_MEM_CNST     = MOD_MEM | MOD_CNST;
const uint8_t MOD_MEM_REG_CNST = MOD_MEM | MOD_REG | MOD_CNST;

enum Mods
{
    MOD_REG_REG = 0b11,
};


#endif //CODING_H_INCLUDED