#ifndef CODING_H_INCLUDED
#define CODING_H_INCLUDED

#include <stdint.h>


#define MSK16(cmd)         (cmd  & 0xFFFF)
#define MSK3(cmd)          (cmd  & 0b111)
#define MSK_CNST32(cnst)   (cnst & 0xFFFFFF00)
#define MSK_BCODE_MOD(cmd) (cmd  & BCODE_MEM_REG_CNST)
#define MSK_HEXB(num4)     (num4 & 0x000000FF)


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



//IR_CODING/////////////////////
////////////////////////////////
//_______________________________
//REGS

const int8_t IRC_RAX = 0b000;
const int8_t IRC_RCX = 0b001;
const int8_t IRC_RDX = 0b010;
const int8_t IRC_RBX = 0b011;

const int8_t IRC_RSI = 0b110;
const int8_t IRC_RDI = 0b111;
const int8_t IRC_RSP = 0b100;

//______________________________
//COMMANDS

const int8_t IRC_PUSH_RAX  = 0x50 + IRC_RAX;
const int8_t IRC_PUSH_RCX  = 0x50 + IRC_RCX;
const int8_t IRC_PUSH_RDX  = 0x50 + IRC_RDX;
const int8_t IRC_PUSH_RBX  = 0x50 + IRC_RBX;
const int8_t IRC_PUSH_RDI  = 0x50 + IRC_RDI;
const int8_t IRC_PUSH_CNST = 0x68;
const int8_t IRC_MEM  = 0xFF; //PUSH MEM and CALL [reg]

const int8_t IRC_POP_RAX = 0x58 + IRC_RAX;
const int8_t IRC_POP_RCX = 0x58 + IRC_RCX;
const int8_t IRC_POP_RDX = 0x58 + IRC_RDX;
const int8_t IRC_POP_RBX = 0x58 + IRC_RBX;
const int8_t IRC_POP_RDI = 0x58 + IRC_RDI;
const int8_t IRC_POP_RSI = 0x58 + IRC_RSI;
const int8_t IRC_POP_MEM = 0x8F;


const int8_t IRC_CALL_REL = 0xE8;
//const int8_t IRC_CALL_ABS = 0xFF;
const int8_t IRC_RET = 0xC3;
const int8_t IRC_HLT = 0xF4;

//REL ADDR
const int8_t IRC_JMP = 0xE9;
const int8_t IRC_JB  = 0x82;
const int8_t IRC_JBE = 0x86;
const int8_t IRC_JA  = 0x87;
const int8_t IRC_JAE = 0x83;
const int8_t IRC_JE  = 0x84;
const int8_t IRC_JNE = 0x85;

//REG_REG
const int8_t IRC_ADD  = 0x01;
const int8_t IRC_SUB  = 0x29;
const int8_t IRC_IMUL = 0xAF;
const int8_t IRC_IDIV = 0xF7;

//REG CNST
const int8_t IRC_OP_CNST = 0x81;

const int8_t IRC_CMP_REG_REG =  0x39;

const int8_t IRC_MOV_REG_MEM = 0x8B;
const int8_t IRC_MOV_REG_REG = 0x89;
const int8_t IRC_MOVABS_RAX  = 0xB8;
const int8_t IRC_MOVABS_RDI  = 0xBF;
const int8_t IRC_MOVABS_RSI  = 0xBE;

const int8_t IRC_LEA_REG_MEM =  0x8D;

const int8_t IRC_TWO_BYTE = 0x0F;


//_______________________________
//MODRM

//mod
const int8_t IRC_MODRM_MOD_00       = 0b00;
const int8_t IRC_MODRM_MOD_REG_CNST = 0b10;

const int8_t IRC_MODRM_MOD_REG_DIR  = 0b11;

//reg
const int8_t IRC_MODRM_REG_POP      = 0b000;
const int8_t IRC_MODRM_REG_MOV_CNST = 0b000;
const int8_t IRC_MODRM_REG_IDIV64   = 0b111;
const int8_t IRC_MODRM_REG_CALL_ABS = 0b010;


const int8_t IRC_MODRM_REG_ADD_REG_CNST = 0b000;
const int8_t IRC_MODRM_REG_SUB_REG_CNST = 0b101;


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

/*ADD/SUB/IMUL//
pop rsi
pop rdi
op rdi, rsi
push rdi*//////

/*IDIV////////
pop rsi
pop rdi
push rax
push rdx
mov rax, rdi
idiv rsi
mov rdi, rax
pop rdx
pop rax
push rdi*/////

/*COND JMP///
pop rsi
pop rdi
cmp rdi, rsi
op addr*////

/*OUT//////
movabs rdi, str
pop rsi
push rax
movabs rax, printf
call rax
pop rax*///

/*IN//////
movabs rdi, str
push rax
sub rsp, 8
lea rsi, [rsp]
movabs rax, scanf
call rax
mov rdi, [rsp]
add rsp, 8
pop rax
push rdi*///




#endif //CODING_H_INCLUDED