#ifndef CODING_H_INCLUDED
#define CODING_H_INCLUDED

#include <stdint.h>


//ASM_CODING/////////////////////
////////////////////////////////

#define DEF_CMD(name, num, arg, code) \
                name##_ASMCODE = num,
enum AsmCode
{
    #include "../proc/cmd.h"
};

#undef DEF_CMD


//JIT_CODING/////////////////////
////////////////////////////////
//______________________________
const uint8_t  HLT_CODE = 0x00;
const uint8_t PUSH_CODE = 0x06;
const uint8_t  POP_CODE = 0x07;

const uint8_t JMP_CODE = 0xEA;
const uint8_t  JB_CODE = 0x72;
const uint8_t JBE_CODE = 0x76;
const uint8_t  JA_CODE = 0x77;
const uint8_t JAE_CODE = 0x73;
const uint8_t  JE_CODE = 0x74;
const uint8_t JNE_CODE = 0x75;

const uint8_t CALL_CODE = 0xE8;
const uint8_t  RET_CODE = 0xCB;

const uint8_t ADD_CODE = 0x01;
const uint8_t SUB_CODE = 0x02;
const uint8_t MUL_CODE = 0x69;
const uint8_t DIV_CODE = 0x70;

const uint8_t OUT_CODE = 0x08;
const uint8_t  IN_CODE = 0x09;

const uint8_t DUMP_CODE = 0xA0;


//_______________________________
const uint8_t RAX_CODE = 0x01;
const uint8_t RBX_CODE = 0x02;
const uint8_t RCX_CODE = 0x03;
const uint8_t RDX_CODE = 0x04;


//_______________________________
const uint8_t  MEM_CODE = 1 << 0;
const uint8_t  REG_CODE = 1 << 1;
const uint8_t CNST_CODE = 1 << 2;





#endif //CODING_H_INCLUDED