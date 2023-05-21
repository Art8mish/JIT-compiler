#ifndef JIT_H_INCLUDED
#define JIT_H_INCLUDED

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "assert.h"
#include "coding.h"


const size_t SUPPORTED_ASM_VERS = 1;
const size_t BCODE_HDR_SIZE     = 3;

const char *const BCODE_SGNTR = "DP";
const size_t    SIZE_OF_SGNTR = 2;

const int32_t PSN_CNST = 0xA1EB;
const int32_t PSN_REG  = 0xFF;

const uint8_t SYS_WORD_LEN = 8;
const uint8_t MAX_BCODE_CMD_LEN = 10; //can be coded with max 10 IR cmds 

const uint32_t MAX_BCODE_BUF_LEN  = 5000;
const uint32_t MAX_JITIR_BUF_LEN  = 5000;
const uint32_t MAX_EXCODE_BUF_LEN = 5000;
const uint32_t MAX_ADRTBL_LEN     = 5000;

typedef struct ByteCode
{
    int32_t *buf     = NULL;
    uint32_t buf_len = 0;
    uint32_t ip      = 0;
} BCode;


struct ModRMb
{
    int8_t rm  : 3;
    int8_t reg : 3;
    int8_t mod : 2;
};

struct SIBb
{
    int8_t base  : 3;
    int8_t index : 3;
    int8_t scale : 2;
};

struct Opcode
{
    int8_t b1 : 8;
    int8_t b2 : 8;
};

typedef struct IRitem
{
    int8_t prfx = 0x00;

    Opcode cmd;

    ModRMb ModRM;
    SIBb   SIB;

    int8_t  reg  = PSN_REG;
    int64_t cnst = PSN_CNST;

    uint8_t instr_len = 0;
} IRitm;

struct JitIR
{
    IRitm   *buf     = NULL;
    uint32_t buf_len = 0;
    uint32_t ip      = 0;
};

typedef struct ExecutableCode
{
    int8_t *buf      = NULL;
    uint32_t buf_len = 0;
    uint32_t ip      = 0;
    
} ExCode;

typedef struct JitContext
{
    JitIR *ir    = NULL;

} JitCntxt;

typedef struct AddressTable
{   
    uint32_t *instr_ip = 0;
    uint32_t *jmp_addr = 0;
    
    uint32_t len       = 0;
}AddrTbl;

#include "dump.h"

BCode *BCodeCtor();
int ReadBCodeF(BCode *bcode, const char *bcode_f_path);
int BCodeDtor(BCode *bcode);

JitIR *JitIRCtor(uint32_t buf_len);
int TranslateBCode(JitIR *ir, BCode *bcode);
int JitIRDtor(JitIR *ir);


ExCode *ExCodeCtor(uint32_t instr_buf_len);
int AssembleIR(ExCode *ex_code, JitIR *ir);
int ExCodeDtor(ExCode *ex_code);



#endif //JIT_H_INCLUDED