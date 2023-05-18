#ifndef JIT_H_INCLUDED
#define JIT_H_INCLUDED

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "assert.h"
#include "coding.h"

#define MASK16(cmd) (cmd & 0xFFFF)

const size_t SUPPORTED_ASM_VERS = 1;
const size_t BCODE_HDR_SIZE     = 3;

const char *const BCODE_SGNTR = "DP";
const size_t    SIZE_OF_SGNTR = 2;

const int32_t PSN_CNST = 0xEDA;

typedef struct ByteCode
{
    int32_t *buf     = NULL;
    uint32_t buf_len = 0;
    uint32_t ip      = 0;
} BCode;


typedef struct IRitem
{
    uint8_t cmd  = 0x00;
    uint8_t mod  = 0x00;

    uint8_t reg  = 0x00;
    int32_t cnst = PSN_CNST;

    uint8_t instr_len = 0;
} IRitm;

struct JitIR
{
    IRitm   *buf     = NULL;
    uint32_t buf_len = 0;
    uint32_t ip      = 0;
};

typedef struct JitContext
{
    JitIR *ir    = NULL;

    int8_t *code_buf = NULL;
    uint64_t code_ip = 0;

} JitCntxt;

typedef struct AddressTable
{   
    uint32_t *instr_ip = 0;
    uint32_t *jmp_addr = 0;
    
    uint32_t len       = 0;
}AddrTbl;
const uint32_t MAX_ADRTBL_LEN = 5000;

#include "dump.h"

JitCntxt *JitCntxtCtor(const char *bcode_f_path);
int JitCntxtDtor(JitCntxt *jit);

BCode *BCodeCtor(const char *bcode_f_path);
int ReadBCodeF(const char *bcode_f_path, BCode *bcode);
int BCodeDtor(BCode *bcode);

JitIR *JitIRCtor(BCode *bcode);
int TranslateBCode(JitIR *ir, BCode *bcode);
int JitIRDtor(JitIR *ir);




#endif //JIT_H_INCLUDED