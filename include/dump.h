#ifndef DUMP_H_INCLUDED
#define DUMP_H_INCLUDED

#include "jit.h"

enum CmdConst
{
    IMMEDIATE_CONST_CODE = 1 << 16,
           REGISTER_CODE = 1 << 17,
             MEMORY_CODE = 1 << 18,
};

enum Register
{
    REG_RAX = 1,
    REG_RBX = 2,
    REG_RCX = 3,
    REG_RDX = 4,
};

int DisAsmBCode(BCode *bcode);
int DisAsmIR(JitIR *ir);
int DumpAddrTbl(AddrTbl *addr_tbl);

#endif //DUMP_H_INCLUDED