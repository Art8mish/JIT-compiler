#ifndef DUMP_H_INCLUDED
#define DUMP_H_INCLUDED

#include "jit.h"

int DisAsmBCode(BCode *bcode);
int DisAsmIR(JitIR *ir);
int DumpAddrTbl(AddrTbl *addr_tbl);

#endif //DUMP_H_INCLUDED