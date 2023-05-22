#ifndef DUMP_H_INCLUDED
#define DUMP_H_INCLUDED

#include "jit.h"

int DisAsmBCode(BCode *bcode);
int DumpIR(JitIR *ir);
int DumpAddrTbl(AddrTbl *addr_tbl);
int DumpExCode(ExCode *ex_code);

#endif //DUMP_H_INCLUDED