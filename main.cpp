
#include "include/jit.h"

static const char *bcode_f_path = "proc/io/asm_output";

int main(void)
{
    BCode *bcode = BCodeCtor();
    ERR_CHK(bcode == NULL, 1);
    
    _err = ReadBCodeF(bcode, bcode_f_path);
    ERR_CHK_SAFE(_err, BCodeDtor(bcode);, 2);
    printf("BCodeLen = %u\n", bcode->buf_len);

    _err = DisAsmBCode(bcode);
    ERR_CHK_SAFE(_err, BCodeDtor(bcode);, 3);

    JitIR *ir = JitIRCtor(bcode->buf_len);
    ERR_CHK_SAFE(ir == NULL, BCodeDtor(bcode);, 4);

    _err = TranslateBCode2IR(ir, bcode);
    ERR_CHK_SAFE(ir == NULL, BCodeDtor(bcode);
                             JitIRDtor(ir);, 5);

    _err = BCodeDtor(bcode);
    ERR_CHK_SAFE(_err, JitIRDtor(ir);, 6);

    _err = DumpIR(ir);
    ERR_CHK_SAFE(_err, JitIRDtor(ir);, 7);
    
    printf("IRLen = %u\n", ir->buf_len);

    ExCode *ex_code = ExCodeCtor(ir->buf_len);
    ERR_CHK_SAFE(ex_code == NULL, JitIRDtor(ir);, 8);

    _err = AssembleIR(ex_code, ir);
    ERR_CHK_SAFE(_err, JitIRDtor(ir);, 9);

    _err = JitIRDtor(ir);
    ERR_CHK(_err, 10);

    _err = DumpExCode(ex_code);
    ERR_CHK(_err, 11);

    _err = CallExCode(ex_code);
    ERR_CHK(_err, 10);

    _err = ExCodeDtor(ex_code);
    ERR_CHK(_err, 9);

    return 0;
}