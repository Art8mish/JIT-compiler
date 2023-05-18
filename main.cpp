
#include "include/jit.h"

static const char *bcode_f_path = "Processor/io/asm_output";

int main(void)
{
    JitCntxt *jit = JitCntxtCtor(bcode_f_path);
    ERR_CHK(_err, 1);

    BCode *bcode = BCodeCtor(bcode_f_path);
    ERR_CHK_SAFE(bcode == NULL, free(jit);, 1);

    _err = DisAsmBCode(bcode);
    ERR_CHK_SAFE(_err, BCodeDtor(bcode);
                       free(jit);, 2);

    jit->ir = JitIRCtor(bcode);
    ERR_CHK_SAFE(jit->ir == NULL, BCodeDtor(bcode);
                                  free(jit);, 3);

    printf("BCodeLen = %u\n", bcode->buf_len);
    _err = BCodeDtor(bcode);
    ERR_CHK_SAFE(_err, JitCntxtDtor(jit);, 4);

    _err = DisAsmIR(jit->ir);
    ERR_CHK_SAFE(_err, JitCntxtDtor(jit);, 5);
    

    printf("IRLen = %ld\n", jit->ir->buf_len);

    _err = JitCntxtDtor(jit);
    ERR_CHK(_err, 6);

    return 0;
}