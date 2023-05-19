
#include "include/jit.h"

static const char *bcode_f_path = "proc/io/asm_output";

int main(void)
{
    int32_t num = 0x12345678;
    int8_t *ptr = (int8_t *)&num;

    printf("%x\n%x %x %x %x", num, ptr[0], ptr[1], ptr[2], ptr[3]);

    BCode *bcode = BCodeCtor();
    ERR_CHK(bcode == NULL, 1);
    
    _err = ReadBCodeF(bcode, bcode_f_path);
    ERR_CHK_SAFE(_err, BCodeDtor(bcode);, 2);
    printf("BCodeLen = %u\n", bcode->buf_len);

    _err = DisAsmBCode(bcode);
    ERR_CHK_SAFE(_err, BCodeDtor(bcode);, 3);

    JitIR *ir = JitIRCtor(bcode->buf_len);
    ERR_CHK_SAFE(ir == NULL, BCodeDtor(bcode);, 4);

    _err = TranslateBCode(ir, bcode);
    ERR_CHK_SAFE(ir == NULL, BCodeDtor(bcode);
                             JitIRDtor(ir);, 5);

    _err = BCodeDtor(bcode);
    ERR_CHK_SAFE(_err, JitIRDtor(ir);, 6);

    _err = DisAsmIR(ir);
    ERR_CHK_SAFE(_err, JitIRDtor(ir);, 7);
    
    printf("IRLen = %u\n", ir->buf_len);

    _err = JitIRDtor(ir);
    ERR_CHK(_err, 8);

    return 0;
}