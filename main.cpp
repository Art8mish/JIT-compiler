
#include "include/jit.h"

static const char *bcode_f_path = "proc/io/asm_output";

int main(int argc, char *argv[])
{
    const char *inpt_f = NULL;
    _err = ProcMainArgs(argc, argv, &inpt_f);
    ERR_CHK(_err, ERR_PROC_MAIN_ARGS);

    BCode *bcode = BCodeCtor();
    ERR_CHK(bcode == NULL, ERR_BCODE_CTOR);
    
    _err = ReadBCodeF(bcode, inpt_f);
    ERR_CHK_SAFE(_err, BCodeDtor(bcode);, ERR_READ_BCODE);

    _err = DisAsmBCode(bcode);
    ERR_CHK_SAFE(_err, BCodeDtor(bcode);, ERR_DISASM_BCODE);

    JitIR *ir = JitIRCtor(bcode->buf_len);
    ERR_CHK_SAFE(ir == NULL, BCodeDtor(bcode);, ERR_JITIR_CTOR);

    _err = TranslateBCode2IR(ir, bcode);
    ERR_CHK_SAFE(ir == NULL, BCodeDtor(bcode);
                             JitIRDtor(ir);, ERR_TRNSLT_BCODE2IR);

    _err = BCodeDtor(bcode);
    ERR_CHK_SAFE(_err, JitIRDtor(ir);, ERR_BCODE_DTOR);

    _err = DumpIR(ir);
    ERR_CHK_SAFE(_err, JitIRDtor(ir);, ERR_DUMP_IR);


    ExCode *ex_code = ExCodeCtor(ir->buf_len);
    ERR_CHK_SAFE(ex_code == NULL, JitIRDtor(ir);, ERR_EXCODE_CTOR);

    _err = AssembleIR(ex_code, ir);
    ERR_CHK_SAFE(_err, JitIRDtor(ir);, ERR_ASSEMBLE_IR);

    _err = JitIRDtor(ir);
    ERR_CHK_SAFE(_err, ExCodeDtor(ex_code);, ERR_JITIR_DTOR);

    _err = DumpExCode(ex_code);
    ERR_CHK_SAFE(_err, ExCodeDtor(ex_code);, ERR_DUMP_EXCODE);

    clock_t start_time = clock();

    _err = CallExCode(ex_code);
    ERR_CHK_SAFE(_err, ExCodeDtor(ex_code);, ERR_CALL_EXCODE);
    
    clock_t end_time = clock();
    double elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    printf("Elapsed time: %lf s\n", elapsed_time);

    _err = ExCodeDtor(ex_code);
    ERR_CHK(_err, ERR_EXCODE_DTOR);

    return 0;
}