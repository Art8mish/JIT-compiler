
#include "../include/jit.h"

static int InitIRitems(JitIR *ir);

BCode *BCodeCtor()
{
    BCode *bcode = (BCode *) calloc(1, sizeof(BCode));
    ERR_CHK(bcode == NULL, NULL);

    bcode->buf     = NULL;
    bcode->buf_len = 0;
    bcode->ip      = 0;

    return bcode;
}

JitIR *JitIRCtor(uint32_t buf_len)
{
    ERR_CHK(buf_len > MAX_JITIR_BUF_LEN, NULL);

    JitIR *ir = (JitIR *) calloc(1, sizeof(JitIR));
    ERR_CHK(ir == NULL, NULL);

    ir->buf_len = buf_len * MAX_BCODE_CMD_LEN;
    ir->buf     = (IRitm *) calloc(ir->buf_len, sizeof(IRitm));
    ERR_CHK(ir->buf == NULL, NULL);

    _err = InitIRitems(ir);
    ERR_CHK(_err, NULL);

    ir->ip = 0;

    return ir;
}

static int InitIRitems(JitIR *ir)
{
    ERR_CHK(ir == NULL, ERR_NULL_PTR);

    for (unsigned i = 0; i < ir->buf_len; i++)
    {
        ir->buf[i].prfx      = 0x00;
        ir->buf[i].cmd.b1    = 0x00;
        ir->buf[i].cmd.b2    = 0x00;

        ir->buf[i].ModRM.rm  = 0b000;
        ir->buf[i].ModRM.reg = 0b000;
        ir->buf[i].ModRM.mod = 0b00;

        ir->buf[i].SIB.base  = 0b000;
        ir->buf[i].SIB.index = 0b000;
        ir->buf[i].SIB.scale = 0b00;

        ir->buf[i].cnst = PSN_CNST;
        ir->buf[i].instr_len = 0;
    }

    return SUCCESS;
}


ExCode *ExCodeCtor(uint32_t instr_buf_len)
{
    ERR_CHK(instr_buf_len > MAX_EXCODE_BUF_LEN, NULL);

    ExCode *ex_code = (ExCode *) calloc(1, sizeof(ExCode));
    ERR_CHK(ex_code == NULL, NULL);

    ex_code->buf_len = instr_buf_len * MAX_IR_INSTR_LEN;
    ex_code->buf = (int8_t *) mmap(NULL, ex_code->buf_len,
                                   PROT_READ  | PROT_WRITE | PROT_EXEC, 
                                   MAP_SHARED | MAP_ANONYMOUS, 0, 0);
    ERR_CHK(ex_code->buf == MAP_FAILED , NULL);

    memset(ex_code->buf, IRC_RET, ex_code->buf_len);
    _err = mprotect(ex_code->buf, ex_code->buf_len, PROT_READ | PROT_WRITE | PROT_EXEC);
    ERR_CHK(_err, NULL);

    ex_code->ip = 0;

    return ex_code;
}


int BCodeDtor(BCode *bcode)
{
    ERR_CHK(bcode      == NULL, ERR_NULL_PTR);
    ERR_CHK(bcode->buf == NULL, ERR_NULL_PTR);

    if (bcode->buf != NULL)
        free(bcode->buf);
    free(bcode);

    return SUCCESS;
}

int JitIRDtor(JitIR *ir)
{
    ERR_CHK(ir      == NULL, ERR_NULL_PTR);
    ERR_CHK(ir->buf == NULL, ERR_NULL_PTR);

    if (ir->buf != NULL)
        free(ir->buf);
    free(ir);

    return SUCCESS;
}

int ExCodeDtor(ExCode *ex_code)
{
    ERR_CHK(ex_code      == NULL, ERR_NULL_PTR);
    ERR_CHK(ex_code->buf == NULL, ERR_NULL_PTR);

    if (ex_code->buf != NULL)
    {
        _err = munmap(ex_code->buf, ex_code->buf_len);
        ERR_CHK(_err, ERR_MUNMAP);
    }

    free(ex_code);

    return SUCCESS;
}

