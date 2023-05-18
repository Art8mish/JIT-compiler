
#include "../include/jit.h"


static int InitIRitems(JitIR *ir);
static int TranslateBCodeArg(JitIR *ir, BCode *bcode);

static AddrTbl *AddrTblCtor(BCode *bcode);
static int      AddrTblDtor(AddrTbl *addr_tbl);
static int FillAdrTbl(AddrTbl *addr_tbl, BCode *bcode);

static int CalcRelAddr(JitIR *ir, AddrTbl *addr_tbl);



JitCntxt *JitCntxtCtor(const char *bcode_f_path)
{
    ERR_CHK(bcode_f_path == NULL, NULL);

    JitCntxt *jit = (JitCntxt *) calloc(1, sizeof(JitCntxt));
    ERR_CHK(jit == NULL, NULL);

    jit->ir       = NULL;
    jit->code_buf = NULL;
    jit->code_ip  = 0;

    return jit;
}

BCode *BCodeCtor(const char *bcode_f_path)
{
    ERR_CHK(bcode_f_path == NULL, NULL);

    BCode *bcode = (BCode *) calloc(1, sizeof(BCode));
    ERR_CHK(bcode == NULL, NULL);

    bcode->buf     = NULL;
    bcode->buf_len = 0;
    bcode->ip      = 0;

    _err = ReadBCodeF(bcode_f_path, bcode);
    ERR_CHK_SAFE(_err, free(bcode);, NULL);

    return bcode;
}

JitIR *JitIRCtor(BCode *bcode)
{
    ERR_CHK(bcode          == NULL, NULL);
    ERR_CHK(bcode->buf     == NULL, NULL);
    ERR_CHK(bcode->buf_len == 0,    NULL);

    JitIR *ir = (JitIR *) calloc(1, sizeof(JitIR));
    ERR_CHK(ir == NULL, NULL);

    ir->buf_len = bcode->buf_len;
    ir->buf     = (IRitm *) calloc(ir->buf_len, sizeof(IRitm));
    ERR_CHK(ir->buf == NULL, NULL);

    _err = InitIRitems(ir);
    ERR_CHK(_err, NULL);

       ir->ip = 0;
    bcode->ip = 0;

    _err = TranslateBCode(ir, bcode);
    ERR_CHK(_err, NULL);

    ir->buf_len = ir->ip;
    ir->buf     = (IRitm *) realloc(ir->buf, ir->buf_len * sizeof(IRitm));
    ERR_CHK(ir->buf == NULL, NULL);

    return ir;
}

static int InitIRitems(JitIR *ir)
{
    ERR_CHK(ir == NULL, ERR_NULL_PTR);

    for (unsigned i = 0; i < ir->buf_len; i++)
    {
        ir->buf[i].cmd = 0x00;
        ir->buf[i].mod = 0x00;

        ir->buf[i].reg  = 0x00;
        ir->buf[i].cnst = PSN_CNST;
    }

    return SUCCESS;
}

#define IS_ASMJUMP(cmd)                       \
           ((MASK16(cmd) ==  JMP_ASMCODE) ||  \
            (MASK16(cmd) ==   JB_ASMCODE) ||  \
            (MASK16(cmd) ==  JBE_ASMCODE) ||  \
            (MASK16(cmd) ==   JA_ASMCODE) ||  \
            (MASK16(cmd) ==  JAE_ASMCODE) ||  \
            (MASK16(cmd) ==   JE_ASMCODE) ||  \
            (MASK16(cmd) ==  JNE_ASMCODE) ||  \
            (MASK16(cmd) == CALL_ASMCODE))

int TranslateBCode(JitIR *ir, BCode *bcode)
{
    ERR_CHK(   ir          == NULL, ERR_NULL_PTR);
    ERR_CHK(   ir->buf     == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(   ir->buf_len == 0,    ERR_NULL_BUF_LEN);
    ERR_CHK(bcode          == NULL, ERR_NULL_PTR);
    ERR_CHK(bcode->buf     == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(bcode->buf_len == 0,    ERR_NULL_BUF_LEN);

    AddrTbl *addr_tbl = AddrTblCtor(bcode);
    ERR_CHK(addr_tbl == NULL, ERR_ADDRTBL_CTOR);

    _err = DumpAddrTbl(addr_tbl);
    ERR_CHK(_err, ERR_DUMP);

    uint32_t tbl_ip = 0;
    int32_t *code = bcode->buf; 
    while(bcode->ip < bcode->buf_len)
    {
        switch(MASK16(code[bcode->ip]))
        {   
            #define DEF_CMD(name, num, arg, cpu_code)                                                           \
                case name##_ASMCODE :   ir->buf[ir->ip].cmd = name##_CODE;                                      \
                                        if (addr_tbl->instr_ip[tbl_ip] == bcode->ip)                            \
                                        {                                                                       \
                                            addr_tbl->instr_ip[tbl_ip] = ir->ip;                                \
                                            tbl_ip++;                                                           \
                                        }                                                                       \
                                        for(uint32_t ti = 0; ti < addr_tbl->len; ti++)                          \
                                            if (addr_tbl->jmp_addr[ti] == bcode->ip)                            \
                                                addr_tbl->jmp_addr[ti] = ir->ip;                                \
                                        if (arg)                                                                \
                                            TranslateBCodeArg(ir, bcode);                                       \
                                        break;

            #include "../Processor/cmd.h"

            #undef DEF_CMD

            default : printf(" # TranslateBCode(): ERROR: code = %d. \n", code[bcode->ip] & (int32_t)0xFFFF);
                      return ERR_BCODE_SYNTAX;
                      break;
        }

        ir->ip++;
        bcode->ip++;

    }

    _err = DumpAddrTbl(addr_tbl);
    ERR_CHK(_err, ERR_DUMP);

    _err = CalcRelAddr(ir, addr_tbl);
    ERR_CHK(_err, ERR_CALC_RAL_ADDR);

    _err = AddrTblDtor(addr_tbl);
    ERR_CHK(_err, ERR_ADDRTBL_DTOR);

    return SUCCESS;
}

static AddrTbl *AddrTblCtor(BCode *bcode)
{
    ERR_CHK(bcode          == NULL, NULL);
    ERR_CHK(bcode->buf     == NULL, NULL);
    ERR_CHK(bcode->buf_len == 0,    NULL);

    AddrTbl *addr_tbl = (AddrTbl *) calloc(1, sizeof(AddrTbl));
    ERR_CHK(addr_tbl == NULL, NULL);

    addr_tbl->instr_ip = (uint32_t *) calloc(bcode->buf_len, sizeof(uint32_t));
    ERR_CHK(addr_tbl->instr_ip == NULL, NULL);
    addr_tbl->jmp_addr = (uint32_t *) calloc(bcode->buf_len, sizeof(uint32_t));
    ERR_CHK(addr_tbl->jmp_addr == NULL, NULL);
    addr_tbl->len = 0;

    _err = FillAdrTbl(addr_tbl, bcode);
    ERR_CHK(_err, NULL);

    addr_tbl->instr_ip = (uint32_t *) realloc(addr_tbl->instr_ip, addr_tbl->len * sizeof(uint32_t));
    ERR_CHK(addr_tbl->instr_ip == NULL, NULL);    
    addr_tbl->jmp_addr = (uint32_t *) realloc(addr_tbl->jmp_addr, addr_tbl->len * sizeof(uint32_t));
    ERR_CHK(addr_tbl->jmp_addr == NULL, NULL);

    return addr_tbl;
}

static int FillAdrTbl(AddrTbl *addr_tbl, BCode *bcode)
{
    ERR_CHK(addr_tbl           == NULL, ERR_NULL_PTR);
    ERR_CHK(addr_tbl->instr_ip == NULL, ERR_NULL_PTR);
    ERR_CHK(addr_tbl->jmp_addr == NULL, ERR_NULL_PTR);
    ERR_CHK(bcode             == NULL, ERR_NULL_PTR);
    ERR_CHK(bcode->buf        == NULL, ERR_NULL_PTR);
    ERR_CHK(bcode->buf_len    == 0,    ERR_NULL_PTR);

    int32_t *code = bcode->buf;
    uint32_t tbl_ip = 0;
    uint32_t bcode_ip = bcode->ip;
    while(bcode_ip < bcode->buf_len)
    {
        if (IS_ASMJUMP(code[bcode_ip]))
        {
            addr_tbl->instr_ip[tbl_ip] = bcode_ip;
            addr_tbl->jmp_addr[tbl_ip] = code[++bcode_ip];
            tbl_ip++;
        }

        bcode_ip++;
    }

    addr_tbl->len = tbl_ip;

    return SUCCESS;
}

static int CalcRelAddr(JitIR *ir, AddrTbl *addr_tbl)
{
    ERR_CHK(ir                 == NULL, ERR_NULL_PTR);
    ERR_CHK(ir->buf            == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(ir->buf_len        == 0,    ERR_NULL_BUF_LEN);
    ERR_CHK(addr_tbl           == NULL, ERR_NULL_PTR);
    ERR_CHK(addr_tbl->instr_ip == NULL, ERR_NULL_PTR);
    ERR_CHK(addr_tbl->jmp_addr == NULL, ERR_NULL_PTR);


    return SUCCESS;
}

static int AddrTblDtor(AddrTbl *addr_tbl)
{
    ERR_CHK(addr_tbl           == NULL, ERR_NULL_PTR);
    ERR_CHK(addr_tbl->instr_ip == NULL, ERR_NULL_PTR);
    ERR_CHK(addr_tbl->jmp_addr == NULL, ERR_NULL_PTR);

    if (addr_tbl->instr_ip != NULL)
        free(addr_tbl->instr_ip);

    if (addr_tbl->jmp_addr != NULL)
        free(addr_tbl->jmp_addr);

    free(addr_tbl);

    return SUCCESS;
}


static int TranslateBCodeArg(JitIR *ir, BCode *bcode)
{
    ERR_CHK(ir    == NULL, ERR_NULL_PTR);
    ERR_CHK(bcode == NULL, ERR_NULL_PTR);

    int32_t cmd = bcode->buf[bcode->ip];

    if (cmd & MEMORY_CODE)
        ir->buf[ir->ip].mod |= MEM_CODE;

    if (cmd & IMMEDIATE_CONST_CODE)
    {
        ir->buf[ir->ip].mod |= CNST_CODE;
        ir->buf[ir->ip].cnst = bcode->buf[++bcode->ip];
    }
    
    if (cmd & REGISTER_CODE)
    {
        ir->buf[ir->ip].mod |= REG_CODE;

        bcode->ip++;
        switch (bcode->buf[bcode->ip])
        {
            case REG_RAX :  ir->buf[ir->ip].reg = RAX_CODE;
                            break;
            case REG_RBX :  ir->buf[ir->ip].reg = RBX_CODE;
                            break;
            case REG_RCX :  ir->buf[ir->ip].reg = RCX_CODE;
                            break;
            case REG_RDX :  ir->buf[ir->ip].reg = RDX_CODE;
                            break;
            default: return ERR_WRONG_REG;
                     break;
        }
    }

    return SUCCESS;
}


int BCodeDtor(BCode *bcode)
{
    ERR_CHK(bcode      == NULL, ERR_NULL_PTR);
    ERR_CHK(bcode->buf == NULL, ERR_NULL_PTR);

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


int JitCntxtDtor(JitCntxt *jit)
{
    ERR_CHK(jit           == NULL, ERR_NULL_PTR);
    ERR_CHK(jit->ir       == NULL, ERR_NULL_PTR);
    //ERR_CHK(jit->code_buf == NULL, ERR_NULL_PTR);

    if (jit->ir != NULL)
    {
        _err = JitIRDtor(jit->ir);
        ERR_CHK(_err, ERR_JITIR_DTOR);
    }
    
    if (jit->code_buf != NULL)
        free(jit->code_buf);
    free(jit);

    return SUCCESS;
}