
#include "../include/jit.h"


static int TranslateBCodeArg(JitIR *ir, BCode *bcode);

static AddrTbl *AddrTblCtor(BCode *bcode);
static int      AddrTblDtor(AddrTbl *addr_tbl);
static int FillAddrTbl(AddrTbl *addr_tbl, BCode *bcode);


static int AssembleIRArg(ExCode *ex_code, JitIR *ir);

#define IS_ASMJUMP(cmd)                       \
           ((MSK16(cmd) ==  JMP_ASMCODE) ||  \
            (MSK16(cmd) ==   JB_ASMCODE) ||  \
            (MSK16(cmd) ==  JBE_ASMCODE) ||  \
            (MSK16(cmd) ==   JA_ASMCODE) ||  \
            (MSK16(cmd) ==  JAE_ASMCODE) ||  \
            (MSK16(cmd) ==   JE_ASMCODE) ||  \
            (MSK16(cmd) ==  JNE_ASMCODE) ||  \
            (MSK16(cmd) == CALL_ASMCODE))


static AddrTbl *AddrTblCtor(BCode *bcode)
{
    ERR_CHK(bcode          == NULL, NULL);
    ERR_CHK(bcode->buf     == NULL, NULL);
    ERR_CHK(bcode->buf_len == 0,    NULL);

    AddrTbl *addr_tbl = (AddrTbl *) calloc(1, sizeof(AddrTbl));
    ERR_CHK(addr_tbl == NULL, NULL);

    //calloc bufs 
    addr_tbl->instr_ip = (uint32_t *) calloc(bcode->buf_len, sizeof(uint32_t));
    ERR_CHK(addr_tbl->instr_ip == NULL, NULL);

    addr_tbl->jmp_addr = (uint32_t *) calloc(bcode->buf_len, sizeof(uint32_t));
    ERR_CHK(addr_tbl->jmp_addr == NULL, NULL);

    //fill tbl
    addr_tbl->len = 0;
    _err = FillAddrTbl(addr_tbl, bcode);
    ERR_CHK(_err, NULL);

    //realloc bufs 
    printf("addr_tbl_len[0] = %u\n", addr_tbl->len);
    addr_tbl->instr_ip = (uint32_t *) realloc(addr_tbl->instr_ip, addr_tbl->len * sizeof(uint32_t));
    ERR_CHK(addr_tbl->instr_ip == NULL, NULL); 

    addr_tbl->jmp_addr = (uint32_t *) realloc(addr_tbl->jmp_addr, addr_tbl->len * sizeof(uint32_t));
    ERR_CHK(addr_tbl->jmp_addr == NULL, NULL);

    return addr_tbl;
}

static int FillAddrTbl(AddrTbl *addr_tbl, BCode *bcode)
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
    printf("tbl_ip = %u\n", tbl_ip);
    addr_tbl->len = tbl_ip;

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


int TranslateBCode(JitIR *ir, BCode *bcode)
{
    ERR_CHK(   ir          == NULL, ERR_NULL_PTR);
    ERR_CHK(   ir->buf     == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(   ir->buf_len == 0,    ERR_NULL_BUF_LEN);
    ERR_CHK(bcode          == NULL, ERR_NULL_PTR);
    ERR_CHK(bcode->buf     == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(bcode->buf_len == 0,    ERR_NULL_BUF_LEN);
    ERR_CHK(ir->buf_len != bcode->buf_len, ERR_WRONG_BUF_LEN);    

    
    AddrTbl *addr_tbl = AddrTblCtor(bcode);
    ERR_CHK(addr_tbl == NULL, ERR_ADDRTBL_CTOR);

    _err = DumpAddrTbl(addr_tbl);
    ERR_CHK(_err, ERR_DUMP);

    uint32_t tbl_ip = 0;
    int32_t *code = bcode->buf;

    bcode->ip = 0;
    ir->ip    = 0;
    while(bcode->ip < bcode->buf_len)
    {
        IRitm ir_itm = ir->buf[ir->ip];
        switch(MSK16(code[bcode->ip]))
        {   
            #define DEF_CMD(name, num, arg, cpu_code)                                                           \
                case ASMCODE_##name :   _err = _processIR_##name(ir, bcode);                                    \
                                        ERR_CHK(_err, ERR_PROC_IR_PUSH);                                        \
                                        if (addr_tbl->instr_ip[tbl_ip] == bcode->ip)                            \
                                        {                                                                       \
                                            addr_tbl->instr_ip[tbl_ip] = ir->ip;                                \
                                            ir->buf[ir->ip].mod |= MOD_JUMP_CODE;\
                                            tbl_ip++;                                                           \
                                        }                                                                       \
                                        for(uint32_t ti = 0; ti < addr_tbl->len; ti++)                          \
                                            if (addr_tbl->jmp_addr[ti] == bcode->ip)                            \
                                                addr_tbl->jmp_addr[ti] = ir->ip;                                \
                                        if (arg)                                                                \
                                        {                                                                       \
                                            _err = TranslateBCodeArg(ir, bcode);                                \
                                            ERR_CHK(_err, ERR_TRANSLT_BCODE_ARG);                               \
                                        }                                                                       \
                                        break;

            #include "../proc/cmd.h"

            #undef DEF_CMD

            default : printf(" # TranslateBCode(): ERROR: code = %d. \n", code[bcode->ip] & (int32_t)0xFFFF);
                      _err = AddrTblDtor(addr_tbl);
                      ERR_CHK(_err, ERR_ADDRTBL_DTOR);
                      return ERR_BCODE_SYNTAX;
                      break;
        }

        ir->ip++;
        bcode->ip++;

    }

    _err = DumpAddrTbl(addr_tbl);
    ERR_CHK_SAFE(_err, AddrTblDtor(addr_tbl);, ERR_DUMP);

    //calc relative addresses
    for (uint32_t i = 0; i < addr_tbl->len; i++)
        ir->buf[addr_tbl->instr_ip[i]].cnst = addr_tbl->jmp_addr[i] - addr_tbl->instr_ip[i] - 1;

    _err = AddrTblDtor(addr_tbl);
    ERR_CHK(_err, ERR_ADDRTBL_DTOR);

    //realloc ir->buf to ir->ip len
    ir->buf_len = ir->ip;
    ir->buf     = (IRitm *) realloc(ir->buf, ir->buf_len * sizeof(IRitm));
    ERR_CHK(ir->buf == NULL, ERR_REALLOC);

    return SUCCESS;
}

static int _processIR_PUSH(IRitm *ir_itm, BCode *bcode)
{
    ERR_CHK(ir_itm == NULL, ERR_NULL_PTR);
    ERR_CHK(bcode  == NULL, ERR_NULL_PTR);

    int32_t *code = bcode->buf; 
    int32_t  bcmd  = code[bcode->ip];

    switch (MSK_BCODE_MOD(bcmd))
    {
        case BCODE_REG:
                switch (code[++bcode->ip])
                {
                    case BCODE_REG_RAX: ir_itm->cmd = IRC_PUSH_RAX;
                                        break;
                    case BCODE_REG_RCX: ir_itm->cmd = IRC_PUSH_RCX;
                                        break;
                    case BCODE_REG_RDX: ir_itm->cmd = IRC_PUSH_RBX;
                                        break;
                    case BCODE_REG_RBX: ir_itm->cmd = IRC_PUSH_RDX;
                                        break;
                }
                break;  

        case BCODE_CNST:  
                ir_itm->cmd       = IRC_PUSH_MEM;

                ir_itm->ModRM.mod = IRC_MODRM_MOD_CNST;
                ir_itm->ModRM.reg = IRC_RSI;
                ir_itm->ModRM.rm  = IRC_MODRM_RM_SIB;

                ir_itm->SIB.scale = IRC_SIB_SCLF1;
                ir_itm->SIB.index = IRC_SIB_INDX_NONE;
                ir_itm->SIB.base  = IRC_SIB_BASE_NONE;

                ir_itm->cnst = code[++bcode->ip];
                break;

        case BCODE_MEM_REG:
                ir_itm->cmd       = IRC_PUSH_MEM;

                ir_itm->ModRM.mod = IRC_MODRM_MOD_REG;
                ir_itm->ModRM.reg = IRC_RSI;
                
                switch (code[++bcode->ip])
                {
                    case BCODE_REG_RAX: ir_itm->ModRM.rm = IRC_RAX;
                                        break;
                    case BCODE_REG_RCX: ir_itm->ModRM.rm = IRC_RCX;
                                        break;
                    case BCODE_REG_RDX: ir_itm->ModRM.rm = IRC_RDX;
                                        break;
                    case BCODE_REG_RBX: ir_itm->ModRM.rm = IRC_RBX;
                                        break;
                }
                break;
        
        case BCODE_MEM_CNST:
                code->buf[code->ip++] = 0xff;
                code->buf[code->ip++] = 0x34; //ModRM
                code->buf[code->ip++] = 0x25; //SIB
                break;

        case BCODE_MEM_REG_CNST:
                code->buf[code->ip++] = 0xff;
                code->buf[code->ip++] = 0xb0 + iritm->reg;   
        default:     
                printf(" # AsmPUSH(): ERROR: code = %x. \n", MSK3(iritm->mod));
                return ERR_IR_SYNTAX;
                break;             
    }
    
    if (CNST_MSK(iritm->mod))
    {
        memmove(&code->buf[code->ip], &iritm->cnst, sizeof(int32_t));
        code->ip += sizeof(int32_t); 
    }

}


static int TranslateBCodeArg(JitIR *ir, BCode *bcode)
{
    ERR_CHK(ir    == NULL, ERR_NULL_PTR);
    ERR_CHK(bcode == NULL, ERR_NULL_PTR);

    int32_t cmd = bcode->buf[bcode->ip];

    if (cmd & MEMORY_CODE)
        ir->buf[ir->ip].mod |= MOD_MEM_CODE;

    if (cmd & IMMEDIATE_CONST_CODE)
    {
        ir->buf[ir->ip].mod |= MOD_CNST_CODE;
        ir->buf[ir->ip].cnst = bcode->buf[++bcode->ip];
    }
    
    if (cmd & REGISTER_CODE)
    {
        ir->buf[ir->ip].mod |= MOD_REG_CODE;

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








int AssembleIR(ExCode *ex_code, JitIR *ir)
{
    ERR_CHK(ex_code          == NULL, ERR_NULL_PTR);
    ERR_CHK(ex_code->buf     == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(ex_code->buf_len == 0,    ERR_NULL_BUF_LEN);
    ERR_CHK(ir               == NULL, ERR_NULL_PTR);
    ERR_CHK(ir->buf          == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(ir->buf_len      == 0,    ERR_NULL_BUF_LEN);
    ERR_CHK(ex_code->buf_len != ir->buf_len * SYS_WORD_LEN, ERR_WRONG_BUF_LEN);

    ExCode *code = ex_code;

    ex_code->ip = 0;
    ir->ip = 0;
    while(ir->ip < ir->buf_len)
    {
        int32_t code_old_ip = code->ip;
        switch(ir->buf[ir->ip].cmd)
        {
            #define JIT_CMD(name, num, arg, jit_code)                                   \
                        case name##_CODE :       
                                                
                                                break;

            #include "../include/ir_cmd.h"

            #undef JIT_CMD

            default : printf(" # AssembleIR(): ERROR: code = %x. \n", ir->buf[ir->ip].cmd);
                      return ERR_IR_SYNTAX;
                      break;
        }

        ir->buf[ir->ip].instr_len = code->ip - code_old_ip;
        ir->ip++;
    }



    ex_code->buf_len = ex_code->ip;
    ex_code->buf     = (int8_t *) realloc(ex_code->buf, ex_code->buf_len * sizeof(int8_t));
    ERR_CHK(ex_code->buf == NULL, ERR_REALLOC);

    //asm ("call %0": "r" (ex_code->buf));

    return SUCCESS;
}

static int AssembleIRArg(ExCode *ex_code, JitIR *ir)
{
    ERR_CHK(ex_code          == NULL, ERR_NULL_PTR);
    ERR_CHK(ex_code->buf     == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(ex_code->buf_len == 0,    ERR_NULL_BUF_LEN);
    ERR_CHK(     ir          == NULL, ERR_NULL_PTR);
    ERR_CHK(     ir->buf     == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(     ir->buf_len == 0,    ERR_NULL_BUF_LEN);

    


    return SUCCESS;
}


static int AsmPUSH(ExCode *code, IRitm *iritm)
{
    ERR_CHK(code          == NULL, ERR_NULL_PTR);
    ERR_CHK(code->buf     == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(code->buf_len == 0,    ERR_NULL_BUF_LEN);
    ERR_CHK(iritm         == NULL, ERR_NULL_PTR);

    switch (MSK3(iritm->mod))
    {
        case MOD_REG:   
                code->buf[code->ip++] = 0x50 + iritm->reg;
                break;  

        case MOD_CNST:  
                code->buf[code->ip++] = 0x68;
                break;

        case MOD_MEM_REG:
                code->buf[code->ip++] = 0xff;
                code->buf[code->ip++] = 0x30 + iritm->reg;
                break;
        
        case MOD_MEM_CNST:
                code->buf[code->ip++] = 0xff;
                code->buf[code->ip++] = 0x34; //ModRM
                code->buf[code->ip++] = 0x25; //SIB
                break;

        case MOD_MEM_REG_CNST:
                code->buf[code->ip++] = 0xff;
                code->buf[code->ip++] = 0xb0 + iritm->reg;   
        default:     
                printf(" # AsmPUSH(): ERROR: code = %x. \n", MSK3(iritm->mod));
                return ERR_IR_SYNTAX;
                break;             
    }
    
    if (CNST_MSK(iritm->mod))
    {
        memmove(&code->buf[code->ip], &iritm->cnst, sizeof(int32_t));
        code->ip += sizeof(int32_t); 
    }

    return SUCCESS;
}


static int AsmPOP(ExCode *code, IRitm *iritm)
{
    ERR_CHK(code          == NULL, ERR_NULL_PTR);
    ERR_CHK(code->buf     == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(code->buf_len == 0,    ERR_NULL_BUF_LEN);
    ERR_CHK(iritm         == NULL, ERR_NULL_PTR);

    switch (MSK3(iritm->mod))
    {
        case MOD_REG:   
                code->buf[code->ip++] = 0x58 + iritm->reg;
                break;  

        case MOD_MEM_REG:
                code->buf[code->ip++] = 0x8f;
                code->buf[code->ip++] = 0x00 + iritm->reg;
                break;
        
        case MOD_MEM_CNST:
                code->buf[code->ip++] = 0x8f;
                code->buf[code->ip++] = 0x04; //ModRM
                code->buf[code->ip++] = 0x25; //SIB
                break;

        case MOD_MEM_REG_CNST:
                code->buf[code->ip++] = 0x8f;
                code->buf[code->ip++] = 0x80 + iritm->reg;   
        default:     
                printf(" # AsmPUSH(): ERROR: code = %x. \n", MSK3(iritm->mod));
                return ERR_IR_SYNTAX;
                break;             
    }
    
    if (CNST_MSK(iritm->mod))
    {
        memmove(&code->buf[code->ip], &iritm->cnst, sizeof(int32_t));
        code->ip += sizeof(int32_t); 
    }

    return SUCCESS;
}
