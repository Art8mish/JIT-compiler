
#include "../include/jit.h"


static int TranslateBCodeArg(JitIR *ir, BCode *bcode);

static AddrTbl *AddrTblCtor(BCode *bcode);
static int      AddrTblDtor(AddrTbl *addr_tbl);

static int CalcRelAddr(JitIR *ir, AddrTbl *addr_tbl);
static int FillAddrTbl(AddrTbl *addr_tbl, BCode *bcode);

static int ProcessBCode2IR(JitIR *ir, BCode *bcode);

static int _processIR_PUSH_POP(JitIR *ir, BCode *bcode);
static int _processIR_OP(JitIR *ir, BCode *bcode);
static int _processIR_JUMP(JitIR *ir, BCode *bcode);
static int _processIR_OUT(JitIR *ir, BCode *bcode);
static int _processIR_IN(JitIR *ir, BCode *bcode);

#define IR_ITM ir->buf[ir->ip]

#define IS_BCODE_JUMP(cmd)                \
           ((MSK16(cmd) == BCODE_JMP) ||  \
            (MSK16(cmd) == BCODE_JB)  ||  \
            (MSK16(cmd) == BCODE_JBE) ||  \
            (MSK16(cmd) == BCODE_JA)  ||  \
            (MSK16(cmd) == BCODE_JAE) ||  \
            (MSK16(cmd) == BCODE_JE)  ||  \
            (MSK16(cmd) == BCODE_JNE) ||  \
            (MSK16(cmd) == BCODE_CALL))

#define IS_BCODE_CND_JMP(cmd)             \
           ((MSK16(cmd) == BCODE_JB)  ||  \
            (MSK16(cmd) == BCODE_JBE) ||  \
            (MSK16(cmd) == BCODE_JA)  ||  \
            (MSK16(cmd) == BCODE_JAE) ||  \
            (MSK16(cmd) == BCODE_JE)  ||  \
            (MSK16(cmd) == BCODE_JNE))


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
        if (IS_BCODE_JUMP(code[bcode_ip]))
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


#define BCODE2IR_PUSH(ir, bcode)                    \
            

#define BCODE2IR_POP(ir, bcode)                     \
            _err = _processIR_PUSH_POP(ir, bcode);  \
            ERR_CHK(_err, ERR_PROC_IR_PUSH_POP)

#define BCODE2IR_JMP(ir, bcode)                     \
            _err = _processIR_JUMP(ir, bcode);      \
            ERR_CHK(_err, ERR_PROC_IR_JUMP)

#define BCODE2IR_JB(ir, bcode)                      \
            _err = _processIR_JUMP(ir, bcode);      \
            ERR_CHK(_err, ERR_PROC_IR_JUMP)

#define BCODE2IR_JBE(ir, bcode)                     \
            _err = _processIR_JUMP(ir, bcode);      \
            ERR_CHK(_err, ERR_PROC_IR_JUMP)

#define BCODE2IR_JA(ir, bcode)                      \
            _err = _processIR_JUMP(ir, bcode);      \
            ERR_CHK(_err, ERR_PROC_IR_JUMP)

#define BCODE2IR_JAE(ir, bcode)                     \
            _err = _processIR_JUMP(ir, bcode);      \
            ERR_CHK(_err, ERR_PROC_IR_JUMP)

#define BCODE2IR_JE(ir, bcode)                      \
            _err = _processIR_JUMP(ir, bcode);      \
            ERR_CHK(_err, ERR_PROC_IR_JUMP)

#define BCODE2IR_JNE(ir, bcode)                     \
            _err = _processIR_JUMP(ir, bcode);      \
            ERR_CHK(_err, ERR_PROC_IR_JUMP)

#define BCODE2IR_CALL(ir, bcode)                    \
            _err = _processIR_JUMP(ir, bcode);      \
            ERR_CHK(_err, ERR_PROC_IR_JUMP)

#define BCODE2IR_ADD(ir, bcode)                     \
            _err = _processIR_OP(ir, bcode);        \
            ERR_CHK(_err, ERR_PROC_IR_OP)

#define BCODE2IR_SUB(ir, bcode)                     \
            _err = _processIR_OP(ir, bcode);        \
            ERR_CHK(_err, ERR_PROC_IR_OP)

#define BCODE2IR_MUL(ir, bcode)                     \
            _err = _processIR_OP(ir, bcode);        \
            ERR_CHK(_err, ERR_PROC_IR_OP)

#define BCODE2IR_DIV(ir, bcode)                     \
            _err = _processIR_OP(ir, bcode);        \
            ERR_CHK(_err, ERR_PROC_IR_OP)

int TranslateBCode(JitIR *ir, BCode *bcode)
{
    ERR_CHK(ir             == NULL, ERR_NULL_PTR);
    ERR_CHK(ir->buf        == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(ir->buf_len    == 0,    ERR_NULL_BUF_LEN);
    ERR_CHK(bcode          == NULL, ERR_NULL_PTR);
    ERR_CHK(bcode->buf     == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(bcode->buf_len == 0,    ERR_NULL_BUF_LEN);
    ERR_CHK(ir->buf_len != bcode->buf_len * MAX_BCODE_CMD_LEN, ERR_WRONG_BUF_LEN);    

    AddrTbl *addr_tbl = AddrTblCtor(bcode);
    ERR_CHK(addr_tbl == NULL, ERR_ADDRTBL_CTOR);

    _err = DumpAddrTbl(addr_tbl);
    ERR_CHK(_err, ERR_DUMP);

    uint32_t tbl_ip = 0;
    int32_t *code = bcode->buf;

    bool is_jump = false;
    bcode->ip = 0;
    ir->ip    = 0;
    while(bcode->ip < bcode->buf_len)
    {
        IRitm *ir_itm = &ir->buf[ir->ip];
        switch(MSK16(code[bcode->ip]))
        {   
            #define DEF_CMD(name, num, arg, cpu_code)                                   \
                case BCODE_##name:  for(uint32_t ti = 0; ti < addr_tbl->len; ti++)      \
                                        if (addr_tbl->jmp_addr[ti] == bcode->ip)        \
                                            addr_tbl->jmp_addr[ti] = ir->ip;            \
                                    if (addr_tbl->instr_ip[tbl_ip] == bcode->ip)        \
                                        is_jump = true;                                 \
                                    _err = ProcessBCode2IR(ir, bcode);                  \
                                    ERR_CHK_SAFE(_err, AddrTblDtor(addr_tbl);,          \
                                                 ERR_PROC_BCODE2IR);                    \
                                    if(is_jump)                                         \
                                    {                                                   \
                                        addr_tbl->instr_ip[tbl_ip] = ir->ip;            \
                                        tbl_ip++;                                       \
                                    }                                                   \ 
                                    break;

            #include "../proc/cmd.h"

            #undef DEF_CMD

            default : printf(" # TranslateBCode(): ERROR: WRONG_BCODE_CMD = %d\n", MSK16(code[bcode->ip]));
                      _err = AddrTblDtor(addr_tbl);
                      ERR_CHK(_err, ERR_ADDRTBL_DTOR);
                      return ERR_BCODE_SYNTAX;
                      break;
        }

        is_jump = false;
        ir->ip++;
        bcode->ip++;

    }

    _err = DumpAddrTbl(addr_tbl);
    ERR_CHK_SAFE(_err, AddrTblDtor(addr_tbl);, ERR_DUMP);

    //calc relative addresses
    _err = CalcRelAddr(ir, addr_tbl);
    ERR_CHK_SAFE(_err, AddrTblDtor(addr_tbl);, ERR_CALC_REL_ADDR);
    
    _err = AddrTblDtor(addr_tbl);
    ERR_CHK(_err, ERR_ADDRTBL_DTOR);

    //realloc ir->buf to ir->ip len
    ir->buf_len = ir->ip;
    ir->buf     = (IRitm *) realloc(ir->buf, ir->buf_len * sizeof(IRitm));
    ERR_CHK(ir->buf == NULL, ERR_REALLOC);

    return SUCCESS;
}

static int ProcessBCode2IR(JitIR *ir, BCode *bcode)
{
    ERR_CHK(ir             == NULL, ERR_NULL_PTR);
    ERR_CHK(ir->buf        == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(ir->buf_len    == 0,    ERR_NULL_BUF_LEN);
    ERR_CHK(bcode          == NULL, ERR_NULL_PTR);
    ERR_CHK(bcode->buf     == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(bcode->buf_len == 0,    ERR_NULL_BUF_LEN);

    switch (MSK16(bcode->buf[bcode->ip]))
    {
        case BCODE_PUSH:    [[fallthrough]];
        case BCODE_POP:     _err = _processIR_PUSH_POP(ir, bcode);  
                            ERR_CHK(_err, ERR_PROC_IR_PUSH_POP);
                            break;

        case BCODE_CALL:    [[fallthrough]];
        case BCODE_JMP:     [[fallthrough]];
        case BCODE_JB:      [[fallthrough]];
        case BCODE_JBE:     [[fallthrough]];
        case BCODE_JA:      [[fallthrough]];
        case BCODE_JAE:     [[fallthrough]];
        case BCODE_JE:      [[fallthrough]];
        case BCODE_JNE:     _err = _processIR_JUMP(ir, bcode);
                            ERR_CHK(_err, ERR_PROC_IR_JUMP);
                            break;

        case BCODE_ADD:     [[fallthrough]];
        case BCODE_SUB:     [[fallthrough]];
        case BCODE_MUL:     [[fallthrough]];
        case BCODE_DIV:     _err = _processIR_OP(ir, bcode);  
                            ERR_CHK(_err, ERR_PROC_IR_OP);
                            break;

        case BCODE_IN:      _err = _processIR_IN(ir, bcode);  
                            ERR_CHK(_err, ERR_PROC_IR_IN);
                            break;

        case BCODE_OUT:      _err = _processIR_OUT(ir, bcode);  
                            ERR_CHK(_err, ERR_PROC_IR_OUT);
                            break;

        case BCODE_RET:     ir->buf[ir->ip].cmd.b1 = IRC_RET;
                            ir->buf[ir->ip].instr_len += 1;
                            break;

        case BCODE_HLT:     ir->buf[ir->ip].cmd.b1 = IRC_HLT;
                            ir->buf[ir->ip].instr_len += 1;
                            break;

        default: printf(" # ProcessBCode2IR(): ERROR: WRONG_BCODE_CMD = %d\n", MSK16(bcode->buf[bcode->ip]));
                 return ERR_BCODE_SYNTAX;
                 break;

    }

    
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

    for (uint32_t tbl_i = 0; tbl_i < addr_tbl->len; tbl_i++)
    {
        uint32_t instr_ip = addr_tbl->instr_ip[tbl_i];
        uint32_t  addr_ip = addr_tbl->jmp_addr[tbl_i];
        ERR_CHK(instr_ip == addr_ip, ERR_WRONG_ADDR_IP);

        int32_t rel_addr = 0;
        uint32_t ip = instr_ip;
        if (addr_ip > ip)
            while (++ip < addr_ip)
                rel_addr += ir->buf[ip].instr_len;
        else
            while (ip >= addr_ip)
                rel_addr -= ir->buf[ip--].instr_len;

        ir->buf[instr_ip].cnst = rel_addr;
    }

    return SUCCESS;
}


static int _processIR_PUSH_POP(JitIR *ir, BCode *bcode)
{
    ERR_CHK(ir             == NULL, ERR_NULL_PTR);
    ERR_CHK(ir->buf        == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(ir->buf_len    == 0,    ERR_NULL_BUF_LEN);
    ERR_CHK(bcode          == NULL, ERR_NULL_PTR);
    ERR_CHK(bcode->buf     == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(bcode->buf_len == 0,    ERR_NULL_BUF_LEN);

    IRitm *ir_itm = &ir->buf[ir->ip];

    int32_t *code = bcode->buf; 
    int32_t  bcmd  = code[bcode->ip];

    int8_t irc_op_rax = 0x00;
    int8_t irc_op_rcx = 0x00;
    int8_t irc_op_rdx = 0x00;
    int8_t irc_op_rbx = 0x00;

    int8_t irc_op_mem = 0x00;
    int8_t irc_op_modrm_reg = 0x00;

    switch(MSK16(bcmd))
    {
        case BCODE_PUSH: irc_op_rax = IRC_PUSH_RAX;
                         irc_op_rcx = IRC_PUSH_RCX;
                         irc_op_rdx = IRC_PUSH_RDX;
                         irc_op_rbx = IRC_PUSH_RBX;

                         irc_op_mem = IRC_MEM;
                         irc_op_modrm_reg = IRC_RSI;
                         break;

        case BCODE_POP:  irc_op_rax = IRC_POP_RAX;
                         irc_op_rcx = IRC_POP_RCX;
                         irc_op_rdx = IRC_POP_RDX;
                         irc_op_rbx = IRC_POP_RBX;

                         irc_op_mem = IRC_POP_MEM;
                         irc_op_modrm_reg = IRC_MODRM_REG_POP;
                         break;
        default: printf(" # _processIR_PUSH_POP(): ERROR: WRONG_BCODE_CMD = %d\n", MSK16(bcmd));
                 return ERR_IR_SYNTAX;
                 break;
    }

    switch (MSK_BCODE_MOD(bcmd))
    {
        case BCODE_REG:
                switch (code[++bcode->ip])
                {
                    case BCODE_REG_RAX: ir_itm->cmd.b1 = irc_op_rax;
                                        break;
                    case BCODE_REG_RCX: ir_itm->cmd.b1 = irc_op_rcx;
                                        break;
                    case BCODE_REG_RDX: ir_itm->cmd.b1 = irc_op_rdx;
                                        break;
                    case BCODE_REG_RBX: ir_itm->cmd.b1 = irc_op_rbx;
                                        break;
                    default: printf(" # _processIR_PUSH_POP(): ERROR: WRONG_REG_CODE = %d\n", code[bcode->ip]);
                             return ERR_IR_SYNTAX;
                             break;
                }
                
                ir_itm->instr_len += 1;
                break;  

        case BCODE_CNST:
                ERR_CHK(MSK16(bcmd) == BCODE_PUSH, ERR_IR_SYNTAX);
                ir_itm->cmd.b1 = IRC_PUSH_CNST;
                ir_itm->instr_len += 1;
                break;

        case BCODE_MEM_REG:
                ir_itm->cmd.b1    = irc_op_mem;

                ir_itm->ModRM.mod = IRC_MODRM_MOD_REG;
                ir_itm->ModRM.reg = irc_op_modrm_reg;

                ir_itm->instr_len += 2;
                break;

        case BCODE_MEM_CNST:
                ir_itm->cmd.b1    = irc_op_mem;

                ir_itm->ModRM.mod = IRC_MODRM_MOD_CNST;
                ir_itm->ModRM.reg = irc_op_modrm_reg;
                ir_itm->ModRM.rm  = IRC_MODRM_RM_SIB;

                ir_itm->SIB.scale = IRC_SIB_SCLF1;
                ir_itm->SIB.index = IRC_SIB_INDX_NONE;
                ir_itm->SIB.base  = IRC_SIB_BASE_NONE;

                ir_itm->instr_len += 3;
                break;

        case BCODE_MEM_REG_CNST:
                ir_itm->cmd.b1    = irc_op_mem;
                
                ir_itm->ModRM.mod = IRC_MODRM_MOD_REG_CNST;
                ir_itm->ModRM.reg = irc_op_modrm_reg;

                ir_itm->instr_len += 2;
                break;

        default:     
                printf(" # _processIR_PUSH_POP(): ERROR: WRONG_BCODE_MOD = %x\n", MSK_BCODE_MOD(bcmd));
                return ERR_IR_SYNTAX;
                break;             
    }

    if (bcmd & BCODE_CNST)
    {
        ir_itm->cnst = code[++bcode->ip];
        ir_itm->instr_len += 4;
    }

    if (bcmd & BCODE_MEM_REG)
    {
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
            default: printf(" # _processIR_PUSH(): ERROR: WRONG_REG_CODE = %d\n", code[bcode->ip]);
                     return ERR_IR_SYNTAX;
                     break;
        }
    }

    return SUCCESS;
}

#define TOIR_POP_REG(ir, reg)                               \
            IR_ITM.cmd.b1 = IRC_POP_##reg;                  \
            IR_ITM.instr_len += 1;                          \
            ir->ip++

#define TOIR_PUSH_REG(ir, reg)                              \
            IR_ITM.cmd.b1 = IRC_PUSH_##reg;                 \
            IR_ITM.instr_len += 1;                          \
            ir->ip++

#define TOIR_PUSH_CNST(ir, cnst32)                          \
            IR_ITM.cmd.b1 = IRC_PUSH_CNST;                  \
            IR_ITM.cnst = cnst32;                           \
            IR_ITM.instr_len += 5;                          \
            ir->ip++


#define TOIR_MOV_REG_REG(ir, regl, regr)                    \
            IR_ITM.prfx      = IRC_PRFX_OP64;               \
            IR_ITM.cmd.b1    = IRC_MOV_REG_REG;             \
            IR_ITM.ModRM.mod = IRC_MODRM_MOD_REG_DIR;       \
            IR_ITM.ModRM.reg = IRC_##regr;                  \
            IR_ITM.ModRM.rm  = IRC_##regl;                  \
            IR_ITM.instr_len += 3;                          \
            ir->ip++

#define TOIR_MOVABS_REG_CNST(ir, reg, cnst64)               \
            IR_ITM.prfx   = IRC_PRFX_OP64;                  \
            IR_ITM.cmd.b1 = IRC_MOVABS_##reg;               \
            IR_ITM.cnst   = cnst64;                         \
            IR_ITM.instr_len += 10;                         \
            ir->ip++

#define TOIR_CMP_REG_REG(ir, regl, regr)                    \
            IR_ITM.prfx      = IRC_PRFX_OP64;               \
            IR_ITM.cmd.b1    = IRC_CMP_REG_REG;             \
            IR_ITM.ModRM.mod = IRC_MODRM_MOD_REG_DIR;       \
            IR_ITM.ModRM.reg = IRC_##regr;                  \
            IR_ITM.ModRM.rm  = IRC_##regl;                  \
            IR_ITM.instr_len += 3;                          \
            ir->ip++

#define TOIR_CALL_REG(ir, register);                        \
            IR_ITM.cmd.b1 = IRC_MEM;                        \
            IR_ITM.ModRM.mod = IRC_MODRM_MOD_REG_DIR;       \
            IR_ITM.ModRM.reg = IRC_MODRM_REG_CALL_ABS;      \
            IR_ITM.ModRM.rm  = IRC_##register;              \
            IR_ITM.instr_len += 2;                          \
            ir->ip++

#define TOIR_SUB_REG_CNST(ir, register, cnst32)             \
            IR_ITM.prfx      = IRC_PRFX_OP64;               \
            IR_ITM.cmd.b1    = IRC_OP_CNST;                 \
            IR_ITM.ModRM.mod = IRC_MODRM_MOD_REG_DIR;       \
            IR_ITM.ModRM.reg = IRC_MODRM_REG_SUB_REG_CNST;  \
            IR_ITM.ModRM.rm  = IRC_##register;              \
            IR_ITM.cnst      = cnst32;                      \
            IR_ITM.instr_len += 7;   

#define TOIR_ADD_REG_CNST(ir, register, cnst32)             \
            IR_ITM.prfx      = IRC_PRFX_OP64;               \
            IR_ITM.cmd.b1    = IRC_OP_CNST;                 \
            IR_ITM.ModRM.mod = IRC_MODRM_MOD_REG_DIR;       \
            IR_ITM.ModRM.reg = IRC_MODRM_REG_ADD_REG_CNST;  \
            IR_ITM.ModRM.rm  = IRC_##register;              \
            IR_ITM.cnst      = cnst32;                      \
            IR_ITM.instr_len += 7;


static int _processIR_OP(JitIR *ir, BCode *bcode)
{
    ERR_CHK(ir             == NULL, ERR_NULL_PTR);
    ERR_CHK(ir->buf        == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(ir->buf_len    == 0,    ERR_NULL_BUF_LEN);
    ERR_CHK(bcode          == NULL, ERR_NULL_PTR);
    ERR_CHK(bcode->buf     == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(bcode->buf_len == 0,    ERR_NULL_BUF_LEN);

    int32_t *code = bcode->buf; 

    TOIR_POP_REG(ir, RSI);
    TOIR_POP_REG(ir, RDI);

    bool idiv = false;
    if (code[bcode->ip] == BCODE_DIV)
        idiv = true;

    if (idiv)
    {
        TOIR_PUSH_REG(ir, RAX);
        TOIR_PUSH_REG(ir, RDX);
        TOIR_MOV_REG_REG(ir, RAX, RDI);
    }
    
    IRitm *ir_itm = &ir->buf[ir->ip];

    ir_itm->prfx = IRC_PRFX_OP64;
    ir_itm->instr_len += 1;
        
    switch(code[bcode->ip])
    {
        //ADD RDI, RSI  
        case BCODE_ADD: ir_itm->cmd.b1 = IRC_ADD;

                        ir_itm->ModRM.mod = IRC_MODRM_MOD_REG_DIR;
                        ir_itm->ModRM.reg = IRC_RSI;
                        ir_itm->ModRM.rm  = IRC_RDI;

                        ir_itm->instr_len += 2;
                        break;

        //SUB RDI, RSI  
        case BCODE_SUB: ir_itm->cmd.b1 = IRC_SUB;

                        ir_itm->ModRM.mod = IRC_MODRM_MOD_REG_DIR;
                        ir_itm->ModRM.reg = IRC_RSI;
                        ir_itm->ModRM.rm  = IRC_RDI;

                        ir_itm->instr_len += 2;
                        break;

        //IMUL RDI, RSI  
        case BCODE_MUL: ir_itm->cmd.b1 = IRC_TWO_BYTE;

                        ir_itm->cmd.b2 = IRC_IMUL;

                        ir_itm->ModRM.mod = IRC_MODRM_MOD_REG_DIR;
                        ir_itm->ModRM.reg = IRC_RDI;
                        ir_itm->ModRM.rm  = IRC_RSI;

                        ir_itm->instr_len += 3;
                        break;

        //IDIV RSI  
        case BCODE_DIV: ir_itm->cmd.b1 = IRC_IDIV;

                        ir_itm->ModRM.mod = IRC_MODRM_MOD_REG_DIR;
                        ir_itm->ModRM.reg = IRC_MODRM_REG_IDIV64;
                        ir_itm->ModRM.rm  = IRC_RSI;

                        ir_itm->instr_len += 2;
                        break;
        
        default: printf(" # _processIR_OP(): ERROR: WRONG_BCODE_CMD = %x\n", code[bcode->ip]);
                 return ERR_IR_SYNTAX;
                 break;
    }
    ir->ip++;

    if (idiv)
    {
        TOIR_MOV_REG_REG(ir, RDI, RAX);
        TOIR_POP_REG(ir, RDX);
        TOIR_POP_REG(ir, RAX);
    }

    TOIR_PUSH_REG(ir, RDI);
    ir->ip--;

    return SUCCESS;
}

static int _processIR_JUMP(JitIR *ir, BCode *bcode)
{
    ERR_CHK(ir             == NULL, ERR_NULL_PTR);
    ERR_CHK(ir->buf        == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(ir->buf_len    == 0,    ERR_NULL_BUF_LEN);
    ERR_CHK(bcode          == NULL, ERR_NULL_PTR);
    ERR_CHK(bcode->buf     == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(bcode->buf_len == 0,    ERR_NULL_BUF_LEN);

    if (IS_BCODE_CND_JMP(bcode->buf[bcode->ip]))
    {
        TOIR_POP_REG(ir, RSI);
        TOIR_POP_REG(ir, RDI);

        TOIR_CMP_REG_REG(ir, RDI, RSI);
    }

    IRitm *ir_itm = &ir->buf[ir->ip];
    switch(MSK16(bcode->buf[bcode->ip]))
    {
        case BCODE_JMP: ir_itm->cmd.b1 = IRC_JMP;
                        ir_itm->instr_len += 1;
                        break;

        case BCODE_CALL:ir_itm->cmd.b1 = IRC_CALL_REL;
                        ir_itm->instr_len += 1;
                        break;

        case BCODE_JB:  ir_itm->cmd.b1 = IRC_TWO_BYTE;
                        ir_itm->cmd.b2 = IRC_JB;
                        ir_itm->instr_len += 2;
                        break;

        case BCODE_JBE: ir_itm->cmd.b1 = IRC_TWO_BYTE;
                        ir_itm->cmd.b2 = IRC_JBE;
                        ir_itm->instr_len += 2;
                        break;

        case BCODE_JA:  ir_itm->cmd.b1 = IRC_TWO_BYTE;
                        ir_itm->cmd.b2 = IRC_JA;
                        ir_itm->instr_len += 2;
                        break;

        case BCODE_JAE: ir_itm->cmd.b1 = IRC_TWO_BYTE;
                        ir_itm->cmd.b2 = IRC_JAE;
                        ir_itm->instr_len += 2;
                        break;

        case BCODE_JE:  ir_itm->cmd.b1 = IRC_TWO_BYTE;
                        ir_itm->cmd.b2 = IRC_JE;
                        ir_itm->instr_len += 2;
                        break;

        case BCODE_JNE: ir_itm->cmd.b1 = IRC_TWO_BYTE;
                        ir_itm->cmd.b2 = IRC_JNE;
                        ir_itm->instr_len += 2;
                        break;

        default: printf(" # _processIR_JUMP(): ERROR: WRONG_BCOODE_JUMP_CMD = %x\n", MSK16(bcode->buf[bcode->ip]));
                 return ERR_IR_SYNTAX;
                 break;
    }

    ir_itm->cnst = bcode->buf[++bcode->ip];
    ir_itm->instr_len += 4;

    return SUCCESS;
}

static int _processIR_OUT(JitIR *ir, BCode *bcode)
{
    ERR_CHK(ir             == NULL, ERR_NULL_PTR);
    ERR_CHK(ir->buf        == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(ir->buf_len    == 0,    ERR_NULL_BUF_LEN);
    ERR_CHK(bcode          == NULL, ERR_NULL_PTR);
    ERR_CHK(bcode->buf     == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(bcode->buf_len == 0,    ERR_NULL_BUF_LEN);

    const char *str = "%d\n";
    int (*printf_ptr)(const char *, ...) = printf; 

    TOIR_MOVABS_REG_CNST(ir, RDI, (int64_t)str);
    TOIR_POP_REG(ir, RSI);

    TOIR_PUSH_REG(ir, RAX);
    TOIR_MOVABS_REG_CNST(ir, RAX, (int64_t)printf_ptr);
    TOIR_CALL_REG(ir, RAX);
    TOIR_POP_REG(ir, RAX);
    ir->ip--;

    return SUCCESS;
}

static int _processIR_IN(JitIR *ir, BCode *bcode)
{
    ERR_CHK(ir             == NULL, ERR_NULL_PTR);
    ERR_CHK(ir->buf        == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(ir->buf_len    == 0,    ERR_NULL_BUF_LEN);
    ERR_CHK(bcode          == NULL, ERR_NULL_PTR);
    ERR_CHK(bcode->buf     == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(bcode->buf_len == 0,    ERR_NULL_BUF_LEN);

    const char *str = "Enter num: %d";
    int (*scanf_ptr)(const char *, ...) = scanf; 

    TOIR_MOVABS_REG_CNST(ir, RDI, (int64_t)str);

    TOIR_PUSH_REG(ir, RAX);
    TOIR_SUB_REG_CNST(ir, RSP, 4);

    //LEA RSI, [RSP]---------------------
    IR_ITM.prfx      = IRC_PRFX_OP64;

    IR_ITM.cmd.b1    = IRC_LEA_REG_MEM;

    IR_ITM.ModRM.mod = IRC_MODRM_MOD_REG;
    IR_ITM.ModRM.reg = IRC_RSI; 
    IR_ITM.ModRM.rm  = IRC_MODRM_RM_SIB;

    IR_ITM.SIB.scale = IRC_SIB_SCLF1;
    IR_ITM.SIB.index = IRC_SIB_INDX_NONE; 
    IR_ITM.SIB.base  = IRC_RSP;

    IR_ITM.instr_len += 4;
    ir->ip++;
    //-----------------------------------

    TOIR_MOVABS_REG_CNST(ir, RAX, (int64_t)scanf_ptr);
    TOIR_CALL_REG(ir, RAX);

    //PUSH [RSP]-------------------------
    IR_ITM.cmd.b1    = IRC_MEM;

    IR_ITM.ModRM.mod = IRC_MODRM_MOD_REG;
    IR_ITM.ModRM.reg = IRC_RSI; 
    IR_ITM.ModRM.rm  = IRC_MODRM_RM_SIB;

    IR_ITM.SIB.scale = IRC_SIB_SCLF1;
    IR_ITM.SIB.index = IRC_SIB_INDX_NONE; 
    IR_ITM.SIB.base  = IRC_RSP;

    IR_ITM.instr_len += 3;
    ir->ip++;
    //-----------------------------------

    TOIR_ADD_REG_CNST(ir, RSP, 4);
    TOIR_POP_REG(ir, RAX);
    ir->ip--;

    return SUCCESS;
}

// int AssembleIR(ExCode *ex_code, JitIR *ir)
// {
//     ERR_CHK(ex_code          == NULL, ERR_NULL_PTR);
//     ERR_CHK(ex_code->buf     == NULL, ERR_NULL_BUF_PTR);
//     ERR_CHK(ex_code->buf_len == 0,    ERR_NULL_BUF_LEN);
//     ERR_CHK(ir               == NULL, ERR_NULL_PTR);
//     ERR_CHK(ir->buf          == NULL, ERR_NULL_BUF_PTR);
//     ERR_CHK(ir->buf_len      == 0,    ERR_NULL_BUF_LEN);
//     ERR_CHK(ex_code->buf_len != ir->buf_len * SYS_WORD_LEN, ERR_WRONG_BUF_LEN);

//     ExCode *code = ex_code;

//     ex_code->ip = 0;
//     ir->ip = 0;
//     while(ir->ip < ir->buf_len)
//     {
//         int32_t code_old_ip = code->ip;
//         switch(ir->buf[ir->ip].cmd)
//         {
//             #define JIT_CMD(name, num, arg, jit_code)                                   \
//                         case name##_CODE :       
                                                
//                                                 break;

//             #include "../include/ir_cmd.h"

//             #undef JIT_CMD

//             default : printf(" # AssembleIR(): ERROR: code = %x\n", ir->buf[ir->ip].cmd);
//                       return ERR_IR_SYNTAX;
//                       break;
//         }

//         ir->buf[ir->ip].instr_len = code->ip - code_old_ip;
//         ir->ip++;
//     }



//     ex_code->buf_len = ex_code->ip;
//     ex_code->buf     = (int8_t *) realloc(ex_code->buf, ex_code->buf_len * sizeof(int8_t));
//     ERR_CHK(ex_code->buf == NULL, ERR_REALLOC);

//     //asm ("call %0": "r" (ex_code->buf));

//     return SUCCESS;
// }

// static int AssembleIRArg(ExCode *ex_code, JitIR *ir)
// {
//     ERR_CHK(ex_code          == NULL, ERR_NULL_PTR);
//     ERR_CHK(ex_code->buf     == NULL, ERR_NULL_BUF_PTR);
//     ERR_CHK(ex_code->buf_len == 0,    ERR_NULL_BUF_LEN);
//     ERR_CHK(     ir          == NULL, ERR_NULL_PTR);
//     ERR_CHK(     ir->buf     == NULL, ERR_NULL_BUF_PTR);
//     ERR_CHK(     ir->buf_len == 0,    ERR_NULL_BUF_LEN);

    


//     return SUCCESS;
// }


// static int AsmPUSH(ExCode *code, IRitm *iritm)
// {
//     ERR_CHK(code          == NULL, ERR_NULL_PTR);
//     ERR_CHK(code->buf     == NULL, ERR_NULL_BUF_PTR);
//     ERR_CHK(code->buf_len == 0,    ERR_NULL_BUF_LEN);
//     ERR_CHK(iritm         == NULL, ERR_NULL_PTR);

//     switch (MSK3(iritm->mod))
//     {
//         case MOD_REG:   
//                 code->buf[code->ip++] = 0x50 + iritm->reg;
//                 break;  

//         case MOD_CNST:  
//                 code->buf[code->ip++] = 0x68;
//                 break;

//         case MOD_MEM_REG:
//                 code->buf[code->ip++] = 0xff;
//                 code->buf[code->ip++] = 0x30 + iritm->reg;
//                 break;
        
//         case MOD_MEM_CNST:
//                 code->buf[code->ip++] = 0xff;
//                 code->buf[code->ip++] = 0x34; //ModRM
//                 code->buf[code->ip++] = 0x25; //SIB
//                 break;

//         case MOD_MEM_REG_CNST:
//                 code->buf[code->ip++] = 0xff;
//                 code->buf[code->ip++] = 0xb0 + iritm->reg;   
//         default:     
//                 printf(" # AsmPUSH(): ERROR: code = %x. \n", MSK3(iritm->mod));
//                 return ERR_IR_SYNTAX;
//                 break;             
//     }
    
//     if (CNST_MSK(iritm->mod))
//     {
//         memmove(&code->buf[code->ip], &iritm->cnst, sizeof(int32_t));
//         code->ip += sizeof(int32_t); 
//     }

//     return SUCCESS;
// }