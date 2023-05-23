
#include "../include/jit.h"

static AddrTbl *AddrTblCtor(BCode *bcode);
static int      AddrTblDtor(AddrTbl *addr_tbl);
static int CalcRelAddr(JitIR *ir, AddrTbl *addr_tbl);
static int FillAddrTbl(AddrTbl *addr_tbl, BCode *bcode);

static int ProcessBCode(JitIR *ir, BCode *bcode);
static int _processIR_PUSH_POP(JitIR *ir, BCode *bcode);
static int _processIR_OP(JitIR *ir, BCode *bcode);
static int _processIR_JUMP(JitIR *ir, BCode *bcode);
static int _processIR_OUT(JitIR *ir, BCode *bcode);
static int _processIR_IN(JitIR *ir, BCode *bcode);


static int AssembleIRitm(ExCode *ex_code, JitIR *ir, int prfx_ind, int modrm_ind, int cnst_ind);

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

    addr_tbl->jmp_addr = (int32_t *) calloc(bcode->buf_len, sizeof(int32_t));
    ERR_CHK(addr_tbl->jmp_addr == NULL, NULL);

    //fill tbl
    addr_tbl->len = 0;
    _err = FillAddrTbl(addr_tbl, bcode);
    ERR_CHK(_err, NULL);

    //realloc bufs 
    addr_tbl->instr_ip = (uint32_t *) realloc(addr_tbl->instr_ip, addr_tbl->len * sizeof(uint32_t));
    ERR_CHK(addr_tbl->instr_ip == NULL, NULL); 

    addr_tbl->jmp_addr = (int32_t *) realloc(addr_tbl->jmp_addr, addr_tbl->len * sizeof(int32_t));
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

        if (MSK16(code[bcode_ip])  == BCODE_PUSH || 
            MSK16(code[bcode_ip])  == BCODE_POP)
            bcode_ip += 2;

        else
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
        addr_tbl->jmp_addr[tbl_i] = rel_addr;
    }

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


int TranslateBCode2IR(JitIR *ir, BCode *bcode)
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
    int32_t new_addr[addr_tbl->len] = {};

    bool is_jump = false;
    bcode->ip = 0;
    ir->ip    = 0;
    while(bcode->ip < bcode->buf_len)
    {
        switch(MSK16(code[bcode->ip]))
        {   
            #define DEF_CMD(name, num, arg, cpu_code)                                   \
                case BCODE_##name:  for(uint32_t ti = 0; ti < addr_tbl->len; ti++)      \
                                        if (addr_tbl->jmp_addr[ti] == (int32_t)bcode->ip)\
                                            new_addr[ti] = ir->ip;                      \
                                    if (addr_tbl->instr_ip[tbl_ip] == bcode->ip)        \
                                        is_jump = true;                                 \
                                    _err = ProcessBCode(ir, bcode);                     \
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


    //writing new abs addresses
    for (uint32_t ti = 0; ti < addr_tbl->len; ti++)
        addr_tbl->jmp_addr[ti] = new_addr[ti];

    _err = DumpAddrTbl(addr_tbl);
    ERR_CHK_SAFE(_err, AddrTblDtor(addr_tbl);, ERR_DUMP);

    //calc relative addresses
    _err = CalcRelAddr(ir, addr_tbl);
    ERR_CHK_SAFE(_err, AddrTblDtor(addr_tbl);, ERR_CALC_REL_ADDR);

    _err = DumpAddrTbl(addr_tbl);
    ERR_CHK_SAFE(_err, AddrTblDtor(addr_tbl);, ERR_DUMP);
    
    _err = AddrTblDtor(addr_tbl);
    ERR_CHK(_err, ERR_ADDRTBL_DTOR);

    //realloc ir->buf to ir->ip len
    ir->buf_len = ir->ip;
    ir->buf     = (IRitm *) realloc(ir->buf, ir->buf_len * sizeof(IRitm));
    ERR_CHK(ir->buf == NULL, ERR_REALLOC);

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
            IR_ITM.instr_len += 7;                          \
            ir->ip++   

#define TOIR_ADD_REG_CNST(ir, register, cnst32)             \
            IR_ITM.prfx      = IRC_PRFX_OP64;               \
            IR_ITM.cmd.b1    = IRC_OP_CNST;                 \
            IR_ITM.ModRM.mod = IRC_MODRM_MOD_REG_DIR;       \
            IR_ITM.ModRM.reg = IRC_MODRM_REG_ADD_REG_CNST;  \
            IR_ITM.ModRM.rm  = IRC_##register;              \
            IR_ITM.cnst      = cnst32;                      \
            IR_ITM.instr_len += 7;                          \
            ir->ip++

static int ProcessBCode(JitIR *ir, BCode *bcode)
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

static int _processIR_PUSH_POP(JitIR *ir, BCode *bcode)
{
    ERR_CHK(ir             == NULL, ERR_NULL_PTR);
    ERR_CHK(ir->buf        == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(ir->buf_len    == 0,    ERR_NULL_BUF_LEN);
    ERR_CHK(bcode          == NULL, ERR_NULL_PTR);
    ERR_CHK(bcode->buf     == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(bcode->buf_len == 0,    ERR_NULL_BUF_LEN);

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
                    case BCODE_REG_RAX: IR_ITM.cmd.b1 = irc_op_rax;
                                        break;
                    case BCODE_REG_RCX: IR_ITM.cmd.b1 = irc_op_rcx;
                                        break;
                    case BCODE_REG_RDX: IR_ITM.cmd.b1 = irc_op_rdx;
                                        break;
                    case BCODE_REG_RBX: IR_ITM.cmd.b1 = irc_op_rbx;
                                        break;
                    default: printf(" # _processIR_PUSH_POP(%d): ERROR: WRONG_REG_CODE = %x\n",
                                    bcode->ip, code[bcode->ip]);
                             return ERR_IR_SYNTAX;
                             break;
                }
                
                IR_ITM.instr_len += 1;
                break;  

        case BCODE_CNST:
                ERR_CHK(MSK16(bcmd) == BCODE_POP, ERR_IR_SYNTAX);
                IR_ITM.cmd.b1 = IRC_PUSH_CNST;
                IR_ITM.instr_len += 1;
                break;

        case BCODE_MEM_REG:
                IR_ITM.cmd.b1    = irc_op_mem;

                IR_ITM.ModRM.mod = IRC_MODRM_MOD_00;
                IR_ITM.ModRM.reg = irc_op_modrm_reg;

                IR_ITM.instr_len += 2;
                break;

        case BCODE_MEM_CNST:
                IR_ITM.cmd.b1    = irc_op_mem;

                IR_ITM.ModRM.mod = IRC_MODRM_MOD_00;
                IR_ITM.ModRM.reg = irc_op_modrm_reg;
                IR_ITM.ModRM.rm  = IRC_MODRM_RM_SIB;

                IR_ITM.SIB.scale = IRC_SIB_SCLF1;
                IR_ITM.SIB.index = IRC_SIB_INDX_NONE;
                IR_ITM.SIB.base  = IRC_SIB_BASE_NONE;

                IR_ITM.instr_len += 3;
                break;

        case BCODE_MEM_REG_CNST:
                IR_ITM.cmd.b1    = irc_op_mem;
                
                IR_ITM.ModRM.mod = IRC_MODRM_MOD_REG_CNST;
                IR_ITM.ModRM.reg = irc_op_modrm_reg;

                IR_ITM.instr_len += 2;
                break;

        default:     
                printf(" # _processIR_PUSH_POP(): ERROR: WRONG_BCODE_MOD = %x\n", MSK_BCODE_MOD(bcmd));
                return ERR_IR_SYNTAX;
                break;             
    }

    if (bcmd & BCODE_CNST)
    {
        IR_ITM.cnst = code[++bcode->ip];
        IR_ITM.instr_len += 4;
    }

    if (bcmd & BCODE_MEM && bcmd & BCODE_REG)
    {
        switch (code[++bcode->ip])
        {
            case BCODE_REG_RAX: IR_ITM.ModRM.rm = IRC_RAX;
                                break;
            case BCODE_REG_RCX: IR_ITM.ModRM.rm = IRC_RCX;
                                break;
            case BCODE_REG_RDX: IR_ITM.ModRM.rm = IRC_RDX;
                                break;
            case BCODE_REG_RBX: IR_ITM.ModRM.rm = IRC_RBX;
                                break;
            default: printf(" # _processIR_PUSH_POP(%d): ERROR: WRONG_REG_CODE = %x\n", 
                            bcode->ip, code[bcode->ip]);
                     return ERR_IR_SYNTAX;
                     break;
        }
    }

    return SUCCESS;
}




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
    

    IR_ITM.prfx = IRC_PRFX_OP64;
    IR_ITM.instr_len += 1;
        
    switch(code[bcode->ip])
    {
        //ADD RDI, RSI  
        case BCODE_ADD: IR_ITM.cmd.b1 = IRC_ADD;

                        IR_ITM.ModRM.mod = IRC_MODRM_MOD_REG_DIR;
                        IR_ITM.ModRM.reg = IRC_RSI;
                        IR_ITM.ModRM.rm  = IRC_RDI;

                        IR_ITM.instr_len += 2;
                        break;

        //SUB RDI, RSI  
        case BCODE_SUB: IR_ITM.cmd.b1 = IRC_SUB;

                        IR_ITM.ModRM.mod = IRC_MODRM_MOD_REG_DIR;
                        IR_ITM.ModRM.reg = IRC_RSI;
                        IR_ITM.ModRM.rm  = IRC_RDI;

                        IR_ITM.instr_len += 2;
                        break;

        //IMUL RDI, RSI  
        case BCODE_MUL: IR_ITM.cmd.b1 = IRC_TWO_BYTE;

                        IR_ITM.cmd.b2 = IRC_IMUL;

                        IR_ITM.ModRM.mod = IRC_MODRM_MOD_REG_DIR;
                        IR_ITM.ModRM.reg = IRC_RDI;
                        IR_ITM.ModRM.rm  = IRC_RSI;

                        IR_ITM.instr_len += 3;
                        break;

        //IDIV RSI  
        case BCODE_DIV: IR_ITM.cmd.b1 = IRC_IDIV;

                        IR_ITM.ModRM.mod = IRC_MODRM_MOD_REG_DIR;
                        IR_ITM.ModRM.reg = IRC_MODRM_REG_IDIV64;
                        IR_ITM.ModRM.rm  = IRC_RSI;

                        IR_ITM.instr_len += 2;
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

    switch(MSK16(bcode->buf[bcode->ip]))
    {
        case BCODE_JMP: IR_ITM.cmd.b1 = IRC_JMP;
                        IR_ITM.instr_len += 1;
                        break;

        case BCODE_CALL:IR_ITM.cmd.b1 = IRC_CALL_REL;
                        IR_ITM.instr_len += 1;
                        break;

        case BCODE_JB:  IR_ITM.cmd.b1 = IRC_TWO_BYTE;
                        IR_ITM.cmd.b2 = IRC_JB;
                        IR_ITM.instr_len += 2;
                        break;

        case BCODE_JBE: IR_ITM.cmd.b1 = IRC_TWO_BYTE;
                        IR_ITM.cmd.b2 = IRC_JBE;
                        IR_ITM.instr_len += 2;
                        break;

        case BCODE_JA:  IR_ITM.cmd.b1 = IRC_TWO_BYTE;
                        IR_ITM.cmd.b2 = IRC_JA;
                        IR_ITM.instr_len += 2;
                        break;

        case BCODE_JAE: IR_ITM.cmd.b1 = IRC_TWO_BYTE;
                        IR_ITM.cmd.b2 = IRC_JAE;
                        IR_ITM.instr_len += 2;
                        break;

        case BCODE_JE:  IR_ITM.cmd.b1 = IRC_TWO_BYTE;
                        IR_ITM.cmd.b2 = IRC_JE;
                        IR_ITM.instr_len += 2;
                        break;

        case BCODE_JNE: IR_ITM.cmd.b1 = IRC_TWO_BYTE;
                        IR_ITM.cmd.b2 = IRC_JNE;
                        IR_ITM.instr_len += 2;
                        break;

        default: printf(" # _processIR_JUMP(): ERROR: WRONG_BCOODE_JUMP_CMD = %x\n", MSK16(bcode->buf[bcode->ip]));
                 return ERR_IR_SYNTAX;
                 break;
    }

    IR_ITM.cnst = bcode->buf[++bcode->ip];
    IR_ITM.instr_len += 4;

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

int __scanf ()
{
    
    int num = 0;
    char buf[32] = {0};

    printf ("Enter num: \n");
    read (0, buf, 32);
    int i = 0;
    while (buf[i] >= '0')
    {
        num *= 10;
        num += buf[i] - '0';
        i += 1;
    }
    return num;
}

static int _processIR_IN(JitIR *ir, BCode *bcode)
{
    ERR_CHK(ir             == NULL, ERR_NULL_PTR);
    ERR_CHK(ir->buf        == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(ir->buf_len    == 0,    ERR_NULL_BUF_LEN);
    ERR_CHK(bcode          == NULL, ERR_NULL_PTR);
    ERR_CHK(bcode->buf     == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(bcode->buf_len == 0,    ERR_NULL_BUF_LEN);

    int (*scanf_ptr)() = __scanf; 

    TOIR_MOV_REG_REG(ir, RDI, RAX);
    // TOIR_SUB_REG_CNST(ir, RSP, 8);

    // //LEA RSI, [RSP+8]---------------------
    // IR_ITM.prfx      = IRC_PRFX_OP64;

    // IR_ITM.cmd.b1    = IRC_LEA_REG_MEM;

    // IR_ITM.ModRM.mod = IRC_MODRM_MOD_REG_CNST;
    // IR_ITM.ModRM.reg = IRC_RSI; 
    // IR_ITM.ModRM.rm  = IRC_MODRM_RM_SIB;

    // IR_ITM.SIB.scale = IRC_SIB_SCLF1;
    // IR_ITM.SIB.index = IRC_SIB_INDX_NONE; 
    // IR_ITM.SIB.base  = IRC_RSP;

    // IR_ITM.cnst = 8;
    // IR_ITM.instr_len += 8;
    // ir->ip++;
    // //-----------------------------------

    TOIR_MOVABS_REG_CNST(ir, RAX, (int64_t)__scanf);
    TOIR_CALL_REG(ir, RAX);

    // //PUSH [RSP]-------------------------
    // IR_ITM.cmd.b1    = IRC_MEM;

    // IR_ITM.ModRM.mod = IRC_MODRM_MOD_00;
    // IR_ITM.ModRM.reg = IRC_RSI; 
    // IR_ITM.ModRM.rm  = IRC_MODRM_RM_SIB;

    // IR_ITM.SIB.scale = IRC_SIB_SCLF1;
    // IR_ITM.SIB.index = IRC_SIB_INDX_NONE; 
    // IR_ITM.SIB.base  = IRC_RSP;

    // IR_ITM.instr_len += 3;
    // ir->ip++;
    // //-----------------------------------

    // //MOV RDI, [RSP+8]-----------------------
    // IR_ITM.prfx      = IRC_PRFX_OP64;

    // IR_ITM.cmd.b1    = IRC_MOV_REG_MEM;

    // IR_ITM.ModRM.mod = IRC_MODRM_MOD_REG_CNST;
    // IR_ITM.ModRM.reg = IRC_RDI; 
    // IR_ITM.ModRM.rm  = IRC_MODRM_RM_SIB;

    // IR_ITM.SIB.scale = IRC_SIB_SCLF1;
    // IR_ITM.SIB.index = IRC_SIB_INDX_NONE; 
    // IR_ITM.SIB.base  = IRC_RSP;

    // IR_ITM.cnst = 8;
    // IR_ITM.instr_len += 8;
    // ir->ip++;
    // //-----------------------------------

    // TOIR_ADD_REG_CNST(ir, RSP, 8);
    TOIR_PUSH_REG(ir, RAX);
    TOIR_MOV_REG_REG(ir, RAX, RDI);
    ir->ip--;

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
    ERR_CHK(ex_code->buf_len != ir->buf_len * MAX_IR_INSTR_LEN, ERR_WRONG_BUF_LEN);

    ex_code->ip = 0;
    ir->ip = 0;
    while(ir->ip < ir->buf_len)
    {
        switch(IR_ITM.cmd.b1)
        {
            #define IR_CMD(name, prefix, ModRMbyte, constant)                                       \
                        case IRC_##name : {                                                         \
                                _err = AssembleIRitm(ex_code, ir, prefix, ModRMbyte, constant);     \
                                ERR_CHK(_err, ERR_ASSEMBLE_IR);                                     \
                                break; }

            #include "../include/ir_cmd.h"

            #undef IR_CMD

            default : {printf(" # AssembleIR(%d): ERROR: WRONG_IR_CMDB1 = %x. \n", ir->ip, IR_ITM.cmd.b1);
                      return ERR_IR_SYNTAX;
                      break;}
        }

        ir->ip++;
    }

    //ex_code->buf_len = ex_code->ip;
    //ex_code->buf     = (int8_t *) realloc(ex_code->buf, ex_code->buf_len * sizeof(int8_t));
    //ERR_CHK(ex_code->buf == NULL, ERR_REALLOC);

    //asm ("call %0": "r" (ex_code->buf));

    return SUCCESS;
}

static int AssembleIRitm(ExCode *ex_code, JitIR *ir, int prfx_ind, int modrm_ind, int cnst_ind)
{
    ERR_CHK(ex_code          == NULL, ERR_NULL_PTR);
    ERR_CHK(ex_code->buf     == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(ex_code->buf_len == 0,    ERR_NULL_BUF_LEN);
    ERR_CHK(ir               == NULL, ERR_NULL_PTR);
    ERR_CHK(ir->buf          == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(ir->buf_len      == 0,    ERR_NULL_BUF_LEN);
    ERR_CHK(prfx_ind  != 0 && prfx_ind  != 1, ERR_WORNG_PRFX_IND);
    ERR_CHK(modrm_ind != 0 && modrm_ind != 1, ERR_WORNG_PRFX_IND);
    ERR_CHK(cnst_ind  != 0 && cnst_ind  != 1 && cnst_ind != 2, ERR_WORNG_PRFX_IND);
    
    int8_t *code = ex_code->buf;
    if (IR_CMD_B1(ir) == IRC_TWO_BYTE) 
    {  
        switch(IR_CMD_B2(ir)) 
        {  
            case IRC_JB:    [[fallthrough]] 
            case IRC_JBE:   [[fallthrough]] 
            case IRC_JA:    [[fallthrough]] 
            case IRC_JAE:   [[fallthrough]] 
            case IRC_JE:    [[fallthrough]] 
            case IRC_JNE:   cnst_ind = 1; 
                            break;  
            case IRC_IMUL:  prfx_ind = 1;
                            modrm_ind = 1;
                            break;
            default: printf(" # AssembleIRitm(%d): ERROR: WRONG_IR_CMDB2 = %x\n",
                                ir->ip, IR_CMD_B2(ir));
                    return ERR_IR_SYNTAX;
                    break;
        } 
    }

    if (prfx_ind)
        code[ex_code->ip++] = IR_PRFX(ir);

    if (IR_CMD_B1(ir) == IRC_HLT)
        code[ex_code->ip] = IRC_RET;

    else
        code[ex_code->ip] = IR_CMD_B1(ir);
    ex_code->ip++;

    if (IR_CMD_B1(ir) == IRC_TWO_BYTE)
        code[ex_code->ip++] = IR_CMD_B2(ir);

    if (modrm_ind)
    {
        code[ex_code->ip++] = IR_MODRM(ir);

        if ((IR_MODRM_MOD_IS_00(ir) && IR_MODRM_RM(ir) == IRC_MODRM_RM_SIB) || 
            (IR_MODRM_MOD_IS_REG_CNST(ir) && IR_MODRM_RM(ir) == IRC_MODRM_RM_SIB))
            code[ex_code->ip++] = IR_SIB(ir);

        if ((IR_CMD_B1_IS_MEM(ir) && IR_ARG_IS_MEM_CNST(ir))
            || IR_MODRM_MOD_IS_REG_CNST(ir))
            cnst_ind = 1;
    }

    if (cnst_ind == 1)
    { 
        memmove(&code[ex_code->ip], &IR_CNST64(ir), sizeof(int32_t));
        ex_code->ip += 4;
    }
    
    else if (cnst_ind == 2)
    {
        memmove(&code[ex_code->ip], &IR_CNST64(ir), sizeof(int64_t));
        ex_code->ip += 8;
    }

    return SUCCESS;
}

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


int CallExCode(ExCode *ex_code)
{
    ERR_CHK(ex_code          == NULL, ERR_NULL_PTR);
    ERR_CHK(ex_code->buf     == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(ex_code->buf_len == 0,    ERR_NULL_BUF_LEN);

    __asm__ ("call %0\n\t" :: "r" (ex_code->buf));

    return SUCCESS;
}


// int factorial(int n)
// {
//     __asm__ 
//     ( 
//         "mov    rdi, rax"
//         "movabs rax,0x7fd7ff691110"
//         "call   rax"
//         "push   rax"
//         "mov    rax, rdi"
//         "mov    rdi, QWORD PTR [rsp]"
//         "pop    rax"
//         "push   rdi"
//         "pop    rax"
//         "push   0x1"
//         "pop    rbx"
//         "push   rax"
//         "push   0x0"
//         "pop    rsi"
//         "pop    rdi"
//         "cmp    rdi, rsi"
//         "jb     0xad"
//         "push   rax"
//         "push   0x1"
//         "pop    rsi"
//         "pop    rdi"
//         "cmp    rdi, rsi"
//         "jbe    0xb7"
//         "call   0x77"
//         "movabs rdi, 0x560df44749b9"
//         "pop    rsi"
//         "push   rax"
//         "movabs rax, 0x7fd7ff68f770"
//         "call   rax"
//         "pop    rax"
//         "ret"
//         "push   rbx"
//         "push   rax"
//         "push   0x1"
//         "pop    rsi"
//         "pop    rdi"
//         "cmp    rdi, rsi"
//         "je     0x94"
//         "pop    rbx"
//         "call   0x95"
//         "call   0x77"
//         "ret"
//         "push   rbx"
//         "push   rax"
//         "pop    rsi"
//         "pop    rdi"
//         "imul   rdi, rsi"
//         "push   rdi"
//         "pop    rbx"
//         "push   rax"
//         "push   0x1"
//         "pop    rsi"
//         "pop    rdi"
//         "sub    rdi, rsi"
//         "push   rdi"
//         "pop    rax"
//         "ret"
//         "push   0x0"
//         "jmp    0x5d"
//         "push   0x1"
//         "jmp    0x5d"
//         "ret"
//     )
// }