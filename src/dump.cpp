
#include "../include/dump.h"

static const char   *BCODE_LOG_PATH = "logs/bcode_log.txt";
static const char      *IR_LOG_PATH = "logs/ir_log.txt";
static const char *ADDRTBL_LOG_PATH = "logs/addrtbl_log.txt";
static const char *EX_CODE_LOG_PATH = "logs/ex_code_log.txt";

static int PrintBCodeArg(BCode *bcode, FILE *log_f);

int DisAsmBCode(BCode *bcode)
{
    ERR_CHK(bcode          == NULL, ERR_NULL_PTR);
    ERR_CHK(bcode->buf     == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(bcode->buf_len == 0,    ERR_NULL_BUF_LEN);

    FILE *log_f = fopen(BCODE_LOG_PATH, "a");
    ERR_CHK(log_f == NULL, ERR_FOPEN);

    int32_t *code = bcode->buf;
    uint32_t old_ip = bcode->ip;

    bcode->ip = 0;
    while(bcode->ip < bcode->buf_len)
    {
        switch(MSK16(code[bcode->ip]))
        {
            #define DEF_CMD(name, num, arg, cpu_code)                                   \
                        case BCODE_##name :   fprintf(log_f,"[%d]: " #name, bcode->ip); \
                                                if (arg)                                \
                                                {                                       \
                                                    fprintf(log_f, " ");                \
                                                    _err = PrintBCodeArg(bcode, log_f); \
                                                    ERR_CHK(_err, ERR_PRNT_BCODE_ARG);  \
                                                }                                       \
                                                break;

            #include "../proc/cmd.h"

            #undef DEF_CMD

            default : printf(" # DisAsmBCode(): ERROR: WRONG_BCODE_CMD = %d\n", MSK16(code[bcode->ip]));
                      _err = fclose(log_f);
                      ERR_CHK(_err, ERR_FCLOSE);
                      return ERR_BCODE_SYNTAX;
                      break;
        }

        fprintf(log_f, "\n");
        bcode->ip++;
    }

    bcode->ip = old_ip;

    _err = fclose(log_f);
    ERR_CHK(_err, ERR_FCLOSE);

    return SUCCESS;
}

static int PrintBCodeArg(BCode *bcode, FILE *log_f)
{
    ERR_CHK(bcode          == NULL, ERR_NULL_PTR);
    ERR_CHK(bcode->buf     == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(bcode->buf_len == 0,    ERR_NULL_BUF_LEN);
    ERR_CHK(log_f          == NULL, ERR_NULL_PTR);

    int32_t cmd = bcode->buf[bcode->ip];

    if (cmd & BCODE_MEM)
        fprintf(log_f, "[");

    if (cmd & BCODE_CNST)
        fprintf(log_f, "%d", bcode->buf[++bcode->ip]);

    if ((cmd & BCODE_CNST) && (cmd & BCODE_REG))
         fprintf(log_f, "+");

    if (cmd & BCODE_REG)
    {
        bcode->ip++;

        switch (bcode->buf[bcode->ip])
        {
            case BCODE_REG_RAX: fprintf(log_f, "rax");
                          break;
            case BCODE_REG_RBX: fprintf(log_f, "rbx");
                          break;
            case BCODE_REG_RCX: fprintf(log_f, "rcx");
                          break;
            case BCODE_REG_RDX: fprintf(log_f, "rdx");
                          break;

            default: return ERR_WRONG_REG;
                     break;
        }
    }

    if (cmd & BCODE_MEM)
        fprintf(log_f, "]");

    return SUCCESS;
}


int DumpIR(JitIR *ir)
{
    ERR_CHK(ir          == NULL, ERR_NULL_PTR);
    ERR_CHK(ir->buf     == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(ir->buf_len == 0,    ERR_NULL_BUF_LEN);

    FILE *log_f = fopen(IR_LOG_PATH, "a");
    ERR_CHK(log_f == NULL, ERR_FOPEN);

    IRitm *code = ir->buf;
    uint32_t old_ip = ir->ip; 

    ir->ip = 0;
    while(ir->ip < ir->buf_len)
    {
        int8_t cmdb1 = code[ir->ip].cmd.b1;

        switch(cmdb1)
        {
            #define IR_CMD(name, prefix, ModRMbyte, constant)                                       \
                        case IRC_##name : {                                                         \
                                int prfx = prefix;                                                  \
                                int modrm = ModRMbyte;                                              \
                                int cnst = constant;                                                \
                                fprintf(log_f, "[%d]: "#name"(%d) ModRm = %x, SIB = %x:\n", ir->ip, \
                                        IR_LEN(ir), MSK_HEXB(IR_MODRM(ir)), MSK_HEXB(IR_SIB(ir)));  \
                                if (IR_CMD_B1(ir) == IRC_TWO_BYTE)                                  \
                                {                                                                   \
                                    switch(IR_CMD_B2(ir))                                           \
                                    {                                                               \
                                        case IRC_JB:    [[fallthrough]]                             \
                                        case IRC_JBE:   [[fallthrough]]                             \
                                        case IRC_JA:    [[fallthrough]]                             \
                                        case IRC_JAE:   [[fallthrough]]                             \
                                        case IRC_JE:    [[fallthrough]]                             \
                                        case IRC_JNE:   cnst = 1;                                   \
                                                        break;                                      \
                                        case IRC_IMUL:  prfx = 1;                                   \
                                                        modrm = 1;                                  \
                                                        break;                                      \
                                        default: printf(" # DisAsmIR(%d): ERROR: WRONG_IR_TWOB_CMDB1 = %x. \n",\
                                                            ir->ip, code[ir->ip].cmd.b1);           \
                                                _err = fclose(log_f);                               \
                                                ERR_CHK(_err, ERR_FCLOSE);                          \
                                                return ERR_IR_SYNTAX;                               \
                                                break;                                              \
                                    }                                                               \
                                }                                                                   \
                                if (prfx)                                                           \
                                    fprintf(log_f, "%x ", MSK_HEXB(IR_PRFX(ir)));                   \
                                fprintf(log_f, "%x ", MSK_HEXB(IR_CMD_B1(ir)));                     \
                                if (IR_CMD_B1(ir) == IRC_TWO_BYTE)                                  \
                                    fprintf(log_f, "%x ", MSK_HEXB(IR_CMD_B2(ir)));                 \
                                if (modrm)                                                          \
                                {                                                                   \
                                    fprintf(log_f, "%x ", MSK_HEXB(IR_MODRM(ir)));                  \
                                    if (IR_MODRM_MOD(ir) == IRC_MODRM_MOD_00 &&                     \
                                        IR_MODRM_RM(ir) == IRC_MODRM_RM_SIB)                        \
                                        fprintf(log_f, "%x ", MSK_HEXB(IR_SIB(ir)));                \
                                    if (IR_CMD_B1_IS_MEM(ir) &&                                     \
                                        (IR_ARG_IS_MEM_CNST(ir) || IR_MODRM_MOD_IS_REG_CNST(ir)))   \
                                        fprintf(log_f, "%x ", IR_CNST32(ir));                       \
                                }                                                                   \
                                if (cnst == 1)                                                      \
                                    fprintf(log_f, "%x ", IR_CNST32(ir));                           \
                                else if (cnst == 2)                                                 \
                                    fprintf(log_f, "%lx ", IR_CNST64(ir));                          \
                                break; }

            #include "../include/ir_cmd.h"

            #undef IR_CMD

            default : {printf(" # DisAsmIR(%d): ERROR: WRONG_IR_CMDB1 = %x. \n", ir->ip, code[ir->ip].cmd.b1);
                      _err = fclose(log_f);
                      ERR_CHK(_err, ERR_FCLOSE);
                      return ERR_IR_SYNTAX;
                      break;}
        }

        fprintf(log_f, "\n\n");
        ir->ip++;
    }

    ir->ip = old_ip;

    _err = fclose(log_f);
    ERR_CHK(_err, ERR_FCLOSE);

    return SUCCESS;
}


int DumpExCode(ExCode *ex_code)
{
    ERR_CHK(ex_code          == NULL, ERR_NULL_PTR);
    ERR_CHK(ex_code->buf     == NULL, ERR_NULL_BUF_PTR);
    ERR_CHK(ex_code->buf_len == 0,    ERR_NULL_BUF_LEN);

    FILE *log_f = fopen(EX_CODE_LOG_PATH, "a");
    ERR_CHK(log_f == NULL, ERR_FOPEN);

    for (int i = 0; i < ex_code->buf_len; i++)
        fprintf(log_f, "%x ", MSK_HEXB(ex_code->buf[i]));

    _err = fclose(log_f);
    ERR_CHK(_err, ERR_FCLOSE);

    return SUCCESS;
}


int DumpAddrTbl(AddrTbl *addr_tbl)
{
    ERR_CHK(addr_tbl           == NULL, ERR_NULL_PTR);
    ERR_CHK(addr_tbl->instr_ip == NULL, ERR_NULL_PTR);
    ERR_CHK(addr_tbl->jmp_addr == NULL, ERR_NULL_PTR);

    FILE *log_f = fopen(ADDRTBL_LOG_PATH, "a");
    ERR_CHK(log_f == NULL, ERR_FOPEN);

    fprintf(log_f, "Address Table (len = %u):\n", addr_tbl->len);
    fprintf(log_f, "  i  \tinstr_ip\tjmp_addr\n");
    for (uint32_t i = 0; i < addr_tbl->len; i++)
        fprintf(log_f, "[%-3u]\t%-8u\t%d(%x)\n", i, addr_tbl->instr_ip[i], 
                        addr_tbl->jmp_addr[i], addr_tbl->jmp_addr[i]);
    fprintf(log_f, "\n");

    _err = fclose(log_f);
    ERR_CHK(_err, ERR_FCLOSE);

    return SUCCESS;
}