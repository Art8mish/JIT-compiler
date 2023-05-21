
#include "../include/dump.h"

static const char   *BCODE_LOG_PATH = "logs/bcode_log.txt";
static const char      *IR_LOG_PATH = "logs/ir_log.txt";
static const char *ADDRTBL_LOG_PATH = "logs/addrtbl_log.txt";

static int PrintBCodeArg(BCode *bcode, FILE *log_f);
static int PrintIRArg(JitIR *ir, FILE *log_f);

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
                        case BCODE_##name :   fprintf(log_f, #name);                  \
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



int DisAsmIR(JitIR *ir)
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
        switch(code[ir->ip].cmd.b1)
        {
            #define IR_CMD(name, prefix, ModRMbyte, const)                                      \
                        case IRC_##name :                                                       \
                                fprintf(log_f, #name": \n[%d]: ", ir->ip);                      \
                                if (prefix)                                                     \
                                    fprintf(log_f, "%x ", code[ir->ip].prfx);                   \
                                fprintf(log_f, "%x ", code[ir->ip].cmd.b1);                     \
                                if (code[ir->ip].cmd.b1 == IRC_TWO_BYTE)                        \
                                    fprintf(log_f, "%x ", code[ir->ip].cmd.b2);                 \
                                if (ModRMbyte)                                                  \
                                {                                                               \
                                    fprintf(log_f, "%x ", *((int8_t *)&code[ir->ip].ModRM));    \
                                    if (code[ir->ip].ModRM.rm == IRC_MODRM_RM_SIB)              \
                                        fprintf(log_f, "%x ", *((int8_t *)&code[ir->ip].SIB));  \
                                    if (code[ir->ip].ModRM.mod == IRC_MODRM_MOD_CNST ||         \
                                        code[ir->ip].ModRM.mod == IRC_MODRM_MOD_REG_CNST)       \
                                        fprintf(log_f, "%x ", code[ir->ip].cnst);               \
                                }                                                               \
                                if (const == 1)                                                  \
                                    fprintf(log_f, "%x ", code[ir->ip].cnst);                   \
                                else if (const == 2)                                             \
                                    fprintf(log_f, "%lx ", code[ir->ip].cnst);                  \
                                break;

            #include "../include/ir_cmd.h"

            #undef IR_CMD

            default : printf(" # DisAsmIR(): ERROR: WRONG_IR_CMDB1 = %x. \n", code[ir->ip].cmd.b1);
                      _err = fclose(log_f);
                      ERR_CHK(_err, ERR_FCLOSE);
                      return ERR_IR_SYNTAX;
                      break;
        }

        fprintf(log_f, "\n");
        ir->ip++;
    }

    ir->ip = old_ip;

    _err = fclose(log_f);
    ERR_CHK(_err, ERR_FCLOSE);

    return SUCCESS;
}

// static int PrintIRArg(JitIR *ir, FILE *log_f)
// {
//     ERR_CHK(ir          == NULL, ERR_NULL_PTR);
//     ERR_CHK(ir->buf     == NULL, ERR_NULL_BUF_PTR);
//     ERR_CHK(ir->buf_len == 0,    ERR_NULL_BUF_LEN);
//     ERR_CHK(log_f       == NULL, ERR_NULL_PTR);

//     int8_t mod = ir->buf[ir->ip].mod;

//     if (mod & MOD_MEM_CODE)
//         fprintf(log_f, "[");

//     if (mod & MOD_CNST_CODE)
//         fprintf(log_f, "%d", ir->buf[ir->ip].cnst);

//     if ((mod & MOD_CNST_CODE) && (mod & MOD_REG_CODE))
//          fprintf(log_f, "+");

//     if (mod & MOD_REG_CODE)
//     {
//         switch (ir->buf[ir->ip].reg)
//         {
//             case RAX_CODE: fprintf(log_f, "rax");
//                           break;
//             case RBX_CODE: fprintf(log_f, "rbx");
//                           break;
//             case RCX_CODE: fprintf(log_f, "rcx");
//                           break;
//             case RDX_CODE: fprintf(log_f, "rdx");
//                           break;

//             default: return ERR_WRONG_REG;
//                      break;
//         }
//     }

//     if (mod & MOD_MEM_CODE)
//         fprintf(log_f, "]");

//     return SUCCESS;
// }

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
        fprintf(log_f, "[%-3u]\t%-8u\t%-8u\n", 
                        i, addr_tbl->instr_ip[i], addr_tbl->jmp_addr[i]);
    fprintf(log_f, "\n");

    _err = fclose(log_f);
    ERR_CHK(_err, ERR_FCLOSE);

    return SUCCESS;
}