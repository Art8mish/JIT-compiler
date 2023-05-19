#ifndef ASSERT_H_INCLUDED
#define ASSERT_H_INCLUDED

#define ASSERT_MODE

#ifdef SOFT_ASSERT
#undef SOFT_ASSERT
#endif

#ifdef ASSERT_MODE

#define SOFT_ASSERT(condition)                                                    \
            do                                                                    \
            {                                                                     \
                if (condition)                                                    \
                    printf("Error in %s = %d; file: %s; num of line: %d \n",      \
                           #condition, condition, __FILE__, __LINE__);            \
            } while(false)

#else
#define SOFT_ASSERT(condition) ;
#endif

#define ERR_CHK(cond, error)                                \
            do                                              \
            {                                               \
                SOFT_ASSERT(cond);                          \
                if (cond)                                   \
                    return error;                           \
            } while(false)
    
#define ERR_CHK_SAFE(cond, code, error)                     \
            do                                              \
            {                                               \
                SOFT_ASSERT(cond);                          \
                if (cond)                                   \
                {                                           \
                    code                                    \
                    return error;                           \
                }                                           \
            } while(false)


#define ERR_CHK_FILE(cond, error, closing_file)             \
            do                                              \
            {                                               \
                SOFT_ASSERT(cond);                          \
                if (cond)                                   \
                {                                           \
                    fclose(closing_file);                   \
                    return error;                           \
                }                                           \
            } while(false)

enum JitErrors
{
    SUCCESS              = 0,
    ERR_NULL_PTR         = 1,
    ERR_NULL_BUF_PTR     = 2,
    ERR_NULL_BUF_LEN     = 3,
    ERR_FOPEN            = 4,
    ERR_FCLOSE           = 5,
    ERR_READ_HEADER      = 6,
    ERR_FREAD            = 7,
    ERR_WRONG_SGNTR      = 8,
    ERR_WRONG_VERS       = 9,
    ERR_CALLOC           = 10,
    ERR_REALLOC          = 11,
    ERR_BCODE_SYNTAX     = 12,
    ERR_IR_SYNTAX        = 13,
    ERR_WRONG_REG        = 14,
    ERR_JITIR_DTOR       = 15,
    ERR_ADDRTBL_CTOR     = 16,
    ERR_ADDRTBL_DTOR     = 17,
    ERR_FILL_ADRTBL      = 18,
    ERR_DUMP             = 19,
    ERR_CALC_RAL_ADDR    = 20,
    ERR_WRONG_BUF_LEN    = 21,
    ERR_TRNSLT_BCODE_ARG = 22,
    ERR_PRNT_IR_ARG      = 23,
    ERR_PRNT_BCODE_ARG   = 24,
    ERR_ASSEMBLE_IR_ARG  = 25,
    ERR_TRANSLT_BCODE_ARG = 26,
};


#define DEF_CMD(name, num, arg, code) \
                ERR_PROC_IR_##name = num + 50,

enum ProcIRErrors
{
    #include "../proc/cmd.h"
};

#undef DEF_CMD

static int32_t _err = 0;

#endif //ASSERT_H_INCLUDED