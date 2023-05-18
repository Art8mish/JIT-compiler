
#ifndef JIT_CMD
#define JIT_CMD(cmd, num, arg, cpu_code)
#endif

JIT_CMD(HLT, HLT_CODE, 0,
{
    return 0;
})

JIT_CMD(PUSH, PUSH_CODE, 1,
{
    StackPush(&field->stk, *ptr_arg_val);
})

JIT_CMD(POP, POP_CODE, 1,
{
    StackPop (&field->stk, &rhs);
    *ptr_arg_val = rhs;
})

JIT_CMD(JMP, JMP_CODE, 1,
{
    field->pc = *ptr_arg_val - 1;
})

JIT_CMD(JB, JB_CODE, 1,
{
    StackPop (&field->stk, &rhs);
    StackPop (&field->stk, &lhs);
    if (lhs < rhs)
        field->pc = *ptr_arg_val - 1;
})

JIT_CMD(JBE, JBE_CODE, 1,
{
    StackPop (&field->stk, &rhs);
    StackPop (&field->stk, &lhs);
    if (lhs <= rhs)
        field->pc = *ptr_arg_val - 1;
})

JIT_CMD(JA, JA_CODE, 1,
{
    StackPop (&field->stk, &rhs);
    StackPop (&field->stk, &lhs);
    if (lhs > rhs)
        field->pc = *ptr_arg_val - 1;
})

JIT_CMD(JAE, JAE_CODE, 1,
{
    StackPop (&field->stk, &rhs);
    StackPop (&field->stk, &lhs);
    if (lhs >= rhs)
        field->pc = *ptr_arg_val - 1;
})

JIT_CMD(JE, JE_CODE, 1,
{
    StackPop (&field->stk, &rhs);
    StackPop (&field->stk, &lhs);
    if (lhs == rhs)
        field->pc = *ptr_arg_val - 1;
})

JIT_CMD(JNE, JNE_CODE, 1,
{
    StackPop (&field->stk, &rhs);
    StackPop (&field->stk, &lhs);
    if (lhs != rhs)
        field->pc = *ptr_arg_val - 1;
})

JIT_CMD(CALL, CALL_CODE, 1,
{
    StackPush(&field->ret_adr, field->pc + 1);
    field->pc = *ptr_arg_val - 1;
})

JIT_CMD(RET, RET_CODE, 0,
{
    StackPop (&field->ret_adr, &rhs);
    field->pc = rhs - 1;
})

JIT_CMD(ADD, ADD_CODE, 0,
{
    StackPop (&field->stk, &rhs);
    StackPop (&field->stk, &lhs);
    StackPush(&field->stk,  lhs + rhs);
})

JIT_CMD(SUB, SUB_CODE, 0,
{
    StackPop (&field->stk, &rhs);
    StackPop (&field->stk, &lhs);
    StackPush(&field->stk,  lhs - rhs);
})

JIT_CMD(MUL, IMUL_CODE, 0,
{
    StackPop (&field->stk, &rhs);
    StackPop (&field->stk, &lhs);
    StackPush(&field->stk,  lhs * rhs);
})

JIT_CMD(DIV, IDIV_CODE, 0,
{
    StackPop (&field->stk, &rhs);
    StackPop (&field->stk, &lhs);
    ERR_CHECK(rhs == 0, ERR_DIV_BY_ZERO);
    StackPush(&field->stk,  lhs / rhs);
})

JIT_CMD(DUMP, DUMP_CODE, 0,
{
    DumpProcessor(field);
})

JIT_CMD(OUT, OUT_CODE, 0,
{
    StackPop (&field->stk, &rhs);
    printf("out: %d\n", rhs);
})

JIT_CMD(IN, IN_CODE, 0,
{
    printf("Enter a number: ");
    scanf("%d", &arg_val);
    StackPush(&field->stk, arg_val);
})

