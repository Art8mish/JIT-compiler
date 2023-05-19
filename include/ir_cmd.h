
#ifndef IR_CMD
#define IR_CMD(cmd, arg, ir_code)
#endif

IR_CMD(PUSH, 1,
{
    _err = _processIR_PUSH(ir, bcode);
    ERR_CHK(_err, ERR_PROC_IR_PUSH);
})

IR_CMD(POP, POP_CODE, 1,
{
    StackPop (&field->stk, &rhs);
    *ptr_arg_val = rhs;
})

IR_CMD(JMP, JMP_CODE, 1,
{
    field->pc = *ptr_arg_val - 1;
})

IR_CMD(JB, JB_CODE, 1,
{
    StackPop (&field->stk, &rhs);
    StackPop (&field->stk, &lhs);
    if (lhs < rhs)
        field->pc = *ptr_arg_val - 1;
})

IR_CMD(JBE, JBE_CODE, 1,
{
    StackPop (&field->stk, &rhs);
    StackPop (&field->stk, &lhs);
    if (lhs <= rhs)
        field->pc = *ptr_arg_val - 1;
})

IR_CMD(JA, JA_CODE, 1,
{
    StackPop (&field->stk, &rhs);
    StackPop (&field->stk, &lhs);
    if (lhs > rhs)
        field->pc = *ptr_arg_val - 1;
})

IR_CMD(JAE, JAE_CODE, 1,
{
    StackPop (&field->stk, &rhs);
    StackPop (&field->stk, &lhs);
    if (lhs >= rhs)
        field->pc = *ptr_arg_val - 1;
})

IR_CMD(JE, JE_CODE, 1,
{
    StackPop (&field->stk, &rhs);
    StackPop (&field->stk, &lhs);
    if (lhs == rhs)
        field->pc = *ptr_arg_val - 1;
})

IR_CMD(JNE, JNE_CODE, 1,
{
    StackPop (&field->stk, &rhs);
    StackPop (&field->stk, &lhs);
    if (lhs != rhs)
        field->pc = *ptr_arg_val - 1;
})

IR_CMD(CALL, CALL_CODE, 1,
{
    StackPush(&field->ret_adr, field->pc + 1);
    field->pc = *ptr_arg_val - 1;
})

IR_CMD(RET, RET_CODE, 0,
{
    StackPop (&field->ret_adr, &rhs);
    field->pc = rhs - 1;
})

IR_CMD(ADD, ADD_CODE, 0,
{
    StackPop (&field->stk, &rhs);
    StackPop (&field->stk, &lhs);
    StackPush(&field->stk,  lhs + rhs);
})

IR_CMD(SUB, SUB_CODE, 0,
{
    StackPop (&field->stk, &rhs);
    StackPop (&field->stk, &lhs);
    StackPush(&field->stk,  lhs - rhs);
})

IR_CMD(MUL, IMUL_CODE, 0,
{
    StackPop (&field->stk, &rhs);
    StackPop (&field->stk, &lhs);
    StackPush(&field->stk,  lhs * rhs);
})

IR_CMD(DIV, IDIV_CODE, 0,
{
    StackPop (&field->stk, &rhs);
    StackPop (&field->stk, &lhs);
    ERR_CHECK(rhs == 0, ERR_DIV_BY_ZERO);
    StackPush(&field->stk,  lhs / rhs);
})

IR_CMD(DUMP, DUMP_CODE, 0,
{
    DumpProcessor(field);
})

IR_CMD(OUT, OUT_CODE, 0,
{
    StackPop (&field->stk, &rhs);
    printf("out: %d\n", rhs);
})

IR_CMD(IN, IN_CODE, 0,
{
    printf("Enter a number: ");
    scanf("%d", &arg_val);
    StackPush(&field->stk, arg_val);
})

IR_CMD(HLT, HLT_CODE, 0,
{
    return 0;
})


