
#include "../include/jit.h"

static int ReadHeader(FILE *bcode_f, BCode *bcode);

int ReadBCodeF(const char *bcode_f_path, BCode *bcode)
{
    ERR_CHK(bcode_f_path == NULL, ERR_NULL_PTR);
    ERR_CHK(       bcode == NULL, ERR_NULL_PTR);

    FILE *bcode_f = fopen(bcode_f_path, "rb");
    ERR_CHK(bcode_f == NULL, ERR_FOPEN);

    int err = ReadHeader(bcode_f, bcode);
    ERR_CHK_SAFE(err, fclose(bcode_f);, ERR_READ_HEADER);

    bcode->buf = (int32_t*) calloc(bcode->buf_len, sizeof(int32_t));
    ERR_CHK_SAFE(bcode->buf == NULL, fclose(bcode_f);, ERR_CALLOC);

    fread(bcode->buf, sizeof(int32_t), bcode->buf_len, bcode_f);
    err = ferror(bcode_f);
    ERR_CHK_SAFE(err, fclose(bcode_f);, ERR_FREAD);

    _err = fclose(bcode_f);
    ERR_CHK(_err, ERR_FCLOSE);

    return SUCCESS;
}

//--------------------------------------------------------------------------------------------------------------

static int ReadHeader(FILE *bcode_f, BCode *bcode)
{
    ERR_CHK(bcode_f == NULL, ERR_NULL_PTR);
    ERR_CHK(  bcode == NULL, ERR_NULL_PTR);

    uint32_t header[BCODE_HDR_SIZE] = {};

    fread(header, sizeof(uint32_t), BCODE_HDR_SIZE, bcode_f);
    int err = ferror(bcode_f);
    ERR_CHK(err, ERR_FREAD);

    ERR_CHK(strncmp((const char*)header, BCODE_SGNTR, SIZE_OF_SGNTR), ERR_WRONG_SGNTR);

    uint32_t vers = header[1];
    ERR_CHK(vers != SUPPORTED_ASM_VERS, ERR_WRONG_VERS);

    bcode->buf_len = header[2];

    return SUCCESS;
}