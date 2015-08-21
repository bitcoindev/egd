#include"desecb3crption.h"
#include<stddef.h>
#include<openssl/des.h>
#include<string.h>
char *desECB3cryption::k= "12345678abcdefgh87654321"; /* 原始密钥 */
bool  desECB3cryption::DESecb3_encrypt(std::vector<unsigned char> &vecDataIn, std::vector<unsigned char> &vecDataOut)
{
    bool bret;
    int data_len;
    int data_rest;
    unsigned char ch;
    unsigned char *src = NULL; /* 补齐后的明文 */
    unsigned char *dst = NULL; /* 解密后的明文 */
    int len;
    unsigned char tmp[8];
    unsigned char in[8];
    unsigned char out[8];
    int key_len;
#define LEN_OF_KEY 24
    unsigned char key[LEN_OF_KEY]; /* 补齐后的密钥 */
    unsigned char block_key[9];
    DES_key_schedule ks,ks2,ks3;
    /* 构造补齐后的密钥 */
    key_len = strlen(k);
    memcpy(key, k, key_len);
    memset(key + key_len, 0x00, LEN_OF_KEY - key_len);
    /* 分析补齐明文所需空间及补齐填充数据 */
    data_len = vecDataIn.size();
    data_rest = data_len % 8;
    len = data_len + (8 - data_rest);
    ch = 8 - data_rest;
    src = (unsigned char *)malloc(len);
    dst = (unsigned char *)malloc(len);
    if (NULL != src && NULL != dst)
    {
        int count;
        int i;
        /* 构造补齐后的加密内容 */
        memset(src, 0, len);
        memcpy(src, &vecDataIn[0], data_len);
        memset(src + data_len, ch, 8 - data_rest);
        /* 密钥置换 */
        memset(block_key, 0, sizeof(block_key));
        memcpy(block_key, key + 0, 8);
        DES_set_key_unchecked((const_DES_cblock*)block_key, &ks);
        memcpy(block_key, key + 8, 8);
        DES_set_key_unchecked((const_DES_cblock*)block_key, &ks2);
        memcpy(block_key, key + 16, 8);
        DES_set_key_unchecked((const_DES_cblock*)block_key, &ks3);
        #ifdef _DEBUG
        printf("before en/decrypt:\n");
        for (i = 0; i < len; i++)
        {
            printf("0x%.2X ", *(src + i));
        }
        printf("\n");
        #endif
        /* 循环加密/解密，每8字节一次 */
        count = len / 8;
        for (i = 0; i < count; i++)
        {
            memset(in, 0, 8);
            memset(out, 0, 8);
            memcpy(in, src + 8 * i, 8);
            /* 加密 */
            DES_ecb3_encrypt((const_DES_cblock*)in, (DES_cblock*)out, &ks, &ks2, &ks3, DES_ENCRYPT);
            memcpy(dst + 8 * i, out, 8);
        }
        vecDataOut.resize(len+sizeof(data_len));
        memcpy(&vecDataOut[0], &data_len, sizeof(data_len));
        memcpy(&vecDataOut[0] +sizeof(data_len), dst, len);
        #ifdef _DEBUG
        printf("after en/decrypt :\n");
        for (i = 0; i < len; i++)
        {
            printf("0x%.2X ", *(dst + i));
        }
        printf("\n\nvecDataOut:\n");

        for (i = 0; i < vecDataOut.size(); i++)
        {
            printf("0x%.2X ", vecDataOut[i]);
        }
        printf("\n\n");
        #endif

        bret = true;
    }
    else
    {
        bret = false;
    }

    if (NULL != src)
    {
        free(src);
        src = NULL;
    }
    if (NULL != dst)
    {
        free(dst);
        dst = NULL;
    }
    return bret;
}

bool  desECB3cryption::DESecb3_decrypt(std::vector<unsigned char> &vecDataIn, std::vector<unsigned char> &vecDataOut)
{
    bool bret;
    int data_len;
    int data_rest;
    unsigned char ch;
    unsigned char *src = NULL; /* 补齐后的明文 */
    unsigned char *dst = NULL; /* 解密后的明文 */
    int len;
    unsigned char tmp[8];
    unsigned char in[8];
    unsigned char out[8];
    int key_len;
#define LEN_OF_KEY 24
    unsigned char key[LEN_OF_KEY]; /* 补齐后的密钥 */
    unsigned char block_key[9];
    DES_key_schedule ks,ks2,ks3;
    /* 构造补齐后的密钥 */
    key_len = strlen(k);
    memcpy(key, k, key_len);
    memset(key + key_len, 0x00, LEN_OF_KEY - key_len);
    /* 分析补齐明文所需空间及补齐填充数据 */
    data_len = vecDataIn.size() - sizeof(data_len);
    data_rest = data_len % 8;
    if(data_rest != 0)
    {
        return false;
    }
    len = data_len;
    //ch = 8 - data_rest;
    src = (unsigned char *)malloc(len);
    dst = (unsigned char *)malloc(len);
    if (NULL != src && NULL != dst)
    {
        int count;
        int i;
        /* 构造补齐后的加密内容 */
        memset(src, 0, len);
        int datalen = *(int *)(&vecDataIn[0] );
        memcpy(src, &vecDataIn[0] + sizeof(data_len), data_len);
        //memset(src + data_len, ch, 8 - data_rest);
        /* 密钥置换 */
        memset(block_key, 0, sizeof(block_key));
        memcpy(block_key, key + 0, 8);
        DES_set_key_unchecked((const_DES_cblock*)block_key, &ks);
        memcpy(block_key, key + 8, 8);
        DES_set_key_unchecked((const_DES_cblock*)block_key, &ks2);
        memcpy(block_key, key + 16, 8);
        DES_set_key_unchecked((const_DES_cblock*)block_key, &ks3);
        #ifdef _DEBUG
        printf("before en/decrypt:\n");
        for (i = 0; i < len; i++)
        {
            printf("0x%.2X ", *(src + i));
        }
        printf("\n");
        #endif
        /* 循环加密/解密，每8字节一次 */
        count = len / 8;
        for (i = 0; i < count; i++)
        {
            memset(in, 0, 8);
            memset(out, 0, 8);
            memcpy(in, src + 8 * i, 8);
            /*解密 */
            DES_ecb3_encrypt((const_DES_cblock*)in, (DES_cblock*)out, &ks, &ks2, &ks3, DES_DECRYPT);
            /* 将解密的内容拷贝到解密后的明文 */
            memcpy(dst + 8 * i, out, 8);
        }
        vecDataOut.resize(datalen);
        memcpy(&vecDataOut[0], dst, datalen);
        #ifdef _DEBUG
        printf("after en/decrypt :\n");
        for (i = 0; i < len; i++)
        {
            printf("0x%.2X ", *(dst + i));
        }
        printf("\n\nvecDataOut:\n");

        for (i = 0; i < vecDataOut.size(); i++)
        {
            printf("0x%.2X ", vecDataOut[i]);
        }
        printf("\n\n");
        #endif
        bret = true;
    }
    else
    {
        bret = false;
    }

    if (NULL != src)
    {
        free(src);
        src = NULL;
    }
    if (NULL != dst)
    {
        free(dst);
        dst = NULL;
    }
    return bret;
}
