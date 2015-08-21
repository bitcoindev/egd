#ifndef DES_ENCRYPT______
#define DES_ENCRYPT______
#include<vector>
class  desECB3cryption
{
    public:
    bool   static DESecb3_encrypt(std::vector<unsigned char> &vecDataIn, std::vector<unsigned char> &vecDataOut);
    bool   static DESecb3_decrypt(std::vector<unsigned char> &vecDataIn, std::vector<unsigned char> &vecDataOut);
    static char *k; /* 原始密钥 */
};

#endif // DES_ENCRYPT_H_INCLUDED
