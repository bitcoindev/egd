#ifndef NEWADDRTRANSLATOR_H
#define NEWADDRTRANSLATOR_H
#include"base58.h"

class newaddrtranslator:public CBase58Data
{
public:
    newaddrtranslator(std::string &strAddrPrefix);
    virtual ~newaddrtranslator();

    bool SetData(const void* pdata, size_t nSize)
    {
        bool bret;
        vchData.resize(nSize);
        if (pdata)
        {
            memcpy(&vchData[0], pdata, nSize);
            bret = true;
        }
        else
        {
            bret = false;
        }
        return bret;
    }

    bool   generateNewAddr(std::string &strOldAddr, std::string &strNewAddr);
    bool   getoldAddr( std::string &strNewAddr, std::string &strOldAddr);

protected:
private:
    std::string m_strAddrPrefix;
};

#endif // NEWADDRTRANSLATOR_H
