#include "newaddrtranslator.h"
#include"base58.h"
#include"desecb3crption.h"

newaddrtranslator::newaddrtranslator(std::string &strAddrPrefix)
{
    //ctor
    m_strAddrPrefix = strAddrPrefix;
}

newaddrtranslator::~newaddrtranslator()
{
    //dtor
}

bool newaddrtranslator::generateNewAddr(std::string &strOldAddr, std::string &strNewAddr)
{
    std::vector<unsigned char> vecIn(strOldAddr.begin(), strOldAddr.end());
    std::vector<unsigned char> vecOut;
    bool  bret = desECB3cryption::DESecb3_encrypt(vecIn, vecOut);
    bret ? SetData(&vecOut[0], vecOut.size()): bret = false;
    strNewAddr = m_strAddrPrefix + this->ToString();

//    uint160 id;
//    memcpy(&id, &vecDataIn[0], 20);
//    CKeyID Keyid(id);
//    CBitcoinAddress newaddr(Keyid);
//    strNewAddr = newaddr.ToString();
    return bret;
}

bool   newaddrtranslator::getoldAddr( std::string &strNewAddr, std::string &strOldAddr)
{

    if (m_strAddrPrefix != strNewAddr.substr(0, m_strAddrPrefix.size()))
        return false;
    std::string strAddrBody = strNewAddr.substr(m_strAddrPrefix.size() + 1, strNewAddr.size());
    std::vector<unsigned char> vecIn(strAddrBody.begin(), strAddrBody.end());
    std::vector<unsigned char> vecOut;
    bool  bret = desECB3cryption::DESecb3_decrypt(vecIn, vecOut);
    bret ? bret = SetData(&vecOut[0], vecOut.size()): bret = false;
    bret ? strOldAddr  = this->ToString(), bret = true: bret = false;
    return bret;
}

