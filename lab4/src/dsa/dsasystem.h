#pragma once
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random.hpp>
#include <random>
#include "md5hash.h"

namespace dsa {
using int1024 = boost::multiprecision::uint1024_t ;
using int256 = boost::multiprecision::uint256_t ;
using cpp_int = boost::multiprecision::cpp_int;

struct DigitalSignatureFormScheme
{
    explicit DigitalSignatureFormScheme(const std::string &hash);
    int256 m_q;
    int1024 m_p;
    int1024 m_g;
    const std::string m_hash;
    void generateQ();
    void findP();
    void findG();
};

struct DigitalSignatureValidateScheme
{
    explicit DigitalSignatureValidateScheme(const int256 &q, const int1024 &p, const int &L, const int1024 &g, const std::string &hash);
    int1024 m_g;
    int256 m_q;
    int1024 m_p;
    int1024 m_k;
    int1024 m_r;
    int1024 m_s;
    int1024 m_secretKey;
    int1024 m_publicKey;
    const int m_hashLength {0};
    int256 m_hash;
    const std::string m_hashString;
    std::pair<int1024, int1024> m_signature {};

    int1024 chooseK();
    int1024 calculateR();
    int1024 calculateSecretKey();

    void generatePublicKey();
    void formPair();
};

class DSACryptosystem
{
public:
    explicit DSACryptosystem(const int &keyLength, const std::string &password,const std::string &message, bool generateByPassword = false)
        : m_keyLength(keyLength), m_password(password), m_message(m_hasher.MD5(message)),
          m_formScheme(new DigitalSignatureFormScheme(m_message)),
          m_validateScheme(new DigitalSignatureValidateScheme(m_formScheme->m_q, m_formScheme->m_p, 1024, m_formScheme->m_g, m_formScheme->m_hash)) {};

    ~DSACryptosystem() = default;
    bool validateSignature() const;
    const std::pair<int1024, int1024> &signature() const;

private:
    // struct Pimpl;
    // std::unique_ptr<Pimpl> m_d;

    int m_keyLength {0};
    const std::string m_password {};
    const std::string m_message {};
    md5::MD5Hasher m_hasher;

    DigitalSignatureFormScheme *m_formScheme {};
    DigitalSignatureValidateScheme *m_validateScheme {};
};

}