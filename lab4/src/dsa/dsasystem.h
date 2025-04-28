#pragma once
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random.hpp>
#include <random>
#include "md5hash.h"

namespace dsa {
using int1024 = boost::multiprecision::uint1024_t ;
using int256 = boost::multiprecision::uint256_t ;

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
    explicit DigitalSignatureValidateScheme(const int256 &q, const int1024 &p, const int &L, const int1024 &g);
    int1024 m_g;
    int256 m_q;
    int1024 m_p;
    int1024 m_k;
    int1024 m_r;
    int1024 m_s;
    int1024 m_secretKey;
    const int m_hashLength {0};
    std::pair<int1024, int1024> m_signature {m_r, m_s};
    int1024 chooseK(const int256 &q) const;

    int1024 calculateR();
    int256 calculateSecretKey() const;
    void formPair();
};

class DSACryptosystem
{
public:
    explicit DSACryptosystem(const int &keyLength, const std::string &password, bool generateByPassword = true)
        : m_keyLength(keyLength), m_password(password),
          m_formScheme(new DigitalSignatureFormScheme(m_password)),
          m_validateScheme(new DigitalSignatureValidateScheme(m_formScheme->m_q, m_formScheme->m_p, 1024, m_formScheme->m_g)) {};

    ~DSACryptosystem() = default;
    void makeSignature();
    void validateSignature();

private:
    // struct Pimpl;
    // std::unique_ptr<Pimpl> m_d;
    DigitalSignatureFormScheme *m_formScheme {nullptr};
    DigitalSignatureValidateScheme *m_validateScheme {nullptr};
    std::vector<md5::byte> m_openKey;
    std::vector<md5::byte> m_secretKey;

    int m_keyLength {0};
    const std::string m_password {""};
    md5::MD5Hasher m_hasher;
};

}