#pragma once
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random.hpp>
#include <random>
#include "md5hash.h"

namespace dsa {
using int1024 = boost::multiprecision::uint1024_t;
using int256 = boost::multiprecision::uint256_t;
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
    explicit DigitalSignatureValidateScheme(const int256 &q, const int1024 &p, const int &L, const int1024 &g, const std::string &hash, const bool &byPassword, const std::string &password);
    const int m_hashLength = 256;
    int m_keySize = 1024;
    int1024 m_g;
    int256 m_q;
    int1024 m_p;
    int256 m_k;
    int256 m_r;
    int256 m_s;

    int256 m_secretKey;
    int1024 m_publicKey;
    int256 m_hash;
    const std::string m_hashString;
    std::pair<int256, int256> m_signature {};
    std::pair<int256, int1024> m_keys {};

    int256 chooseK();
    int256 calculateR();
    int256 calculateSecretKey(const bool &byPassword, const std::string &password);

    void generatePublicKey();
    void formPair();
};

class DSACryptosystem
{
public:
    explicit DSACryptosystem(const int &keyLength, const std::string &password, const std::string &message, const bool &generateByPassword = false);
    ~DSACryptosystem() = default;
    bool validateSignature() const;
    const std::pair<int256, int256> &signature() const;
    const std::pair<int256, int1024> &keys() const;

private:
    // struct Pimpl;
    // std::unique_ptr<Pimpl> m_d;

    int m_keyLength {0};
    std::string m_password {};
    std::string m_message {};
    md5::MD5Hasher m_hasher;
    std::string m_hash {};

    DigitalSignatureFormScheme *m_formScheme {};
    DigitalSignatureValidateScheme *m_validateScheme {};
};

}