#pragma once
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random.hpp>
#include <random>
#include <boost/multiprecision/miller_rabin.hpp>
#include "md5hash.h"

namespace dsa {
using int512 = boost::multiprecision::uint512_t;
using int1024 = boost::multiprecision::uint1024_t;
using int256 = boost::multiprecision::uint256_t;
using cpp_int = boost::multiprecision::cpp_int;

struct DigitalSignatureFormScheme
{
    explicit DigitalSignatureFormScheme(const std::string &hash);
    cpp_int m_q {};
    cpp_int m_p {};
    cpp_int m_g {};
    const std::string m_hash;
    void generateQ();
    void findP();
    void findG();
};

struct DigitalSignatureValidateScheme
{
    explicit DigitalSignatureValidateScheme(const cpp_int &q, const cpp_int &p, const int &L, const cpp_int &g, const std::string &hash, const bool &byPassword, const std::string &password);
    const int m_hashLength = 256;
    int m_keySize = 1024;
    cpp_int m_g {};
    cpp_int m_q {};
    cpp_int m_p {};
    cpp_int m_k {};
    cpp_int m_r {};
    cpp_int m_s {};

    cpp_int m_secretKey; //x
    cpp_int m_publicKey; //y
    cpp_int m_hash;
    const std::string m_hashString;
    std::pair<cpp_int, cpp_int> m_signature {};
    std::pair<cpp_int, cpp_int> m_keys {};

    const cpp_int &chooseK();
    void calculateR();
    const cpp_int &calculateSecretKey(const bool &byPassword, const std::string &password);
    void sign();
    void generatePublicKey();
    void formPair();
};

class DSACryptosystem
{
public:
    explicit DSACryptosystem(const int &keyLength, const std::string &password, const std::string &message, const bool &generateByPassword = false);
    ~DSACryptosystem() = default;
    bool validateSignature() const;
    const std::pair<cpp_int, cpp_int> &signature() const;
    const std::pair<cpp_int, cpp_int> &keys() const;
    std::pair<std::pair<cpp_int, cpp_int>, std::pair<cpp_int, std::pair<cpp_int, cpp_int>>> generate2SignaturesWithOneK(const std::string &message1, const std::string &message2);
    void attack(const std::string &message1, const std::string &message2);

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