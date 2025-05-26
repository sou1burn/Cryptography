#include <utility>
#include <random>
#include <openssl/sha.h>
#include "SchnorrScheme.h"

template <typename T>
static std::string intToHex(const T &value)
{
    std::stringstream ss;
    ss << std::hex << value;
    return ss.str();
}

Prover::Prover(const SchemeParams& params)
    : params(params)
{
    std::random_device rd;
    boost::random::mt19937 rng(rd());
    boost::random::uniform_int_distribution<cpp_int> dist(1, params.q - 1);
    x = dist(rng);
    y = boost::multiprecision::powm(params.g, x, params.p);
}

const cpp_int& Prover::publicKey() const
{
    return y;
}

const cpp_int& Prover::privateKey() const
{
    return x;
}

std::pair<cpp_int, cpp_int> Prover::generateResponse(const cpp_int &challenge) const
{
    std::random_device rd;
    boost::random::mt19937 gen(rd());
    const boost::random::uniform_int_distribution<cpp_int> dist(1, params.q - 1);
    const cpp_int k = dist(gen);
    cpp_int r = powm(params.g, k, params.p);
    cpp_int s = (k + x * challenge) % params.q;
    return {r,s};
}


Verifier::Verifier(SchemeParams params, cpp_int publicKey)
    : params(std::move(params)),
      m_publicKey(std::move(publicKey))
{
}

cpp_int Verifier::generateChallenge() const
{
    boost::random::mt19937 gen(std::random_device{}());
    const boost::random::uniform_int_distribution<cpp_int> dist(1, params.q - 1);
    return dist(gen);
}

bool Verifier::verify(const cpp_int &r, const cpp_int &s, const cpp_int &challenge) const
{
    // g^s ≡ r * y^c mod p
    const cpp_int left = boost::multiprecision::powm(params.g, s, params.p);
    const cpp_int y_pow_c = boost::multiprecision::powm(m_publicKey, challenge, params.p);
    const cpp_int right = (r * y_pow_c) % params.p;
    return (left == right);
}

SchemeParams SchnorrScheme::generateParams(const int &level)
{
    SchemeParams params;
    generatePrimes(params, level);
    if ((params.p - 1) % params.q != 0)
        throw std::runtime_error("Invalid primes: q does not divide p-1");

    findGenerator(params);
    return params;
}

inline bool SchnorrScheme::isPrime(const cpp_int &n, boost::random::mt19937 &gen)
{
    return boost::multiprecision::miller_rabin_test(n, 5, gen);
}

inline cpp_int SchnorrScheme::powm(const cpp_int &base, const cpp_int &exp, const cpp_int &mod)
{
    return boost::multiprecision::powm(base, exp, mod);
}

void SchnorrScheme::generatePrimes(SchemeParams &params, int level)
{
    std::random_device rd;
    boost::random::mt19937 gen(rd());
    do {
        params.q = generatePrime(gen, level / 2);
        params.p = 2 * params.q + 1;
    } while (!isPrime(params.p, gen));
}

void SchnorrScheme::findGenerator(SchemeParams &params)
{
    boost::random::mt19937 gen(std::random_device{}()); //static_cast<unsigned>(time(nullptr))
    boost::random::uniform_int_distribution<cpp_int> dist(2, params.p - 1);

    do {
        params.g = dist(gen);
    } while (params.g == 1 || boost::multiprecision::powm(params.g, params.q, params.p) != 1);
}

cpp_int SchnorrScheme::generatePrime(boost::random::mt19937 &gen, int bits)
{
    cpp_int num;
    do
        num = generateRandomInt(gen, bits);
    while (!isPrime(num, gen));
    return num;
}

cpp_int SchnorrScheme::generateRandomInt(boost::random::mt19937 &gen, int bits)
{
    cpp_int num = 0;
    const boost::random::uniform_int_distribution<uint32_t> dist(0, UINT32_MAX);
    for (auto i = 0; i < bits / 32 + 1; ++i) {
        num = (num << 32) | dist(gen);
    }
    num |= (cpp_int(1) << (bits - 1));
    return num;
}

SchnorrSignature::SchnorrSignature(const std::string &message, const SchemeParams &param, const cpp_int &secret, const cpp_int &publicKey)
    : m_message(message), m_params(param), m_s(secret), m_publicKey(publicKey)
{
    boost::random::mt19937 gen(std::random_device{}());
    boost::random::uniform_int_distribution<cpp_int> dist(2, m_params.q);
    do {
        m_r = dist(gen);
    } while (m_r >= m_params.q);
    m_x = boost::multiprecision::powm(m_params.g, m_r, m_params.p);
}

void SchnorrSignature::sign()
{
    const auto xString = intToHex(m_x);
    const auto toHash = m_message + xString;
    std::cout << "Hashing:   " << toHash << std::endl;
    const auto hash = sha256(toHash);
    m_e = cpp_int("0x" + hash);
    m_y = (m_r + m_s * m_e) % m_params.q;
    m_signature = {m_e, m_y};
}

bool SchnorrSignature::verify() const
{
    // const cpp_int first = boost::multiprecision::powm(m_params.g, m_y, m_params.p);
    // // const cpp_int v = boost::multiprecision::powm(m_params.g, m_publicKey, m_params.p);
    // const cpp_int sec = boost::multiprecision::powm(m_publicKey, m_e, m_params.p);
    // const cpp_int tmp = (first * sec % m_params.p);
    // const auto& x = tmp;
    // const auto xString = intToHex(x);
    // const auto toHash = m_message + xString;
    // const auto hash = sha256(toHash);
    // std::cout << "Verifying: " << toHash << std::endl;
    // const auto e = cpp_int("0x" + hash);
    // std::cout << "Computed e: " << e << ", Expected e: " << m_e << std::endl;
    //
    // return (e == m_e);
    // signature = (e, s)
    const cpp_int &e = m_signature.first;
    const cpp_int &s = m_signature.second;
    const cpp_int &r = m_x;

    // 1) first = g^s mod p
    const cpp_int first = boost::multiprecision::powm(m_params.g, s, m_params.p);

    // 2) sec = publicKey^e mod p
    const cpp_int sec = boost::multiprecision::powm(m_publicKey, e, m_params.p);

    const cpp_int mult = r * sec;
    const cpp_int third  = mult % m_params.p;

    if (first != third) return false;
    const std::string hstr = intToHex(r);
    const cpp_int e2("0x" + sha256(m_message + hstr));
    std::cout << "Verifying: " << m_message + hstr << std::endl;

    return e2 == e;
}

std::string SchnorrSignature::sha256(const std::string &message) const
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    const auto* data = reinterpret_cast<const unsigned char *>(message.c_str());
    SHA256(data, message.size(), hash);
    std::stringstream ss;
    for (auto i = 0; i < SHA256_DIGEST_LENGTH; i++)
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    return ss.str();
}
