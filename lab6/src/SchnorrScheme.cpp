#include "SchnorrScheme.h"

#include <utility>

Prover::Prover(const SchemeParams& params)
    : params(params)
{
    boost::random::mt19937 rng;
    boost::random::uniform_int_distribution<cpp_int> dist(1, params.q - 1);
    x = dist(rng);
    y = boost::multiprecision::powm(params.g, x, params.p);
}

const cpp_int& Prover::publicKey() const
{
    return y;
}

std::pair<cpp_int, cpp_int> Prover::generateResponse(const cpp_int &challenge) const
{
    boost::random::mt19937 gen(static_cast<unsigned>(time(nullptr)));
    const boost::random::uniform_int_distribution<cpp_int> dist(1, params.q - 1);
    const cpp_int k = dist(gen);
    cpp_int r = powm(params.g, k, params.p);
    cpp_int s = (k + x * challenge) % params.q;
    return {r,s};
}


Verifier::Verifier(SchemeParams params, cpp_int publicKey)
    : params(std::move(params)),
      publicKey(std::move(publicKey))
{
}

cpp_int Verifier::generateChallenge() const
{
    boost::random::mt19937 gen(static_cast<unsigned>(time(nullptr)));
    const boost::random::uniform_int_distribution<cpp_int> dist(1, params.q - 1);
    return dist(gen);
}

bool Verifier::verify(const cpp_int &r, const cpp_int &s, const cpp_int &challenge) const
{
    // g^s ≡ r * y^c mod p
    const cpp_int left = boost::multiprecision::powm(params.g, s, params.p);
    const cpp_int right = (r * boost::multiprecision::powm(publicKey, challenge, params.p)) % params.p;
    return (left == right);
}

SchemeParams SchnorrScheme::generateParams(const int &level)
{
    SchemeParams params;
    generatePrimes(params, level);
    findGenerator(params);
    return params;
}

inline bool SchnorrScheme::isPrime(const cpp_int &n, boost::random::mt19937 &gen)
{
    return boost::multiprecision::miller_rabin_test(n, 25, gen);
}

inline cpp_int SchnorrScheme::powm(const cpp_int &base, const cpp_int &exp, const cpp_int &mod)
{
    return boost::multiprecision::powm(base, exp, mod);
}

void SchnorrScheme::generatePrimes(SchemeParams &params, int level)
{
    boost::random::mt19937 gen(static_cast<unsigned>(time(nullptr)));

    params.q = generatePrime(gen, level / 2);

    do {
        params.p = 2 * params.q + 1;
    } while (!isPrime(params.p, gen));
}

void SchnorrScheme::findGenerator(SchemeParams &params)
{
    boost::random::mt19937 gen(static_cast<unsigned>(time(nullptr)));
    boost::random::uniform_int_distribution<cpp_int> dist(2, params.p - 1);

    do {
        params.g = dist(gen);
    } while (boost::multiprecision::powm(params.g, params.q, params.p) != 1);
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
