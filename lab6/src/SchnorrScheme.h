#pragma once
#include <iostream>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random.hpp>
#include <boost/multiprecision/miller_rabin.hpp>

using cpp_int = boost::multiprecision::cpp_int;

struct SchemeParams
{
    cpp_int p;
    cpp_int q;
    cpp_int g;
};

class Prover
{
public:
    explicit Prover(const SchemeParams &params);
    const cpp_int &publicKey() const;
    std::pair<cpp_int, cpp_int> generateResponse(const cpp_int &challenge) const;

private:
    SchemeParams params {};
    cpp_int x; // [1, q-1]
    cpp_int y; // g^x mod p
};

class Verifier
{
public:
    explicit Verifier(SchemeParams params, cpp_int publicKey);
    cpp_int generateChallenge() const;
    bool verify(const cpp_int &r, const cpp_int &s, const cpp_int &challenge) const;
private:
    SchemeParams params {};
    cpp_int publicKey {};
};

class SchnorrScheme {
public:
    static SchemeParams generateParams(const int &level);
private:
    static void generatePrimes(SchemeParams &params, int level);
    static void findGenerator(SchemeParams& params);
    static cpp_int generatePrime(boost::random::mt19937& gen, int bits);
    static cpp_int generateRandomInt(boost::random::mt19937& gen, int bits);
    static bool isPrime(const cpp_int& n, boost::random::mt19937& gen);
    static cpp_int powm(const cpp_int& base, const cpp_int& exp, const cpp_int& mod);
};


