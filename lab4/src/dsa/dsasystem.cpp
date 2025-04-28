#include "dsasystem.h"

namespace helpers {
bool testFermat(const dsa::int256 &q, const int iterations = 20)
{
    if (q < 4 || q % 2 == 0)
        return false;

    boost::random::mt19937 gen(std::random_device{}());
    const boost::random::uniform_int_distribution<dsa::int256> dist(2, q - 2);

    for (auto i = 0; i < iterations; i++) {
        const auto a = dist(gen);
        if (boost::multiprecision::powm(a, q - 1, q) != 1)
            return false;
    }

    return true;
}

bool testFermat(const dsa::int1024 &p, const int iterations = 20)
{
    if (p < 4 || p % 2 == 0)
        return false;

    boost::random::mt19937 gen(std::random_device{}());
    const boost::random::uniform_int_distribution<dsa::int1024> dist(2, p - 2);

    for (auto i = 0; i < iterations; i++) {
        const auto a = dist(gen);
        if (boost::multiprecision::powm(a, p - 1, p) != 1)
            return false;
    }

    return true;
}

int bitLength(const dsa::int1024 &n)
{
    return msb(n) + 1;
}

dsa::cpp_int modExp(dsa::cpp_int base, dsa::cpp_int exp, const dsa::cpp_int& mod)
{
    dsa::cpp_int result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) {
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        exp >>= 1;
    }
    return result;
}

dsa::cpp_int gcdExtended(const dsa::cpp_int& a, const dsa::cpp_int& b, dsa::cpp_int& x, dsa::cpp_int& y)
{
    if (a == 0) {
        x = 0;
        y = 1;
        return b;
    }
    dsa::cpp_int x1, y1;
    dsa::cpp_int g = gcdExtended(b % a, a, x1, y1);
    x = y1 - (b / a) * x1;
    y = x1;
    return g;
}

dsa::cpp_int modInverse(const dsa::cpp_int& a, const dsa::cpp_int& m)
{
    dsa::cpp_int x, y;
    dsa::cpp_int g = gcdExtended(a, m, x, y);
    if (g != 1) {
        throw std::runtime_error("modInverse: обратный элемент не существует");
    }
    return (x % m + m) % m;
}

dsa::int256 hexStringToInt256(const std::string& hexStr)
{
    dsa::int256 result("0x" + hexStr);
    return result;
}

} // namespace helpers

namespace dsa {

    // struct DSACryptosystem::Pimpl {
    //     explicit Pimpl(const int &keyLength, const std::string &password, bool generateByPassword = true) {};
    //     ~Pimpl() {};
    //
    // };
    DigitalSignatureFormScheme::DigitalSignatureFormScheme(const std::string &hash)
        : m_hash(hash)
    {
        generateQ();
        findP();
        findG();
    }

    DigitalSignatureValidateScheme::DigitalSignatureValidateScheme(const int256 &q, const int1024 &p, const int &L, const int1024 &g, const std::string &hash)
        : m_q(q), m_p(p), m_hashLength(L), m_g(g), m_hashString(hash)
    {
        if (m_hashLength < 0 || m_hashLength > 1024)
            throw std::runtime_error("Invalid hash length");

        m_hash = helpers::hexStringToInt256(m_hashString);
        m_k = chooseK();
        m_r = calculateR();
        m_secretKey = calculateSecretKey();
        generatePublicKey();
        formPair();
    }

    void DigitalSignatureFormScheme::generateQ()
    {
        const auto N = static_cast<int>(m_hash.size() * 8);
        boost::random::mt19937 gen(std::random_device{}());
        boost::random::independent_bits_engine<boost::random::mt19937, 256, int256> randBits(gen);

        int256 q;
        do {
            q = randBits();
            q >>= (256 - N);
            q |= (int256(1) << (N - 1));
            q |= 1;
        } while (!helpers::testFermat(q));

        this->m_q = q;
    }

    void DigitalSignatureFormScheme::findP()
    {
        if (!m_q)
            throw std::runtime_error("Q is not generated");
        const auto L = 1024;
        const auto &q = this->m_q;
        int1024 k = 2;
        bool found = false;
        while (true) {
           int1024 p = k * q + 1;

            if (helpers::bitLength(p) > L) break;

            if (helpers::bitLength(p) == L && helpers::testFermat(p)) {
                this->m_p = p;
                found = true;
                break;
            }
            ++k;
        }
        if (!found)
            throw std::runtime_error("Failed to find p with given L = 1024 and q");
    }

    void DigitalSignatureFormScheme::findG()
    {
        if (!m_p || !m_q)
            throw std::runtime_error("P or Q is not generated");

        if (m_p % m_q != 1)
            throw std::runtime_error("P is not divisible by Q");

        const int1024 exp = (m_p - 1) / m_q;
        boost::random::mt19937 gen(std::random_device{}());
        const boost::random::uniform_int_distribution<int1024> dist(2, m_p - 2); // h ∈ (1, p-1)

        while (true) {
            int1024 h = dist(gen);
            int1024 g = boost::multiprecision::powm(h, exp, m_p);
            if (g != 1) {
                this->m_g = g;
                break;
            }
        }
    }

    inline int1024 DigitalSignatureValidateScheme::chooseK()
    {
        boost::mt19937 gen(std::random_device{}());
        boost::random::uniform_int_distribution<int256> dist(1, m_q - 1);
        m_k = static_cast<int1024>(dist(gen));
        return dist(gen);
    }

    inline int1024 DigitalSignatureValidateScheme::calculateR()
    {
        m_r = boost::multiprecision::powm(m_g, m_k, m_p) % m_q;
        return m_r;
    }

    inline int1024 DigitalSignatureValidateScheme::calculateSecretKey()
    {
        int1024 s;
        do {
            m_k = chooseK();
            calculateR();
            const auto kInverse = helpers::modInverse(m_k, m_q);
            s = static_cast<int1024>(kInverse * (m_hash + m_secretKey * m_r)) % m_q;
        } while (s == 0);
        m_s = s;
        return s;
    }

    inline void DigitalSignatureValidateScheme::formPair()
    {
        m_signature = std::make_pair(m_r, m_s);
    }

    inline void DigitalSignatureValidateScheme::generatePublicKey()
    {
        m_publicKey = boost::multiprecision::powm(m_g, m_secretKey, m_p);
    }

    bool DSACryptosystem::validateSignature() const
    {
        if (m_validateScheme->m_r <= 0 || m_validateScheme->m_r >= m_validateScheme->m_q || m_validateScheme->m_s <= 0 || m_validateScheme->m_s >=m_validateScheme->m_q)
            return false;

        const auto w = static_cast<int1024>(helpers::modInverse(m_validateScheme->m_s, m_validateScheme->m_q));
        const auto u1 = (m_validateScheme->m_hash * w) % m_validateScheme->m_q;
        const auto u2 = (m_validateScheme->m_r * w) % m_validateScheme->m_q;
        const auto v = (boost::multiprecision::powm(m_validateScheme->m_g, u1, m_validateScheme->m_p) *
                      boost::multiprecision::powm(m_validateScheme->m_publicKey, u2, m_validateScheme->m_p)) % m_validateScheme->m_p % m_validateScheme->m_q;
        return v == m_validateScheme->m_r;
    }

}   // namespace dsa
