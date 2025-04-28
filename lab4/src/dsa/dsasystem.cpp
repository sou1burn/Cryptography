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
    DigitalSignatureValidateScheme::DigitalSignatureValidateScheme(const int256 &q, const int1024 &p, const int &L, const int1024 &g)
        : m_q(q), m_p(p), m_hashLength(L), m_g(g) {
        if (m_hashLength < 0 || m_hashLength > 1024)
            throw std::runtime_error("Invalid hash length");
        boost::random::mt19937 gen(std::random_device{}());
        boost::random::uniform_int_distribution<int256> dist(1, m_q - 1);
        m_secretKey = dist(gen);
        m_k = chooseK(m_q);
        m_r = calculateR();
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

        while (true) {
           int1024 p = k * q + 1;

            if (helpers::bitLength(p) > L) break;

            if (helpers::bitLength(p) == L && helpers::testFermat(p)) {
                this->m_p = p;
                break;
            }
            ++k;
        }
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

    inline int1024 DigitalSignatureValidateScheme::chooseK(const int256 &q) const {
        boost::mt19937 gen(std::random_device{}());
        boost::random::uniform_int_distribution<int256> dist(1, m_q - 1);
        return dist(gen);
    }

    inline int1024 DigitalSignatureValidateScheme::calculateR()
    {
        const auto r = boost::multiprecision::powm(m_g, m_k, m_p) % m_q;
        m_r = r;
        return r;
    }

    inline int256 DigitalSignatureValidateScheme::calculateSecretKey() const
    {
        const auto s = (boost::multiprecision::pow(m_k, -1) * m_hashLength +) % m_q;
    }


}   // namespace dsa

namespace helpers {
template <typename T>
T modExp(T base, T exp, const T& mod) {
    T result = 1;
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

template <typename T>
T gcdExtended(const T& a, const T& b, T& x, T& y) {
    if (a == 0) {
        x = 0;
        y = 1;
        return b;
    }
    T x1, y1;
    T g = gcdExtended(b % a, a, x1, y1);
    x = y1 - (b / a) * x1;
    y = x1;
    return g;
}

template <typename T>
T modInverse(const T& a, const T& m) {
    T x, y;
    T g = gcdExtended(a, m, x, y);
    if (g != 1) {
        throw std::runtime_error("modInverse: обратный элемент не существует");
    }
    return (x % m + m) % m;
}
}