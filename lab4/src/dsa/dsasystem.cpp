#include "dsasystem.h"

namespace helpers {
    bool testFermat(const dsa::int256 &q, const int iterations = 20) {
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

    bool testFermat(const dsa::int1024 &p, const int iterations = 20) {
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

    int bitLength(const dsa::int1024 &n) {
        return msb(n) + 1;
    }

} // namespace helpers

namespace dsa {

    // struct DSACryptosystem::Pimpl {
    //     explicit Pimpl(const int &keyLength, const std::string &password, bool generateByPassword = true) {};
    //     ~Pimpl() {};
    //
    // };

    void DigitalSignatureFormScheme::generateQ() {
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

    void DigitalSignatureFormScheme::findP() {
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

    void DigitalSignatureFormScheme::findG() {
        if (!m_p)
            throw std::runtime_error("P is not generated");


    }
}   // namespace dsa