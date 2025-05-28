#include "dsasystem.h"

static constexpr auto N = 160;
static constexpr auto L = 1024;

// сравнить хэши сообщения и пароля
// доп 9
//Cценарий атаки
//
//Противник не знает значения k, но он получил две подписи, при создании которых использовалось одно и то же значение k.
//
//Противник знает:
//
//r= (g^kmodp)modq,
//
//s1 = (k^-1 (H(m1) + xr)) mod q,
//
//s2 = (k^-1 (H(m2) + xr)) mod q,
//
//m1,m2.
//
//Противник производит следующие действия.
//
//s1 – s2 = k-1 (H(m1) – H(m2)) mod q (1)
//
//из уравнения (1) вычисляет k^-1modq
//
//зная k^-1modq, вычисляет k
//
//когда k известно, можно произвести те же вычисления, что и в первом сценарии

namespace helpers {

bool testFermat(const dsa::int256 &q, const int iterations = 5)
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

bool testFermat(const dsa::int1024 &p, const int iterations = 5)
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

inline int bitLength(const dsa::int1024 &n)
{
    return boost::multiprecision::msb(n) + 1;
}

dsa::cpp_int modExp(dsa::cpp_int base, dsa::cpp_int exp, const dsa::cpp_int& mod)
{
    dsa::cpp_int result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1)
            result = (result * base) % mod;

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
    if (g != 1)
        throw std::runtime_error("modInverse: обратный элемент не существует");

    return (x % m + m) % m;
}

dsa::int256 hexStringToInt256(const std::string& hexStr)
{
    dsa::int256 result("0x" + hexStr);
    return result;
}

std::string int256ToHexString(const dsa::int256& num)
{
    std::stringstream ss;
    ss << std::hex << num;
    return ss.str();
}

bool isPrime(const dsa::int256 &n, int iterations = 5)
{
    if (n <= 1) return false;
    return boost::multiprecision::miller_rabin_test(n, iterations);
}

bool isPrime(const dsa::int1024 &n, int iterations = 5)
{
    if (n <= 1) return false;
    return boost::multiprecision::miller_rabin_test(n, iterations);
}

bool validateDSAParameters(
            const dsa::int1024& p,
            const dsa::int1024& q,
            const dsa::int1024& g,
            const dsa::int1024& x,
            const dsa::int1024& y)
{
    if (!helpers::isPrime(q)) {
        std::cerr << "q is not prime.\n";
        return false;
    }

    if (!helpers::isPrime(p)) {
        std::cerr << "p is not prime.\n";
        return false;
    }

    if (helpers::bitLength(p) % 64 != 0 || helpers::bitLength(p) < 512) {
        std::cerr << "p has invalid bit length.\n";
        return false;
    }

    if (helpers::bitLength(q) < 160 || helpers::bitLength(q) > 256) {
        std::cerr << "q has invalid bit length.\n";
        return false;
    }

    if ((p - 1) % q != 0) {
        std::cerr << "q does not divide p - 1.\n";
        return false;
    }

    if (g <= 1 || g >= p) {
        std::cerr << "g is out of valid range.\n";
        return false;
    }
    if (boost::multiprecision::powm(g, q, p) != 1) {
        std::cerr << "g^q mod p != 1 (g is not a valid generator).\n";
        return false;
    }

    if (x <= 0 || x >= q) {
        std::cerr << "x is out of range.\n";
        return false;
    }

    if (boost::multiprecision::powm(g, x, p) != y) {
        std::cerr << "y != g^x mod p.\n";
        return false;
    }

    return true;
}
}// namespace helpers

namespace dsa {

DSACryptosystem::DSACryptosystem(const int &keyLength, const std::string &password, const std::string &message, const bool &generateByPassword /*= false*/)
{
    m_keyLength = keyLength;
    m_password = password;
    m_message = message;
    m_hash = m_hasher.MD5(message);
    m_formScheme = new DigitalSignatureFormScheme(m_hash);
    m_validateScheme = new DigitalSignatureValidateScheme(m_formScheme->m_q,
                                                          m_formScheme->m_p,
                                                          keyLength,
                                                          m_formScheme->m_g,
                                                          m_hash,
                                                          generateByPassword,
                                                          m_hasher.MD5(password));
}

DigitalSignatureFormScheme::DigitalSignatureFormScheme(const std::string &hash)
    : m_hash(hash)
{
    generateQ();
    findP();
    findG();
}

DigitalSignatureValidateScheme::DigitalSignatureValidateScheme(const int256 &q, const int1024 &p, const int &L, const int1024 &g, const std::string &hash, const bool &byPassword, const std::string &password)
    : m_keySize(L), m_g(g), m_q(q), m_p(p), m_hashString(hash)
{
    int256 full_hash = helpers::hexStringToInt256(m_hashString);
    int256 adapted_hash = (full_hash << 32) | (full_hash >> 96);
    m_hash = adapted_hash % m_q;
    calculateSecretKey(byPassword, password);
    generatePublicKey();
    sign();
    formPair();
}

void DigitalSignatureFormScheme::generateQ()
{
    boost::random::mt19937 gen(std::random_device{}());
    boost::random::independent_bits_engine<boost::random::mt19937, 256, int256> randBits(gen);

    int256 q;
    do {
        q = randBits();
        q >>= (256 - N);
        q |= (int256(1) << (N - 1));
        q |= 1;
    } while (!helpers::isPrime(q));

    this->m_q = q;
}

void DigitalSignatureFormScheme::findP() {
    if (!m_q)
        throw std::runtime_error("Q is not generated");

    auto found = false;
    boost::random::mt19937 gen(std::random_device{}());
    boost::random::uniform_int_distribution<int1024> dist(1, (int1024(1) << (L - helpers::bitLength(m_q))) - 1);
    while (true) {
        int1024 k = dist(gen);
        if (k < 2) continue;

        int1024 p = k * m_q + 1;

        if (helpers::bitLength(p) != L || helpers::bitLength(p) % 64 != 0)
            continue;

        if (helpers::isPrime(p)) {
            this->m_p = p;
            found = true;
            break;
        }
    }

    if (!found)
        throw std::runtime_error("Failed to find p with given L = 1024 and q");
}

void DigitalSignatureFormScheme::findG()
{
    if (!m_p || !m_q)
        throw std::runtime_error("P or Q is not generated");

    if ((m_p - 1) % m_q != 0)
        throw std::runtime_error("q does not divide p - 1");

    const int1024 exp = (m_p - 1) / m_q;
    boost::random::mt19937 gen(std::random_device{}());
    const boost::random::uniform_int_distribution<int1024> dist(2, m_p - 2); // h ∈ (2, p-2)
    while (true) {
        int1024 h = dist(gen);
        int1024 g = boost::multiprecision::powm(h, exp, m_p);
        if (g > 1) {
            this->m_g = g;
            break;
        }
    }
}

void DigitalSignatureValidateScheme::chooseK()
{
    std::random_device rd{};
    boost::random::mt19937 gen{rd()};

    boost::random::uniform_int_distribution<int256> dist(1, m_q - 1);
    m_k = dist(gen);
}

void DigitalSignatureValidateScheme::calculateR()
{
    const auto tmp = helpers::modExp(m_g, m_k, m_p);//boost::multiprecision::powm(m_g, m_k, m_p);
    m_r = int256(tmp) % m_q;
}

void DigitalSignatureValidateScheme::calculateSecretKey(const bool &byPassword, const std::string &password)
{
    if (byPassword) {
        const int256 passwordHash = helpers::hexStringToInt256(password);
        int256 secretKey = (passwordHash % m_q);
        if (secretKey == 0)
            secretKey = 1;
        m_secretKey = secretKey;
    }
    boost::mt19937 gen(std::random_device{}());
    boost::random::uniform_int_distribution<int256> dist(1, m_q - 1);
    m_secretKey = dist(gen);
}

void DigitalSignatureValidateScheme::generatePublicKey()
{
    m_publicKey = int1024(boost::multiprecision::powm(m_g, static_cast<int1024>(m_secretKey), m_p)); //(helpers::modExp(m_g, m_secretKey, m_p));
}

void DigitalSignatureValidateScheme::sign()
{
    std::cout << "[SIGN] q = " << m_q << "\n";
    std::cout << "[SIGN] p = " << m_p << "\n";
    std::cout << "[SIGN] g = " << m_g << "\n";
    std::cout << "[SIGN] private key x = " << m_secretKey << "\n";
    std::cout << "[SIGN] hash H(m) = " << m_hash << "\n\n";

    // Используем int512 для всех промежуточных вычислений
    using dsa::int512;

    do {
        // Генерируем k и r пока r ≠ 0
        do {
            chooseK();
            std::cout << "[SIGN] chosen k = " << m_k << "\n";
            calculateR();
            std::cout << "[SIGN] computed r = " << m_r << "\n";
        } while (m_r == 0);

        const auto kInverse = helpers::modInverse(m_k, m_q);

        const int512 term1 = (int512(m_hash) + int512(m_secretKey) * m_r) % int512(m_q);

        auto s_val = int512((kInverse * term1) % m_q);

        if (s_val < 0)
            s_val += int512(m_q);

        m_s = static_cast<int256>(s_val);

    } while (m_s == 0);

    std::cout << "[SIGN] signature pair (r, s) = ("
              << m_r << ", " << m_s << ")\n"
              << "Len pair: " << helpers::bitLength(m_r) + helpers::bitLength(m_s)
              << " vs 2*N " << 2 * N << "\n\n";
}

void DigitalSignatureValidateScheme::formPair()
{
    m_signature = std::make_pair(m_r, m_s);
    m_keys = std::make_pair(m_secretKey, m_publicKey);
}

bool DSACryptosystem::validateSignature() const
{
    const auto &r = m_validateScheme->m_r;
    const auto &s = m_validateScheme->m_s;
    const auto &q = m_validateScheme->m_q;
    const auto &p = m_validateScheme->m_p;
    const auto &g = m_validateScheme->m_g;
    const auto &y = m_validateScheme->m_publicKey;
    auto hashOrig = helpers::hexStringToInt256(m_hash);
    hashOrig = (hashOrig << 32) | (hashOrig >> 96);
    hashOrig = (hashOrig % q);
    const auto &hashVal  = m_validateScheme->m_hash;

    const auto valid = helpers::validateDSAParameters(p, q, g, m_validateScheme->m_secretKey, y);
    if (valid)
        std::cout <<"[VERIFY] DSA parameters are valid\n";
    else
        std::cout << "[VERIFY] DSA parameters are invalid\n";

    std::cout << "[VERIFY] r = " << r
              << "  (should be 1 ≤ r < q)\n";
    std::cout << "[VERIFY] s = " << s
              << "  (should be 1 ≤ s < q)\n";
    if (r <= 0 || r >= q || s <= 0 || s >= q) {
        std::cout << "[VERIFY] Range check failed\n";
        return false;
    }
    if (r == boost::multiprecision::powm(g, static_cast<int1024>(m_validateScheme->m_k), p) % q)
        std::cout << "[VERIFY] r = ok \n";
    else
        std::cout << "[VERIFY] r = not ok \n";

    std::cout << "[VERIFY] Range check passed\n\n";

    std::cout << "[VERIFY] original H(m) mod q = "
              << hashOrig << "\n";
    std::cout << "[VERIFY] stored    H(m)     = "
              << hashVal  << "\n";
    if (hashOrig != hashVal) {
        std::cout << "[VERIFY] Hash mismatch!\n";
        return false;
    }
    std::cout << "[VERIFY] Hash check passed\n\n";

    const auto w  = (helpers::modInverse(s, q));
    const int512 u1 = int512((hashVal) * w % q);
    const int512 u2 = int512((r) * w % q);
    // const auto u1 = (hashVal * w) % q;
    // const auto u2 = (r * w) % q;
    std::cout << "[VERIFY] w  = s⁻¹ mod q = " << w  << "\n";
    std::cout << "[VERIFY] u1 = H(m)·w mod q = " << u1 << "\n";
    std::cout << "[VERIFY] u2 = r·w mod q = " << u2 << "\n\n";

    const auto lhs = boost::multiprecision::powm(g,  static_cast<int1024>(u1), p); //helpers::modExp(g, u1, p);
    const auto rhs = boost::multiprecision::powm(y,  static_cast<int1024>(u2), p); //helpers::modExp(y, u2, p);
    const auto product = (lhs * rhs) % p;
    const auto v = product % q;

    std::cout << "[VERIFY] g^u1 mod p = " << lhs << "\n";
    std::cout << "[VERIFY] y^u2 mod p = " << rhs << "\n";
    std::cout << "[VERIFY] v = " << v << "\n";
    std::cout << "[VERIFY] r = " << r << "\n";
    std::cout << "[VERIFY] comparing v == r ? ";

    const bool ok = v == r;
    std::cout << (ok ? "YES\n" : "NO\n");
    return ok;
}

const std::pair<int256, int256> &DSACryptosystem::signature() const
{
    return m_validateScheme->m_signature;
}

const std::pair<int256, int1024> &DSACryptosystem::keys() const
{
    return m_validateScheme->m_keys;
}

//! атака на систему, когда узнали 2 подписи с одним и тем же k
std::pair<std::pair<int256, int1024>, std::pair<int256, std::pair<int256, int1024>>> DSACryptosystem::generate2SignaturesWithOneK(const std::string &message1, const std::string &message2)
{
    const auto formScheme = new DigitalSignatureFormScheme(m_hasher.MD5(message1));
    const auto validateScheme = new DigitalSignatureValidateScheme(formScheme->m_q,
                                                                   formScheme->m_p,
                                                                   m_keyLength,
                                                                   formScheme->m_g,
                                                                   formScheme->m_hash,
                                                                   false, // byPassword
                                                                   m_hasher.MD5(m_password));
    const auto k = validateScheme->m_k;
    const auto sign = validateScheme->m_signature;
    std::cout << "[ATTACK] k from first signature: " << k << "\n";
    delete formScheme;
    delete validateScheme;
    const auto formScheme2 = new DigitalSignatureFormScheme(m_hasher.MD5(message2));
    const auto validateScheme2 = new DigitalSignatureValidateScheme(formScheme2->m_q,
                                                                    formScheme2->m_p,
                                                                    m_keyLength,
                                                                    formScheme2->m_g,
                                                                    formScheme2->m_hash,
                                                                    false, // byPassword
                                                                    m_hasher.MD5(m_password));
    validateScheme2->m_k = k; // use the same k
    validateScheme2->calculateR();
    validateScheme2->calculateSecretKey(false, "");
    validateScheme2->generatePublicKey();
    validateScheme2->sign();
    validateScheme2->formPair();
    std::cout << "[ATTACK] k from first signature: " << validateScheme2->m_k << "\n";
    const auto signature = validateScheme2->m_signature;
    delete formScheme2;
    delete validateScheme2;

    return {sign, {k, signature}};
}

void DSACryptosystem::attack(const std::string &message1, const std::string &message2)
{
    const auto signatures = generate2SignaturesWithOneK(message1, message2);
    const auto &sign1 = signatures.first;
    const auto &sign2 = signatures.second.second;
    const auto &k = signatures.second.first;
    std::cout << "[ATTACK] Signature 1: (r, s) = (" << sign1.first << ", " << sign1.second << ")\n";
    std::cout << "[ATTACK] Signature 2: (r, s) = (" << sign2.first << ", " << sign2.second << ")\n";
    std::cout << "[ATTACK] k = " << k << "\n";
    // if (sign1.first != sign2.first) {
    //     std::cout << "[ATTACK] r values are different, cannot proceed with attack.\n";
    //     return;
    // }

    auto ds = (sign1.second - sign2.second) % m_validateScheme->m_q;
    if (ds < 0) ds += m_validateScheme->m_q;
    if (ds == 0) {
        std::cout << "[ATTACK] ERROR: s1 - s2 = 0 mod q\n";
        return;
    }
    const auto hash1 = helpers::hexStringToInt256(m_hasher.MD5(message1));
    const auto hash2 = helpers::hexStringToInt256(m_hasher.MD5(message2));
    int256 dh = (hash1 - hash2) % m_validateScheme->m_q;
    if (dh < 0) dh += m_validateScheme->m_q;

    int256 inv_ds = static_cast<dsa::int256>(helpers::modInverse(ds, m_validateScheme->m_q));
    int256 k_recovered = (dh * inv_ds) % m_validateScheme->m_q;

    auto s1 = sign1.second;
    auto inv_r = static_cast<dsa::int256>(helpers::modInverse(m_validateScheme->m_r, m_validateScheme->m_q));
    auto x_recovered = ((s1 * k_recovered - hash1) * inv_r) % m_validateScheme->m_q;
    if (x_recovered < 0) x_recovered += m_validateScheme->m_q;

    // std::cout << "\n[ATTACK] Recovered k: " << k_recovered << "\n";
    // std::cout << "[ATTACK] Original k:  " << k << "\n";
    std::cout << "[ATTACK] Recovered x: " << x_recovered << "\n";
    std::cout << "[ATTACK] Original x:  " << m_validateScheme->m_secretKey << "\n";

    if (k_recovered == k && x_recovered == m_validateScheme->m_secretKey)
        std::cout << "[ATTACK] SUCCESS: Key recovered!\n";
    else
        std::cout << "[ATTACK] FAILED: Key recovery failed\n";
}

}   // namespace dsa
