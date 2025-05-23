#include "dsasystem.h"
// сравнить хэши сообщения и пароля
// доп 9
//Для каждой новой подписи с помощью DSAтребуется генерировать новое значениеk, а после создания подписи немедленно уничтожать. Если эти требования не выполняются, то противник может вычислить секретный ключ создателя подписи.
//
//Первый сценарий атаки
//
//Противник узнал значение k, которое использовалось при создании подписи. Конкретный способ, который использовал для этого противник, неважен. Возможно, это значениеkне было уничтожено, или противник использовал какие-либо свойства генератора случайных чисел, который сгенерировалk.
//
//Противник знает:
//
//r= (g^k modp)modq,
//
//s = (k^-1 (H(m) + xr)) mod q,
//
//k, m.
//
//Противник вычисляет:
//
//s - k-1*H(m) = k-1rx mod q
//
//т.к. q– простое, то можно найти (k-1*r)-1modq, откуда
//
//x = (s – k-1*H(m))* (k-1*r)-1 mod q.
//
//Второй сценарий атаки
//
//Противник не знает значения k, но он получил две подписи, при создании которых использовалось одно и то же значениеk.
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


static constexpr auto N = 160;
static constexpr auto L = 1024;

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

}// namespace helpers

namespace dsa {

DSACryptosystem::DSACryptosystem(const int &keyLength, const std::string &password,const std::string &message, const bool &generateByPassword /*= false*/)
{
    m_keyLength = keyLength;
    m_password = password;
    m_message = message;
    m_hash = m_hasher.MD5(message);
    m_formScheme = new DigitalSignatureFormScheme(m_hasher.MD5(message));
    m_validateScheme = new DigitalSignatureValidateScheme(m_formScheme->m_q,
                                                          m_formScheme->m_p,
                                                          keyLength,
                                                          m_formScheme->m_g,
                                                          m_formScheme->m_hash,
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
    m_hash = helpers::hexStringToInt256(m_hashString);
    m_secretKey = calculateSecretKey(byPassword, password);
    sign();
    generatePublicKey();
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
    boost::random::uniform_int_distribution<dsa::int1024> dist(1, (dsa::int1024(1) << (L - helpers::bitLength(m_q))) - 1);
    while (true) {
        dsa::int1024 k = dist(gen);
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

    if (m_p % m_q != 1)
        throw std::runtime_error("P is not divisible by Q");

    const int1024 exp = (m_p - 1) / m_q;
    boost::random::mt19937 gen(std::random_device{}());
    const boost::random::uniform_int_distribution<int1024> dist(2, m_p - 1); // h ∈ (1, p-1)

    while (true) {
        int1024 h = dist(gen);
        int1024 g = boost::multiprecision::powm(h, exp, m_p);
        if (g > 1) {
            this->m_g = g;
            break;
        }
    }
}

inline int256 DigitalSignatureValidateScheme::chooseK()
{
    boost::mt19937 gen(std::random_device{}());
    const boost::random::uniform_int_distribution<int256> dist(1, m_q - 1);
    // while (true) {
        m_k = (dist(gen));
        // m_k >>= (256 - N);
        // m_k |= (int256(1) << (N - 1));
        // m_k |= 1;
        // if (m_k > m_q) continue;
        // else break;
    // }
    return m_k;
}

inline int256 DigitalSignatureValidateScheme::calculateR()
{
    const auto tmp = boost::multiprecision::powm(m_g, static_cast<int1024>(m_k), m_p) % m_q;
    m_r = tmp.convert_to<int256>();
    return m_r;
}

int256 DigitalSignatureValidateScheme::calculateSecretKey(const bool &byPassword, const std::string &password)
{
    if (byPassword) {
        const int256 passwordHash = helpers::hexStringToInt256(password);
        int256 secretKey = (passwordHash % m_q);
        if (secretKey == 0)
            secretKey = 1;
        m_secretKey = secretKey;

        return m_secretKey;
    }
    boost::mt19937 gen(std::random_device{}());
    boost::random::uniform_int_distribution<int256> dist(1, m_q - 1);

    m_secretKey = dist(gen);

    return m_secretKey;
}

void DigitalSignatureValidateScheme::sign()
{
    int256 s;
    do {
        m_k = chooseK();
        calculateR();
    } while (m_r == 0);
    do {
        const auto kInverse = helpers::modInverse(m_k, m_q);
        s = static_cast<int256>(kInverse * (m_hash + m_secretKey * m_r)) % m_q;
    } while (s == 0);

    m_s = s;
}


inline void DigitalSignatureValidateScheme::formPair()
{
    m_signature = std::make_pair(m_r, m_s);
    m_keys = std::make_pair(m_secretKey, m_publicKey);
}

inline void DigitalSignatureValidateScheme::generatePublicKey()
{
    m_publicKey = boost::multiprecision::powm(m_g, static_cast<int1024>(m_secretKey), m_p);
}

bool DSACryptosystem::validateSignature() const
{
    if (m_validateScheme->m_r <= 0 || m_validateScheme->m_r >= m_validateScheme->m_q || m_validateScheme->m_s <= 0 || m_validateScheme->m_s >=m_validateScheme->m_q)
        return false;

    // std::cout << "Hash on validation from DSA params: " << m_hash << std::endl;
    // std::cout << "Hash on validation from formScheme: " << m_formScheme->m_hash << std::endl;
    std::cout << "Hash on validation from validationScheme: " << (m_validateScheme->m_hash) << std::endl;
    if (const auto current_hash = helpers::hexStringToInt256(m_hash) % m_validateScheme->m_q; current_hash != m_validateScheme->m_hash) {
        std::cout << "lyalyalya" << std::endl;
    }
    // helpers::int256ToHexString
    const auto w = static_cast<int1024>(helpers::modInverse(m_validateScheme->m_s, m_validateScheme->m_q));
    const auto u1 = m_validateScheme->m_hash * w % m_validateScheme->m_q;
    const auto u2 = m_validateScheme->m_r * w % m_validateScheme->m_q;
    const auto v = ((boost::multiprecision::powm(m_validateScheme->m_g, u1, m_validateScheme->m_p) *
                  boost::multiprecision::powm(m_validateScheme->m_publicKey, u2, m_validateScheme->m_p)) % m_validateScheme->m_p) % m_validateScheme->m_q;

    // const auto v = (pow(m_validateScheme->m_g, static_cast<unsigned>(u1)) * pow(m_validateScheme->m_publicKey, static_cast<unsigned>(u2))) % m_validateScheme->m_p % m_validateScheme->m_q;
    std::cout << " r = " << m_validateScheme->m_r << std::endl;
    std::cout << " v = " << v << std::endl;
    return static_cast<int256>(v) == m_validateScheme->m_r;
}

const std::pair<int256, int256> &DSACryptosystem::signature() const
{
    return m_validateScheme->m_signature;
}

const std::pair<int256, int1024> &DSACryptosystem::keys() const {
    return m_validateScheme->m_keys;
}

}   // namespace dsa
