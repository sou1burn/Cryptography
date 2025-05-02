#include "collisionfinder.h"
namespace md5
{
CollisionFinder::CollisionFinder(const int &n) : m_stringCount(n) {};

std::vector<std::string> CollisionFinder::generateStringHashes(const int &n)
{
    auto randomChar = []() -> char {
        constexpr char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 ";
        constexpr size_t maxIndex = (sizeof(charset) - 2);
        return charset[rand() % maxIndex];
    };

    std::vector<std::string> randomStrings;
    for (auto i = 0; i < n; ++i) {
        std::string str(16,0);
        std::generate_n(str.begin(), 16, randomChar);
        randomStrings.push_back(str);
    }
    std::vector<std::string> hashes;
    for (auto &str : randomStrings)
        hashes.push_back(m_hasher.MD5(str));

    return hashes;
}

std::vector<byte> CollisionFinder::sequenceMaker(std::vector<std::string> &hashes, const int bitCount)
{
    std::vector<byte> sequence;
    for (const auto &hash : hashes) {
        std::string binaryString;
        for (const char hexValue : hash) {
            const auto value = (hexValue >= '0' && hexValue <= '9') ? hexValue - '0' :
                         (hexValue >= 'a' && hexValue <= 'z') ? hexValue - 'a' + 10 :
                         (hexValue >= 'A' && hexValue <= 'Z') ? hexValue - 'A' + 10 : 0;
            
            binaryString += std::bitset<4>(value).to_string();
        }

        std::string bitString = binaryString.substr(0, bitCount);

        for (size_t i = 0; i < bitString.size(); i += 8) {
            std::string byteString = bitString.substr(i, 8);
            sequence.push_back(static_cast<uint8_t>(std::bitset<8>(byteString).to_ulong()));
        }
    }

    return sequence;
}

void CollisionFinder::collisionPower(std::vector<std::string> &hashes, const int bitCount)
{
    const auto sequence = sequenceMaker(hashes, bitCount);

    for (size_t i = 0; i < sequence.size(); ++i) {
        for (size_t j = i + 1; j < sequence.size(); ++j) {
            if (sequence[i] == sequence[j])
                m_collisionPowers.push_back(j - i);
        }
    }
    m_collisionPowers.push_back(INT32_MAX);
}

void CollisionFinder::makeCsv()
{
    std::ofstream csvFile("experiment.csv");

    if (!csvFile.is_open()) {
        std::cerr << "Error while opening a file\n";
        return;
    }
    auto bitCount = 8;
    csvFile << "bitCount,Power\n";
    for (const auto &power : m_collisionPowers) {
        if (power == INT32_MAX) {
            csvFile << bitCount << ",\n";
            bitCount +=2;
            continue;
        }
        
        csvFile << bitCount <<"," << power << "\n";
    }
    csvFile.close();
}

void CollisionFinder::findCollision() 
{
    auto hashes = generateStringHashes(m_stringCount);

    for (auto bitCount = 8; bitCount <= 16; bitCount += 2) {
        collisionPower(hashes, bitCount);
        makeCsv();
    }
    std::cout << "\nSuccess!\n";
}
}