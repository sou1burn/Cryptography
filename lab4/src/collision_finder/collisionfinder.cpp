#include "collisionfinder.h"
namespace md5
{
std::vector<std::string> CollisionFinder::generateStringHashes(int n)
{
    auto randomChar = []() ->char {
        const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 ";
        const size_t maxIndex = (sizeof(charset) - 1);
        return charset[rand() % maxIndex];
    };
    std::vector<std::string> randomStrings;
    for (auto i = 0; i < n; ++i) {
        std::string str(16,0);
        std::generate_n(str.begin(), 16, randomChar);
        randomStrings.push_back(str);
    }
    std::vector<std::string> hashes;
    for (auto &str : randomStrings) {
        hashes.push_back(m_hasher.MD5(str));
    }

    m_hashes = hashes;
    return hashes;
}

std::vector<byte> CollisionFinder::sequenceMaker(std::vector<std::string> &hashes, int bitCount)
{
    std::vector<byte> sequence;
    for (const auto &hash : hashes) {
        std::string binaryString;
        for (char hexValue : hash) {
            auto value = (hexValue >= '0' && hexValue <= '9') ? hexValue - '0' :
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

void CollisionFinder::collisionPower()
{
    auto sequence = sequenceMaker(m_hashes, 8);

    for (auto i = 0; i < sequence.size(); ++i) {
        for (auto j = 1; j < sequence.size(); ++j) {
            if (sequence[i] == sequence[j]) {
                m_collisionPowers.push_back(j - i);
            }
        }
    }
}

void CollisionFinder::makeCsv()
{

}


}