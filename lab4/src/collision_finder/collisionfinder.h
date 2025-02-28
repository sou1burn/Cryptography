#pragma once
#include <random>
#include <bits/algorithmfwd.h>
#include <bitset>
#include "md5hash.h"
namespace md5
{

class CollisionFinder 
{
public:
    explicit CollisionFinder() = default;
    ~CollisionFinder() = default;
    
    std::vector<std::string> generateStringHashes(int n);
    std::vector<byte> sequenceMaker(std::vector<std::string> &hashes, int bitCount);
    void collisionPower();
    void makeCsv();
private:
    std::vector<std::string> m_hashes;
    std::vector<int> m_collisionPowers;
    // std::vector<int> m_steps;
    MD5Hasher m_hasher;
};
}