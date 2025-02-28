#pragma once
#include <random>
#include <bits/algorithmfwd.h>
#include <bitset>
#include <map>
#include <fstream>
#include "md5hash.h"
namespace md5
{

class CollisionFinder 
{
public:
    explicit CollisionFinder(int n);
    ~CollisionFinder() = default;
    
    void findCollision();
private:
    std::vector<byte> sequenceMaker(std::vector<std::string> &hashes, int bitCount);
    std::vector<std::string> generateStringHashes(int n);
    void collisionPower(std::vector<std::string> &hashes, int bitCount);
    void makeCsv();
    std::vector<int> m_collisionPowers;
    MD5Hasher m_hasher;
    int m_stringCount;
};
}