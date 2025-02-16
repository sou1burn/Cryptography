#include "md5hash.h"

namespace md5 
{

    quad MD5Hasher::F(quad X, quad Y, quad Z) 
    {
        return (X & Y) | (~X & Z);
    }

    quad MD5Hasher::G(quad X, quad Y, quad Z) 
    {
        return (X & Z) | (~Z & Y);
    }

    quad MD5Hasher::H(quad X, quad Y, quad Z) 
    {
        return X ^ Y ^ Z;
    }

    quad MD5Hasher::I(quad X, quad Y, quad Z) 
    {
        return Y ^ (~Z | X);
    }

    std::vector<byte> MD5Hasher::padding(const std::string &msg)
    {
        std::vector<byte> padded(msg.begin(), msg.end());
        padded.push_back(0x80);
        while (padded.size() % 64 != 56)
            padded.push_back(0x00);

        return padded;
    }
}