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

    quad MD5Hasher::leftRotate32(quad n, std::size_t &rot)
    {
        return (n << rot) | (n >> (32 - rot));
    }

    std::string MD5Hasher::MD5(const std::string &message)
    {
        quad A = 0x67452301;
        quad B = 0xEFCDAB89;
        quad C = 0x98BADCFE;
        quad D = 0x10325476;

        auto messageLength = static_cast<byte>(message, message.size());
        
        std::vector<byte> padded = padding(message);

        padded[messageLength] = 1 << 7;
        for (int i = 0; i < 8; i++) 
            padded.push_back((messageLength >> (i * 8)) & 0xFF);
        
    }

    void MD5Hasher::processBlock(std::array<quad, 16> M, quad &A, quad &B, quad &C, quad &D)
    {
        quad a = A, b = B, c = C, d = D;

        

    }

//  stolen
    bool MD5Hasher::isBigEndian()
    {
        union {
            quad i;
            std::array<char, 4> c;
        } bint = {0x01020304};

        return bint.c[0] == 1;
    }

    quad MD5Hasher::toLittleEndian32(quad n)
    {
        if (!isBigEndian())
            return ((n << 24) & 0xFF000000) | ((n << 8) & 0x00FF0000) | ((n >> 8) & 0x0000FF00) | ((n >> 24) & 0x000000FF);
        
        return n;
    }

    octa MD5Hasher::toLittleEndian64(octa n)
    {
        if (!isBigEndian()) 
            return
            ((n << 56) & 0xFF00000000000000) |
            ((n << 40) & 0x00FF000000000000) |
            ((n << 24) & 0x0000FF0000000000) |
            ((n << 8) & 0x000000FF00000000)  |
            ((n >> 56) & 0x00000000FF000000) |
            ((n >> 40) & 0x0000000000FF0000) |
            ((n >> 24) & 0x000000000000FF00) |
            ((n >> 8) & 0x00000000000000FF);

        return n;
    }
}