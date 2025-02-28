#include "md5hash.h"
//dop 2
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

    quad MD5Hasher::leftRotate32(quad n, quad rot)
    {
        return (n << rot) | (n >> (32 - rot));
    }

    std::string MD5Hasher::MD5(const std::string &message)
    {
        quad A = 0x67452301;
        quad B = 0xEFCDAB89;
        quad C = 0x98BADCFE;
        quad D = 0x10325476;

        octa messageLength = message.size();
        
        std::vector<byte> padded = padding(message);
        auto bitLength = messageLength * 8;
        for (auto i = 0; i < 8; i++) 
            padded.push_back(static_cast<byte>((bitLength >> (i * 8)) & 0xFF));;
        
        for (size_t i = 0; i < padded.size(); i += BLOCK_SIZE) {
            quad M[16];
            memcpy(M, &padded[i], 64);
            processBlock(M, A, B, C, D);
        }

        quad hashParts[] = { toLittleEndian32(A), toLittleEndian32(B), toLittleEndian32(C), toLittleEndian32(D) };
        std::stringstream res;
        for (auto &&part : hashParts) {
            for (auto i = 0; i < 4; ++i) {
                res << std::hex << std::setw(2) << std::setfill('0') << (part & 0xFF), part >>= 8;
            }
        }
        return res.str();
    }

    void MD5Hasher::processBlock(quad M[16], quad &A, quad &B, quad &C, quad &D)
    {
        quad a = A, b = B, c = C, d = D;

        for (auto i = 0; i < 64; ++i) {
            quad valF;
            int g;
            if (i < 16) {
                valF = F(b, c, d); 
                g = i;
            } else if (i < 32) {
                valF = G(b, c, d);
                g = (5 * i + 1) % 16;
            } else if (i < 48) {
                valF = H(b, c, d);
                g = (3 * i + 5) % 16;
            } else {
                valF = I(b, c, d);
                g = (7 * i) % 16;
            }
            quad tmp = d;
            d = c;
            c = b;
            b += leftRotate32(a + valF + K[i] + toLittleEndian32(M[g]), S[i]);
            a = tmp;
        }

        A += a, B += b, C += c, D += d;
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
        if (isBigEndian())
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