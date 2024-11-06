#pragma once
#include "BMP.h"
namespace lab2
{

#ifndef FEAL_h
#define FEAL_h

using Block = std::vector<byte>;

struct Key 
{
    Block key;

    Key() : key(16, 0)
    {
        for (size_t i = 0; i < 16; ++i)
        {
            key[i] = rand() % 256;
        }

    };
    
    size_t size() const
    {
        return key.size();
    }

    byte& operator[](size_t idx)
    {
        return key[idx];
    }

};

class FEAL_crypt
{

private:

    int rounds_;
    Block subkeys_;
    Key key_;

    byte S0(byte a, byte b);

    byte S1(byte a, byte b);

    Block F(Block& data, Block& key);

    Block Fk(Block& w, Block& w1);

    void feal_round(Block& L, Block& R, Block& k);

    Block generate_rkeys(Block key, size_t rounds);

    Block xor_blocks(const Block& a, const Block& b) const;

public:

    void encrypt_block(Block& block);

    void decrypt_block(Block& block);

    FEAL_crypt(int rounds, Key& key);

    void encrypt(Block& data, Block& key);

    void decrypt(Block& data, Block& key);

};

}


#endif