#pragma once
#include "Key.h"
#include <iostream>
#include <fstream>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <string>
#include <cstdlib>
#include <random>
namespace lab2
{

#ifndef FEAL_h
#define FEAL_h

using Block = std::vector<byte>;


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

    Block generate_rkeys(Block key, int rounds);

    Block xor_blocks(Block& a, Block& b);

public:

    void encrypt_block(Block& block);

    void decrypt_block(Block& block);

    FEAL_crypt(int rounds, Key& key);

    void encrypt(Block& data);

    void decrypt(Block& data);
    
    void encrypt_cbc(Block& opentext, Block& iv, size_t corrupt_byte_idx = std::numeric_limits<size_t>::max());

    void decrypt_cbc(Block& opentext, Block& iv, size_t corrupt_byte_idx = std::numeric_limits<size_t>::max());

    void corrupt_byte(Block& block, size_t pixel_idx);

    Block generate_iv(const size_t size);
};

}


#endif