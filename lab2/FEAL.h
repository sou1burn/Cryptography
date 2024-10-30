#include "BMP.h"
#ifndef funcs_h
#define funcs_h

namespace lab2{



using Block = std::vector<byte>;


struct Key 
{
    Block key;

    Key() : key(16, 0) {};

    Block key_generator()
    {
        for (size_t i = 0; i < key.size(); ++i)
        {
            key[i] = rand() % 256; 
        }
    }
    
};

class FEAL_crypt
{

private:
    static const int rounds = 32;

    byte S0(byte a, byte b);

    byte S1(byte a, byte b);

    Block F(Block& data, Block& key);

    Block Fk(Block& w, Block& w1);

    void feal_round(byte& left, byte& right, byte k);

    Block generate_rkeys(Block key, size_t rounds);

    void encrypt_block(Block& block, byte key);

    void decrypt_block(Block& block, byte key);


public:
    void encrypt(Block& block, byte key);

    void decrypt(Block& block, byte key);

};

}


#endif