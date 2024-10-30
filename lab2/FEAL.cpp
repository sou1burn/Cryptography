#include "BMP.h"
#include "FEAL.h"
namespace lab2
{

byte FEAL_crypt::S0(byte a, byte b)
{
    return (a + b) % 256;
}

byte FEAL_crypt::S1(byte a, byte b)
{
    return (a + b + 1) % 256;
}

Block FEAL_crypt::F(Block& data, Block& key)
{
    Block Fs(4, 0);

    byte F1 = data[1] ^ key[0];

    byte F2 = data[2] ^ key[1];

    F1 = F1 ^ data[0];

    F2 = F2 ^ data[3];

    F1 = S1(F1, F2);

    F2 = S0(F2, F1);

    byte F0 = S0(data[0], F1);

    byte F3 = S1(data[3], F2);
    
    Fs[0] = F0;
    Fs[1] = F1;
    Fs[2] = F2;
    Fs[3] = F3;


    return Fs; 
}

Block FEAL_crypt::Fk(Block& w, Block& w1)
{
    byte Fk0, Fk1, Fk2, Fk3;

    Block Fks(4, 0);

    Fk1 = w[1] ^ w[0];
    
    Fk2 = w[2] ^ w[3];

    Fk1 = S1(Fk1, (Fk2 ^ w1[0]));

    Fk2 = S0(Fk2, (Fk1 ^ w1[1]));

    Fk0 = S0(w[0], (Fk1 ^ w1[2]));

    Fk3 = S1(w[3], (Fk2 ^ w1[3]));

    Fks[0] = Fk0;
    Fks[1] = Fk1;
    Fks[2] = Fk2;
    Fks[3] = Fk3;


    return Fks;
}

void FEAL_crypt::feal_round(byte& L, byte& R, byte k)
{

}


Block FEAL_crypt::generate_rkeys(Block key, size_t rounds)
{
    Block Keys(rounds + 8, 0);

    Block L(8, 0);
    Block R(8, 0);
    for (size_t i = 0; i < 8; ++i)
    {
        L[i] = key[i];
    }

    for (size_t i = 0; i < 8; ++i)
    {
        R[i] = key[i];
    }

    
}

void FEAL_crypt::encrypt_block(Block& block, byte key)
{

}

void FEAL_crypt::decrypt_block(Block& block, byte key)
{

}


void FEAL_crypt::encrypt(Block& block, byte key)
{

}

void FEAL_crypt::decrypt(Block& block, byte key)
{

}
}