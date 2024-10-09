#include "BMP.h"
#ifndef funcs_h
#define funcs_h


using byte = uint8_t;
using block = std::vector<byte>;

class FEAL_crypt
{
private:
    static const int rounds = 32;
    byte F(byte x, byte k);
    void feal_round(byte& left, byte& right, byte k);
    std::vector<byte> generate_subkeys(byte key, int rounds);
    void encrypt_block(std::vector<byte>& block, byte key);
    void decrypt_block(std::vector<byte>& block, byte key);

public:
    void encrypt(std::vector<byte>& block, byte key);

    void decrypt(std::vector<byte>& block, byte key);

};




#endif