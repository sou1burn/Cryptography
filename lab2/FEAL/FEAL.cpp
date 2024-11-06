#include "FEAL.h"
namespace lab2
{

Block FEAL_crypt::xor_blocks(const Block& a, const Block& b) const {

    //std::cout << "A size == " << a.size() << " B size == " << b.size() << " ";
    if (a.size() != b.size()) throw std::invalid_argument("Block sizes must match for XOR operation");

    Block result(a.size());

    for (size_t i = 0; i < a.size(); ++i)
    {
        result[i] = a[i] ^ b[i];
    }
    

    return result;
}

FEAL_crypt::FEAL_crypt(int rounds, Key& key) : rounds_(rounds), key_(key)
{
    if (rounds_ <= 0) throw std::invalid_argument("Num of rounds must be positive");

    if (key.size() != 16) throw std::invalid_argument("Key len must be 16 bytes");

    Block key_block;

    for (size_t i = 0; i < key.size(); ++i)
    {
        key_block.push_back(key[i]);
    }

    subkeys_ = generate_rkeys(key_block, rounds_);
}

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
    if (data.size() < 4 || key.size() < 4) throw std::invalid_argument("Data and Key blocks must be at least 4 bytes");

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
    if (w.size() < 4 || w1.size() < 4) throw std::invalid_argument("Data and Key blocks must be at least 4 bytes");

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
    
    //std::cout << sizeof(Fks[0]) << " " << sizeof(Fks[1]) << " " << sizeof(Fks[2]) << " " << sizeof(Fks[3]);


    return Fks;
}

void FEAL_crypt::feal_round(Block& L, Block& R, Block& k)
{
    Block F_result = F(R, k);              

    L = xor_blocks(L, F_result);

    std::swap(L, R); 

}


Block FEAL_crypt::generate_rkeys(Block key, size_t rounds)
{
    if (key.size() != 16) throw std::invalid_argument("Key must be 16 bytes");

    Block subkeys;
    
    subkeys.reserve((rounds + 8) * 4);

    Block L(key.begin(), key.begin() + 8);
    Block R(key.begin() + 8, key.end());

    for (size_t i = 0; i < (rounds + 8) / 2; ++i)
    {
        /*for (size_t i = 0; i < L.size(); ++i)
        {
        std::cout << "L[" << i << "] = " << L[i] << " \n";
        std::cout << "R[" << i << "] = " << R[i] << " \n";
        }*/
        std::cout << "L size: " << L.size() << ", R size: " << R.size() << std::endl;
        Block xor_res = xor_blocks(R, L);
        std::cout << "Res size: " << xor_res.size() << std::endl;
        Block tmp = (i > 0 && i != (rounds + 7) / 2) ? Fk(L, xor_res) : Fk(L, R);

        subkeys.insert(subkeys.end(), tmp.begin(), tmp.end());

        std::swap(L, R);
    }
    
    return subkeys;
}

void FEAL_crypt::encrypt_block(Block& block)
{
    if (block.size() != 16) throw std::invalid_argument("Block must be 16 bytes");

    Block L(key_.key.begin(), key_.key.begin() + 8);
    Block R(key_.key.begin() + 8, key_.key.end());

    for (int i = 0; i < rounds_; ++i)
    {
        Block k(subkeys_.begin() + (i * 4), subkeys_.begin() + (i * 4) + 4);
        feal_round(L, R, k);
    }

    std::copy(R.begin(), R.end(), block.begin());

    std::copy(L.begin(), L.end(), block.begin() + 8);
}

void FEAL_crypt::decrypt_block(Block& block)
{
    if (block.size() != 16) throw std::invalid_argument("Block must be 16 bytes");

    Block L(key_.key.begin(), key_.key.begin() + 8);
    Block R(key_.key.begin() + 8, key_.key.end());
       
    for (int i = rounds_ - 1; i >= 0; --i)
    {
        Block k(subkeys_.begin() + (i * 4), subkeys_.begin() + (i * 4) + 4);

        feal_round(R, L, k);
    }

    std::copy(L.begin(), L.end(), block.begin());

    std::copy(R.begin(), R.end(), block.begin() + 8);
}


void FEAL_crypt::encrypt(Block& data, Block& key)
{
    
    const size_t block_size = 16; 
    
    if (data.size() % block_size != 0) throw std::invalid_argument("Data size must be multiple of block size (16 bytes)");

    for (size_t i = 0; i < data.size(); i += block_size)
    {
        Block block(data.begin() + i, data.begin() + i + block_size);
        
        encrypt_block(block); 

        std::copy(block.begin(), block.end(), data.begin() + i); 
    }

}

void FEAL_crypt::decrypt(Block& data, Block& key)
{
    
    const size_t block_size = 16; 

    if (data.size() % block_size != 0) throw std::invalid_argument("Data size must be multiple of block size (16 bytes)");
       
    for (size_t i = 0; i < data.size(); i += block_size)
    {
        Block block(data.begin() + i, data.begin() + i + block_size);

        decrypt_block(block); 

        std::copy(block.begin(), block.end(), data.begin() + i); 
    }

}

}