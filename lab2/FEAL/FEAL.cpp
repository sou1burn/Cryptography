#include "FEAL.h"
namespace lab2
{
//dop1
Block FEAL_crypt::xor_blocks(Block& a, Block& b) {

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

    Block key_block(key.begin(), key.end());

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

    return Fks;
}

void FEAL_crypt::feal_round(Block& L, Block& R, Block& k)
{

    Block F_result = F(R, k);            

    L = xor_blocks(L, F_result);

    std::swap(L, R); 

}


Block FEAL_crypt::generate_rkeys(Block key, int rounds)
{
    /*if (key.size() != 16) throw std::invalid_argument("Key must be 16 bytes");

    Block subkeys;

    Block L(key.begin(), key.begin() + 8);
    Block R(key.begin() + 8, key.end());

    for (size_t i = 0; i < (rounds + 8) / 2; ++i)
    {
        std::cout << "L size: " << L.size() << ", R size: " << R.size()<< " " << i << std::endl;
        Block xor_res = xor_blocks(R, L);
        std::cout << "Res size: " << xor_res.size() << std::endl;

        Block tmp;
        if (i > 0 && i != (rounds + 7) / 2)
        {
            tmp = Fk(L, xor_res); 
        }
        else
        {
            tmp = Fk(L, R);
        }

        subkeys.insert(subkeys.end(), tmp.begin(), tmp.end());

        std::swap(L, R);
    }
    
    return subkeys;
    */

    if (key.size() != 16) throw std::invalid_argument("key must be 16 bytes long");
    
    Block subkeys;

    Block Kl(key.begin(), key.begin() + 8);
    Block Kr(key.begin() + 8, key.end());

    Block A0(Kl.begin(), Kl.begin() + 4);
    Block B0(Kl.begin() + 4, Kl.end());
    Block D = A0;

    Block Kr1(Kr.begin(), Kr.begin() + 4);
    Block Kr2(Kr.begin() + 4, Kr.end());
    Block Q = xor_blocks(Kr1, Kr2);
    Block xored;

    for (int i = 0; i < (rounds + 8) / 2; ++i)
    {
        //std::cout << "L size: " << A0.size() << ", R size: " << B0.size()<< " " << i << std::endl;
        if (i % 3 == 1)
        {
            xored = xor_blocks(B0, Kr1);
        }
        else if (i % 3 == 0)
        {
            xored = xor_blocks(B0, Q);
        }
        else
        {
            xored = xor_blocks(B0, Kr2);
        }

        xored =  i > 0 ? xor_blocks(xored, D) : xored; 
        
        D = A0;
        A0 = Fk(A0, xored);

        subkeys.insert(subkeys.end(), A0.begin(), A0.end());

        std::swap(A0, B0);
    }

    return subkeys;
}

void FEAL_crypt::encrypt_block(Block& block)
{
    if (block.size() != 8) throw std::invalid_argument("Block must be 8 bytes");

    Block L(block.begin(), block.begin() + 4);
    Block R(block.begin() + 4, block.end());
    
    for (int i = 0; i < rounds_; ++i)
    {
        Block k(subkeys_.begin() + (i * 4), subkeys_.begin() + (i * 4) + 4);
        feal_round(L, R, k);
    }

    std::copy(R.begin(), R.end(), block.begin());

    std::copy(L.begin(), L.end(), block.begin() + 4);
}

void FEAL_crypt::decrypt_block(Block& block)
{
    if (block.size() != 8) throw std::invalid_argument("Block must be 8 bytes");

    Block L(block.begin(), block.begin() + 4);
    Block R(block.begin() + 4, block.end());

       
    for (int i = rounds_ - 1; i >= 0; --i)
    {
        Block k(subkeys_.begin() + (i * 4), subkeys_.begin() + (i * 4) + 4);
        //Block k(subkeys_.end() - (i + 1) * 4, subkeys_.end() - i * 4);

        feal_round(L, R, k);
    }

    std::copy(R.begin(), R.end(), block.begin());

    std::copy(L.begin(), L.end(), block.begin() + 4);
}


void FEAL_crypt::encrypt(Block& data)
{
    
    const size_t block_size = 8; 
    
    if (data.size() % block_size != 0) throw std::invalid_argument("Data size must be multiple of block size (8 bytes)");

    for (size_t i = 0; i < data.size(); i += block_size)
    {
        Block block(data.begin() + i, data.begin() + i + block_size);
        
        encrypt_block(block); 

        std::copy(block.begin(), block.end(), data.begin() + i); 
    }

}

void FEAL_crypt::decrypt(Block& data)
{
    
    const size_t block_size = 8; 

    if (data.size() % block_size != 0) throw std::invalid_argument("Data size must be multiple of block size (8 bytes)");
       
    for (size_t i = 0; i < data.size(); i += block_size)
    {
        Block block(data.begin() + i, data.begin() + i + block_size);

        decrypt_block(block); 

        std::copy(block.begin(), block.end(), data.begin() + i); 
    }

}

void FEAL_crypt::encrypt_cbc(Block& opentext, Block& iv, size_t corrupt_byte_idx) {
    if (opentext.size() % iv.size() != 0) 
        throw std::invalid_argument("Plaintext size must be a multiple of block size (8 bytes)");
    if (iv.size() != 8) 
        throw std::invalid_argument("IV size must match block size (8 bytes)");

    Block prev_ciphertext = iv;

    for (size_t i = 0; i < opentext.size(); i += iv.size()) {
        Block block(opentext.begin() + i, opentext.begin() + i + iv.size());        

        block = xor_blocks(block, prev_ciphertext);
        encrypt_block(block);
        std::copy(block.begin(), block.end(), opentext.begin() + i);

        prev_ciphertext = block;
    }
}


void FEAL_crypt::decrypt_cbc(Block& opentext, Block& iv, size_t corrupt_byte_idx) {
    if (opentext.size() % iv.size() != 0) 
        throw std::invalid_argument("Plaintext size must be a multiple of block size (8 bytes)");
    if (iv.size() != 8) 
        throw std::invalid_argument("IV size must match block size (8 bytes)");

    Block prev_ciphertext = iv;
    for (size_t i = 0; i < opentext.size(); i += iv.size()) {
        Block block(opentext.begin() + i, opentext.begin() + i + iv.size());
    
        Block encrypted_block = block; 
        decrypt_block(block);          
        block = xor_blocks(block, prev_ciphertext); 
        std::copy(block.begin(), block.end(), opentext.begin() + i);

        prev_ciphertext = encrypted_block; 
    }
}


void FEAL_crypt::corrupt_byte(Block& block, size_t pixel_idx)
{
    if (pixel_idx >= block.size()) throw std::out_of_range("Pixel index is out of block bounds");

    block[pixel_idx] = ~block[pixel_idx];
}

Block FEAL_crypt::generate_iv(const size_t size = 8)
{
    Block iv(size, 0);

    for (size_t i = 0; i < size; ++i)
    {
        iv[i] = rand() % 256;
    } 

    return iv;
}

}