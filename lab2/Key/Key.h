#pragma once
#include <vector>
#include <string>
#include <cstdlib>
namespace lab2
{
    
using byte = uint8_t;
using Block = std::vector<byte>;
class Key 
{
private:
    Block key;

public:
    Key(); 

    size_t size() const; 

    byte& operator[](size_t idx); 

    Block::iterator begin(); 
    
    Block::iterator end();
};

}