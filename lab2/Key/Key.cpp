#include "Key.h"

namespace lab2
{

Key::Key() : key(16, 0)
{
    for (size_t i = 0; i < 16; ++i)
    {
        key[i] = static_cast<unsigned char>(rand() % 256);
    }
}

size_t Key::size() const
{
    return key.size();
}

byte& Key::operator[](size_t idx)
{
    return key[idx];
}

Block::iterator Key::begin()
{
    return key.begin();
}

Block::iterator Key::end()
{
    return key.end();
}

};