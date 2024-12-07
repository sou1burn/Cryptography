#pragma once
#include "FEAL.h"


namespace lab2
{
class Tests
{
private:
    std::bitset<8 * 8> bytes_to_bits(const Block block);

public:
    double frequency_test(const Block block);

    double sequence_test(const Block block);

    double poker_test(const Block block, size_t m);

    double series_test(const Block block, size_t len);

    void autocorrelation_test();

};
}