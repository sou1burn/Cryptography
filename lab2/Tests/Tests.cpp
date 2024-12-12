#include "Tests.h"

namespace lab2
{

 std::bitset<8 * 8> Tests::bytes_to_bits(const Block block)
 {
    std::bitset<8 * 8> bits;

    for (size_t i = 0; i < block.size();++i)
    {
        int cur = block[i];
        int offset = i * 8;
        for (size_t bit = 0; bit < 8; ++bit)
        {
            bits[offset] = cur & 1;
            ++offset;
            cur >>=1;
        }
    }

    return bits;
 }

 double Tests::frequency_test(const Block block)
 {

    auto bits = bytes_to_bits(block);
    int zeros = 0;
    int ones = 0;

    for (size_t i = 0; i < bits.size(); ++i)
    {
        if (bits[i] == 0) zeros++;
        else if (bits[i] == 1) ones++;
    }
    double X1 = pow((zeros - ones), 2) / (zeros + ones);

    std::cout << "Result of freq test:" << X1 << "\n";

    return X1;
 }
 double Tests::sequence_test(const Block block)
 {
    size_t n0, n1 = 0;
    size_t n00, n01, n10, n11 = 0;
    auto bits = bytes_to_bits(block);

    for (size_t i = 0; i < bits.size(); ++i)
    {
        if(bits[i] == 0) ++n0;
        else ++n1;

        if (i < bits.size() - 1)
        {
            if (bits[i] == 0 && bits[i+1] == 0) ++n00;
            else if (bits[i] == 0 && bits[i+1] == 1) ++n01;
            else if (bits[i] == 1 && bits[i+1] == 0) ++n10;
            else if (bits[i] == 1 && bits[i+1] == 1) ++n11;
        }
    }
//dop2
    double part = (4 / ( bits.size() - 1)) * (n00 * n00 + n01 * n01 + n10 * n10 + n11 * n11);

    double part1 = (2 / bits.size()) * (n0 * n0 + n1 * n1);

    double x2 = part - part1 + 1;
    std::cout << "Result of seq test:" << x2 << "\n";
    return x2; 
 }

 double Tests::poker_test(const Block block, size_t m)
 {
    size_t n = block.size() * 8;

    if (n % m !=0) return 0.0;

    size_t k = n/m;
    size_t num_types = 1 << m;

    auto bits = bytes_to_bits(block);

    std::map<uint32_t, size_t> type_counts;

    for (size_t i = 0; i < k; ++i)
    {
        uint32_t value = 0;
        for (size_t j = 0; j < m; ++j)
        {
            value = (value << 1) | bits[i * m + j];
        }

        type_counts[value]++;
    }

    double sum_of_squares = 0;

    for (const auto& [type, count] : type_counts)
    {
        sum_of_squares += count*count;
    }

    double X3 = (num_types /static_cast<double>(k) * sum_of_squares - k);

    std::cout << "Result of poker test:" << X3 << "\n";
    return X3;
 }

 double Tests::series_test(const Block block, size_t length)
 {
    size_t n = block.size() * 8; 
        
    auto bits = bytes_to_bits(block);

    double e;
    int k = 0;

    for (size_t length = 1; length <= n; ++length)
    {
        e = static_cast<double>(n - length + 3) / pow(2, length + 2);
        if (e >= 5)
        {
            k = length;
        }
        else
        {
            break;
        }
    }

    std::vector<int> B(k + 1, 0), G(k + 1, 0);

    int current_length = 1;
    bool is_one = bits[0];

    for (size_t i = 1; i < bits.size(); ++i)
    {
        if (bits[i] == is_one)
        {
            ++current_length;
        } 
        else
        {
            if (current_length <= k)
            {
                if (is_one)
                {
                    B[current_length]++;
                }
                else
                {
                    G[current_length]++;
                }
            }
            is_one = bits[i];
            current_length = 1;
        }
    }
    if (current_length <= k)
    {
        if (is_one)
        {
            B[current_length]++;
        } 
        else 
        {
            G[current_length]++;
        }
    }

    double chi_squared = 0.0;
    for (int i = 1; i <= k; ++i)
    {
        double e = static_cast<double>(n - i + 3) / pow(2, i + 2);
        chi_squared += pow(B[i] - e, 2) / e;
        chi_squared += pow(G[i] - e, 2) / e;
    }

    std::cout << "Result of series test:" << chi_squared << "\n";

    return chi_squared;
    
 }  

 double Tests::autocorrelation_test(const Block block, int d)
 {
    size_t n = block.size() * 8; 
    auto bits = bytes_to_bits(block);

    int unmatched_count = 0;

    for (size_t i = 0; i < n - d; ++i)
    {
        if (bits[i] != bits[i + d])
        {
            ++unmatched_count;
        }
    }

    double T = (2.0 *unmatched_count / (n - d)) / sqrt(n-d);
     
    std::cout << "Result of autocorrelation test:" << T << "\n";
    return T;
    }
}
