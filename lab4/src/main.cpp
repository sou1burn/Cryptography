#include "md5hash.h"



int main(int argc, char **argv)
{
    md5::MD5Hasher hasher;
    std::string input;

    std::cout << "Enter a string: \n";
    std::cin >> input;
    std::cout << "MD5 hash: " << hasher.MD5(input);

    return 0;
}