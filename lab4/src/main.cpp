#include "collisionfinder.h"

int main()
{
    md5::MD5Hasher hasher;
    std::string input;

    // std::cout << "Enter a string: \n";
    // std::cin >> input;
    // std::cout << "MD5 hash: " << hasher.MD5(input) << "\n";

    int N;
    std::cout << "Enter number N of strings: \n";
    std::cin >> N;

    md5::CollisionFinder finder(N);

    finder.findCollision();

    return 0;
}