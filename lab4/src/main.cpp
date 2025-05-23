#include "collisionfinder.h"
#include "dsa/dsasystem.h"

int main()
{
    md5::MD5Hasher hasher;
    // std::string input;
    // std::cout << "Enter a string: \n";
    // std::cin >> input;
    // const auto hash = hasher.MD5(input);
    // std::cout << "MD5 hash: " << hash << "\n";
    //
    // int N;
    // std::cout << "Enter number N of strings: \n";
    // std::cin >> N;

    // md5::CollisionFinder finder(160);
    //
    // const auto hashes = finder.generateStringHashes(160);

    std::string keyLength;
    auto byPassword = false;
    std::string choice;
    std::string password;
    std::string msg;

    std::cout << "Enter message: \n";
    std::cin >> msg;
    std::cout << "Enter key length: \n";
    std::cin >> keyLength;
    std::cout << "Enter password: \n";
    std::cin >> password;
    std::cout << "Generate by password? (1 for yes, 0 for no): \n";
    std::cin >> choice;
    if (choice == "1")
        byPassword = true;
    else if (choice == "0")
        byPassword = false;
    else {
        std::cerr << "Invalid choice. Exiting.\n";
        return 1;
    }

    std::cout << "Hash message: " << hasher.MD5(msg) << std::endl;

    // for (const auto &hash : hashes) {
        const dsa::DSACryptosystem dsa(std::stoi(keyLength), password, msg, byPassword);
        std::cout << "Generated DSA keys:\n";

        std::cout << "Public key: " << dsa.keys().second << " \nPrivate key: " << dsa.keys().first << "\n";

        std::cout << "Signature: \n r = " << dsa.signature().first << " \n s = " << dsa.signature().second << "\n";

        if (dsa.validateSignature())
            std::cout << "Signature validated successfully \n";
        else
            std::cout << "Signature validation failed \n";
    // }

    return 0;
}