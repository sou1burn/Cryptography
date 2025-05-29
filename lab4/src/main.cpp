// #include "collisionfinder.h"
// #include "dsa/dsasystem.h"
//
// int main()
// {
//     md5::MD5Hasher hasher;
//     // std::string input;
//     // std::cout << "Enter a string: \n";
//     // std::cin >> input;
//     // const auto hash = hasher.MD5(input);
//     // std::cout << "MD5 hash: " << hash << "\n";
//     //
//     // int N;
//     // std::cout << "Enter number N of strings: \n";
//     // std::cin >> N;
//
//     // md5::CollisionFinder finder(160);
//     //
//     // const auto hashes = finder.generateStringHashes(160);
//
//     std::string keyLength;
//     auto byPassword = false;
//     std::string choice;
//     std::string password;
//     std::string msg;
//
//     std::cout << "Enter message: \n";
//     std::cin >> msg;
//     std::cout << "Enter key length: \n";
//     std::cin >> keyLength;
//     std::cout << "Enter password: \n";
//     std::cin >> password;
//     std::cout << "Generate by password? (1 for yes, 0 for no): \n";
//     std::cin >> choice;
//     if (choice == "1")
//         byPassword = true;
//     else if (choice == "0")
//         byPassword = false;
//     else {
//         std::cerr << "Invalid choice. Exiting.\n";
//         return 1;
//     }
//
//     std::cout << "Hash message: " << hasher.MD5(msg) << std::endl;
//
//     // for (const auto &hash : hashes) {
//         const dsa::DSACryptosystem dsa(std::stoi(keyLength), password, msg, byPassword);
//         std::cout << "Generated DSA keys:\n";
//
//         std::cout << "Public key: " << dsa.keys().second << " \nPrivate key: " << dsa.keys().first << "\n";
//
//         std::cout << "Signature: \n r = " << dsa.signature().first << " \n s = " << dsa.signature().second << "\n";
//
//         if (dsa.validateSignature())
//             std::cout << "Signature validated successfully \n";
//         else
//             std::cout << "Signature validation failed \n";
//     // }
//
//     return 0;
// }

#include "collisionfinder.h"
#include "dsa/dsasystem.h"

struct SuccessfulEntry {
    std::string message;
    dsa::cpp_int r;
    dsa::cpp_int s;
    dsa::cpp_int privateKey;
    dsa::cpp_int publicKey;
};

std::vector<std::string> generateStrings(const int &n) {
    auto randomChar = []() -> char {
        constexpr char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 ";
        constexpr size_t maxIndex = (sizeof(charset) - 2);
        return charset[rand() % maxIndex];
    };

    std::vector<std::string> randomStrings;
    for (auto i = 0; i < n; ++i) {
        std::string str(32,0);
        std::generate_n(str.begin(), 32, randomChar);
        randomStrings.push_back(str);
    }
    return randomStrings;
}

int main() {
    // md5::MD5Hasher hasher;

    std::string keyLength;
    auto byPassword = false;
    std::string choice;
    std::string password;
    int N;

    std::cout << "Enter key length: \n";
    std::cin >> keyLength;
    std::cout << "Enter password: \n";
    std::cin >> password;
    std::cout << "Generate by password? (1 for yes, 0 for no): \n";
    std::cin >> choice;
    std::cout << "Enter number of messages to generate: \n";
    std::cin >> N;

    if (choice == "1")
        byPassword = true;
    else if (choice == "0")
        byPassword = false;
    else {
        std::cerr << "Invalid choice. Exiting.\n";
        return 1;
    }

    std::vector<SuccessfulEntry> successfulEntries;
    const auto messages = generateStrings(N);
    for (auto i = 0; i < N; ++i) {
        const auto msg = messages[i];
        try {
            const dsa::DSACryptosystem dsa(std::stoi(keyLength), password, msg, byPassword);

            if (dsa.validateSignature()) {
                SuccessfulEntry entry {
                    .message = msg,
                    .r = dsa.signature().first,
                    .s = dsa.signature().second,
                    .privateKey = dsa.keys().first,
                    .publicKey = dsa.keys().second
                };
                successfulEntries.push_back(entry);
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Error processing message " << msg << ": " << e.what() << "\n";
        }
    }

    std::cout << "\nSuccessfully validated signatures: " << successfulEntries.size() << "\n";
    // for (const auto& entry : successfulEntries) {
    //     std::cout << "\nMessage: " << entry.message
    //               << "\nSignature r: " << entry.r
    //               << "\nSignature s: " << entry.s
    //               << "\nPrivate key: " << entry.privateKey
    //               << "\nPublic key: " << entry.publicKey
    //               << "\n";
    // }
    std::cout << "\n\n________________________________________________________________\n\n";
    auto dsa = dsa::DSACryptosystem(std::stoi(keyLength), password, "message1", byPassword);
    dsa.attack("message1", "message2");

    return 0;
}