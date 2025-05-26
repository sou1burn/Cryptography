#include "src/SchnorrScheme.h"
//доп 9
int main(int argc, char **argv) {

    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <rounds>" << std::endl;
        return 1;
    }

    const int rounds = atoi(argv[1]);

    SchemeParams params = SchnorrScheme::generateParams(1024);
    Prover prover(params);
    Verifier verifier(params, prover.publicKey());
    for (auto i = 0; i < rounds; ++i) {
        cpp_int challenge = verifier.generateChallenge();
        const auto response  = prover.generateResponse(challenge);
        bool isValid;
        if (i % 2 == 0)
            isValid = verifier.verify(response.first, response.second + 1, challenge);
        else
            isValid = verifier.verify(response.first, response.second, challenge);
        std::cout << "Round " << i + 1 << ": " << (isValid ? "Accepted" : "Rejected") << std::endl;
    }

    SchnorrSignature signature("abracadabra avada kedavra", params, prover.privateKey(), prover.publicKey());
    signature.sign();
    std::cout << "Signature: e = " << signature.signature().first
              << ", y = " << signature.signature().second << std::endl;
    if (signature.verify()) {
        std::cout << "Signature is valid!" << std::endl;
    } else {
        std::cout << "Signature is invalid!" << std::endl;
    }

    return 0;
}