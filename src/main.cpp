#include "CryptoFile.h"
#include <iostream>
#include <string>

void printUsage() {
    std::cout << "Usage: crypto_app <operation> <input_file> <output_file> <key> <algorithm>\n"
              << "Operations: encrypt, decrypt\n"
              << "Algorithms: aes-256-cbc, aes-256-gcm\n"
              << "Example: crypto_app encrypt input.txt encrypted.bin My32CharacterLongKey aes-256-gcm\n";
}

CryptoAlgorithm getAlgorithmFromString(const std::string& algoStr) {
    if (algoStr == "aes-256-cbc") {
        return CryptoAlgorithm::AES_256_CBC;
    } else if (algoStr == "aes-256-gcm") {
        return CryptoAlgorithm::AES_256_GCM;
    } else {
        throw std::invalid_argument("Unsupported algorithm: " + algoStr);
    }
}

int main(int argc, char* argv[]) {
    if (argc != 6) {
        printUsage();
        return 1;
    }

    try {
        std::string operation = argv[1];
        std::string inputFile = argv[2];
        std::string outputFile = argv[3];
        std::string key = argv[4];
        CryptoAlgorithm algorithm = getAlgorithmFromString(argv[5]);

        CryptoFile crypto(key, algorithm);

        if (operation == "encrypt") {
            crypto.encrypt(inputFile, outputFile);
        } else if (operation == "decrypt") {
            crypto.decrypt(inputFile, outputFile);
            crypto.decrypt2Buffer(inputFile); // Example usage of decrypt2Buffer
        } else {
            std::cerr << "Invalid operation: " << operation << std::endl;
            printUsage();
            return 1;
        }

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}