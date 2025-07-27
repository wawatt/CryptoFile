#include "CryptoFile.h"
#include <fstream>
#include <iostream>
#include <cstring>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

CryptoFile::CryptoFile(const std::string& key, CryptoAlgorithm algorithm) : key_(key), algorithm_(algorithm) {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Set IV length based on algorithm
    switch (algorithm_) {
        case CryptoAlgorithm::AES_256_CBC:
            iv_length_ = EVP_MAX_IV_LENGTH;
            tag_length_ = 0;
            break;
        case CryptoAlgorithm::AES_256_GCM:
            iv_length_ = 12; // Recommended IV length for GCM
            tag_length_ = 16; // Recommended tag length for GCM
            break;
        default:
            throw std::invalid_argument("Unsupported encryption algorithm");
    }

    // Validate key length
    if (key_.size() != 32) {
        throw std::invalid_argument("Key must be exactly 32 bytes long");
    }
}

void CryptoFile::handleErrors() const {
    ERR_print_errors_fp(stderr);
    throw std::runtime_error("OpenSSL operation failed");
}

const EVP_CIPHER* CryptoFile::getCipher() const {
    switch (algorithm_) {
        case CryptoAlgorithm::AES_256_CBC:
            return EVP_aes_256_cbc();
        case CryptoAlgorithm::AES_256_GCM:
            return EVP_aes_256_gcm();
        default:
            throw std::invalid_argument("Unsupported encryption algorithm");
    }
}

void CryptoFile::generateIV(unsigned char* iv) const {
    if (RAND_bytes(iv, iv_length_) != 1) {
        handleErrors();
    }
}

void CryptoFile::encrypt(const std::string& inputFile, const std::string& outputFile) const {
    // Open input and output files
    std::ifstream inFile(inputFile, std::ios::binary);
    if (!inFile) {
        throw std::runtime_error("Unable to open input file: " + inputFile);
    }

    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile) {
        throw std::runtime_error("Unable to open output file: " + outputFile);
    }

    // Create and initialize context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    // Generate and write IV to output file
    unsigned char* iv = new unsigned char[iv_length_];
    generateIV(iv);
    outFile.write(reinterpret_cast<const char*>(iv), iv_length_);

    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, getCipher(), nullptr, reinterpret_cast<const unsigned char*>(key_.c_str()), iv) != 1) {
        delete[] iv;
        EVP_CIPHER_CTX_free(ctx);
        handleErrors();
    }
    delete[] iv;

    // For GCM mode, set tag length
    if (algorithm_ == CryptoAlgorithm::AES_256_GCM) {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_length_, nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            handleErrors();
        }
    }

    // Buffer for encryption
    unsigned char inBuffer[1024];
    unsigned char outBuffer[1024 + EVP_MAX_BLOCK_LENGTH];
    int bytesRead;
    int bytesWritten;

    // Read file and encrypt
    do {
        inFile.read(reinterpret_cast<char*>(inBuffer), sizeof(inBuffer));
        std::streamsize bytesReadSize = inFile.gcount();
        if (bytesReadSize > INT_MAX) {
            throw std::overflow_error("Read size exceeds integer limit");
        }
        bytesRead = static_cast<int>(bytesReadSize);
        if (bytesRead > 0) {
            if (EVP_EncryptUpdate(ctx, outBuffer, &bytesWritten, inBuffer, bytesRead) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                handleErrors();
            }
            outFile.write(reinterpret_cast<const char*>(outBuffer), bytesWritten);
        }
    } while (bytesRead > 0 && !inFile.eof());

    // Handle final block
    if (EVP_EncryptFinal_ex(ctx, outBuffer, &bytesWritten) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors();
    }
    outFile.write(reinterpret_cast<const char*>(outBuffer), bytesWritten);

    // For GCM mode, get and write tag
    if (algorithm_ == CryptoAlgorithm::AES_256_GCM) {
        unsigned char* tag = new unsigned char[tag_length_];
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_length_, tag) != 1) {
            delete[] tag;
            EVP_CIPHER_CTX_free(ctx);
            handleErrors();
        }
        outFile.write(reinterpret_cast<const char*>(tag), tag_length_);
        delete[] tag;
    }

    // Cleanup
    EVP_CIPHER_CTX_free(ctx);
    std::cout << "Encryption completed successfully. Output file: " << outputFile << std::endl;
}

std::string CryptoFile::decrypt2Buffer(const std::string& inputFile) const {
    // Open input file
    std::ifstream inFile(inputFile, std::ios::binary);
    if (!inFile) {
        throw std::runtime_error("Unable to open input file: " + inputFile);
    }

    // Read IV from input file
    unsigned char* iv = new unsigned char[iv_length_];
    inFile.read(reinterpret_cast<char*>(iv), iv_length_);
    if (inFile.gcount() != iv_length_) {
        delete[] iv;
        throw std::runtime_error("Invalid input file format");
    }

    // For GCM mode, read tag from end of file
    unsigned char* tag = nullptr;
    if (algorithm_ == CryptoAlgorithm::AES_256_GCM) {
        tag = new unsigned char[tag_length_];
        inFile.seekg(0, std::ios::end);
        std::streampos fileSize = inFile.tellg();
        if (fileSize < iv_length_ + tag_length_) {
            delete[] iv;
            delete[] tag;
            throw std::runtime_error("File too small for GCM decryption");
        }
        inFile.seekg(-tag_length_, std::ios::end);
        if (inFile.fail()) {
            delete[] iv;
            delete[] tag;
            throw std::runtime_error("Failed to seek for GCM tag");
        }
        inFile.read(reinterpret_cast<char*>(tag), tag_length_);
        if (inFile.gcount() != tag_length_) {
            delete[] iv;
            delete[] tag;
            throw std::runtime_error("Invalid input file format for GCM");
        }
        inFile.seekg(iv_length_, std::ios::beg); // Move back to start after IV
        if (inFile.fail()) {
            delete[] iv;
            delete[] tag;
            throw std::runtime_error("Failed to seek after IV");
        }
    }

    // Create and initialize context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, getCipher(), nullptr, reinterpret_cast<const unsigned char*>(key_.c_str()), iv) != 1) {
        delete[] iv;
        delete[] tag;
        EVP_CIPHER_CTX_free(ctx);
        handleErrors();
    }
    delete[] iv;

    // For GCM mode, set tag length and tag
    if (algorithm_ == CryptoAlgorithm::AES_256_GCM) {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_length_, nullptr) != 1) {
            delete[] tag;
            EVP_CIPHER_CTX_free(ctx);
            handleErrors();
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_length_, tag) != 1) {
            delete[] tag;
            EVP_CIPHER_CTX_free(ctx);
            handleErrors();
        }
    }

    // Buffer for decryption
    unsigned char inBuffer[1024];
    unsigned char outBuffer[1024 + EVP_MAX_BLOCK_LENGTH];
    int bytesRead;
    int bytesWritten;
    std::string decryptedBuffer;

    // Calculate total file size
    inFile.seekg(0, std::ios::end);
    std::streampos totalFileSize = inFile.tellg();
    inFile.seekg(iv_length_, std::ios::beg);

    // Calculate remaining bytes to read (excluding IV and tag for GCM)
    std::streamoff remainingBytes = static_cast<std::streamoff>(totalFileSize) - iv_length_;
    if (algorithm_ == CryptoAlgorithm::AES_256_GCM) {
        remainingBytes -= tag_length_;
    }

    // Read file and decrypt
    while (remainingBytes > 0) {
        std::streamsize bytesReadSize = std::min(static_cast<std::streamoff>(sizeof(inBuffer)), remainingBytes);
        if (bytesReadSize > INT_MAX) {
            throw std::overflow_error("Read size exceeds integer limit");
        }
        bytesRead = static_cast<int>(bytesReadSize);
        inFile.read(reinterpret_cast<char*>(inBuffer), bytesRead);
        if (EVP_DecryptUpdate(ctx, outBuffer, &bytesWritten, inBuffer, bytesRead) != 1) {
            delete[] tag;
            EVP_CIPHER_CTX_free(ctx);
            handleErrors();
        }
        decryptedBuffer.append(reinterpret_cast<const char*>(outBuffer), bytesWritten);
        remainingBytes -= bytesRead;
    }

    // Finalize decryption
    int finalStatus = EVP_DecryptFinal_ex(ctx, outBuffer, &bytesWritten);

    // Cleanup
    delete[] tag;
    EVP_CIPHER_CTX_free(ctx);

    // Check if decryption was successful
    if (finalStatus != 1) {
        throw std::runtime_error("Decryption failed: Invalid key or corrupted file");
    }

    decryptedBuffer.append(reinterpret_cast<const char*>(outBuffer), bytesWritten);
    return decryptedBuffer;
}

void CryptoFile::decrypt(const std::string& inputFile, const std::string& outputFile) const {
    // Open input and output files
    std::ifstream inFile(inputFile, std::ios::binary);
    if (!inFile) {
        throw std::runtime_error("Unable to open input file: " + inputFile);
    }

    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile) {
        throw std::runtime_error("Unable to open output file: " + outputFile);
    }

    // Read IV from input file
    unsigned char* iv = new unsigned char[iv_length_];
    inFile.read(reinterpret_cast<char*>(iv), iv_length_);
    if (inFile.gcount() != iv_length_) {
        delete[] iv;
        throw std::runtime_error("Invalid input file format");
    }

    // For GCM mode, read tag from end of file
    unsigned char* tag = nullptr;
    if (algorithm_ == CryptoAlgorithm::AES_256_GCM) {
        tag = new unsigned char[tag_length_];
        inFile.seekg(0, std::ios::end);
        std::streampos fileSize = inFile.tellg();
        if (fileSize < iv_length_ + tag_length_) {
            delete[] iv;
            delete[] tag;
            throw std::runtime_error("File too small for GCM decryption");
        }
        inFile.seekg(-tag_length_, std::ios::end);
        if (inFile.fail()) {
            delete[] iv;
            delete[] tag;
            throw std::runtime_error("Failed to seek for GCM tag");
        }
        inFile.read(reinterpret_cast<char*>(tag), tag_length_);
        if (inFile.gcount() != tag_length_) {
            delete[] iv;
            delete[] tag;
            throw std::runtime_error("Invalid input file format for GCM");
        }
        inFile.seekg(iv_length_, std::ios::beg); // Move back to start after IV
        if (inFile.fail()) {
            delete[] iv;
            delete[] tag;
            throw std::runtime_error("Failed to seek after IV");
        }
    }

    // Create and initialize context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, getCipher(), nullptr, reinterpret_cast<const unsigned char*>(key_.c_str()), iv) != 1) {
        delete[] iv;
        delete[] tag;
        EVP_CIPHER_CTX_free(ctx);
        handleErrors();
    }
    delete[] iv;

    // For GCM mode, set tag length and tag
    if (algorithm_ == CryptoAlgorithm::AES_256_GCM) {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_length_, nullptr) != 1) {
            delete[] tag;
            EVP_CIPHER_CTX_free(ctx);
            handleErrors();
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_length_, tag) != 1) {
            delete[] tag;
            EVP_CIPHER_CTX_free(ctx);
            handleErrors();
        }
    }

    // Buffer for decryption
    unsigned char inBuffer[1024];
    unsigned char outBuffer[1024 + EVP_MAX_BLOCK_LENGTH];
    int bytesRead;
    int bytesWritten;

    // Calculate total file size
    inFile.seekg(0, std::ios::end);
    std::streampos totalFileSize = inFile.tellg();
    inFile.seekg(iv_length_, std::ios::beg);

    // Calculate remaining bytes to read (excluding IV and tag for GCM)
    std::streamoff remainingBytes = static_cast<std::streamoff>(totalFileSize) - iv_length_;
    if (algorithm_ == CryptoAlgorithm::AES_256_GCM) {
        remainingBytes -= tag_length_;
    }

    // Read file and decrypt
    while (remainingBytes > 0) {
        std::streamsize bytesReadSize = std::min(static_cast<std::streamoff>(sizeof(inBuffer)), remainingBytes);
        if (bytesReadSize > INT_MAX) {
            throw std::overflow_error("Read size exceeds integer limit");
        }
        bytesRead = static_cast<int>(bytesReadSize);
        inFile.read(reinterpret_cast<char*>(inBuffer), bytesRead);
        if (EVP_DecryptUpdate(ctx, outBuffer, &bytesWritten, inBuffer, bytesRead) != 1) {
            delete[] tag;
            EVP_CIPHER_CTX_free(ctx);
            handleErrors();
        }
        outFile.write(reinterpret_cast<const char*>(outBuffer), bytesWritten);
        remainingBytes -= bytesRead;
    }

    // Finalize decryption
    int finalStatus = EVP_DecryptFinal_ex(ctx, outBuffer, &bytesWritten);

    // Cleanup
    delete[] tag;
    EVP_CIPHER_CTX_free(ctx);

    // Check if decryption was successful
    if (finalStatus != 1) {
        throw std::runtime_error("Decryption failed: Invalid key or corrupted file");
    }

    outFile.write(reinterpret_cast<const char*>(outBuffer), bytesWritten);
    std::cout << "Decryption completed successfully. Output file: " << outputFile << std::endl;
}