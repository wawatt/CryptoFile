#ifndef CRYPTOFILE_H
#define CRYPTOFILE_H

#include <string>
#include <openssl/evp.h>

enum class CryptoAlgorithm {
    AES_256_CBC,
    AES_256_GCM
};

class CryptoFile {
private:
    std::string key_;
    CryptoAlgorithm algorithm_;
    int iv_length_;
    int tag_length_;

    void handleErrors() const;
    const EVP_CIPHER* getCipher() const;
    void generateIV(unsigned char* iv) const;

public:
    CryptoFile(const std::string& key, CryptoAlgorithm algorithm);
    ~CryptoFile() = default;

    void encrypt(const std::string& inputFile, const std::string& outputFile) const;
    void decrypt(const std::string& inputFile, const std::string& outputFile) const;
    std::string decrypt2Buffer(const std::string& inputFile) const;
};

#endif // CRYPTOFILE_H