#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <cstring>
#include <cstdlib>

const int BLOCK_SIZE = 8;
const int ROUNDS = 4;
const int IV_SIZE = 8;  // Размер вектора инициализации

const int FILE_HEADER_SIZE = 14;
const int INFO_HEADER_SIZE = 40;
const int HEADER_SIZE = FILE_HEADER_SIZE + INFO_HEADER_SIZE;

struct Key {
    std::vector<uint8_t> data;

    Key() : data(16, 0) {}

    void generate() {
        for (int i = 0; i < 16; ++i) {
            data[i] = rand() % 256;
        }
    }

    void saveToFile(const std::string& filename) {
        std::ofstream outFile(filename, std::ios::binary);
        if (outFile.is_open()) {
            outFile.write(reinterpret_cast<const char*>(data.data()), data.size());
            outFile.close();
            std::cout << "Key saved to " << filename << std::endl;
        }
        else {
            std::cerr << "Error: Failed to create key file: " << filename << std::endl;
        }
    }

    void loadFromFile(const std::string& filename) {
        std::ifstream inFile(filename, std::ios::binary);
        if (!inFile) {
            std::cerr << "Error: Key file '" << filename << "' could not be opened. Check if the file exists." << std::endl;
            exit(1);
        }

        inFile.read(reinterpret_cast<char*>(data.data()), data.size());
        if (!inFile) {
            std::cerr << "Error: Failed to read key from file '" << filename << "'. Make sure the file is correct." << std::endl;
            exit(1);
        }
        std::cout << "Key loaded from " << filename << std::endl;
    }
};

// Функция F
uint8_t F(uint8_t x, uint8_t y) {
    return (x ^ y) ^ ((x & y) << 1);
}

// Раунд FEAL
void feal_round(uint8_t* L, uint8_t* R, const uint8_t* K) {
    uint8_t temp[4];
    std::memcpy(temp, R, 4);

    for (int i = 0; i < 4; ++i) {
        R[i] = L[i] ^ F(R[i], K[i]);
    }

    std::memcpy(L, temp, 4);
}

// Шифрование блока
void feal_encrypt_block(uint8_t* block, const Key& key) {
    uint8_t L[4], R[4];
    std::memcpy(L, block, 4);
    std::memcpy(R, block + 4, 4);

    for (int round = 0; round < ROUNDS; ++round) {
        feal_round(L, R, key.data.data() + (round * 4));
    }

    std::memcpy(block, L, 4);
    std::memcpy(block + 4, R, 4);
}

// Генерация вектора инициализации (IV)
void generate_iv(uint8_t* iv) {
    for (int i = 0; i < IV_SIZE; ++i) {
        iv[i] = rand() % 256;
    }
}

// Инвертирование случайного байта
void corrupt_byte(std::ofstream& outFile, const std::string& outputFile) {
    outFile.close(); // Закрыть файл, чтобы открыть его снова для изменения

    std::fstream file(outputFile, std::ios::in | std::ios::out | std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error: Failed to open file for corruption: " << outputFile << std::endl;
        return;
    }

    file.seekg(0, std::ios::end); // Переход к концу файла для определения размера
    std::streampos fileSize = file.tellg();
    if (fileSize <= HEADER_SIZE) {
        std::cerr << "Error: File is too small to corrupt a pixel." << std::endl;
        return;
    }

    // Преобразуем fileSize в целочисленный тип, чтобы можно было использовать оператор %
    std::streamsize size = static_cast<std::streamsize>(fileSize) - HEADER_SIZE;
    std::streampos corruptPos = HEADER_SIZE + static_cast<std::streampos>(rand() % size);


    file.seekp(corruptPos);
    char byte;  
    file.read(&byte, 1); // Чтение одного байта
    byte = ~byte;        // Инвертирование байта
    file.seekp(corruptPos);
    file.write(&byte, 1); // Запись инвертированного байта

    file.close();
    std::cout << "Corrupted one byte at position " << corruptPos << " in " << outputFile << std::endl;
}

// Шифрование в режиме OFB с последующей порчей одного байта
void encrypt_ofb(const std::string& inputFile, const std::string& outputFile, const Key& key) {
    std::ifstream inFile(inputFile, std::ios::binary);
    std::ofstream outFile(outputFile, std::ios::binary);

    // Проверка открытия файлов
    if (!inFile.is_open()) {
        std::cerr << "Error: Failed to open input file: " << inputFile << ". Check if the file exists and the path is correct." << std::endl;
        return;
    }

    if (!outFile.is_open()) {
        std::cerr << "Error: Failed to create output file: " << outputFile << ". Check file permissions and directory path." << std::endl;
        return;
    }

    // Чтение и запись заголовка
    std::vector<uint8_t> header(HEADER_SIZE);
    inFile.read(reinterpret_cast<char*>(header.data()), HEADER_SIZE);
    if (!inFile) {
        std::cerr << "Error: Failed to read header from input file: " << inputFile << std::endl;
        return;
    }
    outFile.write(reinterpret_cast<const char*>(header.data()), HEADER_SIZE);

    // Генерация вектора инициализации и шифрование
    uint8_t iv[IV_SIZE];
    generate_iv(iv);

    uint8_t block[BLOCK_SIZE];
    while (inFile.read(reinterpret_cast<char*>(block), BLOCK_SIZE)) {
        feal_encrypt_block(iv, key);  // Шифруем IV
        for (int i = 0; i < BLOCK_SIZE; ++i) {
            block[i] ^= iv[i];  // XOR с блоком данных
        }
        outFile.write(reinterpret_cast<const char*>(block), BLOCK_SIZE);
    }

    if (inFile.eof()) {
        std::cout << "Encryption completed successfully, output saved to " << outputFile << std::endl;
    }
    else {
        std::cerr << "Error: Failed during encryption, possibly incomplete file read." << std::endl;
    }

    // Портим один байт
    corrupt_byte(outFile, outputFile);

    inFile.close();
    outFile.close();
}

// Дешифрование в режиме OFB
void decrypt_ofb(const std::string& inputFile, const std::string& outputFile, const Key& key) {
    std::ifstream inFile(inputFile, std::ios::binary);
    std::ofstream outFile(outputFile, std::ios::binary);

    // Проверка открытия файлов
    if (!inFile.is_open()) {
        std::cerr << "Error: Failed to open input file: " << inputFile << ". Check if the file exists and the path is correct." << std::endl;
        return;
    }

    if (!outFile.is_open()) {
        std::cerr << "Error: Failed to create output file: " << outputFile << ". Check file permissions and directory path." << std::endl;
        return;
    }

    // Чтение и запись заголовка
    std::vector<uint8_t> header(HEADER_SIZE);
    inFile.read(reinterpret_cast<char*>(header.data()), HEADER_SIZE);
    if (!inFile) {
        std::cerr << "Error: Failed to read header from input file: " << inputFile << std::endl;
        return;
    }
    outFile.write(reinterpret_cast<const char*>(header.data()), HEADER_SIZE);

    // Генерация вектора инициализации (для дешифрования в OFB используется тот же процесс, что и для шифрования)
    uint8_t iv[IV_SIZE];
    generate_iv(iv);

    uint8_t block[BLOCK_SIZE];
    while (inFile.read(reinterpret_cast<char*>(block), BLOCK_SIZE)) {
        feal_encrypt_block(iv, key);  // Шифруем IV
        for (int i = 0; i < BLOCK_SIZE; ++i) {
            block[i] ^= iv[i];  // XOR с блоком данных
        }
        outFile.write(reinterpret_cast<const char*>(block), BLOCK_SIZE);
    }

    if (inFile.eof()) {
        std::cout << "Decryption completed successfully, output saved to " << outputFile << std::endl;
    }
    else {
        std::cerr << "Error: Failed during decryption, possibly incomplete file read." << std::endl;
    }

    inFile.close();
    outFile.close();
}

// Главная функция
int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0] << " <encrypt|decrypt> <input.bmp> <output.bmp> <keyfile>\n";
        return 1;
    }

    std::string mode = argv[1];
    std::string inputFile = argv[2];
    std::string outputFile = argv[3];
    std::string keyFile = argv[4];

    Key key;

    if (mode == "encrypt") {
        std::ifstream keyCheck(keyFile);
        if (!keyCheck.good()) {
            std::cout << "Key file not found, generating new key.\n";
            key.generate();
            key.saveToFile(keyFile);
        }
        else {
            keyCheck.close();
            key.loadFromFile(keyFile);
        }

        encrypt_ofb(inputFile, outputFile, key);  // Шифрование

    }
    else if (mode == "decrypt") {
        key.loadFromFile(keyFile);
        decrypt_ofb(inputFile, outputFile, key); // Дешифрование

    }
    else {
        std::cerr << "Error: Invalid mode. Use 'encrypt' or 'decrypt'.\n";
        return 1;
    }

    return 0;
}