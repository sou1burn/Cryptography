#include "BMP.h"

namespace lab2
{

void BmpReader::read_data(const std::string& filename)
{
    bmp_file.open(filename, std::ios::binary);
    
    if (!bmp_file)
    {
        throw std::runtime_error("File not opened\n");
    }
    
    bmp_file.read((char*)(&file_header), sizeof(BmpFileHeader));

    if (file_header.file_type != 0x4D42)
    {
        throw std::runtime_error("File is not .bmp\n");
    }

    bmp_file.read((char*)(&info_header), sizeof(BmpInfoHeader));

    if (info_header.bit_count != 24)
    {
        throw std::runtime_error("Unsupported format\n");
    }


    size_t data_size = file_header.file_size - file_header.offset;

    pixel_data.resize(data_size);

    bmp_file.seekg(file_header.offset, std::ios::beg);

    bmp_file.read(reinterpret_cast<char*>(pixel_data.data()), data_size);

    bmp_file.close();

}


void BmpReader::rewrite_bmp(const std::string& filename, std::vector<byte> data)
{
    std::ofstream out(filename, std::ios::binary);

    if (!out)
    {
        throw std::runtime_error("Output file not opened");
    }

    out.write(reinterpret_cast<char*>(&file_header), sizeof(BmpFileHeader));
    out.write(reinterpret_cast<char*>(&info_header), sizeof(BmpInfoHeader));

    if(data.size() != pixel_data.size())
    {
        throw std::runtime_error("Size of pixel data != original pixel data size");
    }

    out.write(reinterpret_cast<char*>(data.data()), data.size());

    out.close();
}

void BmpReader::encrypt_bmp(const std::string &input, const std::string &output, size_t block_size, Key &key)
{
    read_data(input);
    FEAL_crypt encrypter(32, key);

    Block key_block;

    for (size_t i = 0; i < key.size(); ++i)
    {
        key_block.push_back(key[i]);
    }

    for (size_t i = 0; i < pixel_data.size(); i+=block_size)
    {
        Block block(pixel_data.begin() + i, pixel_data.begin() + std::min(i + block_size, pixel_data.size()));
        
        encrypter.encrypt(block);

        std::copy(block.begin(), block.end(), pixel_data.begin() + i);


    }
    rewrite_bmp(output, pixel_data);
}

void BmpReader::decrypt_bmp(const std::string &input, const std::string &output, size_t block_size, Key &key)
{

    read_data(input);

    FEAL_crypt decryptor(32, key);

    Block key_block;


    for (size_t i = 0; i < key.size(); ++i)
    {
        key_block.push_back(key[i]);
    }

    for (size_t i = 0; i < pixel_data.size(); i += block_size)
    {
        Block block(pixel_data.begin() + i, pixel_data.begin() + std::min(i + block_size, pixel_data.size()));
        
        decryptor.decrypt(block);

        std::copy(block.begin(), block.end(), pixel_data.begin() + i);
    }
    
    rewrite_bmp(output, pixel_data);
}


void BmpReader::encrypt_bmp_cbc(const std::string &input, const std::string &output, size_t block_size, Key &key, Block& iv, size_t corrupt_byte_idx, Tests tests)
{
    read_data(input);

    std::string out1 = "brightness_before_encryption.csv";
    get_brightness(out1);

    FEAL_crypt encrypter(32, key);
    
    Block key_block;

    for (size_t i = 0; i < key.size(); ++i)
    {
        key_block.push_back(key[i]);
    }

    std::vector<std::vector<int>> bit_change;

    for (size_t i = 0; i < pixel_data.size(); i+=block_size)
    {
        Block block(pixel_data.begin() + i, pixel_data.begin() + std::min(i + block_size, pixel_data.size()));
        Block previous_block = block;

        encrypter.encrypt_cbc_dop(block, iv, bit_change);

        std::copy(block.begin(), block.end(), pixel_data.begin() + i);
        
        std::cout << "Block №: " << i / 8 << "\n";
        tests.frequency_test(block);
        tests.sequence_test(block);
        tests.poker_test(block, 8);
        tests.series_test(block, 8);
        tests.autocorrelation_test(block, 8);
        std::cout << std::endl;

    }

    std::string out2 = "brightness_after_encryption.csv";
    get_brightness(out2);

    std::ofstream histogram("bit_change_hist.csv");
    if (!histogram.is_open()) throw std::runtime_error("failed");

    histogram << "block,bits\n";
    for (size_t block_idx = 0; block_idx < bit_change.size(); ++block_idx)
    {
        for (size_t round_idx = 0; round_idx < bit_change[block_idx].size(); ++round_idx)
        {
            histogram << block_idx / 8 << "," << bit_change[block_idx][round_idx] << "\n";
        }
    }

    histogram.close();

    if (corrupt_byte_idx < pixel_data.size()) 
    {
        pixel_data[corrupt_byte_idx] = ~pixel_data[corrupt_byte_idx];  
    }

    rewrite_bmp(output, pixel_data);
}

void BmpReader::decrypt_bmp_cbc(const std::string &input, const std::string &output, size_t block_size, Key &key, Block& iv, size_t corrupt_byte_idx)
{

    read_data(input);

    FEAL_crypt decryptor(32, key);

    Block key_block;


    for (size_t i = 0; i < key.size(); ++i)
    {
        key_block.push_back(key[i]);
    }

    for (size_t i = 0; i < pixel_data.size(); i += block_size)
    {
        Block block(pixel_data.begin() + i, pixel_data.begin() + std::min(i + block_size, pixel_data.size()));
        
        decryptor.decrypt_cbc(block, iv);

        std::copy(block.begin(), block.end(), pixel_data.begin() + i);
    }
    
    rewrite_bmp(output, pixel_data);
}

void BmpReader::get_brightness(std::string& filename)
{
    int width = info_header.width;
    int height = info_header.height;

    int row_padding = (4 - (width * 3) % 4 ) % 4;

    std::map<int, int> brightness_hist;

    for (int y = 0; y < height; ++y)
    {
        for (int x = 0; x < width; ++x)
        {
            int idx = (y * (width * 3 + row_padding)) + (x * 3);
            byte blue = pixel_data[idx];
            byte green = pixel_data[idx + 1];
            byte red = pixel_data[idx + 2];

            int brightness = static_cast<int>(0.2126 * red + 0.7152 * green + 0.0722 * blue);
            brightness_hist[brightness]++; 
        }
    }

    std::ofstream csv_file(filename);

    if (!csv_file.is_open())
    {
        std::cerr << "Failed to create CSV file!" << std::endl;
        return;
    }

    csv_file << "Brightness,Count\n";

    for (const auto& [brightness, count] : brightness_hist)
    {
        csv_file << brightness << "," << count << "\n";
    }

    csv_file.close();

    std::cout << "Brightness histogram exported to brightness_histogram.csv" << std::endl;
}
} 