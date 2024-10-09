#include "BMP.h"

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


void BmpReader::rewrite_bmp(const std::string& filename, std::vector<uint8_t> data)
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
        throw std::runtime_error("Size of pizel data != original pixel data size");
    }

    out.write(reinterpret_cast<char*>(data.data()), data.size());

    out.close();
}