#include "funcs.h"

std::string encrypt(std::string &text, std::vector<size_t> &key)
{

    size_t m = key[0];
    size_t s = key[1];
    size_t p = key[2];
    
    std::vector<std::vector<std::string>> matrix(m, std::vector<std::string>(s, std::string(p, ' ')));

    size_t idx = 0;

    for (size_t i = 0; i < m; ++i)
    {
        for (size_t j = 0; j < s; ++j)
        {
            for (size_t k = 0; k < p && idx < text.size(); ++k)
            {
                matrix[i][j][k] = text[idx++];
            }
        }
    }

    std::cout << "\nМатрица после заполнения текстом:\n";
    for (size_t i = 0; i < m; ++i)
    {
        for (size_t j = 0; j < s; ++j)
        {
            std::cout << matrix[i][j] << " ";
        }
        std::cout << std::endl;
    }

    std::string encrypted_text = "";
    idx = 0;

    for (size_t j = 0; j < s; ++j)
    {
        for (size_t i = 0; i < m; ++i)
        {
            for (size_t k = 0; k < p && idx < text.size(); ++k)
            {
                encrypted_text += matrix[i][j][k];
            }
        }
    }

    std::cout << "Your entered string: \n"
              << text << "\nYour encrypted string: \n"
              << encrypted_text << "\n";

    return encrypted_text;
}

/*съешь_ещё_этих_румяных_булочек
tralivali*/
/* t r a 
   l i v
   a l i
   
tlarilavi*/
std::string decrypt(std::string &encrypted_text, std::vector<size_t> &key)
{

    size_t m = key[0];
    size_t s = key[1];
    size_t p = key[2];
    std::vector<std::vector<std::string>> matrix(m, std::vector<std::string>(s, std::string(p, ' ')));

    size_t idx = 0;

    std::string decrypted_text = "";

    for (size_t j = 0; j < s; ++j)
    {
        for (size_t i = 0; i < m; ++i)
        {
            for (size_t k = 0; k < p && idx < encrypted_text.size(); ++k)
            {
                matrix[i][j][k] = encrypted_text[idx++];
            }
        }
    }

    std::cout << "\nМатрица после заполнения текстом:\n";
    for (size_t i = 0; i < m; ++i)
    {
        for (size_t j = 0; j < s; ++j)
        {
            std::cout << matrix[i][j] << " ";
        }
        std::cout << std::endl;
    }

    idx = 0;

    for (size_t i = 0; i < m; ++i)
    {
        for (size_t j = 0; j < s; ++j)
        {
            for (size_t k = 0; k < p &&idx < encrypted_text.size(); ++k)
            {
                decrypted_text += matrix[i][j][k];
            }
        }
    }

    std::cout << "Your entered string: \n"
              << encrypted_text << "\nYour decrypted string: \n"
              << decrypted_text << "\n";

    return decrypted_text;
}