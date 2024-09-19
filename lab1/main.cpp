#include "funcs.h"
#include <fstream>
#include <sstream>


int main()
{

    std::map<char, double> letter_frequency = {
        {'E', 12.31}, {'T', 9.59}, {'A', 8.05}, {'O', 7.94}, {'N', 7.19}, {'I', 7.18}, {'S', 6.59},
        {'R', 6.03}, {'H', 5.14}, {'L', 4.03}, {'D', 3.65}, {'C', 3.2}, {'U', 3.1},  {'P', 2.29},
        {'F', 2.28}, {'M', 2.25}, {'W', 2.03}, {'Y', 1.88}, {'B', 1.62}, {'G', 1.61}, {'V', 0.93},
        {'K', 0.52}, {'Q', 0.2},  {'X', 0.2},  {'J', 0.1},  {'Z', 0.09}
    };

    char c;

    std::cout << "Choose how to input a string:\n 1.Read from file \n 2.Input a string from console\n";
    std::cin >> c;
    std::string open_text;
    
    switch (c)
    {
    case '1':
    {
        std::cout << "Enter filename\n";
        std::string filename;
        std::cin >> filename;
        std::ifstream fin(filename);

        if (!fin.is_open())
        {
            std::cerr << "Error while opening file " << filename << "\n";
            return 1;
        }

        std::stringstream ss;
        std::string line;


        while (std::getline(fin, line))
        {
            ss << line << "\n";
        }

        fin.close();
        open_text = ss.str();
        std::cout << "Entered string: "<< open_text << "\n";
        
        break;
    }

    case '2':
    {
        std::cout << "Enter a string: \n";
        std::cin.ignore();

        std::getline(std::cin, open_text);

        std::cout << "Entered string: "<< open_text << "\n";
        break;
    }

    default:
        std::cerr << "No such variant, please try again with 1 or 2\n";
    }

    std::cout << "Choose algorithm:\n 1.Matrix permutation \n 2.Caesar cypher\n";
    char option;
    std::cin >> option;

    switch (option)
    {
    case '1':
    {
        size_t m, s, p;

        do
        {
            std::cout << "Enter number of rows: \n";
            std::cin >> m;
            std::cout << "Enter number of cols: \n";
            std::cin >> s;
            std::cout << "Enter number of letter in a cell: \n";
            std::cin >> p;
            if ((m * s * p) < open_text.size())
            {
                std::cout << "\nWarning! Matrix cannot contain all charachters of your string. Please enter different matrix size >= " << open_text.size() << "\n";
            }
        } while (open_text.size() > (m * s * p));

        std::vector<size_t> key = {m,s,p};

        std::cout << "Now choose option: \n 1.Encrypt \n 2.Decrypt\n";
        char d;
        std::cin >> d;

    
        switch (d)
        {
        case '1':
        {
            std::string encrypted_text = encrypt(open_text, key);

            break;
        }

        case '2':
        {
            std::string decrypted_text = decrypt(open_text, key);

            break;
        }

        default:
            std::cerr << "No such variant, please try again with 1 or 2\n";
        }
        break;
    }
    case '2':
    {   
        std::cout << "\nPlease enter a key \n";
        size_t key;
        std::cin >> key;

        std::cout << "\nNow choose option: \n 1.Encrypt\n 2.Decrypt\n";
        char opt;
        std::cin >> opt;

        switch (opt)
        {
        case '1':
        {
            std::string encrypted_caesar = caesar_cipher_encrypt(open_text, key);
            std::map<char, double> text_freq = frequency_analizer(encrypted_caesar);

            std::string predicted_text = text_prediction(letter_frequency, text_freq, encrypted_caesar);


            break;
        }
        case '2':
        {
            std::string decrypted_caesar = caesar_cipher_decrypt(open_text, key);
            break;
        }
        default:
            break;
        }
        break;
    }

    default:
        std::cerr << "Enter one of the options below!\n";
        break;
    }
    

    return 0;
}