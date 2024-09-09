#include "funcs.h"
#include <fstream>
#include <sstream>


int main()
{
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
    } while (open_text.size() < (m * s * p));

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

    return 0;
}