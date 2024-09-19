#include "funcs.h"


std::vector<char> create_alph()
{
    std::vector<char> alphabet;

    for (char i = 'a'; i < 'z'; ++i)
    {
        alphabet.push_back(i);
    }

    for (char i = '0'; i <= '9'; ++i)
    {
        alphabet.push_back(i);
    }

    return alphabet;
}

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


std::string caesar_cipher_encrypt(std::string open_text, size_t key)
{

    std::vector<char> alphabet = create_alph();

    size_t n = alphabet.size();

    if (key > n - 1)
    {
        std::cerr << "\nInvalid key\n";
    }

    std::string encrypted_text = "";

    for (size_t i = 0; i < open_text.size(); ++i)
    {
        char symbol = open_text[i];

        auto it = std::find(alphabet.begin(), alphabet.end(), symbol);

        if (it != alphabet.end())
        {
            size_t idx = std::distance(alphabet.begin(), it);
            size_t new_idx = (idx + n + (key % n)) % n;
            encrypted_text += alphabet[new_idx];
        }
        else{
            encrypted_text += symbol;
        }
        
    }

    std::cout << "Your entered string: \n"
              << open_text << "\nYour decrypted string: \n"
              << encrypted_text << "\n";

    return encrypted_text;

}

std::string caesar_cipher_decrypt(std::string secret_text, size_t key)
{

    std::vector<char> alphabet = create_alph();

    size_t n = alphabet.size();

    if (key > n - 1)
    {
        std::cerr << "\nInvalid key\n";
    }

    std::string decrypted_text = "";

    for (size_t i = 0; i < secret_text.size(); ++i)
    {
        char symbol = secret_text[i];

        auto it = std::find(alphabet.begin(), alphabet.end(), symbol);

        if (it != alphabet.end())
        {
            size_t idx = std::distance(alphabet.begin(), it);
            size_t new_idx = (idx + n - (key % n)) % n;
            decrypted_text += alphabet[new_idx];
        }
        else{
            decrypted_text += symbol;
        }

    }
    
    std::cout << "Your entered string: \n"
              << secret_text << "\nYour decrypted string: \n"
              << decrypted_text << "\n";

    return decrypted_text;
}



std::map<char, double> frequency_analizer(std::string text)
{
    std::map<char, int> freq_map;

    for (char c : text)
    {
        freq_map[c]++;
    }

    int max_val = std::max_element(freq_map.begin(), freq_map.end(),
                                 [](const std::pair<char, int> &a, const std::pair<char, int> &b){return a.second > b.second;})->second;
        
    size_t chars_count = text.length();

    std::map<char, double> percent_map;

    std::cout << "\nHistogram of symbols frequency in encrypted text\n";

    for (const auto& pair : freq_map)
    {
        char symbol = pair.first;
        int count = pair.second;

        percent_map[symbol] = (static_cast<double>(count) / chars_count) * 100;

        std::cout << std::setw(3) << symbol << " : " << std::string(count, '*') << " (" << count << ")\n";
    }

    std::cout << "\nPercentage frequency of symbols in text\n";
    for (const auto &pair : percent_map)
    {
        char symbol = pair.first;
        double percentage = pair.second;

        std::cout << std::setw(3) << symbol << " : " << std::fixed << std::setprecision(2) << percentage << "%\n";
    }

    return percent_map;
}



char find_closest_match(char symbol, std::map<char, double>& letter_freq, double encrypted_freq)
{
    char closest = '\0';

    double min_diff = 100.0;

    for (const auto& pair : letter_freq)
    {
        char known_symbol = pair.first;
        double known_freq = pair.second;

        double diff = std::abs(known_freq - encrypted_freq);

        if (diff < min_diff)
        {
            min_diff = diff;
            closest = known_symbol;
        }
    }
    return closest;
}


std::string text_prediction(std::map<char, double>& letter_freq, std::map<char, double>& text_freq, std::string& encrypted_text)
{

    std::map<char, char> decryption_map;


    for (const auto& pair : text_freq)
    {

        char encrypted_symbol = pair.first;

        double encrypted_freq = pair.second;

        char closest_symbol = find_closest_match(encrypted_symbol, letter_freq, encrypted_freq);

        decryption_map[encrypted_symbol] = closest_symbol;
    }

    std::cout << "\n Decryption map (encrypt -> decrypt):\n";

    for (const auto& pair : decryption_map)
    {
        std::cout << pair.first << " -> " << pair.second << "\n";
    }

    std::cout << "\nDecrypted text using frequency anylisys:\n";

    std::string predicted_text = "";
    
    for (char symbol : encrypted_text)
    {
        if (decryption_map.find(symbol) != decryption_map.end())
        {
            predicted_text += decryption_map[symbol];
            std::cout << decryption_map[symbol];
        }
        else
        {
            predicted_text += symbol;
            std::cout << symbol;
        }
    }
    std::cout << std::endl;

    return predicted_text;
}