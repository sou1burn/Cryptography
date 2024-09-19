#ifndef funcs_h
#define funcs_h
#pragma once
#include <string>
#include <vector>
#include <algorithm>
#include <iostream>
#include<set>
#include<map>
#include <iomanip>

std::vector<char> create_alph();

std::string encrypt(std::string& open_text, std::vector<size_t>& key);

std::string decrypt(std::string& secret_text, std::vector<size_t>& key);

std::string caesar_cipher_encrypt(std::string open_text, size_t key);

std::string caesar_cipher_decrypt(std::string secret_text, size_t key);

std::map<char, double> frequency_analizer(std::string text);

char find_closest_match(char symbol, std::map<char, double>& letter_freq, double encrypted_freq);

std::string text_prediction(std::map<char, double>& letter_freq, std::map<char, double>& text_freq, std::string& encrypted_text);
#endif