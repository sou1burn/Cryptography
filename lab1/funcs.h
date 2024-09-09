#ifndef funcs_h
#define funcs_h
#pragma once
#include <string>
#include <vector>
#include <algorithm>
#include <iostream>

std::string encrypt(std::string& open_text, std::vector<size_t>& key);

std::string decrypt(std::string& secret_text, std::vector<size_t>& key);

#endif