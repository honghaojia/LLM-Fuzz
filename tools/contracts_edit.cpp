#include <iostream>
#include <string>
#include <curl/curl.h>
#include "json.hpp"
#include <regex>
#include <unordered_map>
#include <exception>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <cstdlib> // For system() function call

namespace fs = std::filesystem; // Use the filesystem library

using json = nlohmann::json;

size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* response) {
    size_t totalSize = size * nmemb;
    response->append((char*)contents, totalSize);
    return totalSize;
}

std::string remove_comments(const std::string& input) {
    std::string no_comments = input;

    // Match and remove single-line comments (//...)
    std::regex single_line_comment_regex(R"(//.*?$)", std::regex_constants::multiline);
    no_comments = std::regex_replace(no_comments, single_line_comment_regex, "");

    // Match and remove multi-line comments (/*...*/)
    std::regex multi_line_comment_regex(R"(/\*[\s\S]*?\*/)");
    no_comments = std::regex_replace(no_comments, multi_line_comment_regex, "");

    return no_comments;
}

std::string readSolFile(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        throw std::runtime_error("Can't open file: " + filePath);
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    file.close();
    std::string content = buffer.str();
    
    // Remove comments
    content = remove_comments(content);
    
    content.erase(std::remove(content.begin(), content.end(), '\n'), content.end());
    content.erase(std::remove(content.begin(), content.end(), '\r'), content.end());
    std::replace(content.begin(), content.end(), '\"', '\'');
    return content;
}

void clearDirectory(const std::string& directory) {
    // Check if the directory exists
    if (fs::exists(directory)) {
        // Iterate through all files and subdirectories and remove them
        for (const auto& entry : fs::directory_iterator(directory)) {
            fs::remove_all(entry.path());
        }
    } else {
        // If the directory does not exist, create it
        fs::create_directory(directory);
    }
}

// Generate results using ChatGPT API
std::string generateResponse_chatgpt(const std::string& user_input) {
    CURL* curl;
    CURLcode res;
    std::string response;
    std::string content = "";

    // Initialize curl
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl) {
        // Set URL and request headers
        std::string url = "https://api.gptsapi.net/v1/chat/completions";
        std::string api_key = "Your API Key"; // Replace YOUR_API_KEY with the actual API key
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, ("Authorization: Bearer " + api_key).c_str());

        // Set POST data
        std::string json_data = R"({
            "model": "gpt-4o",
            "messages": [
                {
                    "role": "user",
                    "content": ")" + user_input + R"("
                }
            ]
        })";

        // Set curl options
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data.c_str());

        // Set callback function to receive the response
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        // Execute the request
        res = curl_easy_perform(curl);

        // Check for errors
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        } else {
            // Parse the JSON response
            try {
                auto jsonResponse = nlohmann::json::parse(response);

                // Extract the content part
                content = jsonResponse["choices"][0]["message"]["content"];
            } catch (const std::exception& e) {
                std::cerr << "Error parsing JSON: " << e.what() << std::endl;
            }
        }

        // Cleanup
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
    return content;
}

// Generate results using Claude API
std::string generateResponse_claude(const std::string& user_input) {
    CURL* curl;
    CURLcode res;

    // Create a string to store the server response
    std::string response;
    std::string content = "";

    // API URL and API key (replace $API_KEY with your actual API key)
    std::string api_url = "https://api.gptsapi.net/v1/chat/completions";
    std::string api_key = "Your API Key";  // Replace YOUR_API_KEY with the actual API key

    // Data to send
    std::string json_data = R"({
        "model": "claude-3-haiku-20240307",
        "messages": [
            {
                "role": "system",
                "content": "You are a smart contract analysis expert."
            },
            {
                "role": "user",
                "content":  ")" + user_input + R"("
            }
        ]
    })";

    // Initialize libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl) {
        // Set URL
        curl_easy_setopt(curl, CURLOPT_URL, api_url.c_str());

        // Set HTTP headers, including authorization and content type
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, ("Authorization: " + api_key).c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // Set POST data
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data.c_str());

        // Set callback function to capture response data
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        // Execute the request
        res = curl_easy_perform(curl);

        // Check for errors
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        } else {
            // Parse the JSON response
            try {
                auto jsonResponse = nlohmann::json::parse(response);

                // Extract the content part
                content = jsonResponse["choices"][0]["message"]["content"];
            } catch (const std::exception& e) {
                std::cerr << "Error parsing JSON: " << e.what() << std::endl;
            }
        }

        // Cleanup
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }

    curl_global_cleanup();
    return content;
}



std::vector<std::string> extract_all_contract_codes(const std::string& result) {
    std::vector<std::string> contracts;
    size_t start_pos = 0;
    bool pragma_added = false; // Flag to indicate if pragma has been added

    // Use regular expressions to match each contract, interface, or library declaration
    std::regex contract_regex("(contract\\s+[a-zA-Z0-9_]+|interface\\s+[a-zA-Z0-9_]+|library\\s+[a-zA-Z0-9_]+)");
    std::smatch match;

    while (std::regex_search(result.begin() + start_pos, result.end(), match, contract_regex)) {
        // Find the start position of the next contract, interface, or library
        size_t contract_pos = match.position(0) + start_pos;

        // Find the end of the block, matching content within {}
        size_t open_brace_pos = result.find('{', contract_pos);
        if (open_brace_pos == std::string::npos) break;  // No opening brace found

        int brace_count = 1;
        size_t i = open_brace_pos + 1;
        while (brace_count > 0 && i < result.size()) {
            if (result[i] == '{') brace_count++;
            else if (result[i] == '}') brace_count--;
            i++;
        }

        // Extract the complete contract, interface, or library code
        std::string contract_code = result.substr(contract_pos, i - contract_pos);

        // If pragma has not been added, add it to the first contract, interface, or library
        if (!pragma_added) {
            size_t pragma_pos = result.find("pragma");
            if (pragma_pos != std::string::npos && pragma_pos < contract_pos) {
                std::string pragma_line = result.substr(pragma_pos, result.find(';', pragma_pos) + 1 - pragma_pos);
                contract_code = pragma_line + "\n" + contract_code;
            }
            pragma_added = true;
        }

        // Add the extracted contract, interface, or library code to the contracts list
        contracts.push_back(contract_code);

        // Update the search starting position
        start_pos = i;
    }

    return contracts;  // Return all extracted contracts, interfaces, and libraries
}

// Compile the contract and check if it succeeds, print compile error log
bool compileContract(const std::string& contractFilePath) {
    std::string command = "solc --bin --abi " + contractFilePath + " 2> compile_errors.log";
    int result = system(command.c_str()); // Call solc to compile the contract and redirect errors to log file
    
    if (result != 0) {
        // Print the compile error log content
        std::ifstream errorLog("compile_errors.log");
        if (errorLog.is_open()) {
            std::string line;
            std::cout << "Compilation errors for contract: " << contractFilePath << std::endl;
            while (std::getline(errorLog, line)) {
                std::cerr << line << std::endl;
            }
            errorLog.close();
        }
    }
    
    return result == 0; // Return compile result (0 means success)
}

void processContracts(const std::string& model_type) {
    std::string source_directory = "../rename_contracts"; // Source directory for reading contracts
    std::string target_directory = "../contracts";        // Target directory for output contracts
    std::vector<std::string> failed_contracts;            // To store contract file names that failed to compile

    // Iterate through each contract file in the source directory (no additional layer of subdirectory traversal)
    for (const auto& contract_entry : fs::directory_iterator(source_directory)) {
        if (contract_entry.is_regular_file() && contract_entry.path().extension() == ".sol") {
            std::string contract_name = contract_entry.path().filename().string();
            std::string contract_content = readSolFile(contract_entry.path().string());

            std::cout << "Processing contract: " << contract_name << std::endl;

            // Check if the target directory already contains the contract
            std::string output_path = target_directory + "/" + contract_name;
            if (fs::exists(output_path)) {
                std::cout << "Contract " << contract_name << " already exists in target folder. Skipping...\n";
                continue; // Skip if the contract already exists in the target directory
            }

            bool success = false;
            std::string prompt = "Please help me modify the following Solidity smart contract by adding an `emit` event after each logical branch. "
                                 "For each `emit` event, also declare the corresponding `event` at the beginning of the contract. "
                                 "Ensure the contract is complete and can compile without errors. Here is the original contract code:" + contract_content;

            int edit_attempts = (model_type == "chatglm" || model_type == "llama") ? 10 : 3;

            for (int i = 0; i < edit_attempts; i++) {
                // Call the LLM API to generate modified contract code
                std::string result = generateResponse_claude(prompt);
                std::cout << "Attempt " << (i + 1) << ": LLM Response: " << result << std::endl;

                std::vector<std::string> modified_contracts = extract_all_contract_codes(result);

                // Concatenate multiple contracts into a single string
                std::string content;
                for (const auto& contract : modified_contracts) {
                    content += contract + "\n";
                }

                std::cout << "生成的合约内容:\n" << content << std::endl;


                if (!modified_contracts.empty()) {
                    std::ofstream outfile(output_path);
                    if (outfile.is_open()) {
                        outfile << content;
                        outfile.close();
                        std::cout << "Contract " << contract_name << " written to file." << std::endl;

                        // Attempt to compile the generated contract
                        if (compileContract(output_path)) {
                            std::cout << "Contract " << contract_name << " compiled successfully!\n";
                            success = true; // Contract successfully generated and compiled
                            break;          // Exit loop on success
                        } else {
                            std::cerr << "Failed to compile contract: " << contract_name << "\n";
                            failed_contracts.push_back(contract_name);

                            // **Delete the failed contract file**
                            if (fs::exists(output_path)) {
                                fs::remove(output_path);
                                std::cout << "Deleted failed contract file: " << output_path << "\n";
                            }
                        }
                    } else {
                        std::cerr << "Unable to write to file: " << output_path << "\n";
                        failed_contracts.push_back(contract_name);
                    }
                } else {
                    std::cerr << "Failed to extract contract code for: " << contract_name << "\n";
                    failed_contracts.push_back(contract_name);
                }
            }
        }
    }

    // Print all contract file names that failed to compile
    if (!failed_contracts.empty()) {
        std::cerr << "\nThe following contracts failed to compile:\n";
        for (const auto& failed_contract : failed_contracts) {
            std::cerr << failed_contract << std::endl;
        }
    }
}

int main() {
    processContracts("chatgpt");
    return 0;
}
