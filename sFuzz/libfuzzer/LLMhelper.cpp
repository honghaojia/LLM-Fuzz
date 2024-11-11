#include <iostream>
#include <string>
#include <curl/curl.h>
#include "json.hpp"
#include <regex> 
#include <unordered_map>
#include <exception>
#include <fstream>
#include <sstream>

// Cache structure
std::unordered_map<std::string, std::string> contractCache;

using json = nlohmann::json;

size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* response) {
    size_t totalSize = size * nmemb;
    response->append((char*)contents, totalSize);
    return totalSize;
}

std::string cleanJsonString(const std::string& responseStr) {
    std::string cleanedStr = responseStr;
    
    // Remove trailing period
    if (!cleanedStr.empty() && cleanedStr.back() == '.') {
        cleanedStr.pop_back();
    }
    
    // Clean up the JSON object and replace single quotes with double quotes
    std::string result;
    bool inQuotes = false;
    for (char c : cleanedStr) {
        if (c == '"') {
            inQuotes = !inQuotes; // Toggle quote state
        }
        if (c == '\'') {
            result += '"';  // Replace single quotes with double quotes
        } else {
            result += c;
        }
    }

    // Remove trailing spaces and extra characters from the JSON string
    result.erase(result.find_last_not_of(" \t\r\n") + 1);

    return result;
}

std::string readSolFileWithCache(const std::string& filePath) {
    // Check if the file is already cached
    if (contractCache.find(filePath) != contractCache.end()) {
        return contractCache[filePath];  // Return cached contract content
    }

    // File not cached, read the file
    std::ifstream file(filePath);
    if (!file.is_open()) {
        //throw std::runtime_error("can't open file " + filePath);
    }

    // Read file content using stringstream
    std::stringstream buffer;
    buffer << file.rdbuf();

    // Close the file
    file.close();

    // Convert the buffer content to a string
    std::string content = buffer.str();

    // Remove all newline and carriage return characters
    content.erase(std::remove(content.begin(), content.end(), '\n'), content.end());
    content.erase(std::remove(content.begin(), content.end(), '\r'), content.end());

    // Replace all double quotes with single quotes
    std::replace(content.begin(), content.end(), '\"', '\'');

    // Store the processed content in the cache
    contractCache[filePath] = content;

    // Return the processed string
    return content;
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

    if(curl) {
        // Set URL and request headers
        std::string url = "https://api.gptsapi.net/v1/chat/completions";
        std::string api_key = "Your API Key"; // Replace YOUR_API_KEY with the actual API key
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, ("Authorization: Bearer " + api_key).c_str());

        // Set POST data
        std::string json_data = R"({
            "model": "gpt-4",
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
        if(res != CURLE_OK) {
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
    std::string content = "";

    // Create a string to store the server response
    std::string response;

    // API URL and API key (ensure to replace $API_KEY with your actual API key)
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
        if(res != CURLE_OK) {
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

std::vector<std::string> extractFunctionOrder(const std::string& text) {
    std::vector<std::string> functionOrder;

    // Regular expression pattern to match numeric sequences in the form of 1->2->3
    std::regex arrowPattern(R"((?:\d+\s*->\s*)+\d+)");
    std::smatch matches;

    // Debug print the original text
    // std::cout << "original answer: " << text << std::endl;

    if (std::regex_search(text, matches, arrowPattern)) {
        // std::cout << "match text: " << matches[0] << std::endl;

        std::string result = matches[0].str();

        // Split by the arrow delimiter
        std::string delimiter = "->";
        size_t pos = 0;
        std::string token;
        std::string resultWithoutSpaces;

        // Remove extra spaces
        result.erase(std::remove(result.begin(), result.end(), ' '), result.end());

        // Split and store into the function order array
        while ((pos = result.find(delimiter)) != std::string::npos) {
            token = result.substr(0, pos);
            functionOrder.push_back(token);
            result.erase(0, pos + delimiter.length());
        }
        // Add the last token
        functionOrder.push_back(result);

        return functionOrder;
    }

    return functionOrder;
}

std::vector<std::string> generateExecutionOrder(std::string& filepath, std::string& contractAPI, const std::vector<std::string>& existingOrders) {
    std::string contractContent = "";
    
    try {
        // Call readSolFileWithCache function to read Solidity contract file
        contractContent = readSolFileWithCache(filepath);
    } catch(const std::exception& e) {
        std::cerr <<"error:" <<e.what() <<std::endl;
    };
    
    std::string prompt = std::string("I will provide a smart contract source code. Our task is to analyze the dependencies and call logic of each function in the contract.") +
                        "Based on the code, return a reasonable function execution order of the functions list I give you." +
                        "Please generate a reasonable function execution order list based on the function implementation and " + 
                        "call relationship in the contract. The output format is a string separated by commas for each function name, " +
                        "for example: `1->2->3`, which means that function 1 is executed first, then 2, and finally 3." +
                        "Please note:" +
                        "1. There may be dependencies between functions. Please reflect this dependency in the returned order." +
                        "2. If there are multiple reasonable orders, please return one of them." +
                        "3. Please add terms 'The orders are:' before orders.";

    // Check if existingOrders is not empty
    if (!existingOrders.empty()) {
        // Merge existing execution order list into a string
        std::string existingOrdersStr = "The existing function execution orders are: ";
        for (const auto& order : existingOrders) {
            existingOrdersStr += order + "; ";
        }

        // Add requirement for Levenshtein distance
        prompt += std::string("4. Ensure that the generated order has a Levenshtein distance of at least 2 from all existing execution orders.") +
                  " Here are the existing execution orders: " + existingOrdersStr;
    }
    
    prompt += std::string("The following is the source code of the smart contract:") +
              "```"+contractContent+"```" +
              "Using this information, do not provide suggestions or explanations. " +
              "Please simply return a list of function execution orders for the following functions I give you: " + contractAPI;
  
    // std::cout << "prompt:" << prompt << std::endl;
  
    std::string result = generateResponse_claude(prompt);
    
    // std::cout << "answer: " << result << std::endl;
    
    std::vector<std::string> order = extractFunctionOrder(result);
    
    return order;
}

// Generate random corpus based on logs
std::string log_based_feedback(std::string& logs, std::string& filepath, const std::string& execution_order, std::string current_test_case, const std::string& stateFds, const std::string& remind) {
    std::string contractContent = "";
      
    try {
        // Call readSolFileWithCache function to read Solidity contract file
        contractContent = readSolFileWithCache(filepath);
    } catch(const std::exception& e) {
        std::cerr <<"error:" <<e.what() <<std::endl;
    };

    // std::cout << "logs: " << logs << std::endl;
   
    std::string generate_prompt = std::string("I am conducting fuzz testing on a smart contract and need suggestions on which parameters of ") +
    "multiple state functions should be mutated based on execution logs. I have inserted custom events into each " +
    "branch of the contract and recorded which events were triggered during execution. Please analyze the logs " +
    "and the smart contract functions to provide mutation suggestions for each function and its parameters. " +
    "The logs from a recent contract execution are: " + logs + 
    ". The functions within the contract were executed in the following order: " + execution_order + 
    ". The current test case that was used to trigger this execution sequence is as follows: " + current_test_case + 
    ". The smart contract is as follows: " + contractContent + 
    " Please use the exact parameter names from the following state functions to provide mutation suggestions. " +
    "State functions and their parameters are as follows: " + stateFds +
    ". Your result should be in JSON format with the exact function and parameter names. Each parameter should be labeled 'Yes' or 'No' " +
    "indicating whether or not it should be mutated. The JSON format should be: " +
    "{'function_name1': {'parameter_name1': 'Yes','parameter_name2': 'No'},'function_name2': {'parameter_name1': 'Yes','parameter_name2':'No'}}." +
    " If there were issues with previous suggestions, here is the feedback: " + remind + 
    " Please ensure that all functions and their parameters are correctly identified and avoid the issues mentioned above.";

    // std::cout << "corpus generate prompt:" << generate_prompt<< std::endl;
        
    std::string response = generateResponse_claude(generate_prompt);
    response = cleanJsonString(response);
        
    // std::cout << "response:" << response<< std::endl;
        
    return response;
}
