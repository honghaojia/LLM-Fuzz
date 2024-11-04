#ifndef CORPUS_GENERATE_H
#define CORPUS_GENERATE_H

#include <iostream>
#include <string>
#include <curl/curl.h>
#include "json.hpp"
#include <regex>
#include <unordered_map>
#include <exception>

// 使用 nlohmann::json
using json = nlohmann::json;

// 回调函数，用于处理 CURL 的写操作
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* response);

// 使用llama生成响应函数
std::string generateResponse_llama(const std::string& user_input);

// 从大语言模型的 response 中提取测试用例
std::string corpusExtract(std::string& llm_response, std::string& contract_api);

// 从大语言模型的 response 中提取参数描述
std::string descriptionExtract(std::string& llm_response, std::string& contract_api);

// 生成最终的 corpus
//std::string corpus_generate(std::string& contract_api, std::string& type_name, int& byte_len,std::string& api_explanation);

// 从大语言模型的 response 中提取参数描述
//std::string Sigdescription(std::string& contract_api);

//从大语言模型中生成函数执行顺序
std::vector<std::string> generateExecutionOrder(std::string& filepath, std::string& contractAPI, const std::vector<std::string>& existingOrders);

//从大语言模型返回结果提取合约内容
std::string extract_contract_code(const std::string& response);

//从大语言模型根据日志信息返回新测试用例
std::string log_based_feedback(std::string& logs, std::string& filepath, const std::string& execution_order,std::string current_test_case,const std::string& stateFds,const std::string& remind);

//使用chatgpt生成响应函数
std::string generateResponse_chatgpt(const std::string& user_input);

//使用claude生成响应函数
std::string generateResponse_claude(const std::string& user_input);

//使用大语言模型返回随机
std::string new_corpus_random(std::string& filepath, std::string& execution_order);

#endif // CORPUS_GENERATE_H
