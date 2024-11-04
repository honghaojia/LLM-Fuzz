#include <regex>
#include "ContractABI.h"
#include <vector>
#include <string>
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <sstream>

using namespace std;
namespace pt = boost::property_tree;

namespace fuzzer {
  FuncDef::FuncDef(string name, vector<TypeDef> tds, bool payable) {
    this->name = name;
    this->tds = tds;
    this->payable = payable;
  }
  
  FakeBlock ContractABI::decodeBlock() {
    if (!block.size()) throw "Block is empty";
    auto numberInBytes = bytes(block.begin(), block.begin() + 8);
    auto timestampInBytes = bytes(block.begin() + 8, block.begin() + 16);
    auto number = u64("0x" + toHex(numberInBytes));
    auto timestamp = u64("0x" + toHex(timestampInBytes));
    return make_tuple(block, (int64_t)number, (int64_t)timestamp);
  }

  Address ContractABI::getSender() {
    auto accounts = decodeAccounts();
    for (auto account : accounts) {
      if (get<3>(account)) return get<1>(account);
    }
  }

  Accounts ContractABI::decodeAccounts() {
    unordered_set<string> accountSet;
    Accounts ret;
    auto isSender = true;
    for (auto account : accounts) {
      bytes balanceInBytes(account.begin(), account.begin() + 12);
      bytes addressInBytes(account.begin() + 12, account.end());
      u256 balance = u256("0x" + toHex(balanceInBytes));
      u160 address = u160("0x" + toHex(addressInBytes));
      auto pair = accountSet.insert(toHex(addressInBytes));
      if (pair.second) {
        ret.push_back(make_tuple(account, address, balance, isSender));
        isSender = false;
      }
    }
    return ret;
  }
  
  uint64_t ContractABI::totalFuncs() {
    return count_if(fds.begin(), fds.end(), [](FuncDef fd) {
      return fd.name != "";
    });
  }
  
  string ContractABI::toStandardJson() {
    stringstream os;
    pt::ptree funcs;
    pt::ptree root;
    for (auto fd : this->fds) {
      pt::ptree func;
      pt::ptree inputs;
      func.put("name", fd.name);
      for (auto td : fd.tds) {
        pt::ptree input;
        input.put("type", td.name);
        switch (td.dimensions.size()) {
          case 0: {
            input.put("value", "0x" + toHex(td.dt.value));
            break;
          }
          case 1: {
            pt::ptree values;
            for (auto dt : td.dts) {
              pt::ptree value;
              value.put_value("0x" + toHex(dt.value));
              values.push_back(make_pair("", value));
            }
            input.add_child("value", values);
            break;
          }
          case 2: {
            pt::ptree valuess;
            for (auto dts : td.dtss) {
              pt::ptree values;
              for (auto dt : dts) {
                pt::ptree value;
                value.put_value("0x" + toHex(dt.value));
                values.push_back(make_pair("", value));
              }
              valuess.push_back(make_pair("", values));
            }
            input.add_child("value", valuess);
            break;
          }
        }
        inputs.push_back(make_pair("", input));
      }
      func.add_child("inputs", inputs);
      funcs.push_back(make_pair("", func));
    }
    root.add_child("functions", funcs);
    /* Accounts */
    unordered_set<string> accountSet; // to check exists
    pt::ptree accs;
    auto accountInTuples = decodeAccounts();
    for (auto account : accountInTuples) {
      auto accountInBytes = get<0>(account);
      auto balance = get<2>(account);
      auto address = bytes(accountInBytes.begin() + 12, accountInBytes.end());
      pt::ptree acc;
      acc.put("address", "0x" + toHex(address));
      acc.put("balance", balance);
      accs.push_back(make_pair("", acc));
    }
    root.add_child("accounts", accs);
    pt::write_json(os, root);
    return os.str();
  }
  /*
   * Validate generated data before sending it to vm
   * msg.sender address can not be 0 (32 - 64)
   */
  bytes ContractABI::postprocessTestData(bytes data) {
    auto sender = u256("0x" + toHex(bytes(data.begin() + 44, data.begin() + 64)));
    auto balance = u256("0x" + toHex(bytes(data.begin() + 32, data.begin() + 44)));
    if (!balance) data[32] = 0xff;
    if (!sender) data[63] = 0xf0;
    return data;
  }
  
  void ContractABI::updateTestData(bytes data) {
    /* Detect dynamic len by consulting first 32 bytes */
    int lenOffset = 0;
    auto consultRealLen = [&]() {
      int len = data[lenOffset];
      lenOffset = (lenOffset + 1) % 32;
      return len;
    };
    /* Container of dynamic len */
    auto consultContainerLen = [](int realLen) {
      if (!(realLen % 32)) return realLen;
      return (realLen / 32 + 1) * 32;
    };
    /* Pad to enough data before decoding */
    int offset = 96;
    auto padLen = [&](int singleLen) {
      int fitLen = offset + singleLen;
      while ((int)data.size() < fitLen) data.push_back(0);
    };
    block.clear();
    accounts.clear();
    auto senderInBytes = bytes(data.begin() + 32, data.begin() + 64);
    block = bytes(data.begin() + 64, data.begin() + 96);
    accounts.push_back(senderInBytes);
    for (auto &fd : this->fds) {
      for (auto &td : fd.tds) {
        switch (td.dimensions.size()) {
          case 0: {
            int realLen = td.isDynamic ? consultRealLen() : 32;
            int containerLen = consultContainerLen(realLen);
            /* Pad to enough bytes to read */
            padLen(containerLen);
            /* Read from offset ... offset + realLen */
            bytes d(data.begin() + offset, data.begin() + offset + realLen);
            /* If address, extract account */
            if (boost::starts_with(td.name, "address")) {
              accounts.push_back(d);
            }
            td.addValue(d);
            /* Ignore (containerLen - realLen) bytes */
            offset += containerLen;
            break;
          }
          case 1: {
            vector<bytes> ds;
            int numElem = td.dimensions[0] ? td.dimensions[0] : consultRealLen();
            for (int i = 0; i < numElem; i += 1) {
              int realLen = td.isDynamic ? consultRealLen() : 32;
              int containerLen = consultContainerLen(realLen);
              padLen(containerLen);
              bytes d(data.begin() + offset, data.begin() + offset + realLen);
              ds.push_back(d);
              offset += containerLen;
            }
            /* If address, extract account */
            if (boost::starts_with(td.name, "address")) {
              accounts.insert(accounts.end(), ds.begin(), ds.end());
            }
            td.addValue(ds);
            break;
          }
          case 2: {
            vector<vector<bytes>> dss;
            int numElem = td.dimensions[0] ? td.dimensions[0] : consultRealLen();
            int numSubElem = td.dimensions[1] ? td.dimensions[1] : consultRealLen();
            for (int i = 0; i < numElem; i += 1) {
              vector<bytes> ds;
              for (int j = 0; j < numSubElem; j += 1) {
                int realLen = td.isDynamic ? consultRealLen() : 32;
                int containerLen = consultContainerLen(realLen);
                padLen(containerLen);
                bytes d(data.begin() + offset, data.begin() + offset + realLen);
                ds.push_back(d);
                offset += containerLen;
              }
              dss.push_back(ds);
              /* If address, extract account */
              if (boost::starts_with(td.name, "address")) {
                accounts.insert(accounts.end(), ds.begin(), ds.end());
              }
            }
            td.addValue(dss);
            break;
          }
        }
      }
    }
  }
  
  bytes ContractABI::randomTestcase(std::string filepath) {
    /*
     * Random value for ABI
     * | --- dynamic len (32 bytes) -- | sender | blockNumber(8) + timestamp(8) | content |
     */
     
    /*
    bytes ret(32, 5);
    int lenOffset = 0;
    auto consultRealLen = [&]() {
      int len = ret[lenOffset];
      lenOffset = (lenOffset + 1) % 32;
      return len;
    };
    auto consultContainerLen = [](int realLen) {
      if (!(realLen % 32)) return realLen;
      return (realLen / 32 + 1) * 32;
    };
    
    auto hexStringToBytes = [](const std::string& hex, int len) {
      std::vector<uint8_t> bytes;
      std::string hexStr = hex;
      
      //std::cout << "string is :" << hexStr << std::endl;
      
      size_t start = 0;
  
      // 去掉前缀“0x”（如果存在）
      if (hexStr.find("0x") == 0) {
          start = 2;
      }
  
      // 确保输入字符串长度是偶数，如果不是，添加一个零字符
      if ((hexStr.length() - start) % 2 != 0) {
          hexStr += "0";
      }
  
      // 每两个字符转换为一个字节
      try {
          for (size_t i = start; i < hexStr.length(); i += 2) {
              std::string byteString = hexStr.substr(i, 2);
              uint8_t byte = static_cast<uint8_t>(std::stoul(byteString, nullptr, 16));
              bytes.push_back(byte);
          }
      } catch (const std::exception& e) {
          throw std::runtime_error("Error during conversion: " + std::string(e.what()));
      }
  
      // 如果字节数不足len，填充零字节到左边
      if (bytes.size() < static_cast<size_t>(len)) {
          std::vector<uint8_t> paddedBytes(len, 0);  // 创建一个包含零字节的数组
          std::copy(bytes.begin(), bytes.end(), paddedBytes.begin() + (len - bytes.size()));  // 拷贝原始字节数组到右边
          bytes = std::move(paddedBytes);  // 替换原始字节数组
      } else if (bytes.size() > static_cast<size_t>(len)) {
          bytes.resize(len);  // 截取前len个字节
      }
  
      return bytes;
    };
    
    // sender env 
    bytes sender(32, 0);
    bytes block(32, 0);
    ret.insert(ret.end(), sender.begin(), sender.end());
    ret.insert(ret.end(), block.begin(), block.end());
    
    //std::cout << "while generate random corpus the fds size is :" << this->fds.size() << std::endl;
    
    for (auto fd : this->fds) {
    
      std::string contract_api = functionapi(fd.name,fd.tds);
      std::cout << "contract api is:" << contract_api << std::endl;
      //std::string sigexplaination = Sigdescription(const_cast<std::string&>(contract_api));
      
      for (auto td : fd.tds) {
        switch(td.dimensions.size()) {
          case 0: {
            int realLen = td.isDynamic ? consultRealLen() : 32;
            int containerLen = consultContainerLen(realLen);
            int flag = 0;
            std::string testcase = "0";
            bytes data;
            //std::cout << "testcase is generated! which is :" <<testcase <<std::endl;
            while (testcase=="0" && flag<3){
              testcase = corpus_generate(const_cast<std::string&>(contract_api),td.paraname,containerLen,filepath);
              flag++;
            }
            if (flag==3){
              data = bytes(containerLen, 0);
            }else{
              data = hexStringToBytes(testcase,containerLen);
            }
            ret.insert(ret.end(), data.begin(), data.end());
            //std::cout << "current ret value is : " << ret << std::endl;
            break;
          }
          case 1: {
            int numElem = td.dimensions[0] ? td.dimensions[0] : consultRealLen();
            for (int i = 0; i < numElem; i += 1) {
              int realLen = td.isDynamic ? consultRealLen() : 32;
              int containerLen = consultContainerLen(realLen);
              int flag = 0;
              
              std::string testcase = "0";
              bytes data;
              
              while (testcase=="0" && flag<3){
                testcase = corpus_generate(const_cast<std::string&>(contract_api),td.paraname,containerLen,filepath);
                flag++;
              }
              if (flag==3){
                data = bytes(containerLen, 0);
              }else{
                data = hexStringToBytes(testcase,containerLen);
              }
              
              ret.insert(ret.end(), data.begin(), data.end());
            }
            break;
          }
          case 2: {
            int numElem = td.dimensions[0] ? td.dimensions[0] : consultRealLen();
            int numSubElem = td.dimensions[1] ? td.dimensions[1] : consultRealLen();
            for (int i = 0; i < numElem; i += 1) {
              for (int j = 0; j < numSubElem; j += 1) {
                int realLen = td.isDynamic ? consultRealLen() : 32;
                int containerLen = consultContainerLen(realLen);
                int flag = 0;
                
                std::string testcase = "0";
                bytes data;
              
                while (testcase=="0" && flag<3){
                  testcase = corpus_generate(const_cast<std::string&>(contract_api),td.paraname,containerLen,filepath);
                  flag++;
                }
                if (flag==3){
                  data = bytes(containerLen, 0);
                }else{
                  data = hexStringToBytes(testcase,containerLen);
                }
                
                ret.insert(ret.end(), data.begin(), data.end());
              }
            }
            break;
          }
        }
      }
    }
    return ret;
    */
    
    bytes ret(32, 5);
    int lenOffset = 0;
    auto consultRealLen = [&]() {
      int len = ret[lenOffset];
      lenOffset = (lenOffset + 1) % 32;
      return len;
    };
    auto consultContainerLen = [](int realLen) {
      if (!(realLen % 32)) return realLen;
      return (realLen / 32 + 1) * 32;
    };
    /* sender env */
    bytes sender(32, 0);
    bytes block(32, 0);
    ret.insert(ret.end(), sender.begin(), sender.end());
    ret.insert(ret.end(), block.begin(), block.end());
    for (auto fd : this->fds) {
      for (auto td : fd.tds) {
        switch(td.dimensions.size()) {
          case 0: {
            int realLen = td.isDynamic ? consultRealLen() : 32;
            int containerLen = consultContainerLen(realLen);
            bytes data(containerLen, 0);
            ret.insert(ret.end(), data.begin(), data.end());
            break;
          }
          case 1: {
            int numElem = td.dimensions[0] ? td.dimensions[0] : consultRealLen();
            for (int i = 0; i < numElem; i += 1) {
              int realLen = td.isDynamic ? consultRealLen() : 32;
              int containerLen = consultContainerLen(realLen);
              bytes data = bytes(containerLen, 0);
              ret.insert(ret.end(), data.begin(), data.end());
            }
            break;
          }
          case 2: {
            int numElem = td.dimensions[0] ? td.dimensions[0] : consultRealLen();
            int numSubElem = td.dimensions[1] ? td.dimensions[1] : consultRealLen();
            for (int i = 0; i < numElem; i += 1) {
              for (int j = 0; j < numSubElem; j += 1) {
                int realLen = td.isDynamic ? consultRealLen() : 32;
                int containerLen = consultContainerLen(realLen);
                bytes data = bytes(containerLen, 0);
                ret.insert(ret.end(), data.begin(), data.end());
              }
            }
            break;
          }
        }
      }
    }
    return ret;
  }
  
  ContractABI::ContractABI(string abiJson) {
    stringstream ss;
    ss << abiJson;
    pt::ptree root;
    pt::read_json(ss, root);
    for (auto node : root) {
      vector<TypeDef> tds;
      string type = node.second.get<string>("type");
      string constant = "false";
      bool payable = false;
      if (node.second.get_child_optional("constant")) {
        constant = node.second.get<string>("constant");
      }
      if (type == "fallback") {
        if (node.second.get_child_optional("payable")) {
          payable = node.second.get<bool>("payable");
        }
        this->originalFds.push_back(FuncDef("fallback", tds, payable));
      }
      if ((type == "constructor" || type == "function") && constant == "false") {
        auto inputNodes = node.second.get_child("inputs");
        string name = type == "constructor" ? "" : node.second.get<string>("name");
        if (node.second.get_child_optional("payable")) {
          payable = node.second.get<bool>("payable");
        }
        for (auto inputNode : inputNodes) {
          string type = inputNode.second.get<string>("type");
          string name = inputNode.second.get<string>("name","");
          tds.push_back(TypeDef(type,name));
        }
        this->originalFds.push_back(FuncDef(name, tds, payable));
      }
      // 提取事件信息
      if (type == "event") {
          string eventName = node.second.get<string>("name");
          auto inputNodes = node.second.get_child("inputs");
          for (auto inputNode : inputNodes) {
              string type = inputNode.second.get<string>("type");
              string name = inputNode.second.get<string>("name","");
              tds.push_back(TypeDef(type,name));
          }
          // 将提取的事件信息存储在事件定义列表中
          this->events.push_back(EventDef(eventName, tds));
      }
    };
    for(auto event : this->events){
      std::string contract_api = functionapi(event.name,event.tds);
      bytes selector = eventSelector(event.name /* name */, event.tds /* type defs */);
      this->eventHashToSignatureMap[toHex(selector)] = contract_api;
    }
  }
  
  // 创建一个新的排序后的 fds
/*
void ContractABI::reorderFunctions(std::string filepath) {

    // 检查 originalFds 是否为空
    if (this->originalFds.empty() || this->originalFds.size()==1) {
        std::cerr << "No functions to reorder." << std::endl;
        this->fds = std::move(this->originalFds);
        return;
    }
    // 创建一个映射，从函数名到其在 originalFds 中的位置
    std::map<char, FuncDef*> nameToFunction;
    
    std::string _functionAPI = "";
    
    // 初始化字符起始值为 'A'
    char start = 'A';

    // 遍历 originalFds，并进行映射
    for (size_t i = 0; i < this->originalFds.size(); ++i) {
        // 创建映射条目，使用字符作为键，函数地址作为值
        nameToFunction[start + i] = &this->originalFds[i];
        std::string contract_api = functionapi(this->originalFds[i].name,this->originalFds[i].tds);
        
        _functionAPI += std::string(1, start + i) + ":" + contract_api + ",";
    }
    
    std::cout << "the original execution order is  :" << _functionAPI <<std::endl;
    
    std::set<char> expectedKeys;
    std::vector<std::string> order;
    for (size_t i = 0; i < this->originalFds.size(); ++i) {
        expectedKeys.insert('A' + i);
    }
    
    order = generateExecutionOrder(filepath,_functionAPI);
    std::set<char> providedKeys;

    // 提取每个字符串的第一个字符，并插入到 providedKeys
    for (const auto& s : order) {
        if (!s.empty()) {
            providedKeys.insert(s[0]); // key[0] 是字符，作为映射的键
        }
    }

    // 检查是否缺少函数
    if (expectedKeys != providedKeys) {
        std::cout << "The sorted function list is missing some functions." << std::endl;
        // 计算缺失的函数
        std::set<char> missingFunctions;
        std::set_difference(expectedKeys.begin(), expectedKeys.end(), providedKeys.begin(), providedKeys.end(), std::inserter(missingFunctions, missingFunctions.begin()));

        // 将缺失的函数追加到 order 的末尾
        for (char missing : missingFunctions) {
            order.push_back(std::string(1, missing)); // 将字符转换为字符串并追加到 order
            std::cout << "Added missing function: " << missing << std::endl;
        }
    } 
    
    std::vector<FuncDef> newSortedFds;
    
    for (const auto& key : order) {
        auto it = nameToFunction.find(key[0]); // key[0] 是字符，作为映射的键
        if (it != nameToFunction.end()) {
            newSortedFds.push_back(*(it->second));
        } else {
            std::cerr << "Function " << key << " not found in fds." << std::endl;
        }
    }

    // 替换旧的 fds
    this->fds = std::move(newSortedFds);
    
    _functionAPI = "";
    char _start = 'A';
    
    for(auto i=0;i<this->fds.size();i++){
        std::string contract_api = functionapi(this->fds[i].name,this->fds[i].tds);
        _functionAPI += std::string(1, _start + i) + ":" + contract_api + ".";
    }
    std::cout << "new function execution order  is :" << _functionAPI <<std::endl;
}
*/

std::string ContractABI::generateFunctionAPIs(std::string contractName) {
    if (this->originalFds.empty()) {
        std::cerr << "No functions to process." << std::endl;
        return "";
    }

    std::string functionAPIs = "";

    // 初始化字符起始值为 '1'
    int start = 1;

    // 遍历 originalFds 并将其 API 拼接
    for (size_t i = 0; i < this->originalFds.size(); ++i) {
        std::string contract_api;
        if (this->originalFds[i].name == ""){
          contract_api = functionapi(contractName, this->originalFds[i].tds);
        }else{
          contract_api = functionapi(this->originalFds[i].name, this->originalFds[i].tds);
        }
        // 拼接函数执行顺序字符串，格式为 '1:contract_api,2:contract_api,...'
        functionAPIs += std::to_string(start + i) + ":" + contract_api + ",";
    }

    // 移除最后一个逗号
    if (!functionAPIs.empty()) {
        functionAPIs.pop_back();
    }

    // 输出生成的 functionAPIs
    //std::cout << "Generated Function APIs: " << functionAPIs << std::endl;

    return functionAPIs;
}

void ContractABI::setExecutionOrder(const std::vector<std::string>& order) {
    if (this->originalFds.empty()) {
        std::cerr << "No functions to reorder." << std::endl;
        return;
    }

    // 创建一个映射，从函数名到原始 fds 中的位置
    std::map<std::string, FuncDef*> nameToFunction;

    // 遍历 originalFds，并进行映射
    for (size_t i = 0; i < this->originalFds.size(); ++i) {
        // 使用数字字符串作为键，函数地址作为值
        nameToFunction[std::to_string(i + 1)] = &this->originalFds[i];
    }

    // 根据传入的 order 重新构建 fds
    std::vector<FuncDef> newSortedFds;
    for (const auto& fnName : order) {
        auto it = nameToFunction.find(fnName);
        if (it != nameToFunction.end()) {
            newSortedFds.push_back(*(it->second));
        } else {
            std::cerr << "Function " << fnName << " not found in originalFds." << std::endl;
        }
    }

    // 替换旧的 fds
    this->fds = std::move(newSortedFds);

    // 输出新的执行顺序
    std::cout << "New function execution order is set." << std::endl;
}



// 获取当前的函数执行顺序
std::string ContractABI::executionOrder() {
    std::string order = "";
    for (const auto& fd : this->fds) {
        std::string contract_api = functionapi(fd.name, fd.tds);
        order += contract_api + "->";
    }
    // 移除最后的 '->'
    if (!order.empty()) {
        order.pop_back();
        order.pop_back();
    }
    return order;
}
  
  
  bytes ContractABI::encodeConstructor() {
  
    //std::cout << "while encode constructor the size of fds is :" << this->fds.size() << std::endl;
    
    auto it = find_if(fds.begin(), fds.end(), [](FuncDef fd) { return fd.name == "";});
    if (it != fds.end()) return encodeTuple((*it).tds);
    return bytes(0, 0);
  }
  
  bool ContractABI::isPayable(string name) {
    for (auto fd : fds) {
      if (fd.name == name) return fd.payable;
    }
    return false;
  }
  
  vector<bytes> ContractABI::encodeFunctions() {
    vector<bytes> ret;
    
    //std::cout << "while encode functionsthe the size of fds is :" << this->fds.size() << std::endl;
    
    for (auto fd : this->fds) {
      if (fd.name != "") {
        bytes selector = functionSelector(fd.name /* name */, fd.tds /* type defs */);
        bytes data = encodeTuple(fd.tds);
        selector.insert(selector.end(), data.begin(), data.end());
        ret.push_back(selector);
      }
    }
    return ret;
  }
  
  bytes ContractABI::functionSelector(string name, vector<TypeDef> tds) {
    vector<string> argTypes;
    transform(tds.begin(), tds.end(), back_inserter(argTypes), [](TypeDef td) {
      return td.fullname;
    });
    string signature = name + "(" + boost::algorithm::join(argTypes, ",") + ")";
    bytes fullSelector = sha3(signature).ref().toBytes();
    return bytes(fullSelector.begin(), fullSelector.begin() + 4);
  }
  
  bytes ContractABI::encodeTuple(vector<TypeDef> tds) {
    bytes ret;
    /* Payload */
    bytes payload;
    vector<int> dataOffset = {0};
    for (auto td : tds) {
      if (td.isDynamic || td.isDynamicArray || td.isSubDynamicArray) {
        bytes data;
        switch (td.dimensions.size()) {
          case 0: {
            data = encodeSingle(td.dt);
            break;
          }
          case 1: {
            data = encodeArray(td.dts, td.isDynamicArray);
            break;
          }
          case 2: {
            data = encode2DArray(td.dtss, td.isDynamicArray, td.isSubDynamicArray);
            break;
          }
        }
        dataOffset.push_back(dataOffset.back() + data.size());
        payload.insert(payload.end(), data.begin(), data.end());
      }
    }
    /* Calculate offset */
    u256 headerOffset = 0;
    for (auto td : tds) {
      if (td.isDynamic || td.isDynamicArray || td.isSubDynamicArray) {
        headerOffset += 32;
      } else {
        switch (td.dimensions.size()) {
          case 0: {
            headerOffset += encodeSingle(td.dt).size();
            break;
          }
          case 1: {
            headerOffset += encodeArray(td.dts, td.isDynamicArray).size();
            break;
          }
          case 2: {
            headerOffset += encode2DArray(td.dtss, td.isDynamicArray, td.isSubDynamicArray).size();
            break;
          }
        }
      }
    }
    bytes header;
    int dynamicCount = 0;
    for (auto td : tds) {
      /* Dynamic in head */
      if (td.isDynamic || td.isDynamicArray || td.isSubDynamicArray) {
        u256 offset = headerOffset + dataOffset[dynamicCount];
        /* Convert to byte */
        for (int i = 0; i < 32; i += 1) {
          byte b = (byte) (offset >> ((32 - i - 1) * 8)) & 0xFF;
          header.push_back(b);
        }
        dynamicCount ++;
      } else {
        /* static in head */
        bytes data;
        switch (td.dimensions.size()) {
          case 0: {
            data = encodeSingle(td.dt);
            break;
          }
          case 1: {
            data = encodeArray(td.dts, td.isDynamicArray);
            break;
          }
          case 2: {
            data = encode2DArray(td.dtss, td.isDynamicArray, td.isSubDynamicArray);
            break;
          }
        }
        header.insert(header.end(), data.begin(), data.end());
      }
    }
    /* Head + Payload */
    ret.insert(ret.end(), header.begin(), header.end());
    ret.insert(ret.end(), payload.begin(), payload.end());
    return ret;
  }
  
  bytes ContractABI::encode2DArray(vector<vector<DataType>> dtss, bool isDynamicArray, bool isSubDynamic) {
    bytes ret;
    if (isDynamicArray) {
      bytes payload;
      bytes header;
      u256 numElem = dtss.size();
      if (isSubDynamic) {
        /* Need Offset*/
        vector<int> dataOffset = {0};
        for (auto dts : dtss) {
          bytes data = encodeArray(dts, isSubDynamic);
          dataOffset.push_back(dataOffset.back() + data.size());
          payload.insert(payload.end(), data.begin(), data.end());
        }
        /* Count */
        for (int i = 0; i < 32; i += 1) {
          byte b = (byte) (numElem >> ((32 - i - 1) * 8)) & 0xFF;
          header.push_back(b);
        }
        for (int i = 0; i < numElem; i += 1) {
          u256 headerOffset =  32 * numElem + dataOffset[i];
          for (int i = 0; i < 32; i += 1) {
            byte b = (byte) (headerOffset >> ((32 - i - 1) * 8)) & 0xFF;
            header.push_back(b);
          }
        }
      } else {
        /* Count */
        for (int i = 0; i < 32; i += 1) {
          byte b = (byte) (numElem >> ((32 - i - 1) * 8)) & 0xFF;
          header.push_back(b);
        }
        for (auto dts : dtss) {
          bytes data = encodeArray(dts, isSubDynamic);
          payload.insert(payload.end(), data.begin(), data.end());
        }
      }
      ret.insert(ret.end(), header.begin(), header.end());
      ret.insert(ret.end(), payload.begin(), payload.end());
      return ret;
    }
    for (auto dts : dtss) {
      bytes data = encodeArray(dts, isSubDynamic);
      ret.insert(ret.end(), data.begin(), data.end());
    }
    return ret;
  }
  
  bytes ContractABI::encodeArray(vector<DataType> dts, bool isDynamicArray) {
    bytes ret;
    /* T[] */
    if (isDynamicArray) {
      /* Calculate header and payload */
      bytes payload;
      bytes header;
      u256 numElem = dts.size();
      if (dts[0].isDynamic) {
        /* If element is dynamic then needs offset */
        vector<int> dataOffset = {0};
        for (auto dt : dts) {
          bytes data = encodeSingle(dt);
          dataOffset.push_back(dataOffset.back() + data.size());
          payload.insert(payload.end(), data.begin(), data.end());
        }
        /* Count */
        for (int i = 0; i < 32; i += 1) {
          byte b = (byte) (numElem >> ((32 - i - 1) * 8)) & 0xFF;
          header.push_back(b);
        }
        /* Offset */
        for (int i = 0; i < numElem; i += 1) {
          u256 headerOffset =  32 * numElem + dataOffset[i];
          for (int i = 0; i < 32; i += 1) {
            byte b = (byte) (headerOffset >> ((32 - i - 1) * 8)) & 0xFF;
            header.push_back(b);
          }
        }
      } else {
        /* Do not need offset, count them */
        for (int i = 0; i < 32; i += 1) {
          byte b = (byte) (numElem >> ((32 - i - 1) * 8)) & 0xFF;
          header.push_back(b);
        }
        for (auto dt : dts) {
          bytes data = encodeSingle(dt);
          payload.insert(payload.end(), data.begin(), data.end());
        }
      }
      ret.insert(ret.end(), header.begin(), header.end());
      ret.insert(ret.end(), payload.begin(), payload.end());
      return ret;
    }
    /* T[k] */
    for (auto dt : dts) {
      bytes data = encodeSingle(dt);
      ret.insert(ret.end(), data.begin(), data.end());
    }
    return ret;
  }
  
  bytes ContractABI::encodeSingle(DataType dt) {
    bytes ret;
    bytes payload = dt.payload();
    if (dt.isDynamic) {
      /* Concat len and data */
      bytes header = dt.header();
      ret.insert(ret.end(), header.begin(), header.end());
      ret.insert(ret.end(), payload.begin(), payload.end());
      return ret;
    }
    ret.insert(ret.end(), payload.begin(), payload.end());
    return ret;
  }
  
  DataType::DataType(bytes value, bool padLeft, bool isDynamic) {
    this->value = value;
    this->padLeft = padLeft;
    this->isDynamic = isDynamic;
  }
  
  bytes DataType::header() {
    u256 size = this->value.size();
    bytes ret;
    for (int i = 0; i < 32; i += 1) {
      byte b = (byte) (size >> ((32 - i - 1) * 8)) & 0xFF;
      ret.push_back(b);
    }
    return ret;
  }
  
  bytes DataType::payload() {
    auto paddingLeft = [this](double toLen) {
      bytes ret(toLen - this->value.size(), 0);
      ret.insert(ret.end(), this->value.begin(), this->value.end());
      return ret;
    };
    auto paddingRight = [this](double toLen) {
      bytes ret;
      ret.insert(ret.end(), this->value.begin(), this->value.end());
      while(ret.size() < toLen) ret.push_back(0);
      return ret;
    };
    if (this->value.size() > 32) {
      if (!this->isDynamic) throw "Size of static <= 32 bytes";
      int valueSize = this->value.size();
      int finalSize = valueSize % 32 == 0 ? valueSize : (valueSize / 32 + 1) * 32;
      if (this->padLeft) return paddingLeft(finalSize);
      return paddingRight(finalSize);
    }
    if (this->padLeft) return paddingLeft(32);
    return paddingRight(32);
  }
  
  string TypeDef::toRealname(string name) {
    string fullType = toFullname(name);
    string searchPatterns[2] = {"address[", "bool["};
    string replaceCandidates[2] = {"uint160", "uint8"};
    for (int i = 0; i < 2; i += 1) {
      string pattern = searchPatterns[i];
      string candidate = replaceCandidates[i];
      if (boost::starts_with(fullType, pattern))
        return candidate + fullType.substr(pattern.length() - 1);
      if (fullType == pattern.substr(0, pattern.length() - 1)) return candidate;
    }
    return fullType;
  }
  
  string TypeDef::toFullname(string name) {
    string searchPatterns[4] = {"int[", "uint[", "fixed[", "ufixed["};
    string replaceCandidates[4] = {"int256", "uint256", "fixed128x128", "ufixed128x128"};
    for (int i = 0; i < 4; i += 1) {
      string pattern = searchPatterns[i];
      string candidate = replaceCandidates[i];
      if (boost::starts_with(name, pattern))
        return candidate + name.substr(pattern.length() - 1);
      if (name == pattern.substr(0, pattern.length() - 1)) return candidate;
    }
    return name;
  }
  
  vector<int> TypeDef::extractDimension(string name) {
    vector<int> ret;
    smatch sm;
    regex_match(name, sm, regex("[a-z]+[0-9]*\\[(\\d*)\\]\\[(\\d*)\\]"));
    if (sm.size() == 3) {
      /* Two dimension array */
      ret.push_back(sm[1] == "" ? 0 : stoi(sm[1]));
      ret.push_back(sm[2] == "" ? 0 : stoi(sm[2]));
      return ret;
    }
    regex_match(name, sm, regex("[a-z]+[0-9]*\\[(\\d*)\\]"));
    if (sm.size() == 2) {
      /* One dimension array */
      ret.push_back(sm[1] == "" ? 0 : stoi(sm[1]));
      return ret;
    }
    return ret;
  }
  
  void TypeDef::addValue(vector<vector<bytes>> vss) {
    if (this->dimensions.size() != 2) throw "Invalid dimension";;
    for (auto vs : vss) {
      vector<DataType> dts;
      for (auto v : vs) {
        dts.push_back(DataType(v, this->padLeft, this->isDynamic));
      }
      this->dtss.push_back(dts);
    }
  }
  
  void TypeDef::addValue(vector<bytes> vs) {
    if (this->dimensions.size() != 1) throw "Invalid dimension";
    for (auto v : vs) {
      this->dts.push_back(DataType(v, this->padLeft, this->isDynamic));
    }
  }
  
  void TypeDef::addValue(bytes v) {
    if (this->dimensions.size()) throw "Invalid dimension";
    this->dt = DataType(v, this->padLeft, this->isDynamic);
  }
  
  TypeDef::TypeDef(string name,string paraname) {
    this->paraname = paraname;
    this->name = name;
    this->fullname = toFullname(name);
    this->realname = toRealname(name);
    this->dimensions = extractDimension(name);
    this->padLeft = !boost::starts_with(this->fullname, "bytes") && !boost::starts_with(this->fullname, "string");
    int numDimension = this->dimensions.size();
    if (!numDimension) {
      this->isDynamic = this->fullname == "string" || this->name == "bytes";
      this->isDynamicArray = false;
      this->isSubDynamicArray = false;
    } else if (numDimension == 1) {
      this->isDynamic = boost::starts_with(this->fullname, "string[")
      || boost::starts_with(this->fullname, "bytes[");
      this->isDynamicArray = this->dimensions[0] == 0;
      this->isSubDynamicArray = false;
    } else {
      this->isDynamic = boost::starts_with(this->fullname, "string[")
      || boost::starts_with(this->fullname, "bytes[");
      this->isDynamicArray = this->dimensions[0] == 0;
      this->isSubDynamicArray = this->dimensions[1] == 0;
    }
  }
  
  bytes ContractABI::eventSelector(string name, vector<TypeDef> tds) {
    vector<string> argTypes;
    transform(tds.begin(), tds.end(), back_inserter(argTypes), [](TypeDef td) {
      return td.fullname;
    });
    string signature = name + "(" + boost::algorithm::join(argTypes, ",") + ")";
    bytes fullSelector = sha3(signature).ref().toBytes();
    return bytes(fullSelector);
  }
  
  
  std::string ContractABI::functionapi(string name, vector<TypeDef> tds) {
    vector<string> argTypes;
    transform(tds.begin(), tds.end(), back_inserter(argTypes), [](TypeDef td) {
      return td.name+" "+td.paraname;
    });
    string signature = name + "(" + boost::algorithm::join(argTypes, ",") + ")";
    return signature;
  }
  
  std::pair<bool, std::vector<std::string>> ContractABI::isValidOrder(const std::vector<std::string>& order) {
    if (this->originalFds.empty() || this->originalFds.size() == 1) {
        std::cerr << "No functions to reorder or only one function present." << std::endl;
        this->fds = this->originalFds;
        return {false, order};
    }

    // 创建一个映射，从函数编号（字符串）到函数定义的指针
    std::map<std::string, FuncDef*> nameToFunction;

    // 遍历 originalFds，并建立映射
    for (size_t i = 0; i < this->originalFds.size(); ++i) {
        std::string key = std::to_string(i + 1); // '1', '2', '3', ...
        nameToFunction[key] = &this->originalFds[i];
    }

    // 生成期望的函数编号集合
    std::set<std::string> expectedKeys;
    for (size_t i = 0; i < this->originalFds.size(); ++i) {
        expectedKeys.insert(std::to_string(i + 1));
    }

    // 从 order 中提取实际提供的函数编号集合
    std::set<std::string> providedKeys;
    for (const auto& s : order) {
        if (!s.empty()) {
            providedKeys.insert(s); // s 是函数编号字符串
        }
    }

    // 检查是否缺少函数
    if (expectedKeys != providedKeys) {
        // 计算缺失的函数
        std::set<std::string> missingFunctions;
        std::set_difference(expectedKeys.begin(), expectedKeys.end(), providedKeys.begin(), providedKeys.end(),
                            std::inserter(missingFunctions, missingFunctions.begin()));

        if (missingFunctions.size() == 1) {
            // 只有一个缺失的函数，将其追加到 order 末尾
            std::string missingFunction = *missingFunctions.begin();
            std::vector<std::string> newOrder = order; // 复制原始顺序
            newOrder.push_back(missingFunction);
            std::cout << "Added missing function: " << missingFunction << std::endl;
            return {true, newOrder}; // 返回 true 和更新后的 order
        } else {
            // 缺失函数数量不为 1，返回 false 和原始 order
            std::cout << "Number of missing functions is not 1." << std::endl;
            return {false, order};
        }
    }

    // 没有缺失函数，返回 true 和原始 order
    return {true, order};
}
  
  std::string ContractABI::getCurrentExecutionOrder() const {
    if (this->fds.empty()) {
        return "No functions in the current execution order.";
    }

    std::string executionOrder;

    // 遍历 fds，找到每个函数在 originalFds 中的索引
    for (const auto& func : this->fds) {
        // 找到当前 func 在 originalFds 中的位置
        auto it = std::find_if(this->originalFds.begin(), this->originalFds.end(),
            [&func](const FuncDef& originalFunc) {
                return originalFunc.name == func.name; // 假设使用函数名匹配
            });

        if (it != this->originalFds.end()) {
            // 计算函数在 originalFds 中的索引（从 1 开始）
            int index = std::distance(this->originalFds.begin(), it) + 1;
            executionOrder += std::to_string(index) + "->";
        }
    }

    // 移除最后一个多余的 "->"
    if (!executionOrder.empty()) {
        executionOrder.pop_back(); // 移除最后的 '-'
        executionOrder.pop_back(); // 移除最后的 '>'
    }

    return executionOrder;
}

  
  
}

