#include "Util.h"
#include "Logger.h"

namespace dev {
    using bytes = std::vector<uint8_t>;
}

namespace fuzzer {
  u32 UR(u32 limit) {
    return random() % limit;
  }

  int effAPos(int p) {
    return p >> EFF_MAP_SCALE2;
  }

  int effRem(int x) {
    return (x) & ((1 << EFF_MAP_SCALE2) - 1);
  }

  int effALen(int l) {
    return effAPos(l) + !!effRem(l);
  }

  int effSpanALen(int p, int l) {
    return (effAPos(p + l - 1) - effAPos(p) + 1);
  }
  /* Helper function to see if a particular change (xor_val = old ^ new) could
   be a product of deterministic bit flips with the lengths and stepovers
   attempted by afl-fuzz. This is used to avoid dupes in some of the
   deterministic fuzzing operations that follow bit flips. We also
   return 1 if xor_val is zero, which implies that the old and attempted new
   values are identical and the exec would be a waste of time. */
  bool couldBeBitflip(u32 xorValue) {
    u32 sh = 0;
    if (!xorValue) return true;
    /* Shift left until first bit set. */
    while (!(xorValue & 1)) { sh++ ; xorValue >>= 1; }
    /* 1-, 2-, and 4-bit patterns are OK anywhere. */
    if (xorValue == 1 || xorValue == 3 || xorValue == 15) return 1;
    /* 8-, 16-, and 32-bit patterns are OK only if shift factor is
     divisible by 8, since that's the stepover for these ops. */
    if (sh & 7) return false;
    if (xorValue == 0xff || xorValue == 0xffff || xorValue == 0xffffffff)
      return true;
    return false;
  }
  /* Helper function to see if a particular value is reachable through
   arithmetic operations. Used for similar purposes. */
  bool couldBeArith(u32 old_val, u32 new_val, u8 blen) {
    u32 i, ov = 0, nv = 0, diffs = 0;
    if (old_val == new_val) return true;
    /* See if one-byte adjustments to any byte could produce this result. */
    for (i = 0; i < blen; i++) {
      u8 a = old_val >> (8 * i),
      b = new_val >> (8 * i);
      if (a != b) { diffs++; ov = a; nv = b; }
    }
    /* If only one byte differs and the values are within range, return 1. */
    if (diffs == 1) {
      if ((u8)(ov - nv) <= ARITH_MAX ||
          (u8)(nv - ov) <= ARITH_MAX) return true;
    }
    if (blen == 1) return false;
    /* See if two-byte adjustments to any byte would produce this result. */
    diffs = 0;
    for (i = 0; i < blen / 2; i++) {
      u16 a = old_val >> (16 * i),
      b = new_val >> (16 * i);
      if (a != b) { diffs++; ov = a; nv = b; }
    }
    /* If only one word differs and the values are within range, return 1. */
    if (diffs == 1) {
      if ((u16)(ov - nv) <= ARITH_MAX || (u16)(nv - ov) <= ARITH_MAX)
        return  true;
      ov = swap16(ov); nv = swap16(nv);
      if ((u16)(ov - nv) <= ARITH_MAX || (u16)(nv - ov) <= ARITH_MAX)
        return true;
    }
    /* Finally, let's do the same thing for dwords. */
    if (blen == 4) {
      if ((u32)(old_val - new_val) <= (u32) ARITH_MAX || (u32)(new_val - old_val) <= (u32) ARITH_MAX)
        return true;
      new_val = swap32(new_val);
      old_val = swap32(old_val);
      if ((u32)(old_val - new_val) <= (u32) ARITH_MAX || (u32)(new_val - old_val) <= (u32) ARITH_MAX)
        return true;
    }
    return false;
  }
  /* Last but not least, a similar helper to see if insertion of an
   interesting integer is redundant given the insertions done for
   shorter blen. The last param (check_le) is set if the caller
   already executed LE insertion for current blen and wants to see
   if BE variant passed in new_val is unique. */
  bool couldBeInterest(u32 old_val, u32 new_val, u8 blen, u8 check_le) {
    u32 i, j;
    if (old_val == new_val) return true;
    /* See if one-byte insertions from interesting_8 over old_val could
     produce new_val. */
    for (i = 0; i < blen; i++) {
      for (j = 0; j < sizeof(INTERESTING_8); j++) {
        u32 tval = (old_val & ~(0xff << (i * 8))) |
        (((u8)INTERESTING_8[j]) << (i * 8));
        if (new_val == tval) return true;
      }
    }
    /* Bail out unless we're also asked to examine two-byte LE insertions
     as a preparation for BE attempts. */
    if (blen == 2 && !check_le) return false;
    /* See if two-byte insertions over old_val could give us new_val. */
    for (i = 0; i < blen - 1; i++) {
      for (j = 0; j < sizeof(INTERESTING_16) / 2; j++) {
        u32 tval = (old_val & ~(0xffff << (i * 8))) |
        (((u16)INTERESTING_16[j]) << (i * 8));
        if (new_val == tval) return true;
        /* Continue here only if blen > 2. */
        if (blen > 2) {
          tval = (old_val & ~(0xffff << (i * 8))) |
          (swap16(INTERESTING_16[j]) << (i * 8));
          if (new_val == tval) return true;
        }
      }
    }
    if (blen == 4 && check_le) {
      /* See if four-byte insertions could produce the same result
       (LE only). */
      for (j = 0; j < sizeof(INTERESTING_32) / 4; j++)
        if (new_val == (u32)INTERESTING_32[j]) return true;
    }
    return false;
  }

  u16 swap16(u16 x) {
    return x << 8 | x >> 8;
  }

  u32 swap32(u32 x) {
    return x << 24 | x >> 24 | ((x << 8) & 0x00FF0000) | ((x >> 8) & 0x0000FF00);
  }

  u32 chooseBlockLen(u32 limit) {
    /* Delete at most: 1/4 */
    int maxFactor = limit / (4 * 32);
    if (!maxFactor) return 0;
    return (UR(maxFactor) + 1) * 32;
  }

  void locateDiffs(byte* ptr1, byte* ptr2, u32 len, s32* first, s32* last) {
    s32 f_loc = -1;
    s32 l_loc = -1;
    u32 pos;
    for (pos = 0; pos < len; pos++) {
      if (*(ptr1++) != *(ptr2++)) {
        if (f_loc == -1) f_loc = pos;
        l_loc = pos;
      }
    }
    *first = f_loc;
    *last = l_loc;
    return;
  }

  string formatDuration(int duration) {
    stringstream ret;
    int days = duration / (60 * 60 * 24);
    int hours = duration / (60 * 60) % 24;
    int minutes = duration / 60 % 60;
    int seconds = duration % 60;
    ret << days
      << " days, "
      << hours
      << " hrs, "
      << minutes
      << " min, "
      << seconds
      << " sec";
    return padStr(ret.str(), 48);
  }

  string padStr(string str, int len) {
    while ((int)str.size() < len) str += " ";
    return str;
  }

  vector<string> splitString(string str, char separator) {
    vector<string> elements;
    uint64_t sepIdx = 0;
    if (!str.size()) return {};
    for (uint64_t i = 0; i < str.length(); i ++) {
      if (str[i] == separator) {
        elements.push_back(str.substr(sepIdx, i - sepIdx));
        sepIdx = i + 1;
      }
    }
    elements.push_back(str.substr(sepIdx, str.length() - sepIdx));
    return elements;
  }
  
  bytes hexStringToBytes(const std::string& hex, int len) {
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
    
    
  std::string bytesToHexString(const bytes& data) {
    std::string hexStr = "0x";
    static const char hex_chars[] = "0123456789abcdef";
    
    for (unsigned char byte : data) {
        hexStr += hex_chars[(byte >> 4) & 0x0F];
        hexStr += hex_chars[byte & 0x0F];
    }
    
    return hexStr;
  }
  
  // 计算两个字符串之间的编辑距离（Levenshtein 距离）
  int calculateEditDistance(const std::string& a, const std::string& b) {
    int lenA = a.size();
    int lenB = b.size();
    std::vector<std::vector<int>> dp(lenA + 1, std::vector<int>(lenB + 1));

    // 初始化 dp 表格
    for (int i = 0; i <= lenA; ++i) dp[i][0] = i;
    for (int j = 0; j <= lenB; ++j) dp[0][j] = j;

    // 填充 dp 表格
    for (int i = 1; i <= lenA; ++i) {
        for (int j = 1; j <= lenB; ++j) {
            if (a[i - 1] == b[j - 1]) {
                dp[i][j] = dp[i - 1][j - 1];
            } else {
                dp[i][j] = std::min({ dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + 1 });
            }
        }
    }

    return dp[lenA][lenB];
}

}



