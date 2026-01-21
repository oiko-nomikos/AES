#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <mutex>
#include <deque>

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class SystemClock {
  public:
    inline long long getSeconds() {
        auto now = std::chrono::system_clock::now();
        return std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    }

    inline long long getMilliseconds() {
        auto now = std::chrono::system_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    }

    inline long long getMicroseconds() {
        auto now = std::chrono::system_clock::now();
        return std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
    }

    inline long long getNanoseconds() {
        auto now = std::chrono::system_clock::now();
        return std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
    }
};

// Global Instance
inline SystemClock systemClock;

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

namespace CRYPTO {
class SHA256 {
  public:
    SHA256() { reset(); }

    void update(const uint8_t *data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            buffer[bufferLen++] = data[i];
            if (bufferLen == 64) {
                transform(buffer);
                bitlen += 512;
                bufferLen = 0;
            }
        }
    }

    void update(const std::string &data) { update(reinterpret_cast<const uint8_t *>(data.c_str()), data.size()); }

    std::string digest() {
        uint64_t totalBits = bitlen + bufferLen * 8;

        buffer[bufferLen++] = 0x80;
        if (bufferLen > 56) {
            while (bufferLen < 64)
                buffer[bufferLen++] = 0x00;
            transform(buffer);
            bufferLen = 0;
        }

        while (bufferLen < 56)
            buffer[bufferLen++] = 0x00;

        for (int i = 7; i >= 0; --i)
            buffer[bufferLen++] = (totalBits >> (i * 8)) & 0xFF;

        transform(buffer);

        std::ostringstream oss;
        for (int i = 0; i < 8; ++i)
            oss << std::hex << std::setw(8) << std::setfill('0') << h[i];

        reset(); // reset internal state after digest
        return oss.str();
    }

    std::string digestBinary() {
        std::string hex = digest();
        std::string binary;
        for (char c : hex) {
            uint8_t val = (c <= '9') ? c - '0' : 10 + (std::tolower(c) - 'a');
            for (int i = 3; i >= 0; --i)
                binary += ((val >> i) & 1) ? '1' : '0';
        }
        return binary;
    }

    void reset() {
        h[0] = 0x6a09e667;
        h[1] = 0xbb67ae85;
        h[2] = 0x3c6ef372;
        h[3] = 0xa54ff53a;
        h[4] = 0x510e527f;
        h[5] = 0x9b05688c;
        h[6] = 0x1f83d9ab;
        h[7] = 0x5be0cd19;
        bitlen = 0;
        bufferLen = 0;
    }

  private:
    uint32_t h[8];
    uint64_t bitlen;
    uint8_t buffer[64];
    size_t bufferLen;

    void transform(const uint8_t block[64]) {
        uint32_t w[64];

        for (int i = 0; i < 16; ++i) {
            w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | (block[i * 4 + 3]);
        }

        for (int i = 16; i < 64; ++i) {
            w[i] = theta1(w[i - 2]) + w[i - 7] + theta0(w[i - 15]) + w[i - 16];
        }

        uint32_t a = h[0];
        uint32_t b = h[1];
        uint32_t c = h[2];
        uint32_t d = h[3];
        uint32_t e = h[4];
        uint32_t f = h[5];
        uint32_t g = h[6];
        uint32_t h_val = h[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t temp1 = h_val + sig1(e) + choose(e, f, g) + K[i] + w[i];
            uint32_t temp2 = sig0(a) + majority(a, b, c);
            h_val = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += h_val;
    }

    static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
    static uint32_t choose(uint32_t e, uint32_t f, uint32_t g) { return (e & f) ^ (~e & g); }
    static uint32_t majority(uint32_t a, uint32_t b, uint32_t c) { return (a & b) ^ (a & c) ^ (b & c); }
    static uint32_t sig0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
    static uint32_t sig1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
    static uint32_t theta0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
    static uint32_t theta1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

    const uint32_t K[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be,
                            0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
                            0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
                            0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
                            0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
};
} // namespace CRYPTO

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class RandomNumberGenerator {
  public:
    inline std::string run() {
        std::string result;
        result.reserve((totalIterations - localBufferSize) * 256);

        for (int i = 0; i < totalIterations; ++i) {

            long long duration = countdown();
            ++count;
            globalSum += duration;
            globalAvg = globalSum / count;

            int bit = duration < globalAvg ? 0 : 1;

            if (localBits.size() >= localBufferSize)
                localBits.pop_front();

            localBits.push_back(bit);

            if (localBits.size() == localBufferSize) {
                // 32 raw bytes → 256 bit string
                std::string hashBits = hashLocalBits();
                result += hashBits;
            }
        }

        return result;
    }

  private:
    CRYPTO::SHA256 sha;
    std::deque<int> localBits;
    const int totalIterations = 1000;
    const size_t localBufferSize = 512;
    long long globalSum = 0;
    long long globalAvg = 0;
    int count = 0;

    inline long long countdown() {
        int x = 10;
        auto start = systemClock.getNanoseconds();
        while (x > 0)
            x--;
        auto end = systemClock.getNanoseconds();
        return end - start;
    }

    inline std::string hashLocalBits() {
        // Build 64-byte block
        uint8_t bytes[64] = {0};
        for (size_t i = 0; i < localBits.size(); ++i) {
            if (localBits[i]) {
                bytes[i / 8] |= (1 << (7 - (i % 8)));
            }
        }

        sha.update(bytes, 64);

        // Return 256-bit binary string using fast helper
        return sha.digestBinary();
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class BinaryEntropyPool {
  public:
    inline std::string get(size_t bitsNeeded) {
        std::lock_guard<std::mutex> lock(poolMutex);

        // Refill the pool until we have enough bits
        while (bitPool.size() < bitsNeeded) {
            bitPool += rng.run(); // rng.run() now returns a bit string
        }

        // Extract exactly the number of bits requested
        std::string result = bitPool.substr(0, bitsNeeded);
        bitPool.erase(0, bitsNeeded); // remove consumed bits

        return result;
    }

  private:
    std::string bitPool; // bit string directly
    RandomNumberGenerator rng;
    mutable std::mutex poolMutex;
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

#include <string>
#include <utility>
#include <stdexcept>

std::pair<std::string, std::string> splitBitstreamInHalf(const std::string &bitstream) {
    if (bitstream.size() % 2 != 0) {
        throw std::runtime_error("Bitstream length must be even");
    }

    std::size_t half = bitstream.size() / 2;

    return {bitstream.substr(0, half), bitstream.substr(half)};
}

std::string xorBitStrings(const std::string &a, const std::string &b) {
    if (a.size() != b.size()) {
        throw std::runtime_error("Bitstrings must be the same length");
    }

    std::string result;
    result.reserve(a.size());

    for (std::size_t i = 0; i < a.size(); ++i) {
        if ((a[i] != '0' && a[i] != '1') || (b[i] != '0' && b[i] != '1')) {
            throw std::runtime_error("Bitstrings must contain only '0' or '1'");
        }

        // XOR truth table:
        // 0 ^ 0 = 0
        // 1 ^ 0 = 1
        // 0 ^ 1 = 1
        // 1 ^ 1 = 0
        result.push_back(a[i] == b[i] ? '0' : '1');
    }

    return result;
}

#include <string>
#include <utility>
#include <stdexcept>

std::pair<std::string, std::string> reconstructFromXor(const std::string &xored, const std::string &key) {
    if (xored.size() != key.size()) {
        throw std::runtime_error("XOR value and key must be the same length");
    }

    std::string left;
    std::string right;

    left.reserve(xored.size());
    right.reserve(xored.size());

    for (std::size_t i = 0; i < xored.size(); ++i) {
        char x = xored[i];
        char k = key[i];

        if ((x != '0' && x != '1') || (k != '0' && k != '1')) {
            throw std::runtime_error("Inputs must contain only '0' or '1'");
        }

        if (x == '0') {
            // 0⊕0 or 1⊕1
            if (k == '0') {
                left.push_back('0');
                right.push_back('0');
            } else {
                left.push_back('1');
                right.push_back('1');
            }
        } else {
            // 0⊕1 or 1⊕0
            if (k == '0') {
                left.push_back('0');
                right.push_back('1');
            } else {
                left.push_back('1');
                right.push_back('0');
            }
        }
    }

    return {left, right};
}

std::string buildXorKey(const std::string &a, const std::string &b) {
    if (a.size() != b.size()) {
        throw std::runtime_error("Inputs must be the same length");
    }

    std::string key;
    key.reserve(a.size());

    for (std::size_t i = 0; i < a.size(); ++i) {
        if ((a[i] != '0' && a[i] != '1') || (b[i] != '0' && b[i] != '1')) {
            throw std::runtime_error("Inputs must contain only '0' or '1'");
        }

        key.push_back(a[i] == b[i] ? '0' : '1');
    }

    return key;
}

#include <string>
#include <utility>
#include <stdexcept>

std::pair<std::string, std::string> xorWithLeftKey(const std::string &a, const std::string &b) {
    if (a.size() != b.size()) {
        throw std::runtime_error("Inputs must be the same length");
    }

    std::string xored;
    std::string key;

    xored.reserve(a.size());
    key.reserve(a.size());

    for (std::size_t i = 0; i < a.size(); ++i) {
        char A = a[i];
        char B = b[i];

        if ((A != '0' && A != '1') || (B != '0' && B != '1')) {
            throw std::runtime_error("Inputs must contain only '0' or '1'");
        }

        if (A == B) {
            // 00 or 11
            xored.push_back('0');
            key.push_back(A); // 0 for 00, 1 for 11
        } else {
            // 01 or 10
            xored.push_back('1');
            key.push_back(A); // 0 for 01, 1 for 10
        }
    }

    return {xored, key};
}

std::pair<std::string, std::string> xorWithRightKey(const std::string &a, const std::string &b) {
    if (a.size() != b.size()) {
        throw std::runtime_error("Inputs must be the same length");
    }

    std::string xored;
    std::string key;

    xored.reserve(a.size());
    key.reserve(a.size());

    for (std::size_t i = 0; i < a.size(); ++i) {
        char A = a[i];
        char B = b[i];

        if ((A != '0' && A != '1') || (B != '0' && B != '1')) {
            throw std::runtime_error("Inputs must contain only '0' or '1'");
        }

        // XOR
        xored.push_back(A == B ? '0' : '1');

        // Inverse-A key
        key.push_back(A == '0' ? '1' : '0');
    }

    return {xored, key};
}

int main() {
    std::cout << "Welcome to the Program...\n";

    // Pause for user input
    std::cout << "\nPress Enter to continue...";
    std::cin.get(); // waits until Enter is pressed

    BinaryEntropyPool bep;
    std::string bitStream = bep.get(256);
    std::cout << "bitstream: " << bitStream << "\n\n";

    auto [firstHalf, secondHalf] = splitBitstreamInHalf(bitStream);

    // Create XOR + key together
    auto [xored1, key1] = xorWithLeftKey(firstHalf, secondHalf);

    auto [firstXoredHalf, secondXoredHalf] = splitBitstreamInHalf(xored1);

    // Create XOR + key together
    auto [xored2, key2] = xorWithLeftKey(firstXoredHalf, secondXoredHalf);

    // Reconstruct
    auto [recoveredFirst, recoveredSecond] = reconstructFromXor(xored2, key2);

    std::cout << "First half  : " << firstHalf << "\n";
    std::cout << "Second half : " << secondHalf << "\n\n";

    std::cout << "XOR1 result : " << xored2 << "\n";
    std::cout << "Key1        : " << key2 << "\n\n";

    std::cout << "First half  : " << firstXoredHalf << "\n";
    std::cout << "Second half : " << secondXoredHalf << "\n\n";

    std::cout << "XOR2 result : " << xored2 << "\n";
    std::cout << "Key2        : " << key2 << "\n\n";

    std::cout << "First half  : " << recoveredFirst << "\n";
    std::cout << "Second half : " << recoveredSecond << "\n\n";

    // Pause for user input
    std::cout << "\nPress Enter to continue...";
    std::cin.get(); // waits until Enter is pressed

    // std::string xored = xorBitStrings(firstHalf, secondHalf);
    // std::string key = buildXorKey(firstHalf, secondHalf);
    // auto [recoveredFirst, recoveredSecond] = reconstructFromXor(xored, key);

    // Create XOR + key together
    auto [leftXored, leftKey] = xorWithLeftKey(firstHalf, secondHalf);

    // Reconstruct
    auto [recoveredLeftFirst, recoveredLeftSecond] = reconstructFromXor(leftXored, leftKey);

    // Create XOR + key together
    auto [rightXored, rightKey] = xorWithRightKey(firstHalf, secondHalf);
    auto [recoveredRightFirst, recoveredRightSecond] = reconstructFromXor(rightXored, rightKey);

    std::cout << "First half : " << firstHalf << "\n";
    std::cout << "Second half: " << secondHalf << "\n\n";

    std::cout << "XOR result : " << leftXored << "\n";
    std::cout << "Key        : " << leftKey << "\n\n";

    std::cout << "First half : " << recoveredLeftFirst << "\n";
    std::cout << "Second half: " << recoveredLeftSecond << "\n\n";

    std::cout << "-----------------------------------------------------------------------------------\n\n";

    std::cout << "First half : " << firstHalf << "\n";
    std::cout << "Second half: " << secondHalf << "\n\n";

    std::cout << "XOR result : " << rightXored << "\n";
    std::cout << "Key        : " << rightKey << "\n\n";

    std::cout << "First half : " << recoveredRightFirst << "\n";
    std::cout << "Second half: " << recoveredRightSecond << "\n";

    // Pause for user input
    std::cout << "\nPress Enter to continue...";
    std::cin.get(); // waits until Enter is pressed

    std::vector<std::string> matrix = {"A1", "B1", "C1", "D1", "A2", "B2", "C2", "D2", "A3", "B3", "C3", "D3", "A4", "B4", "C4", "D4"};

    // Print nicely in 4x4 form
    for (size_t i = 0; i < matrix.size(); ++i) {
        std::cout << matrix[i] << " ";
        if ((i + 1) % 4 == 0)
            std::cout << std::endl;
    }

    std::string reverseRowString;
    std::string rowString;
    std::string colString;

    // Row by row
    for (size_t i = 0; i < matrix.size(); ++i) {
        rowString += matrix[i]; // append each cell
    }

    // 4 columns, 4 rows
    for (int c = 0; c < 4; ++c) {
        for (int r = 0; r < 4; ++r) {
            colString += matrix[r * 4 + c];
        }
    }

    // Iterate backwards
    for (int i = matrix.size() - 1; i >= 0; --i) {
        reverseRowString += matrix[i];
    }

    std::cout << "Row: " << rowString << "\n\n";

    std::cout << "Rev: " << reverseRowString << std::endl;
    std::cout << "Col: " << colString << std::endl;

    // Pause for user input
    std::cout << "\nPress Enter to exit...";
    std::cin.get(); // waits until Enter is pressed

    return 0;
}

/*

0 ⊕ 0 = 0 → passed 0
1 ⊕ 1 = 0 → passed 0
0 ⊕ 1 = 1 → passed 1
1 ⊕ 0 = 1 → passed 1

//==================================== 0

0 ⊕ 0 = 0 → passed 0
1 ⊕ 1 = 0 → passed 1
0 ⊕ 1 = 1 → passed 0
1 ⊕ 0 = 1 → passed 1

//==================================== 0

0 ⊕ 0 =
1 ⊕ 1 =
0 ⊕ 1 =
1 ⊕ 0 =
         1st 2nd 3rd
0 ⊕ 0 = 0 - 0 - 0 ect...
1 ⊕ 1 = 0 - 0 - 0
0 ⊕ 1 = 0 - 0 - 1
1 ⊕ 0 = 0 - 1 - 0

0000	FALSE (always 0)
0001	AND only for 0⊕1? Usually depends on mapping order
0010	AND only for 1⊕0?
0011	XOR (0⊕1 and 1⊕0 = 1)
0100	???
0101	A AND B complement?
0110	OR?
0111	OR-like
1000	NAND-like?
1001	???
1010	XOR with complement?
1011	???
1100	AND?
1101	???
1110	OR?
1111	TRUE (always 1)

A	B	A ⊕ B	key
0	0	  0	      0
1	1	  0	      1
0	1	  1	      0
1	0	  1	      1

A	B	A ⊕ B	key
0	0	  0	      1
1	1	  0	      0
0	1	  1	      1
1	0	  1	      0





*/
