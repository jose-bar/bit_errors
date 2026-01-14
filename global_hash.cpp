#include "openfhe.h"
#include "blake3.h"

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

#include <iostream>
#include <iterator>
#include <string>
#include <fstream>
#include <istream>
#include <ostream>
#include <vector>
#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <numeric>

using namespace lbcrypto;

// Configs
const int NUM_CTS = 10;
const int BATCH_SIZE = 8192;
const double TARGET_BER = 1e-6; // bit error rate

std::string blake3(const std::string& data){
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, data.data(), data.size());

    uint8_t hash[BLAKE3_OUT_LEN];
    blake3_hasher_finalize(&hasher, hash, BLAKE3_OUT_LEN);

    std::stringstream ss;
    for(int i = 0; i < BLAKE3_OUT_LEN; i++){
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

template <typename ByteContainer>
void inject_noise(ByteContainer& data, double ber) {
    if (ber <= 0.0) return;

    static std::mt19937 gen(123456);
    static std::uniform_real_distribution<double> dis(0.0, 1.0);

    for (auto& b : data) {
        uint8_t byte = static_cast<uint8_t>(b);

        for (int bit = 0; bit < 8; ++bit) {
            if (dis(gen) < ber) {
                byte ^= (1u << bit);
            }
        }

        b = static_cast<typename ByteContainer::value_type>(byte);
    }
}


void sender(const CryptoContext<DCRTPoly>& cc, const KeyPair<DCRTPoly>& kp){
    std::cout << "[Sender] Generating data..." << std::endl;

    std::stringstream data_steam;
    std::vector<double> encryption_times;

    for(int i = 0; i < NUM_CTS; i++){
        std::vector<double> vec;
        for(int j = 0; j < BATCH_SIZE; j++) vec.push_back(j + i % 256);
        auto start_enc = std::chrono::high_resolution_clock::now();
        Plaintext pt = cc->MakeCKKSPackedPlaintext(vec);
        auto ct = cc->Encrypt(kp.publicKey, pt);
        auto end_enc = std::chrono::high_resolution_clock::now();
        encryption_times.push_back(std::chrono::duration<double>(end_enc - start_enc).count());

        Serial::Serialize(ct, data_steam, SerType::BINARY);
    }

    std::string serialized = data_steam.str();

    auto start = std::chrono::high_resolution_clock::now();
    std::string hash = blake3(serialized);
    auto end = std::chrono::high_resolution_clock::now();
    std::cout << "[Sender] Package Size: " << serialized.size() / (1024 * 1024) << " MB" << std::endl;
    std::cout << "[Sender] Hash Time: " << std::chrono::duration<double>(end - start).count() << " s" << std::endl;
    std::cout << "[Sender] Encryption for " << NUM_CTS << " CT: "
         << std::accumulate(encryption_times.begin(), encryption_times.end(), 0.0) << " s" << std::endl;
    std::ofstream out_file("package.bin", std::ios::binary);

    uint32_t hash_size = hash.size();
    out_file.write(reinterpret_cast<const char*>(&hash_size), sizeof(hash_size));
    out_file.write(hash.data(), hash.size());
    out_file.write(serialized.data(), serialized.size());

    out_file.close();
    std::cout << "[Sender] Package written to package.bin" << std::endl;
}

void receiver(){
    std::cout << "[Receiver] Reading package..." << std::endl;
    auto start = std::chrono::high_resolution_clock::now();
    int tries = 0;
    bool success = false;

    std::string valid_package;

    while(!success){
        tries++;

        std::ifstream in_file("package.bin", std::ios::binary);
        if(!in_file.is_open()){ std::cerr << "[Receiver] Failed to open package.bin" << std::endl; return; }

        uint32_t hash_size;
        in_file.read(reinterpret_cast<char*>(&hash_size), sizeof(hash_size));
        std::string exp_hash(hash_size, '\0');
        in_file.read(&exp_hash[0], hash_size);

        std::string package((std::istreambuf_iterator<char>(in_file)), std::istreambuf_iterator<char>());
        in_file.close();

        // Inject noise, assume good header
        inject_noise(package, TARGET_BER);

        // verify
        auto verify_start = std::chrono::high_resolution_clock::now();
        std::string hash = blake3(package);

        if(hash == exp_hash){
            success = true;
            valid_package = package;
            std::cout << "[Receiver] Package verified successfully after " << tries << " tries." << std::endl;
        }else{
            if(tries % 10 == 0)
                std::cout << "[Receiver] Chunk verification failed after " << tries << " tries, retrying..." << std::endl;
        }

        if(tries >= 100){
            std::cerr << "[Receiver] Failed to verify package after " << tries << " tries, giving up." << std::endl;
            break;
        }
    }

    auto verify_end = std::chrono::high_resolution_clock::now();
    std::cout << "[Receiver] Verification Time: " << std::chrono::duration<double>(verify_end - start).count() << " s" << std::endl;
    std::cout << "[Receiver] Bytes processed: " << valid_package.size() * tries / (1024 * 1024) << " MB" << std::endl;
}

int main() {
    // Setup crypto context
    uint32_t multDepth = 2;
    uint32_t scaleModSize = 50;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(BATCH_SIZE);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    KeyPair<DCRTPoly> kp = cc->KeyGen();

    // Run sender and receiver
    sender(cc, kp);
    receiver();

    return 0;
}