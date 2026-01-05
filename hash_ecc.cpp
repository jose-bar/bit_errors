#include "Reed-Solomon/include/rs.hpp"
#include "openfhe.h"
#include "blake3.h"

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <random>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <sstream>

using namespace lbcrypto;

// Configs
const int NUM_CTS = 10;
const int BATCH_SIZE = 8192;
const double TARGET_BER = 1e-2; // bit error rate

// Reed-Solomon parameters
// can correct up to 16 byte errors per 255-byte block
const int DATA_LEN = 223;
const int ECC_LEN = 32;
const int BLOCK_LEN = DATA_LEN + ECC_LEN;

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

void inject_noise(std::vector<uint8_t>& data, double ber){
    if(ber <= 0) return;

    static std::mt19937 gen(123456);
    static std::uniform_real_distribution<> dis(0.0, 1.0);

    for(size_t i = 0; i < data.size(); i++){
        if(dis(gen) < ber * 8){
            // flip random bit
            int bit_pos = std::uniform_int_distribution<>(0, 7)(gen);
            data[i] ^= (1 << bit_pos);
        }
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

    std::string global_hash = blake3(serialized);

    std::vector<uint8_t> final_package;
    RS::ReedSolomon<DATA_LEN, ECC_LEN> rs;

    size_t processed = 0;
    auto start_ecc = std::chrono::high_resolution_clock::now();

    while(processed < serialized.size()){
        // prep buffer
        char msg_buff[DATA_LEN] = {0};
        char enc_buff[BLOCK_LEN] = {0};

        size_t copy_size = std::min(static_cast<size_t>(DATA_LEN), serialized.size() - processed);
        std::memcpy(msg_buff, serialized.data() + processed, copy_size);

        rs.Encode(msg_buff, enc_buff);
        final_package.insert(final_package.end(), enc_buff, enc_buff + BLOCK_LEN);
        processed += copy_size;
    }
    auto end_ecc = std::chrono::high_resolution_clock::now();

    std::ofstream out_file("package_ecc.bin", std::ios::binary);

    // Header: [Hash Len][Hash][Raw Data Size]
    uint32_t hash_size = global_hash.size();
    uint64_t raw_size = serialized.size();

    out_file.write(reinterpret_cast<const char*>(&hash_size), sizeof(hash_size));
    out_file.write(global_hash.data(), global_hash.size());
    out_file.write(reinterpret_cast<const char*>(&raw_size), sizeof(raw_size));

    // Body: ECC encoded data
    out_file.write(reinterpret_cast<const char*>(final_package.data()), final_package.size());
    out_file.close();

    std::cout << "[Sender] Original Package Size: " << serialized.size() / (1024 * 1024) << " MB" << std::endl;
    std::cout << "[Sender] ECC Encoded Package Size: " << final_package.size() / (1024 * 1024) << " MB" << std::endl;
    std::cout << "[Sender] ECC Overhead: " << ((double)final_package.size() / serialized.size() - 1.0) * 100 << " %" << std::endl;
    std::cout << "[Sender] ECC Encoding Time: " << std::chrono::duration<double>(end_ecc - start_ecc).count() << " s" << std::endl;
}

void receiver(){
    std::cout << "[Receiver] Reading package..." << std::endl;
    
    std::ifstream in_file("package_ecc.bin", std::ios::binary);
    if(!in_file.is_open()){ std::cerr << "[Receiver] Failed to open package_ecc.bin" << std::endl; return;}

    // Read header
    uint32_t hash_size;
    in_file.read(reinterpret_cast<char*>(&hash_size), sizeof(hash_size));

    std::string expected_hash(hash_size, '\0');
    in_file.read(&expected_hash[0], hash_size);

    uint64_t raw_size;
    in_file.read(reinterpret_cast<char*>(&raw_size), sizeof(raw_size));

    std::vector<uint8_t> data(
        (std::istreambuf_iterator<char>(in_file)),
         std::istreambuf_iterator<char>()
    );
    in_file.close();

    // Inject noise
    std::cout << "[Receiver] Injecting noise with BER=" << TARGET_BER << " ..." << std::endl;
    inject_noise(data, TARGET_BER);

    // RS recovery
    RS::ReedSolomon<DATA_LEN, ECC_LEN> rs;
    std::string recovered_data;
    recovered_data.reserve(raw_size);

    bool decode_failed = false;
    int blocks_processed = 0;
    int unrecoverable_blocks = 0;

    auto start_dec = std::chrono::high_resolution_clock::now();

    for(size_t i = 0; i < data.size(); i += BLOCK_LEN){
        char enc_buff[BLOCK_LEN];
        char repair_buff[DATA_LEN];

        std::memcpy(enc_buff, data.data() + i, BLOCK_LEN);

        int result = rs.Decode(enc_buff, repair_buff);

        if(result < 0){
            std::cerr << "[Receiver] Unrecoverable RS block at index "
                      << blocks_processed << std::endl;
            unrecoverable_blocks++;
            decode_failed = true;
            break;
        }

        // Append recovered payload, trimming padding on last block
        size_t bytes_to_copy = DATA_LEN;
        if(recovered_data.size() + DATA_LEN > raw_size){
            bytes_to_copy = raw_size - recovered_data.size();
        }

        recovered_data.append(repair_buff, bytes_to_copy);
        blocks_processed++;
    }

    auto end_dec = std::chrono::high_resolution_clock::now();

    // Verify integrity
    std::cout << "\n--- RESULTS ---" << std::endl;
    std::cout << "Decode time:       "
              << std::chrono::duration<double>(end_dec - start_dec).count()
              << " s" << std::endl;

    if(decode_failed){
        std::cout << "Status:            FAILURE (RS decode failed)" << std::endl;
        std::cout << "Unrecoverable RS blocks: " << unrecoverable_blocks << std::endl;
        return;
    }

    std::string actual_hash = blake3(recovered_data);

    if(actual_hash == expected_hash){
        std::cout << "Status:            SUCCESS (Integrity verified)" << std::endl;
    } else {
        std::cout << "Status:            FAILURE (Hash mismatch)" << std::endl;
    }
}

int main() {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(2);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(BATCH_SIZE);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE); cc->Enable(KEYSWITCH); cc->Enable(LEVELEDSHE);
    KeyPair<DCRTPoly> kp = cc->KeyGen();

    sender(cc, kp);
    receiver();
    return 0;
}