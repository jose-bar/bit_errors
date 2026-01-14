#include "openfhe.h"
#include "blake3.h"

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

#include <iostream>
#include <iterator>
#include <fstream>
#include <sstream>
#include <vector>
#include <random>
#include <chrono>
#include <cstring>
#include <iomanip>

using namespace lbcrypto;

// Configs
const int NUM_CTS = 10;
const int BATCH_SIZE = 8192;
const double TARGET_BER = 1e-6; // bit error rate
const size_t CHUNK_SIZE = 16 * 1024; // 16 KB chunks
const size_t HASH_SIZE = 8; // truncated hash size in bytes

// truncated BLAKE3 hash
std::vector<uint8_t> calc_hash_chunk(const char* data, size_t len){
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, data, len);

    uint8_t output[BLAKE3_OUT_LEN];
    blake3_hasher_finalize(&hasher, output, BLAKE3_OUT_LEN);

    std::vector<uint8_t> truncated(output, output + HASH_SIZE);
    return truncated;
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
    size_t total_size = serialized.size();
    std::cout << "[Sender] Package size: " << total_size / (1024 * 1024) << " MB" << std::endl;

    // chunbk and write

    std::ofstream out_file("package_chunked.bin", std::ios::binary);
    out_file.write(reinterpret_cast<const char*>(&total_size), sizeof(total_size));

    size_t bytes_written = 0;
    size_t chunk_count = 0;

    auto start = std::chrono::high_resolution_clock::now();

    while(bytes_written < total_size){
        size_t curr_chunk_size = std::min(CHUNK_SIZE, total_size - bytes_written);
        const char* chunk_data = serialized.data() + bytes_written;

        std::vector<uint8_t> hash = calc_hash_chunk(chunk_data, curr_chunk_size);

        // write format: [Hash (8 bytes)][Data (N bytes)]
        out_file.write(reinterpret_cast<const char*>(hash.data()), HASH_SIZE);
        out_file.write(chunk_data, curr_chunk_size);

        bytes_written += curr_chunk_size;
        chunk_count++;
    }

    auto end = std::chrono::high_resolution_clock::now();
    out_file.close();
    std::cout << "[Sender] Total chunks: " << chunk_count << std::endl;
    std::cout << "[Sender] Chunked write/hash time: " << std::chrono::duration<double>(end - start).count() << " s" << std::endl;
    std::cout << "[Sender] Encryption for " << NUM_CTS << " CT: "
         << std::accumulate(encryption_times.begin(), encryption_times.end(), 0.0) << " s" << std::endl;
}

void receiver(){
    std::cout << "[Receiver] Reading package..." << std::endl;

    std::ifstream in_file("package_chunked.bin", std::ios::binary);
    if(!in_file.is_open()){ std::cerr << "[Receiver] Failed to open package_chunked.bin" << std::endl; return; }

    // read global header
    uint64_t exp_total_size;
    in_file.read(reinterpret_cast<char*>(&exp_total_size), sizeof(exp_total_size));

    std::vector<char> final_buffer;
    final_buffer.reserve(exp_total_size);

    size_t bytes_read = 0;
    size_t total_bytes = 0;
    int total_retransmission = 0;

    auto start = std::chrono::high_resolution_clock::now();

    while(bytes_read < exp_total_size){
        size_t curr_chunk_size = std::min(CHUNK_SIZE, (size_t) (exp_total_size - bytes_read));
        // remember file positions
        std::streampos chunk_start_pos = in_file.tellg();

        bool chunk_valid = false;
        int chunk_tries = 0;

        while (!chunk_valid){
            chunk_tries++;
            // read hash
            std::vector<uint8_t> exp_hash(HASH_SIZE);
            in_file.read(reinterpret_cast<char*>(exp_hash.data()), HASH_SIZE);
            // read data
            std::vector<uint8_t> chunk_data(curr_chunk_size);
            in_file.read(reinterpret_cast<char*>(chunk_data.data()), curr_chunk_size);

            total_bytes += HASH_SIZE + curr_chunk_size;

            // inject noise
            std::string chunk_str(reinterpret_cast<char*>(chunk_data.data()), curr_chunk_size);
            inject_noise(chunk_str, TARGET_BER);

            // verify hash
            std::vector<uint8_t> calc_hash = calc_hash_chunk(chunk_str.data(), curr_chunk_size);
            if(calc_hash == exp_hash){
                final_buffer.insert(final_buffer.end(), chunk_str.begin(), chunk_str.end());
                chunk_valid = true;
            }else{
                // failure, seek back and retry
                in_file.seekg(chunk_start_pos);
                total_retransmission++;
                if(chunk_tries % 10 == 0){
                    std::cout << "[Receiver] Chunk verification failed after " << chunk_tries << " tries, retrying..." << std::endl;
                }
            }

            if(chunk_tries >= 50){
                std::cerr << "[Receiver] Failed to verify chunk after " << chunk_tries << " tries, giving up." << std::endl;
                return;
            }
        }

        bytes_read += curr_chunk_size;
    }

    auto end = std::chrono::high_resolution_clock::now();
    double time_s = std::chrono::duration<double>(end - start).count();

    std::cout << "\n--- RESULTS ---" << std::endl;
    std::cout << "Total Time:       " << time_s << " s" << std::endl;
    std::cout << "Payload Size:     " << exp_total_size << " bytes" << std::endl;
    std::cout << "Total Transferred:" << total_bytes << " bytes" << std::endl;
    std::cout << "Overhead:         " << std::fixed << std::setprecision(2) 
              << (double(total_bytes) / exp_total_size * 100.0) - 100.0 << " %" << std::endl;
    std::cout << "Retransmissions:  " << total_retransmission << " chunks" << std::endl;
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
