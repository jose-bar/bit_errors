#include "openfhe.h"
#include "blake3.h"

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <queue>
#include <unordered_map>
#include <cstring>
#include <cmath>
#include <random>
#include <chrono>
#include <iomanip>

using namespace lbcrypto;

// ---------------- CONFIG ----------------
const int NUM_CTS = 10;
const int BATCH_SIZE = 8192;
const size_t CHUNK_SIZE = 16 * 1024; // 16KB
const size_t HASH_SIZE = 32;         // BLAKE3 Default
const double TARGET_BER = 1e-5;      // Moderate Noise

// ---------------- BLAKE3 ----------------
std::vector<uint8_t> blake3_hash(const void* data, size_t len) {
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, data, len);
    uint8_t out[BLAKE3_OUT_LEN];
    blake3_hasher_finalize(&h, out, BLAKE3_OUT_LEN);
    return std::vector<uint8_t>(out, out + HASH_SIZE);
}

// ---------------- MERKLE TREE ----------------
class MerkleTree {
public:
    size_t real_leaves;
    size_t padded_leaves;
    const std::vector<uint8_t>& data; 
    std::unordered_map<uint32_t, std::vector<uint8_t>> cache;

    // Constructor accepts reference
    MerkleTree(const std::vector<uint8_t>& d) : data(d) {
        real_leaves = (data.size() + CHUNK_SIZE - 1) / CHUNK_SIZE;
        padded_leaves = 1;
        while (padded_leaves < real_leaves)
            padded_leaves <<= 1;
    }

    std::vector<uint8_t> root() {
        return node_hash(1);
    }

    std::vector<uint8_t> node_hash(uint32_t node_id) {
        if (cache.count(node_id))
            return cache[node_id];

        size_t level = 0;
        uint32_t tmp = node_id;
        while (tmp >>= 1) level++;

        size_t span = padded_leaves >> level;
        size_t start = (node_id - (1u << level)) * span;

        std::vector<uint8_t> h;
        if (span == 1) { // Leaf Level
            h = leaf_hash(start);
        } else {         // Inner Node
            auto L = node_hash(node_id * 2);
            auto R = node_hash(node_id * 2 + 1);
            h = inner_hash(L, R);
        }

        cache[node_id] = h;
        return h;
    }

private:
    std::vector<uint8_t> leaf_hash(size_t idx) {
        uint8_t prefix = 0x00; // Domain separation for leaves

        // Handle padding nodes (beyond real data)
        if (idx >= real_leaves) {
            return blake3_hash(&prefix, 1);
        }

        size_t off = idx * CHUNK_SIZE;
        size_t len = std::min(CHUNK_SIZE, data.size() - off);

        std::vector<uint8_t> buf(1 + len);
        buf[0] = prefix;
        std::memcpy(buf.data() + 1, data.data() + off, len);
        return blake3_hash(buf.data(), buf.size());
    }

    std::vector<uint8_t> inner_hash(const std::vector<uint8_t>& L,
                                    const std::vector<uint8_t>& R) {
        uint8_t prefix = 0x01; // Domain separation for inner nodes
        std::vector<uint8_t> buf(1 + L.size() + R.size());
        buf[0] = prefix;
        std::memcpy(buf.data() + 1, L.data(), L.size());
        std::memcpy(buf.data() + 1 + L.size(), R.data(), R.size());
        return blake3_hash(buf.data(), buf.size());
    }
};

// ---------------- NOISE ----------------
void inject_noise(std::vector<uint8_t>& data, double ber) {
    if (ber <= 0) return;
    static std::mt19937 rng(1337);
    std::uniform_real_distribution<> p(0.0, 1.0);
    std::uniform_int_distribution<> bit(0, 7);

    // Optimization: Skip bytes to simulate sparse error
    // For large buffers, iterating every byte is slow if BER is low.
    for (size_t i = 0; i < data.size(); ++i) {
         if (p(rng) < ber * 8) data[i] ^= (1 << bit(rng));
    }
}

// ---------------- SERVER SIMULATION ----------------
std::vector<uint8_t> SERVER_DATA;
MerkleTree* SERVER_TREE = nullptr;

std::vector<uint8_t> server_get_hash(uint32_t node_id) {
    // Simulating Network Request for Hash
    return SERVER_TREE->node_hash(node_id);
}

std::vector<uint8_t> server_get_chunk(size_t idx) {
    // Simulating Network Request for Data Chunk
    size_t off = idx * CHUNK_SIZE;
    size_t len = std::min(CHUNK_SIZE, SERVER_DATA.size() - off);
    return std::vector<uint8_t>(
        SERVER_DATA.begin() + off,
        SERVER_DATA.begin() + off + len
    );
}

// ---------------- SENDER ----------------
void setup_sender(const CryptoContext<DCRTPoly>& cc,
                  const KeyPair<DCRTPoly>& kp) {

    std::cout << "[Sender] Generating Ciphertexts..." << std::endl;
    std::stringstream ss;
    for (int i = 0; i < NUM_CTS; i++) {
        std::vector<double> v(BATCH_SIZE);
        for (int j = 0; j < BATCH_SIZE; j++) v[j] = j + i;
        Plaintext pt = cc->MakeCKKSPackedPlaintext(v);
        auto ct = cc->Encrypt(kp.publicKey, pt);
        Serial::Serialize(ct, ss, SerType::BINARY);
    }

    std::string s = ss.str();
    SERVER_DATA.assign(s.begin(), s.end());

    // Measure Tree Build Time
    auto start_build = std::chrono::high_resolution_clock::now();
    SERVER_TREE = new MerkleTree(SERVER_DATA);
    auto root = SERVER_TREE->root(); // Triggers full build
    auto end_build = std::chrono::high_resolution_clock::now();

    // Write to disk
    std::ofstream out("package_merkle.bin", std::ios::binary);
    out.write((char*)root.data(), HASH_SIZE);
    out.write((char*)SERVER_DATA.data(), SERVER_DATA.size());
    out.close();

    std::cout << "[Sender] Payload Size: " << SERVER_DATA.size() / (1024.0*1024.0) << " MB\n";
    std::cout << "[Sender] Tree Build Time: " 
              << std::chrono::duration<double>(end_build - start_build).count() << " s\n";
    std::cout << "[Sender] Root Hash: ";
    for(int i=0; i<4; i++) std::cout << std::hex << (int)root[i];
    std::cout << "..." << std::endl;
}

// ---------------- RECEIVER ----------------
void run_receiver() {
    std::cout << "\n[Receiver] Downloading Package..." << std::endl;
    std::ifstream in("package_merkle.bin", std::ios::binary);
    std::vector<uint8_t> expected_root(HASH_SIZE);
    in.read((char*)expected_root.data(), HASH_SIZE);
    
    std::vector<uint8_t> local_data{
        std::istreambuf_iterator<char>(in),
        std::istreambuf_iterator<char>()
    };
    in.close();

    // Reset stream to Decimal mode (Fixes the "1e3" issue)
    std::cout << std::dec; 

    // Simulating Network Noise
    std::cout << "[Receiver] Injecting Noise (BER " << TARGET_BER << ")..." << std::endl;
    inject_noise(local_data, TARGET_BER);

    // Initial Verification
    auto start_total = std::chrono::high_resolution_clock::now();
    
    // Pass local_data by reference. 
    // Any change to local_data is immediately visible to local_tree.
    MerkleTree local_tree(local_data); 
    
    auto initial_root = local_tree.root();
    auto end_detect = std::chrono::high_resolution_clock::now();

    if (initial_root == expected_root) {
        std::cout << "[Receiver] Integrity Verified immediately. No repairs needed.\n";
        return;
    }

    std::cout << "[Receiver] Root Mismatch. Starting Interactive Repair...\n";

    size_t bytes_overhead = 0;
    int rtts = 0;
    int chunks_repaired = 0;

    struct Task { uint32_t id; size_t start, end; };
    std::queue<Task> q;
    q.push({1, 0, local_tree.padded_leaves});

    while (!q.empty()) {
        auto t = q.front(); q.pop();

        auto srv = server_get_hash(t.id);
        auto loc = local_tree.node_hash(t.id);
        
        rtts++; 
        bytes_overhead += HASH_SIZE;

        if (srv == loc) continue; 

        if (t.end - t.start == 1) {
            size_t idx = t.start;
            auto fresh = server_get_chunk(idx);
            
            rtts++; 
            bytes_overhead += fresh.size();
            chunks_repaired++;

            // Patch memory (Visible to local_tree because it holds a reference)
            size_t off = idx * CHUNK_SIZE;
            std::memcpy(local_data.data() + off, fresh.data(), fresh.size());
            
            // Invalidate THIS leaf in cache so subsequent checks see new data
            local_tree.cache.erase(t.id);
            continue;
        }

        size_t mid = (t.start + t.end) / 2;
        q.push({t.id * 2,     t.start, mid});
        q.push({t.id * 2 + 1, mid,     t.end});
    }

    // FINAL VERIFICATION
    // Clear the cache to force a full re-hash of the now-patched data
    local_tree.cache.clear(); 
    auto final_root = local_tree.root(); 
    auto end_total = std::chrono::high_resolution_clock::now();

    // Stats Output
    double detect_time = std::chrono::duration<double>(end_detect - start_total).count();
    double repair_time = std::chrono::duration<double>(end_total - end_detect).count();
    double total_time  = std::chrono::duration<double>(end_total - start_total).count();
    
    std::cout << "\n--- RESULTS (Merkle Interactive) ---\n";
    std::cout << "Status:           " << (final_root == expected_root ? "SUCCESS" : "FAILED") << "\n";
    std::cout << "Chunks Repaired:  " << chunks_repaired << "\n";
    std::cout << "Extra RTTs:       " << rtts << " (Requests to server)\n";
    std::cout << "Bandwidth Overhead: " << bytes_overhead << " bytes (" 
              << std::fixed << std::setprecision(2) 
              << (double)bytes_overhead / local_data.size() * 100.0 << "%)\n";
    
    std::cout << "Latency Breakdown:\n";
    std::cout << "  - Detection:    " << detect_time << " s\n";
    std::cout << "  - Repair:       " << repair_time << " s\n";
    std::cout << "  - Total:        " << total_time << " s\n";
}

// ---------------- MAIN ----------------
int main() {
    CCParams<CryptoContextCKKSRNS> params;
    params.SetMultiplicativeDepth(2);
    params.SetScalingModSize(50);
    params.SetBatchSize(BATCH_SIZE);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    auto kp = cc->KeyGen();

    setup_sender(cc, kp);
    run_receiver();
    return 0;
}