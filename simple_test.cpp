// simple_test.cpp
#include "openfhe.h"
#include <iostream>



using namespace lbcrypto;

int main() {
    // 1. Setup the crypto context
    // We'll use a very simple setup just to check if it compiles/runs
    uint32_t multDepth = 1;
    uint32_t scaleModSize = 50;
    uint32_t batchSize = 8;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    
    // Enable features
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    std::cout << "OpenFHE context generated successfully!" << std::endl;
    std::cout << "CKKS scheme is ready." << std::endl;

    return 0;
}