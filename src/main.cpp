#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>

#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

#include <libsnark/common/default_types/r1cs_se_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_se_ppzksnark/r1cs_se_ppzksnark.hpp>

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_h_se_ppzksnark/r1cs_h_se_ppzksnark.hpp>

#include <vector>
#include <string>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <sstream>

#include <openssl/sha.h>

using namespace libsnark;

/**
 * The code below provides an example of all stages of running a R1CS GG-ppzkSNARK.
 *
 * Of course, in a real-life scenario, we would have three distinct entities,
 * mangled into one in the demonstration below. The three entities are as follows.
 * (1) The "generator", which runs the ppzkSNARK generator on input a given
 *     constraint system CS to create a proving and a verification key for CS.
 * (2) The "prover", which runs the ppzkSNARK prover on input the proving key,
 *     a primary input for CS, and an auxiliary input for CS.
 * (3) The "verifier", which runs the ppzkSNARK verifier on input the verification key,
 *     a primary input for CS, and a proof.
 */
template<typename ppT>
bool run_r1cs_gg_ppzksnark(const r1cs_example<libff::Fr<ppT> > &example, std::ofstream& outfile)
{
    auto start = std::chrono::high_resolution_clock::now();
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    outfile << "\n================================================================================\n";
    outfile << "R1CS GG-ppzkSNARK Generator\n";
    outfile << "================================================================================\n\n";
    // 密钥对
    start = std::chrono::high_resolution_clock::now();
    r1cs_gg_ppzksnark_keypair<ppT> keypair = r1cs_gg_ppzksnark_generator<ppT>(example.constraint_system);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start; outfile<< "Gen Key Time: " << elapsed.count() << "s" << std::endl;
    // 预处理vk
    start = std::chrono::high_resolution_clock::now();
    r1cs_gg_ppzksnark_processed_verification_key<ppT> pvk = r1cs_gg_ppzksnark_verifier_process_vk<ppT>(keypair.vk);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start; outfile<< "Preprocess Time: " << elapsed.count() << "s" << std::endl;
    // 生成证明
    start = std::chrono::high_resolution_clock::now();
    r1cs_gg_ppzksnark_proof<ppT> proof = r1cs_gg_ppzksnark_prover<ppT>(keypair.pk, example.primary_input, example.auxiliary_input);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start; outfile<< "Prove Time: " << elapsed.count() << "s" << std::endl;
    // 验证
    start = std::chrono::high_resolution_clock::now();
    const bool ans = r1cs_gg_ppzksnark_verifier_strong_IC<ppT>(keypair.vk, example.primary_input, proof);
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start; outfile<< "Verify Time: " << elapsed.count() << "s" << std::endl;
    // 
    start = std::chrono::high_resolution_clock::now();
    const bool ans2 = r1cs_gg_ppzksnark_online_verifier_strong_IC<ppT>(pvk, example.primary_input, proof);
    assert(ans == ans2);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start; outfile<< "Online Verify Time: " << elapsed.count() << "s" << std::endl;

    outfile << "================================================================================\n\n";
    outfile.close();
    return ans;
}

template<typename ppT>
bool run_r1cs_se_ppzksnark(const r1cs_example<libff::Fr<ppT> > &example, std::ofstream& outfile)
{
    libff::print_header("R1CS SE-ppzkSNARK Generator");
    auto start = std::chrono::high_resolution_clock::now();
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    outfile << "\n================================================================================\n";
    outfile << "R1CS SE-ppzkSNARK Generator\n";
    outfile << "================================================================================\n\n";
    // 密钥对
    start = std::chrono::high_resolution_clock::now();
    r1cs_se_ppzksnark_keypair<ppT> keypair = r1cs_se_ppzksnark_generator<ppT>(example.constraint_system);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start; outfile<< "Gen Key Time: " << elapsed.count() << "s" << std::endl;
    // 预处理vk
    start = std::chrono::high_resolution_clock::now();
    r1cs_se_ppzksnark_processed_verification_key<ppT> pvk = r1cs_se_ppzksnark_verifier_process_vk<ppT>(keypair.vk);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start; outfile<< "Preprocess Time: " << elapsed.count() << "s" << std::endl;
    // 证明
    start = std::chrono::high_resolution_clock::now();
    r1cs_se_ppzksnark_proof<ppT> proof = r1cs_se_ppzksnark_prover<ppT>(keypair.pk, example.primary_input, example.auxiliary_input);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start; outfile<< "Prove Time: " << elapsed.count() << "s" << std::endl;
    // 验证
    start = std::chrono::high_resolution_clock::now();
    const bool ans = r1cs_se_ppzksnark_verifier_strong_IC<ppT>(keypair.vk, example.primary_input, proof);
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start; outfile<< "Verify Time: " << elapsed.count() << "s" << std::endl;
    // 
    start = std::chrono::high_resolution_clock::now();
    const bool ans2 = r1cs_se_ppzksnark_online_verifier_strong_IC<ppT>(pvk, example.primary_input, proof);
    assert(ans == ans2);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start; outfile<< "Online Verify Time: " << elapsed.count() << "s" << std::endl;

    outfile << "================================================================================\n\n";
    outfile.close();
    return ans;

}

template<typename ppT>
bool run_r1cs_h_se_ppzksnark(const r1cs_example<libff::Fr<ppT> > &example, std::ofstream& outfile)
{
    auto start = std::chrono::high_resolution_clock::now();
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    outfile << "================================================================================\n";
    outfile << "ALgorithm: R1CS H SE GG-ppzkSNARK Generator\n";
    outfile << "================================================================================\n";
    // 密钥对
    start = std::chrono::high_resolution_clock::now();
    r1cs_h_se_ppzksnark_keypair<ppT> keypair = r1cs_h_se_ppzksnark_generator<ppT>(example.constraint_system);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start; outfile<< "Gen Key Time: " << elapsed.count() << "s" << std::endl;
    //  hash2Int(arrayToString(strings))<< std::endl; // 不同的曲线，可能出现不同的处理情况
    // keypair.vk.delta_g1.print_coordinates();
    // 预处理vk
    start = std::chrono::high_resolution_clock::now();
    r1cs_h_se_ppzksnark_processed_verification_key<ppT> pvk = r1cs_h_se_ppzksnark_verifier_process_vk<ppT>(keypair.vk);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start; outfile<< "Preprocess Time: " << elapsed.count() << "s" << std::endl;
    // 生成证明
    start = std::chrono::high_resolution_clock::now();
    r1cs_h_se_ppzksnark_proof<ppT> proof = r1cs_h_se_ppzksnark_prover<ppT>(keypair.pk, example.primary_input, example.auxiliary_input);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start; outfile<< "Prove Time: " << elapsed.count() << "s" << std::endl;
    
    // 验证
    start = std::chrono::high_resolution_clock::now();
    const bool ans = r1cs_h_se_ppzksnark_verifier_strong_IC<ppT>(keypair.vk, example.primary_input, proof);
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));
    outfile << "The verification result is: " << (ans ? "PASS" : "FAIL") << std::endl;
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start; outfile<< "Verify Time: " << elapsed.count() << "s" << std::endl;
    // 
    start = std::chrono::high_resolution_clock::now();
    const bool ans2 = r1cs_h_se_ppzksnark_online_verifier_strong_IC<ppT>(pvk, example.primary_input, proof);
    assert(ans == ans2);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start; outfile<< "Online Verify Time: " << elapsed.count() << "s" << std::endl;

    outfile << "================================================================================\n\n";
    outfile.close();
    return ans;
}

template<typename ppT>
void test_r1cs_gg_ppzksnark(size_t num_constraints, size_t input_size, std::ofstream& outfile)
{
    r1cs_example<libff::Fr<ppT> > example = generate_r1cs_example_with_binary_input<libff::Fr<ppT> >(num_constraints, input_size);
    const bool bit = run_r1cs_gg_ppzksnark<ppT>(example, outfile);
    assert(bit);
}

template<typename ppT>
void test_r1cs_se_ppzksnark(size_t num_constraints, size_t input_size, std::ofstream& outfile)
{
    r1cs_example<libff::Fr<ppT> > example = generate_r1cs_example_with_binary_input<libff::Fr<ppT> >(num_constraints, input_size);
    const bool bit = run_r1cs_se_ppzksnark<ppT>(example, outfile);

}

template<typename ppT>
void test_r1cs_h_se_ppzksnark(size_t num_constraints, size_t input_size, std::ofstream& outfile)
{
    // 这个是生成r1cs约束的例子，不设计电路就用这个
    r1cs_example<libff::Fr<ppT> > example = generate_r1cs_example_with_binary_input<libff::Fr<ppT> >(num_constraints, input_size);
    const bool bit = run_r1cs_h_se_ppzksnark<ppT>(example, outfile);
    assert(bit);
}

// 假设 BigInt 是一个类似于 big.Int 的 C++ 类型
using BigInt = std::vector<uint8_t>;

BigInt HashtoiInt(const std::string& strhash) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, strhash.c_str(), strhash.size());
    SHA256_Final(hash, &sha256);

    return BigInt(hash, hash + SHA256_DIGEST_LENGTH);
}

// std::tuple<BigInt, BigInt, BigInt, BigInt> PitoHashtoInt(const Proof& proof) {
//     std::vector<BigInt> aInt;
//     for (int i = 0; i < 3; ++i) {
//         aInt.push_back(proof.PiA[i]);
//     }
//     std::string strA = arrayToString(aInt); // 实现 arrayToString 函数
//     BigInt hashInta = HashtoiInt(strA);

//     std::vector<BigInt> bInt;
//     for (int i = 0; i < 3; ++i) {
//         for (int j = 0; j < 2; ++j) {
//             bInt.push_back(proof.PiB[i][j]);
//         }
//     }
//     std::string strB = arrayToString(bInt); // 实现 arrayToString 函数
//     BigInt hashIntb = HashtoiInt(strB);

//     return std::make_tuple(hashInta, hashIntb, aInt[0], bInt[0]);
// }

// 实现 arrayToString 函数
std::string arrayToString(const std::vector<BigInt>& array) {
    std::stringstream ss;
    for (const auto& item : array) {
        for (auto byte : item) {
            ss << std::hex << static_cast<int>(byte);
        }
    }
    return ss.str();
}

int main(int argc, char* argv[]) {
    // 设置默认值
    int num_constraints = 10000;
    int input_size = 100;

    if (argc < 2 || argc > 4) {
        std::cerr << "Usage: " << argv[0] << " <scheme> [num_constraints] [input_size]" << std::endl;
        std::cerr << "Available schemes: groth16, gm17, hse" << std::endl;
        return 1;
    }

    std::string scheme(argv[1]);

    // 如果提供了额外的参数，则更新默认值
    if (argc >= 3) {
        num_constraints = std::atoi(argv[2]);
    }
    if (argc == 4) {
        input_size = std::atoi(argv[3]);
    }

    if (num_constraints <= 0 || input_size <= 0) {
        std::cerr << "Number of constraints and input size must be positive integers." << std::endl;
        return 1;
    }

    // 输出文件
    std::ostringstream filename;
    filename << "output_" << scheme << ".txt";
    std::ofstream outfile(filename.str(), std::ios::app);
    if (!outfile.is_open()) {
        std::cerr << "Unable to open file for writing." << std::endl;
        return 1;
    }


    outfile << "================================================================================\n";
    if (scheme == "groth16") {
        outfile << "Constraints Num:"<< num_constraints << std::endl;
        outfile << "Input Size:"<< input_size << std::endl;
        default_r1cs_gg_ppzksnark_pp::init_public_params();
        test_r1cs_gg_ppzksnark<default_r1cs_gg_ppzksnark_pp>(num_constraints, input_size, outfile);
    } else if (scheme == "gm17") {
        outfile << "Constraints Num:"<< num_constraints << std::endl;
        outfile << "Input Size:"<< input_size << std::endl;
        default_r1cs_se_ppzksnark_pp::init_public_params();
        test_r1cs_se_ppzksnark<default_r1cs_se_ppzksnark_pp>(num_constraints, input_size, outfile);
    } else if (scheme == "sha") {
        std::vector<BigInt>* testValue = new std::vector<BigInt>();
        // TODO 这里存在一些类型转换的问题
        std::string strValue = arrayToString(*testValue);
        std::cout<<""<<std::endl;
    } else if (scheme == "hse") {
        outfile << "Constraints Num:"<< num_constraints << std::endl;
        outfile << "Input Size:"<< input_size << std::endl;
        default_r1cs_gg_ppzksnark_pp::init_public_params();
        test_r1cs_h_se_ppzksnark<default_r1cs_gg_ppzksnark_pp>(num_constraints, input_size, outfile);
    }else {
        std::cerr << "Invalid scheme. Available schemes: groth16, gm17" << std::endl;
        return 1;
    }

    return 0;
}
