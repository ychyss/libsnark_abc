#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>

#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

#include <libsnark/common/default_types/r1cs_se_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_se_ppzksnark/r1cs_se_ppzksnark.hpp>

#include <iostream>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <sstream>

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

int main(int argc, char* argv[]) {
    // 设置默认值
    int num_constraints = 10000;
    int input_size = 100;

    if (argc < 2 || argc > 4) {
        std::cerr << "Usage: " << argv[0] << " <scheme> [num_constraints] [input_size]" << std::endl;
        std::cerr << "Available schemes: groth16, gm17" << std::endl;
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
    outfile << "Constraints Num:"<< num_constraints << std::endl;
    outfile << "Input Size:"<< input_size << std::endl;

    if (scheme == "groth16") {
        default_r1cs_gg_ppzksnark_pp::init_public_params();
        test_r1cs_gg_ppzksnark<default_r1cs_gg_ppzksnark_pp>(num_constraints, input_size, outfile);
    } else if (scheme == "gm17") {
        default_r1cs_se_ppzksnark_pp::init_public_params();
        test_r1cs_se_ppzksnark<default_r1cs_se_ppzksnark_pp>(num_constraints, input_size, outfile);
    } else {
        std::cerr << "Invalid scheme. Available schemes: groth16, gm17" << std::endl;
        return 1;
    }

    return 0;
}
