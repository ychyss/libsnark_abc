#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/common/default_types/r1cs_se_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_se_ppzksnark/r1cs_se_ppzksnark.hpp>
#include <libsnark/gadgetlib1/pb_variable.hpp>

#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>

#include <vector>
#include <string>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>

#if _WIN32
// windows file api
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

using namespace libsnark;
using namespace std;

template<typename ppT>
int run_r1cs_gg_ppzksnark_setup(size_t num_constraints, size_t input_size, std::string outputDir)
{
    // 日志
    std::string logFileName = outputDir + "/log.txt";
    // 保存pk和vk到文件
    std::string pkFileName = outputDir + "/pk";
    std::string vkFileName = outputDir + "/vk";

    std::ofstream logFile(logFileName, std::ios::app);
    if (!logFile.is_open()) {
        std::cerr << "Unable to open file for writing." << std::endl;
        return 1;
    }
    std::ofstream pkFile(pkFileName, std::ios::binary);
    if (!pkFile.is_open()) {
        std::cerr << "Unable to open file for writing." << std::endl;
        return 1;
    }
    std::ofstream vkFile(vkFileName, std::ios::binary);
    if (!vkFile.is_open()) {
        std::cerr << "Unable to open file for writing." << std::endl;
        return 1;
    }
    
    logFile << "\n================================================================================\n";
    logFile << "Constraints Num:"<< num_constraints << std::endl;
    logFile << "Input Size:"<< input_size << std::endl;
    // 这个是生成r1cs约束的例子，不设计电路就用这个
    r1cs_example<libff::Fr<ppT> > example = generate_r1cs_example_with_binary_input<libff::Fr<ppT> >(num_constraints, input_size);

    auto start = std::chrono::high_resolution_clock::now();
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    logFile << "================================================================================\n";
    logFile << "ALgorithm: R1CS GG-ppzkSNARK Generator\n";
    logFile << "================================================================================\n";

    // 密钥对
    start = std::chrono::high_resolution_clock::now();
    r1cs_gg_ppzksnark_keypair<ppT> keypair = r1cs_gg_ppzksnark_generator<ppT>(example.constraint_system);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start; logFile<< "Gen Key Time: " << elapsed.count() << "s" << std::endl;
    
    pkFile << keypair.pk;
    pkFile.flush();
    pkFile.close();
    vkFile << keypair.vk;
    vkFile.flush();
    vkFile.close();

    logFile.flush();
    logFile.close();

    return 0;
}

template<typename ppT>
int run_r1cs_gg_ppzksnark_prove(size_t num_constraints, size_t input_size,std::string outputDir)
{
    // 日志
    std::string logFileName = outputDir + "/log.txt";
    // 
    std::string pkFileName = outputDir + "/pk";
    std::string proofFileName = outputDir + "/proof";

    std::ofstream logFile(logFileName, std::ios::app);
    if (!logFile.is_open()) {
        std::cerr << "Unable to open file for writing." << std::endl;
        return 1;
    }
    std::ifstream pkFile(pkFileName, std::ios::binary);
    if (!pkFile.is_open()) {
        std::cerr << "Unable to open file for writing." << std::endl;
        return 1;
    }
    std::ofstream proofFile(proofFileName, std::ios::binary);
    if (!proofFile.is_open()) {
        std::cerr << "Unable to open file for writing." << std::endl;
        return 1;
    }

    logFile << "\n================================================================================\n";
    logFile << "Constraints Num:"<< num_constraints << std::endl;
    logFile << "Input Size:"<< input_size << std::endl;
    // 这个是生成r1cs约束的例子，不设计电路就用这个
    r1cs_example<libff::Fr<ppT> > example = generate_r1cs_example_with_binary_input<libff::Fr<ppT> >(num_constraints, input_size);

    auto start = std::chrono::high_resolution_clock::now();
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    // 读取pk
    r1cs_gg_ppzksnark_proving_key<ppT> pk;
    pkFile >> pk;

    // 生成证明
    start = std::chrono::high_resolution_clock::now();
    r1cs_gg_ppzksnark_proof<ppT> proof = r1cs_gg_ppzksnark_prover<ppT>(pk, example.primary_input, example.auxiliary_input);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start; logFile<< "Prove Time: " << elapsed.count() << "s" << std::endl;
    proofFile << proof;
    proofFile.flush();
    proofFile.close();

    return 0;

}

template<typename ppT>
int run_r1cs_gg_ppzksnark_verify(size_t num_constraints, size_t input_size,std::string outputDir)
{
    // 日志
    std::string logFileName = outputDir + "/log.txt";
    // 
    std::string vkFileName = outputDir + "/vk";
    std::string proofFileName = outputDir + "/proof";

    std::ofstream logFile(logFileName, std::ios::app);
    if (!logFile.is_open()) {
        std::cerr << "Unable to open file for writing." << std::endl;
        return 1;
    }
    std::ifstream vkFile(vkFileName, std::ios::binary);
    if (!vkFile.is_open()) {
        std::cerr << "Unable to open file for writing." << std::endl;
        return 1;
    }
    std::ifstream proofFile(proofFileName, std::ios::binary);
    if (!proofFile.is_open()) {
        std::cerr << "Unable to open file for writing." << std::endl;
        return 1;
    }

    logFile << "\n================================================================================\n";
    logFile << "Constraints Num:"<< num_constraints << std::endl;
    logFile << "Input Size:"<< input_size << std::endl;
    // 这个是生成r1cs约束的例子，不设计电路就用这个
    r1cs_example<libff::Fr<ppT> > example = generate_r1cs_example_with_binary_input<libff::Fr<ppT> >(num_constraints, input_size);

    auto start = std::chrono::high_resolution_clock::now();
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    
    // 读取vk和proof
    r1cs_gg_ppzksnark_verification_key<ppT> vk;
    r1cs_gg_ppzksnark_proof<ppT> proof;
    vkFile >> vk; 
    proofFile >> proof;

    // 验证
    start = std::chrono::high_resolution_clock::now();
    const bool ans = r1cs_gg_ppzksnark_verifier_strong_IC<ppT>(vk, example.primary_input, proof);
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));
    logFile << "The verification result is: " << (ans ? "PASS" : "FAIL") << std::endl;
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start; logFile<< "Verify Time: " << elapsed.count() << "s" << std::endl;

    return ans ? 0 : 2; // 2 代表未通过
}

bool createDirectoryIfNotExists(const std::string& path) {
    struct stat info;
    if (stat(path.c_str(), &info) != 0) {
        // 尝试创建目录
        return mkdir(path.c_str(), 0755) == 0; // 使用适当的权限
    } else if (info.st_mode & S_IFDIR) {
        return true; // 目录已存在
    }
    return false; // 路径存在，但不是一个目录
}


int test_groth16() {
    // groth16的实现是在zk_proof_systems/r1cs_gg_ppzksnark中
    typedef libff::Fr<default_r1cs_gg_ppzksnark_pp> FieldT;

    // Initialize the curve parameters
    default_r1cs_gg_ppzksnark_pp::init_public_params();
  
    // Create protoboard
    protoboard<FieldT> pb;

    // Define variables
    pb_variable<FieldT> x;
    pb_variable<FieldT> sym_1;
    pb_variable<FieldT> y;
    pb_variable<FieldT> sym_2;
    pb_variable<FieldT> out;

    // Allocate variables to protoboard
    // The strings (like "x") are only for debugging purposes    
    out.allocate(pb, "out");
    x.allocate(pb, "x");
    sym_1.allocate(pb, "sym_1");
    y.allocate(pb, "y");
    sym_2.allocate(pb, "sym_2");

    // This sets up the protoboard variables
    // so that the first one (out) represents the public
    // input and the rest is private input
    pb.set_input_sizes(1);

    // Add R1CS constraints to protoboard
    // x*x = sym_1
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x, x, sym_1));
    // sym_1 * x = y
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(sym_1, x, y));
    // y + x = sym_2
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(y + x, 1, sym_2));
    // sym_2 + 5 = ~out
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(sym_2 + 5, 1, out));
    
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

    // generate keypair
    const r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> keypair = r1cs_gg_ppzksnark_generator<default_r1cs_gg_ppzksnark_pp>(constraint_system);

    // Add public input and witness values
    pb.val(out) = 35;
    pb.val(x) = 3;
    pb.val(sym_1) = 9;
    pb.val(y) = 27;
    pb.val(sym_2) = 30;

    // generate proof
    const r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> proof = r1cs_gg_ppzksnark_prover<default_r1cs_gg_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());

    // verify
    bool verified = r1cs_gg_ppzksnark_verifier_strong_IC<default_r1cs_gg_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);

    cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    cout << "Primary (public) input: " << pb.primary_input() << endl;
    cout << "Auxiliary (private) input: " << pb.auxiliary_input() << endl;
    cout << "Verification status: " << verified << endl;

    return 0;
}

int test_gm17() {
    // 使用zk_proof_systems/r1cs_se_ppzksnark进行gm17算法的测试
    typedef libff::Fr<default_r1cs_se_ppzksnark_pp> FieldT;

    // Initialize the curve parameters
    default_r1cs_se_ppzksnark_pp::init_public_params();

    // Create protoboard
    protoboard<FieldT> pb;

    // Define and allocate variables, similar to test_groth16
    pb_variable<FieldT> x;
    pb_variable<FieldT> sym_1;
    pb_variable<FieldT> y;
    pb_variable<FieldT> sym_2;
    pb_variable<FieldT> out;

    // Allocate variables to protoboard
    // The strings (like "x") are only for debugging purposes    
    out.allocate(pb, "out");
    x.allocate(pb, "x");
    sym_1.allocate(pb, "sym_1");
    y.allocate(pb, "y");
    sym_2.allocate(pb, "sym_2");

    // This sets up the protoboard variables
    // so that the first one (out) represents the public
    // input and the rest is private input
    pb.set_input_sizes(1);

    // Add R1CS constraints to protoboard
    // x*x = sym_1
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x, x, sym_1));
    // sym_1 * x = y
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(sym_1, x, y));
    // y + x = sym_2
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(y + x, 1, sym_2));
    // sym_2 + 5 = ~out
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(sym_2 + 5, 1, out));

    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

    // Generate keypair
    const r1cs_se_ppzksnark_keypair<default_r1cs_se_ppzksnark_pp> keypair = r1cs_se_ppzksnark_generator<default_r1cs_se_ppzksnark_pp>(constraint_system);

    // Add public input and witness values
    pb.val(out) = 35;
    pb.val(x) = 3;
    pb.val(sym_1) = 9;
    pb.val(y) = 27;
    pb.val(sym_2) = 30;

    // Generate proof
    const r1cs_se_ppzksnark_proof<default_r1cs_se_ppzksnark_pp> proof = r1cs_se_ppzksnark_prover<default_r1cs_se_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());

    // Verify
    bool verified = r1cs_se_ppzksnark_verifier_strong_IC<default_r1cs_se_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);

    cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    cout << "Primary (public) input: " << pb.primary_input() << endl;
    cout << "Auxiliary (private) input: " << pb.auxiliary_input() << endl;
    cout << "Verification status: " << verified << endl;

    return 0;
}

int main (int argc, char* argv[]) {
    
    // if (argc != 2) {
    //     std::cerr << "Usage: " << argv[0] << " <scheme>" << std::endl;
    //     std::cerr << "Available schemes: groth16, gm17" << std::endl;
    //     return 1;
    // }
    // std::string scheme(argv[1]);

    // if (scheme == "groth16") {
    //     return test_groth16();
    // } else if (scheme == "gm17") {
    //     return test_gm17();
    // } else {
    //     std::cerr << "Invalid scheme. Available schemes: groth16, gm17" << std::endl;
    //     return 1;
    // }

    if (argc < 5) {
        std::cerr << "Usage: " << argv[0] << " <setup|prove|verify> num_constraints input_size outputDir" << std::endl;
        return 1;
    }

    std::string mode = argv[1];
    size_t num_constraints = std::stoul(argv[2]);
    size_t input_size = std::stoul(argv[3]);
    std::string outputDir = argv[4];

    if (num_constraints <= 0 || input_size <= 0) {
        std::cerr << "Number of constraints and input size must be positive integers." << std::endl;
        return 1;
    }

    // 确保输出目录存在
    if (!createDirectoryIfNotExists(outputDir)) {
        std::cerr << "Failed to create or access output directory." << std::endl;
        return 1;
    }

    // 初始化公共参数
    default_r1cs_gg_ppzksnark_pp::init_public_params();

    if (mode == "setup") {
        run_r1cs_gg_ppzksnark_setup<default_r1cs_gg_ppzksnark_pp>(num_constraints, input_size, outputDir);
    } else if (mode == "prove") {
        run_r1cs_gg_ppzksnark_prove<default_r1cs_gg_ppzksnark_pp>(num_constraints, input_size, outputDir);
    } else if (mode == "verify") {
        run_r1cs_gg_ppzksnark_verify<default_r1cs_gg_ppzksnark_pp>(num_constraints, input_size, outputDir);
    } else {
        std::cerr << "Invalid mode. Use 'setup', 'prove', or 'verify'." << std::endl;
        return 1;
    }

}
