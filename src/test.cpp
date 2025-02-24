#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <iostream>

int main() {
    libff::alt_bn128_pp::init_public_params();
    std::cout << "Curve parameters initialized" << std::endl;
    return 0;
}