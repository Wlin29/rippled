#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <iostream>

int main() {
    libsnark::default_r1cs_ppzksnark_pp::init_public_params();
    std::cout << "libsnark is correctly linked and initialized." << std::endl;
    return 0;
}
