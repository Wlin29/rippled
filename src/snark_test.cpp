#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/gadgetlib1/pb_variable.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <iostream>

using namespace libsnark;

// Simple test gadget for verifying x * y = z
class MultiplicationGadget : public gadget<Fr<default_r1cs_ppzksnark_pp>> {
public:
    pb_variable<Fr<default_r1cs_ppzksnark_pp>> x;
    pb_variable<Fr<default_r1cs_ppzksnark_pp>> y;
    pb_variable<Fr<default_r1cs_ppzksnark_pp>> z;

    MultiplicationGadget(
        protoboard<Fr<default_r1cs_ppzksnark_pp>>& pb,
        const std::string& annotation_prefix
    ) : gadget<Fr<default_r1cs_ppzksnark_pp>>(pb, annotation_prefix) {
        x.allocate(pb, "x");
        y.allocate(pb, "y");
        z.allocate(pb, "z");
    }

    void generate_r1cs_constraints() {
        this->pb.add_r1cs_constraint(
            r1cs_constraint<Fr<default_r1cs_ppzksnark_pp>>(
                x, y, z
            ),
            "z = x * y"
        );
    }

    void generate_r1cs_witness(uint64_t x_val, uint64_t y_val) {
        this->pb.val(x) = x_val;
        this->pb.val(y) = y_val;
        this->pb.val(z) = x_val * y_val;
    }
};

void test_basic_snark() {
    std::cout << "Testing basic SNARK operation..." << std::endl;

    // Initialize the curve parameters
    default_r1cs_ppzksnark_pp::init_public_params();

    // Create a protoboard
    protoboard<Fr<default_r1cs_ppzksnark_pp>> pb;
    MultiplicationGadget multiplication_gadget(pb, "multiplication");
    multiplication_gadget.generate_r1cs_constraints();

    // Test values
    const uint64_t x_val = 3;
    const uint64_t y_val = 4;
    multiplication_gadget.generate_r1cs_witness(x_val, y_val);

    // Generate proving and verification keys
    const r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keypair = 
        r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(pb.get_constraint_system());

    // Generate proof
    const r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof = 
        r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(
            keypair.pk,
            pb.primary_input(),
            pb.auxiliary_input()
        );

    // Verify the proof
    bool verified = r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(
        keypair.vk,
        pb.primary_input(),
        proof
    );

    std::cout << "Verification result: " << (verified ? "SUCCESS" : "FAILURE") << std::endl;
}

void test_invalid_proof() {
    std::cout << "\nTesting invalid SNARK proof..." << std::endl;

    // Initialize the curve parameters
    default_r1cs_ppzksnark_pp::init_public_params();

    // Create a protoboard
    protoboard<Fr<default_r1cs_ppzksnark_pp>> pb;
    MultiplicationGadget multiplication_gadget(pb, "multiplication");
    multiplication_gadget.generate_r1cs_constraints();

    // Generate witness with x * y = z (3 * 4 = 12)
    multiplication_gadget.generate_r1cs_witness(3, 4);

    // Generate proving and verification keys
    const r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keypair = 
        r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(pb.get_constraint_system());

    // Generate proof
    const r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof = 
        r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(
            keypair.pk,
            pb.primary_input(),
            pb.auxiliary_input()
        );

    // Modify the primary input to make it invalid (as if claiming 3 * 4 = 13)
    auto invalid_input = pb.primary_input();
    invalid_input[0] = Fr<default_r1cs_ppzksnark_pp>("13");

    // Verify with invalid input - should fail
    bool verified = r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(
        keypair.vk,
        invalid_input,
        proof
    );

    std::cout << "Invalid proof verification (should fail): " << (verified ? "SUCCESS" : "FAILURE") << std::endl;
}

int main() {
    test_basic_snark();
    test_invalid_proof();
    return 0;
}