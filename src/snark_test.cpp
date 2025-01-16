#include <iostream>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/pb_variable.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

using namespace std;
using namespace libsnark;

typedef default_r1cs_ppzksnark_pp ppT;
typedef libff::Fr<ppT> FieldT;

class MultiplicationGadget : public gadget<FieldT>
{
private:
    pb_variable<FieldT> x;  // private input
    pb_variable<FieldT> y;  // private input
    pb_variable<FieldT> z;  // public output

public:
    MultiplicationGadget(
        protoboard<FieldT>& pb,
        const std::string& annotation_prefix)
        : gadget<FieldT>(pb, annotation_prefix)
    {
        // First allocate z (public output)
        z.allocate(pb, FMT("", "%s/z", annotation_prefix.c_str()));

        // Then allocate private inputs
        x.allocate(pb, FMT("", "%s/x", annotation_prefix.c_str()));
        y.allocate(pb, FMT("", "%s/y", annotation_prefix.c_str()));

        // Mark only z as public input
        pb.set_input_sizes(1);
    }

    void
    generate_r1cs_constraints()
    {
        // Constraint x * y = z
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(x, y, z),
            FMT("", "%s/multiplication", this->annotation_prefix.c_str()));
    }

    void
    generate_r1cs_witness(const FieldT& x_val, const FieldT& y_val)
    {
        this->pb.val(x) = x_val;
        this->pb.val(y) = y_val;
        this->pb.val(z) = x_val * y_val;
    }

    // Accessor methods
    const pb_variable<FieldT>&
    get_x() const
    {
        return x;
    }
    const pb_variable<FieldT>&
    get_y() const
    {
        return y;
    }
    const pb_variable<FieldT>&
    get_z() const
    {
        return z;
    }
};

void
test_basic_snark()
{
    std::cout << "Testing basic SNARK operation..." << std::endl;

    // Initialize the curve parameters
    ppT::init_public_params();

    // Create a protoboard
    protoboard<FieldT> pb;

    // Create and set up the gadget
    MultiplicationGadget multiplication_gadget(pb, "multiplication");
    multiplication_gadget.generate_r1cs_constraints();

    // Generate witness with x * y = z (3 * 4 = 12)
    multiplication_gadget.generate_r1cs_witness(FieldT(3), FieldT(4));

    // Debug output
    std::cout << "Number of constraints: "
              << pb.get_constraint_system().num_constraints() << std::endl;
    std::cout << "Primary (public) input size: " << pb.primary_input().size()
              << std::endl;
    std::cout << "Auxiliary (private) input size: "
              << pb.auxiliary_input().size() << std::endl;
    std::cout << "Expected result (z): " << pb.primary_input()[0] << std::endl;

    const r1cs_constraint_system<FieldT> constraint_system =
        pb.get_constraint_system();

    // Generate proving and verification keys
    std::cout << "Generating proving and verification keys..." << std::endl;
    const r1cs_ppzksnark_keypair<ppT> keypair =
        r1cs_ppzksnark_generator<ppT>(constraint_system);

    // Generate proof
    std::cout << "Generating proof..." << std::endl;
    const r1cs_ppzksnark_proof<ppT> proof = r1cs_ppzksnark_prover<ppT>(
        keypair.pk, pb.primary_input(), pb.auxiliary_input());

    // Verify the proof
    std::cout << "Verifying proof..." << std::endl;
    bool verified = r1cs_ppzksnark_verifier_strong_IC<ppT>(
        keypair.vk, pb.primary_input(), proof);

    std::cout << "Verification result: " << (verified ? "SUCCESS" : "FAILURE")
              << std::endl;
}

void
test_invalid_proof()
{
    std::cout << "\nTesting invalid SNARK proof..." << std::endl;

    ppT::init_public_params();
    protoboard<FieldT> pb;

    MultiplicationGadget multiplication_gadget(pb, "multiplication");
    multiplication_gadget.generate_r1cs_constraints();

    // Generate witness with x * y = z (3 * 4 = 12)
    multiplication_gadget.generate_r1cs_witness(FieldT(3), FieldT(4));

    const r1cs_constraint_system<FieldT> constraint_system =
        pb.get_constraint_system();

    // Generate keys and proof with correct values
    const r1cs_ppzksnark_keypair<ppT> keypair =
        r1cs_ppzksnark_generator<ppT>(constraint_system);

    const r1cs_ppzksnark_proof<ppT> proof = r1cs_ppzksnark_prover<ppT>(
        keypair.pk, pb.primary_input(), pb.auxiliary_input());

    // Create invalid input (claiming 3 * 4 = 13)
    std::vector<FieldT> invalid_input = pb.primary_input();
    invalid_input[0] = FieldT(13);

    // Verify with invalid input - should fail
    bool verified = r1cs_ppzksnark_verifier_strong_IC<ppT>(
        keypair.vk, invalid_input, proof);

    std::cout << "Invalid proof verification (should fail): "
              << (verified ? "SUCCESS" : "FAILURE") << std::endl;
}

int
main()
{
    test_basic_snark();
    test_invalid_proof();
    return 0;
}

/*
Compile and run with:

g++ -std=c++14 \
-I/home/wlin/rippled/external/libsnark \
-I/home/wlin/rippled/external/libsnark/depends/libff \
-I/home/wlin/rippled/external/libsnark/depends/libfqfft \
-L/home/wlin/rippled/external/libsnark/build/libsnark \
-L/home/wlin/rippled/external/libsnark/depends/libff/build/libff \
-DCURVE_ALT_BN128 \
snark_test.cpp -o snark_test_program \
-lsnark -lff -lgmp -lgmpxx -lprocps

./snark_test_program
*/