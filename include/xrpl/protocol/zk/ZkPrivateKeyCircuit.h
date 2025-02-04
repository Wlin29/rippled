
#ifndef ZK_PRIVATE_KEY_CIRCUIT_H
#define ZK_PRIVATE_KEY_CIRCUIT_H

#include <string>
#include <libsnark/gadgetlib1/gadget.hpp>

using namespace libsnark;

class ZkPrivateKeyCircuit : public gadget<FieldT>
{
private:
    pb_variable<FieldT> pk;

    pb_variable<FieldT> sk;

    pb_variable<FieldT> g;

public:
    ZkPrivateKeyCircuit(
        protoboard<FieldT>& pb,
        const std::string& annotation_prefix);

    void
    generate_r1cs_constraints();

    void
    generate_r1cs_witness(const FieldT& sk_val, const FieldT& g_val);

    const pb_variable<FieldT>&
    get_private_key() const;

    const pb_variable<FieldT>&
    get_generator() const;

    const pb_variable<FieldT>&
    get_public_key() const;
};

#endif
