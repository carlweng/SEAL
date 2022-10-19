#pragma once

#include "seal/util/seal_patch.h"
#include "seal/encryptor.h"

namespace seal {

class EncryptorExtended : public Encryptor
{
private:
    /* data */
public:
    EncryptorExtended(const SEALContext &context, const SecretKey &secret_key) :
        Encryptor(context, secret_key) {}

 void encrypt_zero_internal_seeding_all(const SEALContext &context_, const SecretKey &secret_key_,
        parms_id_type parms_id, bool is_asymmetric, const prng_seed_type &public_seed, 
        const prng_seed_type &noise_seed, Ciphertext &destination, MemoryPoolHandle pool) const;

    void encrypt_internal_seeding_all(const SEALContext &context_, const SecretKey &secret_key_,
        const Plaintext &plain, bool is_asymmetric, const prng_seed_type &public_seed, 
        const prng_seed_type &noise_seed, Ciphertext &destination, MemoryPoolHandle pool) const;

    inline void encrypt_symmetric(const SEALContext &context_, const SecretKey &secret_key_,
        const Plaintext &plain, const prng_seed_type &public_seed, const prng_seed_type &noise_seed,
        Ciphertext &destination, MemoryPoolHandle pool) const;
};

} // namespace seal
