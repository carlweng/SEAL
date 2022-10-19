#include "seal/seal_patch.h"

namespace seal
{

    void EncryptorExtended::encrypt_zero_internal_seeding_all(
        const SEALContext &context_, const SecretKey &secret_key_,
        parms_id_type parms_id, bool is_asymmetric, const prng_seed_type &public_seed, 
        const prng_seed_type &noise_seed, Ciphertext &destination, MemoryPoolHandle pool) const {
            // Verify parameters.
            if (!pool)
            {
                throw std::invalid_argument("pool is uninitialized");
            }

            auto context_data_ptr = context_.get_context_data(parms_id);
            if (!context_data_ptr)
            {
                throw std::invalid_argument("parms_id is not valid for encryption parameters");
            }

            auto &context_data = *context_.get_context_data(parms_id);
            auto &parms = context_data.parms();
            size_t coeff_modulus_size = parms.coeff_modulus().size();
            size_t coeff_count = parms.poly_modulus_degree();
            bool is_ntt_form = false;

            if (parms.scheme() == scheme_type::ckks)
            {
                is_ntt_form = true;
            }
            else if (parms.scheme() != scheme_type::bfv && parms.scheme() != scheme_type::bgv)
            {
                throw std::invalid_argument("unsupported scheme");
            }

            // Resize destination and save results
            destination.resize(context_, parms_id, 2);

            // If asymmetric key encryption
            if (is_asymmetric)
            {
                // TODO: we just don't need asymmetric key encryption currently
            }
            else
            {
                // Does not require modulus switching
                util::encrypt_zero_symmetric_seeding_all(
                    secret_key_, context_, parms_id, is_ntt_form, public_seed, noise_seed, destination);
            }
    }


    void EncryptorExtended::encrypt_internal_seeding_all(
        const SEALContext &context_, const SecretKey &secret_key_,
        const Plaintext &plain, bool is_asymmetric, const prng_seed_type &public_seed, 
        const prng_seed_type &noise_seed, Ciphertext &destination, MemoryPoolHandle pool) const {
            // Minimal verification that the keys are set
            if (is_asymmetric)
            {
                // TODO: we just don't need the asymmetric case currently
            }
            else
            {
                if (!is_metadata_valid_for(secret_key_, context_))
                {
                    throw std::logic_error("secret key is not set");
                }
            }

            // Verify that plain is valid
            if (!is_valid_for(plain, context_))
            {
                throw std::invalid_argument("plain is not valid for encryption parameters");
            }

            auto scheme = context_.key_context_data()->parms().scheme();
            if (scheme == scheme_type::bfv)
            {
                // TODO: we just don't work on bfv currently
            }
            else if (scheme == scheme_type::ckks)
            {
                // TODO: we just don't work on ckks currently
            }
            else if (scheme == scheme_type::bgv)
            {
                if (plain.is_ntt_form())
                {
                    throw std::invalid_argument("plain cannot be in NTT form");
                }
                encrypt_zero_internal_seeding_all(context_, secret_key_, 
                    context_.first_parms_id(), is_asymmetric, public_seed, noise_seed, destination, pool);
                auto context_data_ptr = context_.first_context_data();
                auto &parms = context_data_ptr->parms();
                size_t coeff_count = parms.poly_modulus_degree();
                // c_{0} = pk_{0}*u + p*e_{0} + M
                util::add_plain_without_scaling_variant(
                    plain, *context_data_ptr, util::RNSIter(destination.data(0), coeff_count));
            }
            else
            {
                throw std::invalid_argument("unsupported scheme");
            }
    }

    inline void EncryptorExtended::encrypt_symmetric(
        const SEALContext &context_, const SecretKey &secret_key_,
        const Plaintext &plain, const prng_seed_type &public_seed, const prng_seed_type &noise_seed,
        Ciphertext &destination, MemoryPoolHandle pool = MemoryManager::GetPool()) const
    {
        encrypt_internal_seeding_all(
            context_, secret_key_, plain, false, public_seed, noise_seed, destination, pool);
    }


} // namespace seal
