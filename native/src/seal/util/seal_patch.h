#pragma once

#include "seal/ciphertext.h"
#include "seal/randomgen.h"
#include "seal/randomtostd.h"
#include "seal/util/rlwe.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/scalingvariant.h"

namespace seal {
namespace util {

// symmetric encryption with specific public seed and seed for noise
static void encrypt_zero_symmetric_seeding_all(
    const SecretKey &secret_key, const SEALContext &context, parms_id_type parms_id, bool is_ntt_form,
    const prng_seed_type &public_seed, const prng_seed_type &noise_seed, Ciphertext &destination)
{
    // save the public seed 
    bool save_seed = true;
#ifdef SEAL_DEBUG
    if (!is_valid_for(secret_key, context))
    {
        throw invalid_argument("secret key is not valid for the encryption parameters");
    }
#endif
    // We use a fresh memory pool with `clear_on_destruction' enabled.
    MemoryPoolHandle pool = MemoryManager::GetPool(mm_prof_opt::mm_force_new, true);

    auto &context_data = *context.get_context_data(parms_id);
    auto &parms = context_data.parms();
    auto &coeff_modulus = parms.coeff_modulus();
    auto &plain_modulus = parms.plain_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t coeff_count = parms.poly_modulus_degree();
    auto ntt_tables = context_data.small_ntt_tables();
    size_t encrypted_size = 2;
    scheme_type type = parms.scheme();

    // If a polynomial is too small to store UniformRandomGeneratorInfo,
    // it is best to just disable save_seed. Note that the size needed is
    // the size of UniformRandomGeneratorInfo plus one (uint64_t) because
    // of an indicator word that indicates a seeded ciphertext.
    size_t poly_uint64_count = mul_safe(coeff_count, coeff_modulus_size);
    size_t prng_info_byte_count =
        static_cast<size_t>(UniformRandomGeneratorInfo::SaveSize(compr_mode_type::none));
    size_t prng_info_uint64_count =
        divide_round_up(prng_info_byte_count, static_cast<size_t>(bytes_per_uint64));
    if (save_seed && poly_uint64_count < prng_info_uint64_count + 1)
    {
        save_seed = false;
    }

    destination.resize(context, parms_id, encrypted_size);
    destination.is_ntt_form() = is_ntt_form;
    destination.scale() = 1.0;
    destination.correction_factor() = 1;

    // Set up a new default PRNG for expanding u from the seed sampled above
    auto ciphertext_prng = UniformRandomGeneratorFactory::DefaultFactory()->create(public_seed);

    // Generate ciphertext: (c[0], c[1]) = ([-(as+ e)]_q, a) in BFV/CKKS
    // Generate ciphertext: (c[0], c[1]) = ([-(as+pe)]_q, a) in BGV
    uint64_t *c0 = destination.data();
    uint64_t *c1 = destination.data(1);

    // Sample a uniformly at random
    if (is_ntt_form || !save_seed)
    {
        // Sample the NTT form directly
        sample_poly_uniform(ciphertext_prng, parms, c1);
    }
    else if (save_seed)
    {
        // Sample non-NTT form and store the seed
        sample_poly_uniform(ciphertext_prng, parms, c1);
        for (size_t i = 0; i < coeff_modulus_size; i++)
        {
            // Transform the c1 into NTT representation
            ntt_negacyclic_harvey(c1 + i * coeff_count, ntt_tables[i]);
        }
    }

    // Set up a new default PRNG for expanding u from the seed sampled above
    auto noise_prng = UniformRandomGeneratorFactory::DefaultFactory()->create(noise_seed);

    // Sample e <-- chi
    auto noise(allocate_poly(coeff_count, coeff_modulus_size, pool));
    SEAL_NOISE_SAMPLER(noise_prng, parms, noise.get());

    // Calculate -(as+ e) (mod q) and store in c[0] in BFV/CKKS
    // Calculate -(as+pe) (mod q) and store in c[0] in BGV
    for (size_t i = 0; i < coeff_modulus_size; i++)
    {
        dyadic_product_coeffmod(
            secret_key.data().data() + i * coeff_count, c1 + i * coeff_count, coeff_count, coeff_modulus[i],
            c0 + i * coeff_count);
        if (is_ntt_form)
        {
            // Transform the noise e into NTT representation
            ntt_negacyclic_harvey(noise.get() + i * coeff_count, ntt_tables[i]);
        }
        else
        {
            inverse_ntt_negacyclic_harvey(c0 + i * coeff_count, ntt_tables[i]);
        }

        if (type == scheme_type::bgv)
        {
            // noise = pe instead of e in BGV
            multiply_poly_scalar_coeffmod(
                noise.get() + i * coeff_count, coeff_count, plain_modulus.value(), coeff_modulus[i],
                noise.get() + i * coeff_count);
        }

        // c0 = as + noise
        add_poly_coeffmod(
            noise.get() + i * coeff_count, c0 + i * coeff_count, coeff_count, coeff_modulus[i],
            c0 + i * coeff_count);
        // (as + noise, a) -> (-(as + noise), a),
        negate_poly_coeffmod(c0 + i * coeff_count, coeff_count, coeff_modulus[i], c0 + i * coeff_count);
    }

    if (!is_ntt_form && !save_seed)
    {
        for (size_t i = 0; i < coeff_modulus_size; i++)
        {
            // Transform the c1 into non-NTT representation
            inverse_ntt_negacyclic_harvey(c1 + i * coeff_count, ntt_tables[i]);
        }
    }

    if (save_seed)
    {
        UniformRandomGeneratorInfo prng_info = ciphertext_prng->info();

        // Write prng_info to destination.data(1) after an indicator word
        c1[0] = static_cast<uint64_t>(0xFFFFFFFFFFFFFFFFULL);
        prng_info.save(reinterpret_cast<seal_byte *>(c1 + 1), prng_info_byte_count, compr_mode_type::none);
    }
}

} // namespace util
} // namespace seal
