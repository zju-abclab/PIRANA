#include "utils.h"

#include <assert.h>
#include <cmath>
uint32_t next_power_of_2(uint32_t n) {
    // If the input number is already a power of 2, return it
    if (n && !(n & (n - 1)))
        return n;

    // Set all bits to the right of the most significant bit
    while (n & (n - 1))
        n &= n - 1;

    // Left shift by 1 and add 1 to get the next power of 2 greater than the input number
    return n << 1;
}
uint64_t calculate_encoding_size(uint64_t col_size, uint64_t hamming_weight)
{
  uint64_t encoding_size = 2;
  while (choose(encoding_size, hamming_weight) < (col_size))
  {
    encoding_size++;
  }
  return encoding_size;
}

uint64_t choose(uint64_t n, uint64_t k)
{
  if (k > n)
  {
    return 0;
  }
  uint64_t r = 1;
  for (uint64_t d = 1; d <= k; ++d)
  {
    r *= n--;
    r /= d;
  }
  return r;
}

void try_clear_irrelevant_bits(
    const seal::EncryptionParameters &parms, seal::Ciphertext &ciphertext)
{
  // If the parameter set has only one prime, we can compress the ciphertext by
  // setting low-order bits to zero. This effectively maxes out the noise, but that
  // doesn't matter as long as we don't use quite all noise budget.
  if (parms.coeff_modulus().size() == 1)
  {
    // The number of data bits we need to have left in each ciphertext coefficient
    int compr_coeff_bit_count =
        parms.plain_modulus().bit_count() +
        seal::util::get_significant_bit_count(parms.poly_modulus_degree())
        // Being pretty aggressive here
        - 1;

    int coeff_mod_bit_count = parms.coeff_modulus()[0].bit_count();

    // The number of bits to set to zero
    int irrelevant_bit_count = coeff_mod_bit_count - compr_coeff_bit_count;

    // Can compression achieve anything?
    if (irrelevant_bit_count > 0)
    {
      // Mask for zeroing out the irrelevant bits
      uint64_t mask = ~((uint64_t(1) << irrelevant_bit_count) - 1);
      seal_for_each_n(seal::util::iter(ciphertext), ciphertext.size(), [&](auto &&I)
                      {
                            // We only have a single RNS component so dereference once more
                            seal_for_each_n(
                                *I, parms.poly_modulus_degree(), [&](auto &J) { J &= mask; }); });
    }
  }
}

std::pair<uint32_t, uint32_t> get_cw_code_k2(const uint64_t number, const uint64_t encoding_size)
{
  std::pair<uint32_t, uint32_t> ans;
  const uint64_t hamming_weight = 2;
  uint64_t mod_size = choose(encoding_size, hamming_weight);
  assert(number < mod_size);

  int64_t remainder = number, k_prime = hamming_weight;
  for (int64_t pointer = encoding_size - 1; pointer >= 0 && k_prime > 0;
       pointer--)
  {
    if (remainder >= choose(pointer, k_prime))
    {
      if (k_prime == 2)
      {
        ans.first = pointer;
      }
      else
      {
        ans.second = pointer;
      }
      remainder -= choose(pointer, k_prime);
      k_prime -= 1;
    }
  }
  return ans;
}
std::vector<uint32_t> get_perfect_constant_weight_codeword(uint64_t number, uint64_t encoding_size, uint64_t hamming_weight)
{

  std::vector<uint32_t> ans(hamming_weight, 0ULL);

  uint32_t mod_size = choose(encoding_size, hamming_weight);
  assert(number < mod_size);

  int32_t remainder = number, k_prime = hamming_weight;
  for (int32_t pointer = encoding_size - 1; pointer >= 0 && k_prime > 0;
       pointer--)
  {
    if (remainder >= choose(pointer, k_prime))
    {
      ans.at(k_prime - 1) = pointer;
      remainder -= choose(pointer, k_prime);
      k_prime -= 1;
    }
  }
  return ans;
}

// return the number of rotation times for selection vector
uint64_t choose_rotate_parms(const uint64_t &N, const uint64_t &num_payload_slot,
                             const uint64_t &num_selection_vector)
{
  uint64_t rotate_expand = 1;
  uint64_t min_rotation = INT64_MAX;
  uint64_t num_output_cipher = std::ceil(num_payload_slot * 1.0 / N);
  while (1)
  {
    auto total_rot_times = (rotate_expand - 1) * num_selection_vector +
                           (uint64_t)(std::ceil((double)std::min(N, num_payload_slot) /
                                                rotate_expand) -
                                      1) *
                               num_output_cipher;

    // update the min of total rotation times
    if (total_rot_times < min_rotation && rotate_expand <= N)
    {
      min_rotation = total_rot_times;
    }
    else
    {
      break;
    }
    rotate_expand *= 2;
  }
  return rotate_expand / 2;
}

void tran_to_multiply_mid_form_inplace(const seal::SEALContext &context, seal::Ciphertext &encrypted, seal::MemoryPoolHandle pool)
{
  auto &context_data = *context.get_context_data(encrypted.parms_id());
  auto &parms = context_data.parms();

  size_t coeff_count = parms.poly_modulus_degree();
  size_t base_q_size = parms.coeff_modulus().size();
  size_t encrypted_size = encrypted.size();
  uint64_t plain_modulus = parms.plain_modulus().value();

  auto rns_tool = context_data.rns_tool();
  size_t base_Bsk_size = rns_tool->base_Bsk()->size();
  size_t base_Bsk_m_tilde_size = rns_tool->base_Bsk_m_tilde()->size();

  // Set up iterators for bases
  auto base_q = seal::util::iter(parms.coeff_modulus());
  auto base_Bsk = seal::util::iter(rns_tool->base_Bsk()->base());

  // Set up iterators for NTT tables
  auto base_q_ntt_tables = seal::util::iter(context_data.small_ntt_tables());
  auto base_Bsk_ntt_tables = seal::util::iter(rns_tool->base_Bsk_ntt_tables());

  // Microsoft SEAL uses BEHZ-style RNS multiplication. This process is somewhat complex and consists of the
  // following steps:
  //
  // (1) Lift encrypted1 and encrypted2 (initially in base q) to an extended base q U Bsk U {m_tilde}
  // (2) Remove extra multiples of q from the results with Montgomery reduction, switching base to q U Bsk
  // (3) Transform the data to NTT form

  // This lambda function takes as input an IterTuple with three components:
  //
  // 1. (Const)RNSIter to read an input polynomial from
  // 2. RNSIter for the output in base q
  // 3. RNSIter for the output in base Bsk
  //
  // It performs steps (1)-(3) of the BEHZ multiplication (see above) on the given input polynomial (given as an
  // RNSIter or ConstRNSIter) and writes the results in base q and base Bsk to the given output
  // iterators.
  auto behz_extend_base_convert_to_ntt = [&](auto I)
  {
    // Make copy of input polynomial (in base q) and convert to NTT form
    // Lazy reduction
    set_poly(std::get<0>(I), coeff_count, base_q_size, std::get<1>(I));
    ntt_negacyclic_harvey_lazy(std::get<1>(I), base_q_size, base_q_ntt_tables);

    // Allocate temporary space for a polynomial in the Bsk U {m_tilde} base
    SEAL_ALLOCATE_GET_RNS_ITER(temp, coeff_count, base_Bsk_m_tilde_size, pool);

    // (1) Convert from base q to base Bsk U {m_tilde}
    rns_tool->fastbconv_m_tilde(std::get<0>(I), temp, pool);

    // (2) Reduce q-overflows in with Montgomery reduction, switching base to Bsk
    rns_tool->sm_mrq(temp, std::get<2>(I), pool);

    // Transform to NTT form in base Bsk
    // Lazy reduction
    ntt_negacyclic_harvey_lazy(std::get<2>(I), base_Bsk_size, base_Bsk_ntt_tables);
  };

  // Allocate space for a base q output of behz_extend_base_convert_to_ntt for encrypted1
  SEAL_ALLOCATE_GET_POLY_ITER(encrypted_q, encrypted_size, coeff_count, base_q_size, pool);
  // auto eq(seal::util::allocate_poly_array(encrypted_size, coeff_count, base_q_size, pool));
  // seal::util::PolyIter encrypted_q(eq.get(), coeff_count, base_q_size);
  // Allocate space for a base Bsk output of behz_extend_base_convert_to_ntt for encrypted1
  SEAL_ALLOCATE_GET_POLY_ITER(encrypted_Bsk, encrypted_size, coeff_count, base_Bsk_size, pool);

  // Perform BEHZ steps (1)-(3) for encrypted1
  SEAL_ITERATE(seal::util::iter(encrypted, encrypted_q, encrypted_Bsk), encrypted_size, behz_extend_base_convert_to_ntt);
  // return std::make_pair(encrypted_q, encrypted_Bsk);
}

void multiply(const seal::SEALContext &context, seal::Ciphertext &encrypted1, const seal::Ciphertext &encrypted2, seal::Ciphertext &destination, seal::MemoryPoolHandle pool)
{
  destination = encrypted1;

  // Extract encryption parameters.
  auto &context_data = *context.get_context_data(encrypted1.parms_id());
  auto &parms = context_data.parms();

  size_t coeff_count = parms.poly_modulus_degree();
  size_t base_q_size = parms.coeff_modulus().size();
  size_t encrypted1_size = encrypted1.size();
  size_t encrypted2_size = encrypted2.size();
  uint64_t plain_modulus = parms.plain_modulus().value();

  auto rns_tool = context_data.rns_tool();
  size_t base_Bsk_size = rns_tool->base_Bsk()->size();
  size_t base_Bsk_m_tilde_size = rns_tool->base_Bsk_m_tilde()->size();

  // // Determine destination.size()
  size_t dest_size = seal::util::sub_safe(seal::util::add_safe(encrypted1_size, encrypted2_size), size_t(1));

  // // Size check
  if (!seal::util::product_fits_in(dest_size, coeff_count, base_Bsk_m_tilde_size))
  {
    throw std::logic_error("invalid parameters");
  }

  // Set up iterators for bases
  auto base_q = seal::util::iter(parms.coeff_modulus());
  auto base_Bsk = seal::util::iter(rns_tool->base_Bsk()->base());

  // Set up iterators for NTT tables
  auto base_q_ntt_tables = seal::util::iter(context_data.small_ntt_tables());
  auto base_Bsk_ntt_tables = seal::util::iter(rns_tool->base_Bsk_ntt_tables());

  // Microsoft SEAL uses BEHZ-style RNS multiplication. This process is somewhat complex and consists of the
  // following steps:
  //
  // (1) Lift encrypted1 and encrypted2 (initially in base q) to an extended base q U Bsk U {m_tilde}
  // (2) Remove extra multiples of q from the results with Montgomery reduction, switching base to q U Bsk
  // (3) Transform the data to NTT form
  // (4) Compute the ciphertext polynomial product using dyadic multiplication
  // (5) Transform the data back from NTT form
  // (6) Multiply the result by t (plain_modulus)
  // (7) Scale the result by q using a divide-and-floor algorithm, switching base to Bsk
  // (8) Use Shenoy-Kumaresan method to convert the result to base q

  // Resize encrypted1 to destination size
  destination.resize(context, context_data.parms_id(), dest_size);

  // This lambda function takes as input an IterTuple with three components:
  //
  // 1. (Const)RNSIter to read an input polynomial from
  // 2. RNSIter for the output in base q
  // 3. RNSIter for the output in base Bsk
  //
  // It performs steps (1)-(3) of the BEHZ multiplication (see above) on the given input polynomial (given as an
  // RNSIter or ConstRNSIter) and writes the results in base q and base Bsk to the given output
  // iterators.
  auto behz_extend_base_convert_to_ntt = [&](auto I)
  {
    // Make copy of input polynomial (in base q) and convert to NTT form
    // Lazy reduction
    set_poly(std::get<0>(I), coeff_count, base_q_size, std::get<1>(I));
    ntt_negacyclic_harvey_lazy(std::get<1>(I), base_q_size, base_q_ntt_tables);

    // Allocate temporary space for a polynomial in the Bsk U {m_tilde} base
    SEAL_ALLOCATE_GET_RNS_ITER(temp, coeff_count, base_Bsk_m_tilde_size, pool);

    // (1) Convert from base q to base Bsk U {m_tilde}
    rns_tool->fastbconv_m_tilde(std::get<0>(I), temp, pool);

    // (2) Reduce q-overflows in with Montgomery reduction, switching base to Bsk
    rns_tool->sm_mrq(temp, std::get<2>(I), pool);

    // Transform to NTT form in base Bsk
    // Lazy reduction
    ntt_negacyclic_harvey_lazy(std::get<2>(I), base_Bsk_size, base_Bsk_ntt_tables);
  };

  // Allocate space for a base q output of behz_extend_base_convert_to_ntt for encrypted1
  SEAL_ALLOCATE_GET_POLY_ITER(encrypted1_q, encrypted1_size, coeff_count, base_q_size, pool);

  // Allocate space for a base Bsk output of behz_extend_base_convert_to_ntt for encrypted1
  SEAL_ALLOCATE_GET_POLY_ITER(encrypted1_Bsk, encrypted1_size, coeff_count, base_Bsk_size, pool);

  // Perform BEHZ steps (1)-(3) for encrypted1
  SEAL_ITERATE(seal::util::iter(encrypted1, encrypted1_q, encrypted1_Bsk), encrypted1_size, behz_extend_base_convert_to_ntt);

  // Repeat for encrypted2
  SEAL_ALLOCATE_GET_POLY_ITER(encrypted2_q, encrypted2_size, coeff_count, base_q_size, pool);
  SEAL_ALLOCATE_GET_POLY_ITER(encrypted2_Bsk, encrypted2_size, coeff_count, base_Bsk_size, pool);

  SEAL_ITERATE(seal::util::iter(encrypted2, encrypted2_q, encrypted2_Bsk), encrypted2_size, behz_extend_base_convert_to_ntt);

  // Allocate temporary space for the output of step (4)
  // We allocate space separately for the base q and the base Bsk components
  SEAL_ALLOCATE_ZERO_GET_POLY_ITER(temp_dest_q, dest_size, coeff_count, base_q_size, pool);
  SEAL_ALLOCATE_ZERO_GET_POLY_ITER(temp_dest_Bsk, dest_size, coeff_count, base_Bsk_size, pool);

  // Perform BEHZ step (4): dyadic multiplication on arbitrary size ciphertexts
  SEAL_ITERATE(seal::util::iter(size_t(0)), dest_size, [&](auto I)
               {
    // We iterate over relevant components of encrypted1 and encrypted2 in increasing order for
    // encrypted1 and reversed (decreasing) order for encrypted2. The bounds for the indices of
    // the relevant terms are obtained as follows.
    size_t curr_encrypted1_last = std::min<size_t>(I, encrypted1_size - 1);
    size_t curr_encrypted2_first = std::min<size_t>(I, encrypted2_size - 1);
    size_t curr_encrypted1_first = I - curr_encrypted2_first;
    size_t curr_encrypted2_last = I - curr_encrypted1_last;

    // The total number of dyadic products is now easy to compute
    size_t steps = curr_encrypted1_last - curr_encrypted1_first + 1;

    // This lambda function computes the ciphertext product for BFV multiplication. Since we use the BEHZ
    // approach, the multiplication of individual polynomials is done using a dyadic product where the inputs
    // are already in NTT form. The arguments of the lambda function are expected to be as follows:
    //
    // 1. a ConstPolyIter pointing to the beginning of the first input ciphertext (in NTT form)
    // 2. a ConstPolyIter pointing to the beginning of the second input ciphertext (in NTT form)
    // 3. a ConstModulusIter pointing to an array of Modulus elements for the base
    // 4. the size of the base
    // 5. a PolyIter pointing to the beginning of the output ciphertext
    auto behz_ciphertext_product = [&](seal::util::ConstPolyIter in1_iter, seal::util::ConstPolyIter in2_iter, seal::util::ConstModulusIter base_iter, size_t base_size, seal::util::PolyIter out_iter)
    {
      // Create a shifted iterator for the first input
      auto shifted_in1_iter = in1_iter + curr_encrypted1_first;

      // Create a shifted reverse iterator for the second input
      auto shifted_reversed_in2_iter = seal::util::reverse_iter(in2_iter + curr_encrypted2_first);

      // Create a shifted iterator for the output
      auto shifted_out_iter = out_iter[I];

      SEAL_ITERATE(seal::util::iter(shifted_in1_iter, shifted_reversed_in2_iter), steps, [&](auto J)
                   { SEAL_ITERATE(seal::util::iter(J, base_iter, shifted_out_iter), base_size, [&](auto K)
                                  {
                                    SEAL_ALLOCATE_GET_COEFF_ITER(temp, coeff_count, pool);
                                    seal::util::dyadic_product_coeffmod(seal::util::get<0, 0>(K), seal::util::get<0, 1>(K), coeff_count, std::get<1>(K), temp);
                                    seal::util::add_poly_coeffmod(temp, std::get<2>(K), coeff_count, std::get<1>(K), std::get<2>(K)); 
                                    }); });
                                  };
                                  // Perform the BEHZ ciphertext product both for base q and base Bsk
                                  behz_ciphertext_product(encrypted1_q, encrypted2_q, base_q, base_q_size, temp_dest_q); behz_ciphertext_product(encrypted1_Bsk, encrypted2_Bsk, base_Bsk, base_Bsk_size, temp_dest_Bsk); });

  // Perform BEHZ step (5): transform data from NTT form
  // Lazy reduction here. The following multiply_poly_scalar_coeffmod will correct the value back to [0, p)
  inverse_ntt_negacyclic_harvey_lazy(temp_dest_q, dest_size, base_q_ntt_tables);
  inverse_ntt_negacyclic_harvey_lazy(temp_dest_Bsk, dest_size, base_Bsk_ntt_tables);

  // Perform BEHZ steps (6)-(8)
  SEAL_ITERATE(seal::util::iter(temp_dest_q, temp_dest_Bsk, destination), dest_size, [&](auto I)
               {
            // Bring together the base q and base Bsk components into a single allocation
            SEAL_ALLOCATE_GET_RNS_ITER(temp_q_Bsk, coeff_count, base_q_size + base_Bsk_size, pool);

            // Step (6): multiply base q components by t (plain_modulus)
            multiply_poly_scalar_coeffmod(std::get<0>(I), base_q_size, plain_modulus, base_q, temp_q_Bsk);

            multiply_poly_scalar_coeffmod(std::get<1>(I), base_Bsk_size, plain_modulus, base_Bsk, temp_q_Bsk + base_q_size);

            // Allocate yet another temporary for fast divide-and-floor result in base Bsk
            SEAL_ALLOCATE_GET_RNS_ITER(temp_Bsk, coeff_count, base_Bsk_size, pool);

            // Step (7): divide by q and floor, producing a result in base Bsk
            rns_tool->fast_floor(temp_q_Bsk, temp_Bsk, pool);

            // Step (8): use Shenoy-Kumaresan method to convert the result to base q and write to encrypted1
            rns_tool->fastbconv_sk(temp_Bsk, std::get<2>(I), pool); });
}
