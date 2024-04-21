#ifndef __UTILS_H
#define __UTILS_H
#include <seal/context.h>
#include <seal/memorymanager.h>
#include <seal/seal.h>
#include <seal/util/iterator.h>
#include <seal/util/polyarithsmallmod.h>
#include <seal/util/polycore.h>

#include <chrono>
#include <iostream>
#include <vector>
class Timer
{
public:
  Timer() { _start = std::chrono::high_resolution_clock::now(); }

  inline double elapsed()
  {
    _end = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(_end - _start)
               .count() /
           1000.0;
  }

  inline void reset() { _start = std::chrono::high_resolution_clock::now(); }
  ~Timer(){};

private:
  std::chrono::high_resolution_clock::time_point _start, _end;
};

uint32_t next_power_of_2(uint32_t n);

uint64_t choose(uint64_t n, uint64_t k);

uint64_t choose_rotate_parms(const uint64_t &N, const uint64_t &num_payload_slot,
                             const uint64_t &num_selection_vector);

std::vector<uint32_t> get_perfect_constant_weight_codeword(
    uint64_t number, uint64_t encoding_size, uint64_t hamming_weight = 2);

std::pair<uint32_t, uint32_t> get_cw_code_k2(const uint64_t number, const uint64_t encoding_size);
uint64_t calculate_encoding_size(uint64_t col_size, uint64_t hamming_weight = 2);

void try_clear_irrelevant_bits(
    const seal::EncryptionParameters &parms, seal::Ciphertext &ciphertext);

// void tran_to_multiply_mid_form_inplace(const seal::SEALContext &context, seal::Ciphertext &encrypted, seal::MemoryPoolHandle pool = seal::MemoryManager::GetPool());

void multiply_mid_form(const seal::SEALContext &context, seal::Ciphertext &encrypted1, seal::Ciphertext &encrypted2, seal::Ciphertext &destination, seal::MemoryPoolHandle pool = seal::MemoryManager::GetPool());

void multiply(const seal::SEALContext &context, seal::Ciphertext &encrypted1, const seal::Ciphertext &encrypted2, seal::Ciphertext &destination, seal::MemoryPoolHandle pool = seal::MemoryManager::GetPool());

#endif
