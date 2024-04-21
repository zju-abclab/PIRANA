#include "pir_parms.h"

#include <map>
#include <unordered_set>

#include "assert.h"
#include "utils.h"

PirParms::PirParms(const uint64_t num_payloads, const uint64_t payload_size)
    : _payload_size(payload_size), _num_query(1) {
  _num_payloads = next_power_of_2(num_payloads);
  uint64_t poly_degree = 8192;
  std::vector<int> coeff_modulus = {56, 56, 24, 24};
  uint64_t plain_prime_len = 31;

  set_seal_parms(poly_degree, coeff_modulus, plain_prime_len);
  _col_size = ceil(num_payloads / _seal_parms.poly_modulus_degree());
  _encoding_size = calculate_encoding_size(_col_size);

  _num_payload_slot = std::ceil(payload_size * 8.0 / (plain_prime_len - 1));

  _pre_rotate = choose_rotate_parms(poly_degree, _num_payload_slot, _col_size);

  // if n is smaller than the poly degree
  if (std::floor(poly_degree / num_payloads)) {
    // duplicate the selection vector to fill the n slots
    _pre_rotate =
        std::max(_pre_rotate, uint64_t(std::floor(poly_degree / num_payloads)));
  }

  assert(poly_degree % _pre_rotate == 0 && "Wrong parameters selection!");

  _rotate_step = poly_degree / _pre_rotate;
  print_seal_parms();
  print_pir_parms();
};

void PirParms::set_seal_parms(uint64_t poly_degree,
                              std::vector<int> coeff_modulus,
                              uint64_t prime_len) {
  _seal_parms = seal::EncryptionParameters(seal::scheme_type::bfv);
  _seal_parms.set_poly_modulus_degree(poly_degree);
  _seal_parms.set_coeff_modulus(
      seal::CoeffModulus::Create(poly_degree, coeff_modulus));
  _seal_parms.set_plain_modulus(
      seal::PlainModulus::Batching(poly_degree, prime_len));
}

void PirParms::print_seal_parms() {
  std::string scheme_name;
  if (_seal_parms.scheme() == seal::scheme_type::bfv)
    scheme_name = "BFV";
  else {
    throw std::invalid_argument("unsupported scheme");
  }

  std::cout << "/" << std::endl;
  std::cout << "|   Encryption parameters: " << std::endl;
  std::cout << "|   scheme: " << scheme_name << std::endl;
  std::cout << "|   poly_modulus_degree: " << _seal_parms.poly_modulus_degree()
            << std::endl;
  /*
    For the BFV scheme print the plain_modulus parameter.
    */
  if (_seal_parms.scheme() == seal::scheme_type::bfv) {
    std::cout << "|   plain_modulus: " << _seal_parms.plain_modulus().value()
              << std::endl;
  }
  /*
  Print the size of the true (product) coefficient modulus.
  */
  std::cout << "|   coeff_modulus size: ";
  std::cout << " (";
  uint64_t total_coeff_modulus = 0;
  auto coeff_modulus = _seal_parms.coeff_modulus();
  std::size_t coeff_modulus_size = coeff_modulus.size();
  for (std::size_t i = 0; i < coeff_modulus_size - 1; i++) {
    std::cout << coeff_modulus[i].bit_count() << " + ";
    total_coeff_modulus += coeff_modulus[i].bit_count();
  }
  std::cout << coeff_modulus.back().bit_count();
  total_coeff_modulus += coeff_modulus.back().bit_count();
  std::cout << ") " << total_coeff_modulus << " bits" << std::endl;

  std::cout << "\\" << std::endl;
};

uint64_t get_bucket_size(std::vector<std::vector<uint32_t>> &bucket) {
  uint64_t max_size = 0;
  for (auto &b : bucket) {
    max_size = std::max(b.size(), max_size);
  }
  return max_size;
}

// Using cuckoo factor to balance between the insert failure and comm cost
// cuckoo table size
// num_slot
// bundle_size
void PirParms::get_all_index_hash_result(const uint64_t num_payloads,
                                         const uint64_t num_query,
                                         const double cuckoo_factor) {
  std::cout << "--------------------------------------" << std::endl;
  std::cout << "Preprocessing cuckoo hash!" << std::endl;

  uint32_t N = _seal_parms.poly_modulus_degree();
  // If the number of query is large enough, the response utilization rate is
  // high. There is no more space to futher compress.
  if (static_cast<uint32_t>(num_query * cuckoo_factor) >= N) {
    _is_compress = false;
  }

  if (_is_compress == false) {
    // One response ciphertext only has one slot payload in each bucket;
    _bundle_size = 0;
    while (_bundle_size * N <
           static_cast<uint32_t>(num_query * cuckoo_factor)) {
      _bundle_size++;
    }
    _table_size = _bundle_size * N;
    _num_slot = 1;
  } else {
    _table_size = static_cast<uint32_t>(num_query * cuckoo_factor);
    assert(_table_size < N);
    _num_slot = std::floor(N / _table_size);
    // 1. Ensure cuckoo hash table size > cuckoo factor * the number of query
    // 2. Make the most of space as much as possible
    // e.g. N = 4096, query = 256
    // cuckoo table size : B = 256 * 1.5 = 384
    // For compress : using 4096 / 384 = 10 slot to carry result
    // Enlarge the table size to 409 -> low cuckoo hash failure rate and low col
    // size
    // -> low communication cost and low computation cost
    _table_size = std::floor(N / _num_slot);
    _bundle_size = 1;
  }
  auto stash_size = static_cast<uint32_t>(0);

  uint8_t hash_count = 3;
  kuku::item_type hash_seed = kuku::make_item(1, 0);
  uint64_t max_probe = 100;
  kuku::item_type empty_item = kuku::make_item(0xFFFF, 0);

  std::cout << "Table size (B = 1.5L): " << _table_size << std::endl;
  _table = std::make_shared<kuku::KukuTable>(
      _table_size, stash_size, hash_count, hash_seed, max_probe, empty_item);

  _bucket.resize(_table_size);
  for (uint64_t index = 0; index < num_payloads; index++) {
    auto result = _table->all_locations(kuku::make_item(0, index));
    for (auto &position : result) {
      _bucket[position].push_back(index);
      if (_hash_index.count(std::to_string(index * _table_size + position)) !=
          0) {
        std::cout << "hash string error: " << index << std::endl;
      }
      assert(_hash_index.count(
                 std::to_string(index * _table_size + position)) == 0);
      _hash_index[std::to_string(index * _table_size + position)] =
          _bucket[position].size() - 1;
    }
  }

  _col_size = get_bucket_size(_bucket);
  _cw_index.resize(_col_size);
  _encoding_size = calculate_encoding_size(_col_size);
  for (uint64_t index = 0; index < _col_size; index++) {
    _cw_index[index] = get_cw_code_k2(index, _encoding_size);
  }
  std::cout << "Cuckoo hash done!" << std::endl;
}

// index -> cw is regular;

PirParms::PirParms(const uint64_t num_payloads, const uint64_t payload_size,
                   const uint64_t num_query, const bool is_batch,
                   const bool is_compress, const bool enable_rotate)
    : _num_payloads(num_payloads),
      _payload_size(payload_size),
      _num_query(num_query),
      _is_compress(is_compress),
      _enable_rotate(enable_rotate) {
  // Todo: add rotate version

  assert(is_batch == true && num_query > 1);

  uint64_t poly_degree = 4096;
  std::vector<int> coeff_modulus = {48, 32, 24};

  uint64_t plain_prime_len = is_compress? 18 : 17;

  set_seal_parms(poly_degree, coeff_modulus, plain_prime_len);

  _num_payload_slot = std::ceil(payload_size * 8.0 / (plain_prime_len - 1));

  get_all_index_hash_result(num_payloads, num_query);

  // _rotate_step = poly_degree / _pre_rotate;
  print_seal_parms();
  print_pir_parms();
}

void PirParms::print_pir_parms() {
  std::cout << "--------------------------------------" << std::endl;
  std::cout << "/" << std::endl;
  std::cout << "|   PIR parameters: " << std::endl;
  std::cout << "|   Number of payloads (n): " << _num_payloads << std::endl;
  std::cout << "|   Payload size (|pl|): " << _payload_size << " Bytes"
            << std::endl;
  std::cout << "|   Number of payload slot: " << _num_payload_slot << std::endl;
  std::cout << "|   Number of query (L): " << _num_query << std::endl;
  std::cout << "|   Col Size: " << _col_size << std::endl;

  std::cout << "|   Hamming weight (k): " << _hamming_weight << std::endl;
  std::cout << "|   Encoding size (m): " << _encoding_size << std::endl;
  std::cout << "\\" << std::endl;
}
