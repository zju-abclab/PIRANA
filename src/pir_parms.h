#ifndef __PIR_PARMS_H
#define __PIR_PARMS_H
#include <kuku/kuku.h>
#include <kuku/locfunc.h>

#include <map>
#include <vector>

#include "seal/seal.h"
#include "utils.h"

class PirParms {
 private:
  const uint64_t _hamming_weight = 2;
  const uint64_t _num_hash = 3;
  uint64_t _num_payloads;
  uint64_t _payload_size;
  uint64_t _num_query;
  uint64_t _col_size;
  uint64_t _encoding_size;
  uint64_t _pre_rotate;
  uint64_t _rotate_step;
  uint64_t _num_payload_slot;

  seal::EncryptionParameters _seal_parms;

  // available only in batch pir
  std::shared_ptr<kuku::KukuTable> _table;
  uint32_t _table_size;
  uint32_t _bundle_size;
  uint32_t _num_slot;
  bool _is_compress;
  bool _enable_rotate = false;
  // uint64_t
  std::vector<std::vector<uint32_t>> _bucket;
  std::map<std::string, uint32_t> _hash_index;
  std::vector<std::pair<uint32_t, uint32_t>> _cw_index;

  void get_all_index_hash_result(const uint64_t num_payloads,
                                 const uint64_t num_query,
                                 const double cuckoo_factor = 1.5);

 public:
  PirParms(const uint64_t num_payloads, const uint64_t payload_size);
  PirParms(const uint64_t num_payloads, const uint64_t payload_size,
           const uint64_t num_query, const bool is_batch, bool is_compress,
           const bool enable_rotate = false);

  void set_seal_parms(uint64_t poly_degree = 4096,
                      std::vector<int> coeff_modulus = {48, 32, 24},
                      uint64_t prime_len = 18);
  inline seal::EncryptionParameters get_seal_parms() { return _seal_parms; };

  inline uint64_t get_num_payloads() { return _num_payloads; }
  inline uint64_t get_payload_size() { return _payload_size; }
  inline uint64_t get_col_size() { return _col_size; }
  inline uint64_t get_num_payload_slot() { return _num_payload_slot; };
  inline uint64_t get_hamming_weight() { return _hamming_weight; };
  inline uint64_t get_encoding_size() { return _encoding_size; };
  inline uint64_t get_rotate_step() { return _rotate_step; };
  inline uint64_t get_pre_rotate() { return _pre_rotate; };

  // using only in Batch PIR
  inline uint64_t get_num_query() { return _num_query; };
  inline uint32_t get_table_size() { return _table_size; };
  inline uint32_t get_num_slot() { return _num_slot; };
  inline uint32_t get_bundle_size() { return _bundle_size; };
  inline uint32_t get_batch_pir_num_compress_slot() {
    return _is_compress
               ? std::ceil(static_cast<double>(_num_payload_slot) / _num_slot)
               : _num_payload_slot;
  };
  inline bool get_is_compress() { return _is_compress; };
  inline std::shared_ptr<kuku::KukuTable> get_cuckoo_table() { return _table; };
  inline std::pair<uint32_t, uint32_t> get_cw(std::string keyword) {
    return _cw_index[_hash_index[keyword]];
  }
  inline std::vector<std::vector<uint32_t>> &get_bucket() { return _bucket; };
  void print_seal_parms();
  void print_pir_parms();
  // void pre_cw_index();
};

#endif