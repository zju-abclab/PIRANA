#ifndef __CLIENT_H
#define __CLIENT_H
#include "pir_parms.h"

class Client {
 private:
  std::unique_ptr<seal::SEALContext> _context;
  std::unique_ptr<seal::KeyGenerator> _keygen;
  std::unique_ptr<seal::Encryptor> _encryptor;
  std::unique_ptr<seal::Decryptor> _decryptor;
  std::unique_ptr<seal::BatchEncoder> _batch_encoder;
  seal::PublicKey _public_key;
  seal::SecretKey _secret_key;
  seal::GaloisKeys _galois_keys;
  seal::RelinKeys _relin_keys;
  PirParms &_pir_parms;
  uint64_t _N;

  /* data */
 public:
  Client(PirParms &pir_parms);
  std::stringstream gen_query(uint32_t index);
  std::stringstream gen_batch_query(const std::vector<uint32_t> &batch_query);
  std::stringstream save_keys() {
    std::stringstream keys;
    _galois_keys.save(keys);
    _relin_keys.save(keys);
    return keys;
  }

  std::vector<std::vector<uint64_t>> extract_answer(
      std::stringstream &responsestream);
  std::vector<std::vector<uint64_t>> extract_batch_answer(
      std::stringstream &responsestream);

  // only use in debug
  std::stringstream send_secret_keys() {
    std::stringstream sk_stream;
    _secret_key.save(sk_stream);
    return sk_stream;
  }

  ~Client();
};

#endif
