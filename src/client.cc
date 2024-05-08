#include "client.h"

#include "assert.h"

Client::Client(/* args */ PirParms &pir_parms) : _pir_parms(pir_parms) {
  _context = std::make_unique<seal::SEALContext>(pir_parms.get_seal_parms());
  _batch_encoder = std::make_unique<seal::BatchEncoder>(*_context);
  _keygen = std::make_unique<seal::KeyGenerator>(*_context);

  _secret_key = _keygen->secret_key();
  _keygen->create_public_key(_public_key);
  _keygen->create_relin_keys(_relin_keys);
  _keygen->create_galois_keys(_galois_keys);

  _encryptor = std::make_unique<seal::Encryptor>(*_context, _public_key);
  _decryptor = std::make_unique<seal::Decryptor>(*_context, _secret_key);
  _encryptor->set_secret_key(_secret_key);

  _N = pir_parms.get_seal_parms().poly_modulus_degree();
}

std::stringstream Client::gen_query(uint32_t index) {
  std::stringstream query_stream;
  uint64_t query_byte_size = 0;
  auto n = _pir_parms.get_num_payloads();
  if( n < _N)
  {
    uint32_t repeat_times = _N / n;
    std::vector<uint64_t> query(_N,0);
    for(uint32_t i = 0 ; i <repeat_times; i++)
    {
      query.at(i * n + index) = 1;
    }
    seal::Plaintext plain;
    _batch_encoder->encode(query,plain);
    query_byte_size += _encryptor->encrypt_symmetric(plain).save(query_stream);
  }
  else{
  uint32_t row = index % _N;
  uint32_t col_index = index / _N;
  std::vector<uint32_t> cw_index = get_perfect_constant_weight_codeword(
      col_index, _pir_parms.get_encoding_size(),
      _pir_parms.get_hamming_weight());

  std::vector<seal::Ciphertext> query(_pir_parms.get_encoding_size());
  std::vector<uint64_t> plain_vector(_N, 0);
  seal::Plaintext plain_zeros;
  _batch_encoder->encode(plain_vector, plain_zeros);
  plain_vector.at(row) = 1;
  seal::Plaintext plain_one_hot;
  _batch_encoder->encode(plain_vector, plain_one_hot);
  for (uint32_t i = 0, index = 0; i < _pir_parms.get_encoding_size(); i++) {
    seal::Ciphertext enc_col;
    if (index < _pir_parms.get_hamming_weight() && i == cw_index.at(index)) {
      query_byte_size +=
          _encryptor->encrypt_symmetric(plain_one_hot).save(query_stream);
      index++;
    } else {
      query_byte_size +=
          _encryptor->encrypt_symmetric(plain_zeros).save(query_stream);
    }
  }
  }
  // std::cout << "Query size: " << query_byte_size / 1024.0 << " KB" << std::endl;
  return query_stream;
}

std::stringstream Client::gen_batch_query(
    const std::vector<uint32_t> &batch_query) {
  bool is_compress = _pir_parms.get_is_compress();
  std::stringstream query_stream;
  uint64_t send_size = 0;
  uint64_t query_size = _pir_parms.get_num_query();
  assert(batch_query.size() == query_size);
  for (auto &q : batch_query) {
    _pir_parms.get_cuckoo_table()->insert(kuku::make_item(0, q));
  }

  auto encoding_size = _pir_parms.get_encoding_size();
  auto bundle_size = _pir_parms.get_bundle_size();
  auto query_ct_size = encoding_size * bundle_size;
  std::vector<std::vector<uint64_t>> cw_query(query_ct_size,
                                              std::vector<uint64_t>(_N, 0));
  if (is_compress == false) {
    for (auto &q : batch_query) {
      kuku::QueryResult res =
          _pir_parms.get_cuckoo_table()->query(kuku::make_item(0, q));
      auto loc = res.location();
      auto cw = _pir_parms.get_cw(
          std::to_string(uint64_t(q) * _pir_parms.get_table_size() + loc));
      cw_query[cw.first * bundle_size + loc / _N][loc % _N] = 1;
      cw_query[cw.second * bundle_size + loc / _N][loc % _N] = 1;
    }
    std::vector<seal::Ciphertext> query_cipher(query_ct_size);
    for (uint32_t i = 0; i < query_ct_size; i++) {
      seal::Plaintext pt;
      _batch_encoder->encode(cw_query[i], pt);
      send_size += _encryptor->encrypt_symmetric(pt).save(query_stream);
    }
  } else {
    assert(bundle_size == 1);
    auto num_slot = _pir_parms.get_num_slot();
    for (auto &q : batch_query) {
      kuku::QueryResult res =
          _pir_parms.get_cuckoo_table()->query(kuku::make_item(0, q));
      auto loc = res.location();
      auto cw = _pir_parms.get_cw(
          std::to_string(q * _pir_parms.get_table_size() + loc));
      for (uint32_t slot = 0; slot < num_slot; slot++) {
        auto slot_index = loc * num_slot + slot;
        cw_query.at(cw.first).at(slot_index) = 1;
        cw_query.at(cw.second).at(slot_index) = 1;
      }
    }
    std::vector<seal::Ciphertext> query_cipher(query_ct_size);
    for (uint32_t i = 0; i < query_ct_size; i++) {
      seal::Plaintext pt;
      _batch_encoder->encode(cw_query[i], pt);
      send_size += _encryptor->encrypt_symmetric(pt).save(query_stream);
    }
  }
  // std::cout << "Send ct size: " << query_ct_size << std::endl;
  // std::cout << "Send query size: " << send_size / 1024.0 << " KBytes "
            // << std::endl;
  return query_stream;
}

std::vector<std::vector<uint64_t>> Client::extract_answer(
    std::stringstream &responsestream) {
  std::vector<seal::Ciphertext> response;
  uint64_t num_output_ciphers =
      std::ceil(static_cast<double>(_pir_parms.get_num_payload_slot()) / _N);
  std::vector<std::vector<uint64_t>> answer(num_output_ciphers,
                                            std::vector<uint64_t>(_N, 0));
  response.resize(num_output_ciphers);
  seal::Plaintext pt;
  for (uint32_t i = 0; i < num_output_ciphers; i++) {
    response[i].load(*_context, responsestream);
    assert(_decryptor->invariant_noise_budget(response[i]) != 0);
    _decryptor->decrypt(response[i], pt);
    _batch_encoder->decode(pt, answer[i]);
  }
  return answer;
}

std::vector<std::vector<uint64_t>> Client::extract_batch_answer(
    std::stringstream &responsestream) {
  std::vector<seal::Ciphertext> response;
  uint64_t num_output_ciphers = _pir_parms.get_batch_pir_num_compress_slot() *
                                _pir_parms.get_bundle_size();

  std::vector<std::vector<uint64_t>> answer(num_output_ciphers,
                                            std::vector<uint64_t>(_N, 0));
  response.resize(num_output_ciphers);
  seal::Plaintext pt;
  for (uint32_t i = 0; i < num_output_ciphers; i++) {
    response[i].load(*_context, responsestream);
    _decryptor->decrypt(response[i], pt);
    _batch_encoder->decode(pt, answer[i]);
    // std::cout << _decryptor->invariant_noise_budget(response[i]) <<
    // std::endl;
    assert(_decryptor->invariant_noise_budget(response[i]) != 0);
  }
  return answer;
}

Client::~Client() {}