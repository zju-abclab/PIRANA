#include "server.h"

#include <assert.h>

#include <random>

Server::Server(PirParms &pir_parms, bool random_db) : _pir_parms(pir_parms) {
  _context = std::make_unique<seal::SEALContext>(pir_parms.get_seal_parms());
  _evaluator = std::make_unique<seal::Evaluator>(*_context);
  _batch_encoder = std::make_unique<seal::BatchEncoder>(*_context);
  _N = pir_parms.get_seal_parms().poly_modulus_degree();
  _p_modulus = pir_parms.get_seal_parms().plain_modulus().bit_count();
  _pre_rot_steps = pir_parms.get_rotate_step();
  _pre_rotate = pir_parms.get_pre_rotate();
  if (random_db == true) {
    gen_random_db();
    _set_db = true;
  } else {
    // Todo: read_db from file
  }
  encode_to_ntt_db();
};

Server::Server(PirParms &pir_parms, bool is_batch, bool random_db)
    : _pir_parms(pir_parms) {
  _context = std::make_unique<seal::SEALContext>(pir_parms.get_seal_parms());
  _evaluator = std::make_unique<seal::Evaluator>(*_context);
  _batch_encoder = std::make_unique<seal::BatchEncoder>(*_context);
  _N = pir_parms.get_seal_parms().poly_modulus_degree();
  _p_modulus = pir_parms.get_seal_parms().plain_modulus().bit_count();
  _pre_rot_steps = pir_parms.get_rotate_step();
  _pre_rotate = pir_parms.get_pre_rotate();
  if (random_db == true) {
    gen_random_db();
    _set_db = true;
  } else {
    // Todo: read_db from file
  }
  if (_pir_parms.get_is_compress()) {
    batch_encode_to_ntt_db_with_compress();
  } else {
    batch_encode_to_ntt_db_without_compress();
  }
}

Server::~Server() {}

void Server::gen_random_db() {
  //_raw_db (n, |pl|)
  auto num_payloads = _pir_parms.get_num_payloads();
  auto plain_modulus = _pir_parms.get_seal_parms().plain_modulus().value();
  auto plain_modulus_bit =
      _pir_parms.get_seal_parms().plain_modulus().bit_count();
  auto num_payload_slot = _pir_parms.get_num_payload_slot();
  uint64_t plain_mask = (1 << (plain_modulus_bit - 1)) - 1;

  // database read for encryption
  // each uint32_t save a plaintext < plain_modulus;
  std::cout << "Generate random database for test!" << std::endl;
  std::cout << "Raw database: " << num_payloads << " , (" << num_payload_slot
            << " * " << plain_modulus_bit - 1 << ") -> "
            << num_payload_slot * (plain_modulus_bit - 1) / 8 << " Bytes"
            << std::endl;
  _raw_db.resize(num_payloads);
  uint64_t pi = 0;
  for (auto &payload : _raw_db) {
    payload.resize(num_payload_slot);
    uint64_t test_i = 0;
    for (auto &data : payload) {
      // unsafe random generate, just for generating a test database
      data = rand() & plain_mask;
      // data = test_i & plain_mask;
      data = data == 0 ? 1 : data;
      // assert for test
      assert(data < plain_modulus && data != 0);

      test_i++;
    }
    pi++;
  }
}
// used for PIR single query
void Server::encode_to_ntt_db() {
  assert(_set_db && "Database has not been loaded correctly!");
  std::cout << "Encode database!" << std::endl;
  auto plaintext_size =
      _pir_parms.get_col_size() * _pir_parms.get_num_payload_slot();
  // (col_size, num_slot)
  _encoded_db.resize(plaintext_size);
  auto N = _pir_parms.get_seal_parms().poly_modulus_degree();
  std::vector<uint64_t> plain_vector(N, 0);

  int rotate_step = 0;

  auto half_N = N / 2;
  bool rotate_column = 0;
  auto rotate_time = 0;
  for (uint64_t pl_slot_index = 0;
       pl_slot_index < _pir_parms.get_num_payload_slot(); pl_slot_index++) {
    for (uint64_t col_index = 0; col_index < _pir_parms.get_col_size();
         col_index++) {
      seal::Plaintext encoded_plain;
      for (uint32_t i = 0, rotate_index = rotate_step; i < half_N;
           i++, rotate_index++) {
        auto raw_db_index =
            rotate_column ? col_index * N + i + half_N : col_index * N + i;
        plain_vector.at(rotate_index % half_N) =
            _raw_db.at(raw_db_index).at(pl_slot_index);
      }
      for (uint32_t i = 0, rotate_index = rotate_step; i < half_N;
           i++, rotate_index++) {
        auto raw_db_index =
            rotate_column ? col_index * N + i : col_index * N + i + half_N;
        plain_vector.at(rotate_index % half_N + half_N) =
            _raw_db.at(raw_db_index).at(pl_slot_index);
      }

      _batch_encoder->encode(plain_vector, encoded_plain);
      _evaluator->transform_to_ntt_inplace(encoded_plain,
                                           _context->first_parms_id());
      _encoded_db.at(pl_slot_index * _pir_parms.get_col_size() + col_index) =
          encoded_plain;
    }

    rotate_step += _pir_parms.get_rotate_step();
    rotate_step = rotate_step % half_N;
    rotate_time++;
    if (rotate_time % (_pir_parms.get_pre_rotate() / 2) == 0) {
      rotate_column = !rotate_column;
    }
  }
};

// used for batch encode
void Server::batch_encode_to_ntt_db_without_compress() {
  assert(_set_db && "Database has not been loaded correctly!");
  std::cout << "Encode database now!" << std::endl;
  auto db_pt_size = _pir_parms.get_col_size() * _pir_parms.get_bundle_size() *
                    _pir_parms.get_num_payload_slot();
  // (col_size, num_slot)
  auto table = _pir_parms.get_cuckoo_table();
  auto bucket = _pir_parms.get_bucket();

  _encoded_db.resize(db_pt_size);

  std::vector<uint64_t> plain_vector(_N, 0);
  for (uint64_t pl_slot_index = 0;
       pl_slot_index < _pir_parms.get_num_payload_slot(); pl_slot_index++) {
    for (uint64_t col_index = 0; col_index < _pir_parms.get_col_size();
         col_index++) {
      for (uint32_t bundle_index = 0;
           bundle_index < _pir_parms.get_bundle_size(); bundle_index++) {
        seal::Plaintext encoded_plain;
        for (uint64_t i = 0; i < _N; i++) {
          if (col_index < bucket[bundle_index * _N + i].size()) {
            auto index = bucket[bundle_index * _N + i][col_index];
            plain_vector.at(i) = _raw_db.at(index).at(pl_slot_index);
          } else {
            // Dummy slot can't be 0
            // If bundle size > 2, then cause ALL zeros plaintext;
            plain_vector.at(i) = 1;
          }
        }
        _batch_encoder->encode(plain_vector, encoded_plain);
        _evaluator->transform_to_ntt_inplace(encoded_plain,
                                             _context->first_parms_id());
        _encoded_db.at(pl_slot_index * _pir_parms.get_col_size() *
                           _pir_parms.get_bundle_size() +
                       col_index * _pir_parms.get_bundle_size() +
                       bundle_index) = encoded_plain;
      }
    }
  }
}

// used for batch encode
void Server::batch_encode_to_ntt_db_with_compress() {
  assert(_pir_parms.get_is_compress() == true &&
         "Wrong call! only used when compress is true!");
  assert(_pir_parms.get_bundle_size() == 1 &&
         "Compress is useful only when the bundle size is 1");
  assert(_set_db && "Database has not been loaded correctly!");
  std::cout << "Encode database now!" << std::endl;
  auto compress_num_slot = _pir_parms.get_batch_pir_num_compress_slot();
  auto db_pt_size = _pir_parms.get_col_size() * compress_num_slot;
  auto table_size = _pir_parms.get_table_size();
  uint32_t num_slot = _pir_parms.get_num_slot();
  // (col_size, num_slot)
  auto table = _pir_parms.get_cuckoo_table();
  auto bucket = _pir_parms.get_bucket();

  _encoded_db.resize(db_pt_size);

  std::vector<uint64_t> plain_vector(_N, 0);
  for (uint64_t pl_slot_index = 0; pl_slot_index < compress_num_slot;
       pl_slot_index++) {
    for (uint64_t col_index = 0; col_index < _pir_parms.get_col_size();
         col_index++) {
      seal::Plaintext encoded_plain;
      for (uint32_t i = 0; i < table_size; i++) {
        for (uint32_t slot = 0; slot < num_slot; slot++) {
          if (col_index < bucket.at(i).size() &&
              (pl_slot_index * num_slot + slot) <
                  _pir_parms.get_num_payload_slot()) {
            auto index = bucket.at(i).at(col_index);
            plain_vector.at(i * num_slot + slot) =
                _raw_db.at(index).at(pl_slot_index * num_slot + slot);
          } else {
            // Dummy slot can't be 0
            // If bundle size >= 2, then there will be ALL zeros plaintext;
            plain_vector.at(i * num_slot + slot) = 1;
          }
        }
      }
      _batch_encoder->encode(plain_vector, encoded_plain);
      _evaluator->transform_to_ntt_inplace(encoded_plain,
                                           _context->first_parms_id());
      _encoded_db.at(pl_slot_index * _pir_parms.get_col_size() + col_index) =
          encoded_plain;
    }
  }
}

std::vector<seal::Ciphertext> Server::load_query(
    std::stringstream &query_stream, uint32_t query_ct_size) {
  std::vector<seal::Ciphertext> query(query_ct_size);
  for (auto &x : query) {
    x.load(*_context, query_stream);
  }
  return query;
};

void Server::selection_vector_debug(
    std::vector<seal::Ciphertext> &selection_vectors) {
  uint64_t N = _pir_parms.get_seal_parms().poly_modulus_degree();
  uint64_t s = selection_vectors.size();
  for (uint64_t i = 0; i < s; i++) {
    seal::Plaintext encoded_result;
    if (selection_vectors.at(i).is_ntt_form())
      _evaluator->transform_from_ntt_inplace(selection_vectors.at(i));
    _decryptor->decrypt(selection_vectors.at(i), encoded_result);
    std::vector<uint64_t> result(N, 0);
    _batch_encoder->decode(encoded_result, result);
    for (uint64_t slot = 0; slot < N; slot++) {
      if (result.at(slot) != 0) {
        std::cout << "*Debug* No. selection vectors: " << i << std::endl;
        std::cout << "*Debug* result index: " << slot << " response "
                  << result.at(slot) << std::endl;
      }
    }
  }
}

std::vector<seal::Ciphertext> Server::gen_selection_vector(
    std::vector<seal::Ciphertext> &query) {
  std::vector<seal::Ciphertext> selection_vector;
  uint64_t col_size = _pir_parms.get_col_size();
  selection_vector.resize(col_size);
  uint64_t encoding_size = _pir_parms.get_encoding_size();
  uint64_t col_index = 0;
  // Todo: now only support hamming weight k = 2
  // Try to support more k
  for (uint64_t i_1 = 1; i_1 < encoding_size && col_index < col_size; i_1++) {
    for (uint64_t i_2 = 0; i_2 < i_1 && col_index < col_size; i_2++) {
      multiply(*_context, query.at(i_1), query.at(i_2),
               selection_vector.at(col_index));
      _evaluator->relinearize_inplace(selection_vector.at(col_index),
                                      _relin_keys);
      col_index++;
    }
  }
  // Todo: test selection vector debug
  // selection_vector_debug(selection_vector);
  return selection_vector;
}

std::vector<seal::Ciphertext> Server::gen_selection_vector_batch(
    std::vector<seal::Ciphertext> &query) {
  std::vector<seal::Ciphertext> selection_vector;
  auto col_size = _pir_parms.get_col_size();
  auto bundle_size = _pir_parms.get_bundle_size();
  selection_vector.resize(col_size * bundle_size);
  auto encoding_size = _pir_parms.get_encoding_size();
  uint64_t col_index = 0;
  // Todo: now only support hamming weight k = 2
  // Try to support more k
  for (uint64_t i_1 = 1; i_1 < encoding_size && col_index < col_size; i_1++) {
    for (uint64_t i_2 = 0; i_2 < i_1 && col_index < col_size; i_2++) {
      for (uint32_t bundle_index = 0; bundle_index < bundle_size;
           bundle_index++) {
        multiply(*_context, query.at(i_1 * bundle_size + bundle_index),
                 query.at(i_2 * bundle_size + bundle_index),
                 selection_vector.at(col_index * bundle_size + bundle_index));
        _evaluator->relinearize_inplace(
            selection_vector.at(col_index * bundle_size + bundle_index),
            _relin_keys);
        _evaluator->transform_to_ntt_inplace(
            selection_vector.at(col_index * bundle_size + bundle_index));
      }
      col_index++;
    }
  }
  // Todo: test selection vector debug
  // selection_vector_debug(selection_vector);
  return selection_vector;
}

// rotate the selection vector and transform them to ntt form
std::vector<seal::Ciphertext> Server::rotate_selection_vector(
    const std::vector<seal::Ciphertext> &selection_vectors) {
  // Todo: make sure have_done computed correctly
  // Add some explanation comments
  uint64_t have_done =
      std::max(1, (int)std::floor((double)_N / _pir_parms.get_num_payloads()));

  uint64_t rot_factor = _pre_rotate / have_done;

  std::cout << "Repead times in one ciphertext: " << have_done << std::endl;
  std::cout << "One to n: " << _pre_rotate << std::endl;
  std::vector<seal::Ciphertext> rotated_selection_vectors(
      selection_vectors.size() * rot_factor);

  if (_pre_rotate <= 1) {
    // Don't need to rotate the selection vector
    for (size_t i = 0; i < selection_vectors.size(); i++) {
      _evaluator->transform_to_ntt(selection_vectors[i],
                                   rotated_selection_vectors[i]);
    }
    return rotated_selection_vectors;
  }
  if (have_done == 1) {
    for (uint64_t sv_i = 0; sv_i < selection_vectors.size(); sv_i++) {
      rotated_selection_vectors[sv_i * _pre_rotate] = selection_vectors[sv_i];
      _evaluator->rotate_columns(
          selection_vectors[sv_i], _galois_keys,
          rotated_selection_vectors[sv_i * _pre_rotate + _pre_rotate / 2]);

      // Continuous rotating same steps can use the same Galois key.
      // [0,0,1,0,0,0,0,0]
      // [0,0,0,0,0,0,1,0]
      for (uint64_t j = 0; j < _pre_rotate / 2 - 1; j++) {
        _evaluator->rotate_rows(
            rotated_selection_vectors[sv_i * _pre_rotate + j], -_pre_rot_steps,
            _galois_keys,
            rotated_selection_vectors[sv_i * _pre_rotate + j + 1]);
      }
      for (uint64_t j = 0; j < _pre_rotate / 2 - 1; j++) {
        _evaluator->rotate_rows(
            rotated_selection_vectors[sv_i * _pre_rotate + _pre_rotate / 2 + j],
            -_pre_rot_steps, _galois_keys,
            rotated_selection_vectors[sv_i * _pre_rotate + _pre_rotate / 2 + j +
                                      1]);
      }
    }
  } else {
    // The 'have_done > 1' means poly_degree > n, and floor(poly_degree/n) > 2;
    // The first row and the second row in the BFV ciphertext is same.
    // Don't need to swap rows.
    uint64_t todo = _pre_rotate / have_done;
    for (uint64_t sv_i = 0; sv_i < selection_vectors.size(); sv_i++) {
      rotated_selection_vectors[sv_i * todo] = selection_vectors[sv_i];
      for (uint64_t j = 0; j < todo - 1; j++) {
        _evaluator->rotate_rows(selection_vectors[sv_i],
                                -_pre_rot_steps * (j + 1), _galois_keys,
                                rotated_selection_vectors[sv_i * todo + j + 1]);
      }
    }
  }
  for (auto &c : rotated_selection_vectors)
    _evaluator->transform_to_ntt_inplace(c);
  return rotated_selection_vectors;
}

std::vector<seal::Ciphertext> Server::mul_database_with_compress(
    const std::vector<seal::Ciphertext> &rotated_selection_vectors) {
  // preprocess the n to be a power of 2
  uint64_t sel_vector_size = _pir_parms.get_col_size();
  uint64_t num_output_ciphers =
      std::ceil((double)_pir_parms.get_num_payload_slot() / _N);

  uint64_t merge_in_one_ct =
      std::max(1, (int)(_N / _pir_parms.get_num_payloads()));

  uint64_t rot_expand = _pre_rotate / merge_in_one_ct;
  assert(rot_expand * _pir_parms.get_col_size() ==
         rotated_selection_vectors.size());
  uint64_t total_mul =
      std::ceil((double)_pir_parms.get_num_payload_slot() / merge_in_one_ct);
  uint64_t rot = _N / _pre_rotate;

  uint64_t total_rot =
      std::ceil((double)_pir_parms.get_num_payload_slot() / _pre_rotate);

  std::vector<seal::Ciphertext> response(num_output_ciphers);

  // rotate_mul_res_time
  uint64_t mul_count = 0;
  for (uint64_t out_i = 0; out_i < num_output_ciphers; out_i++) {
    for (uint64_t slot_i = 0, slot_len = std::min(rot, total_rot - out_i * rot);
         slot_i < slot_len; slot_i++) {
      seal::Ciphertext mul_result;
      seal::Ciphertext sum_result;

      for (uint64_t mul_i = 0; mul_i < rot_expand && mul_count < total_mul;
           mul_i++, mul_count++) {
        for (uint64_t col_i = 0; col_i < _pir_parms.get_col_size(); col_i++) {
          _evaluator->multiply_plain(
              rotated_selection_vectors.at(col_i * rot_expand + mul_i),
              _encoded_db.at(mul_count * _pir_parms.get_col_size() + col_i),
              mul_result);
          if (col_i == 0 && mul_i == 0) {
            sum_result = mul_result;
          } else {
            _evaluator->add_inplace(sum_result, mul_result);
          }
        }
      }
      _evaluator->transform_from_ntt_inplace(sum_result);
      if (slot_i == 0) {
        response.at(out_i) = sum_result;
      } else {
        _evaluator->add_inplace(response.at(out_i), sum_result);
      }
      _evaluator->rotate_rows_inplace(response.at(out_i), 1, _galois_keys);
    }
    _evaluator->mod_switch_to_inplace(response.at(out_i),
                                      _context->last_parms_id());
    try_clear_irrelevant_bits(_pir_parms.get_seal_parms(), response.at(out_i));
  }
  return response;
};

std::stringstream Server::inner_product(
    const std::vector<seal::Ciphertext> &selection_vector) {
  std::stringstream result;
  uint64_t result_size = 0;
  auto col_size = _pir_parms.get_col_size();
  auto bundle_size = _pir_parms.get_bundle_size();
  auto num_ct = _pir_parms.get_batch_pir_num_compress_slot();

  std::vector<seal::Ciphertext> multi_add_res(num_ct * bundle_size);
  std::vector<seal::Ciphertext> result_cipher(num_ct * bundle_size);

  std::vector<seal::Ciphertext> tmp_multi_res(col_size);
  for (uint32_t ct = 0; ct < num_ct; ct++) {
    for (uint32_t bundle = 0; bundle < bundle_size; bundle++) {
      for (uint32_t col = 0; col < col_size; col++) {
        // encode_db (num_plot, col_size, bundle_size)
        uint32_t plain_index =
            ct * bundle_size * col_size + bundle + col * bundle_size;
        uint32_t sv_index = bundle + bundle_size * col;
        _evaluator->multiply_plain(selection_vector.at(sv_index),
                                   _encoded_db.at(plain_index),
                                   tmp_multi_res.at(col));
      }
      _evaluator->add_many(tmp_multi_res,
                           multi_add_res.at(ct * bundle_size + bundle));
      _evaluator->transform_from_ntt_inplace(
          multi_add_res.at(ct * bundle_size + bundle));
      _evaluator->mod_switch_to_inplace(
          multi_add_res.at(ct * bundle_size + bundle),
          _context->last_parms_id());
      try_clear_irrelevant_bits(_context->last_context_data()->parms(),
                                multi_add_res.at(ct * bundle_size + bundle));
    }
  }
  for (auto &i : multi_add_res) {
    result_size += i.save(result);
  }
  std::cout << num_ct << std::endl;
  std::cout << "Response size: " << result_size / 1024.0 << " KB" << std::endl;
  return result;
}

std::stringstream Server::gen_response(std::stringstream &query_stream) {
  std::stringstream response;
  std::vector<seal::Ciphertext> query =
      load_query(query_stream, _pir_parms.get_encoding_size());

  std::vector<seal::Ciphertext> selection_vector = gen_selection_vector(query);
  std::vector<seal::Ciphertext> rotated_selection_vectors =
      rotate_selection_vector(selection_vector);

  std::vector<seal::Ciphertext> response_cipher =
      mul_database_with_compress(rotated_selection_vectors);

  for (auto &r : response_cipher) {
    r.save(response);
  }
  return response;
};

std::stringstream Server::gen_batch_response(std::stringstream &query_stream) {
  std::vector<seal::Ciphertext> query =
      load_query(query_stream,
                 _pir_parms.get_encoding_size() * _pir_parms.get_bundle_size());

  std::vector<seal::Ciphertext> selection_vector =
      gen_selection_vector_batch(query);
  std::stringstream response;
  response = inner_product(selection_vector);
  return response;
};