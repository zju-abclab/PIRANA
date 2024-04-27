#include "test.h"

#include <assert.h>

#include "utils.h"
using namespace seal;
using namespace std;

void test_pir_correctness(Server &server,
                          std::vector<std::vector<uint64_t>> &answer,
                          uint32_t index, PirParms &pir_parms) {
  auto real_item = server.get_plain_response(index);
  auto N = pir_parms.get_seal_parms().poly_modulus_degree();
  auto half_N = N / 2;
  auto start_rows = index % N;
  uint32_t count = 0;
  auto num_slot = pir_parms.get_num_payload_slot();
  uint64_t left_rotate_slot =
      std::ceil(static_cast<double>(num_slot) / pir_parms.get_pre_rotate());
  for (uint32_t i = 0; i < answer.size() && count < num_slot; i++) {
    auto row_index = index / half_N;
    auto offset =
        (index - std::min(left_rotate_slot, pir_parms.get_rotate_step())) %
        half_N;
    for (uint32_t j = 0; j < pir_parms.get_rotate_step() && count < num_slot;
         j++) {
      for (uint32_t k = 0;
           k < pir_parms.get_pre_rotate() / 2 && count < num_slot; k++) {
        uint32_t index =
            row_index * half_N +
            (k * pir_parms.get_rotate_step() + j + offset) % half_N;
        auto response_item = answer[i][index % N];
        auto plain_item = real_item[count];
        // std::cout << count << " " << response_item << std::endl;
        assert(plain_item == response_item);
        count++;
      }
      for (uint32_t k = 0;
           k < pir_parms.get_pre_rotate() / 2 && count < num_slot; k++) {
        uint32_t index =
            (row_index + 1) * half_N +
            (k * pir_parms.get_rotate_step() + j + offset) % half_N;
        auto response_item = answer[i][index % N];
        auto plain_item = real_item[count];

        // std::cout << count << " " << response_item << std::endl;
        assert(plain_item == response_item);
        count++;
      }
    }
    left_rotate_slot -= pir_parms.get_rotate_step();
  }
  // uint32_t c = 0;
  // for (uint32_t i = 0; i < N; i++) {
  //   if (answer[0][i] != 0) {
  //     std::cout << i << " " << answer[0][i] << std::endl;
  //     c++;
  //   }
  // }
  // std::cout << "All " << c << std::endl;
}

void test_batch_pir_correctness(Server &server,
                                std::vector<std::vector<uint64_t>> &answer,
                                std::vector<uint32_t> &query,
                                PirParms &pir_parms) {
  auto table = pir_parms.get_cuckoo_table();
  for (auto &q : query) {
    auto real_item = server.get_plain_response(q);
    // std::cout << " Real item size: " << real_item.size() << std::endl;
    kuku::QueryResult res = table->query(kuku::make_item(0, q));
    auto loc = res.location();
    if (pir_parms.get_is_compress() == false) {
      auto N = pir_parms.get_seal_parms().poly_modulus_degree();
      auto num_ct = pir_parms.get_num_payload_slot();
      auto bundle_size = pir_parms.get_bundle_size();
      for (uint32_t i = 0; i < num_ct; i++) {
        auto slot_index = loc % N;
        auto bundle_index = loc / N;
        // if (real_item.at(i) != answer.at(bundle_size * i +
        // bundle_index).at(slot_index))
        // {
        //   std::cout << "Error: " << std::endl;
        //   std::cout << q << std::endl;
        //   auto count = 0;
        //   std::cout << i << std::endl;
        //   std::cout << real_item.at(i) << " " << answer.at(bundle_size * i +
        //   bundle_index).at(slot_index) << std::endl;
        // }
        assert(real_item.at(i) ==
               answer.at(bundle_size * i + bundle_index).at(slot_index));
      }
    } else {
      auto num_slot = pir_parms.get_num_slot();
      for (uint32_t i = 0, slot = 0, ct_index = 0; i < real_item.size();
           i++, slot++) {
        if (slot == num_slot) {
          slot = 0;
          ct_index++;
        }
        assert(real_item.at(i) ==
               answer.at(ct_index).at(slot + loc * num_slot));
      }
    }
  }
}
void test_mulptiply(SEALContext &context, EncryptionParameters &parms,
                    Encryptor &encryptor, Decryptor &decryptor,
                    BatchEncoder &batch_encoder, uint64_t run_times) {
  size_t slot_count = batch_encoder.slot_count();
  size_t row_size = slot_count / 2;
  uint64_t p = parms.plain_modulus().value();
  vector<uint64_t> matrix_1(slot_count, 0);
  vector<uint64_t> matrix_2(slot_count, 0);
  vector<uint64_t> real_res(slot_count, 0);
  vector<uint64_t> comp_res(slot_count, 0);
  uint64_t multiply_time = 0;
  Timer timer;
  for (uint time = 0; time < run_times; time++) {
    for (int i = 0; i < slot_count; i++) {
      matrix_1[i] = rand() % p;
      matrix_2[i] = rand() % p;
      real_res[i] = (matrix_1[i] * matrix_2[i]) % p;
    }
    Plaintext p_1, p_2, p_res;
    batch_encoder.encode(matrix_1, p_1);
    batch_encoder.encode(matrix_2, p_2);
    Ciphertext c_1, c_2, c_res;
    encryptor.encrypt(p_1, c_1);
    encryptor.encrypt(p_2, c_2);
    timer.reset();
    multiply(context, c_1, c_2, c_res);
    multiply_time += timer.elapsed();
    decryptor.decrypt(c_res, p_res);
    batch_encoder.decode(p_res, comp_res);
    for (int i = 0; i < slot_count; i++) {
      assert(real_res[i] == comp_res[i]);
    }
  }
  cout << "Multiply " << run_times << " , Time: " << multiply_time << " ms"
       << endl;
}

// int main(int argc, char *argv[])
// {
//     EncryptionParameters parms(scheme_type::bfv);
//     size_t poly_modulus_degree = 8192;
//     parms.set_poly_modulus_degree(poly_modulus_degree);
//     parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
//     parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

//     SEALContext context(parms);
//     KeyGenerator keygen(context);
//     SecretKey secret_key = keygen.secret_key();
//     PublicKey public_key;
//     keygen.create_public_key(public_key);
//     RelinKeys relin_keys;
//     keygen.create_relin_keys(relin_keys);
//     Encryptor encryptor(context, public_key);
//     Evaluator evaluator(context);
//     Decryptor decryptor(context, secret_key);
//     BatchEncoder batch_encoder(context);

//     cout << "test multiply function" << endl;
//     test_mulptiply(context, parms, encryptor, decryptor, batch_encoder,
//     1000);
// }
