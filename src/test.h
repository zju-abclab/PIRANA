#ifndef TEST_H
#define TEST_H
#include <assert.h>

#include <getopt.h>
#include <unordered_set>
#include <map>

#include "client.h"
#include "pir_parms.h"
#include "server.h"

void test_pir_correctness(Server &server, std::vector<std::vector<uint64_t>> &answer, uint32_t index, PirParms &pir_parms);

void test_batch_pir_correctness(Server &server, std::vector<std::vector<uint64_t>> &answer, std::vector<uint32_t> &query, PirParms &pir_parms);

#endif