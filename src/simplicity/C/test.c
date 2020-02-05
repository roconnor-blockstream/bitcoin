#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <simplicity/bitcoin.h>
#include "dag.h"
#include "deserialize.h"
#include "eval.h"
#include "typeInference.h"
#include "hashBlock.h"
#include "schnorr0.h"
#include "schnorr6.h"
#include "primitive/bitcoin/checkSigHashAllTx1.h"

_Static_assert(CHAR_BIT == 8, "Buffers passed to fmemopen presume 8 bit chars");

static FILE* fmemopen_rb(const void *buf, size_t size) {
  FILE* result = fmemopen((void *)(uintptr_t)buf, size, "rb"); /* Casting away const. */
  if (!result) {
    fprintf(stderr, "fmemopen failed.");
    exit(EXIT_FAILURE);
  }
  return result;
}

static int successes = 0;
static int failures = 0;

static void test_decodeUptoMaxInt(void) {
  printf("Test decodeUptoMaxInt\n");
  const unsigned char buf[] =
  { 0x4b, 0x86, 0x39, 0xe8, 0xdf, 0xc0, 0x38, 0x0f, 0x7f, 0xff, 0xff, 0x00
  , 0x00, 0x00, 0xf0, 0xe0, 0x00, 0x00, 0x00, 0x3c, 0x3b, 0xff, 0xff, 0xff
  , 0xff, 0x0f, 0x00, 0x00, 0x00, 0x00
  };
  const int32_t expected[] =
  { 1, 2, 3, 4, 5, 7, 8, 15, 16, 17
  , 0xffff, 0x10000, 0x40000000, 0x7fffffff, ERR_DATA_OUT_OF_RANGE
  };

  FILE* file = fmemopen_rb(buf, sizeof(buf));
  bitstream stream = initializeBitstream(file);
  for (size_t i = 0; i < sizeof(expected)/sizeof(expected[0]); ++i) {
    int32_t result = decodeUptoMaxInt(&stream);
    if (expected[i] == result) {
      successes++;
    } else {
      failures++;
      printf("Unexpected result during parsing.  Expected %d and received %d\n", expected[i], result);
    }
  }
  fclose(file);
}

static void test_hashBlock(void) {
  printf("Test hashBlock\n");
  dag_node* dag;
  combinator_counters census;
  int32_t len, err = 0;
  void* witnessAlloc = NULL;
  bitstring witness;
  {
    FILE* file = fmemopen_rb(hashBlock, sizeof_hashBlock);
    bitstream stream = initializeBitstream(file);
    len = decodeMallocDag(&dag, &census, &stream);
    if (!dag) {
      failures++;
      printf("Error parsing dag: %d\n", len);
    } else {
      err = decodeMallocWitnessData(&witnessAlloc, &witness, &stream);
      if (err < 0) {
        failures++;
        printf("Error parsing witness: %d\n", err);
      }
    }
    fclose(file);
  }
  if (dag && 0 <= err) {
    successes++;

    analyses analysis[len];
    computeCommitmentMerkleRoot(analysis, dag, (size_t)len);
    if (0 == memcmp(hashBlock_cmr, analysis[len-1].commitmentMerkleRoot.s, sizeof(uint32_t[8]))) {
      successes++;
    } else {
      failures++;
      printf("Unexpected CMR of hashblock\n");
    }

    type* type_dag;
    size_t sourceIx, targetIx;
    if (!mallocTypeInference(&type_dag, &sourceIx, &targetIx, dag, (size_t)len, &census) || !type_dag ||
        type_dag[sourceIx].bitSize != 768 || type_dag[targetIx].bitSize != 256) {
      failures++;
      printf("Unexpected failure of type inference for hashblock\n");
    } else if (!fillWitnessData(dag, type_dag, (size_t)len, witness)) {
      failures++;
      printf("Unexpected failure of fillWitnessData for hashblock\n");
    } else {
      computeWitnessMerkleRoot(analysis, dag, type_dag, (size_t)len);
      if (0 == memcmp(hashBlock_wmr, analysis[len-1].witnessMerkleRoot.s, sizeof(uint32_t[8]))) {
        successes++;
      } else {
        failures++;
        printf("Unexpected WMR of hashblock\n");
      }

      _Static_assert(UWORD_BIT - 1 <= SIZE_MAX - (256+512), "UWORD_BIT is far too large.");
      UWORD output[roundUWord(256)];
      UWORD input[roundUWord(256+512)];
      { frameItem frame = initWriteFrame(256+512, &input[roundUWord(256+512)]);
        /* Set SHA-256's initial value. */
        write32s(&frame, (uint32_t[8])
            { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }
          , 8);
        /* Set the block to be compressed to "abc" with padding. */
        write32s(&frame, (uint32_t[16]){ [0] = 0x61626380, [15] = 0x18 }, 16);
      }
      bool evalSuccess;
      if (evalTCOExpression(&evalSuccess, output, 256, input, 256+512, dag, type_dag, (size_t)len, NULL) && evalSuccess) {
        /* The expected result is the value 'SHA256("abc")'. */
        const uint32_t expectedHash[8] = { 0xba7816bful, 0x8f01cfeaul, 0x414140deul, 0x5dae2223ul
                                         , 0xb00361a3ul, 0x96177a9cul, 0xb410ff61ul, 0xf20015adul };
        frameItem frame = initReadFrame(256, &output[0]);
        uint32_t result[8];
        read32s(result, 8, &frame);
        if (0 == memcmp(expectedHash, result, sizeof(uint32_t[8]))) {
          successes++;
        } else {
          failures++;
          printf("Unexpected output of hashblock computation.\n");
        }
      } else {
        failures++;
        printf("Unexpected failure of hashblock evaluation\n");
      }
    }
    free(type_dag);
  }
  free(dag);
  free(witnessAlloc);
}

static void test_program(char* name, FILE* file, bool expectedResult, const uint32_t* expectedCMR, const uint32_t* expectedWMR) {
  printf("Test %s\n", name);
  dag_node* dag;
  combinator_counters census;
  int32_t len, err = 0;
  void* witnessAlloc = NULL;
  bitstring witness;
  {
    bitstream stream = initializeBitstream(file);
    len = decodeMallocDag(&dag, &census, &stream);
    if (!dag) {
      failures++;
      printf("Error parsing dag: %d\n", len);
    } else {
      err = decodeMallocWitnessData(&witnessAlloc, &witness, &stream);
      if (err < 0) {
        failures++;
        printf("Error parsing witness: %d\n", err);
      }
    }
  }
  if (dag && 0 <= err) {
    successes++;

    analyses analysis[len];
    computeCommitmentMerkleRoot(analysis, dag, (size_t)len);
    if (expectedCMR) {
      if (0 == memcmp(expectedCMR, analysis[len-1].commitmentMerkleRoot.s, sizeof(uint32_t[8]))) {
        successes++;
      } else {
        failures++;
        printf("Unexpected CMR.\n");
      }
    }
    type* type_dag;
    size_t sourceIx, targetIx;
    if (!mallocTypeInference(&type_dag, &sourceIx, &targetIx, dag, (size_t)len, &census) || !type_dag ||
        sourceIx != 0 || targetIx != 0) {
      failures++;
      printf("Unexpected failure of type inference.\n");
    } else if (!fillWitnessData(dag, type_dag, (size_t)len, witness)) {
      failures++;
      printf("Unexpected failure of fillWitnessData.\n");
    } else {
      computeWitnessMerkleRoot(analysis, dag, type_dag, (size_t)len);
      if (expectedWMR) {
        if (0 == memcmp(expectedWMR, analysis[len-1].witnessMerkleRoot.s, sizeof(uint32_t[8]))) {
          successes++;
        } else {
          failures++;
          printf("Unexpected WMR.\n");
        }
      }
      bool evalSuccess;
      if (evalTCOProgram(&evalSuccess, dag, type_dag, (size_t)len, NULL) && expectedResult == evalSuccess) {
        successes++;
      } else {
        failures++;
        printf(expectedResult ? "Unexpected failure of evaluation.\n" : "Unexpected success of evaluation.\n");
      }
    }
    free(type_dag);
  }
  free(dag);
  free(witnessAlloc);
}

static void test_occursCheck(void) {
  printf("Test occursCheck\n");
  /* The untyped Simplicity term (case (drop iden) iden) ought to cause an occurs check failure. */
  const unsigned char buf[] = { 0xc1, 0x07, 0x20, 0x30 };
  dag_node* dag;
  combinator_counters census;
  int32_t len;
  {
    FILE* file = fmemopen_rb(buf, sizeof(buf));
    bitstream stream = initializeBitstream(file);
    len = decodeMallocDag(&dag, &census, &stream);
    fclose(file);
  }
  if (!dag) {
    printf("Error parsing dag: %d\n", len);
  } else {
    type* type_dag;
    if (mallocTypeInference(&type_dag, &(size_t){0}, &(size_t){0}, dag, (size_t)len, &census) && !type_dag) {
      successes++;
    } else {
      printf("Unexpected occurs check success\n");
      failures++;
    }
    free(type_dag);
  }
  free(dag);
}

static void test_bitcoin(void) {
  unsigned char cmr[32], wmr[32];

  printf("Test bitcoin\n");
  {
    rawTransaction testTx1 = (rawTransaction)
      { .input = (rawInput[])
                 { { .prevTxid = (unsigned char[32]){"\x2c\xfd\x97\x68\x69\x94\xff\x7c\x39\x68\xfb\xef\x08\xbf\x4c\x11\x10\x12\xb5\xe4\x4d\xaf\xdb\x81\xd7\x01\x90\x33\xdd\xa8\xd9\x7e"}
                   , .prevIx = 0
                   , .sequence = 0xfffffffe
                   , .txo = { .value = 100000000
                            , .scriptPubKey = {0}
                 } }        }
      , .output = (rawOutput[])
                  { { .value = 99996700
                    , .scriptPubKey = { .code = (unsigned char [23]){"\xa9\x14\xd0\x8b\xc6\x78\x88\x5b\x67\xbd\xb8\xa4\x79\x78\xe2\x1e\xc7\x85\x61\xc6\xba\x5e\x87"}
                                      , .len = 23
                                      }
                  } }
      , .numInputs = 1
      , .numOutputs = 1
      , .version = 0x00000002
      , .lockTime = 0x00000000
      };
    transaction* tx1 = bitcoin_simplicity_mallocTransaction(&testTx1);
    sha256_fromMidstate(cmr, bitcoinCheckSigHashAllTx1_cmr);
    sha256_fromMidstate(wmr, bitcoinCheckSigHashAllTx1_wmr);
    if (tx1) {
      successes++;
      bool execResult;
      {
        FILE* file = fmemopen_rb(bitcoinCheckSigHashAllTx1, sizeof_bitcoinCheckSigHashAllTx1);
        if (bitcoin_simplicity_execSimplicity(&execResult, tx1, 0, cmr, wmr, file) && execResult) {
          successes++;
        } else {
          failures++;
          printf("execSimplicity of bitcoinCheckSigHashAllTx1 on tx1 failed\n");
        }
        fclose(file);
      }
      {
        /* test the same transaction with a erronous signature. */
        unsigned char brokenSig[sizeof_bitcoinCheckSigHashAllTx1];
        memcpy(brokenSig, bitcoinCheckSigHashAllTx1, sizeof_bitcoinCheckSigHashAllTx1);
        brokenSig[sizeof_bitcoinCheckSigHashAllTx1 - 1] ^= 0x80;
        FILE* file = fmemopen_rb(brokenSig, sizeof_bitcoinCheckSigHashAllTx1);
        if (bitcoin_simplicity_execSimplicity(&execResult, tx1, 0, NULL, NULL, file) && !execResult) {
          successes++;
        } else {
          failures++;
          printf("execSimplicity of brokenSig on tx1 unexpectedly succeeded\n");
        }
        fclose(file);
      }
    } else {
      printf("mallocTransaction(&rawTx1) failed\n");
      failures++;
    }
    free(tx1);
  }
  /* test a modified transaction with the same signature. */
  {
    rawTransaction testTx2 = (rawTransaction)
      { .input = (rawInput[])
                 { { .prevTxid = (unsigned char[32]){"\x2c\xfd\x97\x68\x69\x94\xff\x7c\x39\x68\xfb\xef\x08\xbf\x4c\x11\x10\x12\xb5\xe4\x4d\xaf\xdb\x81\xd7\x01\x90\x33\xdd\xa8\xd9\x7e"}
                   , .prevIx = 0
                   , .sequence = 0xffffffff /* Here is the modification. */
                   , .txo = { .value = 100000000
                            , .scriptPubKey = {0}
                 } }        }
      , .output = (rawOutput[])
                  { { .value = 99996700
                    , .scriptPubKey = { .code = (unsigned char [23]){"\xa9\x14\xd0\x8b\xc6\x78\x88\x5b\x67\xbd\xb8\xa4\x79\x78\xe2\x1e\xc7\x85\x61\xc6\xba\x5e\x87"}
                                      , .len = 23
                                      }
                  } }
      , .numInputs = 1
      , .numOutputs = 1
      , .version = 0x00000002
      , .lockTime = 0x00000000
      };
    transaction* tx2 = bitcoin_simplicity_mallocTransaction(&testTx2);
    if (tx2) {
      successes++;
      bool execResult;
      {
        FILE* file = fmemopen_rb(bitcoinCheckSigHashAllTx1, sizeof_bitcoinCheckSigHashAllTx1);
        if (bitcoin_simplicity_execSimplicity(&execResult, tx2, 0, NULL, NULL, file) && !execResult) {
          successes++;
        } else {
          failures++;
          printf("execSimplicity of bitcoinCheckSigHashAllTx1 on tx2 unexpectedly succeeded\n");
        }
        fclose(file);
      }
    } else {
      printf("mallocTransaction(&testTx2) failed\n");
      failures++;
    }
    free(tx2);
  }
}

int main(void) {
  test_decodeUptoMaxInt();
  test_hashBlock();
  test_occursCheck();
  {
    FILE* file = fmemopen_rb(schnorr0, sizeof_schnorr0);
    test_program("schnorr0", file, true, schnorr0_cmr, schnorr0_wmr);
    fclose(file);
  }
  {
    FILE* file = fmemopen_rb(schnorr6, sizeof_schnorr6);
    test_program("schnorr6", file, false, schnorr6_cmr, schnorr6_wmr);
    fclose(file);
  }
  test_bitcoin();

  printf("Successes: %d\n", successes);
  printf("Failures: %d\n", failures);
  return (0 == failures) ? EXIT_SUCCESS : EXIT_FAILURE;
}
