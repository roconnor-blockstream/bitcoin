#include <simplicity/bitcoin.h>

#include <stdlib.h>
#include <stdalign.h>
#include <string.h>
#include "bitcoin/primitive.h"
#include "../deserialize.h"
#include "../eval.h"
#include "../sha256.h"
#include "../typeInference.h"

#define PADDING(alignType, allocated) ((alignof(alignType) - (allocated) % alignof(alignType)) % alignof(alignType))

/* Add a 256-bit hash to be consumed by an ongoing SHA-256 evaluation.
 *
 * Precondition: NULL != ctx;
 *               NULL != h;
 */
static void sha256_hash(sha256_context* ctx, const sha256_midstate* h) {
  unsigned char buf[32];
  sha256_fromMidstate(buf, h->s);
  sha256_uchars(ctx, buf, sizeof(buf));
}

/* Add an 'outpoint' to be consumed by an ongoing SHA-256 evaluation.
 * The 'txid' is consumed first in big endian order.
 * The 'ix' is consumed next in little endian byte-order.
 *
 * Precondition: NULL != ctx;
 *               NULL != op;
 */
static void sha256_outpoint(sha256_context* ctx, const outpoint* op) {
  sha256_hash(ctx, &op->txid);
  sha256_u32le(ctx,op->ix);
}

/* Compute the SHA-256 hash of a scriptPubKey and write it into 'result'.
 *
 * Precondition: NULL != result;
 *               unsigned char scriptPubKey[scriptLen];
 */
static void hashScriptPubKey(sha256_midstate* result, const rawScript* scriptPubKey) {
  sha256_context ctx = sha256_init(result);
  sha256_uchars(&ctx, scriptPubKey->code, scriptPubKey->len);
  sha256_finalize(&ctx);
}

/* Initialize a 'sigOutput' from a 'rawOuput', copying or hashing the data as needed.
 *
 * Precondition: NULL != result;
 *               NULL != output;
 */
static void copyOutput(sigOutput* result, const rawOutput* output) {
  *result = (sigOutput){ .value = output->value
                       };
  hashScriptPubKey(&result->scriptPubKey, &output->scriptPubKey);
}

/* Initialize a 'sigInput' from a 'rawInput', copying or hashing the data as needed.
 *
 * Precondition: NULL != result;
 *               NULL != input;
 */
static void copyInput(sigInput* result, const rawInput* input) {
  *result = (sigInput){ .prevOutpoint = { .ix = input->prevIx }
                      , .sequence = input->sequence
                      };
  sha256_toMidstate(result->prevOutpoint.txid.s, input->prevTxid);
  hashScriptPubKey(&result->txo.scriptPubKey, &input->txo.scriptPubKey);
  copyOutput(&result->txo, &input->txo);
}

/* Allocate and initialize a 'transaction' from a 'rawOuput', copying or hashing the data as needed.
 * Returns NULL if malloc fails (or if malloc cannot be called because we require an allocation larger than SIZE_MAX).
 *
 * Precondition: NULL != rawTx
 */
extern transaction* bitcoin_simplicity_mallocTransaction(const rawTransaction* rawTx) {
  if (!rawTx) return NULL;

  size_t allocationSize = sizeof(transaction);

  const size_t pad1 = PADDING(sigInput, allocationSize);
  if (SIZE_MAX - allocationSize < pad1) return NULL;
  allocationSize += pad1;

  /* Multiply by (size_t)1 to disable type-limits warning. */
  if (SIZE_MAX / sizeof(sigInput) < (size_t)1 * rawTx->numInputs) return NULL;
  if (SIZE_MAX - allocationSize < rawTx->numInputs * sizeof(sigInput)) return NULL;
  allocationSize += rawTx->numInputs * sizeof(sigInput);

  const size_t pad2 = PADDING(sigOutput, allocationSize);
  if (SIZE_MAX - allocationSize < pad2) return NULL;
  allocationSize += pad2;

  /* Multiply by (size_t)1 to disable type-limits warning. */
  if (SIZE_MAX / sizeof(sigOutput) < (size_t)1 * rawTx->numOutputs) return NULL;
  if (SIZE_MAX - allocationSize < rawTx->numOutputs * sizeof(sigOutput)) return NULL;
  allocationSize += rawTx->numOutputs * sizeof(sigOutput);

  char *allocation = malloc(allocationSize);
  if (!allocation) return NULL;

  transaction* const tx = (transaction*)allocation;
  allocation += sizeof(transaction) + pad1;

  sigInput* const input = (sigInput*)allocation;
  allocation += rawTx->numInputs * sizeof(sigInput) + pad2;

  sigOutput* const output = (sigOutput*)allocation;

  *tx = (transaction){ .input = input
                     , .output = output
                     , .numInputs = rawTx->numInputs
                     , .numOutputs = rawTx->numOutputs
                     , .version = rawTx->version
                     , .lockTime = rawTx->lockTime
                     };

  {
    sha256_context ctx = sha256_init(&tx->inputsHash);
    for (uint_fast32_t i = 0; i < tx->numInputs; ++i) {
      copyInput(&input[i], &rawTx->input[i]);
      tx->totalInputValue += input[i].txo.value;
      sha256_outpoint(&ctx, &input[i].prevOutpoint);
      sha256_u64le(&ctx, input[i].txo.value);
      sha256_u32le(&ctx, input[i].sequence);
    }
    sha256_finalize(&ctx);
  }

  {
    sha256_context ctx = sha256_init(&tx->outputsHash);
    for (uint_fast32_t i = 0; i < tx->numOutputs; ++i) {
      copyOutput(&output[i], &rawTx->output[i]);
      tx->totalOutputValue += output[i].value;
      sha256_u64le(&ctx, output[i].value);
      sha256_hash(&ctx, &output[i].scriptPubKey);
    }
    sha256_finalize(&ctx);
  }

  return tx;
}

/* Deserialize a Simplicity program from 'file' and execute it in the environment of the 'ix'th input of 'tx'.
 * If the file isn't a proper encoding of a Simplicity program, '*success' is set to false.
 * If EOF isn't encountered at the end of decoding, '*success' is set to false.
 * If 'cmr != NULL' and the commitment Merkle root of the decoded expression doesn't match 'cmr' then '*success' is set to false.
 * If 'wmr != NULL' and the witness Merkle root of the decoded expression doesn't match 'wmr' then '*success' is set to false.
 * Otherwise evaluation proceeds and '*success' is set to the result of evaluation.
 *
 * If at any time there is a transient error, such as malloc failing or an I/O error reading from 'file'
 * then 'false' is returned, and 'success' and 'file' may be modified.
 * Otherwise, 'true' is returned.
 *
 * Precondition: NULL != success;
 *               NULL != tx;
 *               NULL != cmr implies unsigned char cmr[32]
 *               NULL != wmr implies unsigned char wmr[32]
 *               NULL != file;
 */
extern bool bitcoin_simplicity_execSimplicity(bool* success, const transaction* tx, uint_fast32_t ix,
                                              const unsigned char* cmr, const unsigned char* wmr, FILE* file) {
  if (!success || !tx || !file) return false;

  bool result;
  combinator_counters census;
  dag_node* dag;
  void* witnessAlloc = NULL;
  bitstring witness;
  int32_t len;
  sha256_midstate cmr_hash, wmr_hash;

  if (cmr) sha256_toMidstate(cmr_hash.s, cmr);
  if (wmr) sha256_toMidstate(wmr_hash.s, wmr);

  {
    bitstream stream = initializeBitstream(file);
    len = decodeMallocDag(&dag, &census, &stream);
    if (len < 0) {
      *success = false;
      return PERMANENT_FAILURE(len);
    }

    int32_t err = decodeMallocWitnessData(&witnessAlloc, &witness, &stream);
    if (err < 0) {
      *success = false;
      result = PERMANENT_FAILURE(err);
    } else if (EOF != getc(file)) { /* Check that we hit the end of 'file' */
      *success = false;
      result = !ferror(file);
    } else {
      *success = result = !ferror(file);
    }
  }

  if (*success) {
    /* :TODO: Fold CMR calculation into dag to remove this VLA.  The CMR is needed to implement disconnect anyway.*/
    analyses analysis[len];
    computeCommitmentMerkleRoot(analysis, dag, (size_t)len);
    *success = !cmr || 0 == memcmp(cmr_hash.s, analysis[len-1].commitmentMerkleRoot.s, sizeof(uint32_t[8]));
    if (*success) {
      type* type_dag;
      size_t sourceIx, targetIx;
      result = mallocTypeInference(&type_dag, &sourceIx, &targetIx, dag, (size_t)len, &census);
      *success = result && type_dag && 0 == sourceIx && 0 == targetIx && fillWitnessData(dag, type_dag, (size_t)len, witness);
      if (*success) {
        computeWitnessMerkleRoot(analysis, dag, type_dag, (size_t)len);
        *success = !wmr || 0 == memcmp(wmr_hash.s, analysis[len-1].witnessMerkleRoot.s, sizeof(uint32_t[8]));
        if (*success) {
          result = evalTCOProgram(success, dag, type_dag, (size_t)len, &(txEnv){.tx = tx, .scriptCMR = cmr_hash.s, .ix = ix});
        }
      }
      free(type_dag);
    }
  }

  free(dag);
  free(witnessAlloc);
  return result;
}
