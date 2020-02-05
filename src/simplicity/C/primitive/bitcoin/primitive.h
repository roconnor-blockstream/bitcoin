/* This module defines the environment ('txEnv') for Simplicity evaluation for Bitcoin.
 * It includes the transaction data and input index of the input whose Simplicity program is being executed.
 * It also includes the commitment Merkle root of the program being executed.
 */
#ifndef PRIMITIVE_BITCOIN_H
#define PRIMITIVE_BITCOIN_H

#include "../../primitive.h"
#include "../../sha256.h"

/* A Bitcoin 'outpoint' consists of a transaction id and output index within that transaction.
 * The transaction id can be a either a transaction within the chain, or the transaction id from another chain in case of a peg-in.
 */
typedef struct outpoint {
  sha256_midstate txid;
  uint_fast32_t ix;
} outpoint;

/* A structure representing data from one output from a Bitcoin transaction.
 * 'scriptPubKey' is the SHA-256 hash of the outputs scriptPubKey.
 */
typedef struct sigOutput {
  uint_fast64_t value;
  sha256_midstate scriptPubKey;
} sigOutput;

/* A structure representing data from one input from a Bitcoin transaction along with the utxo data of the output being redeemed.
 */
typedef struct sigInput {
  outpoint prevOutpoint;
  sigOutput txo;
  uint_fast32_t sequence;
} sigInput;

/* A structure representing data from an Elements transaction (along with the utxo data of the outputs being redeemed).
 * 'totalInputValue' and 'totalOutputValue' are a cache of the sum of the input and output values respectively.
 * 'inputsHash' and 'outputsHash' are a cache of the hash of the input and output data respectively.
 */
typedef struct transaction {
  const sigInput* input;
  const sigOutput* output;
  sha256_midstate inputsHash;
  sha256_midstate outputsHash;
  uint_fast64_t totalInputValue;
  uint_fast64_t totalOutputValue;
  uint_fast32_t numInputs;
  uint_fast32_t numOutputs;
  uint_fast32_t version;
  uint_fast32_t lockTime;
} transaction;

/* The 'txEnv' structure used by the Elements application of Simplcity.
 *
 * It includes
 * + the transaction data, which may be shared when Simplicity expressions are used for multiple inputs in the same transaction),
 * + the input index under consideration,
 * + and the commitment Merkle root of the Simplicity expression being executed.
 */
typedef struct txEnv {
  const transaction* tx;
  const uint32_t* scriptCMR;
  uint_fast32_t ix;
} txEnv;

#endif
