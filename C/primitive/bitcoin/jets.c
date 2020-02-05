#include "jets.h"

#include "../../unreachable.h"

/* Write a 256-bit hash value to the 'dst' frame, advancing the cursor 256 cells.
 *
 * Precondition: '*dst' is a valid write frame for 256 more cells;
 *               NULL != h;
 */
static void writeHash(frameItem* dst, const sha256_midstate* h) {
  write32s(dst, h->s, 8);
}

/* Write an outpoint value to the 'dst' frame, advancing the cursor 288 cells.
 *
 * Precondition: '*dst' is a valid write frame for 288 more cells;
 *               NULL != op;
 */
static void prevOutpoint(frameItem* dst, const outpoint* op) {
  writeHash(dst, &op->txid);
  write32(dst, op->ix);
}

/* version : ONE |- TWO^32 */
bool version(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  write32(dst, env->tx->version);
  return true;
}

/* lockTime : ONE |- TWO^32 */
bool lockTime(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  write32(dst, env->tx->lockTime);
  return true;
}

/* inputsHash : ONE |- TWO^256 */
bool inputsHash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  writeHash(dst, &env->tx->inputsHash);
  return true;
}

/* outputsHash : ONE |- TWO^256 */
bool outputsHash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  writeHash(dst, &env->tx->outputsHash);
  return true;
}

/* numInputs : ONE |- TWO^32 */
bool numInputs(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  write32(dst, env->tx->numInputs);
  return true;
}

/* totalInputValue : ONE |- TWO^64 */
bool totalInputValue(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  write64(dst, env->tx->totalInputValue);
  return true;
}

/* currentPrevOutpoint : ONE |- TWO^256 * TWO^32 */
bool currentPrevOutpoint(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  if (env->tx->numInputs <= env->ix) return false;
  prevOutpoint(dst, &env->tx->input[env->ix].prevOutpoint);
  return true;
}

/* currentValue : ONE |- TWO^64 */
bool currentValue(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  if (env->tx->numInputs <= env->ix) return false;
  write64(dst, env->tx->input[env->ix].txo.value);
  return true;
}

/* currentSequence : ONE |- TWO^32 */
bool currentSequence(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  if (env->tx->numInputs <= env->ix) return false;
  write32(dst, env->tx->input[env->ix].sequence);
  return true;
}

/* currentIndex : ONE |- TWO^32 */
bool currentIndex(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  write32(dst, env->ix);
  return true;
}

/* inputIsPegin : TWO^32 |- S (TWO^256 * TWO^32) */
bool inputPrevOutpoint(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = read32(&src);
  if (writeBit(dst, i < env->tx->numInputs)) {
    prevOutpoint(dst, &env->tx->input[i].prevOutpoint);
  } else {
    skipBits(dst, 288);
  }
  return true;
}

/* inputValue : TWO^32 |- S TWO^64 */
bool inputValue(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = read32(&src);
  if (writeBit(dst, i < env->tx->numInputs)) {
    write64(dst, env->tx->input[i].txo.value);
  } else {
    skipBits(dst, 64);
  }
  return true;
}

/* inputSequence : TWO^32 |- S TWO^32 */
bool inputSequence(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = read32(&src);
  if (writeBit(dst, i < env->tx->numInputs)) {
    write32(dst, env->tx->input[i].sequence);
  } else {
    skipBits(dst, 32);
  }
  return true;
}

/* numOutputs : ONE |- TWO^32 */
bool numOutputs(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  write32(dst, env->tx->numOutputs);
  return true;
}

/* totalOutputValue : ONE |- TWO^64 */
bool totalOutputValue(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  write64(dst, env->tx->totalOutputValue);
  return true;
}

/* outputValue : TWO^32 |- S TWO^64 */
bool outputValue(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = read32(&src);
  if (writeBit(dst, i < env->tx->numOutputs)) {
    write64(dst, env->tx->output[i].value);
  } else {
    skipBits(dst, 64);
  }
  return true;
}

/* outputScriptHash : TWO^32 |- S TWO^256 */
bool outputScriptHash(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = read32(&src);
  if (writeBit(dst, i < env->tx->numOutputs)) {
    writeHash(dst, &env->tx->output[i].scriptPubKey);
  } else {
    skipBits(dst, 256);
  }
  return true;
}

/* scriptCMR : ONE |- TWO^256 */
bool scriptCMR(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  write32s(dst, env->scriptCMR, 8);
  return true;
}
