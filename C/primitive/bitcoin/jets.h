/* This module defines primitives and jets that are specific to the Elements application for Simplicity.
 */
#ifndef PRIMITIVE_BITCOIN_JETS_H
#define PRIMITIVE_BITCOIN_JETS_H

#include "../../frame.h"
#include "primitive.h"

/* Primitives for the Elements application of Simplicity. */
bool version(frameItem* dst, frameItem src, const txEnv* env);
bool lockTime(frameItem* dst, frameItem src, const txEnv* env);
bool inputsHash(frameItem* dst, frameItem src, const txEnv* env);
bool outputsHash(frameItem* dst, frameItem src, const txEnv* env);
bool numInputs(frameItem* dst, frameItem src, const txEnv* env);
bool totalInputValue(frameItem* dst, frameItem src, const txEnv* env);
bool currentPrevOutpoint(frameItem* dst, frameItem src, const txEnv* env);
bool currentValue(frameItem* dst, frameItem src, const txEnv* env);
bool currentSequence(frameItem* dst, frameItem src, const txEnv* env);
bool currentIndex(frameItem* dst, frameItem src, const txEnv* env);
bool inputPrevOutpoint(frameItem* dst, frameItem src, const txEnv* env);
bool inputValue(frameItem* dst, frameItem src, const txEnv* env);
bool inputSequence(frameItem* dst, frameItem src, const txEnv* env);
bool numOutputs(frameItem* dst, frameItem src, const txEnv* env);
bool totalOutputValue(frameItem* dst, frameItem src, const txEnv* env);
bool outputValue(frameItem* dst, frameItem src, const txEnv* env);
bool outputScriptHash(frameItem* dst, frameItem src, const txEnv* env);
bool scriptCMR(frameItem* dst, frameItem src, const txEnv* env);

#endif
