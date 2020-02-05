/* This module implements the 'primitive.h' interface for the Elements application of Simplicity.
 */
#include "primitive.h"

#include "../../callonce.h"
#include "jets.h"
#include "../../jets.h"
#include "../../tag.h"
#include "../../unreachable.h"

#define PRIMITIVE_TAG(s) "Simplicity\x1F" "Primitive\x1F" "Bitcoin\x1F" s
#define JET_TAG "Simplicity\x1F" "Jet"

/* An enumeration of all the types we need to construct to specify the input and output types of all jets created by 'decodeJet'. */
enum TypeNamesForJets {
  one,
  two,
  word2,
  word4,
  word8,
  word16,
  word32,
  word64,
  word128,
  word256,
  word512,
  word1024,
  outpnt,
  sWord32,
  sWord64,
  sWord256,
  sOutpnt,
  twoTimesWord32,
  word64TimesTwo,
  word256TimesWord512,
  NumberOfTypeNames
};

/* Allocate a fresh set of unification variables bound to at least all the types necessary
 * for all the jets that can be created by 'decodeJet', and also the type 'TWO^256'.
 * Return the number of non-trivial bindings created.
 *
 * However, if malloc fails, then return 0.
 *
 * Precondition: NULL != bound_var;
 *               NULL != word256_ix;
 *               NULL != extra_var_start;
 *
 * Postcondition: Either '*bound_var == NULL' and the function returns 0
 *                or 'unification_var (*bound_var)[*extra_var_start + extra_var_len]' is an array of unification variables
 *                   such that for any 'jet : A |- B' there is some 'i < *extra_var_start' and 'j < *extra_var_start' such that
 *                      '(*bound_var)[i]' is bound to 'A' and '(*bound_var)[j]' is bound to 'B'
 *                   and, '*word256_ix < *extra_var_start' and '(*bound_var)[*word256_ix]' is bound the type 'TWO^256'
 */
size_t mallocBoundVars(unification_var** bound_var, size_t* word256_ix, size_t* extra_var_start, size_t extra_var_len) {
  _Static_assert(NumberOfTypeNames <= SIZE_MAX / sizeof(unification_var), "NumberOfTypeNames is too large");
  *bound_var = extra_var_len <= SIZE_MAX / sizeof(unification_var) - NumberOfTypeNames
             ? malloc((NumberOfTypeNames + extra_var_len) * sizeof(unification_var))
             : NULL;
  if (!(*bound_var)) return 0;
  (*bound_var)[one] = (unification_var){ .isBound = true,
      .bound = { .kind = ONE } };
  (*bound_var)[two] = (unification_var){ .isBound = true,
      .bound = { .kind = SUM,     .arg = { &(*bound_var)[one], &(*bound_var)[one] } } };
  (*bound_var)[word2] = (unification_var){ .isBound = true,
      .bound = { .kind = PRODUCT, .arg = { &(*bound_var)[two], &(*bound_var)[two] } } };
  (*bound_var)[word4] = (unification_var){ .isBound = true,
      .bound = { .kind = PRODUCT, .arg = { &(*bound_var)[word2], &(*bound_var)[word2] } } };
  (*bound_var)[word8] = (unification_var){ .isBound = true,
      .bound = { .kind = PRODUCT, .arg = { &(*bound_var)[word4], &(*bound_var)[word4] } } };
  (*bound_var)[word16] = (unification_var){ .isBound = true,
      .bound = { .kind = PRODUCT, .arg = { &(*bound_var)[word8], &(*bound_var)[word8] } } };
  (*bound_var)[word32] = (unification_var){ .isBound = true,
      .bound = { .kind = PRODUCT, .arg = { &(*bound_var)[word16], &(*bound_var)[word16] } } };
  (*bound_var)[word64] = (unification_var){ .isBound = true,
      .bound = { .kind = PRODUCT, .arg = { &(*bound_var)[word32], &(*bound_var)[word32] } } };
  (*bound_var)[word128] = (unification_var){ .isBound = true,
      .bound = { .kind = PRODUCT, .arg = { &(*bound_var)[word64], &(*bound_var)[word64] } } };
  (*bound_var)[word256] = (unification_var){ .isBound = true,
      .bound = { .kind = PRODUCT, .arg = { &(*bound_var)[word128], &(*bound_var)[word128] } } };
  (*bound_var)[word512] = (unification_var){ .isBound = true,
      .bound = { .kind = PRODUCT, .arg = { &(*bound_var)[word256], &(*bound_var)[word256] } } };
  (*bound_var)[word1024] = (unification_var){ .isBound = true,
      .bound = { .kind = PRODUCT, .arg = { &(*bound_var)[word512], &(*bound_var)[word512] } } };
  (*bound_var)[outpnt] = (unification_var){ .isBound = true,
      .bound = { .kind = PRODUCT, .arg = { &(*bound_var)[word256], &(*bound_var)[word32] } } };
  (*bound_var)[sWord32] = (unification_var){ .isBound = true,
      .bound = { .kind = SUM,     .arg = { &(*bound_var)[one], &(*bound_var)[word32] } } };
  (*bound_var)[sWord64] = (unification_var){ .isBound = true,
      .bound = { .kind = SUM,     .arg = { &(*bound_var)[one], &(*bound_var)[word64] } } };
  (*bound_var)[sWord256] = (unification_var){ .isBound = true,
      .bound = { .kind = SUM,     .arg = { &(*bound_var)[one], &(*bound_var)[word256] } } };
  (*bound_var)[sOutpnt] = (unification_var){ .isBound = true,
      .bound = { .kind = SUM,     .arg = { &(*bound_var)[one], &(*bound_var)[outpnt] } } };
  (*bound_var)[twoTimesWord32] = (unification_var){ .isBound = true,
      .bound = { .kind = PRODUCT, .arg = { &(*bound_var)[two], &(*bound_var)[word32] } } };
  (*bound_var)[word64TimesTwo] = (unification_var){ .isBound = true,
      .bound = { .kind = PRODUCT, .arg = { &(*bound_var)[word64], &(*bound_var)[two] } } };
  (*bound_var)[word256TimesWord512] = (unification_var){ .isBound = true,
      .bound = { .kind = PRODUCT, .arg = { &(*bound_var)[word256], &(*bound_var)[word512] } } };

  *word256_ix = word256;
  *extra_var_start = NumberOfTypeNames;

  /* 'one' is a trivial binding, so we made 'NumberOfTypeNames - 1' non-trivial bindings. */
  return NumberOfTypeNames - 1;
};

/* An enumeration of the names of Bitcoin specific jets and primitives. */
typedef enum jetName
{ ADDER32
, SUBTRACTOR32
, MULTIPLIER32
, FULLADDER32
, FULLSUBTRACTOR32
, FULLMULTIPLIER32
, SHA256_HASHBLOCK
, SCHNORRASSERT
, VERSION
, LOCKTIME
, INPUTSHASH
, OUTPUTSHASH
, NUMINPUTS
, TOTALINPUTVALUE
, CURRENTPREVOUTPOINT
, CURRENTVALUE
, CURRENTSEQUENCE
, CURRENTINDEX
, INPUTPREVOUTPOINT
, INPUTVALUE
, INPUTSEQUENCE
, NUMOUTPUTS
, TOTALOUTPUTVALUE
, OUTPUTVALUE
, OUTPUTSCRIPTHASH
, SCRIPTCMR
, NUMBER_OF_JET_NAMES
} jetName;

static int32_t either(jetName* result, jetName a, jetName b, bitstream* stream) {
  int32_t bit = getBit(stream);
  if (bit < 0) return bit;
  *result = bit ? b : a;
  return 0;
}

/* Decode a Bitcoin specific jet name from 'stream' into 'result'.
 * All jets begin with a bit prefix of '1' which needs to have already been consumed from the 'stream'.
 * Returns 'ERR_DATA_OUT_OF_RANGE' if the stream's prefix doesn't match any valid code for a jet.
 * Returns 'ERR_BITSTRING_EOF' if not enough bits are available in the 'stream'.
 * Returns 'ERR_BITSTREAM_ERROR' if an I/O error occurs when reading from the 'stream'.
 * In the above error cases, 'result' may be modified.
 * Returns 0 if successful.
 *
 * Precondition: NULL != result
 *               NULL != stream
 */
static int32_t decodePrimitive(jetName* result, bitstream* stream) {
  int32_t bit = getBit(stream);
  if (bit < 0) return bit;
  if (!bit) {
    int32_t code = getNBits(4, stream);
    if (code < 0) return code;

    switch (code) {
     case 0x0: return either(result, VERSION, LOCKTIME, stream);
     case 0x1: *result = INPUTSHASH; return 0;
     case 0x2: *result = OUTPUTSHASH; return 0;
     case 0x3: *result = NUMINPUTS; return 0;
     case 0x4: *result = TOTALINPUTVALUE; return 0;
     case 0x5: *result = CURRENTPREVOUTPOINT; return 0;
     case 0x6: *result = CURRENTVALUE; return 0;
     case 0x7: *result = CURRENTSEQUENCE; return 0;
     case 0x8: return either(result, CURRENTINDEX, INPUTPREVOUTPOINT, stream);
     case 0x9: *result = INPUTVALUE; return 0;
     case 0xa: *result = INPUTSEQUENCE; return 0;
     case 0xb: *result = NUMOUTPUTS; return 0;
     case 0xc: *result = TOTALOUTPUTVALUE; return 0;
     case 0xd: *result = OUTPUTVALUE; return 0;
     case 0xe: *result = OUTPUTSCRIPTHASH; return 0;
     case 0xf: *result = SCRIPTCMR; return 0;
    }
    assert(false);
    UNREACHABLE;
  } else {
    bit = getBit(stream);
    if (bit < 0) return bit;
    if (!bit) {
      int32_t code = getNBits(2, stream);
      if (code < 0) return code;

      switch (code) {
        case 0x0: return either(result, ADDER32, SUBTRACTOR32, stream);
        case 0x1: *result = MULTIPLIER32; return 0;
        case 0x2: return either(result, FULLADDER32, FULLSUBTRACTOR32, stream);
        case 0x3: *result = FULLMULTIPLIER32; return 0;
      }
      assert(false);
      UNREACHABLE;
    } else {
      return either(result, SHA256_HASHBLOCK, SCHNORRASSERT, stream);
    }
  }
}

/* Cached copy of each node for all the Elements specific jets.
 * Only to be accessed through 'jetNode'.
 */
static once_flag static_initialized = ONCE_FLAG_INIT;
static dag_node jet_node[] = {
 [ADDER32] =
    { .tag = JET
    , .jet = adder32
    , .sourceIx = word64
    , .targetIx = twoTimesWord32
    },
 [SUBTRACTOR32] =
    { .tag = JET
    , .jet = subtractor32
    , .sourceIx = word64
    , .targetIx = twoTimesWord32
    },
 [MULTIPLIER32] =
    { .tag = JET
    , .jet = multiplier32
    , .sourceIx = word64
    , .targetIx = word64
    },
 [FULLADDER32] =
    { .tag = JET
    , .jet = fullAdder32
    , .sourceIx = word64TimesTwo
    , .targetIx = twoTimesWord32
    },
 [FULLSUBTRACTOR32] =
    { .tag = JET
    , .jet = fullSubtractor32
    , .sourceIx = word64TimesTwo
    , .targetIx = twoTimesWord32
    },
 [FULLMULTIPLIER32] =
    { .tag = JET
    , .jet = fullMultiplier32
    , .sourceIx = word128
    , .targetIx = word64
    },
 [SHA256_HASHBLOCK] =
    { .tag = JET
    , .jet = sha256_hashBlock
    , .sourceIx = word256TimesWord512
    , .targetIx = word256
    },
 [SCHNORRASSERT] =
    { .tag = JET
    , .jet = schnorrAssert
    , .sourceIx = word1024
    , .targetIx = one
    },
 [VERSION] =
    { .tag = JET
    , .jet = version
    , .sourceIx = one
    , .targetIx = word32
    },
 [LOCKTIME] =
    { .tag = JET
    , .jet = lockTime
    , .sourceIx = one
    , .targetIx = word32
    },
 [INPUTSHASH] =
    { .tag = JET
    , .jet = inputsHash
    , .sourceIx = one
    , .targetIx = word256
    },
 [OUTPUTSHASH] =
    { .tag = JET
    , .jet = outputsHash
    , .sourceIx = one
    , .targetIx = word256
    },
 [NUMINPUTS] =
    { .tag = JET
    , .jet = numInputs
    , .sourceIx = one
    , .targetIx = word32
    },
 [TOTALINPUTVALUE] =
    { .tag = JET
    , .jet = totalInputValue
    , .sourceIx = one
    , .targetIx = word64
    },
 [CURRENTPREVOUTPOINT] =
    { .tag = JET
    , .jet = currentPrevOutpoint
    , .sourceIx = one
    , .targetIx = outpnt
    },
 [CURRENTVALUE] =
    { .tag = JET
    , .jet = currentValue
    , .sourceIx = one
    , .targetIx = word64
    },
 [CURRENTSEQUENCE] =
    { .tag = JET
    , .jet = currentSequence
    , .sourceIx = one
    , .targetIx = word32
    },
 [CURRENTINDEX] =
    { .tag = JET
    , .jet = currentIndex
    , .sourceIx = one
    , .targetIx = word32
    },
 [INPUTPREVOUTPOINT] =
    { .tag = JET
    , .jet = inputPrevOutpoint
    , .sourceIx = word32
    , .targetIx = sOutpnt
    },
 [INPUTVALUE] =
    { .tag = JET
    , .jet = inputValue
    , .sourceIx = word32
    , .targetIx = sWord64
    },
 [INPUTSEQUENCE] =
    { .tag = JET
    , .jet = inputSequence
    , .sourceIx = word32
    , .targetIx = sWord32
    },
 [NUMOUTPUTS] =
    { .tag = JET
    , .jet = numOutputs
    , .sourceIx = one
    , .targetIx = word32
    },
 [TOTALOUTPUTVALUE] =
    { .tag = JET
    , .jet = totalOutputValue
    , .sourceIx = one
    , .targetIx = word64
    },
 [OUTPUTVALUE] =
    { .tag = JET
    , .jet = outputValue
    , .sourceIx = word32
    , .targetIx = sWord64
    },
 [OUTPUTSCRIPTHASH] =
    { .tag = JET
    , .jet = outputScriptHash
    , .sourceIx = word32
    , .targetIx = sWord256
    },
 [SCRIPTCMR] =
    { .tag = JET
    , .jet = scriptCMR
    , .sourceIx = one
    , .targetIx = word256
    }
 };
static void static_initialize(void) {
  {
    sha256_midstate jet_iv;
    MK_TAG(jet_iv.s, JET_TAG);

#define MK_JET(name, h0, h1, h2, h3, h4, h5, h6, h7) \
  do { \
    jet_node[name].wmr = jet_iv; \
    sha256_compression(jet_node[name].wmr.s, (uint32_t[16]){ [8] = h0, h1, h2, h3, h4, h5, h6, h7 }); \
  } while(0)

    MK_JET(ADDER32,          0x8e389a7d, 0x75429a8a, 0x6f5b448e, 0xc8e84585, 0x20e276fc, 0x8e09ef5a, 0x68f3f32d, 0x9fb97935);
    MK_JET(FULLADDER32,      0xb914e4b5, 0x9f8eded4, 0xcd036e03, 0xffa5f11a, 0xa8668ae4, 0x9863bbb4, 0x3a0d7c3a, 0x14c916f0);
    MK_JET(SUBTRACTOR32,     0x75ebd569, 0xbfce7af8, 0x030c49c7, 0x3e104c03, 0x65de898e, 0xa8d52670, 0xbffe9f6e, 0x312ff6e6);
    MK_JET(FULLSUBTRACTOR32, 0x7a52e83e, 0x253ae776, 0xb0b948f1, 0x5083528e, 0x1c5d58cd, 0x5e03d4f2, 0xf04a9626, 0xe0476aeb);
    MK_JET(MULTIPLIER32,     0x405914c9, 0x524c4873, 0xce5ddb06, 0xfd30d6d5, 0xfc4ac1fa, 0xc0eef8d8, 0x2de6c622, 0x7fb2d2cd);
    MK_JET(FULLMULTIPLIER32, 0x89a0ae09, 0x8aff5e9c, 0x40907447, 0x91ff5c8e, 0xe17a8ceb, 0x9e494224, 0xe919deb1, 0x1c5b8af4);
    MK_JET(SHA256_HASHBLOCK, 0xeeae47e2, 0xf7876c3b, 0x9cbcd404, 0xa338b089, 0xfdeadf1b, 0x9bb382ec, 0x6e69719d, 0x31baec9a);
    MK_JET(SCHNORRASSERT,    0xa1e76928, 0xf5dfd245, 0xf417e465, 0xe067e043, 0xa1070996, 0x497ce766, 0xed95a5c7, 0x85c3c7c1);

#undef MK_JET
  }
  MK_TAG(jet_node[VERSION].wmr.s, PRIMITIVE_TAG("version"));
  MK_TAG(jet_node[LOCKTIME].wmr.s, PRIMITIVE_TAG("lockTime"));
  MK_TAG(jet_node[INPUTSHASH].wmr.s, PRIMITIVE_TAG("inputsHash"));
  MK_TAG(jet_node[OUTPUTSHASH].wmr.s, PRIMITIVE_TAG("outputsHash"));
  MK_TAG(jet_node[NUMINPUTS].wmr.s, PRIMITIVE_TAG("numInputs"));
  MK_TAG(jet_node[TOTALINPUTVALUE].wmr.s, PRIMITIVE_TAG("totalInputValue"));
  MK_TAG(jet_node[CURRENTPREVOUTPOINT].wmr.s, PRIMITIVE_TAG("currentPrevOutpoint"));
  MK_TAG(jet_node[CURRENTVALUE].wmr.s, PRIMITIVE_TAG("currentValue"));
  MK_TAG(jet_node[CURRENTSEQUENCE].wmr.s, PRIMITIVE_TAG("currentSequence"));
  MK_TAG(jet_node[CURRENTINDEX].wmr.s, PRIMITIVE_TAG("currentIndex"));
  MK_TAG(jet_node[INPUTPREVOUTPOINT].wmr.s, PRIMITIVE_TAG("inputPrevOutpoint"));
  MK_TAG(jet_node[INPUTVALUE].wmr.s, PRIMITIVE_TAG("inputValue"));
  MK_TAG(jet_node[INPUTSEQUENCE].wmr.s, PRIMITIVE_TAG("inputSequence"));
  MK_TAG(jet_node[NUMOUTPUTS].wmr.s, PRIMITIVE_TAG("numOutputs"));
  MK_TAG(jet_node[TOTALOUTPUTVALUE].wmr.s, PRIMITIVE_TAG("totalOutputValue"));
  MK_TAG(jet_node[OUTPUTVALUE].wmr.s, PRIMITIVE_TAG("outputValue"));
  MK_TAG(jet_node[OUTPUTSCRIPTHASH].wmr.s, PRIMITIVE_TAG("outputScriptHash"));
  MK_TAG(jet_node[SCRIPTCMR].wmr.s, PRIMITIVE_TAG("scriptCMR"));
}

/* Return a copy of the Simplicity node corresponding to the given Elements specific jet 'name'.
 */
static dag_node jetNode(jetName name) {
  call_once(&static_initialized, &static_initialize);

  return jet_node[name];
}

/* Decode a Bitcoin specific jet from 'stream' into 'node'.
 * All jets begin with a bit prefix of '1' which needs to have already been consumed from the 'stream'.
 * Returns 'ERR_DATA_OUT_OF_RANGE' if the stream's prefix doesn't match any valid code for a jet.
 * Returns 'ERR_BITSTRING_EOF' if not enough bits are available in the 'stream'.
 * Returns 'ERR_BITSTREAM_ERROR' if an I/O error occurs when reading from the 'stream'.
 * In the above error cases, 'dag' may be modified.
 * Returns 0 if successful.
 *
 * Precondition: NULL != node
 *               NULL != stream
 */
int32_t decodeJet(dag_node* node, bitstream* stream) {
  jetName name;
  int32_t err = decodePrimitive(&name, stream);
  if (err < 0) return err;
  *node = jetNode(name);
  return 0;
}
