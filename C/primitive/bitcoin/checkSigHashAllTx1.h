#ifndef PRIMITIVE_BITCOIN_CHECKSIGHASHALLTX1_H
#define PRIMITIVE_BITCOIN_CHECKSIGHASHALLTX1_H

#include <stddef.h>
#include <stdint.h>

/* A length-prefixed encoding of the following Simplicity program:
 *       (Simplicity.Bitcoin.Programs.CheckSigHashAll.Lib.pkwCheckSigHashAll
 *         (XOnlyPubKey 0x00000000000000000000003b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63)
 *         (Sig 0x00000000000000000000003b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63
 *              0x7d0fbcf693ee43460b86b587111e5087d9f7386c1c49284fb2f8e5c096a339b8
 *       ) )
 * with jets.
 */
extern const unsigned char bitcoinCheckSigHashAllTx1[];
extern const size_t sizeof_bitcoinCheckSigHashAllTx1;


/* The commitment Merkle root of the above elementsCheckSigHashAllTx1 Simplicity expression. */
extern const uint32_t bitcoinCheckSigHashAllTx1_cmr[];

/* The witness Merkle root of the above elementsCheckSigHashAllTx1 Simplicity expression. */
extern const uint32_t bitcoinCheckSigHashAllTx1_wmr[];

#endif
