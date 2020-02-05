module Simplicity.Bitcoin.Tests (tests) where

import Data.Array ((!), listArray, elems)
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as BSL
import Data.Digest.Pure.SHA (padSHA1)
import Data.Serialize (encode, put, putLazyByteString, putWord64be, putWord32be, putWord32le, runPutLazy)
import Lens.Family2 (review, over)

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Simplicity.Digest
import Simplicity.Bitcoin.DataTypes
import Simplicity.Bitcoin.Primitive
import Simplicity.Bitcoin.Programs.CheckSigHashAll.Lib
import Simplicity.Bitcoin.Semantics
import Simplicity.MerkleRoot
import Simplicity.Ty.Word

tests :: TestTree
tests = testGroup "Bitcoin"
        [ testCase "sigHashAll" (assertBool "sigHashAll_matches" hunit_sigHashAll)
        ]

tx1 :: SigTx
tx1 = SigTx
      { sigTxVersion = 0x00000002
      , sigTxIn = listArray (0, 0) [input0]
      , sigTxOut = listArray (0, 0) [output0]
      , sigTxLock = 0
      }
 where
  input0 = SigTxInput
    { sigTxiPreviousOutpoint = Outpoint (review (over be256) 0x2cfd97686994ff7c3968fbef08bf4c111012b5e44dafdb81d7019033dda8d97e) 0

    , sigTxiValue = 100000000
    , sigTxiSequence = 0xfffffffe
    }
  output0 = TxOutput
    { txoValue = 99996700
    , txoScript = BSL.pack
        [ 0xa9, 0x14, 0xd0, 0x8b, 0xc6, 0x78, 0x88, 0x5b, 0x67, 0xbd, 0xb8, 0xa4, 0x79, 0x78, 0xe2
        , 0x1e, 0xc7, 0x85, 0x61, 0xc6, 0xba, 0x5e, 0x87]
    }

hunit_sigHashAll :: Bool
hunit_sigHashAll = Just (integerHash256 (bslHash sigAll)) == (fromWord256 <$> (sem sigHashAll txEnv ()))
 where
  ix = 0
  cmr = commitmentRoot sigHashAll
  Just txEnv = primEnv tx1 ix cmr
  sigAll = runPutLazy
         $ putLazyByteString (padSHA1 . BSL.fromStrict $ BSC.pack "Simplicity\USSignature\GS" <> encode sigAllCMR)
        >> put (sigTxInputsHash tx1)
        >> put (sigTxOutputsHash tx1)
        >> putWord64be (sigTxiValue (sigTxIn tx1 ! ix))
        >> putWord32be ix
        >> putWord32be (sigTxLock tx1)
        >> putWord32be (sigTxVersion tx1)
