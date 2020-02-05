module Simplicity.Elements.Tests (tests) where

import Data.Array ((!), listArray, elems)
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as BSL
import Data.Digest.Pure.SHA (padSHA1)
import Data.Serialize (encode, put, putLazyByteString, putWord32be, putWord32le, runPutLazy)
import Lens.Family2 (review, over)

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Simplicity.Digest
import Simplicity.Elements.DataTypes
import Simplicity.Elements.Primitive
import Simplicity.Elements.Programs.CheckSigHashAll.Lib
import Simplicity.Elements.Semantics
import Simplicity.MerkleRoot
import Simplicity.Ty.Word

tests :: TestTree
tests = testGroup "Elements"
        [ testCase "sigHashAll" (assertBool "sigHashAll_matches" hunit_sigHashAll)
        ]

tx1 :: SigTx
tx1 = SigTx
      { sigTxVersion = 0x00000002
      , sigTxIn = listArray (0, 0) [input0]
      , sigTxOut = listArray (0, 1) [output0, output1]
      , sigTxLock = 0
      }
 where
  assetId = Asset . Explicit $ review (over be256) 0xee56c76b75e615f943fad6bf3256369fcaa8e474ff463a0f2999c2570cdf48b2
  input0 = SigTxInput
    { sigTxiIsPegin = False
    , sigTxiPreviousOutpoint = Outpoint (review (over be256) 0x077364992e3b23c5e7ce9bb6315799f60054bb3f3feff496534c2d0734cd5f27) 1
    , sigTxiTxo = UTXO
        { utxoAsset = assetId
        , utxoAmount = Amount . Explicit $ 100000000
        , utxoScript = undefined
        }
    , sigTxiSequence = 0xfffffffd
    , sigTxiIssuance = Nothing
    }
  output0 = TxOutput
    { txoAsset = assetId
    , txoAmount = Amount . Explicit $ 99934464
    , txoNonce = Nothing
    , txoScript = BSL.pack
        [ 0xa9, 0x14, 0xf5, 0x61, 0x0c, 0xfd, 0xe7, 0xa9, 0x51, 0x9e, 0x4e, 0x10, 0xbd, 0x5c, 0xb2, 0x19, 0x6e, 0x16, 0xed, 0xba, 0xb2, 0xf1, 0x87 ]
    }
  output1 = TxOutput
    { txoAsset = assetId
    , txoAmount = Amount . Explicit $ 65536
    , txoNonce = Nothing
    , txoScript = BSL.empty
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
        >> putWord32be (sigTxVersion tx1)
        >> putWord32be (sigTxLock tx1)
        >> putWord32be ix
        >> put (utxoAsset txo)
        >> put (utxoAmount txo)
   where
    ix = 0
    txo = sigTxiTxo (sigTxIn tx1 ! ix)
