-- |
-- Module      : Crypto.Types
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
{-# LANGUAGE DeriveDataTypeable #-}
module Crypto.Types
    (
    -- * Keys Types
      Key64
    , Key128
    , Key192
    , Key256
    -- * Keys Constructors
    , key64
    , key128
    , key192
    , key256
    , InvalidKeySize(..)
    -- * Initial Vectors Types
    , IV64
    , IV128
    , IV256
    -- * Initial Vectors Constructors
    , iv64
    , iv128
    , iv256
    , InvalidIVSize(..)
    -- * A generic secret
    , Secret(..)
    ) where

import Data.Word
import Crypto.Types.SecureMem
import Control.Applicative ((<$>))
import Control.Exception (Exception, throw)
import Data.Serialize
import Data.Data
import Data.ByteString as B

-- | a Secret
newtype Secret = Secret SecureMem
    deriving (Eq)

instance Serialize Secret where
    put (Secret sm) = putByteString $ secureMemToByteString sm
    get = remaining >>= \r -> Secret . secureMemFromByteString <$> getByteString r

-- | 64 bits key
newtype Key64 = Key64 SecureMem
    deriving (Eq)

-- | 128 bits key
newtype Key128 = Key128 SecureMem
    deriving (Eq)

-- | 192 bits key
newtype Key192 = Key192 SecureMem
    deriving (Eq)

-- | 256 bits key
newtype Key256 = Key256 SecureMem
    deriving (Eq)

-- | Invalid Key size exception raised if key is not of proper size.
--
-- the first argument is the expected size and the second is the
-- received size.
data InvalidKeySize = InvalidKeySize Int Int
    deriving (Show,Eq,Typeable)

instance Exception InvalidKeySize

key64 :: ByteString -> Key64
key64 b
    | B.length b == 8 = Key64 $ secureMemFromByteString b
    | otherwise       = throw $ InvalidKeySize 8 (B.length b)

key128 :: ByteString -> Key128
key128 b
    | B.length b == 16 = Key128 $ secureMemFromByteString b
    | otherwise        = throw $ InvalidKeySize 16 (B.length b)

key192 :: ByteString -> Key192
key192 b
    | B.length b == 24 = Key192 $ secureMemFromByteString b
    | otherwise        = throw $ InvalidKeySize 24 (B.length b)

key256 :: ByteString -> Key256
key256 b
    | B.length b == 32 = Key256 $ secureMemFromByteString b
    | otherwise        = throw $ InvalidKeySize 32 (B.length b)

instance Serialize Key64 where
    put (Key64 sm) = putByteString $ secureMemToByteString sm
    get = Key64 . secureMemFromByteString <$> getByteString 8

instance Serialize Key128 where
    put (Key128 sm) = putByteString $ secureMemToByteString sm
    get = Key128 . secureMemFromByteString <$> getByteString 16

instance Serialize Key192 where
    put (Key192 sm) = putByteString $ secureMemToByteString sm
    get = Key192 . secureMemFromByteString <$> getByteString 24

instance Serialize Key256 where
    put (Key256 sm) = putByteString $ secureMemToByteString sm
    get = Key256 . secureMemFromByteString <$> getByteString 32

-- | 64 bits IV
newtype IV64 = IV64 SecureMem
    deriving (Eq)

-- | 128 bits IV
newtype IV128 = IV128 SecureMem
    deriving (Eq)

-- | 256 bits IV
newtype IV256 = IV256 SecureMem
    deriving (Eq)

-- | Invalid IV size exception raised if IV is not of proper size.
--
-- the first argument is the expected size and the second is the
-- received size.
data InvalidIVSize = InvalidIVSize Int Int
    deriving (Show,Eq,Typeable)

instance Exception InvalidIVSize

iv64 :: ByteString -> IV64
iv64 b
    | B.length b == 8 = IV64 $ secureMemFromByteString b
    | otherwise       = throw $ InvalidIVSize 8 (B.length b)

iv128 :: ByteString -> IV128
iv128 b
    | B.length b == 16 = IV128 $ secureMemFromByteString b
    | otherwise        = throw $ InvalidIVSize 16 (B.length b)

iv256 :: ByteString -> IV256
iv256 b
    | B.length b == 32 = IV256 $ secureMemFromByteString b
    | otherwise        = throw $ InvalidIVSize 32 (B.length b)

instance Serialize IV64 where
    put (IV64 sm) = putByteString $ secureMemToByteString sm
    get = IV64 . secureMemFromByteString <$> getByteString 8

instance Serialize IV128 where
    put (IV128 sm) = putByteString $ secureMemToByteString sm
    get = IV128 . secureMemFromByteString <$> getByteString 16

instance Serialize IV256 where
    put (IV256 sm) = putByteString $ secureMemToByteString sm
    get = IV256 . secureMemFromByteString <$> getByteString 32
