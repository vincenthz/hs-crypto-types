-- |
-- Module      : Crypto.Types
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
module Crypto.Types
    (
    -- * Keys
      Key64(..)
    , Key128(..)
    , Key256(..)
    -- * Initial Vectors
    , IV64(..)
    , IV128(..)
    , IV256(..)
    -- * A generic secret
    , Secret(..)
    ) where

import Data.Word
import Crypto.Types.SecureMem
import Control.Applicative ((<$>))
import Data.Serialize

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

-- | 256 bits key
newtype Key256 = Key256 SecureMem
    deriving (Eq)

instance Serialize Key64 where
    put (Key64 sm) = putByteString $ secureMemToByteString sm
    get = Key64 . secureMemFromByteString <$> getByteString 8

instance Serialize Key128 where
    put (Key128 sm) = putByteString $ secureMemToByteString sm
    get = Key128 . secureMemFromByteString <$> getByteString 16

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

instance Serialize IV64 where
    put (IV64 sm) = putByteString $ secureMemToByteString sm
    get = IV64 . secureMemFromByteString <$> getByteString 8

instance Serialize IV128 where
    put (IV128 sm) = putByteString $ secureMemToByteString sm
    get = IV128 . secureMemFromByteString <$> getByteString 16

instance Serialize IV256 where
    put (IV256 sm) = putByteString $ secureMemToByteString sm
    get = IV256 . secureMemFromByteString <$> getByteString 32
