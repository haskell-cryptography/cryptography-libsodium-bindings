{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE Safe #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- |
--
-- Module: Cryptography.Sodium.Bindings.SecureMemory
-- Description: Direct bindings to the libsodium secure memory functions
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Stability: Stable
-- Portability: GHC only
module Cryptography.Sodium.Bindings.SecureMemory
  ( -- * Introduction
    -- $introduction

    -- * Zeroing memory
    memZero,

    -- * Locking memory
    lock,
    unlock,
  )
where

import Foreign (Ptr)
import Foreign.C.Types (CInt (CInt), CSize (CSize))

-- $introduction
-- This module provides bindings to the secure memory functions provided by Libsodium.
-- It is intended to be qualified on import:
--
-- > import qualified Cryptography.Sodium.Bindings.SecureMemory as SecureMemory
--
-- It is recommended to disable swap partitions on machines processing sensitive
-- data or, as a second choice, use encrypted swap partitions.
--
-- For similar reasons, on Unix systems, one should also disable core dumps when
-- running crypto code outside a development environment.
-- This can be achieved using a shell built-in such as @ulimit@ or programmatically
-- using @setrlimit(RLIMIT_CORE, &(struct rlimit) {0, 0})@.
-- On operating systems where this feature is implemented, kernel crash dumps
-- should also be disabled.
--
-- The 'lock' function wraps @mlock()@ and @VirtualLock()@.
--
-- Note: Many systems place limits on the amount of memory that may be locked
-- by a process. Care should be taken to raise those limits (e.g. Unix ulimits)
-- where necessary.

-- | Overwrite the memory region starting at the pointer
-- address with zeros.
--
-- @since 0.0.1.0
foreign import capi "sodium.h sodium_memzero"
  memZero ::
    -- | Start pointer
    Ptr x ->
    -- | Length in bytes of the area to zero
    CSize ->
    IO ()

-- | Lock a memory region starting at the pointer
-- address. This can help avoid swapping sensitive
-- data to disk.
--
-- @since 0.0.1.0
foreign import capi "sodium.h sodium_mlock"
  lock ::
    -- | Start pointer
    Ptr x ->
    -- | Size of the memory region to lock
    CSize ->
    -- | Returns 0 on success, -1 if any system limit is reached.
    IO CInt

-- | Unlock the memory region by overwriting it with zeros and and flagging the
-- pages as swappable again. Calling 'memZero' prior to 'unlock' is thus not required.
--
-- On systems where it is supported, 'lock' also wraps @madvise()@ and advises the kernel not to include the locked memory in core dumps. The 'unlock'
-- function also undoes this additional protection.
--
-- @since 0.0.1.0
foreign import capi "sodium.h sodium_munlock"
  unlock ::
    -- | Start pointer
    Ptr x ->
    -- | Size of the memory region to unlock
    CSize ->
    IO CInt
