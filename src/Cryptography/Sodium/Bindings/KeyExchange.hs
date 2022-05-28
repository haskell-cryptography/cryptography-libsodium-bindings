{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE Trustworthy #-}

-- |
-- Module: Cryptography.Sodium.Bindings.KeyExchange
-- Description: Direct bindings to the key exchange functions implemented in Libsodium
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Stability: Stable
-- Portability: GHC only
module Cryptography.Sodium.Bindings.KeyExchange
  ( -- * Introduction
    -- $introduction

    -- * Key Exchange

    -- ** Key generation
    cryptoKXKeyPair,
    cryptoKXSeedKeypair,

    -- ** Client
    cryptoKXClientSessionKeys,

    -- ** Server
    cryptoKXServerSessionKeys,

    -- ** Constants
    cryptoKXPublicKeyBytes,
    cryptoKXSecretKeyBytes,
    cryptoKXSeedBytes,
    cryptoKXSessionKeyBytes,
    cryptoKXPrimitive,
  )
where

import Foreign (Ptr)
import Foreign.C (CInt (CInt), CSize (CSize), CUChar)

-- $introduction
--
-- The key exchange API allows two parties to securely compute a set of shared keys using their peer's public key, and
-- their own secret key.

-- | Create a new key pair.
--
-- This function takes pointers to two empty buffers that will hold (respectively) the public and secret keys.
--
-- /See also:/ [crypto_kx_keypair()](https://doc.libsodium.org/key_exchange#usage)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_kx_keypair"
  cryptoKXKeyPair ::
    -- | The buffer that will hold the public key, of size 'cryptoKXPublicKeyBytes'.
    Ptr CUChar ->
    -- | The buffer that will hold the secret key, of size 'cryptoKXSecretKeyBytes'.
    Ptr CUChar ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | Create a new key pair from a seed.
--
-- This function takes pointers to two empty buffers that will hold (respectively) the public and secret keys,
-- as well as the seed from which these keys will be derived.
--
-- /See also:/ [crypto_kx_seed_keypair()](https://doc.libsodium.org/key_exchange#usage)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_kx_seed_keypair"
  cryptoKXSeedKeypair ::
    -- | The buffer that will hold the public key, of size 'cryptoKXPublicKeyBytes'.
    Ptr CUChar ->
    -- | The buffer that will hold the secret key, of size 'cryptoKXSecretKeyBytes'.
    Ptr CUChar ->
    -- | The pointer to the seed from which the keys are derived. It is of size 'cryptoKXSeedBytes' bytes.
    Ptr CUChar ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | Compute a pair of shared session keys (secret and public).
--
-- These session keys are computed using:
--
-- * The client's public key
-- * The client's secret key
-- * The server's public key
--
-- The shared secret key should be used by the client to receive data from the server, whereas the shared
-- public key should be used for data flowing to the server.
--
-- If only one session key is required, either the pointer to the shared secret key or the pointer
-- to the shared public key can be set to 'Foreign.nullPtr'.
--
-- /See also:/ [crypto_kx_client_session_keys()](https://doc.libsodium.org/key_exchange#usage)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_kx_client_session_keys"
  cryptoKXClientSessionKeys ::
    -- | A pointer to the buffer that will hold the shared secret key, of size 'cryptoKXSessionKeyBytes' bytes.
    Ptr CUChar ->
    -- | A pointer to the buffer that will hold the shared public key, of size 'cryptoKXSessionKeyBytes' bytes.
    Ptr CUChar ->
    -- | A pointer to the client's public key, of size 'cryptoKXPublicKeyBytes' bytes.
    Ptr CUChar ->
    -- | A pointer to the client's secret key, of size 'cryptoKXSecretKeyBytes' bytes.
    Ptr CUChar ->
    -- | A pointer to the server's public key, of size 'cryptoKXPublicKeyBytes' bytes.
    Ptr CUChar ->
    -- | Returns 0 on success, -1 on error, such as when the server's public key is not acceptable.
    IO CInt

--

-- | Compute a pair of shared session keys (secret and public).
--
-- These session keys are computed using:
--
-- * The server's public key
-- * The server's secret key
-- * The client's public key
--
-- The shared secret key should be used by the server to receive data from the client, whereas the shared
-- public key should be used for data flowing to the client.
--
-- If only one session key is required, either the pointer to the shared secret key or the pointer
-- to the shared public key can be set to 'Foreign.nullPtr'.
--
-- /See also:/ [crypto_kx_server_session_keys()](https://doc.libsodium.org/key_exchange#usage)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_kx_server_session_keys"
  cryptoKXServerSessionKeys ::
    -- | A pointer to the buffer that will hold the shared secret key, of size 'cryptoKXSessionKeyBytes' bytes.
    Ptr CUChar ->
    -- | A pointer to the buffer that will hold the shared public key, of size 'cryptoKXSessionKeyBytes' bytes.
    Ptr CUChar ->
    -- | A pointer to the server's public key, of size 'cryptoKXPublicKeyBytes' bytes.
    Ptr CUChar ->
    -- | A pointer to the server's secret key, of size 'cryptoKXSecretKeyBytes' bytes.
    Ptr CUChar ->
    -- | A pointer to the client's public key, of size 'cryptoKXPublicKeyBytes' bytes.
    Ptr CUChar ->
    -- | Returns 0 on success, -1 on error, such as when the server's public key is not acceptable.
    IO CInt

-- | @since 0.0.1.0
foreign import capi "sodium.h value crypto_kx_PUBLICKEYBYTES"
  cryptoKXPublicKeyBytes :: CSize

-- | @since 0.0.1.0
foreign import capi "sodium.h value crypto_kx_SECRETKEYBYTES"
  cryptoKXSecretKeyBytes :: CSize

-- | @since 0.0.1.0
foreign import capi "sodium.h value crypto_kx_SEEDBYTES"
  cryptoKXSeedBytes :: CSize

-- | @since 0.0.1.0
foreign import capi "sodium.h value crypto_kx_SESSIONKEYBYTES"
  cryptoKXSessionKeyBytes :: CSize

-- | @since 0.0.1.0
foreign import capi "sodium.h value crypto_kx_PRIMITIVE"
  cryptoKXPrimitive :: CSize
