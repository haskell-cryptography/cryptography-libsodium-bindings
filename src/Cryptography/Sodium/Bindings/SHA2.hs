{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE Trustworthy #-}

-- |
--
-- Module: Cryptography.Sodium.Bindings.SHA2
-- Description: Direct bindings to the SHA-256 and SHA-512 hashing functions, and their HMAC variants
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Stability: Stable
-- Portability: GHC only
module Cryptography.Sodium.Bindings.SHA2
  ( -- * Introduction
    -- $introduction

    -- * SHA-256

    -- ** Single-part message
    cryptoHashSHA256,

    -- ** Multi-part messages
    CryptoHashSHA256State,
    withCryptoHashSHA256State,
    cryptoHashSHA256Init,
    cryptoHashSHA256Update,
    cryptoHashSHA256Final,

    -- ** Constants
    cryptoHashSHA256Bytes,
    cryptoHashSHA256StateBytes,

    -- * HMAC-SHA-256

    -- ** Single-part message
    cryptoAuthHMACSHA256,
    cryptoAuthHMACSHA256Verify,
    cryptoAuthHMACSHA256Keygen,

    -- ** Multi-part messages
    CryptoAuthHMACSHA256State,
    withCryptoAuthHMACSHA256State,
    cryptoAuthHMACSHA256Init,
    cryptoAuthHMACSHA256Update,
    cryptoAuthHMACSHA256Final,

    -- ** Constants
    cryptoAuthHMACSHA256StateBytes,
    cryptoAuthHMACSHA256Bytes,
    cryptoAuthHMACSHA256KeyBytes,

    -- * SHA-512

    -- ** Single-part message
    cryptoHashSHA512,

    -- ** Multi-part messages
    CryptoHashSHA512State,
    withCryptoHashSHA512State,
    cryptoHashSHA512Init,
    cryptoHashSHA512Update,
    cryptoHashSHA512Final,

    -- ** Constants
    cryptoHashSHA512Bytes,
    cryptoHashSHA512StateBytes,

    -- * HMAC-SHA-512

    -- ** Single-part message
    CryptoAuthHMACSHA512State,
    withCryptoAuthHMACSHA512State,
    cryptoAuthHMACSHA512,
    cryptoAuthHMACSHA512Verify,
    cryptoAuthHMACSHA512Keygen,

    -- ** Multi-part messages
    cryptoAuthHMACSHA512Init,
    cryptoAuthHMACSHA512Update,
    cryptoAuthHMACSHA512Final,

    -- ** Constants
    cryptoAuthHMACSHA512StateBytes,
    cryptoAuthHMACSHA512Bytes,
    cryptoAuthHMACSHA512KeyBytes,

    -- * HMAC-SHA-512-256
    -- $hmacsha512256

    -- ** Single-part message
    CryptoAuthHMACSHA512256State,
    withCryptoAuthHMACSHA512256State,
    cryptoAuthHMACSHA512256,
    cryptoAuthHMACSHA512256Verify,
    cryptoAuthHMACSHA512256Keygen,

    -- ** Multi-part messages
    cryptoAuthHMACSHA512256Init,
    cryptoAuthHMACSHA512256Update,
    cryptoAuthHMACSHA512256Final,

    -- ** Constants
    cryptoAuthHMACSHA512256StateBytes,
    cryptoAuthHMACSHA512256Bytes,
    cryptoAuthHMACSHA512256KeyBytes,
  )
where

import Foreign (Ptr, allocaBytes)
import Foreign.C (CInt (CInt), CSize (CSize), CUChar, CULLong (CULLong))

-- $introduction
--
-- The SHA-256 and SHA-512 functions are provided for interoperability with other applications. If you are
-- looking for a generic hash function and not specifically SHA-2, using
-- 'Cryptography.Sodium.Bindings.GenericHashing' (BLAKE2b) might be a better choice.
-- These functions are also not suitable for hashing passwords or deriving keys from passwords.
-- Use 'Cryptography.Sodium.Bindings.PasswordHashing' instead.
--
-- Only use these functions for interoperability with 3rd party services.
--
-- These functions are not keyed and are thus deterministic. In addition, the untruncated versions
-- are vulnerable to length extension attacks. A message can be hashed in a single pass, but a
-- streaming API is also available to process a message as a sequence of multiple chunks.

-------------
-- SHA-256 --
-------------

-- | Hash the content of the second buffer and put the result in the first buffer.
--
-- /See also:/ [crypto_hash_sha256()](https://doc.libsodium.org/advanced/sha-2_hash_function#sha-256)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_hash_sha256"
  cryptoHashSHA256 ::
    -- | A pointer to the hash of your data.
    Ptr CUChar ->
    -- | A pointer to the data you want to hash.
    Ptr CUChar ->
    -- | The length of the data you want to hash.
    CULLong ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | This is the opaque state held and used by the SHA-256 functions.
--
-- Its size is 'cryptoHashSHA256StateBytes'.
--
-- /See also:/ [crypto_hash_sha256_state](https://doc.libsodium.org/advanced/sha-2_hash_function#data-types)
--
-- @since 0.0.1.0
data CryptoHashSHA256State

-- | Perform an operation with a 'CryptoHashSHA256State' of size 'cryptoHashSHA256StateBytes'
-- allocated and deallocated automatically.
--
-- ⚠ The return value of 'withCryptoHashSHA256State' __MUST NOT__ leak the 'CryptoHashSHA256State'.
--
-- Please refer to the documentation of 'Foreign.allocaBytes' for more operational details.
--
-- @since 0.0.1.0
withCryptoHashSHA256State :: (Ptr CryptoHashSHA256State -> IO a) -> IO a
withCryptoHashSHA256State action = do
  let size :: Int = fromIntegral cryptoHashSHA256StateBytes
  allocaBytes size action

-- | This function initializes the 'CryptoHashSHA256State' state.
--
-- Call this function on a 'Ptr' 'CryptoHashSHA256State' before using it
-- as an argument in any other function in this module.
--
-- /See also:/ [crypto_hash_sha256_init()](https://doc.libsodium.org/advanced/sha-2_hash_function#sha-256)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_hash_sha256_init"
  cryptoHashSHA256Init ::
    -- | A pointer to an uninitialised hash state. Cannot be 'Foreign.nullPtr'.
    Ptr CryptoHashSHA256State ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | Add a new chunk to the message that will eventually be hashed.
--
-- After all parts have been supplied, 'cryptoHashSHA256Final' can be used to finalise the operation
-- and get the final hash.
--
-- /See also:/ [crypto_hash_sha256_update()](https://doc.libsodium.org/advanced/sha-2_hash_function#sha-256)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_hash_sha256_update"
  cryptoHashSHA256Update ::
    -- | A pointer to an initialised hash state. Cannot be 'Foreign.nullPtr'.
    Ptr CryptoHashSHA256State ->
    -- | A pointer to the new message chunk to process.
    Ptr CUChar ->
    -- | The length in bytes of the chunk.
    CULLong ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | Finalise the hashing of a message. The final hash is padded with extra zeros if necessary,
-- then put in a buffer.
--
-- After this operation, the buffer containing the 'CryptoHashSHA256State' is emptied and
-- cannot be relied upon.
--
-- /See also:/ [crypto_hash_sha256_final()](https://doc.libsodium.org/advanced/sha-2_hash_function#sha-256)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_hash_sha256_final"
  cryptoHashSHA256Final ::
    -- | A pointer to an initialised hash state. Cannot be 'Foreign.nullPtr'.
    Ptr CryptoHashSHA256State ->
    -- | The buffer in which the final hash is stored.
    Ptr CUChar ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-------------------
--  HMAC-SHA-256 --
-------------------

-- | Authenticate a message given its size and a secret key, and produce an authenticator to be
-- validated with 'cryptoAuthHMACSHA256Verify'.
--
-- /See also:/ [crypto_auth_hmacsha256()](https://doc.libsodium.org/advanced/hmac-sha2#hmac-sha-256).
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_auth_hmacsha256"
  cryptoAuthHMACSHA256 ::
    -- | A pointer to the buffer holding the authenticator.
    Ptr CUChar ->
    -- | A pointer to the message to be authenticated.
    Ptr CUChar ->
    -- | The length of the message to be authenticated.
    CULLong ->
    -- | A pointer to the secret key used for authentication, of length 'cryptoAuthHMACSHA256Bytes'.
    Ptr CUChar ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | Verify that an authenticator provided by 'cryptoAuthHMACSHA256' is correct.
--
-- /See also:/ [crypto_auth_hmacsha256_verify()](https://doc.libsodium.org/advanced/hmac-sha2#hmac-sha-256)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_auth_hmacsha256_verify"
  cryptoAuthHMACSHA256Verify ::
    -- | A pointer to buffer holding the authenticator.
    Ptr CUChar ->
    -- | A pointer to the message that is being authenticated.
    Ptr CUChar ->
    -- | The length of the message that is being authenticated.
    CULLong ->
    -- | A pointer to the secret key, of size 'cryptoAuthHMACSHA256KeyBytes'.
    Ptr CUChar ->
    -- | Returns 0 on success, -1 on failure.
    IO CInt

-- | Create a random key of the correct length.
--
-- /See also:/ [crypto_auth_hmacsha256_keygen()](https://doc.libsodium.org/advanced/hmac-sha2#hmac-sha-256)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_auth_hmacsha256_keygen"
  cryptoAuthHMACSHA256Keygen ::
    -- | A pointer to the buffer that will hold the secret key, of size 'cryptoAuthHMACSHA256KeyBytes'.
    Ptr CUChar ->
    -- | Nothing is returned
    IO ()

-- | This is the opaque state held and used by the HMAC-SHA-256 functions.
--
-- Its size is 'cryptoAuthHMACSHA256StateBytes' bytes.
--
-- Please refer to the documentation of 'Foreign.allocaBytes' for more operational details.
--
-- /See also:/ [crypto_auth_hmacsha256_state](https://doc.libsodium.org/advanced/hmac-sha2#data-types)
--
-- @since 0.0.1.0
data CryptoAuthHMACSHA256State

-- | Perform an operation with a 'CryptoAuthHMACSHA256State' of size 'cryptoAuthHMACSHA256StateBytes'
-- allocated and deallocated automatically.
--
-- ⚠ The return value of 'withCryptoAuthHMACSHA256State' __MUST NOT__ leak the 'CryptoAuthHMACSHA256State'.
--
-- Please refer to the documentation of 'Foreign.allocaBytes' for more operational details.
--
-- @since 0.0.1.0
withCryptoAuthHMACSHA256State :: (Ptr CryptoAuthHMACSHA256State -> IO a) -> IO a
withCryptoAuthHMACSHA256State action = do
  let size :: Int = fromIntegral cryptoAuthHMACSHA256StateBytes
  allocaBytes size action

-- | This function initializes the 'CryptoAuthHMACSHA256State' state.
--
-- Call this function on a 'Ptr' 'CryptoAuthHMACSHA256State' before using it
-- as an argument in any other function in this module.
--
-- /See also:/ [crypto_auth_hmacsha256_init()](https://doc.libsodium.org/advanced/hmac-sha2#hmac-sha-256)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_auth_hmacsha256_init"
  cryptoAuthHMACSHA256Init ::
    -- | A pointer to an uninitialised hash state. Cannot be 'Foreign.nullPtr'.
    Ptr CryptoAuthHMACSHA256State ->
    -- | A pointer to the secret key.
    Ptr CUChar ->
    -- | The size of the key.
    CSize ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | Add a new chunk to the message that will eventually be hashed.
--
-- After all parts have been supplied, 'cryptoAuthHMACSHA256Final' can be used to finalise the operation
-- and get the final hash.
--
-- /See also:/ [crypto_auth_hmacsha256_update()](https://doc.libsodium.org/advanced/hmac-sha2#hmac-sha-256)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_auth_hmacsha256_update"
  cryptoAuthHMACSHA256Update ::
    -- | A pointer to an initialised hash state. Cannot be 'Foreign.nullPtr'.
    Ptr CryptoAuthHMACSHA256State ->
    -- | A pointer to the message to authenticate.
    Ptr CUChar ->
    -- | The size of the message to authenticate.
    CULLong ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | Finalise the hashing of a message. The final hash is padded with extra zeros if necessary,
-- then put in a buffer.
--
-- After this operation, the buffer containing the 'CryptoAuthHMACSHA256State' is emptied and
-- cannot be relied upon.
--
-- /See also:/ [crypto_auth_hmacsha256_final()](https://doc.libsodium.org/advanced/hmac-sha2#hmac-sha-256)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_auth_hmacsha256_final"
  cryptoAuthHMACSHA256Final ::
    -- | A pointer to an initialised hash state. Cannot be 'Foreign.nullPtr'.
    Ptr CryptoAuthHMACSHA256State ->
    -- | A pointer to the buffer that will hold the authenticator.
    Ptr CUChar ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-------------
-- SHA-512 --
-------------

-- | Hash the content of the second buffer and put the result in the first buffer.
--
-- /See also:/ [crypto_hash_sha512()](https://doc.libsodium.org/advanced/sha-2_hash_function#sha-512)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_hash_sha512"
  cryptoHashSHA512 ::
    -- | A pointer to the hash of your data.
    Ptr CUChar ->
    -- | A pointer to the data you want to hash.
    Ptr CUChar ->
    -- | The length of the data you want to hash.
    CULLong ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | This is the opaque state held and used by the SHA-512 functions.
--
-- Its size is 'cryptoHashSHA512StateBytes'.
--
-- /See also:/ [crypto_hash_sha512_state](https://doc.libsodium.org/advanced/sha-2_hash_function#data-types)
--
-- @since 0.0.1.0
data CryptoHashSHA512State

-- | Perform an operation with a 'CryptoHashSHA512State of size 'cryptoHashSHA512StateBytes'
-- allocated and deallocated automatically.
--
-- ⚠ The return value of 'withCryptoHashSHA512State' __MUST NOT__ leak the 'CryptoHashSHA512State'.
--
-- Please refer to the documentation of 'Foreign.allocaBytes' for more operational details.
--
-- @since 0.0.1.0
withCryptoHashSHA512State :: (Ptr CryptoHashSHA512State -> IO a) -> IO a
withCryptoHashSHA512State action = do
  let size :: Int = fromIntegral cryptoHashSHA512StateBytes
  allocaBytes size action

-- | This function initializes the 'CryptoHashSHA512State' state.
--
-- Call this function on a 'Ptr CryptoHashSHA512State' before using it
-- as an argument in any other function in this module.
--
-- /See also:/ [crypto_hash_sha512_init()](https://doc.libsodium.org/advanced/sha-2_hash_function#sha-512)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_hash_sha512_init"
  cryptoHashSHA512Init ::
    -- | A pointer to an initialised hash state. Cannot be 'Foreign.nullPtr'.
    Ptr CryptoHashSHA512State ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | Add a new chunk to the message that will eventually be hashed.
--
-- After all parts have been supplied, 'cryptoHashSHA512Final' can be used to finalise the operation
-- and get the final hash.
--
-- /See also:/ [crypto_hash_sha512_update()](https://doc.libsodium.org/advanced/sha-2_hash_function#sha-512)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_hash_sha512_update"
  cryptoHashSHA512Update ::
    -- | A pointer to an initialised hash state. Cannot be 'Foreign.nullPtr'.
    Ptr CryptoHashSHA512State ->
    -- | A pointer to the new message chunk to process.
    Ptr CUChar ->
    -- | The length in bytes of the chunk.
    CULLong ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | Finalise the hashing of a message. The final hash is padded with extra zeros if necessary,
-- then put in a buffer.
--
-- After this operation, the buffer containing the 'CryptoHashSHA512State' is emptied and
-- cannot be relied upon.
--
-- /See also:/ [crypto_hash_sha512_final()](https://doc.libsodium.org/advanced/sha-2_hash_function#sha-512)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_hash_sha512_final"
  cryptoHashSHA512Final ::
    -- | A pointer to an initialised hash state. Cannot be 'Foreign.nullPtr'.
    Ptr CryptoHashSHA512State ->
    -- | The buffer in which the final hash is stored.
    Ptr CUChar ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-------------------
--  HMAC-SHA-512 --
-------------------

-- | Authenticate a message given its size and a secret key, and produce an authenticator to be
-- validated with 'cryptoAuthHMACSHA512Verify'.
--
-- /See also:/ [crypto_auth_hmacsha512()](https://doc.libsodium.org/advanced/hmac-sha2#hmac-sha-512).
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_auth_hmacsha512"
  cryptoAuthHMACSHA512 ::
    -- | A pointer to the buffer holding the authenticator.
    Ptr CUChar ->
    -- | A pointer to the message to be authenticated.
    Ptr CUChar ->
    -- | The length of the message to be authenticated.
    CULLong ->
    -- | A pointer to the secret key used for authentication, of length 'cryptoAuthHMACSHA512Bytes'.
    Ptr CUChar ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | Verify that an authenticator provided by 'cryptoAuthHMACSHA512' is correct.
--
-- /See also:/ [crypto_auth_hmacsha512_verify()](https://doc.libsodium.org/advanced/hmac-sha2#hmac-sha-512)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_auth_hmacsha512_verify"
  cryptoAuthHMACSHA512Verify ::
    -- | A pointer to buffer holding the authenticator.
    Ptr CUChar ->
    -- | A pointer to the message that is being authenticated.
    Ptr CUChar ->
    -- | The length of the message that is being authenticated.
    CULLong ->
    -- | A pointer to the secret key, of size 'cryptoAuthHMACSHA512KeyBytes'.
    Ptr CUChar ->
    -- | Returns 0 on success, -1 on failure.
    IO CInt

-- | Create a random key of the correct length.
--
-- /See also:/ [crypto_auth_hmacsha512_keygen()](https://doc.libsodium.org/advanced/hmac-sha2#hmac-sha-512)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_auth_hmacsha512_keygen"
  cryptoAuthHMACSHA512Keygen ::
    -- | A pointer to the buffer that will hold the secret key, of size 'cryptoAuthHMACSHA512KeyBytes'.
    Ptr CUChar ->
    -- | Nothing is returned
    IO ()

-- | This is the opaque state held and used by the HMAC-SHA-512 functions.
--
-- Its size is 'cryptoAuthHMACSHA512StateBytes' bytes.
--
-- Please refer to the documentation of 'Foreign.allocaBytes' for more operational details.
--
-- /See also:/ [crypto_auth_hmacsha512_state](https://doc.libsodium.org/advanced/hmac-sha2#data-types)
--
-- @since 0.0.1.0
data CryptoAuthHMACSHA512State

-- | Perform an operation with a 'CryptoAuthHMACSHA512State' of size 'cryptoAuthHMACSHA512StateBytes'
-- allocated and deallocated automatically.
--
-- ⚠ The return value of 'withCryptoAuthHMACSHA512State' __MUST NOT__ leak the 'CryptoAuthHMACSHA512State'.
--
-- Please refer to the documentation of 'Foreign.allocaBytes' for more operational details.
--
-- @since 0.0.1.0
withCryptoAuthHMACSHA512State :: (Ptr CryptoAuthHMACSHA512State -> IO a) -> IO a
withCryptoAuthHMACSHA512State action = do
  let size :: Int = fromIntegral cryptoAuthHMACSHA512StateBytes
  allocaBytes size action

-- | This function initializes the 'CryptoAuthHMACSHA512State' state.
--
-- Call this function on a 'Ptr CryptoAuthHMACSHA512State' before using it
-- as an argument in any other function in this module.
--
-- /See also:/ [crypto_auth_hmacsha512_init()](https://doc.libsodium.org/advanced/hmac-sha2#hmac-sha-512)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_auth_hmacsha512_init"
  cryptoAuthHMACSHA512Init ::
    -- | A pointer to an uninitialised hash state. Cannot be 'Foreign.nullPtr'.
    Ptr CryptoAuthHMACSHA512State ->
    -- | A pointer to the secret key.
    Ptr CUChar ->
    -- | The size of the key.
    CSize ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | Add a new chunk to the message that will eventually be hashed.
--
-- After all parts have been supplied, 'cryptoAuthHMACSHA512Final' can be used
-- to finalise the operation and get the final hash.
--
-- /See also:/ [crypto_auth_hmacsha512_update()](https://doc.libsodium.org/advanced/hmac-sha2#hmac-sha-512)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_auth_hmacsha512_update"
  cryptoAuthHMACSHA512Update ::
    -- | A pointer to an initialised hash state. Cannot be 'Foreign.nullPtr'.
    Ptr CryptoAuthHMACSHA512State ->
    -- | A pointer to the message to authenticate.
    Ptr CUChar ->
    -- | The size of the message to authenticate.
    CULLong ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | Finalise the hashing of a message. The final hash is padded with extra zeros if necessary,
-- then put in a buffer.
--
-- After this operation, the buffer containing the 'CryptoAuthHMACSHA512State' is emptied and
-- cannot be relied upon.
--
-- /See also:/ [crypto_auth_hmacsha512_final()](https://doc.libsodium.org/advanced/hmac-sha2#hmac-sha-512)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_auth_hmacsha512_final"
  cryptoAuthHMACSHA512Final ::
    -- | A pointer to an initialised hash state. Cannot be 'Foreign.nullPtr'.
    Ptr CryptoAuthHMACSHA512State ->
    -- | A pointer to the buffer that will hold the authenticator.
    Ptr CUChar ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-----------------------
--  HMAC-SHA-512-256 --
-----------------------

-- $hmacsha512256
-- HMAC-SHA-512-256 is implemented as HMAC-SHA-512 with the output truncated to 256 bits.
-- This is slightly faster than HMAC-SHA-256.
-- Note that this construction is not the same as HMAC-SHA-512\/256, which is HMAC using the SHA-512\/256 function.

-- | Authenticate a message given its size and a secret key, and produce an authenticator to be
-- validated with 'cryptoAuthHMACSHA512256Verify'.
--
-- /See also:/ [crypto_auth_hmacsha512256()](https://doc.libsodium.org/advanced/hmac-sha2#hmac-sha-512256-256).
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_auth_hmacsha512256"
  cryptoAuthHMACSHA512256 ::
    -- | A pointer to the buffer holding the authenticator.
    Ptr CUChar ->
    -- | A pointer to the message to be authenticated.
    Ptr CUChar ->
    -- | The length of the message to be authenticated.
    CULLong ->
    -- | A pointer to the secret key used for authentication, of length 'cryptoAuthHMACSHA512256Bytes'.
    Ptr CUChar ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | Verify that an authenticator provided by 'cryptoAuthHMACSHA512256' is correct.
--
-- /See also:/ [crypto_auth_hmacsha512256_verify()](https://doc.libsodium.org/advanced/hmac-sha2#hmac-sha-512256-256)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_auth_hmacsha512256_verify"
  cryptoAuthHMACSHA512256Verify ::
    -- | A pointer to buffer holding the authenticator.
    Ptr CUChar ->
    -- | A pointer to the message that is being authenticated.
    Ptr CUChar ->
    -- | The length of the message that is being authenticated.
    CULLong ->
    -- | A pointer to the secret key, of size 'cryptoAuthHMACSHA512256KeyBytes'.
    Ptr CUChar ->
    -- | Returns 0 on success, -1 on failure.
    IO CInt

-- | Create a random key of the correct length.
--
-- /See also:/ [crypto_auth_hmacsha512256_keygen()](https://doc.libsodium.org/advanced/hmac-sha2#hmac-sha-512256-256)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_auth_hmacsha512256_keygen"
  cryptoAuthHMACSHA512256Keygen ::
    -- | A pointer to the buffer that will hold the secret key,
    -- of size 'cryptoAuthHMACSHA512256KeyBytes'.
    Ptr CUChar ->
    -- | Nothing is returned
    IO ()

-- | This is the opaque state held and used by the HMAC-SHA-512256 functions.
--
-- Its size is 'cryptoAuthHMACSHA512256StateBytes' bytes.
--
-- Please refer to the documentation of 'Foreign.allocaBytes' for more operational details.
--
-- /See also:/ [crypto_auth_hmacsha512256_state](https://doc.libsodium.org/advanced/hmac-sha2#data-types)
--
-- @since 0.0.1.0
data CryptoAuthHMACSHA512256State

-- | Perform an operation with a 'CryptoAuthHMACSHA512256State'
-- of size 'cryptoAuthHMACSHA512256StateBytes' allocated and deallocated automatically.
--
-- ⚠ The return value of 'withCryptoAuthHMACSHA512256State' __MUST NOT__ leak
-- the 'CryptoAuthHMACSHA512256State'.
--
-- Please refer to the documentation of 'Foreign.allocaBytes' for more operational details.
--
-- @since 0.0.1.0
withCryptoAuthHMACSHA512256State :: (Ptr CryptoAuthHMACSHA512256State -> IO a) -> IO a
withCryptoAuthHMACSHA512256State action = do
  let size :: Int = fromIntegral cryptoAuthHMACSHA512256StateBytes
  allocaBytes size action

-- | This function initializes the 'CryptoAuthHMACSHA512256State' state.
--
-- Call this function on a 'Ptr' 'CryptoAuthHMACSHA512256State' before using it
-- as an argument in any other function in this module.
--
-- /See also:/ [crypto_auth_hmacsha512256_init()](https://doc.libsodium.org/advanced/hmac-sha2#hmac-sha-512256-256)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_auth_hmacsha512256_init"
  cryptoAuthHMACSHA512256Init ::
    -- | A pointer to an uninitialised hash state. Cannot be 'Foreign.nullPtr'.
    Ptr CryptoAuthHMACSHA512256State ->
    -- | A pointer to the secret key.
    Ptr CUChar ->
    -- | The size of the key.
    CSize ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | Add a new chunk to the message that will eventually be hashed.
--
-- After all parts have been supplied, 'cryptoAuthHMACSHA512256Final' can be
-- used to finalise the operation and get the final hash.
--
-- /See also:/ [crypto_auth_hmacsha512256_update()](https://doc.libsodium.org/advanced/hmac-sha2#hmac-sha-512256-256)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_auth_hmacsha512256_update"
  cryptoAuthHMACSHA512256Update ::
    -- | A pointer to an initialised hash state. Cannot be 'Foreign.nullPtr'.
    Ptr CryptoAuthHMACSHA512256State ->
    -- | A pointer to the message to authenticate.
    Ptr CUChar ->
    -- | The size of the message to authenticate.
    CULLong ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

-- | Finalise the hashing of a message. The final hash is padded with extra zeros if necessary,
-- then put in a buffer.
--
-- After this operation, the buffer containing the 'CryptoAuthHMACSHA512256State' is emptied and
-- cannot be relied upon.
--
-- /See also:/ [crypto_auth_hmacsha512256_final()](https://doc.libsodium.org/advanced/hmac-sha2#hmac-sha-512256-256)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_auth_hmacsha512256_final"
  cryptoAuthHMACSHA512256Final ::
    -- | A pointer to an initialised hash state. Cannot be 'Foreign.nullPtr'.
    Ptr CryptoAuthHMACSHA512256State ->
    -- | A pointer to the buffer that will hold the authenticator.
    Ptr CUChar ->
    -- | Returns 0 on success, -1 on error.
    IO CInt

---------------
-- Constants --
---------------

-- | The size of a SHA256-hashed message.
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_hash_sha256_BYTES"
  cryptoHashSHA256Bytes :: CSize

-- | The size of a 'CryptoHashSHA256State'.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_hash_sha256_statebytes"
  cryptoHashSHA256StateBytes :: CSize

-- | This constant represents the size of a pre-hashed message.
-- It is in use in the @ED25519ph@ multi-part signing system.
--
-- For more information, please consult the documentation of
-- "Cryptography.Sodium.Bindings.Signing".
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_hash_sha512_BYTES"
  cryptoHashSHA512Bytes :: CSize

-- | The size of a 'CryptoHashSHA512State'.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_hash_sha512_statebytes"
  cryptoHashSHA512StateBytes :: CSize

-- | The size of a 'CryptoAuthHMACSHA256State'.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_auth_hmacsha256_statebytes"
  cryptoAuthHMACSHA256StateBytes :: CSize

-- | @since 0.0.1.0
foreign import capi "sodium.h value crypto_auth_hmacsha256_BYTES"
  cryptoAuthHMACSHA256Bytes :: CSize

-- | @since 0.0.1.0
foreign import capi "sodium.h value crypto_auth_hmacsha256_KEYBYTES"
  cryptoAuthHMACSHA256KeyBytes :: CSize

-- | @since 0.0.1.0
foreign import capi "sodium.h value crypto_auth_hmacsha512_BYTES"
  cryptoAuthHMACSHA512Bytes :: CSize

-- | @since 0.0.1.0
foreign import capi "sodium.h value crypto_auth_hmacsha512_KEYBYTES"
  cryptoAuthHMACSHA512KeyBytes :: CSize

-- | The size of a 'CryptoAuthHMACSHA512State'.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_auth_hmacsha512_statebytes"
  cryptoAuthHMACSHA512StateBytes :: CSize

-- | @since 0.0.1.0
foreign import capi "sodium.h value crypto_auth_hmacsha512256_BYTES"
  cryptoAuthHMACSHA512256Bytes :: CSize

-- | @since 0.0.1.0
foreign import capi "sodium.h value crypto_auth_hmacsha512256_KEYBYTES"
  cryptoAuthHMACSHA512256KeyBytes :: CSize

-- | The size of a 'CryptoAuthHMACSHA512256State'.
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_auth_hmacsha512256_statebytes"
  cryptoAuthHMACSHA512256StateBytes :: CSize
