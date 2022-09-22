# Targets of CLFuzz

CLFuzz is adapted to 54 target cryptographic algorithms for fuzzing. 

We divide all the target algorithms into four categories and demonstrate the grouped results.

## Hash and Symmetric Function

**Hash function** is a one-way function that maps data of an arbitrary size to a bit array of a fixed size. **Symmetric function** uses the same keys for both the encryption of plaintext and the decryption of ciphertext.

This category contains the following algorithms: 

```
Digest, HMAC, CMAC, SymmetricEncrypt, SymmetricDecrypt
```

## Elliptic Curve Algorithm

**Elliptic curve cryptography** is a public-key cryptography technique based on the algebraic structure of elliptic curves over finite fields. This category contains: 

```
ECC_PrivateToPublic, ECC_ValidatePubkey, ECDH_Derive, 
ECDSA_Sign, ECGDSA_Sign, ECRDSA_Sign, Schnorr_Sign, 
ECDSA_Verify, ECGDSA_Verify, ECRDSA_Verify, Schnorr_Verify,
ECDSA_Recover, ECC_GenerateKeyPair, ECIES_Encrypt, 
ECIES_Decrypt, ECC_Point_Add, ECC_Point_Mul
```

## BLS Signatures

**BLS signature** is a cryptographic signature scheme that uses bilinear pairing as well as elliptic curve. This category includes:

```
BLS_PrivateToPublic, BLS_PrivateToPublic_G2, BLS_Sign, 
BLS_Verify, BLS_IsG1OnCurve, BLS_IsG2OnCurve,
BLS_GenerateKeyPair, BLS_Decompress_G1, BLS_Compress_G1, 
BLS_Decompress_G2, BLS_Compress_G2, BLS_HashToG1, BLS_HashToG2, 
BLS_Pairing, BLS_G1_Add, BLS_G1_Mul, BLS_G1_IsEq, BLS_G1_Neg,
BLS_G2_Add, BLS_G2_Mul, BLS_G2_IsEq, BLS_G2_Neg
```

## Key Derivation Function

**Key derivation function** derives keys from a secret value using pseudorandom function. This category contains: 

```
KDF_SCRYPT, KDF_HKDF, KDF_TLS1_PRF, KDF_PBKDF, KDF_PBKDF1,
KDF_PBKDF2, KDF_ARGON2, KDF_SSH, KDF_X963, KDF_SP_800_108
```