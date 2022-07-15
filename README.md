
# Negacyclic LUT – Concrete DEMO

The objective of this DEMO is to put forward an example of

  * **discrete-valued** messages using the **entire available cleartext space** (i.e., with wrapping, with no padding nor carry bits), together with
  * custom **negacyclic LUT evaluation** (i.e., programmable bootstrapping of TFHE, which *does* use the negacyclic extension),

using Concrete v0.2.x. A fork/branch of Concrete v0.1.11 implements this behavior [here](https://github.com/fakub/concrete/blob/negacyclic/concrete/src/lwe/mod.rs) (functions with `uint` in their name, PBS is called externally).


## Desired Steps

### Parameter Setup (optional)

Choose TFHE parameters, so that

  * the ciphertext can accomodate *n* bits, and
  * *l* independent fresh(ly bootstrapped) samples can be homomorphically added, before the result needs to be bootstrapped (based on error variance).

### Key Generation

For selected parameters, generate appropriate keys (load from file if they already exist).

### Encryption

Encrypt an *n*-bit message (without any additional bits).
E.g., *n* = 3 and encrypt *m* = 6 = `0b110` into *c*.

### Homomorphic Addition

Take *l* samples and add them homomorphically.
Or take a sample and multiply it by a known integer *k*, provided that *k*^2 ≤ *l* (to satisfy the error variance bound).
Since no padding is present, messages aggregate mod 2^n.

### Programmable Bootstrapping

Provide a LUT of size 2^*n* / 2 and evaluate it homomorphically.
If the MSB of the message is 1, a negacyclic extension of the LUT *L* is evaluated implicitly.
E.g., let *L* = [0,2,5,7], with negacyclic extension *L'* = [0,2,5,7,0,6,3,1], then PBS_*L*(*c*) shall encrypt *L'*[6] = -*L*[2] = 3.

### Decryption & Comparison

A usual step...


## Thoughts, Questions, ...

 1. Call methods of `concrete-shortint`, or `concrete-core`?
    * If `concrete-core` (seemingly makes more sense due to more stable API & internal representation), all methods need to be called one-by-one?
    * If `concrete-shortint`, there seems to be, e.g., a function `ShortintEngine::new_client_key(...)`, which calls specific functions from `concrete-core`, but it is not externally accessible (protected).
 2. Other questions to arise...