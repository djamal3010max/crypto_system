# Smart-Card Cryptographic Subsystem (Verilog)

## Block mapping

| Diagram block | File / module |
|---|---|
| Controller (FSM) | rtl/controller_fsm.v |
| HASH | rtl/hash_core.v (single-shot SHA-256, command 02); rtl/hash_engine.v streaming engine (commands 07-09) over rtl/sha256_core.v, sha1_core.v, sha512_core.v, keccak_core.v |
| AES | rtl/aes128_core.v (AES-128 encrypt and decrypt; ECB and CBC in `crypto_accel`) |
| ECC Engine: ECDSA / ECDH | rtl/ecc_engine.v (ecdsa_unit, ecdh_unit) |
| BA-RADIX 2^w recoding (Algorithm 1) | rtl/ba_recoder.v |
| Scalar multiplication (BA-Radix-2^w evaluation = Algorithm 2, and Montgomery ladder) + GF(p)/mod-n arithmetic | rtl/ecc_core.v, rtl/modmul_serial.v, rtl/ecc_ucode.v (generated) |
| Key management unit (key store, certification mgmt) | rtl/key_mgmt_unit.v |
| TRNG (ring osc, thermal noise, sampler, health monitor with Repetition Count + Adaptive Proportion tests, von Neumann corrector, SHA-256 conditioner, output buffer) | rtl/trng.v |
| Top level (+ reset synchronizer) | rtl/sc_crypto_top.v |

`model/ecc_arith_ref.v` is the old behavioral golden model (simulation only, not for synthesis).

## ECC core design choices
* NIST P-256, complete projective formulas (a = -3): no special cases, no data-dependent branches in the point arithmetic.
* Two scalar-multiplication methods in `ecc_core`:
  * **op 0, Montgomery ladder**: one add + one double per key bit, conditional swaps, identical cycle count for every
    scalar (about 1.91M cycles). Used for secret scalars (ECDSA sign, ECDH).
  * **op 6, BA-Radix-2^w** (your paper): `ba_recoder` implements Algorithm 1 (serial, one zero-skip or one slice per
    clock, slices stored LSB-first); `ecc_core` implements Algorithm 2 evaluating slices from the top. Table = P plus
    3P..(2^(w-1)-1)P in projective form, built with one DBL (2P) and 2^(w-2)-1 ADDs. Negative slices negate Y.
    About 1.15M cycles for a 256-bit scalar at w = 4, 5 or 6 (about 40% fewer than the ladder).
* `ecc_engine` parameter `BA_W` (default 4, >= 3) selects the window. ECDSA verify always uses BA (public scalars).
  Sign/ECDH use the ladder unless `BA_SECRET = 1`.
* **BA is not constant time.** The number of additions and the doubling gaps between them are the recoded slice
  positions, i.e. they directly expose the zero-run structure of the scalar to timing/SPA/power analysis. Your paper's
  side-channel section is still "on going", so BA is used only where the scalar is public.
* Evaluation differs slightly from the Algorithm 2 pseudocode: the loop starts at the highest slice position instead
  of `pos_max + w - 1`, skipping the `w - 1` leading doublings of the point at infinity. The result is identical.
* The datapath implements a prime curve (P-256), where -P = (x, -y). The paper's experiments use NIST binary curves
  (B-163..B-409); those would need a GF(2^m) datapath, which is not included.
* One bit-serial modular multiplier (256 cycles/mult); inversion by Fermat (p-2 / n-2) on the same multiplier.

## Verification status
* `tb/tb_top.v`: full-system regression, 13/13 checks pass (SHA-256, AES-128 FIPS vector, TRNG, key store/secret-slot
  protection, certificates, ECDH vs Python, ECDSA sign/verify/reject). About 6-7 minutes in Icarus.
* `tb/tb_ba_recoder.v`: recoder reproduces both worked examples of the paper (k = 4196366: slices (1,+,7),(11,+,1),(22,+,1);
  k = 4196378: (1,-,3),(5,+,1),(11,+,1),(22,+,1)) and k = 0.
* `tb/tb_ecc_core.v` (`-DBAW=<w>`): ECC core against Python vectors, ladder and BA op (w = 4, 5, 6 pass) (MODN/ADDN/MULN/INVN, point add incl. doubling and infinity,
  0*G, 2*G, full 256-bit k*G). Passes. One scalar multiplication = 1,906,190 cycles.
* Yosys (generic, no PDK), whole design with every block described above (streaming hash engine, AES decrypt, composite
  commands, Secure Load with anti-replay counters, KEYGEN, certificate parsing, health tests, von Neumann corrector),
  hierarchical, `BA_W = 4`: about 297.3k generic cells (297,304; log: `synth/yosys.log`, run after the length-counter fix and lint cleanup). Earlier per-block figures: `hash_engine` 51k,
  `keccak_core` 13.7k, `sha512_core` 14.5k, `sha1_core` 4.3k, `aes128_core` 19.9k, `ecc_core` about 87k. Flip-flop total was
  not re-extracted. No PDK numbers, no timing. A flat run was not retried (a flat run of the earlier, smaller design needed
  about 4 GB). The BA version first ran out of memory in Yosys because of variable part-selects on the wide register/table
  vectors; they were replaced by explicit mux/demux loops (simulation behaviour and cycle counts unchanged).

## Lint

`sh lint/verilator_lint.sh` (Verilator 5). The last run had no errors that affect function except one real bug, now fixed: the
certificate-body length counter in `controller_fsm.v` wrapped at 256 bytes instead of saturating (a 321-byte message looked like a
65-byte body); `tb_op7` now has a regression test for it that fails on the old code. Remaining findings are intentional or cosmetic
(see the header of the script). One item deserves a decision before tape-out: `rst_n` is an asynchronous reset in most modules and a
synchronous reset in `ecc_core`, `ecc_engine`, `modmul_serial` and `ba_recoder` (Verilator SYNCASYNCNET); both are driven from
`reset_sync` so it is functionally consistent, but DFT and the foundry reset-recovery checks should be reviewed.

## Operation testbenches (tb/ops/)

One testbench per operation of `Global_Architecture5` section 7. Vectors come from `tools/gen_vectors.py`
(pycryptodome for AES/SHA, `tools/p256.py` for ECDSA/ECDH). Run: `sh run_ops.sh` (full, about 35 min on one core) or
`QUICK=1 sh run_ops.sh` (about 15 min). Output lines are `PASS`, `FAIL` or `GAP`; a **GAP** is a spec feature the RTL does not
implement, reported but never counted as pass or fail. ECDSA signatures and ECDH results produced by the simulation are
re-checked afterwards by independent Python code (`tools/check_vectors.py`).

| # | Operation | Testbench | Exercised in RTL | Spec gaps reported |
|---|---|---|---|---|
| 1 | AES encrypt/decrypt (ECB, CBC) | tb_op1_aes.v | ECB encrypt+decrypt, native CBC encrypt+decrypt (FIPS-197, SP 800-38A F.1/F.2), round trips, key-slot rules; key wrapping is exercised by SECURE_LOAD (op 6) | - (AES-192/256 and CTR/GCM are not in the spec and not implemented) |
| 2 | HASH | tb_op2_hash.v | single-shot SHA-256 (5 vectors); streaming SHA-1 (legacy), SHA-224/256/384/512, SHA3-224/256/384/512: 9 algorithms x 6 lengths x 2 chunk sizes vs hashlib; interleaving, error cases | certificate management does not call the hash engine itself |
| 3 | ECDSA sign | tb_op3_ecdsa_sign.v | sign, nonce freshness, ranges, round trip, hash-then-sign (SHA-256/384/224) with Python re-verify | - |
| 4 | ECDSA verify | tb_op4_ecdsa_verify.v | Python known answer, tampered digest/r/s, r=0, s=0, r=n, wrong key, off-curve public key, hash-then-verify (SHA-256/384/224, tampered message) | - |
| 5 | ECDH | tb_op5_ecdh.v | both directions vs Python, k*G, TRNG scalar, infinity peer, off-curve peer, ECDH + one-step KDF (both parties), KEYGEN (full public key, secret slot, locked/out-of-range slot, two generated pairs agree) | - |
| 6 | Secure Load | tb_op6_secure_load.v | key-store semantics; atomic SECURE_LOAD: authentic package installed and usable, tampered / re-aimed / locked-slot packages refused, bad arguments; anti-replay: replay and older-version (downgrade) rejected, newer version rotates the key | counters are volatile flops (need NVM) |
| 7 | Certificate parse/verify | tb_op7_certificate.v | cert store; CERT_VERIFY (hash, verify, record digest only on success); SCC-1 parse + subject-key install and chain-of-trust check; malformed / wrong-version / odd-slot / off-curve-key / tampered certificates refused; argument errors | no X.509 (ASN.1) parser |
| 8 | Raw random bytes | tb_op8_random.v | distinctness, monobit sanity; Repetition Count Test and Adaptive Proportion Test each block output (sticky, cleared by input); von Neumann corrector: known pairs, bias removal on a 70%-ones stream, rate <= 1/4 | cutoffs assume H = 0.5; real source entropy not measured |

Finding while writing these: `tb_op7` showed that `CERT_WRITE/READ` with an entry index of 4 or more silently aliased onto entries 0..3;
the controller now rejects indexes >= 4.

## Composite commands that use the hash engine internally

| Command | Behaviour |
|---|---|
| 13 SIGN_LAST | `HASH_INIT` / `HASH_UPDATE` / `HASH_FINAL` first; SIGN_LAST then signs the latched digest (the digest never goes back to the host through this command) |
| 14 VERIFY_LAST | same, verifies `{r,s}` in `cpu_b` against the latched digest with the public key pair in slots `slot`, `slot^1` |
| 18 KEYGEN | TRNG scalar d (1 <= d < n by rejection sampling) -> key store as a **secret** slot (the secret attribute is forced on) -> returns the public key {x,y} = d*G. d never leaves the chip. Implements the spec's "ephemeral key + public key to the peer" flow. |
| 16 SECURE_LOAD | atomic key injection/rotation: hash the package (wrapped key, destination slot, attributes, KEK slot, issuer slot), ECDSA-verify it with the issuer key, AES-unwrap with the KEK, write the key; written only if the signature verifies, plaintext never visible to the CPU. Package version `a[39:8]` (signed, 24-byte message) must be greater than the version last installed in the destination slot (per-slot 32-bit counter in the key management unit, bus range 0x20-0x27, reachable only by this command); rejected packages return `ok = 0` before any cryptography runs, and the counter is updated only after the key write succeeds. Uses the hash engine, so it aborts any open streaming session. The counters are volatile flip-flops here and must be NVM in silicon. |
| 17 CERT_VERIFY | verifies the digest latched by the last `HASH_FINAL` with the issuer key and, only on success, records it in a certificate entry (so entries filled this way hold verified digests; `CERT_WRITE` is still a raw provisioning write). With `attr[0] = 1` it also **parses** the certificate body, validates the subject key on the curve and installs it as a public-key pair in slots `a[5:2]`, `a[5:2]+1` (even, < 8), then records the digest in entry `a[1:0]`. Order: signature, on-curve check, key install, record. Nothing is written if any step before the install fails. |

**SCC-1 certificate body** (the format parsed by `CERT_VERIFY` with install): 65 bytes = version byte `0x01`, subject public key `x` (32 bytes), `y` (32 bytes), all big-endian; signed with ECDSA/SHA-256 by the issuer. The controller captures the first 72 bytes of the last hashed message to parse it; a body of any other length or version is rejected with an error. This is a deliberately minimal format, not X.509. A locked destination slot makes the install fail with an error after the earlier steps, so the digest is not recorded but a partial install (x written, y refused) is possible if only the odd slot is locked.
| 15 ECDH_KDF | ECDH, then SHA-256(00000001 \|\| Z \|\| FixedInfo) (SP 800-56C one-step KDF, FixedInfo up to 28 bytes); only the derived key is returned |

ECDSA digest rule (FIPS 186-4): leftmost 256 bits of the digest, or the digest as an integer if it is shorter than 256 bits.
A new `HASH_INIT` invalidates the latched digest. Not done: a certificate parser, and a one-command "hash this buffer and sign it" (the message is streamed with the hash commands first).

## Flow
* Simulate: `./run_sim.sh all` or `./run_sim.sh core` (Icarus Verilog, `-DSIM`). Takes several minutes; pipe through `stdbuf -oL` to see progress.
* ECC core only (about 3 minutes): `iverilog -g2005 -o ecc.out rtl/modmul_serial.v rtl/ecc_ucode.v rtl/ba_recoder.v rtl/ecc_core.v tb/tb_ecc_core.v && vvp ecc.out`
* Synthesis sanity check (generic, no PDK): `yosys -q -l synth/yosys.log synth/yosys_synth.ys`
* Timing template: `constraints/sc_crypto_top.sdc`

## What this repository is NOT (needed before a foundry will take it)
1. **TRNG entropy source is analog.** Build the ring oscillators as a hard macro / dont_touch cells
   (define `USE_TECH_RO` and provide `tech_ro`). The generic inverter-chain fallback is optimised away or
   flagged as a timing loop by synthesis tools. The thermal-noise source and comparator are analog IP.
   Run an SP 800-90B entropy assessment on silicon data; the health tests (Repetition Count and Adaptive Proportion, cutoffs for an assumed H = 0.5 bit/sample) only catch gross failures.
2. **Key store is flip-flops.** Real parts need NVM/OTP macros, tamper detection, zeroization.
3. **No side-channel countermeasures** beyond the regular ladder: no masking/blinding of ECC or AES, table-based AES S-boxes (forward and inverse).
4. **No DFT.** Scan insertion, MBIST for macros and ATPG are done in the physical flow, not in this RTL.
5. Public keys (ECDH peer, ECDSA verify signer) are validated on-curve by `ecc_engine` via the core's ONCURVE op; P-256 has cofactor 1 so no subgroup check is needed. Not done: key-pair consistency checks and fault-injection hardening of the check itself.
6. No fault-injection countermeasures, no CC/FIPS/EMVCo evaluation.
7. Physical implementation, PDK-specific constraints, CDC/lint/UPF/LEC/STA signoff and gate-level simulation are not done.
