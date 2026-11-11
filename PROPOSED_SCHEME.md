# The proposed scheme: specification, evaluation plan, and expectations written BEFORE measuring

This folder = the frozen Banerjee-style baseline (`../goose-banerjee`, results in `BASELINE_RESULTS.md`) **plus** `GOOSE_SCHEME=proposed`. Same apps (`gs_pub`, `gs_sub`, `gs_inject`), same timing boundaries, same datasets, same scripts. Only the security layer differs.

## 1. What the proposed scheme does

| | baseline (assumed from the paper) | proposed |
|---|---|---|
| nonce | BER(stNum) BER(sqNum) timestamp, zero padded (variable length, collides: (1,512) vs (258,0)) | stNum(32) sqNum(32) t(64), fixed width, injective, built from fields already in every frame |
| encrypted | the whole PDU value | only the allData value |
| authenticated (AAD) | EtherType, AppID, Length, Res1, Res2, Authentication Value | the same + every PDU byte before allData (goCbRef, TAL, datSet, goID, t, stNum, sqNum, simulation, confRev, ndsCom, numEntries) |
| what an observer sees | nothing of the PDU | PDU header fields in the clear (readable, but any change is detected) |
| subscriber order | decrypt everything, then parse | read stNum/sqNum/t from the clear, window **pre-check (read only)**, decrypt allData, window **commit after the tag verifies**, parse |
| replay protection | none beyond the stock flag | RFC 6479 window: older state rejected, 64-slot window inside a state |
| extension / frame | 55-59 B extension (IV field carries the nonce), 261 B frame | **identical layout and size** (the IV field is redundant for the proposed nonce but is kept so the frames are byte-for-byte comparable in size) |

Why the pre-check is read only: if the window moved before authentication, an attacker could send a forged frame with a fresh-looking sqNum (a frame that will fail the tag) and push the window ahead so that legitimate frames fall outside it. Unit test `test_window` covers this and the `tamper` security test checks it on the wire.

## 2. Fairness rules (what makes the comparison meaningful)
* One library, one publisher, one subscriber; the scheme is a run-time switch. Identical dataset, names, frame size, receiver thread, CPU pinning, governor, clocks.
* T_gen = publish() call; T_proc = after select() returns until the callback returns (or the reject point); T_tx calculated from frame size; T_E2E = sum of three means. Same definitions for all three schemes.
* Shuffled order, 5 runs per scheme, paired differences, 95% CI over run means.
* Report the baseline as "built after the description in [3]": the nonce and the replay handling are assumptions.

## 3. Expectations, written down before the first proposed measurement
These are predictions to be checked, not results.

**Cipher cost model** from the baseline benchmark (Ascon-AEAD128 `ref`, -O2, Pi 4B): about 0.70 us fixed (init and finalisation) plus about 7.3 ns per absorbed byte. Absorbed bytes (AAD + data): baseline about 173 + 47 = 220 B, proposed about 16 + 197 = 213 B. So the two schemes absorb nearly the same number of bytes and the AEAD call should cost about the same (about 2.2 us, difference within 0.1 us).

| quantity | expectation | would count as a surprise |
|---|---|---|
| frame size | 261 B (first frames), 262 B later, identical to the baseline | any difference |
| T_gen (publisher) | within about +-1 us of the baseline | more than 2 us different |
| T_proc, accepted frames | **about equal** to the baseline (within about +-1 us). The proposed path adds a PDU walk (about 0.3-0.5 us) and saves some copying | a large reduction. Earlier claims of a 49-76% processing-time reduction came from unmatched baselines; in a matched harness I do not expect them to reproduce |
| T_E2E | equal within about 1-2 us | |
| replayed old-state frames | **0 accepted** (baseline: 177-185 of 200) | any accepted |
| forged frames | 200 of 200 rejected (tag) | any accepted |
| tampered sqNum (fresh-looking, fails the tag) | rejected, and **no legitimate frame lost** (window not moved) | legitimate frames dropped |
| cost of a rejected replay | clearly lower than the baseline's 5.2 us (no decryption, no PDU parse): roughly 1.5-3 us | not lower |
| cost of a rejected forgery | lower or equal to the baseline's 4.6 us (the AEAD must still absorb the AAD) | |
| flood of one replayed frame at about 38,000 frames/s | 0 injected frames delivered; receiver CPU well below the baseline's roughly 20% of a core | |

Reading of the model: the scheme's benefits are structural security properties (a collision-free nonce, header fields authenticated, replay and tamper rejection before any decryption), **not** a faster accept path. If the measurements agree, the paper should say exactly that.

## 4. Known limitations (state them in the paper)
* The window state is held per receiver, not per publisher. Several publishers need one window each (keyed by goCbRef/AppID).
* A publisher restart resets stNum to 1; the window then rejects the restarted publisher until its stNum passes the old value (state must be persisted or the window reset by an authenticated management action).
* The fixed key (FIPS 197 test key) means any subscriber that holds it can forge frames; key management (IEC 62351-9) is out of scope.
* The 20-byte IV field is redundant under the proposed nonce; removing it would save 20 B per frame (about 1.6 us of T_tx) but changes the frame size relative to the baseline.
* Only the allData value is confidential; goCbRef, stNum, sqNum, timestamp are readable by design.
* Window pre-check happens before authentication, so an attacker can still force one tag verification per fresh-looking forged frame (cost about 2-4 us), but cannot advance the window.

## 5. Evaluation plan
1. Unit tests (PC) and `build.sh` (nonce demo with the real cipher).
2. Frame size check, then round-trip check for `proposed` (`rej_auth=0`).
3. `run_matrix.sh` with `SCHEMES="none banerjee proposed"`, dataset `example` (Banerjee's frame), then repeat with `DATASET=bool` (the single-boolean 5-byte allData case) for all three schemes.
4. `run_security.sh`: replay, forge, tamper, flood against banerjee, banerjee-strict and proposed.
5. Optional extra: `-O0` cipher test, direct cable, `ASCON_IMPL=opt64`.
6. Fill `RESULTS.md` only from `results/<tag>/results.md`.
