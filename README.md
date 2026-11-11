> **About this repository.** Raspberry Pi 4 Model B test harness comparing three GOOSE configurations on
> libIEC61850 v1.5.3: no security, a *reproduction* of the Banerjee and Banerjee baseline (A. Banerjee and U. Banerjee,
> IEEE FNWF 2025, DOI 10.1109/FNWF66845.2025.11317357; unspecified details are assumptions), and the proposed scheme
> (fixed-width nonce, RFC 6479 replay window on plaintext header fields, encryption of only the `allData` field).
> The frozen baseline alone is in the companion repository https://github.com/polepakamo/goose-banerjee-baseline-pi4
>
> **License.** GPL-3.0-or-later (two files are modified copies of libIEC61850 files); see `LICENSE` and `NOTICE.md`.
>
> **Reproducibility.** `setup.sh` clones libIEC61850 tag `v1.5.3` and ascon-c and writes the exact commits to
> `versions.txt`. Quote that file when citing results.

---

# GOOSE security harness: frozen Banerjee-style baseline + the proposed scheme (Raspberry Pi 4 Model B)

Step 2 of 2. `GOOSE_SCHEME` has three values here: `none` (stock libIEC61850), `banerjee` (the baseline, unchanged from `../goose-banerjee`) and `proposed` (the new scheme). Everything else is shared.
Read `PROPOSED_SCHEME.md` first: it defines the scheme, the fairness rules and the expectations written before measuring. `BASELINE_RESULTS.md` holds the recorded baseline results.

```
lib/goose_sec.[ch]      shared layer: scheme switch, nonces (BER baseline / fixed proposed), IEC 62351-6 extension,
                        RFC 6479 window, per-frame receive log. Pure C, unit-tested on a PC.
lib/goose_publisher.c   drop-in for libIEC61850 v1.5.3 goose_publisher.c (scheme applied in publish())
lib/goose_receiver.c    drop-in for libIEC61850 v1.5.3 goose_receiver.c  (scheme applied in parseGooseMessage())
src/gs_pub.c, gs_sub.c  publisher / subscriber, unchanged from the baseline
src/gs_inject.c         attacker: replay, forge, tamper (new), flood
scripts/run_matrix.sh   performance matrix (schemes: none banerjee proposed)
scripts/run_security.sh replay, forge, tamper, flood against banerjee, banerjee-strict, proposed
scripts/analyze.py      CSVs -> results.md / results.json
tests/                  unit tests (nonces, window, extension, BER) and the real-cipher nonce demo
```

## What changed relative to the frozen baseline
* `goose_sec`: `GS_PROPOSED`, `gs_nonce_fixed`, `gs_window_*`.
* `goose_publisher.c`: remembers where allData starts; for `proposed` encrypts only allData and authenticates every byte before it.
* `goose_receiver.c`: a third branch, `proposed`: walk the clear PDU, window peek, decrypt allData, window commit after the tag, then the stock parser. Baseline branch untouched.
* `gs_inject.c`: `tamper` mode. `run_security.sh`: tamper scenario and the `proposed` configuration.
* `analyze.py`, `make_fake_results.py`, tests: `proposed` added.

## Steps (same Pis, same procedure as the baseline)
```bash
# in WSL (Kali): copy the zip to both Pis (PowerShell: scp goose-proposed.zip pi@<ip>:~/)
# on EACH Pi: unpack, reuse the libIEC61850 / ascon-c already built for the baseline, build
cd ~ && unzip -o goose-proposed.zip && cd goose-proposed
cp -r ~/goose-banerjee/libiec61850 ~/goose-banerjee/ascon-c ~/goose-banerjee/third_party ~/goose-banerjee/versions.txt .
bash build.sh
```
(`libiec61850.a`, `libhal.a` and the headers are already installed in /usr/local from the baseline setup; `build.sh` only needs the source tree for headers.)

1. Frame sizes (publisher Pi): `proposed` must give the same 261 bytes as the baseline.
```bash
sudo GOOSE_SCHEME=proposed GOOSE_IV_LEN=20 ./build/gs_pub eth0 --count 10 --warmup 0 --expect-size 261
```
2. Round trip (subscriber Pi first, then publisher): `rej_auth=0`, `rej_replay=0` expected.
```bash
sudo GOOSE_SCHEME=proposed GOOSE_IV_LEN=20 ./build/gs_sub eth0 --duration 40 --warmup 100 --out /tmp/roundtrip_p.csv
```
```bash
sudo GOOSE_SCHEME=proposed GOOSE_IV_LEN=20 ./build/gs_pub eth0 --count 2000 --warmup 100
```
3. Matrix (from Kali, ssh keys already installed): three schemes, five shuffled runs each.
```bash
cd ~/goose-proposed && PUB=pi@192.168.31.127 SUB=pi@192.168.31.89 RUNS=5 bash scripts/run_matrix.sh
```
Then repeat with the single-boolean dataset: `DATASET=bool` in front of the same command.
4. Security tests:
```bash
cd ~/goose-proposed && PUB=pi@192.168.31.127 SUB=pi@192.168.31.89 bash scripts/run_security.sh
```

## Per-component breakdown (the "Stage | Component | Mean latency | % of T_E2E | Notes" table)

The totals T_gen and T_proc come from the normal build. To split them into steps, build and run the
instrumented variant. It is a separate build in `build-components/`, so the normal binaries and the
normal runs are untouched:

```
COMPONENTS=1 bash build.sh                       # on each Pi
COMPONENTS=1 RUNS=5 bash scripts/run_matrix.sh   # from the controller -> results/<tag>-components/
```

`scripts/analyze.py` then adds a "Per-component breakdown" table per scheme to `results.md` and
`results.json`. Nothing in it is typed by hand.

| Row | How it is obtained |
|---|---|
| Nonce construction | timer around `gs_nonce_ber` / `gs_nonce_fixed` in `GoosePublisher_publish()` |
| ASCON-AEAD128 encrypt | timer around `crypto_aead_encrypt()` |
| Frame serialise + sendto() | **computed**: `T_gen` - nonce - encrypt (the `sendto()` part alone is shown in the Notes column) |
| Total T_gen | the publisher's existing `t_gen_us` |
| Ethernet link (T_tx) | **calculated**: frame bytes x 8 / 100 Mbit/s, not measured |
| BER parse + nonce/AAD reconstruction | **computed**: `T_proc` - window - decrypt (also contains `recv()`, header and extension parsing, and the application callback) |
| RFC 6479 replay window check | timers around `gs_window_peek()` and `gs_window_commit()` (proposed scheme only) |
| ASCON-AEAD128 decrypt | timer around `crypto_aead_decrypt()` |
| Total T_proc | the subscriber's existing `t_proc_us` |

Notes on reading the result:

* Each timer is two `clock_gettime()` reads. The publisher log of the component build prints
  `timer_cost_ns=...` (measured back-to-back read pairs); it is **not** subtracted. Because of this the
  totals of a component run are slightly larger than those of a normal run. Report T_gen, T_proc and T_E2E
  from the normal run and use the component run for the split.
* A step that does not exist in a scheme has no row (no nonce or cipher rows for `none`, no window row for
  `banerjee`).
* Test the table code without hardware (the numbers are random and mean nothing):
  `python3 tests/make_fake_results.py /tmp/fake --components && python3 scripts/analyze.py /tmp/fake`
