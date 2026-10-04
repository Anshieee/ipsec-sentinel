# QA prep: 15 hardest questions (M5 fix 5)

1. **Isn't synthetic data just testing your own generator?**
   Yes, partly — stated in `docs/model-evaluation.md` and every report.
   The 66 real pcaps (6 variants) are the only out-of-distribution check:
   parsed fields transfer at 1.000, TCP traffic abstains (0 wrong).
2. **Why is PFS `unknown` on real captures?**
   strongSwan encrypts the whole CREATE_CHILD_SA (`message.c` rules +
   wire proof, D19). Forced rekeys prove presence, never content.
3. **Why is DH `unknown` without IKE?**
   DH leaves no trace in ESP sizes/timing (ablation: prior + cipher
   pockets only, dh2/5 never recovered).
4. **How was leakage ruled out?**
   `capture/audit_leakage.py`: stratified permutation MI + grouped
   nearest-match, all green; features store no endpoint values (tested by
   hiding `data/labels`); splits never share a variant-run.
5. **Why abstain instead of guessing?**
   Unknowns count as errors in eval, so abstention is never free. On real
   TCP the model abstains 43% with zero wrong guesses — the alternative
   (confident errors at 0.5) was measured and rejected.
6. **How were rubric weights chosen?**
   Cipher 25 / DH 20 mirror NIST SP 800-57 strength timelines; integrity
   15 / PFS 10 follow RFC 8221/8247 optionality language; lifetimes 10,
   replay 5, IKE 10, mode 5 encode standard guidance. Hand-computed
   oracles pin the table (`test_assess.py`).
7. **What does an encrypted IKE_AUTH hide?**
   Identities, the CHILD proposal, traffic selectors. We verify
   synthetic AUTH contents by decrypting with deterministic keys; real
   AUTH is presence + length only.
8. **Why is mode 100% — isn't that leakage?**
   Tunnel overhead shifts every ESP size by 20/40 B; it transfers to real
   captures (different runs/stacks). Brittle across traffic mixes —
   documented, and AH mode is structural anyway.
9. **What if the peer rekeys mid-capture?**
   New SPIs appear (seq restarts per SPI); the validator requires
   per-SPI contiguity and flags SPI-count anomalies.
10. **Why RandomForest, not deep learning?**
    480 pcaps, ~100 tabular features: RF is calibrated-enough, fast,
    deterministic (seed 7), and importances are inspectable. xgboost/
    lightgbm are installed for follow-ups.
11. **Replay-window/ESN/lifetimes: why not predicted?**
    Kernel-side state, invisible in short captures. Predicting them
    would be fabrication; the rubric scores them from labels.
12. **Transport-mode inner traffic: how validated?**
    Synthetic transport ESP is decrypted (L4 parse + UDP-len/TCP-hlen
    checks); real transport is block-alignment + SPI discipline only.
13. **What breaks first on a new strongSwan version?**
    Notify sets, QM sizes, KE lengths for new groups. The validator's
    `--self-test` + full-corpus gate catches drift (rc != 0).
14. **Why per-run shared addresses?**
    So no address value can identify a variant even to a memorizing
    classifier (D15); run-grouped splits are the second defense.
15. **Can the frontend trust `confidence`?**
    Parsed = 1.0 by construction; model = RF `predict_proba` max,
    uncalibrated — treat as rank-ordering, not probability. `unknown`
    below 0.5. Mock mode returns fixed samples for UI work.
16. **Why does a live v1 analysis report posture 89 @ 0.67 while the rubric oracle gives 88?**
    Posture vs evidence coverage are separate, confidence-weighted
    numbers. The oracle is ideal-visibility scoring from labels (every
    field f = 1.0: 95/108 → 88). A short live capture cannot observe
    the CHILD PFS group (rekeys encrypted), SA lifetimes, or receiver
    replay enforcement, so those three controls are UNKNOWN (f = 0);
    INFERRED controls speak with their model confidence (e.g. child
    cipher 0.970). Live v1: 64.346/72.190 → 89 @ 0.6684 — the
    hand-worked table is in `docs/review/security-rubric.md`.
    An unobservable field lowers coverage, not posture — there are no
    "assuming weak" penalties. Weights never change to make numbers
    agree (the two IKE-suite controls were added because v1.1 left
    OBSERVED weak IKE suites unscored, not to move any sample).
17. **What does LIKELY mean, and why not just FAIL?**
    A FAIL resting on INFERRED (model) evidence is reported as LIKELY:
    same posture/coverage math (confidence-weighted), but the finding
    severity is capped one level below the OBSERVED equivalent
    (critical→high…) and the text is marked "Likely:". Example: live
    v19's 3DES child (inferred 0.87) is LIKELY/high, while the
    label-oracle v19 is CONFIRMED/critical. Only OBSERVED FAILs are
    CONFIRMED. Every control carries `source` (observed/inferred/label/
    none) and `confidence` so the UI can badge inference honestly.
18. **Why is dh-strength UNKNOWN while ike-version FAILs for a weak DH group?**
    They score different objects — rule ids are unchanged. `dh-strength`
    scores the negotiated CHILD/PFS DH group, which travels inside the
    encrypted CREATE_CHILD_SA (or quick mode) and is never visible in a
    captured handshake; without that evidence the control is honestly
    UNKNOWN (it lowers coverage, never posture). The IKE SA's own DH
    group *is* read in the clear from IKE_SA_INIT, so it is scored under
    `ike-version` together with the `weak-ike-dh` finding (critical when
    OBSERVED, e.g. v21's DH2 live). A weak IKE group therefore always
    surfaces — just not as the child PFS group.
19. **How does it do on someone else's data?**
    Head-to-head on 180 captures from naman9271/ipsec-pcap-lab
    (`c0cf256`, real strongSwan, `docs/head-to-head.md`): parsed fields
    transfer at 1.000, auth at 0.910, encryption at 0.322 accuracy
    (0.690 when it answers — compare our own synth→real 0.7121 on the
    same unknown-as-error metric). Mode (0.011) and traffic type (0.000;
    15 confident `whatsapp` errors) do NOT transfer: their captures have
    no IKE packets (capture filter), 45 s real traffic mixes, and
    SHA384/DH15 suites outside our schema. Reported as weak, no
    cherry-picking; unmappable fields excluded with counts. Their repo
    has no license, so only our script and aggregates ship here.
20. **What happens on data unlike your training data?**
    Three honest behaviors, all visible in the output. (1) An invariant:
    detected IPsec is never plain/none — a model vote for plain on an
    IPsec-positive capture becomes NOT_OBSERVED with a reason. (2) An
    OOD gate: an INFERRED vote abstains (UNKNOWN + reason
    "capture outside the training distribution: …") iff the capture
    trips ≥ 5 training range checks AND confidence is below 0.6 —
    calibrated for ≤ 2% false-abstain on held-out folds (measured 0)
    and real captures (~0.8%). Either signal alone never abstains.
    (3) What the gate cannot do: residual confident errors persist
    where our own correct answers live (few violations, moderate
    confidence) — e.g. AES-256 predicted as AES-128, both wire-identical
    in ESP size structure. Those stay wrong, stated plainly in
    docs/head-to-head.md, never tuned away on the test split.
