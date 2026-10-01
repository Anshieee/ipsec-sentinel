# Limitations (honest) and future work

## What the data cannot show
- Lifetimes, replay windows and ESN are kernel-side state, invisible in
  short captures — the rubric scores them from labels, the classifier
  reports `unknown`, the API says so explicitly.
- PFS is unparseable from real IKE (strongSwan encrypts the whole
  CREATE_CHILD_SA; source + wire proof in D19). The PFS model reads
  rekey SK length with honest confidence; IKEv1 real rows stay unknown.
- Real captures cover 6 of 19 variants (v1,v3,v5,v7,v12,v18), IPv4 only,
  ~8 s each (plus six 60 s rekey runs). No claim generalizes beyond them
  from real data.
- Synthetic traffic is emulated profiles, not user behavior: TCP
  timing/models transfer partially (synth→real traffic 0.57, zero wrong
  guesses — the system abstains instead).
- Synthetic IKE omits notifies and INFORMATIONAL DELETEs; QM3/AUTH sizes
  vary by implementation; AH ICV coverage is simplified (documented).

## What the models cannot do
- DH group without IKE, cipher without any size signal, traffic on
  pathological flows: expect `unknown`, by design.
- Mode-from-size depends on the traffic mix (tunnel overhead shifts
  sizes); it transfers to real captures but is not a structural proof
  (AH mode is; the API states which decided each output).

## Future work
IPv6 real captures, aggressive-mode IKEv1, MOBIKE, post-quantum KEM
proposals, longer captures with natural rekeys, calibration (reliability
diagrams + CalibratedClassifierCV), LightGBM/XGBoost comparison already
possible via installed deps.
