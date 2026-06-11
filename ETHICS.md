# Ethics & Acceptable Use Policy (AUP)

`veilbox` is a **defensive privacy tool**. It exists to help people protect
their privacy, practice good OPSEC, resist pervasive tracking, and conduct
**authorized** security research.

## Permitted uses

- Protecting your own privacy and reducing your trackable surface.
- OPSEC for journalists, researchers, activists, and at-risk individuals.
- Anti-tracking and anti-fingerprinting on systems and accounts **you own or
  are authorized to operate**.
- Authorized security research, red-team engagements, and privacy audits
  conducted with **explicit, documented permission**.
- Verifying that your own anonymity setup actually works (the `audit` command).

## Prohibited uses

- **Fraud of any kind**, including payment fraud, account-takeover, fake-account
  creation, or incentive/abuse fraud.
- **Evading fraud-detection, anti-abuse, or KYC/AML controls** to commit or
  facilitate unlawful activity.
- Circumventing access controls, terms of service, or technical protections on
  systems you are **not authorized** to use.
- Any harassment, stalking, or activity that endangers others.
- Anything unlawful in your jurisdiction.

## Design choices that reflect this stance

- **Zero telemetry.** veilbox never phones home. We collect nothing.
- **Coherence over evasion.** The fingerprint engine optimizes for *internal
  consistency* (so you don't leak via mismatched fields), not for defeating
  any specific anti-fraud vendor.
- **Proof, not promises.** The built-in leak audit lets you verify your own
  anonymity rather than trust a black box.

By using veilbox you agree to use it only for lawful, authorized, defensive
purposes. The authors disclaim responsibility for misuse.
