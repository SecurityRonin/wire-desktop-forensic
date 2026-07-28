# wire-desktop-forensic

Forensic anomaly analyzer for **Wire desktop** IndexedDB artifacts, layered on
`wire-desktop-core`. Recovers cleartext message metadata and deleted records,
and flags client-side-encrypted (unrecoverable) payloads and exposed attachment
key material — emitting canonical `forensicnomicon::report::Finding`s.

See the [repository README](https://github.com/SecurityRonin/wire-desktop-forensic).
