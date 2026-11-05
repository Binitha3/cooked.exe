# DEADBYTE local review UI

Run from the repository root:

```bash
python3 -m code.web_app --port 8000
```

Open `http://127.0.0.1:8000/`. The case selector includes the 32 public sample
requests and the 518 evaluation requests, labelled by source. Selecting a case
invokes the existing intent classifier, identity resolver, evidence processor,
and policy engine in memory. The UI does not write `output.csv`.

The display is an evidence review tool. It shows policy remediation as proposed
future work and never executes deletion. Each discovered evidence-backed
resource seeds the monochrome particle shell; the shell's specks are visual
texture, while the displayed resource count comes from policy findings. Map
edges appear only for trace relationships established by the evidence processor.
The reported deletion status remains the policy engine's decision. A reported
status in the request is shown as a claim.
