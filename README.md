# DEADBYTE — AI-Powered Data Deletion Verification

### Deleted doesn't mean gone.

**DEADBYTE** is an AI-powered data deletion verification platform designed to investigate whether personal data has actually been removed after a deletion request.

Deleting data from one database does not guarantee that it has disappeared everywhere. Copies may remain in backups, analytics systems, search indexes, support platforms, exports, and third-party integrations.

DEADBYTE investigates these potential remnants, traces evidence across systems, identifies unresolved risks, and generates explainable, evidence-backed deletion audit decisions.

---

## The Problem

When users request deletion of their personal data, organizations may confirm that a deletion operation succeeded without verifying whether all copies and downstream data flows have been addressed.

Residual personal information can remain in:

- Database records and historical snapshots
- Backup and restore systems
- Analytics and telemetry platforms
- Search indexes and cached records
- Customer support conversations and attachments
- Data exports and third-party integrations

A successful deletion message is not necessarily proof of complete deletion.

## Our Solution

DEADBYTE performs evidence-driven deletion verification.

It combines identity resolution, evidence processing, policy evaluation, explainability, and visual investigation tools to help determine whether deletion is complete or whether further action is required.

The system follows a fail-closed approach: when evidence is insufficient, it reports uncertainty instead of making unsupported compliance claims.

---

## Key Features

### 1. Identity Resolution
- Resolves historical and current user identifiers.
- Supports identity matching using available evidence.
- Applies audit cutoffs to prevent future information from influencing past decisions.

### 2. Evidence Processing
- Processes supported structured and unstructured evidence sources.
- Extracts resource observations, timestamps, identifiers, and provenance.
- Preserves source references and evidence locators.
- Distinguishes reported activity from verified deletion evidence.

### 3. Ghost Data Map
- Visualizes systems, resources, and evidence-supported relationships.
- Displays residual data and trace-linked relationships.
- Helps investigators understand where data may remain.
- Avoids inventing relationships that are not supported by evidence.

### 4. Explainability Engine
- Generates risk cards and policy explanations.
- Displays evidence provenance and uncertainty.
- Explains why a deletion decision or finding was produced.
- Requires indexed evidence records for COMPLETE verification.

### 5. What-If Simulator
- Previews proposed remediation actions.
- Highlights potential risk reduction and remaining dependencies.
- Identifies verification requirements.
- Does not execute deletion or modify the underlying decision.

### 6. Temporal Rebirth Detection
- Compares pre-deletion and later evidence snapshots.
- Investigates possible data reappearance.
- Uses evidence-backed snapshot coverage and cause attribution.
- Reports INDETERMINATE when evidence is insufficient.

---

## How It Works

The application follows an evidence-driven investigation pipeline:

1. **Request Classification** — identifies the intent of the deletion request.
2. **Identity Resolution** — resolves the subject using available identity records.
3. **Evidence Ingestion** — processes evidence files and preserves provenance.
4. **Resource Discovery** — identifies potentially associated records and data flows.
5. **Policy Evaluation** — evaluates observations against applicable deletion rules.
6. **Explainability** — generates risk explanations and evidence references.
7. **Remediation Planning** — identifies supported corrective actions.
8. **Verification** — determines whether the available evidence supports a deletion decision.
9. **Rebirth Detection** — investigates possible reappearance across available snapshots.

---

## Decision Philosophy

DEADBYTE does not equate a successful deletion operation with verified deletion.

| Status | Meaning |
|---|---|
| COMPLETE | Evidence-backed verification establishes the required deletion outcome. |
| INCOMPLETE | Evidence supports unresolved findings and a remediation plan. |
| NOT_APPLICABLE | The request does not authorize deletion or deletion verification. |
| POLICY UNRESOLVED | Available evidence is insufficient to establish a policy decision. |

**Important:** Missing evidence is not proof of deletion. The system preserves uncertainty rather than incorrectly reporting compliance.

---

## Technology

The integrated application includes:

- Python-based backend and investigation pipeline
- Frontend dashboard and interactive visualizations
- Evidence-processing and identity-resolution modules
- Policy evaluation and explainability components
- Ghost Data Map
- Temporal Rebirth Detection
- What-If simulation
- Automated tests and evaluation utilities

See the source code and project documentation for implementation details.

---

## Running the Application Locally

### Requirements

- Python 3
- Git
- Project dependencies installed

### Clone the repository

```bash
git clone https://github.com/Binitha3/cooked.exe.git
cd cooked.exe
```

### Start the application

```bash
python3 -m code.web_app --port 8000
```

Open:

http://127.0.0.1:8000/

The application provides the local investigation interface and backend API.

---

## Demo Scenarios

The integrated prototype includes evidence-backed investigation scenarios.

### Case 15
Demonstrates an evidence-backed active data-flow finding and associated trace relationships.

### Case 16
Demonstrates:
- Ghost Data Map with 7 nodes and 5 evidenced edges.
- Two risk cards.
- Evidence provenance.
- What-If remediation preview.
- INDETERMINATE Rebirth status when required snapshot coverage is unavailable.

The hosted demo configuration is restricted to the 32 public sample cases.

---

## Testing and Verification

The latest reported test results include:

| Test suite | Result |
|---|---:|
| Explainability focused tests | 12 passed |
| Main test discovery | 128 passed, 1 error |
| Identity and Rebirth tests | 37 passed |
| Hosted web-app tests | 8/8 passed |

The remaining integration test error concerns case 01, where cutoff-valid evidence does not establish a subject-to-resource link.

Test results should be interpreted alongside the evaluation limitations below.

---

## Evaluation Status and Limitations

The challenge evaluation contains 518 requests.

Current validated results:

- 381 rows validated.
- 137 requests remain unresolved.
- The official 518-row `output.csv` has not been generated.

The unresolved cases require additional cutoff-valid evidence or extraction of potentially relevant image artifacts.

The partial diagnostic CSV is not an official submission and must not be treated as a completed evaluation result.

DEADBYTE intentionally avoids fabricating evidence or forcing unsupported deletion decisions.

---

## Deployment

A Render deployment configuration is provided through `render.yaml`.

The hosted configuration is designed for the Render Free plan and restricts the demo to public sample cases.

**Deployment status: Prepared, not yet publicly deployed.**

A public URL will be added here after deployment and successful verification.

---

## Repository Structure

```text
cooked.exe/
│
├── code/                       # Application source and backend
├── dataset/                    # Hackathon evidence dataset
├── docs/                       # Project documentation
├── evaluation/                 # Evaluation reports and diagnostics
├── results/                    # Generated results and demo outputs
├── scripts/                    # Utility and execution scripts
├── tests/                      # Test suite
│
├── AGENTS.md                   # Agent instructions
├── README.md                   # Project documentation
├── agent_trace_instructions.md # Agent trace requirements
├── log.txt                     # Development activity log
├── problem_statement.md        # Challenge problem statement
├── render.yaml                 # Render deployment configuration
├── code.zip                    # Packaged application
└── agent-trace.zip             # Agent execution traces
```

Directory placement may vary slightly depending on the final repository organization.

---

## Team

**Team Deadbyte**

Built for the Hackoween Hackathon.

Our goal is to make data deletion verifiable, explainable, and evidence-driven.

---

### DEADBYTE

**Deleted doesn't mean gone. Prove it.**
