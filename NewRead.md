# Patch Wrangler

*Herd the cattle through, handle the pets with care.*

A supervised, human-in-the-loop CLI for OS-level patching of a distributed
Splunk deployment on AWS. It walks you through the fleet one box at a time in a
safe order, drives everything through AWS Systems Manager (SSM), runs
role-appropriate health checks, and writes a report as it goes.

---

## Why this exists

A distributed Splunk cluster can't be patched like a fleet of stateless web
servers. The indexer peers hold **replicated data** and the search heads
coordinate as a **cluster**, so rebooting them carelessly — or in parallel —
risks data availability. AWS Patch Manager on its own is not Splunk-aware: point
it at the indexers and it will happily reboot them all at once.

Doing it by hand in the console is safe but clunky: scan and install are
separate operations on separate pages, and you're holding the ordering in your
head across ~18 boxes.

**Patch Wrangler** collapses that into one guided run: it discovers the boxes,
orders them least-critical-first, installs → reboots → health-checks each one,
handles Splunk maintenance mode automatically around the indexer phase, and
stops to let *you* confirm before it advances past any stateful node.

---

## What's in here

| File | What it does |
|---|---|
| `provision_management_box.sh` | One-time setup, run from **AWS CloudShell**. Creates a dedicated `patch-runner` EC2 with a least-privilege IAM role, reachable via SSM Session Manager (no SSH key, no inbound ports). |
| `patch_walkthrough.py` | The main event. The interactive, resumable patching walk-through. Talks only to the SSM API — no SSH, no VPN, no direct line to the instances. |

---

## How it works

**Ordering — cattle before pets.** Every box is classified from its `Name` tag
into a role, and patched in this order (least-critical / most-disposable first,
crown jewels last):

1. MISP → 2. management/Ansible → 3. Zeek workers → 4. Zeek master →
5. heavy forwarders → 6. standalone search heads → 7. deployer →
8. SHC members → 9. cluster manager → 10. indexer peers

- **Cattle** (disposable, independent): patch, reboot, quick check, move on.
- **Pets** (stateful, coordinated): patched one at a time, each behind a health
  check you confirm before proceeding. Indexer peers additionally go through
  Splunk maintenance mode + a graceful `splunk offline` before reboot.

**Check first, install second.** The run opens with a single fleet-wide scan and
a **BEFORE** table (installed / missing / critical / security / failed per box),
walks the boxes, then re-scans for an **AFTER** table and a before/after diff.

**Human-in-the-loop.** For every pet, the script shows you the raw
`cluster-status` / `shcluster-status` output and asks you to confirm it's healthy
before it moves on. That confirmation is the safety valve — it's meant to be
there.

**Resumable.** Progress is written to `patch_state.json` after every box, so an
interrupted run picks up where it left off.

---

## Prerequisites

- The target instances are **SSM-managed** (SSM agent + instance role; they show
  as *Online* in Fleet Manager).
- OS patch baselines exist for each OS in the fleet (Amazon Linux, Ubuntu, and
  Windows if present) and are associated with the instances' patch group.
- A **Splunk admin credential** in AWS Secrets Manager, shaped:
  ```json
  { "username": "svc-patch", "password": "..." }
  ```
  A dedicated least-privilege service account is preferred over a human admin.
- Instances carry a `Name` tag that the classifier can read (see the `classify()`
  rules in the script; edit them if your naming differs).

---

## Setup (one-time): provision the runner box

Run **from AWS CloudShell** (browser — no laptop CLI needed):

```bash
# edit the four values at the top first: REGION, SUBNET_ID, SECRET_ARN, INSTANCE_TYPE
bash provision_management_box.sh
```

The subnet must have a path to the SSM endpoints — either a NAT gateway, or VPC
endpoints for `ssm`, `ssmmessages`, and `ec2messages` — or the box will launch
but never appear in Session Manager.

Then, ~2 minutes later, connect via **Systems Manager → Session Manager →
patch-runner**, and set it up:

```bash
sudo dnf install -y python3-pip git
pip3 install boto3
# fetch the script (git clone your repo, or aws s3 cp it down)
```

> **Why a dedicated box, not the Ansible node:** the runner must not be in its
> own patch list, or it will reboot itself mid-run. `patch-runner` is named so
> the walk-through's env filter never selects it.

---

## Running a patch pass

Always start with a dry run against dev to confirm classification and ordering
without touching anything:

```bash
python3 patch_walkthrough.py --env dev --dry-run
```

Then a real run (dev first, then ref, then prod):

```bash
python3 patch_walkthrough.py --env ref \
  --secret-arn arn:aws:secretsmanager:eu-west-2:ACCOUNT:secret:splunk-admin-XXXX
```

**Tip:** for a long run, launch it inside `tmux` so a dropped Session Manager
connection doesn't interrupt the interactive prompts:

```bash
tmux new -s patch      # start
# ... run the script ...
# detach with Ctrl-b then d ; reattach with:
tmux attach -t patch
```

`tmux` is optional — the state file already means a disconnect only ever costs
the box in flight — but it makes reconnecting seamless.

---

## Command reference

| Flag | Default | Purpose |
|---|---|---|
| `--env` | `ref` | `Name`-tag substring to target (`dev` / `ref` / `prod`). |
| `--secret-arn` | — | Secrets Manager ARN for the Splunk admin credential (recommended). |
| `--region` | `eu-west-2` | AWS region. |
| `--splunk-home` | `/opt/splunk` | Splunk install path on the boxes. |
| `--exclude` | — | Comma-separated names/IDs to drop from the plan (e.g. the runner box). |
| `--state-file` | `patch_state.json` | Resume/progress file. |
| `--dry-run` | off | Plan and scan only; makes no changes. |
| `--reset` | off | Discard prior progress and start fresh. |

---

## Outputs

Each run writes three files, all timestamped where relevant:

- `patch_state.json` — progress, for resume.
- `patch_run_<timestamp>.log` — full trace of every action and prompt.
- `patch_report_<timestamp>.md` — human-readable report: before/after patch
  tables, a per-box run log, and a before/after diff. Written incrementally, so
  a crash still leaves a record.

---

## Configure before first use

Nothing is hard-coded to a specific fleet, but fill these in:

- `provision_management_box.sh`: `REGION`, `SUBNET_ID`, `SECRET_ARN`,
  `INSTANCE_TYPE`.
- `patch_walkthrough.py`: confirm `--splunk-home`, and that the Secrets Manager
  secret matches the `{"username", "password"}` shape.
- The `classify()` rules in the script — eyeball the `--dry-run` output and
  confirm every box landed in the right role. The rules are a simple ordered
  list; edit to match your naming.

---

## Safety & caveats

- **Health checks are best-effort text reads.** The script shows you the raw
  Splunk output and asks you to confirm for every pet. Don't remove that
  confirmation without replacing it with a structured check.
- **Never two of the same clustered tier down at once.** The serial walk
  enforces this; don't parallelise the pet phases.
- **Maintenance mode** is turned on before the peer phase and off after. If you
  halt mid-peer-phase, the script warns you it's still on — decide whether to
  disable it so the cluster can self-heal.
- **Splunk auth over SSM** appears in SSM command history. Fine for a supervised
  run; rotate the service-account credential if that's a concern.

---

## Security note (read before prod)

The script itself isn't sensitive — the **IAM identity it runs as** is.
`ssm:SendCommand` is command execution as root on the targeted boxes, so treat
the runner role as privileged. Two things worth doing before this ever points at
prod:

- **Scope `SendCommand`** from `Resource: "*"` down to your tagged fleet (and,
  ideally, to specific SSM documents). The provisioning policy leaves it broad
  for first setup and flags this in a comment.
- Use a **dedicated least-privilege Splunk service account**, MFA on the humans
  who can Session Manager in, and CloudTrail alerting on `SendCommand` outside a
  change window.

Because the health checks need general command execution, this identity stays
meaningfully privileged no matter what — scope it, log it, and don't leave it
with standing access.

---

## Scope — what this is and isn't

This is the **supervised, manual** tool: a human drives it and confirms each
sensitive step. It is intentionally not a set-and-forget system.

- **OS/package patching only.** It does not upgrade Splunk itself.
- A fully **automated** version (Step Functions, unattended cattle, gated pets,
  approval workflow) is a separate design and lives elsewhere — this repo is the
  hands-on runbook-in-code, and a good starting point for anyone building the
  automated successor.

---

## Glossary

- **Cattle / pet** — disposable interchangeable node vs. stateful hand-tended
  node; determines how carefully it's patched.
- **RF / SF** — replication factor (raw data copies) / search factor (searchable
  copies), enforced by the cluster manager. Patching must never drop the cluster
  below either — hence one peer at a time.
- **Maintenance mode** — a cluster-manager switch that suppresses automatic
  bucket fix-up during planned work.
- **`splunk offline`** — graceful peer shutdown that reassigns primary bucket
  copies and lets in-flight searches finish. Never `--enforce-counts` for
  patching (that permanently decommissions the peer).
