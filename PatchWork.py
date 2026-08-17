#!/usr/bin/env python3
"""
patch_walkthrough.py  (v2)
==========================
Supervised, interactive OS-patching walk-through for the distributed Splunk
fleet on AWS. Runs from inside AWS (CloudShell, or a management EC2 via SSM
Session Manager) authenticated by an IAM role. Talks ONLY to the SSM API —
no SSH, no VPN, no direct line to the instances.

What v2 adds over v1:
  * Fleet patch-level TABLE up front (a single Scan across all boxes, then a
    per-box compliance summary: installed / missing / critical / security /
    failed) — the "check first" pass.
  * Secrets Manager as the primary Splunk-auth path (--secret-arn).
  * A re-scan at the end and a BEFORE vs AFTER comparison.
  * Self-logging: a timestamped .log trace and a Markdown run report, both
    written incrementally so a crash still leaves a record.
  * --exclude to drop boxes (e.g. the box you're running from) from the plan.

USAGE
  python3 patch_walkthrough.py --env ref --secret-arn arn:aws:secretsmanager:...
  python3 patch_walkthrough.py --env ref --dry-run
  python3 patch_walkthrough.py --env ref --reset
  python3 patch_walkthrough.py --env ref --exclude patch-runner,i-0123abcd

VERIFY BEFORE FIRST USE:
  * --splunk-home (default /opt/splunk)
  * secret JSON shape: {"username": "...", "password": "..."}
  * that instance Name tags match the classify() rules
"""

import argparse
import datetime as dt
import getpass
import json
import logging
import os
import sys
import time

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    sys.exit("boto3 is required:  pip3 install boto3")

CATTLE, PET = "cattle", "pet"
RUN_TS = dt.datetime.now().strftime("%Y%m%d_%H%M%S")


# --------------------------------------------------------------------------- #
# Classification / order
# --------------------------------------------------------------------------- #
def classify(name: str):
    n = name.lower()
    if "misp" in n:                       return ("misp", CATTLE, 1)
    if "ansible" in n or "management" in n: return ("management", CATTLE, 2)
    if "zeek" in n and "worker" in n:     return ("zeek-worker", CATTLE, 3)
    if "zeek" in n and "master" in n:     return ("zeek-master", CATTLE, 4)
    if "zeek" in n:                       return ("zeek-other", CATTLE, 4)
    if "forwarder" in n:                  return ("heavy-forwarder", CATTLE, 5)
    if "shc" in n:                        return ("shc-member", PET, 8)
    if "deployer" in n:                   return ("deployer", CATTLE, 7)
    if "manager" in n:                    return ("cluster-manager", PET, 9)
    if "indexer" in n:                    return ("indexer-peer", PET, 10)
    if "search" in n:                     return ("standalone-search", CATTLE, 6)
    return ("unclassified", CATTLE, 99)


# --------------------------------------------------------------------------- #
# Colour + logging (colour to console, plain to file + report)
# --------------------------------------------------------------------------- #
class C:
    G="\033[92m"; Y="\033[93m"; R="\033[91m"; B="\033[94m"
    BOLD="\033[1m"; DIM="\033[2m"; END="\033[0m"


LOG_FILE = f"patch_run_{RUN_TS}.log"
REPORT_FILE = f"patch_report_{RUN_TS}.md"
logging.basicConfig(
    filename=LOG_FILE, level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)


def log(msg, colour=""):
    """Print (optionally coloured) to console and record plain text to the log."""
    print(f"{colour}{msg}{C.END}" if colour else msg)
    logging.info(msg)


def hr(): print(C.DIM + "-" * 74 + C.END)


def ask(prompt, default="n"):
    opts = "Y/n" if default == "y" else "y/N"
    r = input(f"{C.BOLD}{prompt}{C.END} [{opts}] ").strip().lower() or default
    logging.info(f"PROMPT: {prompt} -> {r}")
    return r.startswith("y")


class Report:
    """Incrementally-written Markdown report of the whole run."""
    def __init__(self, path, env, region):
        self.path = path
        self.lines = [
            f"# Patch run report — {env} — {RUN_TS}",
            f"*Region:* {region}  |  *Started:* {dt.datetime.now().isoformat(timespec='seconds')}",
            "",
        ]
        self.flush()

    def add(self, line=""):
        self.lines.append(line)
        self.flush()

    def table(self, headers, rows):
        self.add("| " + " | ".join(headers) + " |")
        self.add("|" + "|".join(["---"] * len(headers)) + "|")
        for r in rows:
            self.add("| " + " | ".join(str(c) for c in r) + " |")
        self.add("")

    def flush(self):
        with open(self.path, "w") as f:
            f.write("\n".join(self.lines))


# --------------------------------------------------------------------------- #
# AWS wrappers
# --------------------------------------------------------------------------- #
class Aws:
    def __init__(self, region, dry_run):
        self.ec2 = boto3.client("ec2", region_name=region)
        self.ssm = boto3.client("ssm", region_name=region)
        self.sm = boto3.client("secretsmanager", region_name=region)
        self.dry = dry_run

    def discover(self, env_substr, exclude):
        boxes = []
        for page in self.ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        ):
            for res in page["Reservations"]:
                for inst in res["Instances"]:
                    name = next((t["Value"] for t in inst.get("Tags", [])
                                 if t["Key"] == "Name"), "")
                    if env_substr.lower() not in name.lower():
                        continue
                    if any(x and (x in name or x == inst["InstanceId"]) for x in exclude):
                        continue
                    platform = ("Windows" if "windows"
                                in inst.get("PlatformDetails", "").lower() else "Linux")
                    role, tier, rank = classify(name)
                    boxes.append({"id": inst["InstanceId"], "name": name,
                                  "platform": platform, "role": role,
                                  "tier": tier, "rank": rank})
        boxes.sort(key=lambda b: (b["rank"], b["name"]))
        return boxes

    # ---- SSM run / wait ----
    def run(self, instance_id, commands, doc="AWS-RunShellScript", comment=""):
        if self.dry:
            log(f"[dry-run] would run on {instance_id}: {commands}", C.DIM)
            return None
        params = {"commands": commands} if doc.endswith("ShellScript") \
            or doc.endswith("PowerShellScript") else commands
        return self.ssm.send_command(InstanceIds=[instance_id], DocumentName=doc,
                                     Parameters=params, Comment=comment[:100]
                                     )["Command"]["CommandId"]

    def wait_cmd(self, command_id, instance_id, timeout=1800):
        if self.dry or command_id is None:
            return "Success", "", ""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                r = self.ssm.get_command_invocation(CommandId=command_id,
                                                    InstanceId=instance_id)
            except ClientError:
                time.sleep(3); continue
            if r["Status"] in ("Success", "Failed", "Cancelled", "TimedOut"):
                return (r["Status"], r.get("StandardOutputContent", ""),
                        r.get("StandardErrorContent", ""))
            time.sleep(5)
        return "TimedOut", "", "poll timeout"

    def scan_fleet(self, instance_ids):
        """One Scan command across all boxes; wait for all invocations."""
        if self.dry:
            return
        cid = self.ssm.send_command(
            InstanceIds=instance_ids, DocumentName="AWS-RunPatchBaseline",
            Parameters={"Operation": ["Scan"]}, Comment="walkthrough fleet scan"
        )["Command"]["CommandId"]
        deadline = time.time() + 1200
        while time.time() < deadline:
            invs = self.ssm.list_command_invocations(CommandId=cid)["CommandInvocations"]
            if invs and all(i["Status"] in ("Success", "Failed", "Cancelled", "TimedOut")
                            for i in invs):
                return
            time.sleep(10)

    def patch_state(self, instance_id):
        try:
            s = self.ssm.describe_instance_patch_states(
                InstanceIds=[instance_id])["InstancePatchStates"][0]
            return {
                "installed": s.get("InstalledCount", 0),
                "missing": s.get("MissingCount", 0),
                "critical": s.get("CriticalNonCompliantCount", 0),
                "security": s.get("SecurityNonCompliantCount", 0),
                "failed": s.get("FailedCount", 0),
                "pending_reboot": s.get("InstalledPendingRebootCount", 0),
            }
        except (ClientError, IndexError, KeyError):
            return {"installed": "-", "missing": "-", "critical": "-",
                    "security": "-", "failed": "-", "pending_reboot": "-"}

    def install(self, instance_id):
        if self.dry:
            log(f"[dry-run] would install (NoReboot) on {instance_id}", C.DIM)
            return "Success", "", ""
        cid = self.ssm.send_command(
            InstanceIds=[instance_id], DocumentName="AWS-RunPatchBaseline",
            Parameters={"Operation": ["Install"], "RebootOption": ["NoReboot"]},
            Comment="walkthrough install")["Command"]["CommandId"]
        return self.wait_cmd(cid, instance_id)

    def ping_online(self, instance_id, timeout=600):
        if self.dry:
            return True
        deadline = time.time() + timeout
        seen_offline = False
        while time.time() < deadline:
            try:
                info = self.ssm.describe_instance_information(
                    Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
                )["InstanceInformationList"]
                status = info[0]["PingStatus"] if info else "Unknown"
            except (ClientError, IndexError):
                status = "Unknown"
            if status != "Online":
                seen_offline = True
            if status == "Online" and seen_offline:
                return True
            time.sleep(10)
        return not seen_offline

    def get_secret(self, arn):
        d = json.loads(self.sm.get_secret_value(SecretId=arn)["SecretString"])
        return d["username"], d["password"]


# --------------------------------------------------------------------------- #
# Health checks + Splunk actions
# --------------------------------------------------------------------------- #
class Health:
    def __init__(self, aws, splunk_home, splunk_auth):
        self.aws = aws; self.home = splunk_home; self.auth = splunk_auth

    def _auth(self):
        return f" -auth {self.auth}" if self.auth else ""

    def _sh(self, instance_id, cmd, ps=False):
        doc = "AWS-RunPowerShellScript" if ps else "AWS-RunShellScript"
        cid = self.aws.run(instance_id, [cmd], doc=doc)
        return self.aws.wait_cmd(cid, instance_id)

    def os_clean(self, box):
        if box["platform"] == "Windows":
            cmd = ("Get-Service | Where-Object {$_.StartType -eq 'Automatic' "
                   "-and $_.Status -ne 'Running'} | Select-Object -Expand Name")
            _, out, _ = self._sh(box["id"], cmd, ps=True)
        else:
            _, out, _ = self._sh(
                box["id"], "uname -r; uptime -p; systemctl --failed --no-legend")
        log(f"  {out.strip() or '(clean)'}", C.DIM)
        return out

    def splunk_status(self, box):
        _, out, _ = self._sh(box["id"], f"sudo -u splunk {self.home}/bin/splunk status")
        log(f"  {out.strip()}", C.DIM)
        return "running" in out.lower()

    def cluster_status(self, manager_id):
        _, out, err = self._sh(
            manager_id,
            f"sudo -u splunk {self.home}/bin/splunk show cluster-status --verbose{self._auth()}")
        log(out.strip() or err.strip())
        return out

    def shcluster_status(self, member_id):
        _, out, err = self._sh(
            member_id, f"sudo -u splunk {self.home}/bin/splunk show shcluster-status{self._auth()}")
        log(out.strip() or err.strip())
        return out


def splunk_cli(aws, health, instance_id, verb):
    cmd = f"sudo -u splunk {health.home}/bin/splunk {verb}{health._auth()}"
    return aws.wait_cmd(aws.run(instance_id, [cmd], comment=f"splunk {verb}"), instance_id)


def reboot(aws, box):
    if box["platform"] == "Windows":
        aws.run(box["id"], ["Restart-Computer -Force"], doc="AWS-RunPowerShellScript")
    else:
        aws.run(box["id"], ["sudo reboot"])
    log("  rebooting; waiting for SSM Online...", C.Y)
    ok = aws.ping_online(box["id"])
    log(f"  online: {ok}", C.G if ok else C.R)
    return ok


# --------------------------------------------------------------------------- #
# Stats table
# --------------------------------------------------------------------------- #
def stats_table(aws, boxes, report, title):
    log(f"\n{title}", C.BOLD)
    headers = ["#", "tier", "role", "name", "os",
               "inst", "miss", "crit", "sec", "fail", "pend"]
    rows = []
    for i, b in enumerate(boxes, 1):
        s = aws.patch_state(b["id"])
        crit_c = C.R if isinstance(s["critical"], int) and s["critical"] else ""
        print(f"  {i:>2} {b['tier']:<6} {b['role']:<17} {b['name']:<38} "
              f"{b['platform']:<7} {str(s['installed']):>4} "
              f"{crit_c}{str(s['missing']):>4}{C.END} "
              f"{crit_c}{str(s['critical']):>4}{C.END} "
              f"{str(s['security']):>4} {str(s['failed']):>4} {str(s['pending_reboot']):>4}")
        rows.append([i, b["tier"], b["role"], b["name"], b["platform"],
                     s["installed"], s["missing"], s["critical"],
                     s["security"], s["failed"], s["pending_reboot"]])
    report.add(f"## {title}")
    report.table(headers, rows)
    return {r[3]: r for r in rows}  # keyed by name for before/after diff


# --------------------------------------------------------------------------- #
# State
# --------------------------------------------------------------------------- #
def load_state(p):
    return json.load(open(p)) if os.path.exists(p) else {"done": [], "maintenance_mode": False}


def save_state(p, s):
    json.dump(s, open(p, "w"), indent=2)


# --------------------------------------------------------------------------- #
# Per-box handlers
# --------------------------------------------------------------------------- #
def do_cattle(aws, health, box, report):
    log("CATTLE — install, reboot, verify", C.B)
    st, _, err = aws.install(box["id"])
    log(f"  install: {st}", C.G if st == "Success" else C.R)
    reboot(aws, box)
    health.os_clean(box)
    if box["role"] in ("standalone-search", "heavy-forwarder", "deployer"):
        health.splunk_status(box)
    report.add(f"- **{box['name']}** (cattle/{box['role']}): install {st}, rebooted, checked.")
    return True


def do_shc(aws, health, box, any_member_id, report):
    log("PET (SHC member) — install, reboot, verify rejoin", C.B)
    aws.install(box["id"]); reboot(aws, box); health.splunk_status(box)
    log("  SHC status (confirm captain + all members Up):", C.Y)
    health.shcluster_status(any_member_id)
    ok = ask("  SHC healthy — proceed?", "n")
    report.add(f"- **{box['name']}** (pet/shc-member): patched, rejoin confirmed={ok}.")
    return ok


def do_manager(aws, health, box, report):
    log("PET (cluster manager) — patched alone, before peers", C.B)
    aws.install(box["id"]); reboot(aws, box); health.splunk_status(box)
    log("  Cluster status (confirm RF/SF Met, peers Up):", C.Y)
    health.cluster_status(box["id"])
    ok = ask("  Cluster green — proceed to peer phase?", "n")
    report.add(f"- **{box['name']}** (pet/cluster-manager): patched, green={ok}.")
    return ok


def do_peer(aws, health, box, manager_id, report):
    log("PET (indexer peer) — stage, offline, reboot, gate", C.B)
    aws.install(box["id"])
    log("  graceful splunk offline...", C.Y)
    splunk_cli(aws, health, box["id"], "offline")
    reboot(aws, box); health.splunk_status(box)
    log("  Cluster status — confirm peer Up, buckets recovered, RF/SF Met, no fixup:", C.Y)
    health.cluster_status(manager_id)
    ok = ask("  Cluster green — proceed to next peer?", "n")
    report.add(f"- **{box['name']}** (pet/indexer-peer): patched, cluster green={ok}.")
    return ok


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--region", default=os.environ.get("AWS_REGION", "eu-west-2"))
    ap.add_argument("--env", default="ref")
    ap.add_argument("--splunk-home", default="/opt/splunk")
    ap.add_argument("--secret-arn", default=None,
                    help="Secrets Manager ARN for Splunk admin (recommended)")
    ap.add_argument("--exclude", default="",
                    help="comma-separated names/IDs to drop (e.g. the runner box)")
    ap.add_argument("--state-file", default="patch_state.json")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--reset", action="store_true")
    args = ap.parse_args()

    if args.reset and os.path.exists(args.state_file):
        os.remove(args.state_file)

    aws = Aws(args.region, args.dry_run)
    state = load_state(args.state_file)
    report = Report(REPORT_FILE, args.env, args.region)
    exclude = [x.strip() for x in args.exclude.split(",") if x.strip()]

    log(f"Discovering '{args.env}' instances in {args.region}...", C.BOLD)
    boxes = aws.discover(args.env, exclude)
    if not boxes:
        sys.exit("No matching running instances found.")
    manager = next((b for b in boxes if b["role"] == "cluster-manager"), None)
    shc_member = next((b for b in boxes if b["role"] == "shc-member"), None)
    peers = [b for b in boxes if b["role"] == "indexer-peer"]

    # ---- CHECK FIRST: fleet scan + before table ----
    log("\nScanning fleet for current patch levels (no changes)...", C.BOLD)
    aws.scan_fleet([b["id"] for b in boxes])
    before = stats_table(aws, boxes, report,
                         "BEFORE — current patch compliance")

    hr()
    if not ask("Proceed to patch, in the order shown above?", "n"):
        sys.exit("Aborted after scan.")

    # ---- Splunk auth (Secrets Manager preferred) ----
    splunk_auth = None
    if any(b["tier"] == PET for b in boxes) and not args.dry_run:
        if args.secret_arn:
            u, p = aws.get_secret(args.secret_arn)
            splunk_auth = f"{u}:{p}"
            log("Splunk creds loaded from Secrets Manager.", C.DIM)
        else:
            log("No --secret-arn given; falling back to prompt (Secrets Manager "
                "is recommended).", C.Y)
            u = input("  Splunk admin username: ")
            splunk_auth = f"{u}:{getpass.getpass('  Splunk admin password: ')}"
    health = Health(aws, args.splunk_home, splunk_auth)

    # ---- INSTALL SECOND: walk boxes in order ----
    report.add("## Run log")
    for i, b in enumerate(boxes, 1):
        if b["id"] in state["done"]:
            continue
        hr()
        log(f"BOX {i} of {len(boxes)} — {b['name']}  "
            f"({b['role']}/{b['tier']}/{b['platform']})", C.BOLD)

        if b["role"] == "indexer-peer" and not state["maintenance_mode"]:
            if manager and ask("Enable cluster maintenance mode before peers?", "y"):
                splunk_cli(aws, health, manager["id"], "enable maintenance-mode")
                state["maintenance_mode"] = True; save_state(args.state_file, state)
                log("  maintenance mode ON", C.Y)

        if not ask("Patch this box now?", "n"):
            log("  skipped."); continue

        try:
            if b["tier"] == CATTLE:
                ok = do_cattle(aws, health, b, report)
            elif b["role"] == "shc-member":
                ok = do_shc(aws, health, b, shc_member["id"], report)
            elif b["role"] == "cluster-manager":
                ok = do_manager(aws, health, b, report)
            elif b["role"] == "indexer-peer":
                ok = do_peer(aws, health, b, manager["id"], report)
            else:
                ok = do_cattle(aws, health, b, report)
        except Exception as e:  # noqa
            log(f"  ERROR: {e}", C.R); ok = False

        if ok:
            state["done"].append(b["id"]); save_state(args.state_file, state)
            log(f"  box {i} complete and recorded.", C.G)
        else:
            log(f"  box {i} NOT confirmed healthy — stopping.", C.R)
            if state["maintenance_mode"]:
                log("  NOTE: maintenance mode still ON — decide whether to disable "
                    "it so the cluster can self-heal.", C.Y)
            report.add(f"\n**HALTED at {b['name']} (box {i}).**")
            sys.exit(1)

        if b["role"] == "indexer-peer" and peers and b["id"] == peers[-1]["id"] \
                and state["maintenance_mode"]:
            if ask("All peers done. Disable maintenance mode?", "y"):
                splunk_cli(aws, health, manager["id"], "disable maintenance-mode")
                state["maintenance_mode"] = False; save_state(args.state_file, state)
                log("  maintenance mode OFF", C.G)

    # ---- INSPECT AGAIN: re-scan + after table + diff ----
    hr()
    log("\nRe-scanning fleet to confirm patch levels...", C.BOLD)
    aws.scan_fleet([b["id"] for b in boxes])
    after = stats_table(aws, boxes, report, "AFTER — post-patch compliance")

    report.add("## Before vs after (missing / critical)")
    diff_rows = []
    for b in boxes:
        bi, af = before.get(b["name"]), after.get(b["name"])
        if bi and af:
            diff_rows.append([b["name"],
                              f"{bi[6]} -> {af[6]}",   # missing
                              f"{bi[7]} -> {af[7]}"])   # critical
    report.table(["name", "missing", "critical"], diff_rows)

    report.add(f"\n*Finished:* {dt.datetime.now().isoformat(timespec='seconds')}")
    hr()
    log("All boxes processed.", C.G + C.BOLD)
    if state["maintenance_mode"]:
        log("WARNING: maintenance mode still recorded ON — verify on the manager.", C.R)
    log(f"Report: {REPORT_FILE}   Log: {LOG_FILE}   State: {args.state_file}", C.DIM)


if __name__ == "__main__":
    main()
