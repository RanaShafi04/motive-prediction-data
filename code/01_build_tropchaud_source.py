"""
01_build_tropchaud_source.py
─────────────────────────────
STAGE 1 of 4 in the dataset pipeline.

Builds a clean, tactic-ordered base dataset from the raw Tropchaud export
(Categorized_Adversary_TTPs.csv). This is the ONLY script that touches the
Tropchaud file directly — every later stage works from this script's output.

What changed vs. the old merge_files.ipynb:
  - Removed an exact-duplicate cell that re-ran this entire script a second
    time on every execution (including a redundant ~40MB ATT&CK STIX
    re-download), silently overwriting the first run's motive labels.
  - The old script produced BOTH "Political-Espionage" and "Espionage" as
    possible values for the same underlying Tropchaud motivation
    ("information theft and espionage"), depending on which duplicate cell
    ran last. This script has one motivation map, with one answer:
    "Espionage".
  - The "merge new campaign sources" step used to live inside this same
    file and ran too early (before cleaning). It has been moved out
    entirely — see 02_clean_and_merge_sources.py, which is now the single
    place both Tropchaud and manually-collected sources get cleaned and
    combined.

Input:
  Categorized_Adversary_TTPs.csv   (Tropchaud export, in the working directory)

Output:
  tropchaud_dataset.csv
    columns: entity_name, technique_id_seq, num_techniques, motive, source,
             source_type
    (source is always "Tropchaud" here; source_type is always "aggregate"
     -- see the source_type comment in main() for why)
  tactic_lookup.json
    {technique_id: tactic_rank} for every ATT&CK technique, built once
    here from the STIX data and reused by 02_clean_and_merge_sources.py
    so that script doesn't need its own ~25,000-object STIX download to
    tactic-sort the combined dataset.
"""

import ast
import io
import json
import requests
import pandas as pd
from stix2 import MemoryStore, Filter

# ── Config ────────────────────────────────────────────────────────────────────
TROPCHAUD_FILE     = "Categorized_Adversary_TTPs.csv"
OUTPUT_FILE        = "tropchaud_dataset.csv"
TACTIC_LOOKUP_FILE = "tactic_lookup.json"

ATTCK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
    "/master/enterprise-attack/enterprise-attack.json"
)

TACTIC_ORDER = {
    "reconnaissance": 0, "resource-development": 1, "initial-access": 2,
    "execution": 3, "persistence": 4, "privilege-escalation": 5,
    "defense-evasion": 6, "credential-access": 7, "discovery": 8,
    "lateral-movement": 9, "collection": 10, "command-and-control": 11,
    "exfiltration": 12, "impact": 13,
}

# One motivation map, one answer per key. (Previously this had two
# competing versions across two duplicate cells — see docstring above.)
MOTIVATION_MAP = {
    "information theft and espionage": "Espionage",
    "espionage":                       "Espionage",
    "financial crime":                 "Financial",
    "financial gain":                  "Financial",
    "cybercrime":                      "Financial",
    "sabotage":                        "Sabotage",
    "destruction":                     "Sabotage",
    "hacktivism":                      "Protest",
    "unknown":                         "Undetermined",
}


# ── Repair broken outer-quoting in the source CSV ─────────────────────────────
def load_and_repair_csv(path: str) -> pd.DataFrame:
    """
    The Tropchaud export wraps every data row in one extra, erroneous layer
    of double quotes, with internal quotes doubled ("" instead of "). This
    breaks standard CSV column splitting. Strip the outer layer and
    un-double internal quotes line-by-line, then parse as normal CSV.
    """
    with open(path, encoding="utf-8") as f:
        raw_lines = f.readlines()

    header = raw_lines[0]
    fixed_lines = [header]

    for line in raw_lines[1:]:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        if line.startswith('"'):
            inner = line[1:]
            if inner.endswith('"'):
                inner = inner[:-1]
            inner = inner.replace('""', '"')
            fixed_lines.append(inner + "\n")
        else:
            fixed_lines.append(line + "\n")

    repaired_text = "".join(fixed_lines)
    df = pd.read_csv(io.StringIO(repaired_text))
    print(f"    -> Repaired and parsed {len(df)} rows from {path}.")
    return df


# ── Helpers ──────────────────────────────────────────────────────────────────
def parse_list_field(val) -> list:
    try:
        parsed = ast.literal_eval(str(val))
        if isinstance(parsed, list):
            return [str(x).strip() for x in parsed]
    except Exception:
        pass
    return [str(val).strip()] if pd.notna(val) and str(val).strip() else []


def normalize_motivation(val) -> str:
    motives = parse_list_field(val)
    if not motives:
        return "Undetermined"
    m = motives[0].lower().strip()
    for key, label in MOTIVATION_MAP.items():
        if key in m:
            return label
    return motives[0]


# ── Load ATT&CK STIX and build technique -> tactic-rank lookup ───────────────
def load_attck() -> MemoryStore:
    print("[*] Downloading ATT&CK STIX data...")
    resp = requests.get(ATTCK_URL, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    print(f"    -> {len(data['objects'])} STIX objects loaded.")
    return MemoryStore(stix_data=data["objects"])


def build_tactic_lookup(src: MemoryStore) -> dict:
    """Returns {technique_id: tactic_rank} for all ATT&CK techniques."""
    lookup = {}
    techniques = src.query([Filter("type", "=", "attack-pattern")])
    for tech in techniques:
        ext_refs = getattr(tech, "external_references", [])
        tid = next(
            (r.external_id for r in ext_refs if r.source_name == "mitre-attack"),
            None
        )
        if not tid:
            continue
        phases = getattr(tech, "kill_chain_phases", [])
        ranks = [
            TACTIC_ORDER.get(p.phase_name, 99)
            for p in phases if p.kill_chain_name == "mitre-attack"
        ]
        lookup[tid] = min(ranks) if ranks else 99
    print(f"    -> Tactic lookup built for {len(lookup)} techniques.")
    return lookup


def sort_ttps(ttp_list: list, tactic_lookup: dict) -> list:
    return sorted(ttp_list, key=lambda t: tactic_lookup.get(t, 99))


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print("[*] Loading Tropchaud dataset...")
    tp = load_and_repair_csv(TROPCHAUD_FILE)
    print(f"    Tropchaud: {len(tp)} actors")

    src = load_attck()
    tactic_lookup = build_tactic_lookup(src)

    with open(TACTIC_LOOKUP_FILE, "w") as f:
        json.dump(tactic_lookup, f)
    print(f"    -> Saved tactic lookup to {TACTIC_LOOKUP_FILE} for reuse by stage 2.")

    print("[*] Processing Tropchaud actors...")
    rows = []
    skipped = 0
    for _, row in tp.iterrows():
        ttp_list = parse_list_field(row["mitre_attack_ttps"])
        if not ttp_list:
            skipped += 1
            continue
        ttp_sorted = sort_ttps(ttp_list, tactic_lookup)
        rows.append({
            "entity_name":      row["mitre_attack_name"],
            "technique_id_seq": " -> ".join(ttp_sorted),
            "num_techniques":   len(ttp_sorted),
            "motive":           normalize_motivation(row.get("motivation", "")),
            "source":           "Tropchaud",
            # Every Tropchaud row is built from a MITRE Group
            # (STIX "intrusion-set") object -- confirmed by checking every
            # row's mitre_attack_id prefix, all 124 of which are
            # "intrusion-set--...". A Group page aggregates an actor's
            # technique usage across its ENTIRE documented history, often
            # spanning several years and many unrelated operations, not
            # one bounded incident. Tagging this explicitly rather than
            # silently treating it the same as a bounded campaign/DFIR
            # entry, so this distinction survives into the final dataset
            # and can be reported on, filtered on, or explained in your
            # methodology section.
            "source_type":      "aggregate",
        })

    final = pd.DataFrame(rows).reset_index(drop=True)
    print(f"    -> {len(final)} actors added ({skipped} skipped, no TTPs).")

    final.to_csv(OUTPUT_FILE, index=False)

    print(f"\n{'=' * 50}")
    print("Summary")
    print(f"{'=' * 50}")
    print(f"Total in {OUTPUT_FILE}: {len(final)}")
    print(f"\nMotive distribution:")
    print(final["motive"].value_counts().to_string())
    print(f"\nSequence length stats:")
    print(final["num_techniques"].describe().to_string())
    print(f"\n[OK] Saved: {OUTPUT_FILE}")
    print("[*] Next step: run 02_clean_and_merge_sources.py")


if __name__ == "__main__":
    main()
