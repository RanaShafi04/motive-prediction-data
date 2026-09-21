"""
02_clean_and_merge_sources.py
───────────────────────────────
STAGE 2 of 4 in the dataset pipeline.

Cleans AND merges in one pass: applies IDENTICAL normalisation, minimum-
length filtering, and Sabotage-handling rules to both the Tropchaud dataset
and your manually-collected new_campaign_sources.csv (MITRE Campaign / DFIR
report / CISA advisory entries), then de-duplicates across the combined
result.

Why this replaced two separate scripts:
  The old pipeline cleaned Tropchaud alone (clean_final_version.ipynb),
  and separately merged new sources into a DIFFERENT, uncleaned file
  (merge_files.ipynb's "MERGING NEW SOURCES" cell read final_union.csv,
  not the cleaned final_clean.csv, despite its own docstring saying
  otherwise). That meant new sources got a lighter/partially-different
  cleaning pass than Tropchaud, and the file that was actually supposed
  to feed stage 3 (prepare_dataset) was never the fully-cleaned,
  fully-merged one. See the audit notes for the full breakdown.

  Doing both sources through ONE cleaning function fixes that: whatever
  rules apply to Tropchaud apply identically to your manual sources, and
  there's only one output file to hand to stage 3.

What else changed vs. the old scripts:
  - normalise_seq() now only collapses CONSECUTIVE duplicate parent IDs
    (the artifact of sub-technique siblings sitting next to each other,
    e.g. T1059.001 -> T1059.003 -> T1059.006 all becoming T1059 three
    times in a row). Non-consecutive repeats of the same technique are
    PRESERVED, since those represent a technique genuinely re-used under
    a different tactic later in the sequence (e.g. T1078 appearing once
    under Initial Access and again later under Persistence) — this was
    being silently deduplicated away before.
  - Duplicate entity-name detection now checks the ENTIRE combined
    dataset (Tropchaud + new sources together), not just overlaps between
    the two files. The old script only checked cross-file overlaps, so
    two same-named rows that both came from new_campaign_sources.csv
    (as happened with your BlackSuit and ScatteredSpider rows before you
    fixed them by hand) were never caught by the automatic logic at all.
  - MIN_TECHNIQUES now applies to both sources equally. Before, it only
    filtered Tropchaud rows.
  - KEEP_SABOTAGE is defined ONCE, here, and this is the only stage that
    should ever touch Sabotage rows. (Stage 4 used to have its own
    separate, disconnected Sabotage filter — see that script's notes.)

  - Every row now carries a source_type column: "aggregate" for Tropchaud
    rows (confirmed to be MITRE Group/intrusion-set pages spanning an
    actor's entire multi-year documented history) vs "bounded_incident"
    for your manually-collected sources (each individually checked, over
    the course of this whole project, to represent one bounded attack or
    campaign rather than a cumulative capability profile). This makes the
    aggregate-vs-bounded distinction visible in the final dataset and in
    every duplicate-resolution decision, rather than disappearing once
    the two sources are combined.

  - Technique sequences are now sorted into canonical MITRE tactic order
    (Reconnaissance -> ... -> Impact) for EVERY row, not just Tropchaud's.
    Previously only Tropchaud rows were tactic-sorted (in stage 1); your
    manually-collected sources kept whatever order their source document
    happened to use, which varied (some CISA/DFIR/MITRE Campaign tables
    are already in tactic order, some aren't -- e.g. your LAUNDRY BEAR
    entry had Collection before Discovery, Pioneer Kitten had Execution
    after Credential Access). That inconsistency meant a model could
    partly learn "which pipeline did this row come from" rather than
    real signal. Uses the tactic_lookup.json built once in stage 1,
    rather than re-downloading the ATT&CK STIX data a second time here.

Inputs:
  tropchaud_dataset.csv       <- output of 01_build_tropchaud_source.py
  new_campaign_sources.csv    <- your manually-collected entries
  tactic_lookup.json          <- output of 01_build_tropchaud_source.py

Outputs:
  clean_dataset.csv           <- ready for 03_prepare_splits.py
  cleaning_report.txt         <- full log of every change made and why
"""

import json
import pandas as pd

# ── Config ────────────────────────────────────────────────────────────────────
TROPCHAUD_INPUT    = "tropchaud_dataset.csv"
NEW_INPUT          = "new_campaign_sources.csv"
TACTIC_LOOKUP_FILE = "tactic_lookup.json"
OUTPUT_FILE        = "clean_dataset.csv"
REPORT_FILE        = "cleaning_report.txt"

# Set to True to keep Sabotage as a third class (needs enough data to
# stratify — check class counts before flipping this).
# Set to False to drop Sabotage and run binary Espionage vs Financial.
# This is the ONLY place in the whole pipeline this should be set —
# stage 4 reads its class list directly from this stage's output rather
# than hardcoding its own copy of this decision.
# Set to False to exclude every aggregate-sourced row (currently: all of
# Tropchaud) and train only on your individually-vetted bounded-incident
# entries. Useful for directly comparing model performance with vs.
# without the aggregate rows, since that's an empirical question as much
# as a methodological one.
INCLUDE_AGGREGATE_SOURCES = True

KEEP_SABOTAGE = False

# Minimum number of techniques a sequence must have to be considered
# "complete enough" to keep. Applies to BOTH sources now.
MIN_TECHNIQUES = 5

# Explicit resolutions for entity names known to appear more than once,
# where the automatic rule (most techniques, then first occurrence)
# would pick the wrong one, or where sources disagree on motive and you
# want a specific one kept rather than whichever happens to have more
# techniques.
#   Key:   entity_name as it appears in the data
#   Value: which SOURCE value to keep (must match a value in the
#          "source" column, e.g. "Tropchaud", "MITRE", "DFIR", "CISA")
KEEP_SOURCE = {
    "CostaRicto":   "attack.mitre.org",
    "Night Dragon": "attack.mitre.org",
    # Add more here as you find them. Value is matched as a SUBSTRING of
    # the "source" column (which holds full URLs for new-source rows,
    # e.g. "attack.mitre.org", "thedfirreport.com", "cisa.gov" -- not
    # bare category labels like "MITRE"). Anything not listed falls back
    # to the automatic "most techniques wins" rule, and gets reported
    # either way so you can check the automatic choice was reasonable.
}

# If you'd rather keep every duplicate as its own distinct entry (e.g.
# your four separate Conti case studies), the real fix is renaming them
# in new_campaign_sources.csv so they're not literal duplicates
# (Conti_Case3584, Conti_Case4641, ...) BEFORE running this script.
# This script's job is only to resolve accidental duplicates, not to
# decide which genuinely-distinct incidents should be merged.


# ── Technique sequence normalisation ──────────────────────────────────────────
def normalise_seq(seq: str) -> str:
    """
    Strip sub-technique suffix from every technique ID, then collapse
    only CONSECUTIVE duplicate parent IDs (the sub-technique-sibling
    artifact). Non-consecutive repeats are preserved as genuine signal.
    e.g. 'T1059.001 -> T1059.003 -> T1078 -> T1059.005'
      ->  'T1059 -> T1078 -> T1059'          (NOT collapsed to one T1059)
    """
    result = []
    for tid in str(seq).split(" -> "):
        tid = tid.strip()
        parent = tid.split(".")[0]
        if not parent:
            continue
        if result and result[-1] == parent:
            continue  # only skip if identical to the immediately preceding entry
        result.append(parent)
    return " -> ".join(result)


def collapse_consecutive(techniques: list) -> list:
    """Same consecutive-only collapse as normalise_seq, but operating on
    an already-split list. Used after tactic-sorting to catch any new
    adjacencies the sort creates (see sort_by_tactic)."""
    result = []
    for t in techniques:
        if result and result[-1] == t:
            continue
        result.append(t)
    return result


def sort_by_tactic(seq: str, tactic_lookup: dict) -> str:
    """
    Sort a technique sequence into canonical MITRE tactic order using a
    stable sort (ties keep their original relative order). Techniques
    not found in the lookup (e.g. deprecated IDs that slipped through,
    or Mobile-domain IDs) sort to the end rather than raising.

    Applied AFTER normalise_seq, so this always operates on parent-level
    IDs -- tactic_lookup.json has entries for both parent and
    sub-technique IDs (inherited from stage 1's STIX parse), so parent-
    level lookups resolve correctly.

    A stable sort can bring two occurrences of the same technique
    together if they happen to map to the SAME tactic rank (e.g. two
    genuinely redundant mentions of T1078 both under Initial Access).
    That's a real duplicate worth collapsing, unlike two occurrences
    under DIFFERENT tactics (a genuine dual-tactic mapping), which the
    sort keeps apart. collapse_consecutive() here catches exactly that
    same-tactic case without touching the cross-tactic one.
    """
    techniques = [t.strip() for t in str(seq).split(" -> ")]
    techniques_sorted = sorted(techniques, key=lambda t: tactic_lookup.get(t, 99))
    return " -> ".join(collapse_consecutive(techniques_sorted))


# ── Deduplication (runs on the FULL combined dataset) ─────────────────────────
def resolve_duplicates(df: pd.DataFrame, report: list) -> pd.DataFrame:
    """
    For each duplicated entity_name anywhere in the combined dataset,
    resolve via KEEP_SOURCE if listed, otherwise keep the row with the
    most techniques (ties broken by first occurrence). Every resolution
    is logged so a real conflict is never dropped silently.
    """
    name_counts = df["entity_name"].value_counts()
    dup_names   = name_counts[name_counts > 1].index.tolist()

    if not dup_names:
        report.append("  No duplicate entity names found.")
        return df

    rows_to_drop = []

    for name in dup_names:
        group = df[df["entity_name"] == name].copy()

        report.append(f"\n  DUPLICATE: {name} ({len(group)} rows)")
        for _, r in group.iterrows():
            report.append(f"    - source_type={r['source_type']:16s} "
                          f"source={r['source']:12s} motive={r['motive']:12s} "
                          f"techs={r['num_techniques']}")

        match_idx = None
        if name in KEEP_SOURCE:
            substr = KEEP_SOURCE[name]
            matches = group[group["source"].astype(str).str.contains(substr, na=False)]
            if len(matches):
                match_idx = matches.index[0]

        if match_idx is not None:
            keep_idx = match_idx
            reason   = f"KEEP_SOURCE override -> kept source matching '{KEEP_SOURCE[name]}'"
        else:
            group_sorted = group.sort_values("num_techniques", ascending=False)
            keep_idx = group_sorted.index[0]
            reason   = f"auto: most techniques ({group_sorted.iloc[0]['num_techniques']})"
            if name in KEEP_SOURCE:
                reason += f"  [NOTE: KEEP_SOURCE listed '{KEEP_SOURCE[name]}' but no " \
                          f"row's source contains that substring for this name -- check spelling]"

        drop_idxs = [i for i in group.index if i != keep_idx]
        rows_to_drop.extend(drop_idxs)
        kept_type = df.loc[keep_idx, "source_type"]
        report.append(f"    -> KEPT row source_type={kept_type}, "
                      f"source={df.loc[keep_idx, 'source']}, "
                      f"techs={df.loc[keep_idx, 'num_techniques']}  ({reason})")

        # An aggregate row winning over a bounded-incident row -- via the
        # automatic "most techniques" rule specifically, not a deliberate
        # KEEP_SOURCE choice -- is exactly the wrong outcome by this
        # project's own standard: an aggregate will always have more
        # techniques than a single bounded incident, by construction, so
        # "most techniques wins" systematically favours the wrong source
        # whenever the two types collide. Flag it loudly rather than let
        # it pass as a routine resolution.
        dropped_types = set(df.loc[drop_idxs, "source_type"])
        if kept_type == "aggregate" and "bounded_incident" in dropped_types \
                and name not in KEEP_SOURCE:
            report.append(f"    !! WARNING: kept an AGGREGATE row over a BOUNDED_INCIDENT "
                          f"row for '{name}' via the automatic most-techniques rule. "
                          f"This is very likely the wrong choice -- add an explicit "
                          f"KEEP_SOURCE entry for '{name}' if you want the bounded "
                          f"incident kept instead.")

    return df.drop(index=rows_to_drop).reset_index(drop=True)


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    report = ["clean_and_merge_sources.py report", "=" * 60]

    # ── Load both sources ─────────────────────────────────────────────────────
    tropchaud = pd.read_csv(TROPCHAUD_INPUT)
    new       = pd.read_csv(NEW_INPUT)
    report.append(f"\nTropchaud rows:  {len(tropchaud)}")
    report.append(f"New-source rows: {len(new)}")

    try:
        with open(TACTIC_LOOKUP_FILE) as f:
            tactic_lookup = json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(
            f"{TACTIC_LOOKUP_FILE} not found -- run 01_build_tropchaud_source.py "
            f"first, it builds and saves this lookup as a side effect."
        )
    report.append(f"Tactic lookup: {len(tactic_lookup)} techniques (from {TACTIC_LOOKUP_FILE})")

    # Every new_campaign_sources row is individually vetted (over the
    # course of building this dataset) to represent one bounded incident,
    # as opposed to Tropchaud's aggregate Group-page rows. Tag it here if
    # the column isn't already present in the source file.
    if "source_type" not in new.columns:
        new["source_type"] = "bounded_incident"
        report.append("\nnew_campaign_sources.csv had no source_type column -- "
                      "tagged every row 'bounded_incident'.")
    else:
        report.append(f"\nnew_campaign_sources.csv already had a source_type column "
                      f"-- left as-is: {dict(new['source_type'].value_counts())}")

    combined = pd.concat([tropchaud, new], ignore_index=True)
    report.append(f"Combined rows (before any cleaning): {len(combined)}")

    if not INCLUDE_AGGREGATE_SOURCES:
        n_before_filter = len(combined)
        dropped_names = combined[combined["source_type"] == "aggregate"]["entity_name"].tolist()
        combined = combined[combined["source_type"] != "aggregate"].reset_index(drop=True)
        report.append(f"\nINCLUDE_AGGREGATE_SOURCES=False -> dropped {n_before_filter - len(combined)} "
                      f"aggregate rows entirely (all Tropchaud rows not already excluded): "
                      f"{len(combined)} rows remain")

    # Defensive strip: a stray leading/trailing space turns "Espionage"
    # and " Espionage" into two different classes as far as pandas is
    # concerned. This is a safety net -- if this line actually changes
    # anything, go find and fix the source row(s) too, since the same
    # typo may be duplicated elsewhere in that file.
    motive_before = set(combined["motive"].unique())
    combined["motive"] = combined["motive"].astype(str).str.strip()
    combined["entity_name"] = combined["entity_name"].astype(str).str.strip()
    combined["source"] = combined["source"].astype(str).str.strip()
    motive_after = set(combined["motive"].unique())
    if motive_before != motive_after:
        report.append(f"\n  WARNING: whitespace found in 'motive' values -- stripped. "
                      f"Before: {motive_before}  After: {motive_after}. "
                      f"Go check new_campaign_sources.csv for the untrimmed row(s).")

    # ── Step 1: technique-ID normalisation ────────────────────────────────────
    report.append("\n--- Step 1: Technique ID normalisation ---")
    before_vocab = set(
        t.strip() for seq in combined["technique_id_seq"] for t in str(seq).split("->")
    )
    combined["technique_id_seq"] = combined["technique_id_seq"].apply(normalise_seq)
    combined["num_techniques"]   = combined["technique_id_seq"].apply(
        lambda s: len(s.split(" -> ")))
    after_vocab = set(
        t.strip() for seq in combined["technique_id_seq"] for t in str(seq).split("->")
    )
    report.append(f"  Vocabulary before: {len(before_vocab)} unique IDs")
    report.append(f"  Vocabulary after:  {len(after_vocab)} unique IDs "
                  f"(sub-techniques collapsed to parent; consecutive dupes removed, "
                  f"non-consecutive dupes preserved)")
    report.append(f"  Technique count: mean {combined['num_techniques'].mean():.1f}, "
                  f"min {combined['num_techniques'].min()}, "
                  f"max {combined['num_techniques'].max()}")

    # ── Step 1b: tactic-order sorting (applies to BOTH sources equally) ───────
    report.append("\n--- Step 1b: Tactic-order sorting ---")
    # Track how many rows actually change order, split by source_type, so
    # you can see the fix's real impact rather than just trusting it ran.
    before_seqs = combined["technique_id_seq"].copy()
    combined["technique_id_seq"] = combined["technique_id_seq"].apply(
        lambda s: sort_by_tactic(s, tactic_lookup))
    changed_mask = combined["technique_id_seq"] != before_seqs
    report.append(f"  Rows reordered: {changed_mask.sum()} / {len(combined)}")
    for st in combined["source_type"].unique():
        st_mask = combined["source_type"] == st
        report.append(f"    {st}: {(changed_mask & st_mask).sum()} / {st_mask.sum()} reordered")

    # The post-sort collapse_consecutive() inside sort_by_tactic() can
    # shorten a sequence if two occurrences of the same technique ended
    # up adjacent under the same tactic rank. Recompute num_techniques
    # to reflect that.
    before_counts = combined["num_techniques"].copy()
    combined["num_techniques"] = combined["technique_id_seq"].apply(
        lambda s: len(s.split(" -> ")))
    shrunk = combined[combined["num_techniques"] < before_counts]
    if len(shrunk):
        report.append(f"  {len(shrunk)} rows lost 1+ technique to a new same-tactic "
                      f"adjacency created by sorting: "
                      f"{', '.join(shrunk['entity_name'].tolist())}")
    else:
        report.append("  No rows shortened by the post-sort collapse.")

    # ── Step 2: deduplicate entity names across the FULL combined dataset ────
    report.append("\n--- Step 2: Deduplication (full combined dataset) ---")
    n_before = len(combined)
    combined = resolve_duplicates(combined, report)
    n_after  = len(combined)
    report.append(f"\n  Rows before: {n_before}  ->  after: {n_after}  "
                  f"(removed {n_before - n_after})")

    # ── Step 3: minimum-length filtering (applies to both sources equally) ───
    report.append("\n--- Step 3: Minimum-length filtering ---")
    short_seqs = combined[combined["num_techniques"] < MIN_TECHNIQUES] \
        .sort_values("num_techniques")
    report.append(f"  Threshold: MIN_TECHNIQUES = {MIN_TECHNIQUES}")
    if len(short_seqs):
        report.append("  Removed: " + ", ".join(
            f"{n} ({c}, {s})" for n, c, s in
            zip(short_seqs["entity_name"], short_seqs["num_techniques"], short_seqs["source"])
        ))
    else:
        report.append("  Removed: none")
    combined = combined[combined["num_techniques"] >= MIN_TECHNIQUES].reset_index(drop=True)
    report.append(f"  Rows remaining: {len(combined)}")

    # ── Step 4: Sabotage handling ──────────────────────────────────────────────
    report.append("\n--- Step 4: Sabotage handling ---")
    sab_actors = combined[combined["motive"] == "Sabotage"]["entity_name"].tolist()
    report.append(f"  Sabotage actors found ({len(sab_actors)}): "
                  f"{', '.join(sab_actors) if sab_actors else 'none'}")
    if not KEEP_SABOTAGE:
        combined = combined[combined["motive"] != "Sabotage"].reset_index(drop=True)
        report.append(f"  KEEP_SABOTAGE=False -> dropped {len(sab_actors)} Sabotage actors")
    else:
        report.append("  KEEP_SABOTAGE=True -> Sabotage retained")

    # ── Step 5: unhandled motive categories check ─────────────────────────────
    # Flags anything that isn't Espionage/Financial/Sabotage so it doesn't
    # silently ride along as an unplanned extra class into stage 3/4.
    report.append("\n--- Step 5: Motive category check ---")
    expected_motives = {"Espionage", "Financial"} | ({"Sabotage"} if KEEP_SABOTAGE else set())
    actual_motives = set(combined["motive"].unique())
    unexpected = actual_motives - expected_motives
    if unexpected:
        report.append(f"  WARNING: unexpected motive categories present: {unexpected}")
        report.append(f"  These rows will still be in {OUTPUT_FILE} -- decide explicitly "
                      f"whether to keep, relabel, or drop them before stage 3.")
        for m in unexpected:
            names = combined[combined["motive"] == m]["entity_name"].tolist()
            report.append(f"    {m}: {', '.join(names)}")
    else:
        report.append(f"  All rows fall within expected categories: {expected_motives}")

    # ── Step 6: final duplicate check (belt-and-suspenders) ───────────────────
    report.append("\n--- Step 6: Final duplicate check ---")
    remaining_dups = combined[combined.duplicated(subset=["entity_name"], keep=False)]
    if len(remaining_dups) > 0:
        report.append(f"  WARNING: {len(remaining_dups)} duplicate entity names still "
                      f"remain after resolution -- this should not happen. Investigate:")
        report.append(remaining_dups[["entity_name", "motive", "source"]].to_string())
    else:
        report.append("  No duplicate entity names remain.")

    # ── Save ──────────────────────────────────────────────────────────────────
    combined.to_csv(OUTPUT_FILE, index=False)

    report.append("\n--- Final dataset ---")
    report.append(f"  Total actors: {len(combined)}")
    report.append(f"  Motive counts: {dict(combined['motive'].value_counts())}")
    report.append(f"  Source counts: {dict(combined['source'].value_counts())}")
    report.append(f"  Source-type counts: {dict(combined['source_type'].value_counts())}")
    report.append(f"    (aggregate = MITRE Group page, spans an actor's full documented "
                  f"history; bounded_incident = one specific attack/campaign. See your "
                  f"methodology write-up for how you're treating this distinction.)")
    report.append(f"  Technique count: mean {combined['num_techniques'].mean():.1f}, "
                  f"median {combined['num_techniques'].median():.0f}, "
                  f"min {combined['num_techniques'].min()}, "
                  f"max {combined['num_techniques'].max()}")

    report_str = "\n".join(report)
    with open(REPORT_FILE, "w") as f:
        f.write(report_str)

    print(report_str)
    print(f"\n[OK] Saved: {OUTPUT_FILE}")
    print(f"[OK] Saved: {REPORT_FILE}")
    print("\n[*] Next step: run 03_prepare_splits.py")


if __name__ == "__main__":
    main()
