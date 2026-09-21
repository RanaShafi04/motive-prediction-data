"""
03_prepare_splits.py
──────────────────────
STAGE 3 of 4 in the dataset pipeline.

Splits the cleaned, merged dataset into actor-level train/val/test sets
and builds the label encoder.

What changed vs. the old prepare_dataset.ipynb:
  - INPUT_FILE now points at clean_dataset.csv, the actual output of
    stage 2 — the old script pointed at "final_clean (2).csv", a
    Colab re-upload artifact that almost certainly meant it was reading
    an old, pre-merge copy of the Tropchaud-only cleaned file rather than
    the fully merged dataset. That silent mismatch is the reason this
    whole pipeline got rebuilt — see the stage 2 docstring for the full
    chain of filename mismatches.
  - No other logic changes: same stratified actor-level split, same
    no-overlap guarantee, same outputs.

Input:
  clean_dataset.csv          <- output of 02_clean_and_merge_sources.py

Outputs:
  train.csv, val.csv, test.csv
  label_encoder.json
  split_summary.txt
"""

import json
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

# ── Config ────────────────────────────────────────────────────────────────────
INPUT_FILE   = "clean_dataset.csv"
TRAIN_RATIO  = 0.70
VAL_RATIO    = 0.15
TEST_RATIO   = 0.15   # must sum to 1.0
RANDOM_STATE = 42


def main():
    print("[*] Loading data...")
    df = pd.read_csv(INPUT_FILE)
    print(f"    Total actors: {len(df)}")
    print(f"\n    Motive distribution:")
    print(df["motive"].value_counts().to_string())

    # Sanity check: this stage assumes stage 2 already resolved every
    # duplicate entity name. If it hasn't, the no-overlap assertion below
    # will fail loudly rather than silently splitting one actor across
    # train/val/test.
    dup_check = df[df.duplicated(subset=["entity_name"], keep=False)]
    if len(dup_check) > 0:
        raise ValueError(
            f"clean_dataset.csv still contains {len(dup_check)} duplicate "
            f"entity_name rows -- go back to stage 2 and resolve these "
            f"before splitting:\n{dup_check[['entity_name', 'source']].to_string()}"
        )

    print(f"\n[*] Splitting by actor (train={TRAIN_RATIO}, val={VAL_RATIO}, "
          f"test={TEST_RATIO})...")

    motive_counts = df["motive"].value_counts()
    rare_motives  = motive_counts[motive_counts < 3].index.tolist()

    if rare_motives:
        print(f"    WARNING: classes too rare to stratify: {rare_motives}")
        print(f"      These will be assigned entirely to train.")

    rare_df   = df[df["motive"].isin(rare_motives)]
    common_df = df[~df["motive"].isin(rare_motives)]

    train_df, temp_df = train_test_split(
        common_df,
        test_size=(VAL_RATIO + TEST_RATIO),
        stratify=common_df["motive"],
        random_state=RANDOM_STATE,
    )

    temp_counts  = temp_df["motive"].value_counts()
    rare_in_temp = temp_counts[temp_counts < 2].index.tolist()

    if rare_in_temp:
        print(f"    WARNING: classes with 1 actor in temp split: {rare_in_temp}")
        print(f"      Moving these to train.")
        rare_temp_df = temp_df[temp_df["motive"].isin(rare_in_temp)]
        temp_df      = temp_df[~temp_df["motive"].isin(rare_in_temp)]
        train_df     = pd.concat([train_df, rare_temp_df], ignore_index=True)

    val_df, test_df = train_test_split(
        temp_df,
        test_size=TEST_RATIO / (VAL_RATIO + TEST_RATIO),
        stratify=temp_df["motive"],
        random_state=RANDOM_STATE,
    )

    train_df = pd.concat([train_df, rare_df], ignore_index=True)

    print(f"    Train actors: {len(train_df)}")
    print(f"    Val actors:   {len(val_df)}")
    print(f"    Test actors:  {len(test_df)}")

    # No actor overlap between splits
    assert len(set(train_df["entity_name"]) & set(val_df["entity_name"]))  == 0
    assert len(set(train_df["entity_name"]) & set(test_df["entity_name"])) == 0
    assert len(set(val_df["entity_name"])   & set(test_df["entity_name"])) == 0
    print("    [OK] No actor overlap between splits.")

    train_df.to_csv("train.csv", index=False)
    val_df.to_csv("val.csv",     index=False)
    test_df.to_csv("test.csv",   index=False)

    le        = LabelEncoder()
    le.fit(df["motive"])
    label_map = {label: int(idx) for idx, label in enumerate(le.classes_)}
    print(f"\n    Label map: {label_map}")

    with open("label_encoder.json", "w") as f:
        json.dump(label_map, f, indent=2)

    summary_lines = [
        "=" * 55,
        "Split Summary",
        "=" * 55,
        f"Input actors:  {len(df)}",
        f"  Train:       {len(train_df)} actors",
        f"  Val:         {len(val_df)} actors",
        f"  Test:        {len(test_df)} actors",
        "",
        f"Label map: {label_map}",
        "",
        "Train motive distribution:",
        train_df["motive"].value_counts().to_string(),
        "",
        "Val motive distribution:",
        val_df["motive"].value_counts().to_string(),
        "",
        "Test motive distribution:",
        test_df["motive"].value_counts().to_string(),
    ]
    summary = "\n".join(summary_lines)
    print("\n" + summary)
    with open("split_summary.txt", "w") as f:
        f.write(summary)

    print("\n[OK] Outputs saved:")
    print("    train.csv")
    print("    val.csv")
    print("    test.csv")
    print("    label_encoder.json")
    print("    split_summary.txt")
    print("\n[*] Next step: run 04_train_and_evaluate.py")


if __name__ == "__main__":
    main()
