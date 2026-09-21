# Early prediction of attacker motive from partial MITRE ATT&CK technique sequences

Anonymised artefact for double-anonymous review. It contains the dataset, the pipeline scripts and the
composition experiment behind the paper's results.

## Layout

    data/
      tropchaud_dataset.csv           aggregate entries (stage 1 output; ATT&CK groups with ETDA-derived motive labels)
      new_campaign_sources.csv        manually extracted bounded-incident entries (input to stage 2)
      tactic_lookup.json              technique -> tactic-phase rank (stage 1 output)
      clean_dataset.csv               final combined dataset: 188 actors (96 aggregate + 92 bounded)
      clean_dataset_bounded_only.csv  bounded-incident-only configuration: 97 actors
    code/
      01_build_tropchaud_source.py    build the aggregate source and the tactic lookup
      02_clean_and_merge_sources.py   normalise, deduplicate, tactic-sort, merge (flag INCLUDE_AGGREGATE_SOURCES)
      03_prepare_splits.py            actor-level stratified 70/15/15 split
      04_train_and_evaluate.ipynb     prefix expansion, features, five classifiers, metrics and figures
    composition_experiment/
      sensitivity.py                  five seeds x two configurations, model chosen on validation accuracy
      sensitivity_all_models.csv      results of every model on every split

## Dataset columns

`entity_name`, `technique_id_seq` (parent-level ATT&CK technique IDs joined by " -> ", in canonical tactic order),
`num_techniques`, `motive` (Espionage or Financial), `source`, `source_type` (`aggregate` = ATT&CK group profile
spanning an actor's documented history; `bounded_incident` = one specific incident or campaign).

## Reproducing the results

1. `python code/01_build_tropchaud_source.py` (needs the tropChaud CSV and network access to the ATT&CK STIX data), or use
   the provided `data/tropchaud_dataset.csv` and `data/tactic_lookup.json`.
2. `python code/02_clean_and_merge_sources.py` writes `clean_dataset.csv` (188 actors). Setting
   `INCLUDE_AGGREGATE_SOURCES = False` gives the bounded-only configuration (97 actors, which includes five actors
   whose bounded entries the combined dataset drops in favour of the aggregate entry).
3. `python code/03_prepare_splits.py` (seed 42) and then run `code/04_train_and_evaluate.ipynb`.
4. `python composition_experiment/sensitivity.py` (seeds 42-46) after placing `clean_all.csv` (combined) and
   `clean_bounded.csv` (bounded only) next to it. The scripts expect their input files in the working directory.

Composition-experiment environment: Python 3.12, scikit-learn 1.8.0, LightGBM 4.7.0. Exact numbers can differ slightly
with other library versions.

## Notes

* Sequences are ordered by ATT&CK tactic phase, not by time (see the paper's threats to validity).
* Comments in the scripts describe earlier cleanup of the pipeline and are kept as written.
* Licences and data provenance: see `DATA_LICENSES.md`.
