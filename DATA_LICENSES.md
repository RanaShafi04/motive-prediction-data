# Data provenance and licences

* **tropChaud, Categorized Adversary TTPs** (GitHub, first merge 24 May 2022): repository under the MIT licence. It merges
  MITRE ATT&CK group-to-technique links with the structured metadata of the ETDA/ThaiCERT Threat Group Cards.
* **ETDA / ThaiCERT, Threat Group Cards: A Threat Actor Encyclopedia** (https://apt.etda.or.th): published under
  Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0), (c) Electronic Transactions
  Development Agency. The motive labels of the aggregate entries derive from this source.
* **MITRE ATT&CK** (https://attack.mitre.org): technique identifiers, group-technique links and Campaign objects are used
  under MITRE's terms of use. ATT&CK is a registered trademark of The MITRE Corporation.
* **Manually extracted entries** (`new_campaign_sources.csv`): technique lists taken from public MITRE Campaign pages, DFIR Report
  write-ups and CISA, national CERT and vendor advisories; each row's `source` column gives the URL.

Proposed licence for the released data files: **CC BY-NC-SA 4.0**, because the ShareAlike clause of the ETDA-derived material
applies to derivatives. Code: MIT. (To be confirmed by the authors before public release.)
