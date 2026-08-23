# Data Protection Impact Assessment (DPIA) Template

This template provides a starting point for conducting a
Data Protection Impact Assessment (DPIA) when deploying the privacy
risk detection platform.  It follows guidance from the GDPR and the
European Data Protection Board (EDPB).  Replace bracketed text with
information specific to your organisation and dataset.

## 1. Description of the processing

* **Controller:** [Name of organisation]
* **Purpose:** Identify and remediate privacy risks in datasets prior
  to analysis or sharing.  The tool parses uploaded files, detects
  personal data (e.g. names, addresses, IDs, medical data) and
  suggests remediations.
* **Data categories:** [Describe the types of personal data involved,
  e.g. patient notes, customer records].  Special categories of
  personal data (health, genetic, biometric) may be included when
  using the Medical/PHI profile.
* **Data subjects:** [Describe whose data is processed, e.g. patients,
  employees, customers].
* **Volume and frequency:** [Estimate size of datasets (e.g. > 2 GB
  CSV) and how often scans will be performed].
* **Technology:** Local deployment using Docker; no outbound data
  transfers.  Processing is performed using regex patterns,
  dictionaries and optional NLP models.  Results are stored in a
  PostgreSQL database; raw data is not stored by default.

## 2. Necessity and proportionality of the processing

* **Legal basis:** [Identify the legal basis under GDPR Article 6 or
  Article 9 if special categories are processed].  The platform does
  not itself create a legal basis; controllers must ensure that one
  exists prior to scanning.
* **Proportionality:** Only metadata about detected findings is
  retained.  Raw data is processed in streaming mode and discarded
  immediately.  Custom profiles allow controllers to limit detection
  to specific fields, supporting data minimisation.
* **Data subject rights:** Mechanisms exist to support data subject
  access, rectification, erasure, restriction, portability and
  objection (see mapping table).  Controllers must ensure that
  procedures are in place to honour requests within statutory
  timeframes.

## 3. Assessment of risks to rights and freedoms

1. **Unauthorized access to findings** - Risk that sensitive
   information (e.g. health data) could be accessed by unauthorized
   personnel.  *Likelihood:* medium; *Impact:* high.
2. **Re-identification through audit logs** - Even with metadata
   storage, combining findings with other information might identify
   individuals.  *Likelihood:* low; *Impact:* medium.
3. **False positives/false negatives** - Misclassification of data
   could lead to over-masking (reducing utility) or under-masking
   (exposing personal data).  *Likelihood:* medium; *Impact:* medium.
4. **Excessive storage** - Enabling raw data storage without timely
   deletion could contravene storage limitation.
5. **Model bias** - NLP models may perform poorly on minority names
   or dialects, potentially resulting in discriminatory outcomes.

## 4. Measures to address risks

1. **RBAC and least-privilege** - Only authorised users can start
   scans or view results.  Roles restrict access to sensitive
   endpoints.  Access logs support accountability.
2. **Encryption** - TLS protects data in transit; disk encryption and
   encryption at the application layer protect data at rest.  Keys
   are stored in environment variables separate from the codebase.
3. **Configurable retention** - Administrators can configure how long
   findings and raw files are retained; the default is to store only
   findings and delete raw data immediately.  A cron job or Celery
   beat task enforces retention policies.
4. **Human review** - A false-positive review queue allows users to
   mark and correct mis-detected entities.  Model confidence scores
   are surfaced to guide reviewers.
5. **Model selection and validation** - Use only locally downloaded
   models with documented performance; evaluate them on a sample
   representative of your data.  Consider disabling NLP detection if
   no trustworthy model is available.
6. **Documentation and training** - Provide users with guidance on
   interpretation of risk scores and remediations.  Train staff on
   privacy principles and the importance of data minimisation.

## 5. Consultation with stakeholders

Depending on context, the controller should consult with the Data
Protection Officer (DPO), works council, employee representatives or
external stakeholders.  Document any feedback and incorporate
recommendations.

## 6. Conclusion

Summarise whether the identified residual risks are acceptable in
light of the purposes of the processing and the measures implemented.
If high risks remain, consider additional safeguards or refrain from
processing.  The DPIA should be revisited whenever the processing
changes (e.g. new data sources, updated models).