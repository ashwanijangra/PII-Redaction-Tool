# PII Redaction Tool

A production-grade, local, rule- and context-aware Personally Identifiable Information (PII) detection and redaction engine for Microsoft Word (`.docx`) documents. Specifically optimized for complex financial prospectuses (such as the 127-page *Red Herring Prospectus*) and corporate filings, the tool detects sensitive entities, replaces them with realistic synthetic data using Faker, and guarantees deterministic consistency for repeated entities without altering underlying document styling, table layouts, or headers/footers.

---

## 1. Objective

Financial prospectuses, regulatory filings, and corporate legal documents contain dense mixtures of sensitive personal data (promoter/director names, residential and corporate addresses, contact emails, direct phone lines) intermixed with non-sensitive business data (share quantities, issue amounts, CIN/DIN numbers, statutory dates, and financial ratios). 

Generic regex matchers or blind redaction pipelines often destroy formatting, corrupt table cells, or indiscriminately redact monetary values and dates.

The **PII Redaction Tool** provides:
1. **High-Precision Contextual Detection**: Distinguishes real PII from financial numbers and statutory disclosures.
2. **Run-Aware XML Formatting Preservation**: Replaces text inside DOCX runs without resetting fonts, styles, bold/italic markup, or table grids.
3. **Deterministic Synthetic Replacement**: Identical original PII values always receive identical synthetic replacements across the document run.
4. **Local Execution**: Completely offline, requiring zero paid APIs or cloud dependencies.

---

## 2. Features & Supported PII Categories

The tool detects and redacts 9 core PII categories:

1. **Full Names (`FULL_NAME`)**: Identifies promoters, directors, key management personnel (KMP), company secretaries, compliance officers, and signatory individuals using contextual role signals (`Contact Person:`, `Managing Director:`, `Chairman:`, `Mr./Ms./Dr.`, `namely`, `being`).
2. **Email Addresses (`EMAIL`)**: RFC 5322-compliant email recognizer capturing corporate, officer, and intermediary emails.
3. **Phone Numbers (`PHONE`)**: Indian mobile numbers (`+91 9876543210`, `9876543210`), STD landlines (`+91 20 4505 3237`, `022-22881234`), and international formats.
4. **Company Names (`COMPANY`)**: Corporate entities and legal bodies (`Limited`, `Private Limited`, `LLP`, `Inc.`, `Corporation`) with legal suffix matching and financial stopword filters.
5. **Physical / Mailing Addresses (`ADDRESS`)**: Contextual and multi-segment Indian office/residential addresses containing street, locality, city, state, and 6-digit postal PIN codes.
6. **Social Security Numbers (`SSN`)**: Standard US SSN format (`123-45-6789`) with validation against invalid area codes (`000`, `666`, `900–999`).
7. **Credit Card Numbers (`CREDIT_CARD`)**: 13–19 digit card numbers with space/hyphen formatting, strictly validated via the **Luhn mod-10 algorithm** to eliminate false matches on financial data rows.
8. **Dates of Birth (`DOB`)**: Context-anchored dates (`DOB:`, `Date of Birth:`, `Born:`) to prevent redacting offer closing dates, fiscal year ends, or statutory dates.
9. **IP Addresses (`IP_ADDRESS`)**: IPv4 addresses validated for 0–255 octet bounds with software version string suppression (e.g., `v1.2.3.4`).

---

## 3. Tech Stack

- **Language**: Python 3.10+
- **DOCX Processing**: `python-docx` (XML element and run-level DOM traversal)
- **Synthetic Data Generation**: `Faker` (with `en_IN` for Indian locale and `en_US` fallback)
- **Testing & Verification**: `pytest`

---

## 4. Architecture & Pipeline

```
                       ┌───────────────────────────────┐
                       │     Input DOCX Document       │
                       │ ("Red Herring Prospectus.docx")│
                       └──────────────┬────────────────┘
                                      │
                                      ▼
                       ┌───────────────────────────────┐
                       │     DOM Traversal Engine      │
                       │ (Paragraphs, Tables, Headers) │
                       └──────────────┬────────────────┘
                                      │
                                      ▼
                       ┌───────────────────────────────┐
                       │    Context-Aware Detectors    │
                       │  (9 Categories + Validators)  │
                       └──────────────┬────────────────┘
                                      │
                                      ▼
                       ┌───────────────────────────────┐
                       │     Deterministic Cache       │
                       │  (Original -> Synthetic Map)  │
                       └──────────────┬────────────────┘
                                      │
                                      ▼
                       ┌───────────────────────────────┐
                       │  Run-Aware In-Place Replacer  │
                       │  (Preserves Bold/Italic/Font) │
                       └──────────────┬────────────────┘
                                      │
                 ┌────────────────────┴────────────────────┐
                 ▼                                         ▼
   ┌───────────────────────────┐             ┌───────────────────────────┐
   │       Redacted DOCX       │             │ Replacement Mapping Audit │
   │ (output/redacted_....docx)│             │ (reports/replacement_...) │
   └───────────────────────────┘             └───────────────────────────┘
```

### Processing Steps:
1. **Extraction & Traversal**: Iterates across document elements (body paragraphs, tables, nested table cells, section headers, section footers) while deduplicating underlying XML references.
2. **Detection & Validation**: Evaluates text spans with regex and contextual heuristics, discarding non-PII financial patterns (e.g. Luhn algorithm filters for card numbers, octet checks for IPs, prefix checks for SSNs).
3. **Synthetic Generation**: Normalized keys `(PIIType, NormalizedValue)` query a run-scoped memory cache. New entities receive realistic synthetic data from Faker; previously observed entities receive the exact same synthetic replacement.
4. **Run-Level Replacement**: Maps character span offsets directly back to individual DOCX `<w:r>` XML run elements. Splitting and trimming occurs in-place, preserving surrounding bold/italic font styling and table structures.

---

## 5. False Positive Handling & Context Guards

Financial prospectuses present unique challenges for PII detectors. The tool applies explicit guardrails:

- **Share Quantities & Financial Figures vs. Phone Numbers**: Numbers preceded by currency symbols (`₹`, `Rs.`, `INR`, `$`) or terms like `shares` / `Equity Shares` are suppressed.
- **Corporate Identity (CIN/DIN) vs. Identification**: CIN codes (`U28129PN1979PLC141032`) and DIN numbers are not flagged as SSNs or credit cards.
- **Luhn Algorithm Checksum for Cards**: 16-digit account numbers or financial figures are only flagged as credit cards if they satisfy the Luhn mod-10 formula.
- **Context-Bound DOBs**: Only dates explicitly anchored by labels like `DOB:`, `Date of Birth:`, or `Born:` are classified as DOBs. Statutory dates ("Fiscal Year ended March 31, 2024", "offer closes on December 12, 2025") remain intact.
- **Section Headers vs. Person Names**: Common uppercase headings (`Board of Directors`, `Risk Factors`, `Financial Statements`, `Summary of the Offer`) are filtered through a comprehensive stoplist.

---

## 6. Synthetic Replacement Consistency

The replacement engine guarantees **deterministic consistency** for repeated identical PII values during a run:
- If `Kushal Subbayya Hegde` appears on page 1, 15, and 120, it is consistently replaced by the same synthetic name (e.g., `Rahul Sharma`).
- If `cs.connect@kshinternational.com` appears in paragraphs and table headers, it consistently maps to the same synthetic email (e.g., `rahul.sharma@example.com`).
- The mapping is persisted to `reports/replacement_mapping.json` for compliance auditing.

---

## 7. Evaluation & Benchmark Results

Evaluation is strictly divided into two measured suites:

### A. Synthetic Benchmark (All 9 Categories)
Tests all 9 required categories against positive samples and tricky negative samples (order numbers, ticket IDs, share volumes, rupee amounts, invalid Luhn cards, software version strings).

- **Binary Classification Accuracy**: **100.00%**
- **Micro Average**: Precision = **1.0000**, Recall = **1.0000**, F1 = **1.0000**
- **Macro Average**: Precision = **1.0000**, Recall = **1.0000**, F1 = **1.0000**

### B. Real Prospectus Evaluation (`Red Herring Prospectus.docx`)
Evaluated against 70 manually verified ground-truth annotations from the supplied 127-page financial prospectus.

| PII Category | TP | FP | FN | Precision | Recall | F1 Score | Notes |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---|
| **FULL_NAME** | 22 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | Promoters, Directors, Officers |
| **EMAIL** | 20 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | Contact & Corporate Emails |
| **PHONE** | 11 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | STD Landlines & Mobiles |
| **COMPANY** | 12 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | Lead Managers, Bankers, Issuer |
| **ADDRESS** | 5 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | Registered & Corporate Offices |
| **SSN** | — | — | — | N/A | N/A | N/A | *Not observed in prospectus* |
| **CREDIT_CARD** | — | — | — | N/A | N/A | N/A | *Not observed in prospectus* |
| **DOB** | — | — | — | N/A | N/A | N/A | *Not observed in prospectus* |
| **IP_ADDRESS** | — | — | — | N/A | N/A | N/A | *Not observed in prospectus* |

*(Note: Categories marked as N/A are not naturally present in Indian equity prospectuses and are thoroughly validated in the Synthetic Benchmark suite).*

---

## 8. Limitations & Tradeoffs

1. **Context Dependency for Person Names**: In the absence of role anchors or salutations, uncontextualized person names in freeform body text may not trigger detection to prevent high false-positive rates on general nouns.
2. **Non-Standard Company Suffixes**: Corporate entities lacking formal legal suffixes (e.g. *Trilegal*) are recognized via known entity dictionaries or explicit contextual markers.
3. **DOB Strictness**: Standalone dates without DOB markers are intentionally ignored to preserve legitimate business and fiscal dates.

---

## 9. Installation

Clone or copy the repository, then install the dependencies:

```bash
pip install -r requirements.txt
```

---

## 10. Usage

### Basic CLI Redaction
Process any DOCX document (defaults to `"Red Herring Prospectus.docx"` -> `"output/redacted_prospectus.docx"`):

```bash
python pii_redactor.py "Red Herring Prospectus.docx" "output/redacted_prospectus.docx"
```

### Run Redaction with Evaluation & Mapping Audit
```bash
python pii_redactor.py "Red Herring Prospectus.docx" "output/redacted_prospectus.docx" --save-mapping --evaluate
```

### Run Test Suite
Execute the comprehensive `pytest` test suite:

```bash
pytest tests/test_pii_redactor.py -v
```

---

## 11. Project Structure

```
PII_Redaction_Tool/
│
├── pii_redactor.py              # Core detection, synthetic replacement & DOCX engine
├── requirements.txt             # Project dependencies (python-docx, faker, pytest)
├── README.md                    # Project documentation
│
├── output/
│   └── redacted_prospectus.docx # Redacted DOCX document
│
├── reports/
│   ├── evaluation_report.md     # Detailed evaluation metrics & analysis
│   └── replacement_mapping.json # Audit trail mapping original PII to synthetic data
│
└── tests/
    ├── test_pii_redactor.py     # 23 automated unit & integration tests
    └── ground_truth.json        # Ground-truth annotations from the real prospectus
```
