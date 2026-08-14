# PII Redaction Tool - Rigorous Evaluation Report

## 1. Executive Summary

This report documents the rigorous evaluation of the **PII Redaction Tool**, executed locally on Python 3.13 without external APIs. The evaluation is split into two distinct tiers:
1. **Synthetic Benchmark Suite**: Measures detector capability across all 9 supported PII categories with both positive PII fixtures and challenging negative non-PII test cases (order IDs, share counts, monetary values, invalid Luhn numbers, version strings).
2. **Real Prospectus Sample Evaluation**: Measures empirical **True Positives (TP)**, **False Positives (FP)**, and **False Negatives (FN)** across a representative 136-passage evaluation sample manually extracted and verified from the supplied 127-page financial prospectus (`Red Herring Prospectus.docx`).

---

## 2. Evaluation Scope & Sample Methodology

To evaluate precision and recall without artificially assuming unannotated text contains zero false positives, we defined a structured, multi-section **Evaluated Sample** comprising 136 distinct passages from `Red Herring Prospectus.docx`:

- **Section 1: Cover Page & Corporate Information (Paragraphs 20–35)**
  Contains company name, registration details, registered office address, company secretary contact details, telephone numbers, and statutory disclaimers.
- **Section 2: Corporate Directory & Promoters Table (Table 0, Rows 0–12)**
  Contains promoter names, promoter selling shareholder details, weighted average cost of acquisition, compliance officer details, and corporate office information.
- **Section 3: General Information, Intermediaries & Bankers (Paragraphs 717–815)**
  Contains Book Running Lead Managers (BRLMs), Syndicate Members, Legal Counsel, Registrar to the Offer, Escrow Collection Banks, Refund Banks, contact persons, telephone numbers, email addresses, multi-line office addresses, and SEBI registration numbers.
- **Section 4: Financial Presentation, Currency & Disclaimers (Paragraphs 113–130)**
  A non-PII dense region containing monetary figures (₹7,100.00 million), currency unit definitions (USD, EUR, SEK, INR), scale numbers (1,000,000, 1,000,000,000), statutory dates, and SEBI regulation references.

### Dataset Counts:
- **Total Evaluated Passages**: 136
- **Total Manually Annotated PII Entities**: 91
- **Total Manually Reviewed Non-PII Candidate Elements**: 45 (CIN, SEBI Reg No, Financial Amounts, Dates, Section Numbers, Regulation refs, Scale Numbers)

---

## 3. Real Prospectus Evaluation Results

Each predicted entity in the evaluated sample was evaluated against the independent ground-truth annotations:
- **True Positive (TP)**: Predicted entity matches a ground-truth PII entity with corresponding type and overlapping character span.
- **False Positive (FP)**: Detector predicted a PII entity where no ground-truth PII entity exists in that passage (or predicted an incorrect entity type).
- **False Negative (FN)**: A ground-truth PII entity was not detected by the engine.

### Per-Category Metrics (Real Document Evaluated Sample)

| PII Category | TP | FP | FN | Precision | Recall | F1 Score | Notes / Evaluation Context |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---|
| **FULL_NAME** | 25 | 0 | 0 | **1.0000** (100.0%) | **1.0000** (100.0%) | **1.0000** (100.0%) | Promoters, Directors, KMP, Compliance Officers |
| **EMAIL** | 20 | 0 | 0 | **1.0000** (100.0%) | **1.0000** (100.0%) | **1.0000** (100.0%) | Intermediary, Registrar & Corporate Emails |
| **PHONE** | 12 | 0 | 0 | **1.0000** (100.0%) | **1.0000** (100.0%) | **1.0000** (100.0%) | Landlines (+91 20 / 022) & Mobile Lines |
| **COMPANY** | 15 | 3 | 4 | **0.8333** (83.3%) | **0.7895** (79.0%) | **0.8108** (81.1%) | Lead Managers, Bankers, Issuer, Legal Counsel |
| **ADDRESS** | 15 | 1 | 0 | **0.9375** (93.8%) | **1.0000** (100.0%) | **0.9677** (96.8%) | Single-line, multi-line & table-cell addresses |
| **SSN** | — | — | — | **N/A** | **N/A** | **N/A** | *Not observed in Indian equity prospectus* |
| **CREDIT_CARD** | — | — | — | **N/A** | **N/A** | **N/A** | *Not observed in Indian equity prospectus* |
| **DOB** | — | — | — | **N/A** | **N/A** | **N/A** | *Not observed in Indian equity prospectus* |
| **IP_ADDRESS** | — | — | — | **N/A** | **N/A** | **N/A** | *Not observed in Indian equity prospectus* |

### Summary Averages (Observed Categories)
- **Micro Average**: Precision = **0.9560 (95.60%)**, Recall = **0.9560 (95.60%)**, F1 = **0.9560 (95.60%)**
- **Macro Average**: Precision = **0.9542 (95.42%)**, Recall = **0.9579 (95.79%)**, F1 = **0.9557 (95.57%)**

---

## 4. Synthetic Benchmark Results (All 9 Categories)

Evaluated against 16 positive PII test cases across all 9 categories and 10 negative non-PII test cases:

| PII Category | TP | FP | FN | Precision | Recall | F1 Score |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **FULL_NAME** | 3 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| **EMAIL** | 2 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| **PHONE** | 2 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| **COMPANY** | 2 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| **ADDRESS** | 2 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| **SSN** | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| **CREDIT_CARD** | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| **DOB** | 2 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| **IP_ADDRESS** | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |

- **Synthetic Binary Classification Accuracy**: **100.00%** (26/26 correct decisions)
- **Micro Average**: Precision = **1.0000**, Recall = **1.0000**, F1 = **1.0000**
- **Macro Average**: Precision = **1.0000**, Recall = **1.0000**, F1 = **1.0000**

---

## 5. Distinction: Unique PII Entities vs Total Redaction Operations

To ensure absolute reporting precision and eliminate ambiguities:

### Email Counts Investigation:
- **Unique Original Email Entities**: **26**
- **Total Original Email Occurrences in Distinct Paragraph XML Elements**: **52**
- **Total Email Redaction Operations**: **52**
- **Synthetic Email Occurrences in Output Document**: **52** (all rewritten to safe `@example.com` domains)
- **Residual Unredacted Original Emails**: **0**

*(Note on previous 70 count: When traversing Microsoft Word tables without deduplicating horizontally merged cells across column indices, the same cell text is repeated across column spans, yielding 70 un-deduplicated cell references. In the actual Word DOM, exactly 52 distinct paragraph XML elements contain email addresses, and all 52 are redacted cleanly).*

### Document-Wide Counts Breakdown (`Red Herring Prospectus.docx`):
- **Unique PII Entities Mapped in Cache**: **294**
- **Total In-Place Redaction Operations**: **551**
  - **FULL_NAME**: 277 operations
  - **EMAIL**: 52 operations (26 unique email values)
  - **PHONE**: 36 operations
  - **COMPANY**: 144 operations
  - **ADDRESS**: 42 operations
  - **SSN**: 0 *(not present in Indian prospectus)*
  - **CREDIT_CARD**: 0 *(not present in Indian prospectus)*
  - **DOB**: 0 *(not present in Indian prospectus)*
  - **IP_ADDRESS**: 0 *(not present in Indian prospectus)*

---

## 6. Formatting & Layout Preservation Verification

- **Paragraph Count**: Original = 1,006 | Redacted = 1,006 (100% matched)
- **Table Count**: Original = 76 | Redacted = 76 (100% matched)
- **Bold XML Runs**: Original = 527 | Redacted = 527 (100% preserved)
- **Italic XML Runs**: Original = 5,266 | Redacted = 5,266 (100% preserved)
- **Original File**: `Red Herring Prospectus.docx` remains completely unmodified (1,844,676 bytes).
