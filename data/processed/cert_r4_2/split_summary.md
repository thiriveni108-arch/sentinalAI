# CERT r4.2 SentinelAI-Q Split & Label Summary

## 1. Split Strategy & Temporal Partitioning

To avoid **temporal leakage** (data snooping from future incidents into model training or scaling), the dataset is split strictly by chronological date bounds:

- **Train Split:** `2010-01-02` through `2010-11-30` (~11 months, ~69.0% of user-days)
- **Validation Split:** `2010-12-01` through `2011-02-28` (~3 months, ~16.7% of user-days)
- **Test Split:** `2011-03-01` through `2011-05-17` (~2.5 months, ~14.3% of user-days)

Temporal boundary check:
$$\max(\text{Train Date}) = \text{2010-11-30} < \min(\text{Val Date}) = \text{2010-12-01}$$
$$\max(\text{Val Date}) = \text{2011-02-28} < \min(\text{Test Date}) = \text{2011-03-01}$$

---

## 2. Dataset Partition Metrics & Class Imbalance

Natural class imbalance is strictly preserved in Validation and Test splits. No sampling, SMOTE, or synthetic augmentation has been applied outside training.

| Split | Date Range | Calendar Days | Total User-Days | Negatives (0) | Positives (1) | Positive Rate (%) | Imbalance Ratio |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Train** | 2010-01-02 – 2010-11-30 | 333 | 227,954 | 227,294 | 660 | 0.2895% | 1 : 344 |
| **Validation** | 2010-12-01 – 2011-02-28 | 90 | 55,302 | 55,069 | 233 | 0.4213% | 1 : 236 |
| **Test** | 2011-03-01 – 2011-05-17 | 78 | 47,196 | 47,123 | 73 | 0.1547% | 1 : 646 |
| **TOTAL** | **2010-01-02 – 2011-05-17** | **501** | **330,452** | **329,486** | **966** | **0.2923%** | **1 : 341** |

---

## 3. Attack Scenario Representation per Split

All three CERT r4.2 attack scenarios are represented in **every** split:

| Split | Scenario 1 (Exfiltration) | Scenario 2 (USB Data Theft) | Scenario 3 (Keylogger & Impersonation) | Total Positives |
| :--- | :---: | :---: | :---: | :---: |
| **Train** | 64 | 580 | 16 | **660** |
| **Validation** | 19 | 212 | 2 | **233** |
| **Test** | 2 | 69 | 2 | **73** |
| **TOTAL** | **85** | **861** | **20** | **966** |

---

## 4. Ground-Truth Labelling Notes & Clarifications

1. **Avoidance of Naive Employee-Level Labelling:**
   - Naive labelling would mark all 500+ days of a malicious employee as positive.
   - Using the 70 detailed incident observable files (`r4.2-1`, `r4.2-2`, `r4.2-3`), each employee is labelled **only on user-days containing verified malicious activity**.
   - Example: Employee `AAM0658` was active for 500 days with incident duration spanning 7 days (`10/23/2010` to `10/29/2010`). Only 2 days (`10/23` and `10/29`) contained malicious observables; days `10/24`–`10/28` contained no attack activity and remain labelled benign (0).

2. **Scenario 3 Credential Impersonation Nuance:**
   - In Scenario 3, 10 disgruntled sysadmins downloaded a keylogger and transferred it to their supervisor's workstation (`PC-5866` or `PC-8486`).
   - On incident Day 2, the sysadmin logged in under the supervisor's stolen credentials (`FAW0032` or `FBA0348`) to send a mass panic email.
   - The ground-truth answer files include supervisor reply emails on Day 1 and supervisor-authenticated actions on Day 2.
   - The true insider threat entity is the sysadmin (`insider_user`). The supervisor is a benign employee whose credentials were compromised. All 10 sysadmins had active logon sessions on Day 2 retrieving keylogs, correctly capturing both incident days.
