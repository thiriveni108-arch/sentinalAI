# CERT r4.2 SentinelAI-Q Quantum Feature Dictionary

This document defines the behavioural features and principal components extracted from the CERT Insider Threat Dataset r4.2 for the **SentinelAI-Q** comparative evaluation between **PennyLane QSVC** (Quantum Support Vector Classifier) and **PennyLane VQC** (Variational Quantum Classifier).

---

## 1. Entity Definition

- **Granularity:** Employee User-Day (`user`, `date`)
- **Total Instances:** 330,452 user-days across 1,000 employees over 16.5 months (2010-01-02 to 2011-05-17).
- **Target Label:** `label` (0 = Benign, 1 = Malicious Insider Activity).
- **Scenario Metadata:** `scenario` (0: Benign, 1: Wikileaks exfiltration, 2: Competitor thumb drive theft, 3: Sysadmin keylogger & supervisor impersonation).

---

## 2. 4-Qubit Principal Components (`pca_1`, `pca_2`, `pca_3`, `pca_4`)

Fitted **strictly on training data** using `StandardScaler` followed by `PCA(n_components=4, random_state=42)`. Validation and test splits were transformed using the fitted scaler and PCA parameters without refitting.

- **Total Cumulative Explained Variance (4 PCs):** 64.43%

| Component | Explained Variance Ratio | Description & Dominant Influences |
| :--- | :---: | :--- |
| **`pca_1`** | **25.26%** | **USB & Exfiltration Intensity:** Positively correlated with `usb_connect_count`, `usb_disconnect_count`, `file_copy_count`, `file_doc_count`, and `usb_pc_count`. Strongly captures physical exfiltration bursts. |
| **`pca_2`** | **16.74%** | **Email Activity & Organizational Breadth:** Strongly loaded on `email_sent_count`, `email_total_size`, `email_distinct_recipients`, and `email_internal_recipients`. Represents overall daily communication volume. |
| **`pca_3`** | **15.03%** | **Off-Hours / Work Schedule Anomalies:** Driven by `logon_after_hours_count`, `logoff_after_hours_count`, `is_weekend`, `first_logon_hour`, and `work_duration_hours`. Captures temporal deviations and unusual logon hours. |
| **`pca_4`** | **7.41%** | **External Collaboration & Attachments:** Dominated by `email_external_recipients`, `email_total_attachments`, `email_max_attachments`, and `email_mean_size`. Differentiates bulk external data transfers from internal communications. |

---

## 3. Raw Daily Behavioural Features (28 Features)

| Feature Name | Source File | Type | Description |
| :--- | :--- | :---: | :--- |
| `is_weekend` | Calendar | Binary (0/1) | 1 if date is Saturday or Sunday, else 0. |
| `logon_count` | `logon.csv` | Integer | Total successful logins recorded during the day. |
| `logoff_count` | `logon.csv` | Integer | Total logoffs recorded during the day. |
| `logon_after_hours_count` | `logon.csv` | Integer | Logons occurring before 07:00, after 18:00, or on weekends. |
| `logoff_after_hours_count` | `logon.csv` | Integer | Logoffs occurring before 07:00, after 18:00, or on weekends. |
| `first_logon_hour` | `logon.csv` | Float | Decimal hour of first login of the day (e.g. 7.5 = 07:30 AM). Defaults to 9.0 if no logon occurred. |
| `last_logoff_hour` | `logon.csv` | Float | Decimal hour of last logoff of the day (e.g. 17.5 = 05:30 PM). Defaults to 17.0 if no logoff occurred. |
| `work_duration_hours` | `logon.csv` | Float | Span in hours between last logoff and first logon. |
| `logon_pc_count` | `logon.csv` | Integer | Distinct computer workstations logged into by the employee. |
| `logon_failures` | `logon.csv` | Integer | Placeholder (0). Note: CERT r4.2 schema lacks failed logon event codes. Excluded from PCA fitting. |
| `usb_connect_count` | `device.csv` | Integer | Count of USB removable storage `Connect` events. |
| `usb_disconnect_count` | `device.csv` | Integer | Count of USB removable storage `Disconnect` events. |
| `usb_after_hours_count` | `device.csv` | Integer | USB connections occurring outside business hours or on weekends. |
| `usb_pc_count` | `device.csv` | Integer | Distinct workstations where the employee connected a USB device. |
| `file_copy_count` | `file.csv` | Integer | Total files copied to removable media. |
| `file_after_hours_count` | `file.csv` | Integer | Files copied to removable media after hours or on weekends. |
| `file_exe_count` | `file.csv` | Integer | Count of executable files (`.exe`) copied (keylogger indicator). |
| `file_doc_count` | `file.csv` | Integer | Count of documents (`.doc`, `.pdf`, `.txt`, `.docx`, etc.) copied. |
| `file_other_count` | `file.csv` | Integer | Other miscellaneous file types copied. |
| `file_pc_count` | `file.csv` | Integer | Distinct workstations where files were copied. |
| `email_sent_count` | `email.csv` | Integer | Total emails sent by the user during the day. |
| `email_after_hours_count` | `email.csv` | Integer | Emails sent outside business hours or on weekends. |
| `email_total_size` | `email.csv` | Integer | Total bytes of email body content sent. |
| `email_mean_size` | `email.csv` | Float | Mean bytes per sent email. |
| `email_total_attachments` | `email.csv` | Integer | Total attachments across all sent emails. |
| `email_max_attachments` | `email.csv` | Integer | Maximum attachments in any single email. |
| `email_external_recipients` | `email.csv` | Integer | Count of emails sent to non-`@dtaa.com` external addresses. |
| `email_internal_recipients` | `email.csv` | Integer | Count of emails sent to internal `@dtaa.com` addresses. |
| `email_distinct_recipients` | `email.csv` | Integer | Count of unique recipient email addresses contacted during the day. |

---

## 4. Usage in PennyLane Quantum Circuits

For 4-qubit quantum architectures (PennyLane QSVC / VQC):
```python
import pandas as pd
import numpy as np

# Load identical dataset split
train_df = pd.read_csv("data/processed/cert_r4_2/train.csv")

# Extract 4 PCA features for 4-qubit circuit
X_train_4q = train_df[['pca_1', 'pca_2', 'pca_3', 'pca_4']].values
y_train = train_df['label'].values
```
