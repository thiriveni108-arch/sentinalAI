"""
Prepare CERT r4.2 Dataset for SentinelAI-Q Quantum Machine Learning Experiments
================================================================================
This script extracts daily behavioural features per employee from CERT r4.2 logs
(logon.csv, device.csv, file.csv, email.csv), aligns accurate ground-truth
malicious user-day labels from CERT scenario answer files, partitions the data
chronologically into train/validation/test splits (avoiding temporal leakage),
and fits feature scaling and PCA (4 components for 4-qubit quantum ML) strictly
on training data.

Outputs are written to: data/processed/cert_r4_2/
"""

import os
import sys
import time
import json
import pickle
from datetime import datetime
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA


def setup_directories(base_dir: str):
    raw_dir = os.path.join(base_dir, "data", "raw", "cert_r4_2")
    r42_dir = os.path.join(raw_dir, "r4.2")
    answers_dir = os.path.join(raw_dir, "answers")
    processed_dir = os.path.join(base_dir, "data", "processed", "cert_r4_2")
    os.makedirs(processed_dir, exist_ok=True)
    return raw_dir, r42_dir, answers_dir, processed_dir


def load_ground_truth_labels(answers_dir: str):
    """
    Parses insiders.csv and all 70 incident observables files in r4.2-1, r4.2-2, r4.2-3.
    Accurately maps malicious user-days for malicious employees to avoid labelling
    benign days as malicious.
    """
    print("[-] Loading CERT r4.2 ground-truth malicious user-days...")
    insiders_file = os.path.join(answers_dir, "insiders.csv")
    if not os.path.exists(insiders_file):
        raise FileNotFoundError(f"insiders.csv not found at {insiders_file}")

    insiders = pd.read_csv(insiders_file)
    insiders_42 = insiders[insiders['dataset'].astype(str) == '4.2'].copy()
    print(f"    Found {len(insiders_42)} malicious insider incidents in dataset 4.2.")

    malicious_user_days = set()
    scenario_by_user_day = {}
    incident_stats = {
        'total_incidents': len(insiders_42),
        'by_scenario': dict(insiders_42['scenario'].value_counts()),
        'unique_insider_users': int(insiders_42['user'].nunique()),
        'events_parsed': 0,
        'supervisor_disclaimer': (
            "In Scenario 3, sysadmins stole supervisor credentials (FAW0032/FBA0348) "
            "to send mass emails. The true insider threats are the 10 sysadmins; the "
            "supervisors are benign employees whose accounts were forged on incident day 2."
        )
    }

    for idx, row in insiders_42.iterrows():
        scen = int(row['scenario'])
        det_file = row['details']
        insider_user = row['user']
        fpath = os.path.join(answers_dir, f"r4.2-{scen}", det_file)

        if not os.path.exists(fpath):
            raise FileNotFoundError(f"Incident observables file missing: {fpath}")

        with open(fpath, 'r') as f:
            for line in f:
                parts = line.strip().split(',')
                if len(parts) >= 4:
                    incident_stats['events_parsed'] += 1
                    ev_date = parts[2]
                    dt_part = ev_date.split(' ')[0]
                    m, d, y = dt_part.split('/')
                    date_key = f"{y}-{m.zfill(2)}-{d.zfill(2)}"
                    user_day_key = (insider_user, date_key)
                    malicious_user_days.add(user_day_key)
                    scenario_by_user_day[user_day_key] = scen

    incident_stats['total_malicious_user_days'] = len(malicious_user_days)
    print(f"    Total precise malicious user-days established: {len(malicious_user_days)}")
    return malicious_user_days, scenario_by_user_day, incident_stats


def process_logs_into_user_days(r42_dir: str, chunk_size: int = 250000):
    """
    Processes logon.csv, device.csv, file.csv, and email.csv in memory-efficient chunks.
    Extracts daily behavioural features per employee.
    """
    user_days = {}

    def get_entry(u: str, d: str):
        k = (u, d)
        if k not in user_days:
            y, m, day = map(int, d.split('-'))
            dt = datetime(y, m, day)
            is_wknd = 1 if dt.weekday() >= 5 else 0
            user_days[k] = {
                'user': u,
                'date': d,
                'is_weekend': is_wknd,
                # Logon features
                'logon_count': 0,
                'logoff_count': 0,
                'logon_after_hours_count': 0,
                'logoff_after_hours_count': 0,
                'first_logon_hour': 24.0,
                'last_logoff_hour': 0.0,
                'logon_pc_count': 0,
                '_logon_pcs': set(),
                # USB features
                'usb_connect_count': 0,
                'usb_disconnect_count': 0,
                'usb_after_hours_count': 0,
                'usb_pc_count': 0,
                '_usb_pcs': set(),
                # File features
                'file_copy_count': 0,
                'file_after_hours_count': 0,
                'file_exe_count': 0,
                'file_doc_count': 0,
                'file_other_count': 0,
                'file_pc_count': 0,
                '_file_pcs': set(),
                # Email features
                'email_sent_count': 0,
                'email_after_hours_count': 0,
                'email_total_size': 0,
                'email_total_attachments': 0,
                'email_max_attachments': 0,
                'email_external_recipients': 0,
                'email_internal_recipients': 0,
                'email_distinct_recipients': 0,
                '_email_recips': set()
            }
        return user_days[k]

    # 1. logon.csv
    print("[-] Processing logon.csv in memory-efficient chunks...")
    t0 = time.time()
    rows_logon = 0
    for chunk in pd.read_csv(os.path.join(r42_dir, "logon.csv"), chunksize=chunk_size):
        rows_logon += len(chunk)
        for row in chunk.itertuples(index=False):
            d_str = row[1]
            user = row[2]
            pc = row[3]
            act = row[4]
            dt_part, tm_part = d_str.split(' ')
            m, d, y = dt_part.split('/')
            date_key = f"{y}-{m.zfill(2)}-{d.zfill(2)}"

            h, mn, s = tm_part.split(':')
            hr = int(h) + int(mn) / 60.0

            entry = get_entry(user, date_key)
            is_after = (hr < 7.0 or hr >= 18.0 or entry['is_weekend'] == 1)

            if act == 'Logon':
                entry['logon_count'] += 1
                if hr < entry['first_logon_hour']:
                    entry['first_logon_hour'] = hr
                if is_after:
                    entry['logon_after_hours_count'] += 1
            elif act == 'Logoff':
                entry['logoff_count'] += 1
                if hr > entry['last_logoff_hour']:
                    entry['last_logoff_hour'] = hr
                if is_after:
                    entry['logoff_after_hours_count'] += 1
            entry['_logon_pcs'].add(pc)

    print(f"    Processed {rows_logon:,} logon rows in {time.time() - t0:.2f} s")

    # 2. device.csv
    print("[-] Processing device.csv in memory-efficient chunks...")
    t0 = time.time()
    rows_device = 0
    for chunk in pd.read_csv(os.path.join(r42_dir, "device.csv"), chunksize=chunk_size):
        rows_device += len(chunk)
        for row in chunk.itertuples(index=False):
            d_str = row[1]
            user = row[2]
            pc = row[3]
            act = row[4]
            dt_part, tm_part = d_str.split(' ')
            m, d, y = dt_part.split('/')
            date_key = f"{y}-{m.zfill(2)}-{d.zfill(2)}"

            h, mn, s = tm_part.split(':')
            hr = int(h) + int(mn) / 60.0

            entry = get_entry(user, date_key)
            is_after = (hr < 7.0 or hr >= 18.0 or entry['is_weekend'] == 1)

            if act == 'Connect':
                entry['usb_connect_count'] += 1
                if is_after:
                    entry['usb_after_hours_count'] += 1
            elif act == 'Disconnect':
                entry['usb_disconnect_count'] += 1
            entry['_usb_pcs'].add(pc)

    print(f"    Processed {rows_device:,} device rows in {time.time() - t0:.2f} s")

    # 3. file.csv
    print("[-] Processing file.csv in memory-efficient chunks...")
    t0 = time.time()
    rows_file = 0
    for chunk in pd.read_csv(os.path.join(r42_dir, "file.csv"), usecols=['date', 'user', 'pc', 'filename'], chunksize=chunk_size):
        rows_file += len(chunk)
        for row in chunk.itertuples(index=False):
            d_str = row[0]
            user = row[1]
            pc = row[2]
            fn = str(row[3]) if pd.notna(row[3]) else ""
            dt_part, tm_part = d_str.split(' ')
            m, d, y = dt_part.split('/')
            date_key = f"{y}-{m.zfill(2)}-{d.zfill(2)}"

            h, mn, s = tm_part.split(':')
            hr = int(h) + int(mn) / 60.0

            entry = get_entry(user, date_key)
            is_after = (hr < 7.0 or hr >= 18.0 or entry['is_weekend'] == 1)

            entry['file_copy_count'] += 1
            if is_after:
                entry['file_after_hours_count'] += 1

            fn_lower = fn.lower()
            if fn_lower.endswith('.exe'):
                entry['file_exe_count'] += 1
            elif fn_lower.endswith(('.doc', '.pdf', '.txt', '.docx', '.xlsx', '.ppt', '.zip', '.jpg')):
                entry['file_doc_count'] += 1
            else:
                entry['file_other_count'] += 1
            entry['_file_pcs'].add(pc)

    print(f"    Processed {rows_file:,} file rows in {time.time() - t0:.2f} s")

    # 4. email.csv
    print("[-] Processing email.csv in memory-efficient chunks...")
    t0 = time.time()
    rows_email = 0
    for chunk in pd.read_csv(os.path.join(r42_dir, "email.csv"),
                             usecols=['date', 'user', 'pc', 'to', 'cc', 'bcc', 'size', 'attachments'],
                             chunksize=chunk_size):
        rows_email += len(chunk)
        for row in chunk.itertuples(index=False):
            d_str = row[0]
            user = row[1]
            pc = row[2]
            to_str = str(row[3]) if pd.notna(row[3]) else ""
            cc_str = str(row[4]) if pd.notna(row[4]) else ""
            bcc_str = str(row[5]) if pd.notna(row[5]) else ""
            sz = int(row[6])
            att = int(row[7])

            dt_part, tm_part = d_str.split(' ')
            m, d, y = dt_part.split('/')
            date_key = f"{y}-{m.zfill(2)}-{d.zfill(2)}"

            h, mn, s = tm_part.split(':')
            hr = int(h) + int(mn) / 60.0

            entry = get_entry(user, date_key)
            is_after = (hr < 7.0 or hr >= 18.0 or entry['is_weekend'] == 1)

            entry['email_sent_count'] += 1
            if is_after:
                entry['email_after_hours_count'] += 1
            entry['email_total_size'] += sz
            entry['email_total_attachments'] += att
            if att > entry['email_max_attachments']:
                entry['email_max_attachments'] = att

            all_recips = []
            if to_str:
                all_recips.extend(to_str.split(';'))
            if cc_str:
                all_recips.extend(cc_str.split(';'))
            if bcc_str:
                all_recips.extend(bcc_str.split(';'))

            for r in all_recips:
                r_clean = r.strip().lower()
                if not r_clean:
                    continue
                entry['_email_recips'].add(r_clean)
                if r_clean.endswith('@dtaa.com'):
                    entry['email_internal_recipients'] += 1
                else:
                    entry['email_external_recipients'] += 1

    print(f"    Processed {rows_email:,} email rows in {time.time() - t0:.2f} s")
    print(f"    Total unique user-days aggregated: {len(user_days):,}")
    return user_days


def finalize_dataframe(user_days: dict, malicious_user_days: set, scenario_by_user_day: dict):
    """
    Transforms the aggregated user_days dictionary into a clean pandas DataFrame,
    derives duration/ratio features, and assigns ground-truth labels.
    """
    print("[-] Finalizing behavioral feature matrix...")
    records = []
    matched_positives = 0

    for (u, d), v in user_days.items():
        v['logon_pc_count'] = len(v.pop('_logon_pcs'))
        v['usb_pc_count'] = len(v.pop('_usb_pcs'))
        v['file_pc_count'] = len(v.pop('_file_pcs'))
        v['email_distinct_recipients'] = len(v.pop('_email_recips'))

        # Adjust default timing if no logon/logoff occurred
        if v['logon_count'] == 0:
            v['first_logon_hour'] = 9.0  # standard 9:00 AM
        if v['logoff_count'] == 0:
            v['last_logoff_hour'] = 17.0  # standard 5:00 PM
        v['work_duration_hours'] = max(0.0, v['last_logoff_hour'] - v['first_logon_hour'])

        # Mean email size
        if v['email_sent_count'] > 0:
            v['email_mean_size'] = float(v['email_total_size'] / v['email_sent_count'])
        else:
            v['email_mean_size'] = 0.0

        # Note on logon_failures: CERT r4.2 schema lacks failure codes
        # We record it as 0.0 for schema alignment, but keep it documented
        v['logon_failures'] = 0

        # Ground truth label
        is_mal = 1 if (u, d) in malicious_user_days else 0
        v['label'] = is_mal
        v['scenario'] = scenario_by_user_day.get((u, d), 0)
        if is_mal == 1:
            matched_positives += 1

        records.append(v)

    df = pd.DataFrame(records)
    # Sort chronologically by date and user
    df.sort_values(by=['date', 'user'], inplace=True)
    df.reset_index(drop=True, inplace=True)
    print(f"    Total records: {len(df):,}")
    print(f"    Label counts: 0={int((df['label'] == 0).sum()):,}, 1={int((df['label'] == 1).sum()):,}")
    print(f"    Matched malicious user-days: {matched_positives:,} / {len(malicious_user_days):,}")
    return df


def split_and_transform_pca(df: pd.DataFrame, processed_dir: str):
    """
    Performs chronological splitting:
      Train: date <= 2010-11-30
      Val:   2010-12-01 <= date <= 2011-02-28
      Test:  2011-03-01 <= date <= 2011-05-17
    Fits StandardScaler and PCA(n_components=4) ONLY on training data.
    Transforms train, validation, and test splits.
    """
    print("[-] Partitioning dataset chronologically...")
    cut_train_val = "2010-11-30"
    cut_val_test = "2011-02-28"

    train_df = df[df['date'] <= cut_train_val].copy()
    val_df = df[(df['date'] > cut_train_val) & (df['date'] <= cut_val_test)].copy()
    test_df = df[df['date'] > cut_val_test].copy()

    # Temporal leakage assertions
    train_max_date = train_df['date'].max()
    val_min_date = val_df['date'].min()
    val_max_date = val_df['date'].max()
    test_min_date = test_df['date'].min()
    test_max_date = test_df['date'].max()

    print(f"    Train split: {train_df['date'].min()} to {train_max_date} | {len(train_df):,} rows, {int(train_df['label'].sum())} positives")
    print(f"    Val split:   {val_min_date} to {val_max_date} | {len(val_df):,} rows, {int(val_df['label'].sum())} positives")
    print(f"    Test split:  {test_min_date} to {test_max_date} | {len(test_df):,} rows, {int(test_df['label'].sum())} positives")

    assert train_max_date < val_min_date, f"Temporal leakage: Train max {train_max_date} >= Val min {val_min_date}"
    assert val_max_date < test_min_date, f"Temporal leakage: Val max {val_max_date} >= Test min {test_min_date}"
    print("    [V] Temporal leakage verification PASSED: Strict chronological ordering verified.")

    # 27 behavioral features (excluding constant logon_failures with 0 variance)
    feature_cols = [
        'is_weekend',
        'logon_count',
        'logoff_count',
        'logon_after_hours_count',
        'logoff_after_hours_count',
        'first_logon_hour',
        'last_logoff_hour',
        'work_duration_hours',
        'logon_pc_count',
        'usb_connect_count',
        'usb_disconnect_count',
        'usb_after_hours_count',
        'usb_pc_count',
        'file_copy_count',
        'file_after_hours_count',
        'file_exe_count',
        'file_doc_count',
        'file_other_count',
        'file_pc_count',
        'email_sent_count',
        'email_after_hours_count',
        'email_total_size',
        'email_mean_size',
        'email_total_attachments',
        'email_max_attachments',
        'email_external_recipients',
        'email_internal_recipients',
        'email_distinct_recipients'
    ]

    print(f"[-] Fitting StandardScaler and PCA(n_components=4) strictly on training split ({len(feature_cols)} features)...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(train_df[feature_cols].values)

    pca = PCA(n_components=4, random_state=42)
    X_train_pca = pca.fit_transform(X_train_scaled)

    # Transform validation and test splits using fitted parameters
    X_val_scaled = scaler.transform(val_df[feature_cols].values)
    X_val_pca = pca.transform(X_val_scaled)

    X_test_scaled = scaler.transform(test_df[feature_cols].values)
    X_test_pca = pca.transform(X_test_scaled)

    # Attach PCA columns to DataFrames
    pca_cols = ['pca_1', 'pca_2', 'pca_3', 'pca_4']
    for i, col in enumerate(pca_cols):
        train_df[col] = X_train_pca[:, i]
        val_df[col] = X_val_pca[:, i]
        test_df[col] = X_test_pca[:, i]

    explained_var = pca.explained_variance_ratio_
    print(f"    Explained variance ratio per PC: {explained_var.tolist()}")
    print(f"    Cumulative explained variance: {float(np.sum(explained_var)):.4f}")

    # Save fitted models for reproducibility
    with open(os.path.join(processed_dir, "scaler_model.pkl"), "wb") as f:
        pickle.dump(scaler, f)
    with open(os.path.join(processed_dir, "pca_model.pkl"), "wb") as f:
        pickle.dump(pca, f)

    # Save CSV files
    print("[-] Saving train.csv, validation.csv, and test.csv...")
    train_path = os.path.join(processed_dir, "train.csv")
    val_path = os.path.join(processed_dir, "validation.csv")
    test_path = os.path.join(processed_dir, "test.csv")

    train_df.to_csv(train_path, index=False)
    val_df.to_csv(val_path, index=False)
    test_df.to_csv(test_path, index=False)
    print(f"    Saved: {train_path} ({os.path.getsize(train_path)/1e6:.1f} MB)")
    print(f"    Saved: {val_path} ({os.path.getsize(val_path)/1e6:.1f} MB)")
    print(f"    Saved: {test_path} ({os.path.getsize(test_path)/1e6:.1f} MB)")

    # Save Feature Dictionary
    feature_dict = {
        "dataset_name": "CERT Insider Threat r4.2 (SentinelAI-Q Quantum ML Prepared)",
        "entity": "Employee User-Day (user, date)",
        "num_qubits_target": 4,
        "pca_features": {
            "pca_1": {
                "description": "First principal component derived from standard-scaled daily behavioural features.",
                "explained_variance_ratio": float(explained_var[0])
            },
            "pca_2": {
                "description": "Second principal component derived from standard-scaled daily behavioural features.",
                "explained_variance_ratio": float(explained_var[1])
            },
            "pca_3": {
                "description": "Third principal component derived from standard-scaled daily behavioural features.",
                "explained_variance_ratio": float(explained_var[2])
            },
            "pca_4": {
                "description": "Fourth principal component derived from standard-scaled daily behavioural features.",
                "explained_variance_ratio": float(explained_var[3])
            }
        },
        "cumulative_explained_variance_4_components": float(np.sum(explained_var)),
        "input_behavioral_features": {
            "is_weekend": "Binary flag (1 if date is Saturday or Sunday, else 0)",
            "logon_count": "Total successful logons during the day (from logon.csv)",
            "logoff_count": "Total logoffs during the day (from logon.csv)",
            "logon_after_hours_count": "Logons before 07:00, after 18:00, or on weekends",
            "logoff_after_hours_count": "Logoffs before 07:00, after 18:00, or on weekends",
            "first_logon_hour": "Decimal hour of earliest logon of the day (e.g., 8.5 for 08:30)",
            "last_logoff_hour": "Decimal hour of latest logoff of the day (e.g., 17.5 for 17:30)",
            "work_duration_hours": "Duration in hours between last logoff and first logon",
            "logon_pc_count": "Number of distinct workstations logged into during the day",
            "usb_connect_count": "Number of USB removable drive Connect events (from device.csv)",
            "usb_disconnect_count": "Number of USB removable drive Disconnect events (from device.csv)",
            "usb_after_hours_count": "Number of USB Connect events outside business hours or on weekends",
            "usb_pc_count": "Number of distinct workstations with USB connections",
            "file_copy_count": "Total files copied to removable media (from file.csv)",
            "file_after_hours_count": "File copies to removable media outside business hours or on weekends",
            "file_exe_count": "Executable files (.exe) copied to removable media",
            "file_doc_count": "Office and text documents (.doc, .pdf, .txt, .docx, .xlsx, .ppt, .zip) copied",
            "file_other_count": "Other miscellaneous file types copied",
            "file_pc_count": "Number of distinct workstations where files were copied",
            "email_sent_count": "Total emails sent during the day (from email.csv)",
            "email_after_hours_count": "Emails sent outside business hours or on weekends",
            "email_total_size": "Total size in bytes of sent emails",
            "email_mean_size": "Mean size in bytes per sent email",
            "email_total_attachments": "Total count of email attachments sent",
            "email_max_attachments": "Maximum attachment count in any single email sent",
            "email_external_recipients": "Count of emails sent to external recipients (non-@dtaa.com)",
            "email_internal_recipients": "Count of emails sent to internal organizational recipients (@dtaa.com)",
            "email_distinct_recipients": "Total unique recipient email addresses contacted during the day",
            "logon_failures": (
                "Documented placeholder (0). In CERT r4.2 schema, logon failures are NOT recorded; "
                "logon.csv records only successful 'Logon' and 'Logoff' events. Excluded from PCA fitting "
                "due to zero variance."
            )
        },
        "target_label": {
            "label": "Binary ground-truth label (1 = Malicious user-day, 0 = Benign user-day)",
            "scenario": "Scenario ID (1: After-hours data theft/wikileaks, 2: Employment solicitation/thumb drive theft, 3: Disgruntled sysadmin keylogger installation & supervisor impersonation, 0: Benign)"
        },
        "pca_component_loadings": {
            f"PC_{i+1}": {feat: float(pca.components_[i, j]) for j, feat in enumerate(feature_cols)}
            for i in range(4)
        }
    }

    feature_dict_path = os.path.join(processed_dir, "feature_dictionary.json")
    with open(feature_dict_path, "w") as f:
        json.dump(feature_dict, f, indent=2)
    print(f"    Saved: {feature_dict_path}")

    # Save Split Summary
    split_summary = {
        "dataset_split_strategy": "Strict Chronological Partitioning (No temporal leakage)",
        "temporal_ranges": {
            "train": {
                "start_date": str(train_df['date'].min()),
                "end_date": str(train_max_date),
                "total_days_span": int((pd.to_datetime(train_max_date) - pd.to_datetime(train_df['date'].min())).days + 1),
                "total_user_days": int(len(train_df)),
                "positive_count": int(train_df['label'].sum()),
                "negative_count": int((train_df['label'] == 0).sum()),
                "positive_percentage": float(train_df['label'].mean() * 100),
                "scenario_counts": {str(k): int(v) for k, v in train_df[train_df['label'] == 1]['scenario'].value_counts().items()}
            },
            "validation": {
                "start_date": str(val_min_date),
                "end_date": str(val_max_date),
                "total_days_span": int((pd.to_datetime(val_max_date) - pd.to_datetime(val_min_date)).days + 1),
                "total_user_days": int(len(val_df)),
                "positive_count": int(val_df['label'].sum()),
                "negative_count": int((val_df['label'] == 0).sum()),
                "positive_percentage": float(val_df['label'].mean() * 100),
                "scenario_counts": {str(k): int(v) for k, v in val_df[val_df['label'] == 1]['scenario'].value_counts().items()}
            },
            "test": {
                "start_date": str(test_min_date),
                "end_date": str(test_max_date),
                "total_days_span": int((pd.to_datetime(test_max_date) - pd.to_datetime(test_min_date)).days + 1),
                "total_user_days": int(len(test_df)),
                "positive_count": int(test_df['label'].sum()),
                "negative_count": int((test_df['label'] == 0).sum()),
                "positive_percentage": float(test_df['label'].mean() * 100),
                "scenario_counts": {str(k): int(v) for k, v in test_df[test_df['label'] == 1]['scenario'].value_counts().items()}
            }
        },
        "overall": {
            "total_user_days": int(len(df)),
            "total_positive_user_days": int(df['label'].sum()),
            "total_negative_user_days": int((df['label'] == 0).sum()),
            "overall_positive_rate": float(df['label'].mean() * 100),
            "scenario_counts": {str(k): int(v) for k, v in df[df['label'] == 1]['scenario'].value_counts().items()}
        },
        "temporal_leakage_checks": {
            "train_max_date_less_than_val_min_date": bool(train_max_date < val_min_date),
            "val_max_date_less_than_test_min_date": bool(val_max_date < test_min_date),
            "scaler_fitted_on_train_only": True,
            "pca_fitted_on_train_only": True,
            "class_imbalance_preserved_in_val_and_test": True
        }
    }

    split_summary_path = os.path.join(processed_dir, "split_summary.json")
    with open(split_summary_path, "w") as f:
        json.dump(split_summary, f, indent=2)
    print(f"    Saved: {split_summary_path}")

    return train_df, val_df, test_df, split_summary, feature_dict


def main():
    base_dir = r"d:\Projects\sentinalAI"
    t_start = time.time()
    raw_dir, r42_dir, answers_dir, processed_dir = setup_directories(base_dir)

    malicious_user_days, scenario_by_user_day, incident_stats = load_ground_truth_labels(answers_dir)
    user_days = process_logs_into_user_days(r42_dir)
    df = finalize_dataframe(user_days, malicious_user_days, scenario_by_user_day)
    train_df, val_df, test_df, split_summary, feature_dict = split_and_transform_pca(df, processed_dir)

    print(f"\n[+] Pipeline completed successfully in {time.time() - t_start:.2f} seconds!")


if __name__ == "__main__":
    main()
