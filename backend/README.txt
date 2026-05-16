VSAWA — Malware-Scan Module Integration Notes
=============================================

This backend is the original VSAWA Flask + SQLite + ZAP backend, extended
with a fourth scan type -- `MALWARE` -- that runs a Windows PE binary
through three ML classifiers (LightGBM, Random Forest, XGBoost). The
integrated module was originally part of a standalone "malware-detection"
project; it was lifted into VSAWA and adapted to the VSAWA database schema
and JWT auth flow so it appears as just another scan type next to
URL / APK / FOLDER.

What was added
--------------
Backend layout (new things marked NEW):

    backend/
      app.py                       (extended)
      schema.sql                   (extended)
      requirements.txt             (extended)
      Dockerfile                   (added libgomp1)
      malware_scan/                NEW package
        __init__.py
        scanner.py                 single adapter the rest of VSAWA calls
        util/
          number_utils.py
        lightgbm_model/            (ported from upstream project)
          model_prediction.py
          weights/...
        randomforest_model/
          model_prediction1.py
          weights/...
        xgboost_model/
          model_prediction.py
          weights/...

Database schema
---------------
* targets.target_type keeps its original CHECK constraint (URL, APK, HOST).
  PE targets piggy-back on the HOST supertype the same way code_targets
  do, so existing v1 databases upgrade in place.
* New specialization table pe_files (target_id, file_name, file_size,
  md5_hash, verdict, summary_json) is created at runtime by
  ensure_runtime_schema().
* All target-listing queries (list_scans, _load_scan_report_data,
  get_scan_notification_context, dashboard_stats, list_notifications)
  were extended with LEFT JOIN pe_files pf ON pf.target_id = t.target_id
  and the MALWARE target_type case.

API
---
New route:

    POST /api/malware-scans
        multipart field: file = .exe | .dll | .sys
        returns 202 {scan_id, status: "RUNNING"}

It runs the same scan lifecycle (status / phase / spider_progress /
ascan_progress) as the existing scan endpoints, so the ScanPage progress
bar polling code works unchanged. Phases emitted by the worker:

    PE_INIT  ->  PE_FEATURES  ->  PE_PREDICT  ->  PE_PERSIST  ->  DONE
                                                              ->  FAILED

How findings are stored
-----------------------
scanner.scan_pe_file() produces one finding per model plus one aggregate
finding ("ensemble verdict"). Each is mapped onto VSAWA's standard
findings / evidence / remediations schema, so the existing PDF generator
and Reports page render malware findings with zero special-casing.

Severity mapping:
    probability >= 0.85       -> CRITICAL
    probability >= 0.65       -> HIGH
    probability >= 0.50       -> MEDIUM
    < 0.50 (still malicious)  -> LOW
    benign                    -> INFO

The aggregate finding is CRITICAL if all 3 models agree, HIGH if a strict
subset flag the binary, and INFO if all three clear it. The 1-of-3
escalation is deliberate: in malware triage a missed positive is more
expensive than a false positive a human will eyeball.

Why each library is needed
--------------------------
    lief 0.16.4         : parses PE headers / sections / imports for feature extraction
    lightgbm 3.3.2      : gradient-boosted-tree classifier (text format model file)
    xgboost 3.0.0       : second gradient-boosted-tree classifier (joblib model)
    scikit-learn 1.6.1  : pipelines (PCA, scaler, RF, hashers); loaded by joblib
    joblib 1.4.2        : load .joblib model artefacts
    pandas / numpy      : feature vector handling

The model weights ship inside the package under each model's weights/
directory.

Disk + time costs
-----------------
* The container image grows by ~250 MB after pip install because of pandas
  + numpy + scikit-learn + xgboost.
* First malware scan takes ~3-8 s on a typical laptop because the models
  load lazily on the first call. Subsequent scans are sub-second per model.
* Each .joblib / .txt weight file is bundled, so no network access is
  needed once the image is built.
