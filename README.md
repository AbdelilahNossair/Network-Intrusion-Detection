# Network Intrusion Detection Experiments

A Python machine-learning project using NSL-KDD connection records. It includes an exploratory/training notebook, serialized preprocessing/model artifacts, Flask and FastAPI inference endpoints, and two Streamlit simulation interfaces.

**Scope:** the included API returns a sample connection record, and Streamlit replays/generates feature records. The repository does not implement a live packet-capture or network-blocking agent.

## Components

| File | Role |
| --- | --- |
| `app.ipynb` | Exploration, encoding, feature selection, scaling, logistic regression/XGBoost experiments, artifact export |
| `FastAPI_app.py` | Typed request schema and prediction API on port 8000 |
| `Flask_app.py` | Alternative API with saved-label inverse transformation |
| `Streamlit_app_v1.py` | Dataset-driven simulation UI |
| `Streamlit_app_v2.py` | Simulation with generated attack-like feature records |
| `nids_model.pkl`, `scaler.pkl` | Saved predictor and scaler |
| `le_*.pkl` | Category and attack-label encoders |
| `KDDTrain+.txt`, `archive-2/` | NSL-KDD data/resources |

## Setup

Use Python 3 in a separate environment. No requirements file is included; dependencies below are inferred from source imports.

```bash
git clone https://github.com/AbdelilahNossair/Network-Intrusion-Detection.git
cd Network-Intrusion-Detection
python3 -m venv .venv
source .venv/bin/activate
python -m pip install numpy pandas scikit-learn xgboost joblib matplotlib seaborn jupyterlab
python -m pip install fastapi uvicorn flask flask-cors streamlit
```

Saved sklearn/XGBoost artifacts may require the versions used when they were exported. If loading fails, recreate a compatible environment or retrain and export **all** preprocessing/model artifacts together. Load pickle/joblib files only from a trusted source.

## Run an interface

```bash
python FastAPI_app.py
```

FastAPI listens on port 8000; inspect `http://localhost:8000/docs`. Alternatively:

```bash
python Flask_app.py
streamlit run Streamlit_app_v1.py
# Or:
streamlit run Streamlit_app_v2.py
```

Choose the interface you need; they are alternatives, not a required multi-service chain. Run from the repository root because data/artifact paths are relative.

## API contract

Both APIs expose `GET /api/data` and `POST /predict`. The GET endpoint returns a **fixed example**, not a live feed. Prediction expects these features in the model's order:

```text
duration, protocol_type, service, flag, src_bytes, dst_bytes,
wrong_fragment, hot, logged_in, num_compromised, count,
srv_count, serrorate, srv_serrorate, rerror_rate
```

Note the exact API spellings `serrorate` and `srv_serrorate`; parts of the exploratory notebook use different names.

Example against FastAPI:

```bash
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"duration":0,"protocol_type":"tcp","service":"http","flag":"SF","src_bytes":491,"dst_bytes":0,"wrong_fragment":0,"hot":0,"logged_in":1,"num_compromised":0,"count":2,"srv_count":2,"serrorate":0,"srv_serrorate":0,"rerror_rate":0}'
```

The categorical values must be known to the saved encoders. FastAPI returns `prediction` and input `details`; Flask returns the decoded prediction or an error.

## Training and artifact consistency

Open `app.ipynb` with JupyterLab. It explores NSL-KDD, encodes categorical fields, selects 15 inputs, scales features, compares logistic regression and XGBoost, and exports artifacts.

The notebook includes multiple experimental/export branches. Use one coherent final branch so feature names, scaler fitting, model fitting, and label encoding remain aligned.

## Known correctness issues

The final notebook export fits LabelEncoder on “attack” and “normal”, whereas FastAPI hard-codes 0 → normal and all other values → attack. Those conventions can be reversed. Verify `le_attack.classes_` and decode predictions consistently before trusting labels. Flask already uses the saved label encoder.

The Streamlit implementations fit their own category encodings, and their prediction paths do not consistently apply the loaded scaler. Their outputs therefore need alignment with training preprocessing. Some calls use older Streamlit APIs.

The interfaces allow broad CORS access, Flask enables debug mode locally, and input errors may expose exception messages. These scripts are development prototypes. No test suite, locked environment, live-traffic validation, or reproducible production accuracy claim is provided.

## Related frontend

[Network-Intrusion-Detection-Website](https://github.com/AbdelilahNossair/Network-Intrusion-Detection-Website) calls the FastAPI sample/prediction endpoints. Keeping both projects linked makes the backend/UI relationship clear.

No standalone license file is included. Dataset and third-party usage terms apply independently.
