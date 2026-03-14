import os
import pickle
import json
import cloudpickle
import requests
import streamlit as st

# ── GitHub config (public repo, no token needed) ──────────────────────────────
GITHUB_BASE = "https://github.com/f4tm4ze/FinalCS20/raw/main/models"

CACHE_DIR = "/tmp/cs20_models"

MODEL_FILES = {
    'Random Forest':            'baseline_rf_results.pkl',
    'SVM':                      'baseline_svm_results.pkl',
    'XGBoost':                  'xgb_results.pkl',
    'LightGBM':                 'lgbm_results.pkl',
    'Extra Trees':              'et_results.pkl',
    'Hybrid (XGB+LGBM+ET+RF)': 'hybrid_results.pkl',
}


def _download(filename: str) -> str:
    """Download a model file from GitHub if not already cached locally."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    local_path = os.path.join(CACHE_DIR, filename)

    if os.path.exists(local_path) and os.path.getsize(local_path) > 0:
        return local_path  # already cached

    url = f"{GITHUB_BASE}/{filename}"

    try:
        with requests.get(url, stream=True, timeout=120) as r:
            r.raise_for_status()
            total      = int(r.headers.get("content-length", 0))
            downloaded = 0
            progress   = st.progress(0, text=f"Downloading {filename}...")
            with open(local_path, "wb") as f:
                for chunk in r.iter_content(65536):
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total:
                        progress.progress(
                            min(downloaded / total, 1.0),
                            text=f"Downloading {filename}... {downloaded // (1024*1024)} MB / {total // (1024*1024)} MB"
                        )
            progress.empty()
    except Exception as e:
        if os.path.exists(local_path):
            os.unlink(local_path)
        raise e

    return local_path


@st.cache_resource
def load_features() -> list:
    """
    Load the feature list.
    Fast path 1: models/features.json committed in repo root.
    Fast path 2: download features.json from GitHub.
    Fallback:    download baseline pkl and extract features.
    """
    for json_path in ["models/features.json", "features.json"]:
        if os.path.exists(json_path) and os.path.getsize(json_path) > 0:
            try:
                with open(json_path) as f:
                    features = json.load(f)
                if features:
                    return features
            except (json.JSONDecodeError, ValueError):
                pass

    # Try fetching features.json directly from GitHub
    try:
        url  = f"{GITHUB_BASE}/features.json"
        resp = requests.get(url, timeout=30)
        if resp.status_code == 200 and resp.text.strip():
            features = resp.json()
            if features:
                os.makedirs("models", exist_ok=True)
                with open("models/features.json", "w") as f:
                    json.dump(features, f)
                return features
    except Exception as e:
        print(f"[model_loader] Could not fetch features.json from GitHub: {e}")

    # Final fallback: download pkl and extract
    local_path = _download("baseline_rf_results.pkl")
    with open(local_path, "rb") as f:
        data = pickle.load(f)
    features = [str(x) for x in data.get("features", [])]
    os.makedirs("models", exist_ok=True)
    with open("models/features.json", "w") as f:
        json.dump(features, f)
    return features


@st.cache_resource
def load_model(name: str):
    """Download (if needed) and load a single model. Cached after first load."""
    filename = MODEL_FILES.get(name)
    if not filename:
        st.error(f"Unknown model: {name}")
        return None

    try:
        local_path = _download(filename)
    except Exception as e:
        st.error(f"Failed to download {name}: {e}")
        return None

    try:
        with open(local_path, "rb") as f:
            try:
                data = cloudpickle.load(f)
            except Exception:
                f.seek(0)
                data = pickle.load(f)

        model = (
            data.get("classifier")
            or data.get("model")
            or data.get("et_model")
        )
        if model is None:
            st.warning(f"Could not find model object inside {filename}")
        return model

    except Exception as e:
        st.warning(f"Could not load {name}: {e}")
        return None


def load_all_models() -> tuple:
    """Returns (models_dict, features). Models load lazily on first use."""
    models   = {name: None for name in MODEL_FILES}
    features = load_features()
    return models, features