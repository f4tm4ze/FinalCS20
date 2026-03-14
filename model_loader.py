import os
import pickle
import json
import cloudpickle
import requests
import streamlit as st

# ── HuggingFace config ────────────────────────────────────────────────────────
HF_BASE  = "https://huggingface.co/idowntknow/finalcs20-models/resolve/main"
HF_TOKEN = st.secrets.get("HF_TOKEN", "")

CACHE_DIR = "/tmp/models"

MODEL_FILES = {
    'Random Forest':            'baseline_rf_results.pkl',
    'SVM':                      'baseline_svm_results.pkl',
    'XGBoost':                  'xgb_results.pkl',
    'LightGBM':                 'lgbm_results.pkl',
    'Extra Trees':              'et_results.pkl',
    'Hybrid (XGB+LGBM+ET+RF)': 'hybrid_results.pkl',
}


def _download(filename: str) -> str:
    """Download a model file from HuggingFace if not already cached locally."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    local_path = os.path.join(CACHE_DIR, filename)

    if os.path.exists(local_path):
        return local_path  # already cached, skip download

    url     = f"{HF_BASE}/{filename}"
    headers = {"Authorization": f"Bearer {HF_TOKEN}"} if HF_TOKEN else {}

    with requests.get(url, headers=headers, stream=True) as r:
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

    return local_path


@st.cache_resource
def load_features() -> list:
    """
    Load the feature list.
    Fast path: models/features.json committed to GitHub (tiny, instant).
    Fallback:  download baseline pkl from HuggingFace and extract features.
    """
    if os.path.exists("models/features.json"):
        with open("models/features.json") as f:
            return json.load(f)

    # Fallback — only runs if features.json is missing
    local_path = _download("baseline_rf_results.pkl")
    with open(local_path, "rb") as f:
        data = pickle.load(f)
    return [str(x) for x in data.get("features", [])]


@st.cache_resource
def load_model(name: str):
    """
    Download (if needed) and load a single model by name.
    Result is cached — subsequent calls with the same name are instant.
    """
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
    """
    Returns (models_dict, features).
    Models dict only contains names as keys — actual loading happens lazily
    via load_model(name) when the user picks one in the sidebar.
    """
    models   = {name: None for name in MODEL_FILES}
    features = load_features()
    return models, features