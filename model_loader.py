<<<<<<< HEAD
import pickle
import cloudpickle
import os
import streamlit as st
import numpy as np


@st.cache_resource
def load_all_models():
    """Load all trained models with caching"""
    models = {}
    features = None

    model_paths = {
        'Hybrid (XGB+LGBM+ET+RF)': 'models/hybrid_results.pkl',
        'Random Forest':            'models/baseline_rf_results.pkl',
        'SVM':                      'models/baseline_svm_results.pkl',
        'XGBoost':                  'models/xgb_results.pkl',
        'LightGBM':                 'models/lgbm_results.pkl',
        'Extra Trees':              'models/et_results.pkl',
    }

    for name, path in model_paths.items():
        if not os.path.exists(path):
            st.warning(f"Model file not found: {path}")
            continue

        try:
            with open(path, 'rb') as f:
                try:
                    data = cloudpickle.load(f)
                except Exception:
                    f.seek(0)
                    data = pickle.load(f)

            model_obj = data.get('classifier') or data.get('model') or data.get('et_model')
            if model_obj:
                models[name] = model_obj

            if features is None and 'features' in data and data['features'] is not None:
                raw = data['features']
                features = [str(f) for f in raw]

        except Exception as e:
            st.warning(f"Could not load {name}: {e}")

    if not models:
        st.error("No models could be loaded. Check that your models/ folder exists and contains .pkl files.")

    if features is None or len(features) == 0:
        st.error("Could not load features from any model file.")
        features = []

    return models, features
=======
import pickle
import cloudpickle
import os
import streamlit as st
import numpy as np


@st.cache_resource
def load_all_models():
    """Load all trained models with caching"""
    models = {}
    features = None

    model_paths = {
        'Hybrid (XGB+LGBM+ET+RF)': 'models/hybrid_results.pkl',
        'Random Forest':            'models/baseline_rf_results.pkl',
        'SVM':                      'models/baseline_svm_results.pkl',
        'XGBoost':                  'models/xgb_results.pkl',
        'LightGBM':                 'models/lgbm_results.pkl',
        'Extra Trees':              'models/et_results.pkl',
    }

    for name, path in model_paths.items():
        if not os.path.exists(path):
            st.warning(f"Model file not found: {path}")
            continue

        try:
            with open(path, 'rb') as f:
                try:
                    data = cloudpickle.load(f)
                except Exception:
                    f.seek(0)
                    data = pickle.load(f)

            model_obj = data.get('classifier') or data.get('model') or data.get('et_model')
            if model_obj:
                models[name] = model_obj

            if features is None and 'features' in data and data['features'] is not None:
                raw = data['features']
                features = [str(f) for f in raw]

        except Exception as e:
            st.warning(f"Could not load {name}: {e}")

    if not models:
        st.error("No models could be loaded. Check that your models/ folder exists and contains .pkl files.")

    if features is None or len(features) == 0:
        st.error("Could not load features from any model file.")
        features = []

    return models, features
>>>>>>> 2b51d82368086acbb8f187ee36bf08591a96c1a9
