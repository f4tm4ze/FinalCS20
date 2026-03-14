import pickle
import cloudpickle
import os
import streamlit as st


@st.cache_resource
def load_features():
    """Load features from the smallest model file only"""
    for path in ['models/baseline_rf_results.pkl', 'models/xgb_results.pkl']:
        if os.path.exists(path):
            try:
                with open(path, 'rb') as f:
                    data = pickle.load(f)
                if data.get('features'):
                    return [str(f) for f in data['features']]
            except:
                pass
    return []


@st.cache_resource
def load_model(name, path):
    """Load a single model by name - cached individually"""
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'rb') as f:
            try:
                data = cloudpickle.load(f)
            except Exception:
                f.seek(0)
                data = pickle.load(f)
        return (data.get('classifier') or 
                data.get('model') or 
                data.get('et_model'))
    except Exception as e:
        st.warning(f"Could not load {name}: {e}")
        return None


def load_all_models():
    """Returns model name dict and features - models load on demand"""
    model_paths = {
        'Random Forest':            'models/baseline_rf_results.pkl',
        'SVM':                      'models/baseline_svm_results.pkl',
        'XGBoost':                  'models/xgb_results.pkl',
        'LightGBM':                 'models/lgbm_results.pkl',
        'Extra Trees':              'models/et_results.pkl',
        'Hybrid (XGB+LGBM+ET+RF)': 'models/hybrid_results.pkl',
    }

    # Build a lazy proxy dict
    models = {}
    for name, path in model_paths.items():
        if os.path.exists(path):
            model = load_model(name, path)
            if model:
                models[name] = model

    features = load_features()
    return models, features