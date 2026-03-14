
import pickle
import cloudpickle
import os

model_paths = {
    'Hybrid (XGB+LGBM+ET+RF)': 'models/hybrid_results.pkl',
    'XGBoost':                  'models/xgb_results.pkl',
    'LightGBM':                 'models/lgbm_results.pkl',
    'Extra Trees':              'models/et_results.pkl',
}

for name, path in model_paths.items():
    if os.path.exists(path):
        try:
            with open(path, 'rb') as f:
                data = pickle.load(f, encoding='latin1')  # load old format
            with open(path, 'wb') as f:
                cloudpickle.dump(data, f)                 # re-save with current numpy
            print(f"Fixed: {name}")
        except Exception as e:
            print(f"Failed {name}: {e}")
