
import pickle
import cloudpickle
import os

files = {
    'hybrid': 'models/hybrid_results.pkl',
    'rf':     'models/baseline_rf_results.pkl',
    'svm':    'models/baseline_svm_results.pkl',
    'xgb':    'models/xgb_results.pkl',
    'lgbm':   'models/lgbm_results.pkl',
    'et':     'models/et_results.pkl',
}

for name, path in files.items():
    if not os.path.exists(path):
        print(f"{name}: FILE NOT FOUND at {path}")
        continue

    try:
        with open(path, 'rb') as f:
            try:
                data = cloudpickle.load(f)
            except Exception:
                f.seek(0)
                data = pickle.load(f)

        print(f"\n{name}: keys = {list(data.keys())}")

        if 'features' in data:
            feats = data['features']
            print(f"  features type : {type(feats)}")
            print(f"  features count: {len(feats)}")
            print(f"  first 5       : {list(feats)[:5]}")
        else:
            print("  NO 'features' key found")

        if 'classifier' in data:
            clf = data['classifier']
            print(f"  classifier    : {type(clf).__name__}")
            if hasattr(clf, 'n_features_in_'):
                print(f"  n_features_in_: {clf.n_features_in_}")
            if hasattr(clf, 'feature_names_in_'):
                fn = clf.feature_names_in_
                print(f"  feature_names : {list(fn)[:5]} ...")

        if 'metrics' in data:
            print(f"  metrics keys  : {list(data['metrics'][0])[:3] if hasattr(data['metrics'], '__iter__') else 'present'}")

    except Exception as e:
        print(f"{name}: ERROR — {e}")