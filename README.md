# A Hybrid Ensemble Model for Android Malware Detection

## Description
Android malware is becoming increasingly sophisticated, making traditional signature-based detection methods insufficient. This project implements a **hybrid stacking ensemble model** that combines multiple machine learning algorithms—XGBoost, LightGBM, Random Forest, and Extra Trees—as base learners with a Logistic Regression meta-learner to improve detection accuracy. The system can effectively classify Android apps as **malicious** or **benign** using static analysis features.

## Features
- **Hybrid Stacking Ensemble:** Combines the strengths of multiple ML algorithms.
- **High Accuracy:** Achieves over 98% accuracy in malware detection.
- **Static Analysis:** Detects malware without executing apps, ensuring safety.
- **Extensible:** Easily add new base learners or evaluation metrics.
- **User-Friendly Interface:** Input app features to get predictions.

## Usage
- **Input Android app features (or APK data preprocessed to features).
- **The model predicts malicious or benign.
- **Results include probability scores for better analysis.

## Evaluation Metrics
- **Accuracy
- **Precision
- **Recall
- **F1-Score
- **ROC-AUC

## Key Advantages
- **Combines multiple ML models for improved detection.
- **Works with static app features, making it safer than dynamic methods.
- **Easily extendable and adaptable to new malware variants.

## Technologies Used
- **Python, scikit-learn, XGBoost, LightGBM
- **Pandas, NumPy for data processing
- **Streamlit
