# A Hybrid Ensemble Model for Android Malware Detection

## Description
Android malware is becoming increasingly sophisticated, making traditional signature-based detection methods insufficient. This project implements a **hybrid stacking ensemble model** that combines multiple machine learning algorithms—XGBoost, LightGBM, Random Forest, and Extra Trees—as base learners with a Logistic Regression meta-learner to improve detection accuracy. The system can effectively classify Android apps as **malicious** or **benign** using static analysis features.

## Features
- **Hybrid Stacking Ensemble:** Combines the strengths of multiple ML algorithms.
- **High Accuracy:** Achieves over 98% accuracy in malware detection.
- **Static Analysis:** Detects malware without executing apps, ensuring safety.
- **Extensible:** Easily add new base learners or evaluation metrics.
- **User-Friendly Interface:** Input app features to get predictions (optional GUI).
