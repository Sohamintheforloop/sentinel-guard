import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from app.core.extractor import extract_features

# Sample baseline data: [legitimate vs phishing examples]
training_urls = [
    ("https://google.com", 0),
    ("https://github.com/explore", 0),
    ("https://wikipedia.org/wiki/Main_Page", 0),
    ("http://192.168.1.1/login-verify-account", 1),
    ("http://secure-paypal-update-user.account-checker.xyz", 1),
    ("http://bank-verification-login.com@badsite.net", 1),
]

X = np.vstack([extract_features(u) for u, _ in training_urls])
y = np.array([label for _, label in training_urls])

clf = RandomForestClassifier(n_estimators=50, max_depth=5, random_state=42)
clf.fit(X, y)

joblib.dump(clf, "app/models/rf_model.joblib")
print("Model trained and saved to app/models/rf_model.joblib")