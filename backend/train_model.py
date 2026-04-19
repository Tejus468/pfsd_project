import pandas as pd
import pickle
import json
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV

# ==========================================
# 1️⃣ LOAD DATASET
# ==========================================

data = pd.read_csv(r"C:\Hackathon\trustshield-ai\backend\emails.csv")

print("Dataset Loaded Successfully")
print("Total rows:", len(data))
print("Total columns:", len(data.columns))

# Drop ID column if exists
if "Email No." in data.columns:
    data = data.drop(columns=["Email No."])

X = data.drop(columns=["Prediction"])
y = data["Prediction"]

# ==========================================
# 2️⃣ TRAIN / TEST SPLIT
# ==========================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# ==========================================
# 3️⃣ DEFINE MODELS
# ==========================================

models = {
    "Logistic Regression": LogisticRegression(max_iter=2000),
    "Random Forest": RandomForestClassifier(n_estimators=200),
    "Gradient Boosting": GradientBoostingClassifier(),
    "Linear SVM": CalibratedClassifierCV(
        LinearSVC(max_iter=5000)
    )
}

results = {}
detailed_reports = {}

# ==========================================
# 4️⃣ TRAIN & EVALUATE ALL MODELS
# ==========================================

for name, model in models.items():
    print(f"\nTraining {name}...")

    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_prob)

    cm = confusion_matrix(y_test, y_pred)
    report = classification_report(y_test, y_pred, output_dict=True)

    results[name] = {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "auc_score": round(auc, 4)
    }

    detailed_reports[name] = {
        "confusion_matrix": cm.tolist(),
        "classification_report": report
    }

# ==========================================
# 5️⃣ SELECT BEST MODEL (Based on F1)
# ==========================================

best_model_name = max(results, key=lambda x: results[x]["f1_score"])
best_model = models[best_model_name]

print("\n========== MODEL COMPARISON ==========")
for model_name, metrics in results.items():
    print(f"{model_name}: {metrics}")

print(f"\n🏆 Best Model Selected: {best_model_name}")

# ==========================================
# 6️⃣ SAVE EVERYTHING
# ==========================================

# Save best model
with open("model.pkl", "wb") as f:
    pickle.dump(best_model, f)

# Save model comparison metrics
with open("model_report.json", "w") as f:
    json.dump(results, f, indent=4)

# Save detailed evaluation (confusion matrix + classification report)
with open("detailed_report.json", "w") as f:
    json.dump(detailed_reports, f, indent=4)

# Save best model name
with open("best_model.txt", "w") as f:
    f.write(best_model_name)

# Save feature columns
feature_columns = X.columns.tolist()
with open("features.json", "w") as f:
    json.dump(feature_columns, f)

print("\n✅ Best model, reports, and features saved successfully.")