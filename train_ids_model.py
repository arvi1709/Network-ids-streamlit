import pandas as pd
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.ensemble import RandomForestClassifier
from imblearn.over_sampling import RandomOverSampler


# ==========================
# LOAD DATASET
# ==========================
def load_dataset():
    """
    Load UNSW-NB15 training and testing sets.
    Files are expected inside the 'data' folder with headers already present.
    """
    train_path = "data/UNSW_NB15_training-set.csv"
    test_path = "data/UNSW_NB15_testing-set.csv"

    print("Loading training set:", train_path)
    df_train = pd.read_csv(train_path)

    print("Loading testing set:", test_path)
    df_test = pd.read_csv(test_path)

    print("\nTraining Shape:", df_train.shape)
    print("Testing Shape :", df_test.shape)
    print("\nColumns in training set:")
    print(df_train.columns.tolist())

    return df_train, df_test


# ==========================
# COMMON FEATURE SELECTION
# ==========================
def select_features(df: pd.DataFrame):
    drop_cols = ["id", "attack_cat", "label"]
    return df.drop(columns=drop_cols, errors="ignore")


# ==========================
# BINARY MODEL (NORMAL VS ATTACK)
# ==========================
def train_binary_model(df_train, df_test):
    print("\n====== TRAINING BINARY CLASSIFICATION MODEL ======")

    X_train = select_features(df_train)
    X_test = select_features(df_test)

    y_train = df_train["label"].astype(int)
    y_test = df_test["label"].astype(int)

    print("\nTraining label distribution:")
    print(y_train.value_counts())
    print("\nTesting label distribution:")
    print(y_test.value_counts())

    categorical_cols = [c for c in X_train.columns if X_train[c].dtype == "object"]
    numeric_cols = [c for c in X_train.columns if c not in categorical_cols]

    preprocessor = ColumnTransformer(
        transformers=[
            ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_cols),
            ("num", "passthrough", numeric_cols),
        ]
    )

    ros = RandomOverSampler(random_state=42)
    X_train_resampled, y_train_resampled = ros.fit_resample(X_train, y_train)

    print("\nResampled training label distribution:")
    print(y_train_resampled.value_counts())

    model = Pipeline(steps=[
        ("preprocess", preprocessor),
        ("clf", RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1))
    ])

    print("\nTraining RandomForest model...")
    model.fit(X_train_resampled, y_train_resampled)

    print("\nEvaluating on test set...")
    y_pred = model.predict(X_test)

    print("\nClassification Report (Normal=0, Attack=1):")
    print(classification_report(y_test, y_pred, digits=4))

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    return model


# ==========================
# MULTI-CLASS (NORMAL, DoS, RECON)
# ==========================
def filter_for_multiclass(df):
    keep_classes = ["DoS", "Reconnaissance"]
    df = df[df["attack_cat"].isin(keep_classes) | (df["label"] == 0)]
    df["attack_cat"] = df["attack_cat"].fillna("Normal")
    df["attack_cat"] = df["attack_cat"].replace("", "Normal")
    return df


def train_multiclass_model(df_train, df_test):
    print("\n====== TRAINING MULTI-CLASS MODEL (Normal / DoS / Port Scan) ======")

    df_train = filter_for_multiclass(df_train)
    df_test = filter_for_multiclass(df_test)

    print("\nTraining categories:")
    print(df_train["attack_cat"].value_counts())
    print("\nTesting categories:")
    print(df_test["attack_cat"].value_counts())

    X_train = select_features(df_train)
    y_train = df_train["attack_cat"]

    X_test = select_features(df_test)
    y_test = df_test["attack_cat"]

    categorical_cols = [c for c in X_train.columns if X_train[c].dtype == "object"]
    numeric_cols = [c for c in X_train.columns if c not in categorical_cols]

    preprocessor = ColumnTransformer(
        transformers=[
            ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_cols),
            ("num", "passthrough", numeric_cols)
        ]
    )

    ros = RandomOverSampler(random_state=42)
    X_train_resampled, y_train_resampled = ros.fit_resample(X_train, y_train)

    model = Pipeline(steps=[
        ("prep", preprocessor),
        ("clf", RandomForestClassifier(n_estimators=150, random_state=42, n_jobs=-1))
    ])

    print("\nTraining multi-class model...")
    model.fit(X_train_resampled, y_train_resampled)

    print("\nEvaluating multi-class model...")
    y_pred = model.predict(X_test)

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    return model


# ==========================
# MAIN
# ==========================
def main():
    df_train, df_test = load_dataset()

    binary_model = train_binary_model(df_train, df_test)
    multi_model = train_multiclass_model(df_train, df_test)

    import joblib
    joblib.dump(binary_model, "binary_ids_model.pkl")
    joblib.dump(multi_model, "multiclass_ids_model.pkl")

    print("\n=== ALL MODELS TRAINED & SAVED SUCCESSFULLY ===")

if __name__ == "__main__":
    main()
