import joblib
model = joblib.load("binary_ids_model.pkl")
joblib.dump(model, "binary_ids_model_compressed.pkl", compress=3)
