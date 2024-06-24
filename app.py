from flask import Flask, request, jsonify, render_template
import numpy as np
import pickle
import warnings
from feature import FeatureExtraction
import traceback

warnings.filterwarnings('ignore')

# Load the pre-trained model
try:
    with open("phishing_model.pkl", "rb") as file:
        gbc = pickle.load(file)
except Exception as e:
    print(f"Error loading model: {e}")
    gbc = None

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"]
        print(f"Received URL: {url}")
        try:
            obj = FeatureExtraction(url)
            features = obj.get_features()
            print(f"Extracted Features: {features}")
            x = np.array(features).reshape(1, -1)

            y_pred = gbc.predict(x)[0]
            y_pro_non_phishing = gbc.predict_proba(x)[0, 0]
            y_pro_phishing = gbc.predict_proba(x)[0, 1]
            pred = "It is {0:.2f} % likely to be a phishing site".format(y_pro_phishing * 100)
            print(f"Prediction: {y_pred}, Probability Safe: {y_pro_non_phishing}, Probability Phishing: {y_pro_phishing}")
            return render_template('index.html', xx=round(y_pro_phishing, 2), url=url, prediction=pred)
        except Exception as e:
            print(f"Error during prediction: {e}")
            traceback.print_exc()
            return render_template('index.html', xx=-1, error="An error occurred during prediction")
    return render_template("index.html", xx=-1)

@app.route("/api/predict", methods=["POST"])
def api_predict():
    try:
        data = request.get_json()
        print(f"Received data: {data}")
        
        if not data or "url" not in data:
            return jsonify({"error": "URL is required"}), 400

        url = data.get("url")
        obj = FeatureExtraction(url)
        features = obj.get_features()
        print(f"Extracted Features: {features}")
        x = np.array(features).reshape(1, -1)

        y_pred = int(gbc.predict(x)[0])
        y_pro_non_phishing = float(gbc.predict_proba(x)[0, 0])
        y_pro_phishing = float(gbc.predict_proba(x)[0, 1])
        pred = f"It is {y_pro_phishing * 100:.2f}% likely to be a phishing site"
        print(f"Prediction: {y_pred}, Probability Safe: {y_pro_non_phishing}, Probability Phishing: {y_pro_phishing}")

        return jsonify({
            "prediction": y_pred,
            "probability_safe": y_pro_non_phishing,
            "probability_phishing": y_pro_phishing,
            "message": pred
        })
    except Exception as e:
        print(f"Error in predict function: {e}")
        traceback.print_exc()  # Print the full stack trace
        return jsonify({"error": "An internal error occurred"}), 500

if __name__ == "__main__":
    print("Available routes:")
    print(app.url_map)
    app.run(debug=True)
