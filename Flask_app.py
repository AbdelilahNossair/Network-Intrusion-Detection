from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler

app = Flask(__name__)
CORS(app)  # Allow requests from any origin

# Load the trained model and scaler
model = joblib.load('nids_model.pkl')
scaler = joblib.load('scaler.pkl')

# Load the label encoders used in preprocessing
le_protocol = joblib.load('le_protocol.pkl')
le_service = joblib.load('le_service.pkl')
le_flag = joblib.load('le_flag.pkl')
le_attack = joblib.load('le_attack.pkl')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.json
        # Preprocess the input data
        data['protocol_type'] = le_protocol.transform([data['protocol_type']])[0]
        data['service'] = le_service.transform([data['service']])[0]
        data['flag'] = le_flag.transform([data['flag']])[0]

        # Select and scale features
        selected_columns = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
                            'wrong_fragment', 'hot', 'logged_in', 'num_compromised', 'count',
                            'srv_count', 'serrorate', 'srv_serrorate', 'rerror_rate']
        input_data = [[data[col] for col in selected_columns]]
        scaled_data = scaler.transform(input_data)

        # Make predictions
        prediction = model.predict(scaled_data)
        prediction_label = le_attack.inverse_transform(prediction)[0]

        return jsonify({'prediction': prediction_label})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/data', methods=['GET'])
def get_data():
    data = {
        'duration': 0,
        'protocol_type': 'tcp',
        'service': 'http',
        'flag': 'SF',
        'src_bytes': 491,
        'dst_bytes': 0,
        'wrong_fragment': 0,
        'hot': 0,
        'logged_in': 1,
        'num_compromised': 0,
        'count': 2,
        'srv_count': 2,
        'serrorate': 0.0,
        'srv_serrorate': 0.0,
        'rerror_rate': 0.0
    }
    return jsonify(data)

if __name__ == '__main__':
    app.run(debug=True)
