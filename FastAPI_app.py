from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import joblib
from pydantic import BaseModel

app = FastAPI()

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# Load the trained model and scaler
model = joblib.load('nids_model.pkl')
scaler = joblib.load('scaler.pkl')

# Load the label encoders used in preprocessing
le_protocol = joblib.load('le_protocol.pkl')
le_service = joblib.load('le_service.pkl')
le_flag = joblib.load('le_flag.pkl')

class DataModel(BaseModel):
    duration: int = 0
    protocol_type: str = 'tcp'
    service: str = 'http'
    flag: str = 'SF'
    src_bytes: int = 0
    dst_bytes: int = 0
    wrong_fragment: int = 0
    hot: int = 0
    logged_in: int = 0
    num_compromised: int = 0
    count: int = 0
    srv_count: int = 0
    serrorate: float = 0.0
    srv_serrorate: float = 0.0
    rerror_rate: float = 0.0

@app.post("/predict")
async def predict(data: DataModel):
    try:
        # Preprocess the input data
        input_data = data.dict()
        input_data['protocol_type'] = le_protocol.transform([input_data['protocol_type']])[0]
        input_data['service'] = le_service.transform([input_data['service']])[0]
        input_data['flag'] = le_flag.transform([input_data['flag']])[0]

        # Select and scale features
        selected_columns = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
                            'wrong_fragment', 'hot', 'logged_in', 'num_compromised', 'count',
                            'srv_count', 'serrorate', 'srv_serrorate', 'rerror_rate']
        input_values = [[input_data[col] for col in selected_columns]]
        scaled_data = scaler.transform(input_values)

        # Make predictions
        prediction = model.predict(scaled_data)
        prediction_label = 'normal' if prediction[0] == 0 else 'attack'

        return {"prediction": prediction_label, "details": data.dict()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/data")
async def get_data():
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
    return data

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
