# Network Intrusion Detection System

## Overview

This project is an Network Intrusion Detection System (NIDS) designed to analyze network traffic data and identify potential security threats using machine learning techniques. The system is built using Python and includes Jupyter notebooks for data exploration and model development.

## Project Structure

- `app.ipynb`: Jupyter notebook for developing and testing the intrusion detection model. It includes data loading, preprocessing, feature engineering, model training, and evaluation steps.
- `Flask_app.py`: Main application script to run the IDS in a production-like environment.
- `Streamlit_app_v1.py`: Script for the user interface of the application using the Streamlit framework.
- `Streamlit_app_v2.py`: Script for the user interface of the application using the Streamlit framework.
- `FastAPI_app.py`: Entry point for the application, orchestrating the loading of models, processing of data, and initiating the IDS.
- `scaler.pkl`: Serialized scaler object used to normalize features during preprocessing.
- `le_service.pkl`, `le_protocol.pkl`, `le_attack.pkl`, `le_flag.pkl`: Serialized label encoders for transforming categorical features into numerical values.
- `nids_model.pkl`: Serialized trained machine learning model used for detecting intrusions.
- `KDDTrain+.txt`: Dataset used for training and evaluating the model. This is a subset of the KDD'99 dataset, a widely used benchmark dataset for intrusion detection.
- `image.png`: Logo image, possibly used in the user interface or documentation.
- `archive-2`: Directory potentially containing additional resources or backup data.
- `__pycache__`: Directory containing compiled Python files to improve performance.

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/AbdelilahNossair/network-intrusion-detection.git
    cd intrusion-detection
    ```

2. Create a virtual environment and activate it:
    ```sh
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. Install the required packages:
    ```sh
    pip install -r requirements.txt
    ```

## Usage

1. Ensure that all necessary files (`scaler.pkl`, `le_service.pkl`, `le_protocol.pkl`, `le_attack.pkl`, `le_flag.pkl`, `nids_model.pkl`, `KDDTrain+.txt`) are in the project directory.

2. Run the main application:
    ```sh
    python main.py
    ```

3. Alternatively, you can use the Jupyter notebook `app.ipynb` to explore the data and experiment with the model.

## Model Development

The model development process includes the following steps:

1. **Data Loading**: Load the KDD'99 dataset from `KDDTrain+.txt`.
2. **Data Preprocessing**: Handle missing values, encode categorical features using `LabelEncoder`, and scale numerical features using `StandardScaler`.
3. **Feature Engineering**: Create new features and select the most relevant features for the model.
4. **Model Training**: Train a machine learning model (e.g., Random Forest, SVM) on the preprocessed data.
5. **Model Evaluation**: Evaluate the model's performance using metrics like accuracy, precision, recall, and F1-score.
6. **Model Serialization**: Save the trained model and preprocessing objects for future use.

## Acknowledgements

- This project is developed by Abdelilah Nossair.
- Special thanks to Deloitte for their support and resources.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
