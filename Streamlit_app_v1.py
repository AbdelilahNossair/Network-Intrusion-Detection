import streamlit as st
import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler, LabelEncoder
import time

# Load the trained model and scaler
model = joblib.load('nids_model.pkl')
scaler = joblib.load('scaler.pkl')

# Initialize the label encoders used in preprocessing
le_protocol = LabelEncoder()
le_service = LabelEncoder()
le_flag = LabelEncoder()

# Read the dataset and verify columns
columns = (['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land',
            'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
            'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
            'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
            'srv_count', 'serrorate', 'srv_serrorate', 'rerror_rate', 'srv_rerror_rate',
            'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
            'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
            'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
            'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
            'attack', 'level'])
df = pd.read_csv("KDDTrain+.txt", names=columns)

# Convert attack labels
df['attack'] = df['attack'].apply(lambda x: 'normal' if x == 'normal' else 'attack')

# Fit the label encoders on the training data categories
cat_features = ['protocol_type', 'service', 'flag']
le_protocol.fit(df['protocol_type'])
le_service.fit(df['service'])
le_flag.fit(df['flag'])

# Initialize Streamlit components
st.title('Network Intrusion Detection System')

# Project description
st.markdown("""
### Project Description
Network Intrusion Detection Systems (NIDS) monitor network traffic for suspicious activity and potential threats (unauthorized access or denial-of-service attacks). \n
This NIDS identifies normal and malicious activities, helping to protect the network from cyber threats.
### Types of Network attacks:
        Denial of Service (DoS)\n
        User to Root (U2R)\n
        Remote to Local (R2L)\n
        Probing\n
""")

st.header('Real-Time Intrusion Detection Dashboard')


# Initialize variables for tracking
analysis_count = 0
attack_count = 0
all_data = pd.DataFrame()
attacks_data = pd.DataFrame()

# Function to simulate fetching new network activity data
def fetch_new_data():
    # In a real application, this would be replaced with actual data fetching
    data = pd.DataFrame({
        'duration': [0],
        'protocol_type': ['tcp'],
        'service': ['http'],
        'flag': ['SF'],
        'src_bytes': [181],
        'dst_bytes': [5450],
        'wrong_fragment': [0],
        'hot': [0],
        'logged_in': [1],
        'num_compromised': [0],
        'count': [2],
        'srv_count': [2],
        'serrorate': [0.0],
        'srv_serrorate': [0.0],
        'rerror_rate': [0.0]
    })
    return data

# Placeholder for displaying results and tables
result_placeholder = st.empty()
network_table_placeholder = st.empty()
attacks_table_placeholder = st.empty()
timer_placeholder = st.empty()
stats_placeholder = st.empty()

# Continuous monitoring and prediction
while True:
    new_data = fetch_new_data()
    new_data['timestamp'] = pd.Timestamp.now()

    # Preprocess the input data
    new_data['protocol_type'] = le_protocol.transform(new_data['protocol_type'])
    new_data['service'] = le_service.transform(new_data['service'])
    new_data['flag'] = le_flag.transform(new_data['flag'])
    
    # Select and scale features
    selected_columns = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'wrong_fragment', 'hot', 'logged_in', 'num_compromised', 'count', 'srv_count', 'serrorate', 'srv_serrorate', 'rerror_rate']
    scaled_data = new_data[selected_columns]
    scaled_data = scaler.transform(scaled_data)
    
    # Make predictions
    prediction = model.predict(scaled_data)
    prediction_label = 'Normal' if prediction[0] == 0 else 'Attack'
    new_data['prediction'] = prediction_label
    
    # Update tracking variables
    analysis_count += 1
    if prediction_label == 'Attack':
        attack_count += 1
        attacks_data = pd.concat([new_data, attacks_data], ignore_index=True)
    
    all_data = pd.concat([new_data, all_data], ignore_index=True)

    # Display stats
    stats_placeholder.markdown(f"""
    **Total Analyses:** {analysis_count}  
    **Total Attacks:** {attack_count}
    """)

    # Display network activity table
    network_table_placeholder.dataframe(all_data)

    # Display attacks table with delete option
    def delete_attack(index):
        global attacks_data
        attacks_data = attacks_data.drop(index).reset_index(drop=True)
        st.experimental_rerun()

    for i, row in attacks_data.iterrows():
        attacks_table_placeholder.markdown(f"""
        **Attack detected at {row['timestamp']}**  
        - **Protocol:** {row['protocol_type']}
        - **Service:** {row['service']}
        - **Flag:** {row['flag']}
        - **Source Bytes:** {row['src_bytes']}
        - **Destination Bytes:** {row['dst_bytes']}
        - **Logged In:** {row['logged_in']}
        - **Count:** {row['count']}
        """)
        if st.button('Delete', key=f'delete_{i}'):
            delete_attack(i)

    # Countdown timer
    for i in range(10, 0, -1):
        timer_placeholder.write(f'Next analysis in {i} seconds...')
        time.sleep(1)
    
    timer_placeholder.empty()  # Clear the timer text
