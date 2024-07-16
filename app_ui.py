import streamlit as st
import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler, LabelEncoder
import time
import random

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
st.header('Real-Time Intrusion Detection Dashboard')

# Project description
st.markdown("""
### Project Description
**Network Intrusion Detection Systems (NIDS)** monitor network traffic for suspicious activity and potential threats. \n
This NIDS identifies normal and malicious activities, helping to protect the network from cyber threats.
### Types of Network attacks Detected by our system:
- **Denial of Service (DoS):** An attacker floods a network resource with excessive requests, overwhelming the system and causing legitimate users to be unable to access services.
- **User to Root (U2R):** An attacker begins with access to a normal user account on a system and exploits vulnerabilities to gain root or administrative privileges.
- **Remote to Local (R2L):** An attacker who does not have an account on the victim's system exploits some vulnerability to gain (unauthorized) local access as a user.
- **Probing:** An attacker scans a network or system to gather information about its vulnerabilities, configuration, and available services.
""")

# Initialize variables for tracking
analysis_count = 0
attack_count = 0
all_data = pd.DataFrame()
attacks_data = pd.DataFrame()

# Generate example attacks
def generate_dos_attack():
    data = {
        'duration': [0],
        'protocol_type': ['tcp'],
        'service': ['http'],
        'flag': ['S0'],
        'src_bytes': [0],
        'dst_bytes': [0],
        'land': [0],
        'wrong_fragment': [0],
        'urgent': [0],
        'hot': [0],
        'num_failed_logins': [0],
        'logged_in': [0],
        'num_compromised': [0],
        'root_shell': [0],
        'su_attempted': [0],
        'num_root': [0],
        'num_file_creations': [0],
        'num_shells': [0],
        'num_access_files': [0],
        'num_outbound_cmds': [0],
        'is_host_login': [0],
        'is_guest_login': [0],
        'count': [511],
        'srv_count': [511],
        'serrorate': [1.0],
        'srv_serrorate': [1.0],
        'rerror_rate': [0.0],
        'srv_rerror_rate': [0.0],
        'same_srv_rate': [0.0],
        'diff_srv_rate': [0.0],
        'srv_diff_host_rate': [0.0],
        'dst_host_count': [255],
        'dst_host_srv_count': [255],
        'dst_host_same_srv_rate': [1.0],
        'dst_host_diff_srv_rate': [0.0],
        'dst_host_same_src_port_rate': [1.0],
        'dst_host_srv_diff_host_rate': [0.0],
        'dst_host_serror_rate': [1.0],
        'dst_host_srv_serror_rate': [1.0],
        'dst_host_rerror_rate': [0.0],
        'dst_host_srv_rerror_rate': [0.0],
        'timestamp': [pd.Timestamp.now()]
    }
    return pd.DataFrame(data)

def generate_port_scanning_attack():
    data = {
        'duration': [0],
        'protocol_type': ['tcp'],
        'service': ['ftp_data'],
        'flag': ['SF'],
        'src_bytes': [0],
        'dst_bytes': [0],
        'land': [0],
        'wrong_fragment': [0],
        'urgent': [0],
        'hot': [0],
        'num_failed_logins': [0],
        'logged_in': [0],
        'num_compromised': [0],
        'root_shell': [0],
        'su_attempted': [0],
        'num_root': [0],
        'num_file_creations': [0],
        'num_shells': [0],
        'num_access_files': [0],
        'num_outbound_cmds': [0],
        'is_host_login': [0],
        'is_guest_login': [0],
        'count': [50],
        'srv_count': [50],
        'serrorate': [0.0],
        'srv_serrorate': [0.0],
        'rerror_rate': [1.0],
        'srv_rerror_rate': [1.0],
        'same_srv_rate': [0.0],
        'diff_srv_rate': [1.0],
        'srv_diff_host_rate': [0.0],
        'dst_host_count': [255],
        'dst_host_srv_count': [1],
        'dst_host_same_srv_rate': [0.0],
        'dst_host_diff_srv_rate': [1.0],
        'dst_host_same_src_port_rate': [0.0],
        'dst_host_srv_diff_host_rate': [0.0],
        'dst_host_serror_rate': [0.0],
        'dst_host_srv_serror_rate': [0.0],
        'dst_host_rerror_rate': [1.0],
        'dst_host_srv_rerror_rate': [1.0],
        'timestamp': [pd.Timestamp.now()]
    }
    return pd.DataFrame(data)

def generate_brute_force_attack():
    data = {
        'duration': [0],
        'protocol_type': ['tcp'],
        'service': ['ssh'],
        'flag': ['REJ'],
        'src_bytes': [0],
        'dst_bytes': [0],
        'land': [0],
        'wrong_fragment': [0],
        'urgent': [0],
        'hot': [0],
        'num_failed_logins': [5],
        'logged_in': [0],
        'num_compromised': [0],
        'root_shell': [0],
        'su_attempted': [0],
        'num_root': [0],
        'num_file_creations': [0],
        'num_shells': [0],
        'num_access_files': [0],
        'num_outbound_cmds': [0],
        'is_host_login': [0],
        'is_guest_login': [0],
        'count': [10],
        'srv_count': [10],
        'serrorate': [0.0],
        'srv_serrorate': [0.0],
        'rerror_rate': [1.0],
        'srv_rerror_rate': [1.0],
        'same_srv_rate': [0.0],
        'diff_srv_rate': [1.0],
        'srv_diff_host_rate': [0.0],
        'dst_host_count': [255],
        'dst_host_srv_count': [255],
        'dst_host_same_srv_rate': [0.0],
        'dst_host_diff_srv_rate': [1.0],
        'dst_host_same_src_port_rate': [0.0],
        'dst_host_srv_diff_host_rate': [0.0],
        'dst_host_serror_rate': [0.0],
        'dst_host_srv_serror_rate': [0.0],
        'dst_host_rerror_rate': [1.0],
        'dst_host_srv_rerror_rate': [1.0],
        'timestamp': [pd.Timestamp.now()]
    }
    return pd.DataFrame(data)

# Function to simulate fetching new network activity data
def fetch_new_data():
    data_types = ['normal', 'dos', 'port_scan', 'brute_force']
    probabilities = [0.3, 0.5, 0.1, 0.1]  # Higher probability for normal data
    selected_type = random.choices(data_types, probabilities)[0]
    
    if selected_type == 'normal':
        data = {
            'duration': [0],
            'protocol_type': ['tcp'],
            'service': ['http'],
            'flag': ['SF'],
            'src_bytes': [181],
            'dst_bytes': [5450],
            'land': [0],
            'wrong_fragment': [0],
            'urgent': [0],
            'hot': [0],
            'num_failed_logins': [0],
            'logged_in': [1],
            'num_compromised': [0],
            'root_shell': [0],
            'su_attempted': [0],
            'num_root': [0],
            'num_file_creations': [0],
            'num_shells': [0],
            'num_access_files': [0],
            'num_outbound_cmds': [0],
            'is_host_login': [0],
            'is_guest_login': [0],
            'count': [2],
            'srv_count': [2],
            'serrorate': [0.0],
            'srv_serrorate': [0.0],
            'rerror_rate': [0.0],
            'timestamp': [pd.Timestamp.now()]
        }
        return pd.DataFrame(data)
    elif selected_type == 'dos':
        return generate_dos_attack()
    elif selected_type == 'port_scan':
        return generate_port_scanning_attack()
    elif selected_type == 'brute_force':
        return generate_brute_force_attack()

# Placeholder for displaying results and tables
result_placeholder = st.empty()
network_table_placeholder = st.empty()
attacks_table_placeholder = st.empty()
timer_placeholder = st.empty()
stats_placeholder = st.empty()

# Continuous monitoring and prediction
while True:
    new_data = fetch_new_data()

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
    network_table_placeholder.write("### Network Activity Table")
    network_table_placeholder.dataframe(all_data)

    # Display attacks table with delete option
    def delete_attack(index):
        global attacks_data
        attacks_data = attacks_data.drop(index).reset_index(drop=True)
        st.experimental_rerun()

    attack_rows = []
    for i, row in attacks_data.iterrows():
        attack_rows.append(
            f"**Attack detected at {row['timestamp']}**<br>"
            f"- **Protocol:** {row['protocol_type']}<br>"
            f"- **Service:** {row['service']}<br>"
            f"- **Flag:** {row['flag']}<br>"
            f"- **Source Bytes:** {row['src_bytes']}<br>"
            f"- **Destination Bytes:** {row['dst_bytes']}<br>"
            f"- **Logged In:** {row['logged_in']}<br>"
            f"- **Count:** {row['count']}<br>"
            f'<button onClick="delete_attack({i})">Delete</button>'
        )
    
    attacks_table_placeholder.markdown("<br>".join(attack_rows), unsafe_allow_html=True)

    # Countdown timer
    for i in range(10, 0, -1):
        timer_placeholder.write(f'Next analysis in {i} seconds...')
        time.sleep(1)
    
    timer_placeholder.empty()  # Clear the timer text

