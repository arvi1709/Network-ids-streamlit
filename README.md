# Network Intrusion Detection System (NIDS)

A comprehensive machine learning-based network intrusion detection system with real-time dashboard and ARP spoofing detection capabilities.

## 📋 Project Overview

This project implements a **Network Intrusion Detection System (NIDS)** that combines machine learning models with network security features to detect and classify network attacks. The system provides both real-time visualization and detection capabilities through an interactive Streamlit web interface.

**Key Features:**
- 🤖 **Binary & Multi-class ML Models** - Detect and classify network attacks
- 📊 **Interactive Dashboard** - Real-time visualization of network events and attacks
- 🛡️ **ARP Spoofing Detection** - Monitor network for ARP spoofing attempts
- 🕸️ **Network Graph Visualization** - Visualize attacker-target relationships
- 📈 **Performance Metrics** - Comprehensive attack statistics and trends

## 👥 Team

- **Anshuman** (231302042)
- **Deepak** (231302069)
- **Arvind** (231302109)

**Role:** B.Tech CSE (AI & ML) Students

## 🏗️ Project Architecture

### Components

#### 1. **[app.py](app.py)** - Main Streamlit Application
The core web application with four main pages:

- **Dashboard Page**
  - Displays KPI metrics (Total Events, Attacks Detected, ARP Spoof Alerts)
  - Line chart showing attack events over time
  - Bar chart of attack category distribution
  - Network graph visualization showing IP relationships (attacker → target)
  - Live event logs table

- **ML Attack Detection Page**
  - Upload CSV files with network traffic data (UNSW-NB15 format)
  - Two prediction modes:
    - Binary: Normal vs Attack
    - Multi-class: Normal vs DoS vs Reconnaissance
  - Real-time predictions on uploaded data
  - Automatic logging of detected attacks to dashboard

- **ARP Spoof Detector Page**
  - Real-time ARP spoofing detection using Scapy
  - Configurable scan duration (5-60 seconds)
  - Detects MAC address changes for suspicious IP addresses
  - Maintains history of ARP scan results

- **About Page**
  - Project information and team details
  - Technologies used

#### 2. **[train_ids_model.py](train_ids_model.py)** - Model Training Pipeline
Trains two machine learning models on the UNSW-NB15 dataset:

**Binary Classification Model:**
- Classifies network traffic as Normal (0) or Attack (1)
- Uses RandomForestClassifier with 100 estimators
- Handles class imbalance with RandomOverSampler
- Includes categorical feature encoding with OneHotEncoder

**Multi-class Classification Model:**
- Classifies network traffic into three categories:
  - Normal
  - DoS (Denial of Service)
  - Reconnaissance (Port Scanning)
- Uses RandomForestClassifier with 150 estimators
- Balances class distribution through oversampling

**Key Features:**
- Automatic feature selection (excludes id, attack_cat, label)
- Categorical and numeric feature preprocessing pipeline
- Classification reports and confusion matrices for model evaluation
- Saves trained models as pickle files: `binary_ids_model.pkl` and `multiclass_ids_model.pkl`

#### 3. **[testtt.py](testtt.py)** - Model Compression Utility
- Loads the trained binary model
- Compresses the model with compression level 3
- Saves as `binary_ids_model_compressed.pkl`

## 📊 Dataset

The project uses the **UNSW-NB15** (UNSW Network Benchmark Dataset 15) dataset:

**Files:**
- `data/UNSW_NB15_training-set.csv` - Training dataset with labeled network flows
- `data/UNSW_NB15_testing-set.csv` - Testing dataset for model evaluation
- `data/NUSW-NB15_features.csv` - Feature descriptions and metadata

**Dataset Characteristics:**
- Contains 45 features including source/destination IPs, ports, protocols, and flow statistics
- Labeled with attack categories: DoS, Reconnaissance, Backdoor, Exploitation, etc.
- Binary labels: 0 (Normal), 1 (Attack)
- Used for training both binary and multi-class classification models

## 🔧 Technologies Used

### Core Libraries
- **Streamlit (1.51.0)** - Web UI framework
- **Scikit-learn (1.7.2)** - Machine learning algorithms
- **Imbalanced-learn (0.14.0)** - Class imbalance handling

### Data Processing
- **Pandas (2.3.3)** - Data manipulation and analysis
- **NumPy (2.3.5)** - Numerical computing

### Visualization
- **Plotly (6.5.0)** - Interactive charts and graphs
- **NetworkX (3.6)** - Network graph creation and visualization
- **Matplotlib (3.10.7)** - Additional plotting capabilities

### Network Security
- **Scapy (2.6.1)** - Packet manipulation and ARP spoofing detection

### Model Persistence
- **Joblib (1.5.2)** - Model serialization and caching

## 📦 Installation & Setup

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Steps

1. **Clone the Repository**
   ```bash
   git clone https://github.com/arvi1709/Network-ids-streamlit.git
   cd Network-ids-streamlit
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Train Models** (if not already trained)
   ```bash
   python train_ids_model.py
   ```
   This generates:
   - `binary_ids_model.pkl`
   - `multiclass_ids_model.pkl`

4. **Run the Streamlit Application**
   ```bash
   streamlit run app.py
   ```
   The application will be available at `http://localhost:8501`

## 🚀 Usage

### 1. Dashboard
- View real-time metrics and attack statistics
- Monitor attack trends over time
- Visualize network topology and relationships

### 2. ML Attack Detection
1. Navigate to "ML Attack Detection" tab
2. Upload a CSV file with network data (same structure as UNSW-NB15 testing set)
3. Choose between Binary or Multi-class prediction mode
4. Click "Run Prediction" to analyze the data
5. View results and automatically logged events in the dashboard

### 3. ARP Spoof Detector
1. Navigate to "ARP Spoof Detector" tab
2. Adjust scan duration (5-60 seconds)
3. Click "Scan my network for ARP spoofing"
4. Review detected alerts and scan history

**Note:** ARP spoofing detection requires:
- Administrator/root privileges
- Appropriate network permissions
- On Windows: Npcap/WinPcap installation
- On Linux/macOS: Scapy requirements

## 📈 Model Performance

### Binary Model Metrics
- Distinguishes between normal and attack traffic
- Uses ensemble learning (RandomForest) for robustness
- Handles highly imbalanced datasets

### Multi-class Model Metrics
- Classifies three attack categories plus normal traffic
- Higher estimators (150) for better multi-class separation
- Optimized for DoS and Reconnaissance detection

Run `python train_ids_model.py` to see detailed classification reports and confusion matrices.

## 📁 Project Structure

```
Network-ids-streamlit/
├── app.py                                      # Main Streamlit application
├── train_ids_model.py                          # Model training pipeline
├── testtt.py                                   # Model compression utility
├── requirements.txt                            # Python dependencies
├── binary_ids_model.pkl                        # Trained binary model
├── multiclass_ids_model.pkl                    # Trained multi-class model
├── data/
│   ├── UNSW_NB15_training-set.csv             # Training dataset
│   ├── UNSW_NB15_testing-set.csv              # Testing dataset
│   └── NUSW-NB15_features.csv                 # Feature descriptions
└── README.md                                   # This file
```

## 🔐 Security Considerations

- Models are trained on realistic network traffic data
- ARP spoofing detection monitors network layer for anomalies
- Session state maintains local logs without external storage
- No sensitive data transmission or storage

## 🛠️ Troubleshooting

### Model Files Not Found
- Run `python train_ids_model.py` to train and generate model files

### ARP Scan Errors
- Ensure running with administrator/root privileges
- Check Scapy installation: `pip install scapy`
- Verify network interface availability

### Upload CSV Errors
- Ensure CSV has same columns as UNSW-NB15 dataset
- Check for missing or misnamed columns (id, attack_cat, label)

## 📚 References

- **UNSW-NB15 Dataset:** [UNSW Cyber Security Dataset](https://www.unsw.adfa.edu.au/unsw-canberra/academic-schools/school-of-cyber-and-information-systems/cyber-security-datasets)
- **Scikit-learn Documentation:** [scikit-learn.org](https://scikit-learn.org/)
- **Streamlit Documentation:** [streamlit.io](https://streamlit.io/)
- **Scapy Documentation:** [scapy.readthedocs.io](https://scapy.readthedocs.io/)

## 📝 License

This project is developed for educational and research purposes.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

---

**Last Updated:** December 2025
