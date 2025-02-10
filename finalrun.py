import streamlit as st
import joblib
from datetime import datetime
import mysql.connector
from mysql.connector import Error
import hashlib
import nltk
from nltk.tokenize import RegexpTokenizer
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
import warnings
import re
from datetime import datetime
import time
import speech_recognition as sr
import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.ensemble import RandomForestClassifier
from typing import Tuple, Optional, Dict, Any
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go 
from plotly.subplots import make_subplots
import librosa
import soundfile as sf
import pickle
from scipy.spatial.distance import cosine
from datetime import timedelta

ADMIN_CREDENTIALS = {
    'username': 'admin',
    'password_hash': '21232f297a57a5a743894a0e4a801fc3'  # Hash for 'admin'
}

def verify_admin_login(username: str, password: str) -> bool:
    """Verify admin credentials"""
    if username != ADMIN_CREDENTIALS['username']:
        return False
    input_hash = hash_password_md5(password)
    return input_hash == ADMIN_CREDENTIALS['password_hash']

def get_all_user_activities() -> pd.DataFrame:
    """Fetch all user activities for admin monitoring"""
    conn = init_db_connection()
    if conn is None:
        st.error("Database connection failed")
        return pd.DataFrame()

    try:
        query = """
        SELECT 
            l.Log_id,
            l.User_id,
            CONCAT(u.F_name, ' ', COALESCE(u.L_name, '')) as Full_Name,
            l.IP_Address,
            l.L_Timestamp,
            l.Activity_Type,
            l.Status,
            l.Access_Level
        FROM LOG l
        JOIN user u ON l.User_id = u.User_id
        ORDER BY l.L_Timestamp DESC
        LIMIT 1000
        """
        return pd.read_sql(query, conn)
    except Exception as e:
        st.error(f"Error fetching user activities: {e}")
        return pd.DataFrame()
    finally:
        if conn:
            conn.close()

def get_all_transactions() -> pd.DataFrame:
    """Fetch all transactions for admin monitoring"""
    conn = init_db_connection()
    if conn is None:
        st.error("Database connection failed")
        return pd.DataFrame()

    try:
        query = """
        SELECT 
            t.*,
            CONCAT(u.F_name, ' ', COALESCE(u.L_name, '')) as Full_Name
        FROM TRANSACTION t
        JOIN user u ON t.User_id = u.User_id
        ORDER BY t.Timestamp DESC
        LIMIT 1000
        """
        df = pd.read_sql(query, conn)
        
        # Convert Amount to numeric and add fraud flag
        df['Amount'] = pd.to_numeric(df['Amount'], errors='coerce')
        df['is_fraudulent'] = df['Amount'].ge(100000)
        return df
    except Exception as e:
        st.error(f"Error fetching transactions: {e}")
        return pd.DataFrame()
    finally:
        if conn:
            conn.close()
def style_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Apply styling to the dataframe"""
    def highlight_fraudulent(row):
        return ['background-color: #ffcccc' if row['Amount'] >= 100000 else '' for _ in row]
    
    return df.style.apply(highlight_fraudulent, axis=1)
# (Keep all the previous imports and existing code from the original script)
warnings.filterwarnings('ignore')

# Download NLTK data with error handling
try:
    nltk.data.find('corpora/stopwords')
except LookupError:
    nltk.download('stopwords')

try:
    nltk.data.find('corpora/wordnet')
except LookupError:
    nltk.download('wordnet')
    nltk.download('omw-1.4')

# Initialize NLTK components
stop_words = set(stopwords.words('english'))
lemmatizer = WordNetLemmatizer()

# Number words dictionary
NUMBER_WORDS = {
    'one': '1', 'two': '2', 'three': '3', 'four': '4', 'five': '5',
    'six': '6', 'seven': '7', 'eight': '8', 'nine': '9', 'ten': '10',
    'first': '1', 'second': '2', 'third': '3', 'fourth': '4', 'fifth': '5',
    'sixth': '6', 'seventh': '7', 'eighth': '8', 'ninth': '9', 'tenth': '10'
}

# Database configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'code',
    'database': 'dbms'
}


class BankingSystem:
    def __init__(self):
        self.lemmatizer = WordNetLemmatizer()
        self.tokenizer = RegexpTokenizer(r'\w+')
        self.stop_words = set(stopwords.words('english'))
        self.recognizer = sr.Recognizer()

    def connect_db(self):
        try:
            return mysql.connector.connect(**DB_CONFIG)
        except mysql.connector.Error as err:
            st.error(f"Database Connection Error: {err}")
            return None

    def listen_to_voice(self):
        try:
            with sr.Microphone() as source:
                st.info("🎤 Adjusting for ambient noise...")
                self.recognizer.adjust_for_ambient_noise(source, duration=1)
                st.info("🎙 Listening... (Speak now)")
                audio = self.recognizer.listen(source, timeout=5)
                st.info("🔍 Processing speech...")
                text = self.recognizer.recognize_google(audio)
                return text
        except sr.WaitTimeoutError:
            return "Error: No speech detected"
        except sr.UnknownValueError:
            return "Error: Could not understand audio"
        except sr.RequestError:
            return "Error: Could not connect to speech recognition service"
        except Exception as e:
            return f"Error: {str(e)}"

    def preprocess_query(self, query_text):
        tokens = self.tokenizer.tokenize(query_text.lower())
        tokens = [self.lemmatizer.lemmatize(token) for token in tokens if token not in self.stop_words]
        return " ".join(tokens)

    def get_threat_info(self, cursor, user_id):
        try:
            cursor.execute("""
                SELECT 
                    Threat_id,
                    Threat_type,
                    Detected_time,
                    Status
                FROM THREAT_DETECTION
                WHERE User_id = %s
                ORDER BY Detected_time DESC
                LIMIT 5
            """, (user_id,))
            
            threats = cursor.fetchall()
            
            if not threats:
                return "\n🔒 No threat detections found.\n"
                
            response = "\n🔒 Recent Threat Detections:\n"
            for t in threats:
                response += f"""
                Threat ID: {t['Threat_id']}
                Type: {t['Threat_type']}
                Detected: {t['Detected_time']}
                Status: {t['Status']}
                {'─' * 40}
                """
            return response
        except mysql.connector.Error as err:
            return f"❌ Error retrieving threat information: {err}"
    def get_transaction_history(self, cursor, user_id):
        try:
            cursor.execute("""
                SELECT 
                    t.*,
                    a.Account_Type
                FROM TRANSACTION t
                JOIN ACCOUNT a ON t.Account_id = a.Account_id
                WHERE t.User_id = %s
                ORDER BY t.Timestamp DESC
                LIMIT 10
            """, (user_id,))
            
            transactions = cursor.fetchall()
            if not transactions:
                return "\n💰 No transactions found.\n"
                
            response = "\n💰 Recent Transactions:\n"
            for t in transactions:
                response += f"""
                            Transaction ID: {t['Transaction_id']}
                            Date: {t['Timestamp']}
                            Amount: ₹{t['Amount']:,.2f}
                            Type: {t['Transaction_type']}
                            Location: {t['Location']}
                            {'─' * 40}
                            """
            return response
        except mysql.connector.Error as err:
            return f"❌ Error retrieving transaction history: {err}"

    def get_account_information(self, cursor, user_id):
        try:
            cursor.execute("""
                SELECT *
                FROM ACCOUNT
                WHERE User_id = %s
            """, (user_id,))
            
            accounts = cursor.fetchall()
            if not accounts:
                return "\n💳 No accounts found.\n"
                
            response = "\n💳 Account Information:\n"
            for a in accounts:
                response += f"""
                            Account ID: {a['Account_id']}
                            Type: {a['Account_Type']}
                            Balance: ₹{a['Balance']:,.2f}
                            Status: {a['Account_status']}
                            Created: {a['Creation_date']}
                            Credit Score: {a['Credit_Score']}
                            {'─' * 40}
                            """
            return response
        except mysql.connector.Error as err:
            return f"❌ Error retrieving account information: {err}"

    def get_loan_information(self, cursor, user_id):
        try:
            cursor.execute("""
                SELECT *
                FROM LOAN
                WHERE User_id = %s
            """, (user_id,))
            
            loans = cursor.fetchall()
            if not loans:
                return "\n💸 No loans found.\n"
                
            response = "\n💸 Loan Information:\n"
            for l in loans:
                response += f"""
                                Loan ID: {l['Loan_id']}
                                Amount: ₹{l['Loan_amount']:,.2f}
                                Type: {l['Loan_type']}
                                Interest Rate: {l['Interest_rate']}%
                                Status: {l['Loan_status']}
                                Applied: {l['Date_applied']}
                                {'─' * 40}
                                """
            return response
        except mysql.connector.Error as err:
            return f"❌ Error retrieving loan information: {err}"

    def process_query(self, query_text, user_id):
        if not query_text:
            return "❌ No query detected"

        processed_query = self.preprocess_query(query_text)
        conn = self.connect_db()
        if not conn:
            return "❌ Database connection failed"

        cursor = conn.cursor(dictionary=True)
        try:
            response = []

            # Check query type and get relevant information
            if any(word in processed_query for word in ['threat', 'security', 'detection', 'alert']):
                result = self.get_threat_info(cursor, user_id)
                response.append(result)
                
            if any(word in processed_query for word in ['transaction', 'payment', 'spent', 'received']):
                result = self.get_transaction_history(cursor, user_id)
                response.append(result)
                
            if any(word in processed_query for word in ['account', 'balance', 'money']):
                result = self.get_account_information(cursor, user_id)
                response.append(result)
                
            if any(word in processed_query for word in ['loan', 'credit', 'borrow']):
                result = self.get_loan_information(cursor, user_id)
                response.append(result)

            # If no specific query type is detected, return all information
            if not response:
                response = [
                    self.get_account_information(cursor, user_id),
                    self.get_loan_information(cursor, user_id),
                    self.get_transaction_history(cursor, user_id),
                    self.get_threat_info(cursor, user_id)
                ]

            return "\n".join(filter(None, response))

        except mysql.connector.Error as err:
            return f"❌ Database error: {err}"
        finally:
            cursor.close()
            conn.close()
def train_insider_threat_model():
    """Train insider threat detection model using MySQL data"""
    conn = init_db_connection()
    if conn is None:
        st.error("Database connection failed")
        return None

    try:
        # Load log data directly from MySQL
        query = """
        SELECT 
            Log_id, 
            User_id, 
            IP_Address, 
            L_Timestamp, 
            Activity_Type, 
            Status, 
            Access_Level,
            HOUR(L_Timestamp) as Hour
        FROM LOG
        """
        
        data = pd.read_sql(query, conn)
        
        # One-hot encoding for categorical variables
        encoded_data = pd.get_dummies(
            data, 
            columns=['Activity_Type', 'Status', 'Access_Level'], 
            drop_first=True
        )
        
        # Create binary target variable 
        encoded_data['Anomaly_Status'] = (
            (encoded_data['Hour'] >= 22) | (encoded_data['Hour'] <= 5)
        ).astype(int)
        
        # Select features
        features = [col for col in encoded_data.columns if col not in 
                    ['Log_id', 'User_id', 'IP_Address', 'L_Timestamp', 'Hour']]
        
        X = encoded_data[features]
        y = encoded_data['Anomaly_Status']
        
        # Split dataset
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42
        )
        
        # Train Random Forest Classifier
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)
        
        # Save model
        joblib.dump(model, 'insider_threat_model.joblib')
        
        return model
    
    except Exception as e:
        st.error(f"Model training error: {e}")
        return None
    finally:
        if conn:
            conn.close()

def insider_threat_detection_page(banking_system):
    st.title("🚨 Insider Threat Detection")
    
    # Fetch user logs
    conn = init_db_connection()
    if conn is None:
        st.error("Database connection failed")
        return
    
    try:
        query = """
        SELECT 
            User_id, 
            IP_Address, 
            L_Timestamp, 
            Activity_Type, 
            Status, 
            Access_Level,
            HOUR(L_Timestamp) as Hour
        FROM LOG
        WHERE User_id = %s
        ORDER BY L_Timestamp DESC
        LIMIT 50
        """
        
        user_logs = pd.read_sql(query, conn, params=(st.session_state.user_id,))
        
        st.subheader("Insider Threat Analysis")
        
        # Initialize threat flag
        threat_detected = False
        threat_reasons = []
        
        # Check specific conditions for insider threat
        for _, log in user_logs.iterrows():
            # Rule for Terminated Status
            if log['Status'] == 'Terminated':
                if log['Activity_Type'] != 'Logout':
                    threat_detected = True
                    threat_reasons.append("Unauthorized activity after termination")
            
            # Rule for Suspended Status
            elif log['Status'] == 'Suspended':
                # If logs are in irregular pattern
                if len(user_logs[user_logs['Status'] != 'Suspended']) > 1:
                    threat_detected = True
                    threat_reasons.append("Irregular log activity during suspension")
            
            # Rule for Active Status
            elif log['Status'] == 'Active':
                # Check for odd working hours
                if 0 <= log['Hour'] <= 5:
                    threat_detected = True
                    threat_reasons.append("Activity during suspicious hours")
        
        # Display threat detection results
        if threat_detected:
            st.error("🚨 Potential Insider Threat Detected!")
            for reason in threat_reasons:
                st.warning(f"- {reason}")
            
            # Log the threat
            # log_high_risk_event(st.session_state.user_id, len(threat_reasons))
        else:
            st.success("✅ No Insider Threat Indicators Found")
        
        # Display log details for reference
        st.subheader("Recent Log Details")
        st.dataframe(user_logs)
    
    except Exception as e:
        st.error(f"Insider threat detection error: {e}")
    finally:
        if conn:
            conn.close()
def calculate_entropy(data):
    """Calculate entropy of categorical data"""
    from scipy.stats import entropy
    try:
        value_counts = data.value_counts(normalize=True)
        return entropy(value_counts)
    except Exception:
        return 0

def log_high_risk_event(user_id, risk_probability):
    """Log high-risk insider threat events to database"""
    conn = init_db_connection()
    if conn is not None:
        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO THREAT_DETECTION 
                (User_id, Threat_type, Risk_probability, Detected_time, Status) 
                VALUES (%s, 'INSIDER_THREAT', %s, NOW(), 'PENDING_INVESTIGATION')
            """, (user_id, risk_probability))
            conn.commit()
            
            # Optional: Send email/SMS notification to security team
            send_security_alert(user_id, risk_probability)
        
        except mysql.connector.Error as e:
            st.error(f"Error logging high-risk event: {e}")
        finally:
            conn.close()

def send_security_alert(user_id, risk_prob):
    """Placeholder for sending security alerts via email/SMS"""
    # Implement actual email or SMS notification logic here
    # This could integrate with services like SendGrid, Twilio, etc.
    pass

def log_analysis_display(user_logs):
    """Display detailed log insights"""
    col1, col2 = st.columns(2)
    
    with col1:
        st.metric("Unique IP Addresses", user_logs['IP_Address'].nunique())
        st.metric("Total Log Entries", len(user_logs))
    
    with col2:
        st.metric("Night Time Activities", f"{((user_logs['Hour'] >= 22) | (user_logs['Hour'] <= 5)).mean():.2%}")
        st.metric("Failed Access Attempts", f"{(user_logs['Status'] != 'SUCCESS').mean():.2%}")
    
    # Activity type distribution
    st.subheader("Activity Type Distribution")
    activity_counts = user_logs['Activity_Type'].value_counts()
    st.bar_chart(activity_counts)

def init_db_connection():
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        return connection
    except Error as e:
        st.error(f"Error connecting to MySQL: {e}")
        return None

def hash_password_md5(password):
    return hashlib.md5(password.encode('utf-8')).hexdigest()

def verify_password(input_password, stored_hash):
    input_hash = hash_password_md5(input_password)
    return input_hash == stored_hash

def login_user(username, password):
    conn = init_db_connection()
    if conn is not None:
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM user WHERE F_name = %s", (username,))
            user = cursor.fetchone()
            
            if user and verify_password(password, user['Password']):
                return True, user
            return False, None
        except Error as e:
            st.error(f"Database error during login: {e}")
            return False, None
        finally:
            cursor.close()
            conn.close()
    return False, None


def load_fraud_detection_model():
    try:
        model = joblib.load('fraud_detection.joblib')
        return model
    except Exception as e:
        st.error(f"Error loading fraud detection model: {e}")
        return None

def get_user_transaction_features(user_id):
    conn = init_db_connection()
    if conn is None:
        st.error("Database connection failed")
        return None

    try:
        cursor = conn.cursor(dictionary=True)
        
        # Fetch recent transactions
        cursor.execute("""
            SELECT 
                Transaction_id, 
                CAST(Amount AS DECIMAL(10,2)) AS Amount, 
                Transaction_type, 
                Location, 
                Timestamp
            FROM TRANSACTION 
            WHERE User_id = %s 
            ORDER BY Timestamp DESC 
            LIMIT 50
        """, (user_id,))
        
        transactions = cursor.fetchall()
        
        if not transactions:
            st.warning("No transaction history found.")
            return None
        
        # Convert to DataFrame
        df = pd.DataFrame(transactions)
        df['Amount'] = pd.to_numeric(df['Amount'], errors='coerce')
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])
        
        # Feature engineering matching model training
        df['hour'] = df['Timestamp'].dt.hour
        df['is_night'] = ((df['hour'] >= 22) | (df['hour'] <= 5)).astype(int)
        
        features = {
            'Amount': df['Amount'].mean(),
            'transaction_count': len(df),
            'hour': df['hour'].mean(),
            'is_night': df['is_night'].mean(),
            'Location': df['Location'].mode()[0],
            'Transaction_type': df['Transaction_type'].mode()[0]
        }
        
        return features
    
    except mysql.connector.Error as e:
        st.error(f"Database error: {e}")
        return None
    finally:
        if conn:
            conn.close()

def get_user_contact_details(user_id):
    """Retrieve user contact information"""
    conn = init_db_connection()
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT Phone_no 
                FROM USER 
                WHERE User_id = %s
            """, (user_id,))
            return cursor.fetchone()
        except Exception as e:
            st.error(f"Error fetching user details: {e}")
            return None
        finally:
            conn.close()

def fraud_detection_page(banking_system):
    st.title("🕵️ Automated Fraud Detection")
    
    # Fetch user contact details
    user_id = st.session_state.user_id
    user_details = get_user_contact_details(user_id)
    
    # Fetch transactions
    conn = init_db_connection()
    if conn is None:
        st.error("Database connection failed")
        return
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT 
                Transaction_id, 
                Amount, 
                Transaction_type, 
                Location, 
                Timestamp,
                User_id
            FROM TRANSACTION 
            WHERE User_id = %s 
            ORDER BY Timestamp DESC
        """, (user_id,))
        
        transactions = cursor.fetchall()
        
        if not transactions:
            st.warning("No transactions found for this user.")
            return
        
        # Fraud Detection and Alerting
        high_risk_transactions = []
        
        st.subheader("Transaction Fraud Risk Analysis")
        
        for transaction in transactions:
            is_high_risk = transaction['Amount'] >= 100000
            risk_color = "red" if is_high_risk else "green"
            risk_text = "High Fraud Risk" if is_high_risk else "Low Fraud Risk"
            
            # Collect high-risk transactions
            if is_high_risk:
                high_risk_transactions.append(transaction)
            
            st.markdown(f"""
            <div style="background-color:{risk_color}; color:white; padding:10px; margin:5px 0; border-radius:5px;">
            Transaction ID: {transaction['Transaction_id']}
            | Amount: ₹{transaction['Amount']:.2f}
            | Type: {transaction['Transaction_type']}
            | Location: {transaction['Location']}
            | Date: {transaction['Timestamp']}
            | Risk: {risk_text}
            </div>
            """, unsafe_allow_html=True)
        
        # Fraud Alert Section
        if high_risk_transactions:
            st.subheader("🚨 Fraud Alerts")
            
            for transaction in high_risk_transactions:
                # Prepare SMS and Call Alert
                mobile_number = user_details['Phone_no']
                alert_message = generate_fraud_alert_message(transaction)
                
                # Simulate Call Alert
                st.success(f"📞 Automated Call Initiated to {mobile_number}")
                
                # Display Draft SMS
                st.markdown("""
                **Draft SMS Alert:**
                ```
                {}
                ```
                """.format(alert_message))
                
        
    except Exception as e:
        st.error(f"Error in fraud detection: {e}")
    finally:
        if conn:
            conn.close()

def generate_fraud_alert_message(transaction):
    """Generate a detailed SMS alert for suspicious transaction"""
    return f"""🚨 FRAUD ALERT 🚨
Suspicious Transaction Detected:
- Amount: ₹{transaction['Amount']:.2f}
- Type: {transaction['Transaction_type']}
- Location: {transaction['Location']}
- Time: {transaction['Timestamp']}

If this was NOT you, contact customer support IMMEDIATELY.
"""



def get_user_contact_details(user_id):
    """Retrieve user contact information"""
    conn = init_db_connection()
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT Phone_no
                FROM USER 
                WHERE User_id = %s
            """, (user_id,))
            return cursor.fetchone()
        except Exception as e:
            st.error(f"Error fetching user details: {e}")
            return None
        finally:
            conn.close()
    
def dashboard():
    full_name = f"{st.session_state.F_name} {st.session_state.L_name}"
    
    st.title(f"Welcome, {full_name}! 👋")
    st.write(f"Your User ID: {st.session_state.user_id}")
    
    banking_system = BankingSystem()
    
    # Determine user type based on User_id prefix
    is_employee = st.session_state.user_id.startswith('EMP')
    is_customer = st.session_state.user_id.startswith('CUS')
    
    # Create tabs based on user type
    if is_employee:
        tab1, tab2 = st.tabs(["Queries", "Insider Threat"])
    elif is_customer:
        tab1, tab2 = st.tabs(["Queries", "Fraud Detection"])
    else:
        tab1 = st.tabs(["Queries"])[0]  # Only show queries tab for other user types
    
    with tab1:
        # Original query section
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            <div class="query-box">
                <h3>🎤 Voice Query</h3>
            </div>
            """, unsafe_allow_html=True)
            
            if st.button("Start Voice Query"):
                query_text = banking_system.listen_to_voice()
                if not query_text.startswith("Error"):
                    st.success(f"🎯 Recognized: {query_text}")
                    with st.spinner("Processing your query..."):
                        result = banking_system.process_query(query_text, st.session_state.user_id)
                        st.markdown(f"""
                        <div class="output-container">
                            {result}
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.error(query_text)
        
        with col2:
            st.markdown("""
            <div class="query-box">
                <h3>⌨️ Text Query</h3>
            </div>
            """, unsafe_allow_html=True)
            
            text_query = st.text_input(
                "Enter your query",
                placeholder="Example: Show my account balance"
            )
            
            if st.button("Submit Query"):
                if text_query:
                    with st.spinner("Processing your query..."):
                        result = banking_system.process_query(text_query, st.session_state.user_id)
                        st.markdown(f"""
                        <div class="output-container">
                            {result}
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.warning("⚠ Please enter a query")
    
    # Show additional tabs based on user type
    if 'tab2' in locals():  # Check if tab2 exists
        with tab2:
            if is_customer:
                # Fraud Detection Page for customers
                fraud_detection_page(banking_system)
            elif is_employee:
                # Insider Threat Detection Page for employees
                insider_threat_detection_page(banking_system)
    


def admin_dashboard():
    st.title("👨‍💼 Admin Dashboard")
    
    # Create tabs for different monitoring sections
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "💹 User Activity Monitor", 
        "💰 Transaction Monitor", 
        "🚨 Threat Detection", 
        "⚙️ System Analytics",
        "🔍 User Comprehensive Details"
    ])
    
    
    with tab1:
        st.subheader("👥 User Activity Monitoring")
        activities = get_all_user_activities()
        
        if not activities.empty:
            # Activity metrics
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Users", int(activities['User_id'].nunique()))
            with col2:
                st.metric("Active Sessions", 
                        int(len(activities[activities['Status'] == 'Active'])))
            with col3:
                st.metric("Failed Logins", 
                        int(len(activities[activities['Status'] == 'Terminated'])))
            
            # Employee selection dropdown
            employee_filter = st.selectbox(
                "Select Employee",
                ["All Employees"] + sorted(list(activities[activities['User_id'].str.startswith('EMP')]['Full_Name'].unique()))
            )
            
            # Filter data based on selection
            filtered_activities = activities[activities['Full_Name'] == employee_filter] if employee_filter != "All Employees" else activities
            
            # Activity timeline with filtered data
            timeline_df = filtered_activities.groupby('L_Timestamp').size().reset_index(name='count')
            
            if not timeline_df.empty:
                fig = go.Figure()
                
                fig.add_trace(go.Scatter(
                    x=timeline_df['L_Timestamp'],
                    y=timeline_df['count'],
                    mode='lines+markers',
                    name='Activity Count',
                    line=dict(color='blue', width=2),
                    marker=dict(size=6),
                    hovertemplate="<br>".join([
                        "Time: %{x}",
                        "Activities: %{y}",
                        "<extra></extra>"
                    ])
                ))
                
                fig.update_layout(
                    title=f"Activity Timeline - {employee_filter}",
                    xaxis_title="Timestamp",
                    yaxis_title="Number of Activities",
                    hovermode='x unified',
                    showlegend=False,
                    height=400
                )
                
                st.plotly_chart(fig, use_container_width=True)
            
            # Additional employee-specific metrics if an employee is selected
            if employee_filter != "All Employees":
                st.subheader(f"Detailed Metrics for {employee_filter}")
                
                if not filtered_activities.empty:
                    # Calculate metrics
                    login_attempts = filtered_activities[filtered_activities['Activity_Type'] == 'Login']
                    successful_logins = login_attempts[login_attempts['Status'] == 'Success']
                    
                    login_success_rate = (
                        (len(successful_logins) / len(login_attempts) * 100)
                        if len(login_attempts) > 0 
                        else 0.0
                    )
                    
                    total_activities = len(filtered_activities)
                    
                    col1, col3, col4 = st.columns(3)
                    
                    with col1:
                        st.metric(
                            "Total Activities", 
                            int(total_activities)
                        )
                    # with col2:
                    #     st.metric(
                    #         "Login Success Rate", 
                    #         f"{login_success_rate:.1f}%",
                    #         help="Percentage of successful login attempts"
                    #     )
                    with col3:
                        active_hours = filtered_activities['L_Timestamp'].dt.hour.nunique()
                        st.metric(
                            "Active Hours", 
                            f"{active_hours} hrs",
                            help="Number of unique hours during which activities were recorded"
                        )
                    with col4:
                        suspicious_count = len(filtered_activities[
                            filtered_activities['Status'].isin(['Suspended', 'Terminated'])
                        ])
                        st.metric(
                            "Suspicious Activities", 
                            int(suspicious_count),
                            help="Count of suspended or terminated activities"
                        )
                    
                    # Detailed breakdown of suspicious activities
                    suspicious_activities = filtered_activities[
                        filtered_activities['Status'].isin(['Suspended', 'Terminated'])
                    ].copy()
                    
                    if not suspicious_activities.empty:
                        st.subheader("🚨 Suspicious Activity Details")
                        
                        # Tabs for different types of suspicious activities
                        susp_tab1, susp_tab2 = st.tabs(["Suspended Activities", "Terminated Activities"])
                        
                        with susp_tab1:
                            suspended = suspicious_activities[suspicious_activities['Status'] == 'Suspended']
                            if not suspended.empty:
                                st.write(f"Found {len(suspended)} suspended activities")
                                
                                # Format the suspended activities for display
                                suspended_display = suspended.copy()
                                suspended_display['L_Timestamp'] = suspended_display['L_Timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
                                
                                st.dataframe(
                                    suspended_display[['L_Timestamp', 'Activity_Type', 'User_id', 'IP_Address', 'Status']],
                                    column_config={
                                        "L_Timestamp": "Timestamp",
                                        "Activity_Type": "Activity",
                                        "User_id": "User ID",
                                        "IP_Address": "IP Address",
                                        "Status": "Status"
                                    },
                                    hide_index=True
                                )
                            else:
                                st.info("No suspended activities found.")
                        
                        with susp_tab2:
                            terminated = suspicious_activities[suspicious_activities['Status'] == 'Terminated']
                            if not terminated.empty:
                                st.write(f"Found {len(terminated)} terminated activities")
                                
                                # Format the terminated activities for display
                                terminated_display = terminated.copy()
                                terminated_display['L_Timestamp'] = terminated_display['L_Timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
                                
                                st.dataframe(
                                    terminated_display[['L_Timestamp', 'Activity_Type', 'User_id', 'IP_Address', 'Status']],
                                    column_config={
                                        "L_Timestamp": "Timestamp",
                                        "Activity_Type": "Activity",
                                        "User_id": "User ID",
                                        "IP_Address": "IP Address",
                                        "Status": "Status"
                                    },
                                    hide_index=True
                                )
                            else:
                                st.info("No terminated activities found.")
                    
                    # Overall status breakdown
                    st.subheader("📊 Activity Status Breakdown")
                    status_counts = filtered_activities['Status'].value_counts()
                    status_df = pd.DataFrame({
                        'Status': status_counts.index,
                        'Count': status_counts.values,
                        'Percentage': (status_counts.values / total_activities * 100).round(1)
                    })
                    
                    st.dataframe(
                        status_df,
                        column_config={
                            "Status": "Status Type",
                            "Count": "Number of Activities",
                            "Percentage": st.column_config.NumberColumn(
                                "% of Total",
                                format="%.1f%%"
                            )
                        },
                        hide_index=True
                    )
                else:
                    st.warning("No activities found for selected employee.")
        else:
            st.warning("No activity data available.")
    with tab2: 
        st.subheader("💰 Transaction Monitoring")
        transactions = get_all_transactions()
        
        if not transactions.empty:
            fraudulent_count = transactions['is_fraudulent'].sum()
            
            # Transaction metrics
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Value", 
                         f"₹{transactions['Amount'].sum():,.2f}")
            with col2:
                st.metric("Avg Transaction", 
                         f"₹{transactions['Amount'].mean():,.2f}")
            with col3:
                st.metric("Transaction Count", 
                         len(transactions))
            with col4:
                st.metric("Flagged as Fraudulent", 
                         int(fraudulent_count),
                         delta=f"{(fraudulent_count/len(transactions))*100:.1f}%")
            
            # Create two subplots
            fig = make_subplots(
                rows=2, cols=1,
                subplot_titles=('Transaction Distribution', 'Transaction Timeline'),
                vertical_spacing=0.2,
                row_heights=[0.6, 0.4]
            )
            
            # Normal transactions
            normal_trans = transactions[~transactions['is_fraudulent']]
            fig.add_trace(
                go.Scatter(
                    x=normal_trans['Timestamp'],
                    y=normal_trans['Amount'],
                    mode='markers',
                    name='Normal Transactions',
                    marker=dict(
                        color='blue',
                        size=8
                    ),
                    hovertemplate="<br>".join([
                        "Amount: ₹%{y:,.2f}",
                        "Time: %{x}",
                        "Type: %{customdata[0]}",
                        "User: %{customdata[1]}",
                        "Location: %{customdata[2]}"
                    ]),
                    customdata=normal_trans[['Transaction_type', 'Full_Name', 'Location']]
                ),
                row=1, col=1
            )
            
            # Fraudulent transactions
            fraud_trans = transactions[transactions['is_fraudulent']]
            if not fraud_trans.empty:
                fig.add_trace(
                    go.Scatter(
                        x=fraud_trans['Timestamp'],
                        y=fraud_trans['Amount'],
                        mode='markers',
                        name='Suspicious Transactions (≥₹1,00,000)',
                        marker=dict(
                            color='red',
                            size=12,
                            symbol='star'
                        ),
                        hovertemplate="<br>".join([
                            "Amount: ₹%{y:,.2f}",
                            "Time: %{x}",
                            "Type: %{customdata[0]}",
                            "User: %{customdata[1]}",
                            "Location: %{customdata[2]}"
                        ]),
                        customdata=fraud_trans[['Transaction_type', 'Full_Name', 'Location']]
                    ),
                    row=1, col=1
                )
            
            # Add threshold line
            fig.add_hline(
                y=100000, 
                line_dash="dash", 
                line_color="red",
                annotation_text="Fraud Threshold (₹1,00,000)",
                annotation_position="right",
                row=1, col=1
            )
            
            # Transaction volume timeline
            timeline_data = transactions.set_index('Timestamp').resample('D')['Amount'].sum().reset_index()
            fig.add_trace(
                go.Scatter(
                    x=timeline_data['Timestamp'],
                    y=timeline_data['Amount'],
                    name='Daily Transaction Volume',
                    fill='tozeroy',
                    line=dict(color='lightblue')
                ),
                row=2, col=1
            )
            
            # Update layout
            fig.update_layout(
                height=800,
                showlegend=True,
                title_text="Transaction Monitoring Dashboard",
                hovermode='closest'
            )
            
            fig.update_xaxes(title_text="Timestamp", row=2, col=1)
            fig.update_yaxes(title_text="Amount (₹)", row=1, col=1)
            fig.update_yaxes(title_text="Daily Volume (₹)", row=2, col=1)
            
            # Display the plot
            st.plotly_chart(fig, use_container_width=True)
            
            # Create tabs for detailed transaction views
            trans_tab1, trans_tab2 = st.tabs(["All Transactions", "Flagged Transactions"])
            
            with trans_tab1:
                st.dataframe(style_dataframe(transactions))
            
            with trans_tab2:
                flagged_trans = transactions[transactions['is_fraudulent']]
                if not flagged_trans.empty:
                    st.dataframe(style_dataframe(flagged_trans))
                else:
                    st.info("No transactions flagged as suspicious")
            
            # Fraud analysis section
            if not fraud_trans.empty:
                st.subheader("🔍 Fraud Analysis")
                col1, col2 = st.columns(2)
                
                with col1:
                    # Location analysis
                    location_fraud = fraud_trans['Location'].value_counts()
                    fig_loc = px.pie(
                        values=location_fraud.values,
                        names=location_fraud.index,
                        title="High-Value Transactions by Location"
                    )
                    st.plotly_chart(fig_loc)
                
                with col2:
                    # Transaction type analysis
                    type_fraud = fraud_trans['Transaction_type'].value_counts()
                    fig_type = px.pie(
                        values=type_fraud.values,
                        names=type_fraud.index,
                        title="High-Value Transactions by Type"
                    )
                    st.plotly_chart(fig_type)
    
    with tab3:
        st.subheader("🚨 Threat Detection Monitor")
        
        # Fetch and display threat data
        conn = init_db_connection()
        if conn is not None:
            try:
                threat_query = """
                SELECT 
                    td.*,
                    CONCAT(u.F_name, ' ', COALESCE(u.L_name, '')) as Full_Name
                FROM THREAT_DETECTION td
                JOIN user u ON td.User_id = u.User_id
                ORDER BY td.Detected_time DESC
                """
                threats = pd.read_sql(threat_query, conn)
                
                if not threats.empty:
                    # Threat metrics
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("Active Threats", 
                                 len(threats[threats['Status'] == 'PENDING_INVESTIGATION']))
                    with col2:
                        st.metric("Total Threats", len(threats))
                    
                    # Threat visualization
                    fig = px.pie(
                        threats,
                        names='Threat_type',
                        title='Threat Distribution by Type'
                    )
                    st.plotly_chart(fig)
                    
                    # Detailed threat log
                    st.dataframe(threats)
                else:
                    st.info("No threats detected")
            
            except Exception as e:
                st.error(f"Error fetching threat data: {e}")
            finally:
                conn.close()
    
    with tab4:
        st.subheader("📊 System Analytics")
        
        # System health metrics
        col1, col2 = st.columns(2)
        with col1:
            # Database connection status
            conn = init_db_connection()
            status = "🟢 Connected" if conn is not None else "🔴 Disconnected"
            st.metric("Database Status", status)
            if conn:
                conn.close()
        
        with col2:
            # Model status
            model = load_fraud_detection_model()
            model_status = "🟢 Loaded" if model is not None else "🔴 Not Loaded"
            st.metric("Fraud Detection Model", model_status)
        with tab5:
            st.subheader("🔍 Comprehensive User Details")
            
            conn = init_db_connection()
            if conn is not None:
                try:
                    # Modified query with proper aggregation
                    user_query = """
                    SELECT 
                        u.User_id,
                        CONCAT(u.F_name, ' ', COALESCE(u.L_name, '')) as Full_Name,
                        u.Email,
                        u.Phone_no,
                        MAX(a.Account_Type) as Account_Type,
                        MAX(a.Account_status) as Account_status,
                        COUNT(DISTINCT t.Transaction_id) as Total_Transactions,
                        COALESCE(SUM(t.Amount), 0) as Total_Transaction_Value,
                        COUNT(DISTINCT td.Threat_id) as Total_Threats,
                        COUNT(DISTINCT l.Loan_id) as Total_Loans,
                        COALESCE(SUM(l.Loan_amount), 0) as Total_Loan_Amount
                    FROM 
                        USER u
                    LEFT JOIN ACCOUNT a ON u.User_id = a.User_id
                    LEFT JOIN TRANSACTION t ON u.User_id = t.User_id
                    LEFT JOIN THREAT_DETECTION td ON u.User_id = td.User_id
                    LEFT JOIN LOAN l ON u.User_id = l.User_id
                    GROUP BY 
                        u.User_id, u.F_name, u.L_name, u.Email, u.Phone_no
                    """
                    users_df = pd.read_sql(user_query, conn)
                    
                    # User selection dropdown
                    selected_user = st.selectbox(
                        "Select User to View Details",
                        ["All Users"] + list(users_df['Full_Name'])
                    )
                    
                    # Filter dataframe if a specific user is selected
                    if selected_user != "All Users":
                        users_df = users_df[users_df['Full_Name'] == selected_user]
                    
                    # Display user summary
                    st.subheader("👥 User Summary")
                    st.dataframe(
                        users_df,
                        column_config={
                            "User_id": "User ID",
                            "Full_Name": "Name",
                            "Phone_no": "Phone Number",
                            "Total_Transactions": "Transaction Count",
                            "Total_Transaction_Value": st.column_config.NumberColumn(
                                "Total Transaction Value (₹)",
                                format="₹%.2f"
                            ),
                            "Total_Threats": "Threat Incidents",
                            "Total_Loans": "Loan Count",
                            "Total_Loan_Amount": st.column_config.NumberColumn(
                                "Total Loan Amount (₹)",
                                format="₹%.2f"
                            )
                        },
                        hide_index=True
                    )
                    
                    # Detailed tabs for selected user
                    if selected_user != "All Users":
                        user_details_tabs = st.tabs([
                            "📊 Transactions", 
                            "🚨 Threats", 
                            "💸 Loans", 
                            "👤 Personal Info"
                        ])
                        
                        selected_user_id = users_df['User_id'].iloc[0]
                        
                        with user_details_tabs[0]:  # Transactions
                            st.subheader("User Transactions")
                            trans_query = f"""
                            SELECT 
                                t.Timestamp, 
                                t.Transaction_type, 
                                t.Amount, 
                                t.Location,
                                a.Account_id
                            FROM 
                                TRANSACTION t
                            LEFT JOIN ACCOUNT a ON t.Account_id = a.Account_id
                            WHERE 
                                t.User_id = '{selected_user_id}'
                            ORDER BY 
                                t.Timestamp DESC
                            """
                            user_transactions = pd.read_sql(trans_query, conn)
                            
                            if not user_transactions.empty:
                                st.dataframe(
                                    user_transactions,
                                    column_config={
                                        "Timestamp": "Date & Time",
                                        "Transaction_type": "Type",
                                        "Amount": st.column_config.NumberColumn(
                                            "Amount (₹)",
                                            format="₹%.2f"
                                        ),
                                        "Account_id": "Account ID"
                                    },
                                    hide_index=True
                                )
                                
                                col1, col2 = st.columns(2)
                                with col1:
                                    st.metric("Total Transactions", len(user_transactions))
                                with col2:
                                    st.metric("Total Transaction Value", 
                                            f"₹{user_transactions['Amount'].sum():,.2f}")
                            else:
                                st.info("No transactions found for this user.")
                        
                        with user_details_tabs[1]:  # Threats
                            st.subheader("User Threat Incidents")
                            threat_query = f"""
                            SELECT 
                                Detected_time, 
                                Threat_type, 
                                Status,
                                Time
                            FROM 
                                THREAT_DETECTION 
                            WHERE 
                                User_id = '{selected_user_id}'
                            ORDER BY 
                                Detected_time DESC
                            """
                            user_threats = pd.read_sql(threat_query, conn)
                            
                            if not user_threats.empty:
                                st.dataframe(
                                    user_threats,
                                    column_config={
                                        "Detected_time": "Detection Time",
                                        "Threat_type": "Type",
                                        "Time": "Time of Incident"
                                    },
                                    hide_index=True
                                )
                                
                                col1, col2 = st.columns(2)
                                with col1:
                                    st.metric("Total Threats", len(user_threats))
                                with col2:
                                    active_threats = len(user_threats[user_threats['Status'] == 'PENDING'])
                                    st.metric("Active Threats", active_threats)
                            else:
                                st.info("No threat incidents found for this user.")
                        
                        with user_details_tabs[2]:  # Loans
                            st.subheader("User Loan History")
                            loan_query = f"""
                            SELECT 
                                Loan_id,
                                Loan_amount,
                                Interest_rate,
                                Loan_type,
                                Date_applied,
                                Approval_date,
                                Loan_status,
                                Tenure,
                                Annual_Income
                            FROM 
                                LOAN 
                            WHERE 
                                User_id = '{selected_user_id}'
                            ORDER BY 
                                Date_applied DESC
                            """
                            user_loans = pd.read_sql(loan_query, conn)
                            
                            if not user_loans.empty:
                                st.dataframe(
                                    user_loans,
                                    column_config={
                                        "Loan_id": "Loan ID",
                                        "Loan_amount": st.column_config.NumberColumn(
                                            "Loan Amount (₹)",
                                            format="₹%.2f"
                                        ),
                                        "Interest_rate": st.column_config.NumberColumn(
                                            "Interest Rate",
                                            format="%.2f%%"
                                        ),
                                        "Annual_Income": st.column_config.NumberColumn(
                                            "Annual Income (₹)",
                                            format="₹%.2f"
                                        ),
                                        "Tenure": "Tenure (Months)"
                                    },
                                    hide_index=True
                                )
                                
                                col1, col2, col3 = st.columns(3)
                                with col1:
                                    st.metric("Total Loans", len(user_loans))
                                with col2:
                                    st.metric("Total Loan Amount", 
                                            f"₹{user_loans['Loan_amount'].sum():,.2f}")
                                with col3:
                                    active_loans = len(user_loans[user_loans['Loan_status'] == 'ACTIVE'])
                                    st.metric("Active Loans", active_loans)
                            else:
                                st.info("No loan history found for this user.")
                        
                        with user_details_tabs[3]:  # Personal Info
                            st.subheader("Detailed Personal Information")
                            personal_query = f"""
                            SELECT 
                                u.F_name, 
                                u.L_name, 
                                u.Email, 
                                u.Phone_no, 
                                u.DOB, 
                                CONCAT(u.Street, ', ', u.City, ', ', u.State, ' - ', u.Pincode) as Address,
                                u.Role,
                                GROUP_CONCAT(DISTINCT a.Account_Type) as Account_Types,
                                GROUP_CONCAT(DISTINCT a.Account_status) as Account_Statuses,
                                GROUP_CONCAT(DISTINCT a.Account_id) as Account_IDs,
                                MAX(a.Credit_Score) as Credit_Score
                            FROM 
                                USER u
                            LEFT JOIN ACCOUNT a ON u.User_id = a.User_id
                            WHERE 
                                u.User_id = '{selected_user_id}'
                            GROUP BY
                                u.User_id, u.F_name, u.L_name, u.Email, u.Phone_no, u.DOB, u.Street, u.City, u.State, u.Pincode, u.Role
                            """
                            personal_info = pd.read_sql(personal_query, conn)
                            
                            if not personal_info.empty:
                                col1, col2 = st.columns(2)
                                with col1:
                                    st.subheader("Personal Details")
                                    st.text(f"Name: {personal_info['F_name'].iloc[0]} {personal_info['L_name'].iloc[0]}")
                                    st.text(f"Email: {personal_info['Email'].iloc[0]}")
                                    st.text(f"Phone: {personal_info['Phone_no'].iloc[0]}")
                                    st.text(f"DOB: {personal_info['DOB'].iloc[0]}")
                                    st.text(f"Role: {personal_info['Role'].iloc[0]}")
                                    st.text(f"Address: {personal_info['Address'].iloc[0]}")
                                
                                with col2:
                                    st.subheader("Account Details")
                                    st.text(f"Account IDs: {personal_info['Account_IDs'].iloc[0]}")
                                    st.text(f"Account Types: {personal_info['Account_Types'].iloc[0]}")
                                    st.text(f"Account Statuses: {personal_info['Account_Statuses'].iloc[0]}")
                                    st.text(f"Credit Score: {personal_info['Credit_Score'].iloc[0]}")
                            else:
                                st.warning("Could not retrieve personal information.")
                
                except Exception as e:
                    st.error(f"Error fetching user details: {e}")
                
                finally:
                    if conn:
                        conn.close()
            else:
                st.error("Unable to establish database connection")

# Keep the rest of the existing code (main function, login, etc.) the same
def get_next_customer_id():
    """Get the next available customer ID"""
    conn = init_db_connection()
    if conn is not None:
        try:
            cursor = conn.cursor()
            # Get the highest customer ID
            cursor.execute("""
                SELECT User_id 
                FROM user 
                WHERE User_id LIKE 'CUS_%' 
                ORDER BY User_id DESC 
                LIMIT 1
            """)
            result = cursor.fetchone()
            
            if result:
                # Extract the number from existing highest ID
                last_num = int(result[0].split('_')[1])
                next_num = last_num + 1
            else:
                # If no existing customer, start from 1
                next_num = 1
                
            # Format new ID with leading zeros
            new_id = f"CUS_{next_num:06d}"
            return new_id
            
        except Error as e:
            st.error(f"Error getting next customer ID: {e}")
            return None
        finally:
            cursor.close()
            conn.close()
    return None
def validate_password(password):
    """
    Validate password requirements:
    1. Minimum 6 characters
    2. At least one digit
    3. At least one uppercase letter
    4. At least one lowercase letter
    """
    if len(password) < 6:
        return False, "Password must be at least 6 characters long"
    
    if not any(char.isdigit() for char in password):
        return False, "Password must contain at least one digit"
    
    if not any(char.isupper() for char in password):
        return False, "Password must contain at least one uppercase letter"
    
    if not any(char.islower() for char in password):
        return False, "Password must contain at least one lowercase letter"
    
    return True, "Password is valid"

def register_user(username, password):
    """
    Register new user with auto-generated customer ID
    Returns: (bool, str) - (success status, message)
    """
    # Validate password first
    password_valid, password_message = validate_password(password)
    if not password_valid:
        return False, password_message

    conn = init_db_connection()
    if conn is not None:
        try:
            cursor = conn.cursor(dictionary=True)
            
            # Check if username already exists
            cursor.execute("SELECT F_name FROM user WHERE F_name = %s", (username,))
            if cursor.fetchone():
                return False, "Username already exists!"

            # Get next customer ID
            next_id = get_next_customer_id()
            if not next_id:
                return False, "Error generating customer ID!"

            # Hash the password
            hashed_password = hash_password_md5(password)
            if not hashed_password:
                return False, "Error in password hashing!"

            # Insert new user with customer ID
            cursor.execute("""
                INSERT INTO user (User_id, F_name, Password) 
                VALUES (%s, %s, %s)
            """, (next_id, username, hashed_password))
            conn.commit()

            # Verify the insertion
            cursor.execute(
                "SELECT * FROM user WHERE User_id = %s AND F_name = %s", 
                (next_id, username)
            )
            if cursor.fetchone():
                return True, f"Registration successful! Your Customer ID is {next_id}"
            else:
                return False, "Registration failed - verification error!"

        except mysql.connector.Error as e:
            error_msg = str(e)
            if e.errno == 1062:  # Duplicate entry error
                error_msg = "Username already exists!"
            return False, f"Registration error: {error_msg}"
        finally:
            cursor.close()
            conn.close()
    return False, "Database connection failed!"


class VoiceAuthenticator:
    def __init__(self, sample_rate=16000, duration=5):
        """
        Initialize VoiceAuthenticator with configurable parameters
        
        Args:
            sample_rate (int): Audio sample rate
            duration (int): Recording duration in seconds
        """
        try:
            self.recognizer = sr.Recognizer()
            self.sample_rate = sample_rate
            self.duration = duration
            
            # More stringent verification parameters
            self.verification_threshold = 0.90  # Increased threshold
            self.min_correlation = 0.85  # Minimum correlation coefficient
            self.feature_dimensions = 40  # Number of MFCC features
        except Exception as e:
            st.error(f"Voice Authenticator initialization error: {e}")
            raise
    def record_voice(self, message="Please speak for voice authentication"):
        """
        Record voice sample with comprehensive error handling and user guidance
        
        Args:
            message (str): Instruction message for the user
        
        Returns:
            audio data or None if recording fails
        """
        try:
            # Check if SpeechRecognition Microphone is available
            if not hasattr(sr, 'Microphone'):
                st.error("SpeechRecognition Microphone not available")
                return None

            # Ensure microphone is available
            try:
                with sr.Microphone(sample_rate=self.sample_rate) as source:
                    # Adjust for ambient noise
                    st.info("🔊 Adjusting microphone for ambient noise... Please stay quiet.")
                    self.recognizer.adjust_for_ambient_noise(source, duration=1)
                    
                    # Prepare user for recording
                    st.warning("🎙 Voice Recording Instructions:")
                    st.info("1. Find a quiet environment")
                    st.info("2. Speak clearly and consistently")
                    st.info(f"3. Recording will last {self.duration} seconds")
                    
                    # Countdown before recording
                    for countdown in range(3, 0, -1):
                        st.info(f"Recording starts in {countdown} seconds...")
                        time.sleep(1)
                    
                    # Main recording
                    st.success("🔴 RECORDING NOW - Speak clearly!")
                    
                    # Listen with timeout and duration limits
                    audio = self.recognizer.listen(
                        source,
                        timeout=10,  # Wait up to 10 seconds for speech to start
                        phrase_time_limit=self.duration  # Record for specified duration
                    )
                    
                    # Additional checks on recorded audio
                    if not audio:
                        st.error("No audio captured. Please try again.")
                        return None
                    
                    # Optional: Basic audio quality check
                    try:
                        audio_array = np.frombuffer(audio.get_wav_data(), dtype=np.int16)
                        if len(audio_array) == 0:
                            st.error("Recorded audio is empty. Please try again.")
                            return None
                        
                        # Check audio energy/volume
                        energy = np.abs(audio_array).mean()
                        if energy < 100:  # Adjust threshold as needed
                            st.warning("Audio seems very quiet. Please speak louder.")
                            return None
                    
                    except Exception as audio_check_error:
                        st.error(f"Audio quality check failed: {audio_check_error}")
                        return None
                    
                    st.success("✅ Voice recording successful!")
                    return audio
            
            except sr.WaitTimeoutError:
                st.error("No speech detected. Recording timed out.")
                return None
            
            except RuntimeError as mic_error:
                st.error(f"Microphone error: {mic_error}")
                st.info("Possible reasons:")
                st.info("- No microphone connected")
                st.info("- Microphone is being used by another application")
                st.info("- Microphone permissions not granted")
                return None
        
        except Exception as general_error:
            st.error(f"Unexpected error during voice recording: {general_error}")
            return None

    def extract_features(self, audio_data):
        """Enhanced feature extraction with consistent feature vector length"""
        try:
            # Validate audio data
            if audio_data is None:
                st.error("No audio data provided!")
                return None

            # Convert audio to numpy array
            audio_array = np.frombuffer(audio_data.get_wav_data(), dtype=np.int16)
            
            # Further validate audio array
            if len(audio_array) == 0:
                st.error("Empty audio data detected!")
                return None
            
            # Normalize audio
            audio_array = audio_array / np.max(np.abs(audio_array))
            
            # Extract MFCC features with consistent parameters
            mfccs = librosa.feature.mfcc(
                y=audio_array.astype(float), 
                sr=self.sample_rate,
                n_mfcc=20,  # Reduced to ensure consistent length
                n_fft=2048,
                hop_length=512
            )
            
            # Compute statistical features with fixed length
            features = []
            
            # Mean of MFCCs
            features.extend(np.mean(mfccs.T, axis=0))
            
            # Standard deviation of MFCCs
            features.extend(np.std(mfccs.T, axis=0))
            
            # Ensure fixed length vector
            fixed_length_features = features[:40]  # Trim or pad to exact 40 features
            
            return np.array(fixed_length_features)
            
        except Exception as e:
            st.error(f"Feature extraction error: {e}")
            return None

    def compare_voices(self, stored_features, current_features):
        """Compare voice features with robust error handling"""
        try:
            # Validate input features
            if stored_features is None or current_features is None:
                st.error("Invalid voice features for comparison")
                return False, 0.0

            # Ensure consistent length by truncating to the shorter length
            min_length = min(len(stored_features), len(current_features))
            stored_features = stored_features[:min_length]
            current_features = current_features[:min_length]

            # Compute similarity metrics
            cosine_similarity = 1 - cosine(stored_features, current_features)
            
            # Enhanced authentication checks
            authentication_result = (
                cosine_similarity > self.verification_threshold and
                np.corrcoef(stored_features, current_features)[0, 1] > 0.8
            )
            
            st.info(f"""Voice Authentication:
            - Similarity: {cosine_similarity:.2f}
            - Authenticated: {authentication_result}
            """)
            
            return authentication_result, cosine_similarity
        
        except Exception as e:
            st.error(f"Voice comparison error: {e}")
            return False, 0.0

class VoiceBankingSystem:
    def __init__(self, banking_system=None):
        """
        Initialize VoiceBankingSystem
        
        Args:
            banking_system: Parent banking system for database connection
        """
        self.banking_system = banking_system
        # Always create VoiceAuthenticator
        self.voice_auth = VoiceAuthenticator()
        
        # Setup voice features table
        self.setup_voice_table()
    
    def connect_db(self):
        """
        Database connection method
        If banking_system is provided, use its connection method
        """
        if self.banking_system and hasattr(self.banking_system, 'connect_db'):
            return self.banking_system.connect_db()
        
        # Fallback database connection (replace with your actual connection method)
        try:
            conn = mysql.connector.connect(
                host='localhost',
                user='root',
                password='code',
                database='dbms'
            )
            return conn
        except Exception as e:
            st.error(f"Database connection error: {e}")
            return None
    
    def setup_voice_table(self):
        """Create voice features table with error handling"""
        conn = self.connect_db()
        if not conn:
            st.error("Failed to connect to database")
            return
        
        cursor = conn.cursor()
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS VOICE_FEATURES (
                    User_id VARCHAR(10) PRIMARY KEY,
                    Voice_features BLOB,
                    Verification_count INT DEFAULT 0,
                    Last_failed_attempt DATETIME,
                    Lockout_time DATETIME
                )
            """)
            conn.commit()
        except Exception as e:
            st.error(f"Voice features table creation error: {e}")
        finally:
            cursor.close()
            conn.close()
    
    def register_voice(self, user_id):
        """Voice registration method with comprehensive error handling"""
        try:
            st.info("🎙 Voice Registration Process")
            
            # Ensure voice authenticator exists
            if not hasattr(self, 'voice_auth'):
                self.voice_auth = VoiceAuthenticator()
            
            # Record audio
            audio = self.voice_auth.record_voice(
                "Please speak your name and a unique phrase for 5 seconds"
            )
            
            if not audio:
                st.error("Voice recording failed")
                return False
            
            # Extract features
            features = self.voice_auth.extract_features(audio)
            if features is None:
                st.error("Feature extraction failed")
                return False
            
            # Store features
            conn = self.connect_db()
            if not conn:
                st.error("Database connection failed")
                return False
            
            cursor = conn.cursor()
            try:
                # Serialize features
                features_bytes = pickle.dumps(features)
                
                # Use INSERT ... ON DUPLICATE KEY UPDATE for MySQL
                cursor.execute("""
                    INSERT INTO VOICE_FEATURES 
                    (User_id, Voice_features, Verification_count) 
                    VALUES (%s, %s, 0)
                    ON DUPLICATE KEY UPDATE 
                    Voice_features = %s, 
                    Verification_count = Verification_count + 1
                """, (user_id, features_bytes, features_bytes))
                
                conn.commit()
                st.success("✅ Voice registration successful!")
                return True
            
            except Exception as e:
                st.error(f"Voice registration error: {e}")
                return False
            
            finally:
                cursor.close()
                conn.close()
        
        except Exception as e:
            st.error(f"Unexpected error in voice registration: {e}")
            return False
    
    def verify_voice(self, user_id):
        """Voice verification method with enhanced security"""
        try:
            # Ensure voice authenticator exists
            if not hasattr(self, 'voice_auth'):
                self.voice_auth = VoiceAuthenticator()
            
            # Connect to database
            conn = self.connect_db()
            if not conn:
                st.error("Database connection failed")
                return False
            
            cursor = conn.cursor(dictionary=True)
            try:
                # Retrieve stored voice features
                cursor.execute(
                    "SELECT Voice_features FROM VOICE_FEATURES WHERE User_id = %s", 
                    (user_id,)
                )
                result = cursor.fetchone()
                
                if not result:
                    st.warning("No voice registration found")
                    return False
                
                # Deserialize stored features
                stored_features = pickle.loads(result['Voice_features'])
                
                # Record verification audio
                audio = self.voice_auth.record_voice("Speak for verification")
                if not audio:
                    st.error("Verification audio recording failed")
                    return False
                
                # Extract current features
                current_features = self.voice_auth.extract_features(audio)
                if current_features is None:
                    st.error("Feature extraction failed")
                    return False
                
                # Compare voices
                is_match, similarity = self.voice_auth.compare_voices(
                    stored_features, 
                    current_features
                )
                
                if is_match:
                    st.success(f"✅ Voice verified! (Similarity: {similarity:.2f})")
                    return True
                else:
                    st.error(f"❌ Voice verification failed (Similarity: {similarity:.2f})")
                    return False
            
            except Exception as e:
                st.error(f"Voice verification error: {e}")
                return False
            
            finally:
                cursor.close()
                conn.close()
        
        except Exception as e:
            st.error(f"Unexpected error in voice verification: {e}")
            return False
def main():
    # Set page configuration
    st.set_page_config(
        page_title="FinShield Voice Banking System",
        page_icon="🏦",
        layout="centered",
        initial_sidebar_state="collapsed",
    )

    # Apply CSS styling
    st.markdown("""
    <style>
        .main-header {
            color: white !important;
            text-align: center;
            text-shadow: 0 0 10px rgba(255,255,255,0.5);
        }
        @keyframes gradientBG {
            0% {background-position: 0% 50%;}
            50% {background-position: 100% 50%;}
            100% {background-position: 0% 50%;}
        }
        .stApp {
            background: linear-gradient(-45deg, #1e3c72, #2a5298, #23a6d5, #23d5ab);
            background-size: 400% 400%;
            animation: gradientBG 15s ease infinite;
            color: white;
        }
        .stButton > button {
            background: linear-gradient(45deg, #2937f0, #9f1ae2) !important;
            color: white !important;
            border-radius: 25px;
            padding: 12px 25px;
            font-weight: bold;
            text-transform: uppercase;
            animation: pulse 2s infinite;
        }
        .stTextInput > div > div > input {
            background: rgba(255, 255, 255, 0.2) !important;
            border: 1px solid rgba(255, 255, 255, 0.3) !important;
            color: white !important;
            border-radius: 25px;
        }
    </style>
    """, unsafe_allow_html=True)

    # Initialize session state variables if they don't exist
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'is_admin' not in st.session_state:
        st.session_state.is_admin = False
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'username' not in st.session_state:
        st.session_state.username = None
    if 'user_id' not in st.session_state:
        st.session_state.user_id = None
    if 'F_name' not in st.session_state:
        st.session_state.F_name = None
    if 'L_name' not in st.session_state:
        st.session_state.L_name = None
    if 'user_type' not in st.session_state:
        st.session_state.user_type = None

    # Initialize banking system
    banking_system = VoiceBankingSystem()

    # Main application flow
    if not st.session_state.logged_in:
        # Display initial login/register interface
        st.markdown('<h1 class="main-header">FinShield Voice Banking 🏦</h1>', unsafe_allow_html=True)
        tab1, tab2, tab3 = st.tabs(["🔑 Login", "✨ Register", "👨‍💼 Admin Login"])

        # Regular Login tab
        with tab1:
            with st.form("login_form"):
                st.subheader("Sign In")
                username = st.text_input("Username", placeholder="Enter your username", key="login_username")
                password = st.text_input("Password", type="password", placeholder="Enter your password", key="login_password")
                submit_button = st.form_submit_button("Sign In")

                if submit_button and username and password:
                    success, user = login_user(username, password)
                    if success:
                        st.session_state.logged_in = True
                        st.session_state.username = user["F_name"]
                        st.session_state.F_name = user["F_name"]
                        st.session_state.L_name = user["L_name"]
                        st.session_state.user_id = user["User_id"]
                        st.success("Login successful! Proceeding to voice verification... 🎉")
                        st.session_state.user_type = "Customer"
                        st.rerun()
                    else:
                        st.error("Invalid username or password ❌")

        # Registration tab
        with tab2:
            with st.form("register_form"):
                st.subheader("Create Account")
                new_username = st.text_input("Choose Username", placeholder="Enter desired username", key="reg_username")
                new_password = st.text_input("Choose Password", type="password", key="reg_password")
                confirm_password = st.text_input("Confirm Password", type="password", key="reg_confirm")
                register_button = st.form_submit_button("Create Account")

                if register_button:
                    if all([new_username, new_password, confirm_password]):
                        if new_password == confirm_password:
                            if len(new_password) >= 6:
                                success, message = register_user(new_username, new_password)
                                if success:
                                    st.success(f"{message} 🎉 Please proceed to login and voice registration.")
                                else:
                                    st.error(f"{message} ❌")
                            else:
                                st.warning("Password must be at least 6 characters long ⚠")
                        else:
                            st.error("Passwords do not match! ❌")
                    else:
                        st.warning("Please fill in all fields ⚠")

        # Admin Login tab
        with tab3:
            with st.form("admin_login_form"):
                st.subheader("Admin Login")
                admin_username = st.text_input("Admin Username", key="admin_username")
                admin_password = st.text_input("Admin Password", type="password", key="admin_password")
                admin_login_button = st.form_submit_button("Admin Login")

                if admin_login_button and admin_username and admin_password:
                    if verify_admin_login(admin_username, admin_password):
                        st.session_state.logged_in = True
                        st.session_state.is_admin = True
                        st.session_state.user_type = "Employee"
                        st.session_state.authenticated = True
                        st.success("Admin login successful! 🎉")
                        st.rerun()
                    else:
                        st.error("Invalid admin credentials ❌")

    else:
        # Handle voice authentication for customers
        if st.session_state.user_type == "Customer" and not st.session_state.authenticated:
            st.markdown("""
            <div class="user-selection">
                <h2 style="text-align: center; color: white;">Voice Authentication Required</h2>
            </div>
            """, unsafe_allow_html=True)

            col1, col2 = st.columns(2)
            with col1:
                if st.button("🎙 Register Voice", key="register_voice_btn"):
                    if banking_system.register_voice(st.session_state.user_id):
                        st.session_state.authenticated = True
                        st.rerun()
            
            with col2:
                if st.button("🔐 Verify Voice", key="verify_voice_btn"):
                    if banking_system.verify_voice(st.session_state.user_id):
                        st.session_state.authenticated = True
                        st.rerun()

        # Main authenticated user interface
        elif st.session_state.authenticated or st.session_state.is_admin:
            welcome_message = ""
            if st.session_state.is_admin:
                welcome_message = "Welcome, Admin"
            else:
                portal_type = ""
                if st.session_state.user_id.startswith('CUS'):
                    portal_type = "Customer Portal"
                elif st.session_state.user_id.startswith('EMP'):
                    portal_type = "Employee Portal"
                else:
                    portal_type = "User Portal"
                    
                welcome_message = f"Welcome to {portal_type}"
            
            st.markdown(f"""
            <div class="user-selection">
                <h2 style="text-align: center; color: white;">
                    {welcome_message}
                </h2>
            </div>
            """, unsafe_allow_html=True)

            # Display appropriate dashboard
            if st.session_state.is_admin:
                admin_dashboard()
            else:
                dashboard()

            # Logout button
            if st.button("🚪 Logout", key="logout_btn"):
                # Only reset non-widget session state variables
                st.session_state.logged_in = False
                st.session_state.is_admin = False
                st.session_state.authenticated = False
                st.session_state.username = None
                st.session_state.user_id = None
                st.session_state.F_name = None
                st.session_state.L_name = None
                st.session_state.user_type = None
                st.rerun()

if __name__ == "__main__":
    main()
