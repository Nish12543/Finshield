-- Create a new schema named 'dbms'
CREATE SCHEMA dbms;

USE dbms;

-- USER Table
CREATE TABLE USER (
    User_id VARCHAR(15) PRIMARY KEY,
    F_name VARCHAR(50),
    L_name VARCHAR(50),
    DOB DATE,
    Street VARCHAR(100),
    City VARCHAR(50),
    State VARCHAR(50),
    Pincode VARCHAR(10),
    Phone_no VARCHAR(15),
    Email VARCHAR(100),
    Role VARCHAR(20),
    Password VARCHAR(100)
);

-- ACCOUNT Table
CREATE TABLE ACCOUNT (
    Account_id INT PRIMARY KEY AUTO_INCREMENT,
    Balance DECIMAL(15, 2),
    Creation_date DATE,
    Account_status VARCHAR(20),
    Account_Type VARCHAR(20),
    Credit_Score INT,
    User_id VARCHAR(15),
    FOREIGN KEY (User_id) REFERENCES USER(User_id)
);

-- THREAT_DETECTION Table
CREATE TABLE THREAT_DETECTION (
    Threat_id INT PRIMARY KEY AUTO_INCREMENT,
    Threat_type VARCHAR(50),
    Detected_time TIMESTAMP,
    Status VARCHAR(20),
    Time TIME,
    User_id VARCHAR(15),
    FOREIGN KEY (User_id) REFERENCES USER(User_id)
);

-- LOAN Table
CREATE TABLE LOAN (
    Loan_id INT PRIMARY KEY AUTO_INCREMENT,
    Loan_amount DECIMAL(15, 2),
    Loan_type VARCHAR(50),
    Interest_rate DECIMAL(5, 2),
    Tenure INT,
    Loan_status VARCHAR(20),
    Date_applied DATE,
    Approval_date DATE,
    Annual_Income DECIMAL(15, 2),
    User_id VARCHAR(15),
    FOREIGN KEY (User_id) REFERENCES USER(User_id)
);

-- TRANSACTION Table
CREATE TABLE TRANSACTION (
    Transaction_id INT PRIMARY KEY AUTO_INCREMENT,
    User_id VARCHAR(15),
    Account_id INT,
    Amount DECIMAL(15, 2),
    Transaction_type VARCHAR(50),
    Location VARCHAR(100),
    Timestamp TIMESTAMP,
    FOREIGN KEY (User_id) REFERENCES USER(User_id),
    FOREIGN KEY (Account_id) REFERENCES ACCOUNT(Account_id)
);

-- LOG Table
CREATE TABLE LOG (
    Log_id INT PRIMARY KEY AUTO_INCREMENT,
    User_id VARCHAR(15),
    IP_Address VARCHAR(50),
    L_Timestamp TIMESTAMP,
    Activity_Type VARCHAR(50),
    Status VARCHAR(20),
    Access_Level VARCHAR(20),
    FOREIGN KEY (User_id) REFERENCES USER(User_id)
);

-- Populate the tables
-- USER Table
INSERT INTO USER (User_id, F_name, L_name, DOB, Street, City, State, Pincode, Phone_no, Email, Role, Password)
VALUES
('CUS_000001', 'Aarav', 'Sharma', '1995-06-15', 'MG Road', 'Mumbai', 'Maharashtra', '400001', '9876543211', 'aarav.sharma@gmail.com', 'Customer', 'b20f6f89dc6834a64fa558c9219fd406'),
('CUS_000002', 'Diya', 'Mehta', '1990-03-21', 'Park Street', 'Kolkata', 'West Bengal', '700016', '9876123451', 'diya.mehta@gmail.com', 'Customer', '4b2867ac9da89211a9ac281ac8b6af84'),
('CUS_000003', 'Rohan', 'Singh', '1988-11-05', 'MG Road', 'Delhi', 'Delhi', '110001', '9867543212', 'rohan.singh@gmail.com', 'Customer', '3a714e83fb94eb56bcec1a92742b9113'),
('CUS_000004', 'Priya', 'Kumar', '2000-01-11', 'Indira Nagar', 'Lucknow', 'Uttar Pradesh', '226016', '9876543213', 'priya.kumar@gmail.com', 'Customer', 'f07df14eebffb0eb21c79c890585b093'),
('CUS_000005', 'Aisha', 'Ansari', '1993-08-25', 'Banjara Hills', 'Hyderabad', 'Telangana', '500034', '9876578902', 'aisha.ansari@gmail.com', 'Customer', 'c06229239c5d31d61d089192e5523838'),
('CUS_000006', 'Kunal', 'Patel', '1985-10-09', 'Satellite', 'Ahmedabad', 'Gujarat', '380015', '9876598321', 'kunal.patel@gmail.com', 'Customer', 'bb253f7ebcb681a2646bb4fac398b7f6'),
('CUS_000007', 'Sneha', 'Gupta', '1992-11-23', 'Rajouri Garden', 'Delhi', 'Delhi', '110027', '9876547432', 'sneha.gupta@gmail.com', 'Customer', 'f6b4bc58f34b79eaf6711e8f93a79285'),
('CUS_000008', 'Vikram', 'Reddy', '1989-05-17', 'Gachibowli', 'Hyderabad', 'Telangana', '500032', '9876598123', 'vikram.reddy@gmail.com', 'Customer', '18e13576d2c5a5fbf3f8aa74a4deb323'),
('CUS_000009', 'Nisha', 'Jain', '1997-02-19', 'MG Road', 'Bangalore', 'Karnataka', '560001', '9876549876', 'nisha.jain@gmail.com', 'Customer', 'fe5711a2fd2225cbec6d5e17ba77bb32'),
('CUS_000010', 'Aditya', 'Malhotra', '1986-04-22', 'Sector 14', 'Gurgaon', 'Haryana', '122001', '9876587654', 'aditya.malhotra@gmail.com', 'Customer', '4190ebe6fa98d124b88d0c554733a2e8'),
('EMP_000001', 'Rajesh', 'Kumar', '1985-01-15', 'MG Road', 'Mumbai', 'Maharashtra', '400001', '9876543210', 'rajesh.kumar@bank.com', 'Manager', '0b60daf76c849b0dfcc8bbeb90009b88'),
('EMP_000002', 'Anjali', 'Sharma', '1992-06-25', 'Park Street', 'Kolkata', 'West Bengal', '700016', '9876123450', 'anjali.sharma@bank.com', 'Loan Officer', '5d50f0d55c24fe8687df7747e10f7c70'),
('EMP_000003', 'Ravi', 'Verma', '1988-08-05', 'Indiranagar', 'Bangalore', 'Karnataka', '560038', '9876501234', 'ravi.verma@bank.com', 'Accountant', 'de0b9b364558558d25c48e21f70f83bc'),
('EMP_000004', 'Priya', 'Nair', '1990-03-14', 'Connaught Place', 'Delhi', 'Delhi', '110001', '9876547890', 'priya.nair@bank.com', 'Customer Support', 'a9fd9c6e2e03f960208f49a410d470f9'),
('EMP_000005', 'Amit', 'Mehta', '1987-12-11', 'Baner Road', 'Pune', 'Maharashtra', '411045', '9876598765', 'amit.mehta@bank.com', 'IT Specialist', 'f936784f154a1740e153662fd27ff969');
-- ACCOUNT Table
INSERT INTO ACCOUNT (Balance, Creation_date, Account_status, Account_Type, Credit_Score, User_id)
VALUES
(150000.50, '2020-10-15', 'Active', 'Current', 750, 'CUS_000001'),
(250000.00, '2021-01-25', 'Active', 'Savings', 820, 'CUS_000002'),
(100000.00, '2019-05-10', 'Inactive', 'Current', 690, 'CUS_000003'),
(200000.00, '2022-07-20', 'Active', 'Savings', 780, 'CUS_000004'),
(180000.75, '2021-11-30', 'Active', 'Savings', 770, 'CUS_000005'),
(90000.00, '2018-05-18', 'Active', 'Savings', 760, 'CUS_000006'),
(120000.00, '2020-08-25', 'Inactive', 'Savings', 700, 'CUS_000007'),
(250000.00, '2021-10-15', 'Active', 'Savings', 810, 'CUS_000008'),
(175000.00, '2022-12-12', 'Active', 'Current', 820, 'CUS_000009'),
(225000.00, '2023-01-05', 'Active', 'Savings', 770, 'CUS_000010'),
(50000.00, '2023-03-05', 'Active', 'Savings', 720, 'CUS_000001'),
(350000.50, '2021-12-01', 'Active', 'Current', 790, 'CUS_000002'),
(220000.00, '2022-05-20', 'Active', 'Savings', 730, 'CUS_000003'),
(150000.00, '2020-10-05', 'Inactive', 'Savings', 680, 'CUS_000004'),
(200000.00, '2023-02-14', 'Active', 'Current', 800, 'CUS_000005');

-- THREAT_DETECTION Table
INSERT INTO THREAT_DETECTION (Threat_type, Detected_time, Status, Time, User_id)
VALUES
('Phishing', '2023-01-05 10:15:00', 'Resolved', '10:15:00', 'CUS_000001'),
('Account Breach', '2023-02-10 14:30:00', 'Under Review', '14:30:00', 'CUS_000002'),
('Suspicious Login', '2023-03-22 18:45:00', 'Resolved', '18:45:00', 'CUS_000003'),
('Fraud Transaction', '2023-04-15 09:20:00', 'Escalated', '09:20:00', 'CUS_000004'),
('Data Leak', '2023-05-10 12:00:00', 'Resolved', '12:00:00', 'CUS_000005');

-- LOAN Table
INSERT INTO LOAN (Loan_amount, Loan_type, Interest_rate, Tenure, Loan_status, Date_applied, Approval_date, Annual_Income, User_id)
VALUES
(500000.00, 'Home Loan', 6.5, 240, 'Approved', '2023-01-15', '2023-01-20', 800000.00, 'CUS_000001'),
(300000.00, 'Car Loan', 7.2, 60, 'Pending', '2023-02-10', NULL, 650000.00, 'CUS_000002'),
(200000.00, 'Personal Loan', 9.5, 36, 'Rejected', '2023-03-05', NULL, 400000.00, 'CUS_000003'),
(750000.00, 'Business Loan', 8.0, 120, 'Approved', '2023-04-01', '2023-04-10', 1200000.00, 'CUS_000004'),
(100000.00, 'Education Loan', 5.5, 84, 'Approved', '2023-05-20', '2023-05-25', 300000.00, 'CUS_000005');

-- TRANSACTION Table
INSERT INTO TRANSACTION (User_id, Account_id, Amount, Transaction_type, Location, Timestamp)
VALUES
('CUS_000001', 1, 5000.00, 'Deposit', 'Mumbai', '2023-01-01 09:00:00'),
('CUS_000001', 11, 15000.00, 'Deposit', 'Mumbai', '2023-02-03 11:30:00'),
('CUS_000001', 1, 25000.00, 'Withdrawal', 'Mumbai', '2023-04-15 15:45:00'),
('CUS_000001', 1, 50000.00, 'Withdrawal', 'Kolkata', '2023-05-12 20:00:00'),
('CUS_000001', 1, 100000.00, 'Withdrawal', 'Bangalore', '2023-06-21 22:00:00'),
('CUS_000002', 2, 2000.00, 'Withdrawal', 'Kolkata', '2023-02-01 10:30:00'),
('CUS_000002', 12, 15000.00, 'Deposit', 'Kolkata', '2023-02-03 09:00:00'),
('CUS_000002', 2, 5000.00, 'Withdrawal', 'Kolkata', '2023-11-15 15:45:00'),
('CUS_000002', 12, 250000.00, 'Withdrawal', 'Punjab', '2023-07-12 21:00:00'),
('CUS_000002', 12, 25000.00, 'Deposit', 'Kolkata', '2023-12-13 12:45:00'),
('CUS_000003', 3, 1500.00, 'Deposit', 'Delhi', '2023-03-01 11:15:00'),
('CUS_000003', 13, 20000.00, 'Withdrawal', 'Delhi', '2023-02-21 22:00:00'),
('CUS_000003', 3, 5000.00, 'Withdrawal', 'Delhi', '2023-03-17 19:45:00'),
('CUS_000003', 3, 2500.00, 'Withdrawal', 'Delhi', '2023-06-23 18:00:00'),
('CUS_000003', 3, 15000.00, 'Deposit', 'Delhi', '2023-06-17 19:45:00');

-- LOG Table
INSERT INTO LOG (User_id, IP_Address, L_Timestamp, Activity_Type, Status, Access_Level)
VALUES
('EMP_000001', '192.168.76.214', '2025-01-01 08:00:00', 'File Access', 'Active', 'l2'),
('EMP_000002', '192.168.235.60', '2025-01-01 09:00:00', 'Login', 'Active', 'l3'),
('EMP_000003', '192.168.66.95', '2025-01-01 10:00:00', 'Email', 'Active', 'l4'),
('EMP_000001', '192.168.76.214', '2025-01-01 12:00:00', 'Database Query', 'Active', 'l2'),
('EMP_000002', '192.168.235.60', '2025-01-01 14:00:00', 'Email', 'Active', 'l3'),
('EMP_000003', '192.168.66.95', '2025-01-01 14:30:00', 'Logout', 'Active', 'l4'),
('EMP_000001', '192.168.76.214', '2025-01-01 18:00:00', 'Logout', 'Active', 'l2'),
('EMP_000002', '192.168.235.60', '2025-01-01 19:00:00', 'Logout', 'Active', 'l3'),
('EMP_000001', '192.168.76.214', '2025-01-02 08:00:00', 'File Access', 'Active', 'l2'),
('EMP_000002', '192.168.235.60', '2025-01-02 09:00:00', 'Login', 'Active', 'l3'),
('EMP_000003', '192.168.66.95', '2025-01-02 10:00:00', 'Email', 'Suspended', 'l4'),
('EMP_000001', '192.168.76.214', '2025-01-02 12:00:00', 'Database Query', 'Active', 'l2'),
('EMP_000002', '192.168.235.60', '2025-01-02 14:00:00', 'Logout', 'Active', 'l3'),
('EMP_000001', '192.168.76.214', '2025-01-02 18:00:00', 'Logout', 'Active', 'l2'),
('EMP_000001', '192.168.76.214', '2025-01-03 08:00:00', 'File Access', 'Active', 'l2'),
('EMP_000002', '192.168.235.60', '2025-01-03 09:00:00', 'Login', 'Terminated', 'l3'),
('EMP_000003', '192.168.66.95', '2025-01-03 10:00:00', 'Email', 'Suspended', 'l4'),
('EMP_000001', '192.168.76.214', '2025-01-03 12:00:00', 'Database Query', 'Active', 'l2'),
('EMP_000001', '192.168.76.214', '2025-01-03 18:00:00', 'Logout', 'Active', 'l2'),
('EMP_000003', '192.168.66.95', '2025-01-04 10:00:00', 'Login', 'Active', 'l4');
