import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import pickle

# Step 1: Load the dataset
file_path = 'C:/Users/dhiaz/Documents/Phishing/phishing.csv'

df = pd.read_csv(file_path)

# Step 2: Preprocess the data
# Assuming the last column is the target variable and all other columns are features
X = df.drop(columns=['Index','class'])
y = df['class']

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print(f"Size of X_train: {X_train.shape}")

# Step 3: Train the model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Step 4: Evaluate the model
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

# Step 5: Save the model
with open('phishing_model.pkl', 'wb') as file:
    pickle.dump(model, file)