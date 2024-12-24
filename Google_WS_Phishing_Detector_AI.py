# GS_Phishing_Detection_AI
A simple AI used to detect phishing emails in Google Workspace accounts with custom domains

"""
Basic Gmail Phishing Scanner
Written by: Nick Alonzo
Version 0.0.1.1

Scans gmail inboxes for phishing emails and prints results to the terminal or console
Does not remediate

to install use the below bash script (check requirements):
(Requires Google API Client and google-auth libraries - imported into source code below)
(Regular Expresssions)

pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib

Then go to GCP Cloud Console >> Create New Project >> Enable Gmail API >> Create OAuth 2.0 credentials

"""

import os
import base64
import re
import json
import subprocess
import sys
import requests
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
import pickle

# If modifying the SCOPES, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Load or train a phishing detection model
def load_phishing_model():
    """Load the pre-trained phishing model (or train it)."""
    model_path = 'phishing_model.pkl'
    
    # Check if the model exists, otherwise train it
    if os.path.exists(model_path):
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        print("Loaded pre-trained phishing detection model.")
    else:
        print("Training new phishing detection model.")
        model = train_phishing_model()
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
        print("Model trained and saved.")
    
    return model

def train_phishing_model():
    """Train a basic phishing detection model using a sample dataset."""
    # Sample data for training: 1 for phishing, 0 for legitimate
    # In practice, you would use a larger labeled dataset
    data = [
        ("Your account has been suspended. Click here to resolve the issue.", 1),
        ("Urgent: Verify your account immediately.", 1),
        ("Dear user, your recent purchase was successful. Thank you!", 0),
        ("Reminder: Your bill is due next week. Please pay now.", 0)
    ]
    
    texts, labels = zip(*data)
    
    # Vectorize the text data
    vectorizer = CountVectorizer(stop_words='english')
    X = vectorizer.fit_transform(texts)
    
    # Train a Naive Bayes classifier
    model = MultinomialNB()
    model.fit(X, labels)
    
    return model

def classify_email(model, email_content):
    """Classify an email as phishing or legitimate using the AI model."""
    vectorizer = CountVectorizer(stop_words='english')
    email_vector = vectorizer.transform([email_content])
    
    prediction = model.predict(email_vector)
    return prediction[0]

def install_requirements():
    """Automatically install required libraries."""
    try:
        import google.auth
        import google.auth.transport.requests
        import google_auth_oauthlib
        import googleapiclient.discovery
        import sklearn
    except ImportError:
        print("Installing required libraries...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", '--upgrade', 'google-api-python-client', 'google-auth-httplib2', 'google-auth-oauthlib', 'scikit-learn'])
        print("Libraries installed successfully.")
        return True
    return False

def authenticate_gmail_api():
    """Authenticate and return the Gmail API service."""
    creds = None

    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            print("Requesting OAuth consent...")
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)

        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    try:
        service = build('gmail', 'v1', credentials=creds)
        return service
    except HttpError as error:
        print(f'An error occurred: {error}')
        return None

def list_messages(service, label_ids=['INBOX'], q=""):
    """List all messages in the user's inbox."""
    try:
        results = service.users().messages().list(userId='me', labelIds=label_ids, q=q).execute()
        messages = results.get('messages', [])
        return messages
    except HttpError as error:
        print(f'An error occurred: {error}')
        return []

def get_message(service, msg_id):
    """Get the details of a specific message."""
    try:
        message = service.users().messages().get(userId='me', id=msg_id).execute()
        return message
    except HttpError as error:
        print(f'An error occurred: {error}')
        return None

def decode_message(message):
    """Decode and return the content of the email."""
    try:
        data = message['payload']['headers']
        for header in data:
            if header['name'] == 'From':
                sender = header['value']
        
        payload = message['payload']['parts'][0]['body']['data']
        byte_code = base64.urlsafe_b64decode(payload)
        text = byte_code.decode("utf-8")
        
        return sender, text
    except Exception as e:
        print(f"Error decoding message: {e}")
        return None, None

def scan_inbox_for_phishing(service, model):
    """Scan the inbox and look for phishing emails."""
    print("Scanning inbox for phishing emails...")

    messages = list_messages(service)
    if not messages:
        print('No messages found.')
        return
    
    for msg in messages:
        msg_id = msg['id']
        message = get_message(service, msg_id)
        
        if message:
            sender, email_content = decode_message(message)
            if email_content:
                # Use the AI model to classify the email
                is_phishing = classify_email(model, email_content)
                
                if is_phishing == 1:
                    print(f"Potential phishing email found from: {sender}")
                    print(f"Subject: {message['snippet']}")
                    print("-----")

def bootstrap():
    """Automated bootstrap process to install dependencies and authenticate."""
    if install_requirements():
        print("Dependencies were installed. You can now run the program.")

    if not os.path.exists('credentials.json'):
        print("The 'credentials.json' file is missing. Please provide it manually.")
        return

    # Load phishing detection model
    model = load_phishing_model()

    service = authenticate_gmail_api()
    if service:
        scan_inbox_for_phishing(service, model)

if __name__ == '__main__':
    bootstrap()
