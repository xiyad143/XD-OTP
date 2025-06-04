import re
import time
import requests
import os
import json
import psycopg2
from psycopg2.extras import Json
from flask import Flask, render_template, request, jsonify, redirect, url_for
import bleach
from pywebpush import webpush, WebPushException

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'supersecretkey')

# Global variable to store messages
message_store = {}

def init_db():
    """Initialize PostgreSQL database"""
    conn = psycopg2.connect(os.environ.get('DB_URL'))
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS subscriptions (
            id SERIAL PRIMARY KEY,
            subscription JSONB NOT NULL
        )
    ''')
    conn.commit()
    cur.close()
    conn.close()

def validate_credentials(email: str, password: str, refresh_token: str, client_id: str) -> tuple:
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        return False, "Invalid email format"
    if not password or not refresh_token or not client_id:
        return False, "Password, refresh_token, or client_id cannot be empty"
    return True, ""

def get_messages(email: str, password: str, refresh_token: str, client_id: str, timeout: int = 15):
    try:
        valid, msg = validate_credentials(email, password, refresh_token, client_id)
        if not valid:
            return {"status": "error", "message": msg}

        headers = {
            'accept': 'application/json',
            'content-type': 'application/json',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

        response = requests.post(
            'https://tools.dongvanfb.net/api/get_messages_oauth2',
            headers=headers,
            json={
                'email': email,
                'pass': password,
                'refresh_token': refresh_token,
                'client_id': client_id,
            },
            timeout=timeout
        )

        if response.status_code == 429:
            return {"status": "error", "message": "Rate limit exceeded. Please try again later."}
        elif response.status_code != 200:
            return {"status": "error", "message": f"API request failed with status {response.status_code}"}

        data = response.json()
        messages = data.get('messages', [])
        
        for message in messages:
            body = (message.get('body', '') or 
                    message.get('text', '') or 
                    message.get('content', '') or 
                    'No Body Available')
            message['body'] = bleach.clean(body, tags=['p', 'br', 'strong', 'em'], strip=True)
        
        message_store[email] = messages
        return {"status": "success", "messages": messages}
        
    except Exception as e:
        return {"status": "error", "message": f"An error occurred: {str(e)}"}

def extract_otp(messages):
    for message in messages:
        text = message.get('subject', '') + ' ' + message.get('body', '')
        match = re.search(r'\b(\d{4,8})\b', text, re.IGNORECASE)
        if match:
            return match.group(1)
    return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    input_data = request.form['credentials'].strip()
    
    if '|' in input_data:
        parts = input_data.split('|')
        if len(parts) == 4:
            email, password, refresh_token, client_id = [part.strip() for part in parts]
        else:
            return render_template('index.html', error="Invalid input format. Expected: email|password|refresh_token|client_id")
    else:
        return render_template('index.html', error="Invalid input format. Use '|' separator")
    
    result = get_messages(email, password, refresh_token, client_id)
    
    if result['status'] == 'error':
        return render_template('index.html', error=result['message'], email=email)
    
    messages = result['messages']
    otp_code = extract_otp(messages)
    
    if otp_code:
        send_push_notification(otp_code)
    
    return render_template(
        'index.html', 
        email=email,
        password=password,
        refresh_token=refresh_token,
        client_id=client_id,
        messages=messages,
        otp_code=otp_code,
        success=f"Successfully retrieved {len(messages)} messages"
    )

@app.route('/refresh', methods=['POST'])
def refresh():
    email = request.form['email']
    password = request.form['password']
    refresh_token = request.form['refresh_token']
    client_id = request.form['client_id']
    
    result = get_messages(email, password, refresh_token, client_id)
    
    if result['status'] == 'error':
        return render_template('index.html', error=result['message'], email=email)
    
    messages = result['messages']
    otp_code = extract_otp(messages)
    
    if otp_code:
        send_push_notification(otp_code)
    
    return render_template(
        'index.html', 
        email=email,
        password=password,
        refresh_token=refresh_token,
        client_id=client_id,
        messages=messages,
        otp_code=otp_code,
        success=f"Mailbox refreshed. {len(messages)} messages found"
    )

@app.route('/delete', methods=['POST'])
def delete():
    email = request.form['email']
    if email in message_store:
        del message_store[email]
    return render_template('index.html', email=email, success=f"Account data for {email} deleted")

@app.route('/delete_message', methods=['POST'])
def delete_message():
    data = request.get_json()
    email = data.get('email')
    message_id = data.get('message_id')
    if not email or not message_id:
        return jsonify({"status": "error", "message": "Email or message ID missing"})
    if email in message_store:
        message_store[email] = [msg for msg in message_store[email] if str(msg.get('id', '')) != str(message_id)]
        return jsonify({"status": "success", "message": "Message deleted"})
    return jsonify({"status": "error", "message": "Email not found in message store"})

@app.route('/subscribe', methods=['POST'])
def subscribe():
    subscription = request.get_json()
    conn = psycopg2.connect(os.environ.get('DB_URL'))
    try:
        cur = conn.cursor()
        cur.execute('INSERT INTO subscriptions (subscription) VALUES (%s)', (Json(subscription),))
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Subscribed to push notifications'})
    except Exception as e:
        print(f"Database error: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Failed to subscribe'})
    finally:
        cur.close()
        conn.close()

@app.route('/send_notification', methods=['POST'])
def send_notification():
    data = request.get_json()
    otp_code = data.get('otp_code')
    if not otp_code:
        return jsonify({'status': 'error', 'message': 'No OTP code provided'})
    send_push_notification(otp_code)
    return jsonify({'status': 'success', 'message': 'Notification sent'})

def send_push_notification(otp_code):
    VAPID_PRIVATE_KEY = os.environ.get('VAPID_PRIVATE_KEY')
    VAPID_CLAIMS = {"sub": "mailto:xiyad404@gmail.com"}
    conn = psycopg2.connect(os.environ.get('DB_URL'))
    try:
        cur = conn.cursor()
        cur.execute('SELECT subscription FROM subscriptions')
        subscriptions = cur.fetchall()
        for (subscription,) in subscriptions:
            try:
                webpush(
                    subscription_info=subscription,
                    data=json.dumps({
                        'title': 'New OTP Found  !',
                        'body': f'Your Verification Code : {otp_code}',
                        'url': os.environ.get('APP_URL', 'https://xiyadotp.onrender.com')
                    }),
                    vapid_private_key=VAPID_PRIVATE_KEY,
                    vapid_claims=VAPID_CLAIMS
                )
            except WebPushException as e:
                print(f'Push failed: {e}')
    finally:
        cur.close()
        conn.close()

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)