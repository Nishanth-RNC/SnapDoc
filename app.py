from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import sqlite3
from datetime import datetime
import json
import smtplib
from email.mime.text import MIMEText
from twilio.rest import Client
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
import google.generativeai as genai
import traceback
import random
import os
from itsdangerous import URLSafeTimedSerializer as Serializer

# Initialize Flask app
app = Flask(__name__)

# Set a secure secret key (replace with your own)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'fallback-secret-key')

# Database configuration
DATABASE = 'database.db'

# Load environment variables
load_dotenv()

print("Loaded GOOGLE_API_KEY:", bool(os.getenv('GOOGLE_API_KEY')))

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="memory://",  # For production
    # storage_uri="file:///tmp/flask_limiter"  # For development
    default_limits=["200 per day", "50 per hour"]
)

model=genai.GenerativeModel('gemini-1.5-flash')

# Configure Gemini AI
genai.configure(
    api_key=os.getenv('GOOGLE_API_KEY'),
    transport="rest",
    client_options={
        "api_endpoint": "generativelanguage.googleapis.com/"
    }
)

AI_MODEL = 'gemini-1.5-flash'  # Valid model name
SYSTEM_PROMPT = """You are a medical assistant that helps patients understand possible causes for symptoms. 
Your responses MUST use this EXACT format:

Hello SnapDoc user, I'm an AI assistant to help you with my medical advice

Possible Conditions
1. [Condition 1]: Brief explanation
2. [Condition 2]: Brief explanation
3. [Condition 3]: Brief explanation
4. [Condition 4]: Brief explanation

Self-Care Advice
- Recommendation 1
- Recommendation 2
- Recommendation 3

Seek Immediate Care If
- Warning sign 1
- Warning sign 2
- Warning sign 3

Additional requirements:
- Use only the sections above with bold headers ending with colons
- Number possible conditions (1-4)
- Use hyphens for self-care and warning signs
- Keep explanations concise
- Use everyday language
- Never suggest medications beyond basic OTC recommendations
- Include age-specific warnings where relevant"""

# Load states and cities
with open(os.path.join(app.static_folder, 'states_and_cities.json'), 'r') as f:
    statesAndCities = json.load(f)

# Email and SMS configuration
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USER = 'hospital.app2025@gmail.com'  # Replace with your Gmail
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')  # Use App Password (not regular password)
TWILIO_ACCOUNT_SID = os.getenv('TWILIO_SID')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
TWILIO_PHONE_NUMBER = os.getenv('TWILIO_NUMBER')  # Your Twilio phone number

# OTP Configuration
OTP_EXPIRATION = 300  # 5 minutes

# Initialize the serializer
def get_serializer():
    return Serializer(app.secret_key)

# Helper function to connect to the database
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def check_gemini_auth():
    try:
        genai.list_models()
        print("✅ Gemini API connection successful!")
    except Exception as e:
        print(f"❌ Gemini Auth Failed: {str(e)}")

def check_redis_connection():
    try:
        limiter.storage.check()
        print("✅ Redis connection successful!")
    except Exception as e:
        print(f"❌ Redis connection failed: {str(e)}")

# Initialize the database
def init_db():
    with app.app_context():
        db = get_db_connection()
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL,
                phone TEXT NOT NULL,
                email TEXT NOT NULL,
                state TEXT NOT NULL,
                city TEXT NOT NULL
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS doctors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                specialization TEXT NOT NULL,
                experience INTEGER NOT NULL,
                success_rate REAL NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS appointments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                patient_id INTEGER NOT NULL,
                doctor_id INTEGER NOT NULL,
                slot TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('pending', 'confirmed', 'declined', 'cancelled')),
                FOREIGN KEY (patient_id) REFERENCES users (id),
                FOREIGN KEY (doctor_id) REFERENCES doctors (id)
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS chatbot_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                conversation TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        db.commit()

# Generate OTP
def generate_otp():
    return str(random.randint(100000, 999999))

# Send email
def send_email(to_email, subject, body):
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = EMAIL_USER
        msg['To'] = to_email

        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_USER, [to_email], msg.as_string())
        return True
    except Exception as e:
        print(f"Failed to send email: {str(e)}")
        return False

# Send SMS
def send_sms(to_phone, message):
    try:
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        client.messages.create(
            body=message,
            from_=TWILIO_PHONE_NUMBER,
            to=to_phone
        )
        return True
    except Exception as e:
        print(f"Failed to send SMS: {str(e)}")
        return False

# Analyze symptoms using Gemini AI
def analyze_symptoms_generative(symptoms, conversation_history):
    messages = []
    # Include system prompt
    messages.append({"role": "user", "parts": [SYSTEM_PROMPT]})
    messages.append({"role": "model", "parts": ["Understood. I'll follow all guidelines."]})
    
    # Add conversation history
    for entry in conversation_history[-3:]:
        messages.append({"role": "user", "parts": [entry['user']]})
        messages.append({"role": "model", "parts": [entry['bot']]})
    
    # Add current symptoms
    messages.append({"role": "user", "parts": [symptoms]})

    try:
        response = model.generate_content(messages)
        return response.text  # Directly return the text response
        
    except Exception as e:
        print(f"AI Error: {str(e)}")
        return "⚠️ Service unavailable. Please try again later."  # Return plain error string

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ? AND role = ?', 
                            (username, password, role)).fetchone()
        conn.close()

        if user:
            session['user_id'] = user['id']
            session['role'] = user['role']
            session['email'] = user['email']
            if user['role'] == 'patient':
                return redirect(url_for('patient_dashboard'))
            else:
                return redirect(url_for('doctor_dashboard'))
        else:
            flash('Invalid username, password, or role')
    return render_template('login.html')

# OTP Verification Endpoints
@app.route('/send_otp', methods=['POST'])
def send_otp():
    try:
        # Parse JSON data from the request
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400

        # Extract email, phone, and form_data
        email = data.get('email')
        phone = data.get('phone')
        form_data = data.get('form_data')

        # Validate required fields
        if not email or not phone or not form_data:
            return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400

        # Validate location
        state = form_data.get('state')
        city = form_data.get('city')
        if not state or not city:
            return jsonify({'status': 'error', 'message': 'State and city are required'}), 400

        if state not in statesAndCities or city not in statesAndCities.get(state, []):
            return jsonify({'status': 'error', 'message': 'Invalid location'}), 400

        # Generate OTPs
        email_otp = generate_otp()
        phone_otp = generate_otp()

        # Store in session
        serializer = get_serializer()
        session['otp_data'] = serializer.dumps({
            'email': email,
            'phone': phone,
            'email_otp': email_otp,
            'phone_otp': phone_otp,
            'form_data': form_data
        })

        # Send OTPs
        email_sent = send_email(email, "Verification OTP", f"Your OTP is: {email_otp}")
        sms_sent = send_sms(phone, f"Your OTP is: {phone_otp}")

        if email_sent and sms_sent:
            return jsonify({'status': 'success'})
        return jsonify({'status': 'error', 'message': 'Failed to send OTPs'}), 500

    except Exception as e:
        print(f"Error in send_otp: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500
    
@app.route('/otp_verification', methods=['GET'])
def otp_verification():
    # Render the OTP verification page
    return render_template('otp_verification.html')

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    user_email_otp = request.json.get('email_otp')
    user_phone_otp = request.json.get('phone_otp')
    
    serializer = get_serializer()
    try:
        data = serializer.loads(
            session.get('otp_data', ''),
            max_age=OTP_EXPIRATION
        )
    except:
        return jsonify({'status': 'expired'})

    if (data['email_otp'] == user_email_otp and 
        data['phone_otp'] == user_phone_otp):
        # Process signup
        form_data = data['form_data']
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password, role, phone, email, state, city) VALUES (?, ?, ?, ?, ?, ?, ?)', 
                         (form_data['username'], form_data['password'], form_data['role'], 
                          form_data['phone'], form_data['email'], form_data['state'], form_data['city']))
            user_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]

            if form_data['role'] == 'doctor':
                conn.execute('INSERT INTO doctors (user_id, specialization, experience, success_rate) VALUES (?, ?, ?, ?)', 
                             (user_id, form_data['specialization'], form_data['experience'], form_data['success_rate']))

            conn.commit()
            return jsonify({'status': 'success'})
        except sqlite3.IntegrityError:
            return jsonify({'status': 'error', 'message': 'Username already exists'}), 400
        except Exception as e:
            conn.rollback()
            return jsonify({'status': 'error', 'message': str(e)}), 500
        finally:
            conn.close()
    
    return jsonify({'status': 'invalid'})

# Analyze symptoms using Gemini AI
@app.route('/analyze_symptoms', methods=['POST'])
@limiter.limit("5/minute")
def analyze_symptoms():
    if 'user_id' not in session or session['role'] != 'patient':
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json
    symptoms = data.get('text', '').strip()
    history_id = data.get('history_id')

    if not symptoms:
        return jsonify({'error': 'Empty input'}), 400

    conn = get_db_connection()
    try:
        # Load existing history
        conversation_history = []
        if history_id:
            history = conn.execute('SELECT conversation FROM chatbot_history WHERE id = ? AND user_id = ?', 
                                 (history_id, session['user_id'])).fetchone()
            if history:
                conversation_history = json.loads(history['conversation'])

        # Get AI response (plain text)
        diagnosis = analyze_symptoms_generative(symptoms, conversation_history)
        
        # Validate response
        if not diagnosis or len(diagnosis) < 20:  # Basic sanity check
            diagnosis = "Could not generate a proper diagnosis. Please try again."

        # Update conversation
        new_entry = {'user': symptoms, 'bot': diagnosis}
        conversation_history.append(new_entry)
        
        if history_id:
            conn.execute('UPDATE chatbot_history SET conversation = ? WHERE id = ?',
                        (json.dumps(conversation_history), history_id))
        else:
            conn.execute('INSERT INTO chatbot_history (user_id, conversation) VALUES (?, ?)',
                        (session['user_id'], json.dumps(conversation_history)))
            history_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        
        conn.commit()
        return jsonify({
            'response': diagnosis,
            'history_id': history_id,
            'full_conversation': conversation_history
        })

    except Exception as e:
        conn.rollback()
        print(f"Database Error: {str(e)}")
        return jsonify({'error': 'Failed to save conversation'}), 500
    finally:
        conn.close()

# Home page
@app.route('/')
def index():
    return render_template('index.html')

# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        phone = request.form['phone']
        email = request.form['email']
        state = request.form['state']
        city = request.form['city']
        specialization = request.form.get('specialization')
        experience = request.form.get('experience')
        success_rate = request.form.get('success_rate')

        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password, role, phone, email, state, city) VALUES (?, ?, ?, ?, ?, ?, ?)', 
                         (username, password, role, phone, email, state, city))
            user_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]

            if role == 'doctor':
                conn.execute('INSERT INTO doctors (user_id, specialization, experience, success_rate) VALUES (?, ?, ?, ?)', 
                             (user_id, specialization, experience, success_rate))

            conn.commit()

            # Store email in session
            session['email'] = email

            # Send confirmation messages
            email_sent = send_email(email, "Account Created", "Your account has been successfully created.")
            sms_sent = send_sms(phone, "Your account has been successfully created.")
            
            if not email_sent or not sms_sent:
                flash('Account created, but failed to send confirmation messages.')

        except sqlite3.IntegrityError:
            flash('Username already exists')
            return redirect(url_for('signup'))
        except Exception as e:
            conn.rollback()
            flash('Error creating account')
            print(f"Error: {str(e)}")
        finally:
            conn.close()

        return redirect(url_for('login'))
    return render_template('signup.html')

# Patient dashboard
@app.route('/patient_dashboard')
def patient_dashboard():
    if 'user_id' not in session or session['role'] != 'patient':
        return redirect(url_for('login'))

    conn = get_db_connection()
    user = conn.execute('SELECT state, city FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if user:
        doctors = conn.execute('''
            SELECT doctors.id, doctors.specialization, doctors.experience, doctors.success_rate, users.username, users.city
            FROM doctors 
            JOIN users ON doctors.user_id = users.id
            WHERE users.state = ? AND users.city = ?
        ''', (user['state'], user['city'])).fetchall()
    else:
        doctors = []

    confirmed_appointments = conn.execute('''
        SELECT appointments.id, appointments.slot, users.username AS doctor_name 
        FROM appointments 
        JOIN doctors ON appointments.doctor_id = doctors.id 
        JOIN users ON doctors.user_id = users.id 
        WHERE appointments.patient_id = ? AND appointments.status = ?
    ''', (session['user_id'], 'confirmed')).fetchall()

    declined_appointments = conn.execute('''
        SELECT appointments.id, appointments.slot, users.username AS doctor_name 
        FROM appointments 
        JOIN doctors ON appointments.doctor_id = doctors.id 
        JOIN users ON doctors.user_id = users.id 
        WHERE appointments.patient_id = ? AND appointments.status = ?
    ''', (session['user_id'], 'declined')).fetchall()

    chatbot_history = conn.execute('''
        SELECT id, conversation, timestamp 
        FROM chatbot_history 
        WHERE user_id = ?
        ORDER BY timestamp DESC
    ''', (session['user_id'],)).fetchall()
    conn.close()

    return render_template('patient_dashboard.html', doctors=doctors, confirmed_appointments=confirmed_appointments, declined_appointments=declined_appointments, chatbot_history=chatbot_history)

# Doctor dashboard
@app.route('/doctor_dashboard')
def doctor_dashboard():
    if 'user_id' not in session or session['role'] != 'doctor':
        return redirect(url_for('login'))

    conn = get_db_connection()
    doctor = conn.execute('SELECT id FROM doctors WHERE user_id = ?', (session['user_id'],)).fetchone()
    if not doctor:
        flash('Doctor profile not found.')
        return redirect(url_for('logout'))

    appointments = conn.execute('''
        SELECT appointments.id, appointments.slot, appointments.status, users.username 
        FROM appointments 
        JOIN users ON appointments.patient_id = users.id 
        WHERE appointments.doctor_id = ?
    ''', (doctor['id'],)).fetchall()

    # Send important messages to the doctor
    upcoming_appointments = conn.execute('''
        SELECT appointments.slot, users.username 
        FROM appointments 
        JOIN users ON appointments.patient_id = users.id 
        WHERE appointments.doctor_id = ? AND appointments.status = 'confirmed' AND datetime(appointments.slot) > datetime('now')
    ''', (doctor['id'],)).fetchall()

    pending_appointments = conn.execute('''
        SELECT appointments.slot, users.username 
        FROM appointments 
        JOIN users ON appointments.patient_id = users.id 
        WHERE appointments.doctor_id = ? AND appointments.status = 'pending'
    ''', (doctor['id'],)).fetchall()

    conn.close()

    # Send email notifications
    if 'email' in session:  # Check if email exists in session
        if upcoming_appointments:
            message = "Upcoming Appointments:\n"
            for appointment in upcoming_appointments:
                message += f"{appointment['username']} at {appointment['slot']}\n"
            send_email(session['email'], "Upcoming Appointments", message)

        if pending_appointments:
            message = "Pending Appointments:\n"
            for appointment in pending_appointments:
                message += f"{appointment['username']} at {appointment['slot']}\n"
            send_email(session['email'], "Pending Appointments", message)
    else:
        flash('Email not found in session. Please log in again.')

    return render_template('doctor_dashboard.html', appointments=appointments)

# Book slot route
@app.route('/book_slot/<int:doctor_id>', methods=['GET', 'POST'])
def book_slot(doctor_id):
    if 'user_id' not in session or session['role'] != 'patient':
        return redirect(url_for('login'))

    if request.method == 'POST':
        slot = request.form['slot']

        if datetime.fromisoformat(slot) < datetime.now():
            flash('You cannot book a slot in the past.')
            return redirect(url_for('patient_dashboard'))

        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO appointments (patient_id, doctor_id, slot, status) VALUES (?, ?, ?, ?)', 
                          (session['user_id'], doctor_id, slot, 'pending'))
            conn.commit()

            # Fetch patient details
            patient = conn.execute('SELECT phone, email FROM users WHERE id = ?', (session['user_id'],)).fetchone()

            # Send confirmation message to patient
            if patient:
                send_sms(patient['phone'], f"Your appointment has been booked for {slot}. Waiting for doctor confirmation.")
                send_email(patient['email'], "Appointment Booked", f"Your appointment has been booked for {slot}. Waiting for doctor confirmation.")
            else:
                flash('Failed to fetch patient details.')

            flash('Slot booked successfully. Waiting for doctor confirmation.')
        except Exception as e:
            conn.rollback()
            flash('Error booking slot')
            print(f"Error: {str(e)}")
        finally:
            conn.close()

        return redirect(url_for('patient_dashboard'))

    return render_template('book_slot.html', doctor_id=doctor_id)

# Confirm appointment route
@app.route('/confirm_appointment/<int:appointment_id>')
def confirm_appointment(appointment_id):
    if 'user_id' not in session or session['role'] != 'doctor':
        return redirect(url_for('login'))

    conn = get_db_connection()
    doctor = conn.execute('SELECT id FROM doctors WHERE user_id = ?', (session['user_id'],)).fetchone()
    if not doctor:
        flash('Doctor profile not found.')
        return redirect(url_for('logout'))

    appointment = conn.execute('SELECT * FROM appointments WHERE id = ? AND doctor_id = ?', 
                               (appointment_id, doctor['id'])).fetchone()
    if appointment:
        conn.execute('UPDATE appointments SET status = ? WHERE id = ?', ('confirmed', appointment_id))
        conn.commit()

        # Send confirmation message to patient
        patient = conn.execute('SELECT phone, email FROM users WHERE id = ?', (appointment['patient_id'],)).fetchone()
        send_sms(patient['phone'], f"Your appointment has been confirmed for {appointment['slot']}.")
        send_email(patient['email'], "Appointment Confirmed", f"Your appointment has been confirmed for {appointment['slot']}.")

        flash('Appointment confirmed.')
    else:
        flash('Appointment not found or you do not have permission to confirm it.')
    conn.close()

    return redirect(url_for('doctor_dashboard'))

# Decline appointment route
@app.route('/decline_appointment/<int:appointment_id>')
def decline_appointment(appointment_id):
    if 'user_id' not in session or session['role'] != 'doctor':
        return redirect(url_for('login'))

    conn = get_db_connection()
    doctor = conn.execute('SELECT id FROM doctors WHERE user_id = ?', (session['user_id'],)).fetchone()
    if not doctor:
        flash('Doctor profile not found.')
        return redirect(url_for('logout'))

    appointment = conn.execute('SELECT * FROM appointments WHERE id = ? AND doctor_id = ?', 
                               (appointment_id, doctor['id'])).fetchone()
    if appointment:
        conn.execute('UPDATE appointments SET status = ? WHERE id = ?', ('declined', appointment_id))
        conn.commit()

        # Send notification to patient
        patient = conn.execute('SELECT phone, email FROM users WHERE id = ?', (appointment['patient_id'],)).fetchone()
        send_sms(patient['phone'], f"Your appointment for {appointment['slot']} has been declined.")
        send_email(patient['email'], "Appointment Declined", f"Your appointment for {appointment['slot']} has been declined.")

        flash('Appointment declined.')
    else:
        flash('Appointment not found or you do not have permission to decline it.')
    conn.close()

    return redirect(url_for('doctor_dashboard'))

# Emergency cancellation of appointment by patient
@app.route('/cancel_appointment/<int:appointment_id>')
def cancel_appointment(appointment_id):
    if 'user_id' not in session or session['role'] != 'patient':
        return redirect(url_for('login'))

    conn = get_db_connection()
    appointment = conn.execute('SELECT * FROM appointments WHERE id = ? AND patient_id = ?', 
                               (appointment_id, session['user_id'])).fetchone()
    if appointment:
        conn.execute('UPDATE appointments SET status = ? WHERE id = ?', ('cancelled', appointment_id))
        conn.commit()

        # Send notification to doctor
        doctor = conn.execute('SELECT users.phone, users.email FROM doctors JOIN users ON doctors.user_id = users.id WHERE doctors.id = ?', (appointment['doctor_id'],)).fetchone()
        send_sms(doctor['phone'], f"Appointment for {appointment['slot']} has been cancelled by the patient.")
        send_email(doctor['email'], "Appointment Cancelled", f"Appointment for {appointment['slot']} has been cancelled by the patient.")

        flash('Appointment cancelled successfully.')
    else:
        flash('Appointment not found or you do not have permission to cancel it.')
    conn.close()

    return redirect(url_for('patient_dashboard'))

# Emergency cancellation of appointment by doctor
@app.route('/doctor_cancel_appointment/<int:appointment_id>')
def doctor_cancel_appointment(appointment_id):
    if 'user_id' not in session or session['role'] != 'doctor':
        return redirect(url_for('login'))

    conn = get_db_connection()
    doctor = conn.execute('SELECT id FROM doctors WHERE user_id = ?', (session['user_id'],)).fetchone()
    if not doctor:
        flash('Doctor profile not found.')
        return redirect(url_for('logout'))

    appointment = conn.execute("SELECT * FROM appointments WHERE id = ? AND doctor_id = ? AND status = 'confirmed'", 
                               (appointment_id, doctor['id'])).fetchone()
    if appointment:
        conn.execute('UPDATE appointments SET status = ? WHERE id = ?', ('cancelled', appointment_id))
        conn.commit()

        # Send notification to patient
        patient = conn.execute('SELECT phone, email FROM users WHERE id = ?', (appointment['patient_id'],)).fetchone()
        send_sms(patient['phone'], f"Your appointment for {appointment['slot']} has been cancelled by the doctor.")
        send_email(patient['email'], "Appointment Cancelled", f"Your appointment for {appointment['slot']} has been cancelled by the doctor.")

        flash('Appointment cancelled successfully.')
    else:
        flash('Appointment not found or you do not have permission to cancel it.')
    conn.close()

    return redirect(url_for('doctor_dashboard'))

# Chatbot route
@app.route('/chatbot')
def chatbot():
    if 'user_id' not in session or session['role'] != 'patient':
        return redirect(url_for('login'))

    history_id = request.args.get('history_id')
    conn = get_db_connection()
    if history_id:
        history = conn.execute('SELECT conversation FROM chatbot_history WHERE id = ? AND user_id = ?', 
                              (history_id, session['user_id'])).fetchone()
        if history:
            conversation = json.loads(history['conversation'])
        else:
            conversation = []
    else:
        conversation = []

    chatbot_history = conn.execute('''
        SELECT id, conversation, timestamp 
        FROM chatbot_history 
        WHERE user_id = ?
        ORDER BY timestamp DESC
    ''', (session['user_id'],)).fetchall()
    conn.close()

    parsed_chatbot_history = []
    for chat in chatbot_history:
        parsed_chat = {
            'id': chat['id'],
            'conversation': json.loads(chat['conversation']),
            'timestamp': chat['timestamp']
        }
        parsed_chatbot_history.append(parsed_chat)

    return render_template('chatbot.html', history=conversation, chatbot_history=parsed_chatbot_history, history_id=history_id)

# Delete chatbot history
@app.route('/delete_chat_history/<int:history_id>')
def delete_chat_history(history_id):
    if 'user_id' not in session or session['role'] != 'patient':
        return redirect(url_for('login'))

    conn = get_db_connection()
    conn.execute('DELETE FROM chatbot_history WHERE id = ? AND user_id = ?', 
                 (history_id, session['user_id']))
    conn.commit()
    conn.close()

    flash('Chat history deleted successfully.')
    return redirect(url_for('patient_dashboard'))

# Logout route
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('role', None)
    session.pop('email', None)
    return redirect(url_for('index'))

# Run the application
if __name__ == '__main__':
    init_db()
    app.run(debug=True)