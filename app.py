import sqlite3
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from markupsafe import escape
import uuid
from datetime import datetime, timedelta
import ollama
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode



app = Flask(__name__)
CORS(app)  # Enable CORS for frontend communication
app.secret_key = '55428bfda7a40f8503d98fd3f6dd2e625aee4a1a58303f52a67904863ffbec41c409f556835771dcb208d9be05eac871758a7cf7a6ed90103e5138b4e75ff7caed4e14cd204c5470f61f3c2b135418fb998385995a89680d4b4890d56906b439521d0bb92f9028a100b532213878f46eb9c706ccb46349d528e7d77ebe1dfb40458f1f1ebd03ac7a4be83e9f8480b925cdacbdedd3b7acdd6f93459b17176b654cb22d83d18ad731355decad0ec7987c3ed6ec27e06a405723101b3d39bfeaf237aa227f4b16a3103b61b652f495909078e8162566d3b3ce8dfeb8050d872f866e0ea7e7c7d1fc75e6357fbef1967dde85ea12e0d62315cac813e4c7eb5251e3649903e7f38e79b2424af57ceb7492db737c606a38654d4265a47ebe6fc607b28b4cd1f057d5a47025d35fb10ecc114cd9903e18587958d19d7758c171a63f66'

app.config.update(
    SESSION_COOKIE_SECURE=True,  # Enforces HTTPS for session cookies
    SESSION_COOKIE_HTTPONLY=True,  # Prevents client-side JS from accessing session cookies
    SESSION_COOKIE_SAMESITE='Strict'  # Prevents cross-site request forgery (CSRF)
)

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)


@app.before_request
def enforce_https():
    if not request.is_secure:
        return redirect(request.url.replace('http://', 'https://'))
    if 'Session' not in session:
        set_session_values()  # Ensure session values are set

def make_session_permanent():
    session.permanent = True
    set_session_values()  # Ensure session is properly initialized

def set_session_values():
    session.clear()
    session['Session'] = False
    session['chat_id'] = None  # Reset chat ID
    session['pending_user'] = None
    session.modified = True  # Ensure Flask recognizes the changes




limiter = Limiter(get_remote_address, app=app, default_limits=["50 per minute"])




#Initialise the user database and creates it if it does not exist
def init_db():
    conn = sqlite3.connect('databases.db')
    c = conn.cursor()

    c.execute('''
                CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                permission_level INTEGER DEFAULT 0 NOT NULL,
                mfa_secret TEXT
               )
                ''')
    
    c.execute('''
              CREATE TABLE IF NOT EXISTS chat_history (
              chat_id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id INTEGER NOT NULL,
              chatNumber INTEGER NOT NULL,
              chatTitle TEXT NOT NULL,
              FOREIGN KEY (user_id) REFERENCES users(user_id)
              )
              ''')
    
    c.execute('''
              CREATE TABLE IF NOT EXISTS chat_data (
              chat_id INTEGER,
              message TEXT NOT NULL,
              role TEXT NOT NULL,
              messageTime TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
              FOREIGN KEY (chat_id) REFERENCES chat_history(chat_id)
              )
              ''')
    
    conn.commit()
    conn.close()

def insert_admin_user():
    conn = sqlite3.connect('databases.db')
    c = conn.cursor()
    
    # Check if admin user already exists
    c.execute("SELECT * FROM users WHERE username = 'admin'")
    if c.fetchone() is None:
        # Insert admin user with a default password and permission level 1
        admin_password = generate_password_hash('admin')
        c.execute("INSERT INTO users (username, password, permission_level) VALUES (?, ?, ?)", ('admin', admin_password, 1))
        conn.commit()
    
    conn.close()

def insert_mfa_secret_for_user(username):
    conn = sqlite3.connect('databases.db')
    c = conn.cursor()

    c.execute("SELECT mfa_secret FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    if result:
        existing_mfa_secret = result[0]
    
    c.execute("UPDATE users SET mfa_secret = ? WHERE username = ?", (result[0], 'admin'))
    
    conn.commit()
    conn.close()


init_db()


#Empty Log file
f = open("error.txt", "w")
f.write("")
f.close()




@app.route('/')
def index():
    if 'user_id' not in session:
        session.clear()
    return render_template('chat.html')




@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
     if request.method == 'POST':
         
         username = escape(request.form.get('username'))
         password = escape(request.form.get('password'))

         if username == '' or password == '':
            return redirect(url_for('login'))
         elif len(username) > 50 or len(password) > 50:
             return redirect(url_for('login'))
         
         else:
             try:
                conn = sqlite3.connect('databases.db')
                conn.row_factory = sqlite3.Row
                c = conn.cursor()

                c.execute("SELECT * FROM users WHERE username = ?", (username,))
                user = c.fetchone()  # Now returns a single row or None if no match

                if user:  # Check if a user was found
                    user = dict(user)

                    if check_password_hash(user["password"], str(password)) == True:  # Use column names
                        session.clear()

                        session['pending_user'] = user["user_id"]
                        session['csrf_token'] = str(uuid.uuid4())
                        session['Session'] = True

                        #print(session['user_id'])

                        if user["mfa_secret"] is None:
                            return redirect(url_for('setup_mfa'))
                        
                         # Otherwise, this will just ask them to enter their code
                        return redirect(url_for('verify_mfa', username=user['username'], perm_lvl=user['permission_level']))


                conn.commit()
                conn.close()
             except:
                 return redirect(url_for('login'))
     return render_template('login.html')




@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def signup():
     if request.method == 'POST':

        #Gets username and password from the form
        username = escape(request.form.get('username'))
        password = escape(request.form.get('password'))
        c_password = escape(request.form.get('c-password'))
        
        #Check if the username and password are empty
        if username == '' or password == '':
            return redirect(url_for('signup'))
        elif len(username) > 50 or len(password) > 50:
             return redirect(url_for('signup'))
        elif password == c_password:
            password = generate_password_hash(password)
        
            #Connect to the database
            try:
                conn = sqlite3.connect('databases.db')
                c = conn.cursor()

                c.execute('''
                        SELECT * from users where username = (?)
                        ''', [username])
                
                #Check if the username already exists
                exists = c.fetchone()

                if exists is not None:
                    return redirect(url_for('signup'))
                
                #If the username does not exist, add the user to the database
                else:
                    c.execute('''INSERT INTO users (username, password)
                                VALUES (?, ?)
                            ''', (username, password))

                    conn.commit()
                    conn.close()

                    log_error(200, f"New Account Created: {username}")
                    return redirect(url_for('login'))
            except:
                log_error(500, "Couldn't Connect to Database")
                return redirect(url_for('error', error=500, message="Couldn't Connect to Database"))
     else:
        return render_template('signup.html')
     



@app.route('/setup_mfa', methods=['GET', 'POST'])
def setup_mfa():
    if session.get('pending_user') is None:
        return redirect('/login')
    user_id = session['pending_user']
    # This will just retrieve the current MFA secret key for the user

    conn = sqlite3.connect('databases.db')
    c = conn.cursor()
    c.execute("SELECT mfa_secret FROM users WHERE user_id = ?", (user_id,))
    secret = c.fetchone()[0]

    # Creates a MFA secret key
    if not secret:
        secret = pyotp.random_base32()
        c.execute("UPDATE users SET mfa_secret = ? WHERE user_id = ?", (secret, user_id))
        conn.commit()
    conn.close()
    
    # Generate QR Code -> So the user can setup MFA on the MS Authenticator App
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name="AI Chatbot Website", issuer_name="General Kenobi")
    
    qr = qrcode.make(uri)
    qr_path = "static/qrcode.png"
    qr.save(qr_path)
    return render_template("setup_mfa.html", qr_path=qr_path)




@app.route('/verify_mfa', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def verify_mfa():
    user = {
        "username": request.args.get("username"),
        "permission_level": request.args.get("perm_lvl")
    }
    if 'pending_user' not in session:
        return redirect('/login')
    user_id = session['pending_user']
    if request.method == 'POST':
        # Retrieves the code from the text box
        otp_code = request.form['otp'].strip()


        conn = sqlite3.connect('databases.db')
        cursor = conn.cursor()

        cursor.execute("SELECT mfa_secret FROM users WHERE user_id = ?", (user_id,))

        secret = cursor.fetchone()[0]
        conn.close()


        totp = pyotp.TOTP(secret)


        # Compares the input code to the database 
        if totp.verify(otp_code, valid_window=1):
            #del session['pending_user']
            session['user_id'] = user_id
            session['username'] = user['username']
            session['permission_level'] = user['permission_level']
            session['csrf_token'] = str(uuid.uuid4())
            session['chat_id'] = None  # Reset chat ID

            log_error(200, f"{session['username']} Logged In")

            return redirect('/')
        flash("Invalid 2FA code. Try again.", "error")
    return render_template("verify_mfa.html")




@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    session['Session'] = False
    session['chat_id'] = None
    return redirect(url_for('index'))




@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = escape(request.form.get('username'))
        password = escape(request.form.get('password'))
        c_password = request.form.get('c_password')

        if username == session.get('username') and password == c_password:
            password = generate_password_hash(password)
            
            try:

                conn= sqlite3.connect('databases.db')
                c = conn.cursor()

                c.execute('''
                            UPDATE users SET password = ? WHERE username = ? 
                        ''',(password, username))
                
                
                conn.commit()
                conn.close()

                log_error(200, f"{username} Reset Password")

                return redirect(url_for('index'))
            except:
                log_error(500, "Couldn't Connect to Database")
                return redirect(url_for('error', error=500, message="Couldn't Connect to Database"))

    return render_template('reset_password.html')




@app.route('/request_admin', methods=['GET'])
def request_admin():
    print(session['permission_level'])
    if int(session['permission_level']) == 1:
        return redirect(url_for('admin'))
    else:
        log_error(401, "Not Admin User")
        return jsonify({'error': "Not Admin User"}), 401
    



@app.route('/admin')
def admin():
    log_error(200, "Admin Page Opened")
    return render_template('admin.html')




# Fetch chat history endpoint
@app.route("/history", methods=["GET"])
def history():
    return jsonify(load_chat_history())




# Chat endpoint
@app.route("/chat", methods=["POST"])
def chat():
    data = request.json
    user_input = data.get("message", "")

    if not user_input:
        log_error(400, "Message cannot be empty")
        return jsonify({"error": "Message cannot be empty"}), 400

    model = "llama3.1"
    chat_history = load_chat_history()
    chat_history.append({"role": "user", "content": user_input})
      
    
    # Generate chatbot response
    response = ollama.chat(model=model, messages=chat_history)
    bot_message = response["message"]["content"]

    chat_history.append({"role": "assistant", "content": bot_message})

    if session['Session'] == True and session['chat_id'] != None:
        # Append user message to database
        save_chat_message(session['chat_id'], user_input, 'user')
    
        # Append bot message to database
        save_chat_message(session['chat_id'], bot_message, 'assistant')

        create_chat_title(session['chat_id'], model, user_input)
    
    return jsonify({"response": bot_message})




@app.route('/new_chat', methods=['POST'])
def new_chat():
    if 'user_id' not in session:
        log_error(401, "User not logged in")
        return jsonify({"error": "User not logged in"}), 401

    new_chat_id, new_chat_title = create_new_chat(session['user_id'])
    
    return jsonify({"message": "New chat created", "chat_id": new_chat_id, "chat_title": new_chat_title})




@app.route('/get_chats', methods=['GET'])
def get_chats():
    #Fetches a list of past chats for the current user.
    if 'user_id' not in session:
        log_error(401, "User not logged in")
        return jsonify({"error": "User not logged in"}), 401

    conn = sqlite3.connect('databases.db')
    c = conn.cursor()

    c.execute("SELECT chat_id, chatTitle FROM chat_history WHERE user_id = ?", (session['user_id'],))

    chats = [{"chat_id": row[0], "title": row[1]} for row in c.fetchall()]
    conn.commit()
    conn.close()

    return jsonify(chats)




@app.route("/admin_get_chats", methods=["GET"])
def admin_chats():
    return jsonify(admin_all_chats())




@app.route('/set_chat_id', methods=['GET'])
def set_chat_id():
    chat_id = request.args.get("chat_id")
    if not chat_id:
        log_error(400, "Chat ID is required")
        return jsonify({"error": "Chat ID is required"}), 400
    
    session['chat_id'] = chat_id
    return jsonify({"message": "Chat ID set"})




@app.route('/check_user_data', methods=['GET'])
def check_user_data():
    perm_level = session.get('permission_level')
    in_session = session.get('Session')
    try:
        perm_level = int(perm_level)
        if perm_level == 1:
            return jsonify({"message": "True", "in_session": "True"})
        elif in_session == True:
            return jsonify({"message": "sfihsbi33bjefowefwewegarerbrpo22u393", "in_session": "True"})     
        else:
            return jsonify({"message": "sdfhbwefobqbfinewvvweeve018y5249tggw", "in_session": "False"})
        
    except:
        log_error(400, "Permission level not found")
        return redirect(url_for('error', error=400, message="Permission level not found"))




@app.route("/delete_chat/<int:chat_id>", methods=["DELETE"])
def delete_chat(chat_id):
    conn = sqlite3.connect("databases.db")
    cursor = conn.cursor()

    cursor.execute("DELETE FROM chat_history WHERE chat_id = ?", (chat_id,))

    conn.commit()
    conn.close()
    
    log_error(200, "Admin Deleted Chat")
    return jsonify({"success": True, "message": "Chat deleted successfully!"})




@app.route("/user_profile")
def user_profile():
    if session.get('Session') == True:
        return render_template('user_profile.html', username=session.get('username'))
    else: 
        log_error(401, "Invalid User or Not Logged In")
        return redirect(url_for('error', error=401, message="Invalid User or Not Logged In"))




@app.route("/get_chat_count", methods=['GET'])
def get_chat_count():
    user_id = session.get('user_id')  # Ensure the user is logged in
    if not user_id:
        return jsonify({"chat_count": 0})

    conn = sqlite3.connect('databases.db')
    c = conn.cursor()
    c.execute("SELECT MAX(chatNumber) FROM chat_history WHERE user_id = ?", (user_id,))
    result = c.fetchone()
    conn.close()

    chat_count = result[0] if result and result[0] else 0
    return jsonify({"chat_count": chat_count})
    



@app.route('/get_chat_dates')
def get_chat_dates():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"dates": [], "counts": []})

    conn = sqlite3.connect('databases.db')
    c = conn.cursor()

    date_counts = {}
    for i in range(5, -1, -1):
        date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        date_counts[date] = 0

    # Query to count unique chats per day for the user
    c.execute("""
        SELECT DATE(cd.messageTime) AS chat_date, COUNT(DISTINCT ch.chat_id) 
        FROM chat_history ch
        JOIN chat_data cd ON ch.chat_id = cd.chat_id
        WHERE ch.user_id = ? 
        AND cd.messageTime >= datetime('now', '-6 days')
        GROUP BY chat_date
        ORDER BY chat_date ASC
    """, (user_id,))

    for row in c.fetchall():
        chat_date, count = row
        if chat_date in date_counts:
            date_counts[chat_date] = count

    conn.close()

    return jsonify({"dates": list(date_counts.keys()), "counts": list(date_counts.values())})




@app.route('/error')
def error():
    error_code = request.args.get('error', 'Unknown Error')  # Get from query params
    message = request.args.get('message', 'Something went wrong')
    return render_template('error.html', error=error_code, message=message)




def create_new_chat(user_id, title='New Chat'):
    """Create a new chat, reset chat history, and store the new chat ID in session."""
    conn = sqlite3.connect('databases.db')
    c = conn.cursor()
    
    # Insert new chat and get chat ID
    c.execute('''
                INSERT INTO chat_history (user_id, chatNumber, chatTitle)
                VALUES (?, (SELECT COALESCE(MAX(chatNumber), 0) + 1 FROM chat_history WHERE user_id = ?), ?)
              ''', (user_id, user_id, title))
    
    chat_id = c.lastrowid  # Get the ID of the newly created chat
    conn.commit()
    conn.close()

    # Reset session chat history and store the new chat ID
    session['chat_id'] = chat_id

    log_error(200, "User created chat")
    return chat_id, title




def save_chat_message(chat_id, msg, role):
    """Save a message to the chat_data table under the given chat_id."""
    conn = sqlite3.connect('databases.db')
    c = conn.cursor()

    c.execute('''
                INSERT INTO chat_data (chat_id, message, role)
                VALUES (?, ?, ?)
              ''', (chat_id, msg, role))
    
    conn.commit()
    conn.close()




def create_chat_title(chat_id, model, prompt):
    """Create a chat title based on the first message in the chat."""
    conn = sqlite3.connect('databases.db')
    c = conn.cursor()
    c.execute('''
              SELECT chatTitle FROM chat_history WHERE chat_id = ?
              ''', (chat_id,))  
    chat_title = c.fetchone()
    if chat_title[0] == 'New Chat':
        title_prompt = f"Generate a 2-3 word summary of the topic in this promt: {prompt}"
        response = ollama.chat(model=model, messages=[{"role": "user", "content": title_prompt}])
        c.execute("UPDATE chat_history SET chatTitle = ? WHERE chat_id = ?", (response["message"]["content"], chat_id))
    conn.commit()
    conn.close()




def load_chat_history():
    """Load chat history for the current chat_id in the session."""
    chat_id= session.get('chat_id')
    if not session['chat_id']:
        return []  # Return empty list if no chat is selected

           

    conn = sqlite3.connect('databases.db')
    c = conn.cursor()
    c.execute("SELECT message, role, messageTime FROM chat_data WHERE chat_id = ?", (chat_id,))
    chat_history = [{"role": row[1], "content": row[0], "time": row[2]} for row in c.fetchall()]
    
    conn.commit()
    conn.close()
    return chat_history




def admin_all_chats():
    conn = sqlite3.connect("databases.db")
    c = conn.cursor()
    c.execute("""
                    SELECT chat_history.chat_id, users.username, chat_history.chatTitle 
                    FROM chat_history 
                    JOIN users ON chat_history.user_id = users.user_id
                    """)
    chats = c.fetchall()
    conn.close()
    
    # Parse data into JSON format
    return [{"chat_id": row[0], "username": row[1], "chat_title": row[2]} for row in chats]




def log_error(error, message):
    f = open("error.txt", "a")
    f.write(f"{datetime.now()} Error: {error} {message}")
    f.close()




if __name__ == '__main__':
    app.run(debug=True, ssl_context=("cert.pem", "key.pem"), host="0.0.0.0", port=443)
