import sqlite3
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch
from markupsafe import escape
import uuid
from datetime import timedelta
import ollama



app = Flask(__name__)
CORS(app)  # Enable CORS for frontend communication
app.secret_key = 'HelloThereGeneralKenobi'

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
    
def make_session_permanent():
    session.permanent = True



limiter = Limiter(get_remote_address, app=app, default_limits=["20 per minute"])




#Initialise the user database and creates it if it does not exist
def init_user_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
                CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                permission_level INTEGER DEFAULT 0 NOT NULL
               )
                ''')
    conn.commit()
    conn.close()




#Initialise the chat history database and creates it if it does not exist
def init_chathistory_db():
    conn = sqlite3.connect('chat_history.db')
    c = conn.cursor()
    c.execute('''
              CREATE TABLE IF NOT EXISTS chat_history (
              chat_id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id INTEGER NOT NULL,
              chatNumber INTEGER NOT NULL,
              chatTitle TEXT NOT NULL,
              FOREIGN KEY (user_id) REFERENCES users(user_id)
              )
              ''')
    conn.commit()
    conn.close()




def init_chatdata_db():
    conn = sqlite3.connect('chat_data.db')
    c = conn.cursor()
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




init_user_db()
init_chathistory_db()
init_chatdata_db()




@app.route('/')
def index():
    session['Session'] = False
    return render_template('testing.html')




@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
     if request.method == 'POST':
         
         username = escape(request.form.get('username'))
         password = escape(request.form.get('password'))

         if username == '' or password == '':
            return redirect(url_for('login'))
         
         else:
             conn = sqlite3.connect('users.db')
             conn.row_factory = sqlite3.Row
             c = conn.cursor()
             c.execute('''
                    SELECT * from users where username = (?) and password = (?)
                    ''', [username, password])
             userInfo = c.fetchall()

             session.clear()
             session['user_id'] = userInfo[0][0]
             session['username'] = userInfo[0][1]
             session['csrf_token'] = str(uuid.uuid4())
             session['Session'] = True
                      
             conn.commit()
             conn.close()

             conn = sqlite3.connect('chat_history.db')
             c = conn.cursor()
             chatInfo = c.execute('''
                        SELECT * from chat_history where user_id = (?)
                        ''', [session['user_id']]).fetchall()
             conn.commit()
             conn.close()
             return redirect(url_for('index'))
         
     return render_template('login.html')




@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def signup():
     if request.method == 'POST':

        #Gets username and password from the form
        username = escape(request.form.get('username'))
        password = escape(request.form.get('password'))
        
        #Check if the username and password are empty
        if username == '' or password == '':
            return redirect(url_for('signup'))
        else:
            #Connect to the database
            try:
                conn = sqlite3.connect('users.db')
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
                    
                    
                    userInfo = c.execute('''
                                        SELECT * from users where username = (?)
                                        ''', [username]).fetchall()
                    
                    session.clear()
                    session['user_id'] = userInfo[0][0]
                    session['username'] = userInfo[0][1]
                    session['csrf_token'] = str(uuid.uuid4())
                    session['Session'] = True

                    conn.commit()
                    conn.close()
                    return redirect(url_for('index'))
            except:
                return print('Database connection error')
     else:
        return render_template('signup.html')




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
        return jsonify({"error": "Message cannot be empty"}), 400

    model = "llama3.1"  # Replace with your preferred model
    chat_history = load_chat_history()
    chat_history.append({"role": "user", "content": user_input})
      
    
    # Generate chatbot response
    response = ollama.chat(model=model, messages=chat_history)
    bot_message = response["message"]["content"]

    chat_history.append({"role": "assistant", "content": bot_message})

    if session['Session'] == False:
        # Append user message to database
        save_chat_message(session['chat_id'], user_input, 'user')
    
        # Append bot message to database
        save_chat_message(session['chat_id'], bot_message, 'assistant')
    
    return jsonify({"response": bot_message})




@app.route('/new_chat', methods=['POST'])
def new_chat():
    if 'user_id' not in session:
        return jsonify({"error": "User not logged in"}), 401

    new_chat_id, new_chat_title = create_new_chat(session['user_id'])
    print(session['chat_id'])
    return jsonify({"message": "New chat created", "chat_id": new_chat_id, "chat_title": new_chat_title})




@app.route("/load_chat", methods=["GET"])
def load_chat():
    chat_id = request.args.get("chat_id")

    if not chat_id:
        return jsonify({"error": "Chat ID is required"}), 400

    conn = sqlite3.connect('chat_data.db')
    c = conn.cursor()
    c.execute("SELECT message, role FROM chat_data WHERE chat_id = ?", (chat_id,))
    chat_history = [{"role": row[1], "content": row[0]} for row in c.fetchall()]
    conn.close()

    return jsonify({"messages": chat_history})




@app.route('/get_chats', methods=['GET'])
def get_chats():
    """Fetches a list of past chats for the current user."""
    if 'user_id' not in session:
        return jsonify({"error": "User not logged in"}), 401

    conn = sqlite3.connect('chat_history.db')
    c = conn.cursor()
    c.execute("SELECT chat_id, chatTitle FROM chat_history WHERE user_id = ?", (session['user_id'],))
    chats = [{"chat_id": row[0], "title": row[1]} for row in c.fetchall()]
    conn.commit()
    conn.close()

    return jsonify(chats)




def create_new_chat(user_id, title='General'):
    """Create a new chat, reset chat history, and store the new chat ID in session."""
    conn = sqlite3.connect('chat_history.db')
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

    return chat_id, title




def save_chat_message(chat_id, msg, role):
    """Save a message to the chat_data table under the given chat_id."""
    conn = sqlite3.connect('chat_data.db')
    c = conn.cursor()
    c.execute('''
                INSERT INTO chat_data (chat_id, message, role)
                VALUES (?, ?, ?)
              ''', (chat_id, msg, role))
    conn.commit()
    conn.close()




def load_chat_history():
    """Load chat history for the current chat_id in the session."""
    chat_id = session.get('chat_id')
    if not chat_id:
        return []  # Return empty list if no chat is selected

    conn = sqlite3.connect('chat_data.db')
    c = conn.cursor()
    c.execute("SELECT message, role FROM chat_data WHERE chat_id = ?", (chat_id,))
    chat_history = [{"role": row[1], "content": row[0]} for row in c.fetchall()]
    
    conn.commit()
    conn.close()
    return chat_history


 

if __name__ == '__main__':
    app.run(debug=True, ssl_context=("cert.pem", "key.pem"), host="0.0.0.0", port=443)
