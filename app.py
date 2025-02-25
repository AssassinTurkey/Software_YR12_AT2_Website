import sqlite3
from flask import Flask, render_template, request, jsonify, redirect, url_for
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch

#Setting up the model, tokeniser, global variables and Flask app
tokenizer = AutoTokenizer.from_pretrained("microsoft/DialoGPT-medium")
model = AutoModelForCausalLM.from_pretrained("microsoft/DialoGPT-medium")

userInfo = {}


app = Flask(__name__)


#Initialise the user database and creates it if it does not exist
def init_user_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
                CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER AUTO_INCREMENT PRIMARY KEY,
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
              chat_id INTEGER AUTO_INCREMENT PRIMARY KEY,
              user_id INTEGER NOT NULL,
              message TEXT NOT NULL,
              chatNumber INTEGER NOT NULL,
              chatTitle TEXT NOT NULL,
              messageTime TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
              FOREIGN KEY (user_id) REFERENCES users(user_id)
              )
              ''')
    conn.commit()
    conn.close()


init_user_db()
init_chathistory_db()


@app.route('/')
def index():
    return render_template('chat.html')


@app.route('/get', methods=['GET', 'POST'])
def chat():
    msg = request.form['msg']
    input = msg
    return get_Chat_respone(input)



@app.route('/login', methods=['GET', 'POST'])
def login():
     #if request.method == 'POST':
         

     return render_template('login.html')



@app.route('/signup', methods=['GET', 'POST'])
def signup():
     if request.method == 'POST':

        #Gets username and password from the form
        username = request.form.get('username')
        password = request.form.get('password')

        #Check if the username and password are empty
        if username == '' or password == '':
            return redirect(url_for('signup'))
        
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
                c.execute('''
                            INSERT INTO users (username, password)
                            VALUES (?, ?)
                        ''', (username, password))
                
                userInfo = c.execute('''
                                    SELECT * from users where username = (?)
                                    ''', [username]).fetchall()
        except:
            return print('Database connection error')
        
        finally:

            #Commit the changes and close the connection
            conn.commit()
            conn.close()

            return redirect(url_for('index'))
     else:
        return render_template('signup.html')






def get_Chat_respone(text):
    # encode the new user input, add the eos_token and return a tensor in Pytorch
    noOfMessages = 0
    new_user_input_ids = tokenizer.encode(str(text) + tokenizer.eos_token, return_tensors='pt')

    # append the new user input tokens to the chat history
    bot_input_ids = torch.cat([chat_history_ids, new_user_input_ids], dim=-1) if noOfMessages > 0 else new_user_input_ids

    # generated a response while limiting the total chat history to 1000 tokens, 
    chat_history_ids = model.generate(bot_input_ids, max_length=1000, pad_token_id=tokenizer.eos_token_id)

    noOfMessages += 1

    print(userInfo)


    #conn = sqlite3.connect('chat_history.db')
    #c = conn.cursor()
    #c.execute('''
    #            INSERT INTO chat_history (user_id, message, chatNumber, chatTitle)
    #            VALUES (?, ?, ?, ?)
    #            ''', (1, text, 1, 'General'))

    return tokenizer.decode(chat_history_ids[:, bot_input_ids.shape[-1]:][0], skip_special_tokens=True)
    

if __name__ == '__main__':
    app.run(debug=True)
    #get_Chat_respone()
