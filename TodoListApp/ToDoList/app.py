from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

PRIOTITY = ['High', 'Medium', 'Low']

@app.route('/')
def index():
    return render_template('index.html', priorities=PRIOTITY)