from flask import Flask, render_template, request, redirect
app = Flask(__name__)

ELECTIVES = ["comp sci", "math", "history", "art"]

elective_dict = {}

@app.route("/")
def index():
    return render_template('index.html', electives=ELECTIVES)

@app.route('/register', methods=['POST'])
def register():
    name = request.form.get('name')
    elective = request.form.get('electives')
    if not request.form.get('name') or not request.form.get('electives'):
        render_template('failure.html', message = "Please fill out all fields")
    
    elective_dict[name] = elective

    return render_template('success.html', name=name, elective=elective)

    #return redirect('/registerants')


'''@app.route('/registerants')
def registerants():
    return render_template('success.html', name=name, elective=elective)'''