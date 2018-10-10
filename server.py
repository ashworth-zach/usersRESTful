from flask import Flask, redirect, render_template, request, flash, session
import pymysql.cursors
import datetime
import re
from flask_bcrypt import Bcrypt        

# import the function connectToMySQL from the file mysqlconnection.py
from mysqlconnection import connectToMySQL
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
mysql = connectToMySQL("registrationdb")

app = Flask(__name__)
app.secret_key = "ThisIsSecret!"
bcrypt = Bcrypt(app)
@app.route('/',methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    query='select email from users where email = %(email)s'
    data={
        'email': request.form['email']
    }
    checkvalid=mysql.query_db(query,data)
    print(checkvalid)
    if len(checkvalid)>0:
        flash('this email is already taken', 'erroremail')
        return redirect('/')
    if len(request.form['email']) < 1:
        flash("Email cannot be blank!", 'erroremail')
    if not EMAIL_REGEX.match(request.form['email']):
        flash("Invalid Email Address!", 'erroremail')
        return redirect('/')
    if len(request.form['firstname']) < 1:
        flash("name cannot be blank!", 'errorfirstname')
        return redirect('/')
    if request.form['firstname'].isalpha()==False:
        flash("name cannot be contain numbers", 'errorfirstname')
        return redirect('/')
    if request.form['lastname'].isalpha()==False:
        flash("name cannot be contain numbers", 'errorlastname')
        return redirect('/')
    if len(request.form['lastname']) < 1:
        flash("last name cannot be blank!",'errorlastname')
        return redirect('/')
    if len(request.form['password']) < 8:
        flash("password must be at least 8 characters",'errorpassword')
        return redirect('/')
    if request.form['passwordconf'] != request.form['password']:
        flash("passwords do not match",'errorpasswordconf')
        return redirect('/')
    elif len(request.form['email'])>1 and EMAIL_REGEX.match(request.form['email']) and len(request.form['firstname']) > 1 and len(request.form['lastname']) > 1 and len(request.form['password']) >= 8 and request.form['passwordconf'] == request.form['password']:
        pw_hash = bcrypt.generate_password_hash(request.form['password']) 
        query='INSERT INTO users(firstname,lastname,email,userlevel,password,created_at,updated_at) VALUES(%(firstname)s,%(lastname)s,%(email)s,0,%(password)s,now(),now())'
        data={
            'firstname': request.form['firstname'],
            'lastname': request.form['lastname'],
            'email': request.form['email'],
            'password': pw_hash
        }
        mysql.query_db(query,data)
        session['level']=0
        return render_template('/result.html')
    return redirect('/')
@app.route('/login', methods=['POST'])
def login():
    query='select email,password,userlevel from users where email = %(email)s'
    data={
        'email': request.form['email']
    }
    checkvalid=mysql.query_db(query,data)
    if len(checkvalid)>0:
        flash('this email exists','erroremaillogin')
    elif len(checkvalid)==0:
        flash('this email doesnt exist','erroremaillogin')
        return redirect('/')
    if bcrypt.check_password_hash(checkvalid[0]['password'], request.form['password']) != True:
        flash('wrong password',"errorpasswordlogin")
        return redirect('/')
    if len(checkvalid)>0 and checkvalid[0]['userlevel']==0 and bcrypt.check_password_hash(checkvalid[0]['password'], request.form['password']) == True:
        session['level']=0
        return redirect('/user')
    elif len(checkvalid)>0 and checkvalid[0]['userlevel']==1 and bcrypt.check_password_hash(checkvalid[0]['password'], request.form['password']) == True:
        session['level']=1
        return redirect('/admin')
    return redirect('/')
@app.route('/user')
def show():
    if 'level' not in session:
        return redirect('/danger')
    return render_template('result.html')
@app.route('/admin')
def adminpage():
    if 'level' not in session:
        return redirect('/danger')
    if session['level']==0:
        return redirect('/danger')
    allusers=mysql.query_db('select firstname,email,id,created_at,userlevel from users')
    return render_template('admin.html', allusers=allusers)
@app.route('/delete', methods=['POST'])
def delete():
    if 'level' not in session:
        return redirect('/danger')
    if session['level']==0:
        return redirect('/danger')
    id = int(request.form['hidden'])
    query = "DELETE FROM users WHERE id = {}".format(id)
    mysql.query_db(query)
    return redirect('/admin')
@app.route('/removeadmin', methods=['POST'])
def removeadmin():
    if 'level' not in session:
        return redirect('/danger')
    if session['level']==0:
        return redirect('/danger')
    data={
        'id':request.form['hiddenadmin']
    }
    mysql.query_db('update users set userlevel=0 where id=%(id)s',data)
    return redirect('/admin')
@app.route('/makeadmin', methods=['POST'])
def addadmin():
    if 'level' not in session:
        return redirect('/danger')
    if session['level']==0:
        return redirect('/danger')
    data={
        'id':request.form['hiddenadmin']
    }
    mysql.query_db('update users set userlevel=1 where id=%(id)s',data)
    return redirect('/admin')
@app.route('/danger')
def danger():
    return render_template('danger.html')
if __name__ == "__main__":
    app.run(debug=True)