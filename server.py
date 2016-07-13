from flask import Flask, render_template, redirect, request, session, flash
from mysqlconnection import MySQLConnector
from flask_bcrypt import Bcrypt
import re
import os, binascii
from datetime import datetime


app = Flask(__name__)
app.secret_key = binascii.b2a_hex(os.urandom(15))
mysql = MySQLConnector(app, 'the_wall')
bcrypt = Bcrypt(app)

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')


# this route is for the main Wall page
@app.route('/')
def index():
	if 'id' not in session:
		return redirect('/sign_in')
	#get current user's info
	user_query = "SELECT first_name, last_name FROM users WHERE id = :id"
	data = {'id': session['id']}
	user = mysql.query_db(user_query, data)
	#get all messages
	messages_query = ("SELECT message, messages.id, messages.created_at, users.id as user_id, first_name, last_name " +
					"FROM messages LEFT JOIN " +
					"users ON messages.user_id = users.id " +
					"ORDER BY messages.created_at DESC")
	messages = mysql.query_db(messages_query)
	#get all comments
	comments_query = ("SELECT comment, comments.created_at, comments.id as comment_id, comments.message_id, users.id as user_id, first_name, last_name " +
					"FROM messages JOIN " +
					"comments ON messages.id = comments.message_id " +
					"JOIN " +
					"users ON comments.user_id = users.id " +
					"ORDER BY comments.created_at ASC")
	comments = mysql.query_db(comments_query)
	return render_template('index.html', user = user[0], posts = messages, comments = comments)

#this route directs the user to a sign-in/register page
@app.route('/sign_in')
def signin():
	return render_template('login.html')

#this route logs off the user, clears session
@app.route('/logoff')
def logoff():
	session.clear()
	return redirect('/')


#this route handles the login process
@app.route('/login', methods = ['POST'])
def login():
	email = request.form['email']
	password = request.form['password']
	contains_query = 'SELECT * FROM users WHERE email = :email'
	data = {'email': email}
	user = mysql.query_db(contains_query, data)
	if len(user) == 0:
		flash("That email address is not registered.", 'login')
		return redirect('/sign_in')
	elif not bcrypt.check_password_hash(user[0]['password'], password):
		flash("Incorrect password.", 'login')
		return redirect('/sign_in')
	else:
		session['id'] = user[0]['id']
		return redirect('/')


#this route handles registration process
@app.route('/register', methods = ['POST'])
def register():
	#get data from form
	first_name = request.form['first_name']
	last_name = request.form['last_name']
	email = request.form['email']
	password = request.form['password']
	confirm_password = request.form['confirm_password']
	#perform validations
	valid = True
	if len(first_name) < 2 or len(last_name) < 2:
		flash('Name fields must contain at least 2 letters.', 'register')
		valid = False
	if not first_name.isalpha() or not last_name.isalpha():
		flash('Name fields can only contain letters.', 'register')
		valid = False
	if not EMAIL_REGEX.match(email):
		flash("Invalid email address.", 'register')
		valid = False
	contains_query = 'SELECT id FROM users WHERE email = :email'
	data = {'email': email}
	has_email = mysql.query_db(contains_query, data)
	if len(has_email) > 0:
		flash("That email is already registered to a user.", 'register')
		valid = False
	if len(password) < 8:
		flash("Password must contain at least 8 characters.", 'register')
		valid = False
	if not re.compile(r'\d').search(password) or not re.compile(r'[A-Z]').search(password):
		flash("Password must contain at least one number and one uppercase letter.", 'register')
		valid = False
	if password != confirm_password:
		flash("Password must match confirmation password", 'register')
		valid = False

	if not valid:
		return redirect('/sign_in')
	else:
		#add to database
		add_query = ("INSERT INTO users " +
					"(first_name, last_name, email, password, created_at, updated_at) " +
					"VALUES (:first_name, :last_name, :email, :password, NOW(), NOW())")
		data = {'first_name': first_name, 'last_name': last_name, 'email': email, 'password': bcrypt.generate_password_hash(password)}
		mysql.query_db(add_query, data)
		#get user id to put in session
		query = "SELECT id FROM users WHERE email = :email"
		data = {'email': email}
		user = mysql.query_db(query, data)
		session['id'] = user[0]['id']
		return redirect('/')


#this route handles message generation
@app.route('/message', methods = ['POST'])
def message():
	message = request.form['message']
	add_query = ("INSERT INTO messages " +
				"(message, created_at, updated_at, user_id) " +
				"VALUES (:message, NOW(), NOW(), :user_id)")
	data = {'message': message, 'user_id': session['id']}
	mysql.query_db(add_query, data)
	return redirect('/')

#this route handles comment generation
@app.route('/comment/<post_id>', methods = ['POST'])
def comment(post_id):
	comment = request.form['comment']
	add_query = ("INSERT INTO comments " +
				"(comment, created_at, updated_at, message_id, user_id) " +
				"VALUES (:comment, NOW(), NOW(), :message_id, :user_id)")
	data = {'comment': comment, 'message_id': post_id, 'user_id': session['id']}
	mysql.query_db(add_query, data)
	return redirect('/')

#this route handles message deletion
@app.route('/delete/<message_id>')
def delete(message_id):
	delete_query = "DELETE FROM messages WHERE id = :message_id"
	delete_query2 = "DELETE FROM comments WHERE message_id = :message_id"
	data = {'message_id': message_id}
	mysql.query_db(delete_query2, data)
	mysql.query_db(delete_query, data)
	return redirect('/')

#this route handles comment deletion
@app.route('/delete/comment/<comment_id>')
def delete_comment(comment_id):
	delete_query = "DELETE FROM comments WHERE id = :comment_id"
	data = {'comment_id': comment_id}
	mysql.query_db(delete_query, data)
	return redirect('/')


app.run(debug = True)