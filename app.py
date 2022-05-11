# flask imports
from flask import Flask, jsonify, make_response, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import uuid
# imports for PyJWT authentication
import jwt
import datetime
from functools import wraps

# from flask_jwt_extended import unset_jwt_cookies


app = Flask(__name__)
 
app.config['SECRET_KEY']='97782032435c3a4f964235adb305c268'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///bookstore.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
 
db = SQLAlchemy(app)


# Database ORMs
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.Integer)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)


class Books(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(50), unique=True, nullable=False)
    Author = db.Column(db.String(50), unique=True, nullable=False)
    Publisher = db.Column(db.String(50), nullable=False)
    book_prize = db.Column(db.Integer)


# decorator for verifying the JWT
def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message': 'a valid token is missing'}), 401
        try:
            # decoding the payload to fetch the stored 
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Users.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'token is invalid'}), 401
        # returns the current logged in users contex to the routes
        return f(current_user, *args, **kwargs)
    return decorator


# signup route
@app.route('/register', methods=['POST'])
def signup_user(): 
    # creates a dictionary of the form data
    #  data = request.form
    data = request.get_json()     
    
    # checking for existing user
    user = Users.query.filter_by(name = data['name']).first()
    if not user:
        # database ORM object
        hashed_password = generate_password_hash(data['password'], method='sha256')
        new_user = Users(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
        # insert user
        db.session.add(new_user) 
        db.session.commit()   
        return jsonify({'message': 'registered successfully'}), 201
    else:
        # returns 202 if user already exists
        # return make_response('User already exists. Please Log in.', 202)
        return jsonify({'message': 'User already exists. Please Log in.'}), 202


# route for logging user in
@app.route('/login', methods=['POST']) 
def login_user():
    # creates dictionary of form data
    auth = request.authorization 
    if not auth or not auth.username or not auth.password: 
        # returns 401 if any username or / and password is missing
        return make_response('could not verify', 401, {'Authentication': 'login required"'})   
    # user = User.query.filter_by(name = auth.get('username')).first()
    user = Users.query.filter_by(name=auth.username).first() 
    if not user:
        # returns 401 if user does not exist
        return make_response(
            'could not verify',
            401,
            {'Authentication': 'login required"'}
        ) 
    # if check_password_hash(user.password, auth.get('password')):
    if check_password_hash(user.password, auth.password):
        # generates the JWT Token
        token = jwt.encode({
            'public_id' : user.public_id, 
            'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=45)
            }, app.config['SECRET_KEY'], "HS256") 
        # return jsonify({'token' : token}), 201
        response = make_response(jsonify({'token' : token}))
        response.set_cookie('token', token, httponly=True)
        return response, 201
    # returns 403/401 if password is wrong
    return make_response('could not verify',  401, {'Authentication': '"login required"'})


# User Database Route
# this route sends back list of users users
@app.route('/users', methods=['GET'])
@token_required
def get_all_users(current_user): 
    # querying the database
    # for all the entries in it 
    users = Users.query.all()
    print(users)
    # converting the query objects
    # to list of jsons
    result = []  
    for user in users: 
        # appending the user data json
        # to the response list 

        # result.append({
        #     'public_id': user.public_id,
        #     'name' : user.name,
        #     'password' : user.password,
        #     'admin' : user.admin,
        # })

        user_data = {}  
        user_data['public_id'] = user.public_id 
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        
        result.append(user_data)  
    return jsonify({'users': result})


@app.route('/book', methods=['POST'])
@token_required
def create_book(current_user):
 
    data = request.get_json()
    
    new_books = Books(name=data['name'], Author=data['Author'], Publisher=data['Publisher'], book_prize=data['book_prize'], user_id=current_user.id) 
    db.session.add(new_books)  
    db.session.commit() 
    return jsonify({'message' : 'new books created'})


@app.route('/books', methods=['GET'])
@token_required
def get_books(current_user):
 
    books = Books.query.filter_by(user_id=current_user.id).all()
    output = []
    for book in books:
        book_data = {}
        book_data['id'] = book.id
        book_data['name'] = book.name
        book_data['Author'] = book.Author
        book_data['Publisher'] = book.Publisher
        book_data['book_prize'] = book.book_prize
        output.append(book_data)
 
    return jsonify({'list_of_books' : output})


@app.route('/books/<book_id>', methods=['DELETE'])
@token_required
def delete_book(current_user, book_id): 
 
    book = Books.query.filter_by(id=book_id, user_id=current_user.id).first()  
    if not book:  
        return jsonify({'message': 'book does not exist'})  
    
    db.session.delete(book) 
    db.session.commit()  
    return jsonify({'message': 'Book deleted'})
 

@app.route('/logout', methods=['POST'])
def logout():
    resp = jsonify({'logout': True})
    resp.delete_cookie('token')
    return resp, 200


if  __name__ == '__main__': 
    app.run(debug=True)

    