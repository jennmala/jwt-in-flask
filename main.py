from flask import Flask, jsonify, request, make_response
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt, set_access_cookies, set_refresh_cookies, unset_jwt_cookies, create_refresh_token, get_current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone


app = Flask(__name__)

# for sqlalchemy
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///bookstore.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True 
db = SQLAlchemy(app)

app.config['JWT_SECRET_KEY']='97782032435c3a4f964235adb305c268'
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(seconds=20)
app.config['JWT_COOKIE_CSRF_PROTECT'] = False # SET TRUE IN PRODUCTION (and handle in frontend)
# app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(hours=8)

jwt = JWTManager(app)


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

class TokenBlocklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True)
    type = db.Column(db.String(16), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), default=lambda: get_current_user().id, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(), nullable=False,)



@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    user = Users.query.filter_by(name=username).first() 
    if not user:
        return make_response('could not verify', 401, {'Authentication': 'login required"'} ) 

    if not check_password_hash(user.password, password):
        return jsonify("Wrong password"), 401

    additional_claims = {"isAdmin": user.admin}
    access_token = create_access_token(identity=username, additional_claims=additional_claims)
    # refresh_token = create_refresh_token(identity=username)
    response = jsonify({"msg": "login successful"})
    set_access_cookies(response, access_token)
    # set_refresh_cookies(response, refresh_token)

    return response, 200

# Using refresh tokens is our recommended approach when your frontend is not a website (mobile, api only, etc).
# @app.route("/refresh", methods=["POST"])
# @jwt_required(refresh=True)
# def refresh():
#     identity = get_jwt_identity()
#     access_token = create_access_token(identity=identity)
#     return jsonify(access_token=access_token)


@app.route("/logout", methods=["POST"])
@jwt_required(verify_type=False)
def logout():
    token = get_jwt()
    # if token["jti"]:
        # jti = token["jti"]
        # ttype = token["type"]
        # now = datetime.now(timezone.utc)
        # db.session.add(TokenBlocklist(jti=jti, type=ttype, created_at=now))
        # db.session.commit()
    response = jsonify({"msg": "logout successful, token successfully revoked"})
    # unset_jwt_cookies(response)
    return response, 200

@app.after_request
def refresh_expiring_jwts(response):
    try:
        exp_timestamp = get_jwt()["exp"]
        now = datetime.now(timezone.utc)
        target_timestamp = datetime.timestamp(now + timedelta(seconds=10))
        if target_timestamp > exp_timestamp:
            access_token = create_access_token(identity=get_jwt_identity())
            set_access_cookies(response, access_token)
        return response
    except (RuntimeError, KeyError):
        # Case where there is not a valid JWT. Just return the original response
        return response


@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload: dict) -> bool:
    jti = jwt_payload["jti"]
    token = db.session.query(TokenBlocklist.id).filter_by(jti=jti).scalar()

    return token is not None




@app.route("/books", methods=["GET"])
@jwt_required()
def get_books():
    current_user = get_jwt_identity()
    books = Books.query.all()
    output = []
    for book in books:
        book_data = {}
        book_data['id'] = book.id
        book_data['name'] = book.name
        book_data['Author'] = book.Author
        book_data['Publisher'] = book.Publisher
        book_data['book_prize'] = book.book_prize
        output.append(book_data)
 
    return jsonify({'list_of_books' : output, 'logged_in_as' : current_user}), 200


@app.route('/book', methods=['POST'])
@jwt_required()
def create_book():
    current_user = get_jwt_identity() 
    user = Users.query.filter_by(name=current_user).first()
    claims = get_jwt()
    admin = claims['isAdmin']
    if admin:
        data = request.get_json()    
        new_books = Books(name=data['name'], Author=data['Author'], Publisher=data['Publisher'], book_prize=data['book_prize'], user_id=user.id) 
        db.session.add(new_books)  
        db.session.commit() 
        return jsonify({'message' : 'new books created'}), 200
    return jsonify("Admin role required"), 403


@app.route('/books/<book_id>', methods=['DELETE'])
@jwt_required()
def delete_book(book_id):  
    current_user = get_jwt_identity()
    user = Users.query.filter_by(name=current_user).first()
    claims = get_jwt()
    admin = claims['isAdmin']
    if admin:
        book = Books.query.filter_by(id=book_id, user_id=user.id).first()  
        if not book:  
            return jsonify({'message': 'book does not exist'})          
        db.session.delete(book) 
        db.session.commit()  
        return jsonify({'message': 'Book deleted'})
    return jsonify("Admin role required"), 403


if __name__ == "__main__":
    app.run()

