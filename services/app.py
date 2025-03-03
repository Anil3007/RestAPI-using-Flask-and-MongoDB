from dotenv import load_dotenv
import os
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson import ObjectId

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
jwt_secret = os.getenv("JWT_SECRET_KEY")


app = Flask(__name__)

client = MongoClient(MONGO_URI)
db = client['user_templates']
users_collection = db['users']
templates_collection = db['templates']

app.config['JWT_SECRET_KEY'] = jwt_secret
jwt = JWTManager(app)


def object_id_to_str(obj):
    return str(obj['_id'])

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    if users_collection.find_one({"email": data['email']}):
        return jsonify({"message": "User already exists"}), 400

    hashed_password = generate_password_hash(data['password'], method='sha256')

    user = {
        'first_name': data['first_name'],
        'last_name': data['last_name'],
        'email': data['email'],
        'password': hashed_password
    }

    users_collection.insert_one(user)
    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    user = users_collection.find_one({"email": data['email']})
    
    if not user or not check_password_hash(user['password'], data['password']):
        return jsonify({"message": "Invalid email or password"}), 401

    access_token = create_access_token(identity=str(user['_id']))
    return jsonify({"access_token": access_token}), 200


@app.route('/template', methods=['POST'])
@jwt_required()
def create_template():
    current_user_id = get_jwt_identity()
    data = request.get_json()

    template = {
        'template_name': data['template_name'],
        'subject': data['subject'],
        'body': data['body'],
        'user_id': current_user_id
    }

    templates_collection.insert_one(template)
    return jsonify({"message": "Template created successfully"}), 201

@app.route('/template', methods=['GET'])
@jwt_required()
def get_all_templates():
    current_user_id = get_jwt_identity()

    templates = templates_collection.find({"user_id": current_user_id})
    templates_list = [{"template_name": template['template_name'], "subject": template['subject'], "body": template['body'], "template_id": object_id_to_str(template)} for template in templates]

    return jsonify(templates_list), 200

@app.route('/template/<template_id>', methods=['GET'])
@jwt_required()
def get_template(template_id):
    current_user_id = get_jwt_identity()

    template = templates_collection.find_one({"_id": ObjectId(template_id), "user_id": current_user_id})
    if not template:
        return jsonify({"message": "Template not found"}), 404

    return jsonify({
        "template_name": template['template_name'],
        "subject": template['subject'],
        "body": template['body']
    }), 200

@app.route('/template/<template_id>', methods=['PUT'])
@jwt_required()
def update_template(template_id):
    current_user_id = get_jwt_identity()
    data = request.get_json()

    template = templates_collection.find_one({"_id": ObjectId(template_id), "user_id": current_user_id})
    if not template:
        return jsonify({"message": "Template not found"}), 404

    templates_collection.update_one(
        {"_id": ObjectId(template_id), "user_id": current_user_id},
        {"$set": {
            'template_name': data['template_name'],
            'subject': data['subject'],
            'body': data['body']
        }}
    )
    return jsonify({"message": "Template updated successfully"}), 200

@app.route('/template/<template_id>', methods=['DELETE'])
@jwt_required()
def delete_template(template_id):
    current_user_id = get_jwt_identity()

    template = templates_collection.find_one({"_id": ObjectId(template_id), "user_id": current_user_id})
    if not template:
        return jsonify({"message": "Template not found"}), 404

    templates_collection.delete_one({"_id": ObjectId(template_id), "user_id": current_user_id})
    return jsonify({"message": "Template deleted successfully"}), 200

if __name__ == '__main__':
    app.run('localhost',5000)
