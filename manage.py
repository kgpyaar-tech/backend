import json
import os
import re
from datetime import datetime
from logging import getLogger

from logging_config import setup_logger

setup_logger()

import bcrypt
import bson
from cryptography.fernet import Fernet
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt_identity,
    jwt_required,
    verify_jwt_in_request,
)
from mailer import Mailer
from mongoengine import connect
from pymongo import MongoClient
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

from config import *
from fuzzy import return_results
from models import User

app = Flask(__name__)
cors = CORS(app)
jwt = JWTManager(app)

LOG = getLogger(__name__)

DATE_FORMAT = "%d/%m/%Y, %H:%M:%S"

client = MongoClient(MONGODB_URL)
# database
db = client["pyaar"]
# collection
user = db["User"]

connect("pyaar")

# JWT Config
app.config["JWT_SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["JWT_ACCESS_LIFESPAN"] = {"hours": 24}
app.config["JWT_REFRESH_LIFESPAN"] = {"days": 10}
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = False

# GLOBAL Lovenumber hashmap
global_love_number_map = db["global_map"]


@app.route("/")
def home():
    return "Server is On!!!"


@app.route("/register", methods=["POST"])
def handle_register():
    """
    Format of the request json
    {
        "email": <user_email>
    }
    """
    if not request.is_json:
        return jsonify(message="request data is not a json format"), 415

    user_email = request.json["email"].lower()

    # Check if domain of email is iitkgp.ac.in
    pattern = re.compile("/^[a-zA-Z0-9](.?[a-zA-Z0-9_-]){3,}@(kgpian.)?iitkgp.ac.in$/i")
    if not pattern.match(user_email):
        return jsonify(message="email is not valid"), 401

    user_data = db.user.find_one({"email": user_email})

    # Check if user is present in the db, if not return error
    if not user_data:
        roll_number = ""
        year = ""
        department = ""
        email = user_email
        sent_hearts = []
        request_time_window = []
        is_registered = False
        name = ""
        verify_hash = ""
        db.user.insert_one(
            {
                "public_key": "",
                "nickname": "",
                "name": name,
                "email": email,
                "year": year,
                "department": department,
                "sent_hearts": sent_hearts,
                "request_time_window": request_time_window,
                "is_registered": is_registered,
                "verify_hash": verify_hash,
            }
        )

    user_data = db.user.find_one({"email": user_email})
    if user_data["is_registered"]:
        return jsonify(message="You have already registered"), 302

    verify_hash = user_data["verify_hash"]
    if verify_hash == "":
        key = Fernet.generate_key()
        f = Fernet(key)
        verify_hash = f.encrypt(bytes(user_email, "utf-8")).decode()

    verify_link = "{0}/verify/{1}".format(FRONTEND_URL, verify_hash)
    Filter = {"email": user_email}
    new_value = {"$set": {"verify_hash": verify_hash}}
    db.user.update_one(Filter, new_value)

    # body = """
    # <h2> Thanks for registering to KGPyaar! </h2>
    # <p>Verification Link: {0}</p>
    # <p>For issues with registration, contact us at kgpyaar@gmail.com</p>
    # """.format(
    #     verify_link
    # )
    # message = Mail(
    #     from_email=KGPYAAR_EMAIL,
    #     to_emails=alt_email,
    #     subject=subject,
    #     html_content=body,
    # )
    # sg = SendGridAPIClient(SENDGRID_KEY)

    subject = "Verification link for KGPyaar"
    mail = Mailer(email=os.getenv("MAIL_ADDRESS"), password=os.getenv("MAIL_PASSWORD"))
    try:
        mail.send(
            receiver=user_email,
            subject=subject,
            message="Thank you for registering on KGPyaar, please open the following link in your browser: {}".format(
                verify_link
            ),
        )
    except Exception as e:
        LOG.error("/Mail Error: {0}".format(e))
        return jsonify(message="sendgrid issue, please try again later"), 500

    return jsonify(message="verify link successfully sent"), 200


@app.route("/verify/<hash>", methods=["GET"])
def handle_verify(hash):
    user_data = db.user.find_one({"verify_hash": hash})
    if not user_data:
        return jsonify(message="Not found"), 404

    if user_data["is_registered"]:
        return jsonify(message="You have already registered"), 302

    access_token = create_access_token(identity=user_data["email"])
    user_info = dict(
        name=user_data["name"],
        email=user_data["email"],
        year=user_data["year"],
        department=user_data["department"],
        jwt=access_token,
    )
    return json.dumps(user_info, default=str), 200


@app.route("/signup", methods=["POST"])
@jwt_required
def handle_signup():
    """
    Format of the request json
    {
       "password": <password>,
       "nickname": <nickname>,
       "contact_details": <contact_details>,
       "encryptedPrivateKey": <encryptedPrivateKey>,
       "serializedPublicKey": <serializedPublicKey>
    }
    """
    if not request.is_json:
        return jsonify(message="request data is not a json format"), 415

    identity = get_jwt_identity()
    if identity is None:
        return jsonify(message="Auth Token is invalid"), 401

    email = identity
    user_data = db.user.find_one({"email": email})
    if not user_data:
        return jsonify(message="Email not found"), 404

    if user_data["is_registered"]:
        return jsonify(message="User Already Exists"), 409

    password = request.json["password"].encode("utf-8")
    nickname = request.json["nickname"]
    contact_details = request.json["contact_details"]
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password, salt)
    encrypted_private_key = request.json["encryptedPrivateKey"]
    public_key = request.json["serializedPublicKey"]

    Filter = {"email": email}
    new_value = {
        "$set": {
            "nickname": nickname,
            "password": hashed.decode("utf-8"),
            "contact_details": contact_details,
            "is_registered": True,
            "encrypted_private_key": encrypted_private_key,
            "public_key": public_key,
        }
    }
    db.user.update_one(Filter, new_value)
    return jsonify(message="User added sucessfully"), 201


@app.route("/login", methods=["POST"])
def handle_login():
    """
    Format of the request json
    {
        "email" <user_email>,
        "password": <password>
    }
    """
    if not request.is_json:
        return jsonify(message="request data is not a json format"), 415

    email = request.json["email"]
    password = request.json["password"]

    user_data = db.user.find_one({"email": email})
    if not user_data:
        return jsonify(message="Email not found"), 404

    hashed = bcrypt.hashpw(password.encode("utf-8"), user_data["password"].encode("utf-8"))
    if user_data["password"].encode("utf-8") == hashed:
        access_token = create_access_token(identity=email)
        user_info = dict(
            name=user_data["name"],
            nickname=user_data["nickname"],
            email=user_data["email"],
            jwt=access_token,
            contact_details=user_data["contact_details"],
            encryptedPrivateKey=user_data["encrypted_private_key"],
            serializedPublicKey=user_data["public_key"],
        )
        return json.dumps(user_info, default=str), 201

    return jsonify(message="Bad Email or Password"), 401


# @app.route("/forgot_password", methods=["POST"])
# def forgot_password():

#     if not request.is_json:
#         return jsonify(message="request data is not a json format"), 415

#     # Send in a link to reset password


# Add heart count for the sender
# Increase the count of the lovenumber in the global hashmap
@app.route("/add", methods=["POST"])
@jwt_required
def add_heart():
    """
    Format of the request json
    {
        "data" : "<some string>,
        "sha256" : <sha256 stringified>
        "encryptedContactDetails": "<encryptedContactDetails>"
    }
    """
    """
	sent_hearts_data = [ {'encrypted_data' : data, 'sha256' : sha256}, {'encrypted_data' : data, 'sha256' : sha256},]
	"""

    if not request.is_json:
        return jsonify(message="request data is not a json format"), 415

    # Check the identity of the Token
    identity = get_jwt_identity()

    if identity is None:
        return jsonify(message="Auth Token is invalid"), 401

    # Lets add the user's vote!

    req_data = request.json["data"]
    # love_number = request.json["love_number"]

    user_data = db.user.find_one({"email": identity})

    sent_hearts_data = user_data["sent_hearts"]
    sha256 = request.json["sha256"]
    encryptedContactDetails = request.json["encryptedContactDetails"]

    # Check if user has already voted
    # import pdb; pdb.set_trace()
    for data in sent_hearts_data:
        if sha256 == data["sha256"]:
            return jsonify(message="You have already sent heart to this person"), 409

    # Check if user has not exceeded MAX_HEART_COUNT votes
    if len(sent_hearts_data) + 1 > MAX_HEART_COUNT:
        return jsonify(message="You can't send hearts to more than 4 people"), 405

    final_data = {"encrypted_data": req_data, "sha256": sha256}
    # Add in the vote
    sent_hearts_data.append(final_data)

    Filter = {"email": identity}
    new_value = {"$set": {"sent_hearts": sent_hearts_data}}
    db.user.update_one(Filter, new_value)

    try:
        current_enc_contact = user_data["encrypted_contact_details"]
    except:
        current_enc_contact = []
    current_enc_contact.append(encryptedContactDetails)
    new_value = {"$set": {"encrypted_contact_details": current_enc_contact}}
    db.user.update_one(Filter, new_value)

    # Add the love number
    db.global_love_number_map.insert_one({"love_number": sha256})

    return jsonify(message="Heart successfully sent"), 200


# Remove the heart count for the sender
# Decrease the count of the lovenumber in the global hashmap
@app.route("/remove", methods=["POST"])
@jwt_required
def remove_heart():
    """
    Format of the request json
    {
        "sha256" : <sha256 stringified>
    }
    """
    if not request.is_json:
        return jsonify(message="request data is not a json format"), 415

    # Check the identity of the Token
    identity = get_jwt_identity()

    if identity is None:
        return jsonify(message="Auth Token is invalid"), 401

    # Let's remove the user's vote!

    sha256 = request.json["sha256"]

    user_data = db.user.find_one({"email": identity})
    sent_hearts_data = user_data["sent_hearts"]

    # Check if user has voted at least one vote
    if len(sent_hearts_data) == 0:
        return jsonify(message="user has not voted for anyone"), 401

    # Check if the vote is present in the sent_heart
    isPresent = False
    index_to_be_removed = 0
    for index, data in enumerate(sent_hearts_data):
        if data["sha256"] == sha256:
            isPresent = True
            index_to_be_removed = index
            break

    if not isPresent:
        return jsonify(message="User has not voted for the person"), 401

    # Remove the love number
    db.global_love_number_map.delete_one({"love_number": sha256})

    # Remove the vote
    # sent_hearts_data.remove({"encrypted_data": req_data, "sha256": sha256})
    del sent_hearts_data[index_to_be_removed]

    Filter = {"email": identity}
    new_value = {"$set": {"sent_hearts": sent_hearts_data}}

    db.user.update_one(Filter, new_value)

    return jsonify(message="heart successfully removed"), 200


def validate_search(user_data):
    """
    Perform rate limiting of request
    return (True, updated_time_window) if request can be handled, (False, []) otherwise
    """
    # Check if the rate limit hasn't been hit
    if not "request_time_window" in user_data.keys():
        user_data["request_time_window"] = []
    time_window = user_data["request_time_window"]
    time_now = datetime.now()

    if len(time_window) == 0:
        time_window.append(time_now.strftime(DATE_FORMAT))
        return True, time_window

    first_time_access = datetime.strptime(time_window[0], DATE_FORMAT)

    # If the total requests made in the window exceeds the MAX_SEARCH_COUNT
    if len(time_window) + 1 >= MAX_SEARCH_COUNT:
        time_diff = time_now - first_time_access

        # Handle (X - WINDOW_SIZE_TIME) request
        if ((time_diff.seconds // 60)) < WINDOW_SIZE_TIME:
            # the last MAX_SEARCH_COUNT'th request was made in a WINDOW_SIZE_TIME
            # return the user that wait for some time before making another request
            return False, []

        # Case when the diff between the time.Now and last MAX_SEARCH_COUNT'th request >= WINDOW_SIZE_TIME
        while len(time_window) > 0:
            last_time = datetime.strptime(time_window[0], DATE_FORMAT)
            time_diff = time_now - last_time
            if (time_diff.seconds // 60) < WINDOW_SIZE_TIME:
                break
            time_window.pop(0)

    # Add the current request to the window
    time_window.append(time_now.strftime(DATE_FORMAT))
    return True, time_window


@app.route("/search", methods=["POST"])
@jwt_required
def search():
    """
    Return the top MAX_SEARCH_LIMIT search results based on the given input
    Apply rate limit for the user.
    If the rate limit hits the count of MAX_SEARCH_COUNT, return an appropriate message

    request_object -
    {
        "name" : <name>,
        "year" : <year>,
        "department" : <dep>
    }
    """
    if not request.is_json:
        return jsonify(message="request data is not a json format"), 415

    # Check the identity of the Token
    identity = get_jwt_identity()

    # identity = request.json['email']

    if identity is None:
        return jsonify(message="Auth Token is invalid"), 401

    user_data = db.user.find_one({"email": identity})

    # Check if the total count of requests made is within MAX_SEARCH_COUNT for rate limiting
    isPos, new_time_window = validate_search(user_data)
    if not isPos:
        LOG.info(
            "User {0} has reached the count for search on date: {1}".format(
                identity, datetime.now()
            )
        )
        return jsonify(message="max request count has reached, please try sometime later"), 429

    # Update the latest timestamp of the request made
    Filter = {"email": identity}
    new_value = {"$set": {"request_time_window": new_time_window}}
    db.user.update_one(Filter, new_value)

    # Return the search result
    name, department, year = request.json["name"], request.json["department"], request.json["year"]
    if name == "":
        return jsonify(message="name parameter for search is empty"), 400

    if department == "" or year == "":
        department = bson.regex.Regex(".*") if department == "" else department
        year = bson.regex.Regex(".*") if year == "" else year

    # change is registered to True
    Filter = {"department": department, "year": year, "is_registered": True}
    results = list(db.user.find(Filter))

    # fill threshold as much minimum for more results
    fuzzy_results = return_results(results, name)

    if len(fuzzy_results) > MAX_SEARCH_LIMIT:
        fuzzy_results = fuzzy_results[:MAX_SEARCH_LIMIT]

    output = list()
    for entry in fuzzy_results:
        output.append(
            dict(
                nickname=entry["nickname"],
                public_key=entry["public_key"],
                year=entry["year"],
                department=entry["department"],
                name=entry["name"],
            )
        )

    return jsonify(output), 200


@app.route("/get_freq", methods=["POST"])
@jwt_required
def get_frequency_heart():
    """
    Get the frequency of the love number provided.
    The function would return the count of the data
    This is secure because, we don't track the JWT
    of the user
    {
        "sha256": <sha256>
    }
    """
    return jsonify(message="Thambha"), 200
    # if not request.is_json:
    #     return jsonify(message="request data is not a json format"), 415

    # # Check the identity of the Token
    # identity = get_jwt_identity()
    # if identity is None:
    #     return jsonify(message="Auth Token is invalid"), 401

    # user_data = db.user.find_one({"email": identity})
    # sent_hearts = user_data["sent_hearts"]
    # sha256 = request.json["sha256"]
    # # check by SHA256 of love_number that the user is requesting freq of only his sent hearts
    # for heart in sent_hearts:
    #     if sha256 == heart["sha256"]:
    #         count = db.global_love_number_map.find({"love_number": sha256}).count()
    #         return jsonify(frequency=count), 200
    # return jsonify(message="It seems you are sending the wrong data"), 401


@app.route("/get_sent_hearts")
@jwt_required
def get_sent_hearts():
    identity = get_jwt_identity()

    if identity is None:
        return jsonify(message="Auth Token is invalid"), 401

    user_data = db.user.find_one({"email": identity})
    heart_sent_list = user_data["sent_hearts"]

    return jsonify(heart_sent_list), 200


@app.route("/enc_contact", methods=["POST"])
@jwt_required
def get_crush_contact():
    """
    {
        "public_key": <public_key_of_crush>
        "sha256": <sha256 of the love_number>
    }
    """
    return jsonify(message="Thambha"), 200
    # identity = get_jwt_identity()

    # if identity is None:
    #     return jsonify(message="Auth Token is invalid"), 401

    # public_key = request.json["public_key"]
    # sha256 = request.json["sha256"]

    # user_data = db.user.find_one({"email": identity})
    # isPresent = False
    # for data in user_data["sent_hearts"]:
    #     if data["sha256"] == sha256:
    #         isPresent = True
    #         break

    # if not isPresent:
    #     return jsonify(message="User has not voted for the person"), 401

    # crush = db.user.find_one({"public_key": public_key})
    # try:
    #     encryptedContact = crush["encrypted_contact_details"]
    # except:
    #     encryptedContact = []

    # return jsonify(encryptedContact=encryptedContact), 200


if __name__ == "__main__":
    app.run(URL, port=PORT, debug=True)
