import os
import configparser

from flask import Flask, render_template
from flask.json import JSONEncoder
from flask_cors import CORS
from flask_pymongo import PyMongo
from pushjack_http2 import APNSSandboxClient
from apns2.client import APNsClient
from apns2.payload import Payload

from pymongo import GEO2D
import random, string
##from flask_bcrypt import Bcrypt
##from flask_jwt_extended import JWTManager

from bson import json_util, ObjectId
from bson.binary import Binary
from datetime import datetime, timedelta

from flask_socketio import SocketIO

socketio = SocketIO()


class MongoJsonEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime("%Y-%m-%d %H:%M:%S")
        if isinstance(obj, ObjectId):
            return str(obj)
        return json_util.default(obj, json_util.CANONICAL_JSON_OPTIONS)

    
import eventlet
eventlet.monkey_patch()
#def create_app():
#
##    APP_DIR = os.path.abspath(os.path.dirname(__file__))
#    #STATIC_FOLDER = os.path.join(APP_DIR, 'build/static')
#    #TEMPLATE_FOLDER = os.path.join(APP_DIR, 'build')
#
#
#
#    return app
    
import functools
from werkzeug.local import LocalProxy

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for, jsonify
)
from werkzeug.security import check_password_hash, generate_password_hash

from datetime import datetime

from flask_login import logout_user, login_required, login_user, current_user
from flask import current_app, g

def get_db():
    """
    Configuration method to return db instance
    """
    #db = getattr(g, "_database", None)

    #if db is None:

    db = PyMongo(current_app).db
       
    return db
    
bp = Blueprint('auth', __name__, url_prefix='/auth')
db = LocalProxy(get_db)

@bp.route('/')
def index():
    if 'email' in session:
        return 'You are logged in as ' + session['email']
    return 'You are not loggged in.'

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
    
        content = request.json
        email = content['upEmail']
        password = content['upPassword']
        now = datetime.now()

#        db = get_db()
        error = None


        if not email:
            error = 'Email is required.'
        elif not password:
            error = 'Password is required.'

        existing_user = db.acc_users.find_one({"email":email},{})
        if existing_user is None:
            if error is None:
                try:
                    user_doc = {'on_duty': False, 'first_name': "", 'last_name':"", 'gender':"", 'picture_url':"", 'phone':"", 'email' : email, 'password' : generate_password_hash(password), 'activation_code':"", 'secret_code':"", 'last_location': {'plus_code': "", 'timestamp': now}, 'is_premium': False, 'guardian_mode': False, 'citizen_dispatch': False, 'linked_accounts': False, 'user_groups': [], 'client_score': 0, 'responder_score': 0, 'is_active': True, 'is_deleted': False, 'date_created': now, 'date_modified': now}
                    db.acc_users.insert_one(user_doc),
                except db.IntegrityError:
                    error = f"User {email} is already registered."
                else:
                    return redirect(url_for("auth.login"))

            flash(error)
        return "That email is already used."
    return "User wes created"

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
    
        content = request.json
        email = content['email']
        password = content['password']
        
        print(email)
#        db = get_db()
        error = None
        user = db.acc_users.find_one({"email":email})

        if user is None:
            error = 'Incorrect email.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            #login_user(user)
            session.clear()
            session['user_id'] = user['_id']
            session.permanent = True
            return jsonify(user)

        flash(error)

    return "User was logged in"

@bp.before_app_request
def load_logged_in_user():

#    db = get_db()
    
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = db.acc_users.find_one({"_id":user_id},{})

@bp.route('/logout')
#@login_required
def logout():
    session.clear()
    #logout_user
    return redirect(url_for('auth.login'))

import bson

from pymongo.errors import DuplicateKeyError, OperationFailure
from bson.objectid import ObjectId
from bson.errors import InvalidId




# Use LocalProxy to read the global db instance with just `db`


def get_users():
    try:
        return list(db.acc_users.find())
    except Exception as e:
        return e

def get_agents():
    try:
        return list(db.pro_agents.find())
    except Exception as e:
        return e

def get_agents_info():
    try:
        return list(db.acc_users.find({"agent_id": {"$exists": 'true'}}))
    except Exception as e:
        return e
        
def get_crews():
    try:
        return list(db.pro_crews.find())
    except Exception as e:
        return e

def get_agencies():
    try:
        return list(db.pro_agencies.find())
    except Exception as e:
        return e

def get_emergencies():
    try:
        return list(db.sos_emergencies.find())
    except Exception as e:
        return e
        
def get_active_emergencies(id):
    rejected_emergencies = list(db.pro_agents.find({"_id": id, "requests.accepted": False}))
    
    try:
        return list(db.sos_emergencies.find({
                "_id": {"$nin": rejected_emergencies},
                "is_premium":  True,
                "is_accepted": False,
                "is_closed": False,
                "assigned_responders": { "$elemMatch": { "id": id } }
                }
            ))
    except Exception as e:
        return e

        
def get_agents_by_agency(agencies):
    """
    Finds and returns movies by country.
    Returns a list of dictionaries, each dictionary contains a title and an _id.
    """
    try:

        """
        Ticket: Projection
        Write a query that matches movies with the countries in the "countries"
        list, but only returns the title and _id of each movie.
        Remember that in MongoDB, the $in operator can be used with a list to
        match one or more values of a specific field.
        """

        # Find movies matching the "countries" list, but only return the title
        # and _id. Do not include a limit in your own implementation, it is
        # included here to avoid sending 46000 documents down the wire.
        print(f" c: {agencies}")
        return list(db.pro_agents.find({},{"agency" : 1}))

    except Exception as e:
        return e

def get_user(id):
    """
    Given a movie ID, return a movie with that ID, with the comments for that
    movie embedded in the movie document. The comments are joined from the
    comments collection using expressive $lookup.
    """
    try:
        pipeline = [
            {
                "$match": {
                    "_id": ObjectId(id)
                }
            }
        ]

        user = db.acc_users.aggregate(pipeline).next()
        return user

    # TODO: Error Handling
    # If an invalid ID is passed to `get_user`, it should return None.
    except (StopIteration) as _:

        return None

    except Exception as e:
        return {}

def get_agent(id):
     """
     Given a movie ID, return a movie with that ID, with the comments for that
     movie embedded in the movie document. The comments are joined from the
     comments collection using expressive $lookup.
     """
     try:

         pipeline = [
             {
                 "$match": {
                     "_id": ObjectId(id)
                 }
             }
         ]

         agent = db.pro_agents.aggregate(pipeline).next()
         return agent

     # TODO: Error Handling
     # If an invalid ID is passed to `get_agent`, it should return None.
     except (StopIteration) as _:

         return None

     except Exception as e:
         return {}
         
def get_responder_primary(id):

    try:
        pipeline = [{"$match": {"emergency_id": ObjectId(id),"is_primary": True}}]
        agent = db.sos_emergency_responders.aggregate(pipeline).next()
        return agent

     # TODO: Error Handling
     # If an invalid ID is passed to `get_agent`, it should return None.
    except (StopIteration) as _:
        return None
    except Exception as e:
        return {}
         
def get_agent_by_userid(id):
     """
     Given a movie ID, return a movie with that ID, with the comments for that
     movie embedded in the movie document. The comments are joined from the
     comments collection using expressive $lookup.
     """
     try:

         pipeline = [
             {
                 "$match": {
                     "user_id": ObjectId(id)
                 }
             }
         ]

         agent = db.pro_agents.aggregate(pipeline).next()
         return agent

     # TODO: Error Handling
     # If an invalid ID is passed to `get_agent`, it should return None.
     except (StopIteration) as _:

         return None

     except Exception as e:
         return {}
         
def get_emergency(id):
     """
     Given a movie ID, return a movie with that ID, with the comments for that
     movie embedded in the movie document. The comments are joined from the
     comments collection using expressive $lookup.
     """
     try:

         pipeline = [
             {
                 "$match": {
                     "_id": ObjectId(id)
                 }
             }
         ]

         emergency = db.sos_emergencies.aggregate(pipeline).next()
         return emergency

     # TODO: Error Handling
     # If an invalid ID is passed to `get_agent`, it should return None.
     except (StopIteration) as _:

         return None

     except Exception as e:
         return {}

def get_last_emergency_user(id):
     """
     Given a movie ID, return a movie with that ID, with the comments for that
     movie embedded in the movie document. The comments are joined from the
     comments collection using expressive $lookup.
     """
     try:

         pipeline = [
             {
                 "$match": {
                     "user_id": ObjectId(id)
                 }
             },
                          {
                 "$sort": {
                     "date_created": -1
                 }
             },
                          {
                 "$limit": 1
                 
             },
             
         ]

         emergency = db.sos_emergencies.aggregate(pipeline).next()
         return emergency

     # TODO: Error Handling
     # If an invalid ID is passed to `get_agent`, it should return None.
     except (StopIteration) as _:

         return None

     except Exception as e:
         return {}
         
from flask import Blueprint, request, jsonify
from flask_cors import CORS

from datetime import datetime
from bson.objectid import ObjectId
from difflib import SequenceMatcher
from openlocationcode import openlocationcode as olc
import time
import geopy
import re

heroo_api_v1 = Blueprint(
    'herooy_api_v1', 'heroo_api_v1', url_prefix='/api/v1/heroo')

CORS(heroo_api_v1)


@heroo_api_v1.route('/users', methods=['GET'])
def api_get_users():

    users = get_users()

    response = {
        "users": users,
    }

    return jsonify(response)

@heroo_api_v1.route('/agents', methods=['GET'])
def api_get_agents():

    agents = get_agents()

    response = {
        "agents": agents,
    }

    return jsonify(response)
    
@heroo_api_v1.route('/agents_info', methods=['GET'])
def api_get_agents_info():

    agents = get_agents_info()
    
    response = {
        "users": agents,
    }
    return jsonify(response)

@heroo_api_v1.route('/crews', methods=['GET'])
def api_get_crews():

    crews = get_crews()

    response = {
        "crews": crews,
    }

    return jsonify(response)

@heroo_api_v1.route('/agencies', methods=['GET'])
def api_get_agencies():

    agencies = get_agencies()

    response = {
        "agencies": agencies,
    }

    return jsonify(response)

@heroo_api_v1.route('/emergencies', methods=['GET'])
def api_get_emergencies():

    emergencies = get_emergencies()

    response = {
        "emergencies": emergencies,
    }
    return jsonify(response)
    
@heroo_api_v1.route('/emergencies/citizen/<id>', methods=['GET'])
def api_get_emergencies_citizen(id):
    user = get_user(id)
    location = user["last_location"]["plus_code"]

#    db = get_db()
    rgx = re.compile("^"+location[:6], re.IGNORECASE)
    near_emergencies = {}
    near_emergencies = list(db.sos_emergencies.find({"user_id":{"$ne":ObjectId(id)},"initial_location": rgx, "citizen_dispatch": True, "is_closed": False}))
    response = {
        "emergencies": near_emergencies,
    }
    print(near_emergencies)
    return jsonify(response)

@heroo_api_v1.route('/emergencies/active/<id>', methods=['GET'])
def api_get_emergency(id):
    
    print("Searching")
    
#    db = get_db()

    user = get_user(id)

    location = user["last_location"]["plus_code"]

    agent = get_agent_by_userid(id)
    
    emergencies = get_active_emergencies(agent["_id"])
                
    max = 0
    response = {}
    rejected = []
    
    print(emergencies)
    
    assigned_emergencies = []
    
                            
    for request in agent["requests"]:
        if request["accepted"] == False:
            rejected.append(request["emergency_id"])
    
    while response == {}:
        print("Searching")
        emergencies = get_active_emergencies(agent["_id"])
        position = 1
        for emergency in emergencies:
            if emergency["is_closed"] == False:
                if str(emergency["_id"]) not in rejected:
                    if emergency["statuses"][-1]["status"] == "Created":
                        print(emergency["assigned_responders"][0]["id"])
                        print(ObjectId(agent["_id"]))
                        if position == 1 and emergency["assigned_responders"][0]["id"] == ObjectId(agent["_id"]):
                            response = emergency
#            if emergency["is_closed"] == False:
#                if str(emergency["_id"]) in rejected:
#                    print("Emergency is rejected")
#                else:
#            print(emergency["assigned_responders"]["id"==ObjectId(id)])
            
#            s = SequenceMatcher(None, user["last_location"]["plus_code"], emergency["initial_location"])
#            sim = s.ratio()
#            if sim>max:
#                max = sim
#                response = emergency
#                print("Emergency is new best")
        

        

#                        elif position == 1 and emergency["assigned_responders"][1]["id"] == ObjectId(id):
#                            print("Secondary")

        time.sleep(2)

    

    return jsonify(response)
    
@heroo_api_v1.route('/agents_agencies', methods=['GET'])
def api_get_agents_by_agencies():
    try:
        agencies = request.args.getlist('pro_agencies')
        results = get_agents_by_agency(agencies)
        response_object = {
            "agents": results
        }
        return jsonify(response_object), 200
    except Exception as e:
        response_object = {
            "error": str(e)
        }
        return jsonify(response_object), 400
        
@heroo_api_v1.route('/users/<id>', methods=['GET'])
def api_get_user_by_id(id):
    user = get_user(id)
    if user is None:
        return jsonify({
            "error": "Not found"
        }), 400
    elif user == {}:
        return jsonify({
            "error": "uncaught general exception"
        }), 400
    else:
        return jsonify(user), 200

@heroo_api_v1.route('/users/email/check/<id>', methods=['GET'])
def check_email_exists(id):
    existing_user = db.acc_users.find_one({"email":id},{})
    if existing_user is None:
        response = {
        "status": False,
    }
        return jsonify(response)
    else:
        response = {
        "status": True,
    }
        return jsonify(response)
    
@heroo_api_v1.route('/users/link/request/<id>', methods=['POST'])
def api_link_request(id):

    content= request.json
    email = content["email"]
#    db = get_db()
    now = datetime.now()
    
    existing_user = db.acc_users.find_one({"email":email},{})
    if existing_user is None:
        response = {"text": "User does not exist"}
        print(response)
        return jsonify(response)
    else:
    
        user = db.acc_users.aggregate([{"$match":{"email": email}}]).next()
        existing_group = db.acc_user_groups.find_one({"user_id":ObjectId(id)},{"users":1})

        if existing_group is None:
            group_doc = { 'user_id' : ObjectId(id), 'users' : [{"user_id": ObjectId(user["_id"]), 'status': "No response",'is_deleted': False, 'date_created': now, 'date_modified': now}], 'is_deleted': False, 'date_created': now, 'date_modified': now}
            db.acc_user_groups.insert_one(group_doc),
            group = db.acc_user_groups.aggregate([{"$match":{"user_id": ObjectId(id)}}]).next()
            db.acc_users.update_one({"_id": ObjectId(user["_id"])},{"$push":{"user_groups":group["_id"]}})
        else:
            if any(x["user_id"] == user["_id"] for x in existing_group["users"]):
                response = {"text": "Request already sent"}
                print(response)
                return jsonify(response)
            else:
                db.acc_user_groups.update_one({"user_id": ObjectId(id)},{"$push":{"users":{"user_id":ObjectId(user["_id"]), 'status': "No response", 'is_deleted': False, 'date_created': now, 'date_modified': now}}})
                group = db.acc_user_groups.aggregate([{"$match":{"user_id": ObjectId(id)}}]).next()
                db.acc_users.update_one({"_id": ObjectId(user["_id"])},{"$push":{"user_groups":group["_id"]}})
                response = {"text": "Request sent"}
                print(response)
                return jsonify(response)

@heroo_api_v1.route('/users/link/requested/<id>', methods=['GET'])
def api_link_requested(id):
    user = get_user(id)
    user_groups = user["user_groups"]
#    db = get_db()
    requests = []
    for user_group in user_groups:
        pipeline = [{"$match": {"_id": user_group}}]
        group = db.acc_user_groups.aggregate(pipeline).next()
        users = group["users"]
        for group_user in users:
            if group_user["user_id"] == ObjectId(id) and group_user["status"] == "No response":
                new_user = get_user(ObjectId(group["user_id"]))
                requests.append({"group": group["_id"], "first_name": new_user["first_name"], "last_name": new_user["last_name"], "email": new_user["email"]})
    response = {
        "linkRequests": requests,
    }

    return jsonify(response)


@heroo_api_v1.route('/users/link/response/<id>', methods=['PUT'])
def api_link_response(id):
    content = request.json
    user_group = content["group"]
    response = content["response"]
#    db = get_db()
    now = datetime.now()
    index = 0
    print(user_group)
    pipeline = [{"$match": {"_id": ObjectId(user_group)}}]
    group = db.acc_user_groups.aggregate(pipeline).next()
    users = group["users"]
    for i, group_user in enumerate(users):
        if group_user["user_id"] == id:
            index = i
    db.acc_user_groups.update_one({"_id": ObjectId(user_group)},{"$set":{"users."+str(index)+".status": response, "users."+str(index)+".date_modified": now}})
    if response == "Rejected":
        print(group)
        db.acc_users.update_one({"_id": id},{"$pull":{"user_groups": group}})
        
    return "Response updated"
        
@heroo_api_v1.route('/agents/<id>', methods=['GET'])
def api_get_agent_by_id(id):
    agent = get_agent(id)
    if agent is None:
        return jsonify({
            "error": "Not found"
        }), 400
    elif agent == {}:
        return jsonify({
            "error": "uncaught general exception"
        }), 400
    else:
        return jsonify(agent), 200

@heroo_api_v1.route('/emergencies/<id>', methods=['GET'])
def api_get_emergency_by_id(id):
    emergency = get_emergency(id)
    if emergency is None:
        return jsonify({
            "error": "Not found"
        }), 400
    elif emergency == {}:
        return jsonify({
            "error": "uncaught general exception"
        }), 400
    else:
        return jsonify(emergency), 200
        
@heroo_api_v1.route('/emergencies/history/<id>', methods=['GET'])
def api_get_emergency_history(id):
#    db = get_db()

    emergencies = list(db.sos_emergencies.find({"user_id": ObjectId(id), "is_closed": True}))


#    if existing_emergency is not None:
#        pipeline = [{"$match": {"user_id": ObjectId(id), "is_closed": True}}]
#        emergencies = db.sos_emergencies.aggregate(pipeline).next()
#    else:
#        emergencies = None
    
    if emergencies is None:
        return jsonify({
            "error": "Not found"
        }), 400
    elif emergencies == {}:
        return jsonify({
            "error": "uncaught general exception"
        }), 400
    else:
        response = {"emergencies": emergencies,}
        return jsonify(response), 200
        
@heroo_api_v1.route('/agents/status/<id>', methods=['GET'])
def api_get_agent_status(id):
    agent = get_agent(id)
    if agent is None:
        return jsonify({
            "error": "Not found"
        }), 400
    elif agent == {}:
        return jsonify({
            "error": "uncaught general exception"
        }), 400
    else:
        status = agent["statuses"][-1]
        return jsonify(status), 200
        
@heroo_api_v1.route('/emergencies/status/<id>', methods=['GET'])
def api_get_emergency_status(id):

    emergency = get_emergency(id)
    
    if emergency is None:
        return jsonify({
            "error": "Not found"
        }), 400
    elif emergency == {}:
        return jsonify({
            "error": "uncaught general exception"
        }), 400
    else:
        check = False
        for status in emergency["statuses"]:
            print(status)
            if status["status"] == "Cancelled":
                check = True

        if check == False:
            status = emergency["statuses"][-1]
        else:
            status = {"status": "Cancelled", "timestamp": "N/A"}
            
        return jsonify(status), 200
        
@heroo_api_v1.route('/emergencies/messages/<id>', methods=['GET'])
def api_get_messages(id):
#    db = get_db()
    existing_chat = db.sos_chats.find_one({"emergency_id": ObjectId(id)},{})
    if existing_chat is not None:
        pipeline = [{"$match": {"emergency_id": ObjectId(id)}}]
        chat = db.sos_chats.aggregate(pipeline).next()
        print(chat)
        return jsonify(chat)
        
@heroo_api_v1.route('/agents/location/primary/<id>', methods=['GET'])
def api_get_agent_location_primary(id):

    responder = None
    
    while responder is None:
        responder = get_responder_primary(id)

    
    if responder is None:
        return jsonify({
            "error": "Not found"
        }), 400
    elif responder == {}:
        return jsonify({
            "error": "uncaught general exception"
        }), 400
    else:
        location = {"location": responder["location"], "agentId": str(responder["user_id"])}
        
        return jsonify(location), 200

@heroo_api_v1.route('/users/last_emergency/<id>', methods=['GET'])
def api_get_user_last_emergency(id):

    emergency = get_last_emergency_user(id)

    if emergency is None:
        return jsonify({
            "error": "Not found"
        }), 400
    elif emergency == {}:
        return jsonify({
            "error": "uncaught general exception"
        }), 400
    else:
        return jsonify(emergency), 200

@heroo_api_v1.route('/users/update/location/<id>', methods=['PUT'])
def update_user_location(id):
    content = request.json
    location = content["loc"]
    
#    db = get_db()
    now = datetime.now()
    latlong = olc.decode(location)
    print(latlong)
    db.acc_users.update_one({"_id": ObjectId(id)},{"$set":{"last_location":{"plus_code":location,"timestamp":now},"location":{ "type": "Point", "coordinates": [ latlong.latitudeCenter, latlong.longitudeCenter ] } }})
    
    

    return "Location was updated", 200
    
@heroo_api_v1.route('/users/update/location/emergency/<id>', methods=['PUT'])
def update_responder_location_emergency(id):
    content = request.json
    location = content["loc"]
    emergencyId = content["emergencyId"]
#    db = get_db()
    now = datetime.now()
    
    if len(location) != 9:

        pipeline = [{"$match": {"user_id": ObjectId(id), "emergency_id": ObjectId(emergencyId)}}]
        responder = db.sos_emergency_responders.aggregate(pipeline).next()
        if responder["departure_time"] is None:
            db.sos_emergency_responders.update_one({"user_id": ObjectId(id), "emergency_id": ObjectId(emergencyId)},{"$set":{"departure_time":now}})
        db.sos_emergency_responders.update_one({"user_id": ObjectId(id), "emergency_id": ObjectId(emergencyId)},{"$set":{"location":location}})
        db.acc_users.update_one({"_id": ObjectId(id)},{"$set":{"last_location":{"plus_code":location,"timestamp":now}}})


    return "Location was updated", 200
    
@heroo_api_v1.route('/emergency/accept', methods=['PUT'])
def accept_emergency():
    content = request.json
    emergencyId = content["emergKey"]
    agentId = content["agentKey"]
    agent = get_agent(agentId)
    user = get_user(agent["user_id"])
    emergency = get_emergency(emergencyId)

    
    now = datetime.now()
#    db = get_db()
    
    db.pro_agents.update_one({"_id": ObjectId(agentId)},{"$push":{"requests":{"emergency_id":ObjectId(emergencyId),"request_time":now, "accepted": True, "response_time": now}}})
    db.pro_agents.update_one({"_id": ObjectId(agentId)},{"$push": {"statuses":{"status":"On mission","start_date":now}}})
    db.sos_emergencies.update_one({"_id": ObjectId(emergencyId)},{"$push": {"statuses":{"status":"Accepted","start_date":now}}})
    db.sos_emergencies.update_one({"_id": ObjectId(emergencyId)},{"$push": {"responders":{"id": ObjectId(agentId),"start_date":now}}})
    db.sos_emergencies.update_one({"_id": ObjectId(emergencyId)},{"$set": {"is_accepted": True, "date_modified": now}})
    db.acc_users.update_one({"_id": ObjectId(emergency["user_id"])},{"$set":{"on_emergency": True}})
    responder_doc = { 'emergency_id': ObjectId(emergencyId),'user_id' : ObjectId(agent["user_id"]), 'is_professional' : True, 'is_primary': True, 'location': user["last_location"]["plus_code"], 'departure_time': now, 'is_finalized': False, 'is_deleted': False, 'date_created': now, 'date_created': now}
    db.sos_emergency_responders.insert_one(responder_doc),
    return "Emergency was accepted", 200

@heroo_api_v1.route('/emergency/cancel/<id>', methods=['PUT'])
def cancel_emergency(id):  
    print(id)
    pipeline = [
             {
                 "$match": {
                     "user_id": ObjectId(id)
                 }
             },
                          {
                 "$sort": {
                     "date_created": -1
                 }
             },
                          {
                 "$limit": 1
                 
             },
         ]
       
    emergency = db.sos_emergencies.aggregate(pipeline).next()
            
    #print(emergency)
    
    now = datetime.now()
#    db = get_db()
    
    responders = list(db.sos_emergency_responders.find({"emergency_id": ObjectId(id)}))
    
    for responder in responders:
        db.pro_agents.update_one({"user_id": ObjectId(responder["user_id"])},{"$push": {"statuses":{"status":"On duty","start_date":now}}})
    print(emergency["_id"])
    print(ObjectId(emergency["_id"]))
    #db.pro_agents.update({"_id": ObjectId(agentId)},{"$set":{"statuses":{"end_date":now}}})
    db.sos_emergency_responders.update_one({"emergency_id": ObjectId(emergency["_id"])},{"$set":{"is_finalized": True, "date_modified": now}})
    db.sos_emergencies.update_one({"_id": ObjectId(emergency["_id"])},{"$push":{"statuses":{"status":"Cancelled","start_date":now}}})
    db.sos_emergencies.update_one({"_id": ObjectId(emergency["_id"])},{"$set":{"is_closed": True, "date_modified": now}})
    db.sos_chats.update_one({"emegency_id": ObjectId(emergency["_id"])},{"$set":{"is_closed": True, "date_modified": now}})

    db.acc_users.update_one({"_id": ObjectId(id)},{"$set":{"in_danger": False}})
    existing_chat = db.sos_chats.find_one({"emergency_id": ObjectId(emergency["_id"])},{})
    if existing_chat is not None:
        db.sos_chats.update_one({"emegency_id": ObjectId(emergency["_id"])},{"$set":{"is_closed": True, "date_modified": now}})

    return "Emergency was cancelled", 200

@heroo_api_v1.route('/emergency/end/<id>', methods=['PUT'])
def end_emergency(id):

    emergency = get_emergency(id)
    content = request.json
    comment = content["comment"]
    type = content["type"]
    rating = content["rating"]
    #print(emergency)
    
    now = datetime.now()
#    db = get_db()
    
    responders = list(db.sos_emergency_responders.find({"emergency_id": ObjectId(id)}))
    
    for responder in responders:
        db.pro_agents.update_one({"user_id": ObjectId(responder["user_id"])},{"$push": {"statuses":{"status":"On duty","start_date":now}}})
    responder = get_responder_primary(id)
    db.sos_emergency_responders.update_one({"_id":ObjectId(responder["_id"])},{"$set": {"emergency_score": rating}})

    #db.pro_agents.update({"_id": ObjectId(agentId)},{"$set":{"statuses":{"end_date":now}}})
    db.sos_emergency_responders.update_one({"emergency_id": ObjectId(id)},{"$set":{"is_finalized": True, "date_modified": now}})
    db.sos_emergencies.update_one({"_id": ObjectId(id)},{"$push":{"statuses":{"status":"Finished","start_date":now}}})
    db.sos_emergencies.update_one({"_id": ObjectId(id)},{"$push":{"resolutions":{"agent_id":responder["user_id"],"comment":comment, "type": type, "attachments": [], "date_created": now}}})
    db.sos_emergencies.update_one({"_id": ObjectId(id)},{"$set":{"is_closed": True, "date_modified": now}})
#     db.sos_emergencies.update({"_id": ObjectId(id)},{"$set":{"user_nps": rating}})
    db.sos_chats.update_one({"emegency_id": ObjectId(id)},{"$set":{"is_closed": True, "date_modified": now}})
    db.acc_users.update_one({"_id": ObjectId(emergency["user_id"])},{"$set":{"in_danger": False}})

    return "Emergency was finished", 200
    

@heroo_api_v1.route('/emergency/end/user/<id>', methods=['PUT'])
def end_emergency_user(id):

    emergency = get_emergency(id)
    content = request.json
    rating = content["rating"]
    print(rating)
    if rating == 0:
        rating = "Bad"
    
    now = datetime.now()
#    db = get_db()

    db.sos_emergencies.update_one({"_id": ObjectId(id)},{"$set":{"user_nps": rating}})

    return "Emergency was rated", 200
    
@heroo_api_v1.route('/emergency/arrived/<id>', methods=['PUT'])
def emergency_arrived(id):
    
    now = datetime.now()
#    db = get_db()
    status = []
    emergency = get_emergency(id)
    for i in range(len(emergency["statuses"])):
        status.append(emergency["statuses"][i]["status"])
        
    print(status)
    if "Arrived" not in status:
        db.sos_emergencies.update_one({"_id": ObjectId(id)},{"$push": {"statuses":{"status":"Arrived","start_date":now}}})
        db.sos_emergency_responders.update_one({"emergency_id": ObjectId(id), 'is_primary': True}, {"$set": {"arrival_time": now}})
    return "Status was updated", 200
    
@heroo_api_v1.route('/emergency/premium/create', methods=('GET', 'POST'))
def create_emergency_premium():
    if request.method == 'POST':
    
        content = request.json
        userId = content['userId']
        location = content['location']
        now = datetime.now()
#        db = get_db()
        user = get_user(userId)
        
        assigned_responders = []
        position = 1
        for i in range(1,7):
            responder_location = location[:11-i]
            rgx = re.compile("^"+responder_location, re.IGNORECASE)
            responders = {}
            near_users = list(db.acc_users.find({"last_location.plus_code": rgx}))
            
            if near_users == {}:
                print("None found")
            else:
                for near_user in near_users:
                    agent = get_agent_by_userid(str(near_user["_id"]))
                    
                    if agent is not None:
                        if agent["statuses"][-1]["status"] == "On duty":
                            check = True
                            for assigned_responder in assigned_responders:
                                if agent["_id"] == assigned_responder["id"]:
                                    check = False
                            if check == True:
                                assigned_responders.append({"id": agent["_id"], "position": position})
                                position += 1
                                    
        emergency_doc = { 'user_id' : ObjectId(userId), 'initial_location' : location, 'is_premium': True,'citizen_dispatch': user["citizen_dispatch"], 'is_accepted': False, 'statuses': [{'status': "Created",'start_date': now }], 'assigned_responders': assigned_responders, 'is_closed': False, 'date_created': now}
        db.sos_emergencies.insert_one(emergency_doc),
        
        emergency = get_last_emergency_user(userId)
        print(jsonify(emergency))
        return(jsonify(emergency))
        
        
        
@heroo_api_v1.route('/agents/create/<id>', methods=('GET', 'POST'))
def create_agent(id):
    if request.method == 'POST':
        
        now = datetime.now()

#        db = get_db()
        
        exists = list(db.acc_users.find({"_id": ObjectId(id),"agent_id": {"$exists": False}}))
                
        if exists:

            agent_doc = {'user_id' : ObjectId(id), 'agency_internal_code':"", 'is_driver': False, 'statuses':[], 'requests': [], 'is_active': False, 'is_deleted': False, 'date_created': now, 'date_modified': now}
            db.pro_agents.insert_one(agent_doc),
        
            agent = get_agent_by_userid(id)
                
            db.acc_users.update_one({"_id": ObjectId(id)},{"$set":{"agent_id":agent["_id"]}})
            
            response = agent["_id"]
        else:
            response = "Agent exists"

#        print(response)
        
        return jsonify({
            "response": response
        })
        
    return "Agent was created"

@heroo_api_v1.route('/agents/emergency/rejected/<id>', methods=['PUT'])
def update_agent_emergencies_rejected(id):
    content = request.json
    user = get_user(id)
    emergencyId = content["emergencyId"]
    now = datetime.now()
#    db = get_db()
    db.pro_agents.update_one({"_id": ObjectId(user["agent_id"])},{"$push":{"requests":{"emergency_id":emergencyId,"request_time":now, "accepted": False, "response_time": now}}})

    return "Emergency was rejected", 200
    
@heroo_api_v1.route('/agents/status/update/<id>', methods=['PUT'])
def update_agent_status(id):
    content = request.json
    status = content["status"]
    now = datetime.now()
#    db = get_db()
    db.pro_agents.update_one({"user_id": ObjectId(id)},{"$push": {"statuses":{"status":status,"start_date":now}}})

    return "Agent status was updated", 200

@heroo_api_v1.route('/users/photo/upload/<id>', methods=['PUT'])
def upload_user_photo(id):
    content = request.json
    now = datetime.now()
#    db = get_db()
    if "@" in id:
        db.acc_users.update_one({"email": id},{"$set": {"picture_url":content["picture"],"date_modified":now}})
        print("email")
        print(id)
    else:
        db.acc_users.update_one({"_id": ObjectId(id)},{"$set": {"picture_url":content["picture"],"date_modified":now}})
        print("userId")
        print(id)

    print("Profile pic was uploaded")
    return "Profile pic was uploaded", 200

@heroo_api_v1.route('/users/photo/download/<id>', methods=['GET'])
def download_user_photo(id):
    content = db.acc_users.find_one({"_id":ObjectId(id)},{"picture_url":1})
    print(content["picture_url"][0:10])

    if content is None:
        print("No picture")
        response = {"Response": "No picture",}
        return jsonify(response), 200
    else:
        print("Picture")
        response = {"Response": content["picture_url"],}
        return jsonify(response), 200

@heroo_api_v1.route('/users/update/phone/<id>', methods=['PUT'])
def update_user_phone(id):
    content = request.json
    now = datetime.now()
#    db = get_db()

    db.acc_users.update_one({"_id": ObjectId(id)},{"$set": {"phone":content["phone"],"date_modified":now}})


    print("Phone was updated")
    return "Phone was updated", 200

@heroo_api_v1.route('/users/update/device/<id>', methods=['PUT'])
def update_user_device(id):
    content = request.json
    now = datetime.now()
#    db = get_db()

    db.acc_users.update_one({"_id": ObjectId(id)},{"$set": {"device":content["device"],"date_modified":now}})


    print("Device was updated")
    return "Device was updated", 200

@heroo_api_v1.route('/users/citizen/update/<id>', methods=['PUT'])
def update_user_citizen(id):
    content = request.json
    status = content["status"]
    now = datetime.now()
#    db = get_db()
    db.acc_users.update_one({"_id": ObjectId(id)},{"$set": {"citizen_dispatch": status, "date_modified": now}})

    return "Citizen dispatch was updated", 200
    
@heroo_api_v1.route('/users/on_duty/update/<id>', methods=['PUT'])
def update_user_onduty(id):
    content = request.json
    status = content["status"]
    now = datetime.now()
#    db = get_db()
    if status == True:
        db.pro_agents.update_one({"user_id": ObjectId(id)},{"$push": {"statuses":{"status":"On duty","start_date":now}}})
    else:
        db.pro_agents.update_one({"user_id": ObjectId(id)},{"$push": {"statuses":{"status":"Off duty","start_date":now}}})
    db.acc_users.update_one({"_id": ObjectId(id)},{"$set": {"on_duty": status, "date_modified": now}})

    return "Citizen dispatch was updated", 200
    
@heroo_api_v1.route('/users/socket/update/<id>', methods=['PUT'])
def update_user_socket(id):
    content = request.json
    socket = content["socket"]
    status = content["status"]
    now = datetime.now()
#    db = get_db()
    db.acc_users.update_one({"_id": ObjectId(id)},{"$set": {"socket":{"id": socket,"status":status,"start_date":now}}})

    return "User socket was updated", 200
    
@heroo_api_v1.route('users/upload/profile_pic/<id>', methods=['POST'])
def upload_profile_pic(id):
#    db = get_db()
    if 'profile_image' in request.files:
        profile_image = request.files['profile_image']
        name = "profile_pic:"+id
        mongo.save_file(name, profile_image)
        db.acc_users.update_one({"_id": ObjectId(id)},{"$setr":{"profile_pic": name}})
    return "Done"

@heroo_api_v1.route('users/download/profile_pic/<id>', methods=['POST'])
def download_profile_pic(id):
    user = get_user(id)
    if user["profile_pic"] != "":
        return mongo.send_file(user["profile_pic"])
    else:
        return None

@heroo_api_v1.route('/users/account/update/<id>', methods=['PUT'])
def update_user_account(id):
    content = request.json
    firstName = content["firstName"]
    lastName = content["lastName"]
    gender = content["gender"]
    DoB = content["dateOfBirth"]
    dateOfBirth = datetime.strptime(DoB,'%b/%d/%y')
    now = datetime.now()
#    db = get_db()
    db.acc_users.update_one({"email": id},{"$set": {"first_name": firstName, "last_name": lastName, "gender": gender, "date_of_birth": dateOfBirth}})

    return "User account was updated", 200
    
def expect(input, expectedType, field):
    if isinstance(input, expectedType):
        return input
    raise AssertionError("Invalid input for type", field)
    
from flask import session, jsonify, request
from flask_socketio import emit, send, join_room, leave_room
import json
from datetime import datetime
from bson.objectid import ObjectId
import time
import re

clients = []
agent_response = "No response"

@socketio.on('connected')
def connected():
    clients.append(request.sid)
    print("Connected")
    
@socketio.on('disconnected')
def disconnect():
    print("Disconnected")
    clients.remove(request.namespace)
    
@socketio.on('create_premium_emergency')
def create_premium_emergency(not_json):
    content = json.loads(not_json)
    userId = content["id"]
    location = content["location"]
    now = datetime.now()
#    db = get_db()
    user = get_user(userId)
    x = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(5))

    emergency_doc = { 'user_id' : ObjectId(userId), 'cod': x,'initial_location' : location, 'is_premium': True,'citizen_dispatch': user["citizen_dispatch"], 'is_accepted': False, 'statuses': [{'status': "Created",'start_date': now }], 'is_closed': False, 'date_created': now}
    db.sos_emergencies.insert_one(emergency_doc),
        
    emergency = get_last_emergency_user(userId)
    emergency_info ={"id": str(emergency["_id"]), "location": location}
    
#    print(emergency_info)
#    emit("premium_emergency_created", emergency_info["id"])
    existing_group = db.acc_user_groups.find_one({"user_id":ObjectId(userId)},{})
#    print(existing_group)

    if existing_group is not None:
        pipeline = [{"$match": {"user_id": ObjectId(userId)}}]
        group = db.acc_user_groups.aggregate(pipeline).next()
        for linked_user in group["users"]:
            linked_user_info = get_user(linked_user["user_id"])
            print(linked_user_info["socket"]["id"])
            emit("linked_emergency", emergency_info, room = linked_user_info["socket"]["id"])
            #if "device" in linked_user_info:
                #res = client.send(linked_user_info["device"], user["first_name"]+" "+user["last_name"]+" are o urgenta!", title='Urgenta!')
    print(existing_group)

    def ack(value):
        if value == "accepted" or value == "rejected":
            global agent_response
            agent_response = value
#            print(agent_response)
        else:
            raise ValueError('unexpected return value')

    reject_list = []
    check = False
    i = 1
    
    db.acc_users.create_index([("location.coordinates", GEO2D)])

    near_agents = list(db.acc_users.aggregate([{
     "$geoNear": {
        "near": user["location"]["coordinates"],
        "key": "location.coordinates",
        "maxDistance": 3000,
        "distanceField": "dist.calculated",
        "query": { "on_duty": True }
     }
   },
   { "$limit": 6 }
    ]))
    
#     print(list(near_active_agents))
#     near_agents = list(near_active_agents)
#     while check == False: 
#      and i<7:
#         print(i)
#         responder_location = location[:11-i]
#         rgx = re.compile("^"+responder_location, re.IGNORECASE)
#         near_agents = list(db.acc_users.find({"last_location.plus_code": rgx, "on_duty": True}))
    #print(near_agents)
    if near_agents != []:
        for near_agent in near_agents:
            agent = get_agent_by_userid(str(near_agent["_id"]))
            check_emergency = get_last_emergency_user(userId)
            if check_emergency["is_closed"] == True:
                break
            if agent["statuses"][-1]["status"] == "On duty":
#                i = 0
#                while i<60:
#
#                for request in agent["requests"]:
#                    if request["accepted"] == False:
#                        rejected.append(request["emergency_id"])
                print(agent["_id"])
                global agent_response
                agent_response = "No response"

                if agent["_id"] not in reject_list:
                    emit("near_premium_emergency", emergency_info, room = near_agent["socket"]["id"], callback = ack)
                    if "device" in near_agent:
                        #token_hex = near_agent["device"]
                        #payload = Payload(alert="Este nevoie de ajutorul tau!", sound="default", badge=1)
                        #apns.gateway_server.send_notification(token_hex, payload)
                        alert = 'Este nevoie de ajutorul tau!'
                        titlu = 'Urgenta'
                        token = near_agent["device"]
                        #res = client.send(token, alert)
                        #print(res.tokens)
                        #print(res.errors)
                        #print(res.token_errors)
                        token_hex = near_agent["device"]
                        payload = Payload(alert='Este nevoie de ajutorul tau!', sound="default", badge=1)
                        topic = 'heroo.HerooDev'
                        client.send_notification(token_hex, payload, topic)
                        print("Notification sent to APN")


#                         global agent_response
                    j = 0
                    print(agent_response)
                    print(j)
                    while agent_response == "No response" and j <7:
                        print(agent_response)
                        print(j)
                        time.sleep(1)
                        j += 1
                    if agent_response == "accepted":
                        agent_response = "No response"
                        check = True
                        break
                    elif agent_response == "rejected":
                        reject_list.append(agent["_id"])
                        db.pro_agents.update_one({"_id": ObjectId(agent["_id"])},{"$push":{"requests":{"emergency_id":str(emergency["_id"]),"request_time":now, "accepted": False, "response_time": now}}})
                        agent_response = "No response"
                    elif agent_response == "No response" and j == 7:
                        reject_list.append(agent["_id"])
                        db.pro_agents.update_one({"_id": ObjectId(agent["_id"])},{"$push":{"requests":{"emergency_id":str(emergency["_id"]),"request_time":now, "accepted": False, "response_time": now}}})
                        agent_response = "No response"
                    else:
                        agent_response = "No response"
#             i += 1
#         else:
#             i += 1
            
    if check == True:
        response = {"emergencyId": emergency_info["id"], "responder": str(agent["_id"])}
        print(response)
        emit("premium_emergency_created", response)
    else:
        response = {"emergencyId": emergency_info["id"], "responder": "None"}
        print(response)
        emit("premium_emergency_created", response)
    
@socketio.on('joined')
def joined(message):
    print("Joined")
    content = json.loads(message)
    emergencyId = content["emergencyId"]
    """Sent by clients when they enter a room.
    A status message is broadcast to all people in the room."""
#    db = get_db()
    now = datetime.now()
    existing_chat = db.sos_chats.find_one({"emergency_id": ObjectId(emergencyId)},{})
    if existing_chat is None:
        chat_doc = { 'emergency_id' : ObjectId(emergencyId), 'is_public' : False, 'chat_messages': [],'is_closed': False, 'date_created': now, 'date_modified': now}
        db.sos_chats.insert_one(chat_doc),
    chat = db.sos_chats.find_one({"emergency_id": ObjectId(emergencyId)},{})
    room = str(chat["_id"])
    join_room(room)
    emit('status', "User has entered the room.", room=room)


@socketio.on('text')
def text(message):
    print("Text")
    """Sent by a client when the user entered a new message.
    The message is sent to all people in the room."""
    content = json.loads(message)
    userId = content["userId"]
    emergencyId = content["emergencyId"]
    message = content["message"]
    requester = content["requester"]
#    db = get_db()
    now = datetime.now()
    db.sos_chats.update_one({"emergency_id": ObjectId(emergencyId)},{"$push":{"chat_messages":{"user_id": userId, "is_requester": requester, "message": message, "attachments":"", "timestamp": now}}})
    chat = db.sos_chats.find_one({"emergency_id": ObjectId(emergencyId)},{})
    room = str(chat["_id"])
    message = {"userId": userId, "message": message}
    emit('message', message, room=room)


@socketio.on('left')
def left(message):
    """Sent by clients when they leave a room.
    A status message is broadcast to all people in the room."""
    room = session.get('room')
    leave_room(room)
    emit('status', "User has left the room.", room=room)

app = Flask(__name__, instance_relative_config=True)
app.config["SECRET_KEY"] = os.environ.get('SECRET')
app.config['DEBUG'] = True
app.config['MONGO_URI'] = "mongodb+srv://Costin:Emposess2020@cluster0.nnatx.mongodb.net/HerooDB?retryWrites=true&w=majority&ssl=true"
#&ssl_cert_reqs=CERT_NONE"
    #app = Flask(__name__, static_folder=STATIC_FOLDER,
    #            template_folder=TEMPLATE_FOLDER,
    #            )
#mongo = PyMongo(app)

@app.route('/')
def hello_world():
    return 'Hello, World!'

CORS(app)
app.json_encoder = MongoJsonEncoder
app.register_blueprint(heroo_api_v1)

#    from . import auth
app.register_blueprint(bp)

socketio.init_app(app)

client = APNsClient('pemAPNSCert.pem', use_sandbox=True, use_alternative_port=False)

#client = APNSSandboxClient(certificate='pemAPNSCert.pem',
#                    default_error_timeout=10,
#                    default_expiration_offset=2592000,
#                    default_batch_size=100,
#                    default_retries=5)

if __name__ == "__main__":
    app.run()


