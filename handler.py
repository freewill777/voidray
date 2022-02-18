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
    
