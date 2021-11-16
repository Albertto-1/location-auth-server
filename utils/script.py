import sys
import firebase_admin
from firebase_admin import credentials
from firebase_admin import db
from tabulate import tabulate

cred = credentials.Certificate("../service-account.json")
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://location-auth-10-default-rtdb.firebaseio.com/'
    })

TESTING_TYPE = "ALL"
if len(sys.argv) > 1:
    TESTING_TYPE = sys.argv[1]

def get_result(feedback):
    if feedback["result"] == "SUCCESS_REGISTRATION" or (feedback["result"] == "TRUSTED_LOCATION" and feedback["expected_trusted_location"] == True) or (feedback["result"] == "NEW_LOCATION" and feedback["expected_trusted_location"] == True):
        return "success"
    if feedback["result"] == "TRUSTED_LOCATION" and feedback["expected_trusted_location"] == False:
        return "false positive"
    return "false negative"

def results():
    results = []
    users = {}
    refered = {}
    locations = {}

    feedbacks = db.reference("/feedbacks").get()
    for key in feedbacks:
        if TESTING_TYPE == "THEM" and feedbacks[key]["used_id"] == "-MnSWqBIbIFkjI00TTON": continue
        if TESTING_TYPE == "ME" and feedbacks[key]["used_id"] != "-MnSWqBIbIFkjI00TTON": continue

        if feedbacks[key]["used_id"] not in users:
            users[feedbacks[key]["used_id"]] = {
                    "count": 0
                    }
        users[feedbacks[key]["used_id"]]["count"] = users[feedbacks[key]["used_id"]]["count"] + 1
        results.append(get_result(feedbacks[key]))

    users_ref = db.reference("/users").get()
    for key in users_ref:
        if TESTING_TYPE == "THEM" and key == "-MnSWqBIbIFkjI00TTON": continue
        if TESTING_TYPE == "ME" and key != "-MnSWqBIbIFkjI00TTON": continue

        if users_ref[key]["refered_by"] not in refered:
            refered[users_ref[key]["refered_by"]] = {
                    "count": 0
                    }
        refered[users_ref[key]["refered_by"]]["count"] = refered[users_ref[key]["refered_by"]]["count"] + 1
        if "trusted_locations" in users_ref[key]: locations[key] = len(users_ref[key]["trusted_locations"])

    results_count = len(results)
    results = {i:results.count(i) for i in results}
    results["total"] = results_count
    print(tabulate([aux, results[aux]] for aux in results))
    print(tabulate([aux, refered[aux]["count"]] for aux in refered))
    print(tabulate([aux, users[aux]["count"], locations.get(aux, 0)] for aux in users))







results()
