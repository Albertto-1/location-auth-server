from datetime import datetime
from utils.models import Location
from firebase_admin import db
from geopy.distance import great_circle
import numpy as np

def calculate_locations_weighted_center(location_list):
    total = 0
    for location in location_list:
        total += location.acc
    new_total = 0
    for location in location_list:
        location.weight = total-location.acc
        new_total += location.weight
    mean_lat = 0
    mean_lon = 0
    mean_acc = 0
    for location in location_list:
        percentage_weight = location.weight/new_total
        mean_lat += percentage_weight*location.lat
        mean_lon += percentage_weight*location.lon
        mean_acc += percentage_weight*location.acc
    return {
            "lat": round(mean_lat, 7),
            "lon": round(mean_lon, 7),
            "acc": round(mean_acc, 2)
            }

def get_locations_weighted_center(location_list):
    center = calculate_locations_weighted_center(location_list)
    lat = center["lat"]
    lon = center["lon"]
    acc = center["acc"]
    today = datetime.today().isoformat()
    return {
            "lat": lat,
            "lon": lon,
            "acc": acc,
            "created_at": today,
            "last_login_date": today,
            "related_locations": [
                {
                    "lat": lat,
                    "lon": lon,
                    "acc": acc,
                }
            ]
        }

def calculate_distance_between(locationA, locationB):
    coords_1 = (locationA['lat'], locationA['lon'])
    coords_2 = (locationB.lat, locationB.lon)
    return great_circle(coords_1, coords_2).m

def get_closest_location(base_location, saved_locations):
    distances = []
    for location in saved_locations:
        distances.append(calculate_distance_between(base_location, location))
    a = np.array(distances)
    return saved_locations[np.where(a == a.min())[0][0]]

def get_distance_to_farthest(center, related_locations):
    distances = []
    for location in related_locations:
        distances.append(calculate_distance_between(center, location))
    a = np.array(distances)
    return a.max()

def optimize_trusted_location(user_id, new_location, trusted_location):
    today = datetime.today().isoformat()
    related_locations = db.reference(f'/users/{user_id}/trusted_locations/{trusted_location.id}/related_locations').get()
    # related_locations = db.reference(f'/users/{user_id}/trusted_locations/-MoWdLwet_QYy0slYCSK/related_locations').get()
    if not related_locations:
        db.reference(f'/users/{user_id}/trusted_locations/{trusted_location.id}').update({
                "last_login_date": today,
                "related_locations": [new_location]
            })
        return
    related_locations.append(new_location)
    if (len(related_locations) > 20):
        del related_locations[0]
    center = calculate_locations_weighted_center([Location(**rl) for rl in related_locations])
    lat = center["lat"]
    lon = center["lon"]
    acc = (20/len(related_locations)) + max(10, get_distance_to_farthest(center, related_locations))
    db.reference(f'/users/{user_id}/trusted_locations/{trusted_location.id}').update({
            "last_login_date": today,
            "lat": lat,
            "lon": lon,
            "acc": acc,
            "related_locations": related_locations
        })

def is_trusted_location(location, user):
    today = datetime.today().isoformat()
    location = {
            "lat": location.get("lat"),
            "lon": location.get("lon"),
            "acc": location.get("acc"),
            "created_at": today,
            "last_login_date": today
            }
    trusted_locations = user.trusted_locations
    if len(trusted_locations) == 0:
        return False
    closest_location = get_closest_location(location, trusted_locations)

    if calculate_distance_between(location, closest_location) <= closest_location.acc:
        optimize_trusted_location(user.id, location, closest_location)
        return True
    return False

def store_new_trusted_location(user_id, location):
    db.reference(f'/users/{user_id}/trusted_locations').push(location)

def are_valid_locations(location_list):
    is_mocked = False
    mean_acc = 0.0
    mean_speed = 0.0
    for location in location_list:
        if location.is_mocked:
            is_mocked = True
        mean_acc += location.acc
        mean_speed += location.speed

    n = len(location_list)
    mean_acc = mean_acc/n
    mean_speed = mean_speed/n

    result = True
    reason = ""
    if is_mocked:
        reason += "Tu dispositivo tiene la ubicación hackeada."
        result = False
        return result, reason
    if mean_acc > 30:
        reason += " La exactitud de la ubicación es muy baja."
        result = False
    if mean_speed > 1.4:
        reason += " Parece que estas en movimiento."
        result = False

    return result, reason


