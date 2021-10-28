from datetime import datetime
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
    for location in location_list:
        percentage_weight = location.weight/new_total
        mean_lat += percentage_weight*location.lat
        mean_lon += percentage_weight*location.lon
    return mean_lat, mean_lon

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

def is_trusted_location(location, user):
    trusted_locations = user.trusted_locations
    location = {
            "lat": location[0],
            "lon": location[1]
            }
    closest_location = get_closest_location(location, trusted_locations)
    if calculate_distance_between(location, closest_location) <= 20.00:
        today = datetime.today().isoformat()
        db.reference(f'/users/{user.id}/trusted_locations/{closest_location.id}').update({
            "last_login_date": today
            })
        return True
    return False

def store_new_trusted_location(user_id, locations):
    lat, lon = calculate_locations_weighted_center(locations)
    today = datetime.today().isoformat()
    location = {
            "lat": lat,
            "lon": lon,
            "acc": 20,
            "created_at": today,
            "last_login_date": today
            }
    db.reference(f'/users/{user_id}/trusted_locations').push(location)

