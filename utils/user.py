from firebase_admin import db
from .models import User 


def get_user(email):
    users = db.reference('/users').get()
    user = None
    if users:
        for user_id in users:
            if users[user_id]['email'] == email:
                user = {**users[user_id], "id": user_id}
                if user.get('trusted_locations', None):
                    new_trusted_locations = []
                    for tl_id in user['trusted_locations']:
                        new_trusted_locations.append({**user['trusted_locations'][tl_id], "id": tl_id})
                    user['trusted_locations'] = new_trusted_locations
                else:
                    user['trusted_locations'] = []
    if user:
        return User(**user)
    return None

def give_feedback(feedback):
    return feedback

