import requests
import config


def get_admin_token():
    data = {
        "username": "admin",
        "password": "admin",
        "grant_type": "password",
        "client_id": "admin-cli",
    }
    resp = requests.post(f"{config.KEYCLOAK_SERVER}/realms/master/protocol/openid-connect/token", data=data)
    return resp.json().get("access_token")


def get_user_id(username, token):
    resp = requests.get(
        f"{config.KEYCLOAK_SERVER}/admin/realms/{config.REALM}/users",
        headers={"Authorization": f"Bearer {token}"},
        params={"username": username}
    )
    users = resp.json()
    return users[0]["id"] if users else None
