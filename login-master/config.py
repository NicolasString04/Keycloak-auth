import os

KEYCLOAK_SERVER = os.getenv("KEYCLOAK_SERVER", "http://localhost:8081")
REALM = os.getenv("KEYCLOAK_REALM", "master")
CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "myclient")
CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET", "ZkYaF0HG5R3A6j0qAKZ5fNyiJjtvPiSv")
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:5000/callback")
