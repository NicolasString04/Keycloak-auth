from flask import Flask, redirect, request, session, url_for, render_template
import requests
import uuid
import config
from keycloak_admin import get_admin_token, get_user_id

web_app = Flask(__name__)
web_app.secret_key = "super-secreta"  # Use algo seguro no real

# URLs Keycloak
authorization_endpoint = config.KEYCLOAK_SERVER + "/realms/" + config.REALM + "/protocol/openid-connect/auth"
token_endpoint = config.KEYCLOAK_SERVER + "/realms/" + config.REALM + "/protocol/openid-connect/token"
user_info_endpoint = config.KEYCLOAK_SERVER + "/realms/" + config.REALM + "/protocol/openid-connect/userinfo"

@web_app.route("/")
def index():
    if "user_data" in session:
        return render_template("home.html", user_name=session["user_data"]["preferred_username"])
    else:
        return render_template("home.html", user_name=None)


@web_app.route("/login")
def authenticate():
    session_state = str(uuid.uuid4())
    session["state"] = session_state

    # Verifica se está vindo com ?register=1 na URL
    keycloak_action = "kc_action=register" if request.args.get("register") == "1" else ""

    auth_params = "?client_id={}&response_type=code&scope=openid&redirect_uri={}&state={}".format(
        config.CLIENT_ID, config.REDIRECT_URI, session_state
    )

    if keycloak_action:
        auth_params += "&" + keycloak_action

    return redirect(authorization_endpoint + auth_params)


@web_app.route("/callback")
def auth_callback():
    if request.args.get("state") != session.get("state"):
        return "Estado invalido", 400

    auth_code = request.args.get("code")

    token_data = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": config.REDIRECT_URI,
        "client_id": config.CLIENT_ID,
        "client_secret": config.CLIENT_SECRET
    }

    token_response = requests.post(token_endpoint, data=token_data)
    if token_response.status_code != 200:
        return "Erro ao obter token: " + token_response.text, 400

    bearer_token = token_response.json().get("access_token")
    user_info_response = requests.get(user_info_endpoint, headers={"Authorization": "Bearer " + bearer_token})

    if user_info_response.status_code == 200:
        session["user_data"] = user_info_response.json()
        return redirect(url_for("index"))
    else:
        return "Erro ao obter informacoes do usuario", 400

@web_app.route("/logout")
def sign_out():
    session.clear()
    logout_endpoint = (
        config.KEYCLOAK_SERVER + "/realms/" + config.REALM + "/protocol/openid-connect/logout"
        + "?post_logout_redirect_uri=" + url_for("index", _external=True)
        + "&client_id=" + config.CLIENT_ID
    )
    return redirect(logout_endpoint)

@web_app.route("/delete", methods=["POST"])
def remove_account():
    if "user_data" not in session:
        return redirect("/")

    current_user = session["user_data"]["preferred_username"]
    admin_token = get_admin_token()
    user_identifier = get_user_id(current_user, admin_token)

    if not user_identifier:
        return "Usuário não encontrado", 404

    delete_response = requests.delete(
        f"{config.KEYCLOAK_SERVER}/admin/realms/{config.REALM}/users/{user_identifier}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )

    if delete_response.status_code == 204:
        session.clear()
        return (
            "Conta excluída com sucesso"
            "<p><a href='/'>Página Inicial</a></p>")
    else:
        return f"Erro ao excluir: {delete_response.text}", 500


if __name__ == "__main__":
    web_app.run(debug=True)