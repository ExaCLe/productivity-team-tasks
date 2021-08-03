from flask import redirect, session
from functools import wraps

from cs50 import SQL
from flask import redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///tasks.db")


def return_error(message):
    return render_template("error.html", message=message)


def getUsername(id):
    try:
        username = db.execute("SELECT username FROM users WHERE id = ?",
                              id)[0]["username"]
    except:
        username = None
    return username


def getTasks():
    return db.execute("SELECT * FROM tasks WHERE user_id=? AND fullfilled=0",
                      session.get("user_id"))


def getRequests(user_id, type):
    incoming_requests = set()
    requests = db.execute(
        "SELECT * FROM requests WHERE recipient_id = ? AND type = ?", user_id,
        type)
    for req in requests:
        try:
            name = db.execute("SELECT username FROM users WHERE id = ?",
                              req["sender_id"])[0]["username"]
            incoming_requests.add(name)
        except:
            print("An error occured with one friend request.")
    pending_requests = set()
    requests = db.execute(
        "SELECT * FROM requests WHERE sender_id = ? AND type = ?", user_id,
        type)
    for req in requests:
        try:
            name = db.execute("SELECT username FROM users WHERE id = ?",
                              req["recipient_id"])[0]["username"]
            pending_requests.add(name)
        except:
            print("An error occured with one friend request.")
    return incoming_requests, pending_requests


def respondRequest(type, add):
    user_id = session.get("user_id")
    # Make sure that the request exists
    sender = db.execute("SELECT id FROM users WHERE username = ? ",
                        request.form.get("username"))
    if len(sender) == 0:
        return render_template("error.html",
                               message="User not found. Please try again. ")
    try:
        sender_id = sender[0]["id"]
    except:
        return render_template(
            "error.html",
            message="Sender id was not unpacked correctly. Please try again. ")

    req = db.execute(
        "SELECT * FROM requests WHERE sender_id = ? AND recipient_id = ? AND type=?",
        sender_id, user_id, type)
    if len(req) == 0:
        return render_template(
            "error.html",
            message="The request was not found. Please try again. ")
    # Delete the open request and insert the friendship if needed
    if (add):
        if type == 0:
            db.execute(
                "INSERT INTO friends (first_user_id, second_user_id) VALUES (?,?)",
                user_id, sender_id)
        if type == 1:
            db.execute(
                "INSERT INTO challenges(challenger_id, challenged_id, challenger_score, challenged_score, finished, expire_date) VALUES (?, ?, 0, 0, false, Date('now', '+7 days'))",
                sender_id, user_id)
    result = db.execute(
        "DELETE FROM requests WHERE sender_id = ? AND recipient_id = ? AND type=?",
        sender_id, user_id, type)
    return None


def getChallenges(history):
    challenges_set = set()
    user_id = session.get("user_id")
    if history:
        challenges = db.execute(
            "SELECT * FROM challenges WHERE (challenger_id = ? OR challenged_id = ?) AND expire_date < Date('now')",
            user_id, user_id)
    else:
        challenges = db.execute(
            "SELECT * FROM challenges WHERE (challenger_id = ? OR challenged_id = ?) AND expire_date >= Date('now')",
            user_id, user_id)
    for challenge in challenges:
        first_user = db.execute("SELECT username FROM users WHERE id = ?",
                                challenge["challenger_id"])[0]["username"]
        second_user = db.execute("SELECT username FROM users WHERE id = ?",
                                 challenge["challenged_id"])[0]["username"]
        challenge = (challenge["id"], challenge["challenger_score"],
                     challenge["challenged_score"], first_user, second_user,
                     challenge["expire_date"])
        challenges_set.add(challenge)
    return challenges_set


def createRequest(sender_id, recipient_id, type):
    db.execute(
        "INSERT INTO requests (sender_id, recipient_id, type) VALUES (?, ?, ?)",
        sender_id, recipient_id, type)


def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function