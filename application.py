# Query for routes like: Routes/Tasks/Add

from cs50 import SQL
from flask import Flask, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import login_required, createRequest, getChallenges, return_error, respondRequest, getTasks, getUsername, getRequests

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///tasks.db")


# Route/
@app.route("/")
@login_required
def index():
    incoming_friend_requests, outgoind_friend_requests = getRequests(
        session.get("user_id"), 0)
    incoming_challenge_requests, outgoing_challenge_requests = getRequests(
        session.get("user_id"), 1)
    friends = getFriends()
    challenges = getChallenges(False)
    tasks = getTasks()
    return render_template(
        "index.html",
        incoming_challenge_requests=list(incoming_challenge_requests)[:2],
        incoming_friend_requests=list(incoming_friend_requests)[:2],
        friends=list(friends)[:2],
        challenges=list(challenges)[:2],
        tasks=tasks[:2])


# Routes/Login
@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return render_template("error.html",
                                   code=403,
                                   message="must provide username")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return render_template("error.html",
                                   code=403,
                                   message="must provide password")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?",
                          request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
                rows[0]["hash"], request.form.get("password")):
            return render_template("error.html",
                                   code=403,
                                   message="invalid username/password")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


# Routes/Register
@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        # validate the username
        if username == "":
            return render_template("error.html",
                                   code=403,
                                   message="must provide username")
        result = db.execute("SELECT * FROM users WHERE username = ?", username)
        if result:
            return render_template("error.html",
                                   code=403,
                                   message="username is already used")
        # Validate the email
        if email == "":
            return render_template("error.html",
                                   code=403,
                                   message="must provide email")
        result = db.execute("SELECT * FROM users WHERE email = ?", email)
        if result:
            return render_template("error.html",
                                   code=403,
                                   message="email is already used")

        # check that the password field is not empty
        if not password or not confirmation:
            return render_template("error.html",
                                   code=403,
                                   message="Provide a password")

        # check that the two passwords are equal
        if password != confirmation:
            return render_template("error.html",
                                   code=403,
                                   message="Password are not equal")

        if not db.execute(
                "INSERT INTO users(username, hash, email) VALUES(?, ?, ?)",
                username, generate_password_hash(password), email):
            return render_template(
                "error.html",
                code=403,
                message="Something went wrong. Please try again. ")

        return redirect("/login")
    else:
        return render_template("register.html")


# Routes/Logout
@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/login")


# Routes/Tasks
@app.route("/tasks", methods=["GET", "POST"])
@login_required
def tasks():
    if request.method == "GET":
        # Get the data from the database
        tasks = getTasks()
        return render_template("tasks/tasks.html", tasks=tasks)
    else:
        # Make sure the correct user is logged in
        result = db.execute("SELECT * FROM tasks WHERE id=? AND user_id=?",
                            request.form.get("id"), session.get("user_id"))
        # Change the fullfilled state for the task
        if result is not None:
            db.execute("UPDATE tasks SET fullfilled=1 WHERE id=?",
                       request.form.get("id"))
        return redirect("/tasks")


# Routes/Tasks/Add
@app.route("/tasks/add", methods=["GET", "POST"])
@login_required
def addTask():
    # Nothing todo if method is get
    if request.method == "GET":
        return render_template("tasks/add.html")
    else:
        # Make sure input name is given
        name = request.form.get("name")
        if name == "" or name is None:
            return render_template("tasks/add.html",
                                   message="Bitte Namen eingeben.")
        date = request.form.get("due")
        if date is not None:
            db.execute(
                "INSERT INTO tasks (name, user_id, due, fullfilled, private) VALUES (?, ?, ?, 0, 0)",
                name, session.get("user_id"), date)
        else:
            db.execute(
                "INSERT INTO tasks (description, user_id, fullfilled, private) VALUES (?, ?, 0, 0)",
                name, session.get("user_id"))
        return redirect("/tasks")


# Routes/Tasks/Edit
@app.route("/tasks/edit", methods=["GET", "POST"])
@login_required
def editTask():
    # Get method for getting the info, post for editing
    if request.method == "GET":
        id = request.args.get("id")
        # Make sure a valid is given
        if id is None:
            return redirect("/")
        task = db.execute("SELECT * FROM tasks WHERE id=?", id)
        return render_template("tasks/edit.html", task=task[0])
    else:
        name = request.form.get("name")
        id = request.form.get("id")
        user = session.get("user_id")
        due = request.form.get("due")
        # Make sure the task belongs to the user
        if not name or not id:
            return render_template("/tasks/edit",
                                   message="Fehler. Kontaktiere den Support.")
        result = db.execute("SELECT * FROM tasks WHERE id=? AND user_id=?", id,
                            user)
        if result is not None:
            db.execute("UPDATE tasks SET due=?, name=? WHERE id=?", due, name,
                       id)
        return redirect("/tasks")


# Routes/Scoreboard/Monthly
@app.route("/scoreboard/monthly", methods=["GET", "POST"])
@login_required
def scoreboardMonthly():
    return render_template("scoreboard/monthly.html")


# Routes/Scoreboard/Weekly
@app.route("/scoreboard/weekly", methods=["GET", "POST"])
@login_required
def scoreboardWeekly():
    return render_template("scoreboard/weekly.html")


# Routes/Scoreboard/Daily
@app.route("/scoreboard/daily", methods=["GET", "POST"])
@login_required
def scoreboardDaily():
    return render_template("scoreboard/daily.html")


# Routes/Profile
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "GET":
        username = request.args.get("username")
        # Check for the user trying to access his own profile
        if username is None:
            username = db.execute("SELECT username FROM users WHERE id=?",
                                  session.get("user_id"))[0]["username"]
            try:
                score = db.execute("SELECT score FROM scores WHERE user_id=?",
                                   session.get("user_id"))[0]["score"]
            except:
                score = "xxxx"
            return render_template("profiles/profile.html",
                                   own_profile=True,
                                   username=username,
                                   score=score)
        else:
            # Username provided via get
            try:
                user_id = db.execute("SELECT id FROM users WHERE username=?",
                                     username)[0]["id"]
                score = db.execute("SELECT score FROM scores WHERE user_id=?",
                                   user_id)
                if len(score) == 0:
                    score = "xxxx"
                else:
                    score = score[0]["score"]
                friend = db.execute(
                    "SELECT * FROM friends WHERE (first_user_id = ? AND second_user_id = ?) OR (first_user_id = ? AND second_user_id = ?)",
                    user_id, session.get("user_id"), session.get("user_id"),
                    user_id)
                if len(friend) == 0:
                    friend = False
                else:
                    friend = True
                return render_template("profiles/profile.html",
                                       own_profile=False,
                                       username=username,
                                       score=score,
                                       friend=friend)
            except:
                return return_error("An error occured. ")
    return render_template("profiles/profile.html")


# Routes/Profile/Edit
@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def profileEdit():
    if request.method == "GET":
        return render_template("profiles/edit.html")
    else:
        username = request.form.get("username")
        email = request.form.get("email")
        current_password = request.form.get("current_password")
        password = request.form.get("password")
        confirmation = request.form.get("confirm_password")
        print("_____")
        print(email)
        print("______")

        if username != "":
            # validate the username
            if username == "":
                return render_template("error.html",
                                       code=403,
                                       message="must provide username")
            result = db.execute("SELECT * FROM users WHERE username = ?",
                                username)
            if result:
                return render_template("error.html",
                                       code=403,
                                       message="username is already used")
            if not db.execute("UPDATE users SET username = ? WHERE id = ?",
                              username, session.get("user_id")):
                return render_template(
                    "error.html",
                    code=403,
                    message="Something went wrong. Please try again. ")
        if email != "":
            # Validate the email
            if email == "":
                return render_template("error.html",
                                       code=403,
                                       message="must provide email")
            result = db.execute("SELECT * FROM users WHERE email = ?", email)
            if result:
                return render_template("error.html",
                                       code=403,
                                       message="email is already used")
            if not db.execute("UPDATE users SET email = ? WHERE id = ?", email,
                              session.get("user_id")):
                return render_template(
                    "error.html",
                    code=403,
                    message="Something went wrong. Please try again. ")
        if password != "":
            # check that the password field is not empty
            if not password or not confirmation or not current_password:
                return render_template("error.html",
                                       code=403,
                                       message="A password is missing")

            # check that the two passwords are equal
            if password != confirmation:
                return render_template("error.html",
                                       code=403,
                                       message="Password are not equal")
            # Query database for user_id
            rows = db.execute("SELECT * FROM users WHERE id = ?",
                              session.get("user_id"))

            # Ensure user exists and password is correct
            if len(rows) != 1 or not check_password_hash(
                    rows[0]["hash"], current_password):
                return render_template("error.html",
                                       code=403,
                                       message="invalid current password")
            if not db.execute("UPDATE users SET hash = ? WHERE id = ?",
                              generate_password_hash(password),
                              session.get("user_id")):
                return render_template(
                    "error.html",
                    code=403,
                    message="Something went wrong. Please try again. ")
        return redirect("/profile")


def getFriends():
    user_id = session.get("user_id")
    # Get the friends from the db
    friends = set()
    friends_list_first = db.execute(
        "SELECT * FROM friends WHERE first_user_id = ? ", user_id)
    friends_list_second = db.execute(
        "SELECT * FROM friends WHERE second_user_id = ?", user_id)
    for entry in friends_list_first:
        friend_information = db.execute("SELECT * FROM users WHERE id = ?",
                                        entry["second_user_id"])
        friend_score = db.execute("SELECT * FROM scores WHERE user_id = ?",
                                  entry["second_user_id"])
        try:
            score = friend_score[0]["score"]
        except:
            score = "xxxx"
        friend = (score, friend_information[0]["username"])
        friends.add(friend)
    for entry in friends_list_second:
        friend_information = db.execute("SELECT * FROM users WHERE id = ?",
                                        entry["first_user_id"])
        friend_score = db.execute("SELECT * FROM scores WHERE user_id = ?",
                                  entry["first_user_id"])
        try:
            score = friend_score[0]["score"]
        except:
            score = "xxxx"
        friend = (score, friend_information[0]["username"])
        friends.add(friend)
    return friends


# Routes/Friends
@app.route("/friends", methods=["GET"])
@login_required
def friends():
    user_id = session.get("user_id")
    friends = getFriends()
    # Load the open friend requests
    incoming_requests, pending_requests = getRequests(user_id, 0)
    return render_template("friends/friends.html",
                           friends=friends,
                           incoming_requests=incoming_requests,
                           pending_requests=pending_requests)


# Routes/Friends/Add/Accept
@app.route("/friends/add/accept", methods=["POST"])
@login_required
def friendAccept():
    result = respondRequest(0, True)
    if result:
        return result
    return redirect("/friends")


def getId(username):
    try:
        return db.execute("SELECT id FROM users WHERE username = ?",
                          username)[0]["id"]
    except:
        return None


# Routes/Friends/Add/Decline
@app.route("/friends/add/decline", methods=["POST"])
@login_required
def friendDecline():
    result = respondRequest(0, False)
    if result:
        return result
    return redirect("/friends")


# Routes/Friends/Delete
@app.route("/friends/delete", methods=["GET", "POST"])
@login_required
def friendsDelete():
    username = request.form.get("username")
    if not username:
        return return_error("No username given. Please try again.")
    friend_id = getId(username)
    if not friend_id:
        return return_error("User id not found. Please try again.")
    user_id = session.get("user_id")
    db.execute(
        "DELETE FROM friends WHERE (first_user_id = ? AND second_user_id = ?) OR (first_user_id = ? AND second_user_id = ?)",
        user_id, friend_id, friend_id, user_id)
    print("deleted")
    return redirect("/friends")


# Routes/Friends/Add
@app.route("/friends/add", methods=["GET", "POST"])
@login_required
def friendsAdd():
    # For get return the information about the possible friend
    if request.method == "GET":
        username = request.args.get("username")
        if username is None:
            return render_template(
                "error.html", message="No username given. Please try again.")
        user_id = db.execute("SELECT id FROM users WHERE username = ?",
                             username)
        if len(user_id) == 0:
            return render_template(
                "error.html", message="User not found. Please try again. ")
        try:
            score = db.execute("SELECT score FROM scores WHERE user_id = ?",
                               user_id[0]["id"])[0]["score"]
        except:
            score = None
        return render_template("friends/add.html",
                               score=score,
                               username=username)
    # For POST create a friend request in the db
    else:
        sender_id = session.get("user_id")
        username = request.form.get("username")
        recipient_id = db.execute("SELECT id FROM users WHERE username = ?",
                                  username)
        if len(recipient_id) == 0:
            return render_template(
                "error.html", message="User not found. Please try again. ")
        recipient_id = recipient_id[0]["id"]
        # Type 0 is for friend reqests
        createRequest(sender_id, recipient_id, 0)
        return redirect("/friends")


# Routes/Friends/Search
@app.route("/friends/search", methods=["GET", "POST"])
@login_required
def friendsSearch():
    if request.method == "GET":
        return render_template("friends/search.html")
    else:
        username = request.form.get("username")
        users = db.execute(
            "SELECT username FROM users WHERE username LIKE ? AND NOT id = ?",
            username, session.get("user_id"))
        print(users)
        return render_template("friends/searchResults.html", users=users)


# Routes/Friends/TeamUp
@app.route("/friends/teamUp", methods=["GET"])
@login_required
def friendsTeamUp():
    # Validate the teamUp
    username = request.args.get("username")
    if not username:
        return render_template(
            "error.html", message="Error. No username. Please try again. ")
    friend = db.execute("SELECT * FROM users WHERE username = ?", username)
    if len(friend) == 0:
        return render_template("error.html",
                               message="User not found. Please try again. ")
    friend_id = friend[0]["id"]
    user_id = session.get("user_id")
    verify = db.execute(
        "SELECT * FROM friends WHERE (first_user_id = ? AND second_user_id = ?) OR (first_user_id = ? AND second_user_id = ? ) ",
        user_id, friend_id, friend_id, user_id)
    if len(verify) == 0:
        return render_template(
            "error.html",
            message="The given user is not your friend. Please try again. ")
    friend_tasks = db.execute(
        "SELECT * FROM tasks WHERE user_id = ? and private = false", friend_id)
    user_tasks = db.execute("SELECT * FROM tasks WHERE user_id = ?", user_id)
    return render_template(
        "friends/teamUp.html",
        friend_tasks=friend_tasks,
        user_tasks=user_tasks,
        friend=friend[0],
    )


# Routes/Challenges
@app.route("/challenges", methods=["GET"])
@login_required
def challenges():
    challenges = getChallenges(False)
    incoming_requests, outgoing_requests = getRequests(session.get("user_id"),
                                                       1)
    return render_template("challenges/overview.html",
                           challenges=challenges,
                           incoming_requests=incoming_requests,
                           pending_requests=outgoing_requests)


# Routes/Challenges/Decline
@app.route("/challenges/decline", methods=["POST"])
@login_required
def challengesDecline():
    result = respondRequest(1, False)
    if result:
        return result
    return redirect("/challenges")


# Routes/Challenges/Accept
@app.route("/challenges/accept", methods=["POST"])
@login_required
def challengesAccept():
    result = respondRequest(1, True)
    if result:
        return result
    return redirect("/challenges")


# Routes/Challenges/Details
@app.route("/challenges/details", methods=["GET", "POST"])
@login_required
def challengesDetails():
    # Verify the request
    user_id = session.get("user_id")
    challenge_id = request.args.get("challenge_id")
    if not challenge_id:
        return return_error("No challenge id provided. Please try again.")
    data = db.execute(
        "SELECT * FROM challenges WHERE (challenger_id = ? OR challenged_id = ?) AND id = ?",
        user_id, user_id, challenge_id)
    if len(data) == 0:
        return return_error(
            "You either don't have access to this challenge or the challenge does not exist."
        )
    first_user = getUsername(data[0]["challenger_id"])
    second_user = getUsername(data[0]["challenged_id"])
    if first_user is None or second_user is None:
        return return_error("One user was not found. Please try again.")
    return render_template("challenges/details.html",
                           first_user=first_user,
                           second_user=second_user,
                           date=data[0]["expire_date"],
                           first_score=data[0]["challenger_score"],
                           second_score=data[0]["challenged_score"])


# Routes/Challenges/History
@app.route("/challenges/history", methods=["GET", "POST"])
@login_required
def challengesHistory():
    challenges = getChallenges(True)
    return render_template("challenges/history.html", challenges=challenges)


# Routes/Challenges/New
@app.route("/challenges/new", methods=["GET", "POST"])
@login_required
def challengesNew():
    return render_template("challenges/newChallenge.html")


# Routes/Challenges/Search
@app.route("/challenges/search", methods=["GET", "POST"])
@login_required
def challengesSearch():
    return render_template("challenges/search.html")


# Routes/Challenges/SearchResults
@app.route("/challenges/searchResults", methods=["GET", "POST"])
@login_required
def challengesResults():
    if request.method == "GET":
        username = request.args.get("username")
        if not username:
            return render_template("error.html",
                                   message="No username. Please try again. ")
        results = db.execute(
            "SELECT username FROM users WHERE username LIKE ? AND NOT id = ?",
            username, session.get("user_id"))
        return render_template("challenges/searchResults.html",
                               results=results)
    else:
        username = request.form.get("username")
        if not username:
            return render_template("error.html",
                                   message="No username. Please try again. ")
        user_id = db.execute("SELECT id FROM users WHERE username = ?",
                             username)
        if len(user_id) == 0:
            return render_template(
                "error.html", message="User not found. Please try again. ")
        try:
            user_id = user_id[0]["id"]
        except:
            return render_template(
                "error.html", message="An error occured. Please try again. ")
        createRequest(session.get("user_id"), user_id, 1)
        return redirect("/challenges")