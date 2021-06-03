# Query for routes like: Routes/Tasks/Add

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import login_required

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
    return render_template("index.html")


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

        if not db.execute("INSERT INTO users(username, hash) VALUES(?, ?)",
                          username, generate_password_hash(password)):
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
        tasks = db.execute("SELECT * FROM tasks WHERE user_id=?",
                           session.get("user_id"))

        # Filter the tasks
        tasksCopy = tasks.copy()
        for task in tasksCopy:
            print(task)
            if task["fullfilled"] is None or task["fullfilled"] == 1:
                tasks.remove(task)
        return render_template("tasks/tasks.html", tasks=tasks)
    else:
        # Change the fullfilled state for the task
        db.execute("UPDATE tasks SET fullfilled=1 WHERE id=?",
                   request.form.get("id"))
        return redirect("/tasks")


# Routes/Tasks/Add
@app.route("/tasks/add", methods=["GET", "POST"])
@login_required
def addTask():
    return render_template("tasks/add.html")


# Routes/Tasks/Edit
@app.route("/tasks/edit", methods=["GET", "POST"])
@login_required
def editTask():
    return render_template("tasks/edit.html")


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
    return render_template("profiles/profile.html")


# Routes/Profile/Edit
@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def profileEdit():
    return render_template("profiles/edit.html")


# Routes/Friends
@app.route("/friends", methods=["GET", "POST"])
@login_required
def friends():
    return render_template("friends/friends.html")


# Routes/Friends/Add
@app.route("/friends/add", methods=["GET", "POST"])
@login_required
def friendsAdd():
    return render_template("friends/add.html")


# Routes/Friends/Search
@app.route("/friends/search", methods=["GET", "POST"])
@login_required
def friendsSearch():
    return render_template("friends/search.html")


# Routes/Friends/Search/Results
@app.route("/friends/search/results", methods=["GET", "POST"])
@login_required
def friendsSearchResults():
    return render_template("friends/searchResults.html")


# Routes/Friends/TeamUp
@app.route("/friends/teamUp", methods=["GET", "POST"])
@login_required
def friendsTeamUp():
    return render_template("friends/teamUp.html")


# Routes/Challenges
@app.route("/challenges", methods=["GET", "POST"])
@login_required
def challenges():
    return render_template("challenges/overview.html")


# Routes/Challenges/Accept
@app.route("/challenges/accept", methods=["GET", "POST"])
@login_required
def challengesAccept():
    return render_template("challenges/accept.html")


# Routes/Challenges/Details
@app.route("/challenges/details", methods=["GET", "POST"])
@login_required
def challengesDetails():
    return render_template("challenges/details.html")


# Routes/Challenges/History
@app.route("/challenges/history", methods=["GET", "POST"])
@login_required
def challengesHistory():
    return render_template("challenges/history.html")


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


# Routes/Challenges/Search/Results
@app.route("/challenges/search/results", methods=["GET", "POST"])
@login_required
def challengesResults():
    return render_template("challenges/searchResults.html")