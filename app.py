from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import bcrypt
from datetime import datetime

app = Flask(__name__)
app.secret_key = "supersecretkey"

# --- DB Helper ---
def get_db_connection():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn

# --- Create tables ---
def init_db():
    with get_db_connection() as conn:
        c = conn.cursor()
        
        # Create users table first (was missing)
        c.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )""")
        
        # Fixed results table (missing closing parenthesis and users table reference)
        c.execute("""CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            left_eye_score TEXT,
            right_eye_score TEXT,
            test_type TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            notes TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )""")
        
        # Create admin user if not exists
        c.execute("SELECT * FROM users WHERE username=?", ('admin',))
        admin_user = c.fetchone()
        if not admin_user:
            admin_password = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt())
            c.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)", 
                     ('admin', admin_password, 1))
        
        conn.commit()

# Initialize database on startup
init_db()

# --- Routes ---
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"].encode("utf-8")
        hashed = bcrypt.hashpw(password, bcrypt.gensalt())

        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
            conn.commit()
            flash("Registration successful! Please login.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already exists!", "danger")
        finally:
            conn.close()
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"].encode("utf-8")

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()

        if user and bcrypt.checkpw(password, user["password"]):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["is_admin"] = user["is_admin"]
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials!", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM results WHERE user_id=? ORDER BY timestamp DESC", (session["user_id"],))
    results = c.fetchall()
    conn.close()

    return render_template("dashboard.html", results=results, username=session["username"])

@app.route("/test", methods=["GET", "POST"])
def test():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        # Get the auto-detected results from the test
        left_eye_score = request.form.get("left_eye_score", "6/6")
        right_eye_score = request.form.get("right_eye_score", "6/6") 
        test_type = request.form.get("test_type", "Distance")
        notes = request.form.get("notes", "Auto-saved from digital eye test")
        
        # Auto-determine acuity level based on scores
        acuity_level = "Excellent"
        if "6/9" in left_eye_score or "6/9" in right_eye_score:
            acuity_level = "Good"
        elif "6/12" in left_eye_score or "6/12" in right_eye_score:
            acuity_level = "Mild Concern"
        elif "6/18" in left_eye_score or "6/18" in right_eye_score:
            acuity_level = "Moderate Concern"
        elif "6/24" in left_eye_score or "6/24" in right_eye_score:
            acuity_level = "Significant Concern"

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("INSERT INTO results (user_id, left_eye_score, right_eye_score, test_type, notes) VALUES (?, ?, ?, ?, ?)", 
                 (session["user_id"], left_eye_score, right_eye_score, test_type, f"{acuity_level} - {notes}"))
        conn.commit()
        conn.close()
        
        flash(f"Test completed! Results saved: {acuity_level} vision", "success")
        return redirect(url_for("dashboard"))

    return render_template("test.html")

@app.route("/admin")
def admin():
    if "user_id" not in session or session.get("is_admin") != 1:
        flash("Access denied! Admins only.", "danger")
        return redirect(url_for("dashboard"))

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
        SELECT r.id, u.username, r.left_eye_score, r.right_eye_score, r.test_type, r.timestamp, r.notes
        FROM results r
        JOIN users u ON r.user_id = u.id
        ORDER BY r.timestamp DESC
    """)
    records = c.fetchall()
    conn.close()

    return render_template("admin.html", records=records)

@app.route("/delete_result/<int:result_id>", methods=["POST"])
def delete_result(result_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    conn = get_db_connection()
    c = conn.cursor()
    
    # Check if user owns the result or is admin
    c.execute("SELECT user_id FROM results WHERE id=?", (result_id,))
    result = c.fetchone()
    
    if result and (result["user_id"] == session["user_id"] or session.get("is_admin") == 1):
        c.execute("DELETE FROM results WHERE id=?", (result_id,))
        conn.commit()
        flash("Result deleted successfully!", "success")
    else:
        flash("Access denied!", "danger")
    
    conn.close()
    
    if session.get("is_admin") == 1:
        return redirect(url_for("admin"))
    else:
        return redirect(url_for("dashboard"))

@app.route("/records")
def records():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM results WHERE user_id=? ORDER BY timestamp DESC", (session["user_id"],))
    results = c.fetchall()
    conn.close()

    return render_template("records.html", results=results)

if __name__ == "__main__":
    app.run(debug=True)