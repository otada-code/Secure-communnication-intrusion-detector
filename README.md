# secure-communnication-intrusion-detector
Python flask-secure log in with intrusion detection for cyber defence 
from flask import Flask, render_template, request, redirect, session
import sqlite3, bcrypt, datetime
from collections import defaultdict

app = Flask(__name__)
app.secret_key = 'kdf-secure-key-2026'
failed_attempts = defaultdict(int)
blocked_ips = {}

# Init DB
def init_db():
    conn = sqlite3.connect('secure.db')
    conn.execute('''CREATE TABLE IF NOT EXISTS users
    (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS logs
    (id INTEGER PRIMARY KEY, username TEXT, ip TEXT, time TEXT, status TEXT)''')
    conn.commit()
    conn.close()

@app.route('/', methods=['GET','POST'])
def login():
    ip = request.remote_addr
    # Check if IP blocked
    if ip in blocked_ips:
        return f"Intrusion Detected! IP {ip} blocked for 5 mins. Alert sent to Admin."

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode()

        conn = sqlite3.connect('secure.db')
        cur = conn.cursor()
        cur.execute("SELECT password FROM users WHERE username=?", (username,))
        user = cur.fetchone()

        time_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if user and bcrypt.checkpw(password, user[0].encode()):
            failed_attempts[ip] = 0
            cur.execute("INSERT INTO logs VALUES (NULL,?,?,?,?)", (username, ip, time_now, "SUCCESS"))
            conn.commit()
            session['user'] = username
            return redirect('/dashboard')
        else:
            failed_attempts[ip] += 1
            cur.execute("INSERT INTO logs VALUES (NULL,?,?,?,?)", (username, ip, time_now, "FAILED"))
            conn.commit()
            if failed_attempts[ip] >= 3:
                blocked_ips[ip] = True
                return f"ALERT: 3 Failed attempts from {ip}. System locked. Intrusion logged."
            return "Wrong credentials. Attempt logged."
        conn.close()
    return '''
    <h2>KDF Secure Login</h2>
    <form method=post>
    Username: <input name=username><br>
    Password: <input name=password type=password><br>
    <button>Login</button>
    </form>
    <p>Test user: admin / admin123 (register first via /register)</p>
    '''

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        u = request.form['username']
        p = bcrypt.hashpw(request.form['password'].encode(), bcrypt.gensalt()).decode()
        conn = sqlite3.connect('secure.db')
        conn.execute("INSERT INTO users (username,password) VALUES (?,?)", (u,p))
        conn.commit()
        conn.close()
        return "User registered securely with encryption! Go to /"
    return '<form method=post>User:<input name=username> Pass:<input name=password><button>Register</button></form>'

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/')
    conn = sqlite3.connect('secure.db')
    logs = conn.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 20").fetchall()
    conn.close()
    html = f"<h2>Welcome {session['user']} - Secure Comms Dashboard</h2>"
    html += "<h3>Intrusion Logs (IP Monitoring):</h3><table border=1><tr><th>User</th><th>IP</th><th>Time</th><th>Status</th></tr>"
    for l in logs:
        color = "red" if l[4]=="FAILED" else "green"
        html += f"<tr style=color:{color}><td>{l[1]}</td><td>{l[2]}</td><td>{l[3]}</td><td>{l[4]}</td></tr>"
    html += "</table><br><a href='/'>Logout</a>"
    return html

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
