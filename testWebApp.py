import sqlite3, DataFilter, os
from flask import Flask, request, render_template_string, redirect, url_for, session

app = Flask(__name__)
app.secret_key = "ungu3ss4b13_53cr3t_14b_k3y"
DB_PATH = "database.db"
prot = False

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DROP TABLE IF EXISTS users")
        conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, note_title TEXT, notes TEXT)")
        conn.execute("INSERT INTO users (note_title, notes) VALUES ('Flag', 'DF{SQL_INJECTION_SUCCESS}')")
        conn.commit()

@app.route("/")
def index():
    return render_template_string("""
    <!DOCTYPE html><html><head><title>DF Lab</title>
    <style>
        body { font-family: sans-serif; max-width: 900px; margin: 40px auto; background: #f0f2f5; }
        .card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px; }
        nav a { margin-right: 20px; text-decoration: none; color: #1a73e8; font-weight: bold; }
        .prot-on { color: green; } .prot-off { color: red; }
        button { padding: 10px 20px; border: none; border-radius: 5px; background: #1a73e8; color: white; cursor: pointer; }
    </style></head><body>
    <div class="card">
        <nav><a href="/">Home</a><a href="/sqli">SQLi</a><a href="/ssti">SSTI</a><a href="/xss">XSS</a></nav>
        <hr>
        <p>Global Protection: <b class="{{ 'prot-on' if prot else 'prot-off' }}">{{ 'ENABLED' if prot else 'DISABLED' }}</b></p>
        <form action="/toggle" method="POST"><button type="submit">Switch Protection</button></form>
    </div>
    <div class="card"><h1>Web-DataFilter Testbed</h1><p>Test your payloads with and without the DataFilter module.</p></div>
    </body></html>
    """, prot=prot)

@app.route("/toggle", methods=["POST"])
def toggle():
    global prot
    prot = not prot
    return redirect(request.referrer or url_for("index"))

@app.route("/sqli", methods=["GET", "POST"])
def sqli():
    result = None
    error = None
    if request.method == "POST":
        q = request.form.get("q", "")
        if prot:
            check = DataFilter.strSQLICheck(q)
            print(check.detections)
            if not check.issecure: error = f"Blocked by DataFilter: {check.detections}"
            else:
                db = get_db()
                result = db.execute('SELECT notes FROM users WHERE note_title = "{q}"').fetchone()
        else:
            db = get_db()
            try:
                sql = f'SELECT notes FROM users WHERE note_title = "{q}"'
                result = db.execute(sql).fetchone()
            except Exception as e: error = str(e)
    return render_template_string("""
    <div class="card">
        <a href="/">← Back</a><h2>SQL Injection</h2>
        <form method="POST"><input name="q" placeholder="Note Title"><button type="submit">Search</button></form>
        {% if error %}<p style="color:red">{{error}}</p>{% endif %}
        {% if result %}<p>Note content: <b>{{result['notes']}}</b></p>{% endif %}
    </div>
    """, result=result, error=error)

@app.route("/ssti", methods=["GET", "POST"])
def ssti():
    rendered = ""
    if request.method == "POST":
        tpl = request.form.get("tpl", "")
        print(tpl)
        if prot:
            check = DataFilter.strSSTICheck(tpl)
            print(check.detections)
            if not check.issecure: rendered = f"Blocked by DataFilter: {check.detections}"
            else: 
                try: rendered = render_template_string(tpl)
                except Exception as e: rendered = str(e)
        else:
            try: rendered = render_template_string(tpl)
            except Exception as e: rendered = str(e)
    return render_template_string("""
    <div class="card">
        <a href="/">← Back</a><h2>SSTI RCE</h2>
        <form method="POST"><textarea name="tpl" style="width:100%" rows="5">{{request.form.get('tpl','')}}</textarea><br><button type="submit">Render</button></form>
        <div style="margin-top:20px; border: 1px solid #ccc; padding: 10px;">{{rendered}}</div>
    </div>
    """, rendered=rendered)

@app.route("/xss", methods=["GET", "POST"])
def xss():
    if request.method == "POST":
        title = request.form.get("t", "")
        content = request.form.get("c", "")
        if prot:
            report1 = DataFilter.strMultCheck(title)
            report2 = DataFilter.strMultCheck(content)
            print(report1["SQLI"].detections)
            print(report1["SSTI"].detections)
            print(report1["XSS"].detections)
            print("- - - - - - - - - - - - - - - - - - - -")
            print(report2["SQLI"].detections)
            print(report2["SSTI"].detections)
            print(report2["XSS"].detections)
            if report1["total_issecure"] and report2["total_issecure"]:
                db = get_db(); db.execute(f"INSERT INTO users (note_title, notes) VALUES ('{title}', '{content}')"); db.commit()
        else:
            db = get_db(); db.execute(f"INSERT INTO users (note_title, notes) VALUES ('{title}', '{content}')"); db.commit()
    
    db = get_db()
    notes = db.execute("SELECT * FROM users").fetchall()
    return render_template_string("""
    <div class="card">
        <a href="/">← Back</a><h2>Stored XSS</h2>
        <form method="POST"><input name="t" placeholder="Title"><input name="c" placeholder="Content"><button type="submit">Add</button></form>
        <hr>
        {% for n in notes %}
            <div style="border-bottom:1px solid #eee">
                <h4>{{ n['note_title'] | safe if not prot else n['note_title'] }}</h4>
                <p>{{ n['notes'] | safe if not prot else n['notes'] }}</p>
            </div>
        {% endfor %}
    </div>
    """, notes=notes, prot=prot)

if __name__ == "__main__":
    DataFilter.set_sqli_timeout(0.15)
    DataFilter.set_ssti_timeout(0.2)
    DataFilter.set_xss_timeout(0.2)
    if not os.path.exists(DB_PATH): init_db()
    app.run(debug=True, port=12000)
