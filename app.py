import sqlite3
import flask
import DataFilter

app = flask.Flask(__name__)

DB_PATH = "database.db"


def get_user_notes(username: str):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.cursor()
        cur.execute(f"SELECT * FROM users WHERE user = '{username}';")
        return cur.fetchall()
    finally:
        conn.close()
        
html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Greeting</title>
</head>
<body>
    {}
</body>
</html>
    """ 

@app.route("/")
def index():
    user = flask.request.args.get("user", "")

    report = DataFilter.strSQLICheck(user)
    print(report.data)
    print(report.status)
    print(report.detections)
    print(report.issecure)
    print(f"{report.processtime/1000000000:.9f}s")
    if not report.issecure:
        return flask.render_template_string(html.format("Restricted"))
    
    if user:
        rows = get_user_notes(user)
    else:
        return flask.render_template_string(html.format("Empty user"))

    if not rows:
        body = f"Hello, (user not found)"
    else:
        body=""
        for i in rows:
            body += f"<p>Hello, {i['user']}! Secret: {i['secret']}</p>"

    return flask.render_template_string(html.format(body))


if __name__ == "__main__":
    app.run(debug=True, port=31337)