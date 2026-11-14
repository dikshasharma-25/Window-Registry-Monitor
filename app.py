from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return """
    <html>
    <head>
        <title>Windows Registry Monitor</title>
    </head>
    <body style="background:#101827; color:white;
                 font-family:Arial; text-align:center;
                 padding:60px;">
        <h1>WINDOWS REGISTRY MONITOR</h1>
        <h2>Project Dashboard</h2>
        <p>Windows Registry Change Monitoring System</p>
        <p>Features:</p>
        <p>Registry Monitoring | Baseline Checking</p>
        <p>Suspicious Activity Detection | Security Alerts</p>
        <p>Timestamped Logging</p>
        <p>Developed using Python</p>
    </body>
    </html>
    """

if __name__ == "__main__":
    app.run()
