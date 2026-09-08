from app import create_app
import webbrowser
import threading
import os

app = create_app()

def open_browser():
    webbrowser.open_new("http://localhost:5000")

if __name__ == '__main__':
    # Prevent running browser twice on Flask auto-reload
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        threading.Timer(1.0, open_browser).start()

    app.run(host="0.0.0.0", debug=True, port=5000)
