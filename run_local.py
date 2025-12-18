from http.server import HTTPServer
from api.telegram import Handler  # импортируем твой Handler

if __name__ == "__main__":
    host = "0.0.0.0"
    port = 8000
    print(f"Listening on http://{host}:{port}/api/telegram (local)")
    httpd = HTTPServer((host, port), Handler)
    httpd.serve_forever()
