from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class DemoRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"Demo server received the request.\n")

    def log_message(self, format, *args):
        print(f"{self.client_address[0]} - {format % args}")


def main():
    server = ThreadingHTTPServer(("127.0.0.1", 8080), DemoRequestHandler)
    print("Demo HTTP server listening on http://127.0.0.1:8080")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping demo HTTP server.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
