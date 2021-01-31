import http.server, ssl

class RequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write("<html><head><title>Environment Test</title></head></html>\n".encode("utf-8"))

server_address = ('localhost', 4443)

context = ssl.SSLContext(ssl.PROTOCOL_TLS)
context.load_cert_chain(certfile='localhost.pem', password=(lambda: "third-wheel"))
httpd = http.server.HTTPServer(server_address, RequestHandler)
httpd.socket = context.wrap_socket(httpd.socket,
                               server_hostname='my_test_site.com'
                               )
httpd.serve_forever()
