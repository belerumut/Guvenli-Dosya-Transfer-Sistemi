from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == "/test":
            query = parse_qs(parsed_path.query)
            veri = query.get("veri", ["yok"])[0]
            
            # İstek başarılı, 200 dön
            self.send_response(200)
            self.send_header('Content-type', 'text/plain; charset=utf-8')
            self.end_headers()
            response_text = f"Veri alındı: {veri}"
            self.wfile.write(response_text.encode('utf-8'))
        else:
            # Diğer istekler için 404
            self.send_response(404)
            self.end_headers()
            self.wfile.write("Sayfa bulunamadı.".encode("utf-8"))

def run(server_class=HTTPServer, handler_class=MyHandler):
    server_address = ('', 8000)  # Tüm IP'lerden gelen 8000 portu
    httpd = server_class(server_address, handler_class)
    print("HTTP server çalışıyor, port 8000...")
    httpd.serve_forever()

if __name__ == '__main__':
    run()
