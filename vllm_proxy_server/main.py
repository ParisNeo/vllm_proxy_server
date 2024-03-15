import configparser
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs
from queue import Queue
import requests
import threading
import argparse
import base64
from ascii_colors import ASCIIColors
from pathlib import Path
import csv
import datetime

class UserManager:
    def __init__(self, users_list):
        self.authorized_users = self._get_authorized_users(users_list)

    def _get_authorized_users(self, filename):
        authorized_users = {}
        with open(filename, 'r') as f:
            lines = f.readlines()
        for line in lines:
            if line == "":
                continue
            try:
                user, key = line.strip().split(':')
                authorized_users[user] = key
            except:
                ASCIIColors.red(f"User entry broken: {line.strip()}")
        return authorized_users

    def validate_user_and_key(self, user, key):
        return self.authorized_users.get(user) == key

class Server:
    def __init__(self, config, user_manager, log_path, num_threads=10):
        self.config = config
        self.user_manager = user_manager
        self.log_path = log_path
        self.num_threads = num_threads

    def start(self):
        class RequestHandler(BaseHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                self.user_manager = self.server.user_manager
                BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

            def add_access_log_entry(self, event, user, ip_address, access, server, nb_queued_requests_on_server, error=""):
                log_file_path = Path(self.server.log_path)

                if not log_file_path.exists():
                    with open(log_file_path, mode='w', newline='') as csvfile:
                        fieldnames = ['time_stamp', 'event', 'user_name', 'ip_address', 'access', 'server', 'nb_queued_requests_on_server', 'error']
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                        writer.writeheader()

                with open(log_file_path, mode='a', newline='') as csvfile:
                    fieldnames = ['time_stamp', 'event', 'user_name', 'ip_address', 'access', 'server', 'nb_queued_requests_on_server', 'error']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    row = {'time_stamp': str(datetime.datetime.now()), 'event': event, 'user_name': user, 'ip_address': ip_address, 'access': access, 'server': server, 'nb_queued_requests_on_server': nb_queued_requests_on_server, 'error': error}
                    writer.writerow(row)

            def _validate_user_and_key(self):
                auth_header = self.headers.get('Authorization')

                if not auth_header or not auth_header.startswith('Bearer '):
                    return False

                token = auth_header.split(' ')[1]
                user, key = token.split(':')
                return self.user_manager.validate_user_and_key(user, key)

            def do_GET(self):
                if not self._validate_user_and_key():
                    self.send_response(403)
                    self.end_headers()
                    return

                client_ip, client_port = self.client_address
                self.add_access_log_entry(event="gen_request", user=self.user_manager.user, ip_address=client_ip, access="Authorized", server=self.server.config[0][0], nb_queued_requests_on_server=0)

                que = Queue()
                que.put_nowait(1)

                try:
                    response = self._process_request()
                    self.send_response(response.status_code)
                    self.send_header('Content-type', response.headers['content-type'])
                    self.end_headers()
                    self.wfile.write(response.content)
                except Exception as ex:
                    self.add_access_log_entry(event="gen_error", user=self.user_manager.user, ip_address=client_ip, access="Authorized", server=self.server.config[0][0], nb_queued_requests_on_server=que.qsize(), error=str(ex))
                finally:
                    que.get_nowait()
                    self.add_access_log_entry(event="gen_done", user=self.user_manager.user, ip_address=client_ip, access="Authorized", server=self.server.config[0][0], nb_queued_requests_on_server=que.qsize())

            def do_POST(self):
                if not self._validate_user_and_key():
                    self.send_response(403)
                    self.end_headers()
                    return

                client_ip, client_port = self.client_address
                self.add_access_log_entry(event="gen_request", user=self.user_manager.user, ip_address=client_ip, access="Authorized", server=self.server.config[0][0], nb_queued_requests_on_server=0)

                que = Queue()
                que.put_nowait(1)

                try:
                    response = self._process_request()
                    self.send_response(response.status_code)
                    self.send_header('Content-type', response.headers['content-type'])
                    self.end_headers()
                    self.wfile.write(response.content)
                except Exception as ex:
                    self.add_access_log_entry(event="gen_error", user=self.user_manager.user, ip_address=client_ip, access="Authorized", server=self.server.config[0][0], nb_queued_requests_on_server=que.qsize(), error=str(ex))
                finally:
                    que.get_nowait()
                    self.add_access_log_entry(event="gen_done", user=self.user_manager.user, ip_address=client_ip, access="Authorized", server=self.server.config[0][0], nb_queued_requests_on_server=que.qsize())

            def _process_request(self):
                url = urlparse(self.path)
                path = url.path
                get_params = parse_qs(url.query) or {}

                if self.command == "POST":
                    content_length = int(self.headers['Content-Length'])
                    post_data = self.rfile.read(content_length)
                    post_params = parse_qs(post_data.decode('utf-8'))
                else:
                    post_params = {}

                # Find the server with the lowest number of queue entries.
                min_queued_server = self.server.config[0]
                for server in self.server.config:
                    cs = server[1]
                    if cs['queue'].qsize() < min_queued_server[1]['queue'].qsize():
                        min_queued_server = server

                # Apply the queuing mechanism only for a specific endpoint.
                que = min_queued_server[1]['queue']
                client_ip, client_port = self.client_address
                self.add_access_log_entry(event="gen_request", user=self.user_manager.user, ip_address=client_ip, access="Authorized", server=min_queued_server[0], nb_queued_requests_on_server=que.qsize())
                que.put_nowait(1)

                try:
                    response = requests.request(self.command, min_queued_server[1]['url'] + path, params=get_params, data=post_params)
                    return response
                except Exception as ex:
                    self.add_access_log_entry(event="gen_error", user=self.user_manager.user, ip_address=client_ip, access="Authorized", server=min_queued_server[0], nb_queued_requests_on_server=que.qsize(), error=str(ex))
                    raise ex
                finally:
                    que.get_nowait()
                    self.add_access_log_entry(event="gen_done", user=self.user_manager.user, ip_address=client_ip, access="Authorized", server=min_queued_server[0], nb_queued_requests_on_server=que.qsize())

        class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
            def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
                self.num_threads = self.server.num_threads
                HTTPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)

        print('Starting server')
        self.server = ThreadedHTTPServer(('', self.config['port']), RequestHandler)
        print(f'Running server on port {self.config["port"]}')
        self.server.serve_forever()

class VllmProxyServer:
    def __init__(self, config_file, users_list, log_path, num_threads=10):
        self.config = get_config(config_file)
        self.user_manager = UserManager(users_list)
        self.log_path = log_path
        self.num_threads = num_threads

    def start(self):
        self.server = Server(self.config, self.user_manager, self.log_path, self.num_threads)
        self.server.start()

def get_config(filename):
    config = configparser.ConfigParser()
    config.read(filename)
    return [(name, {'url': config[name]['url'], 'queue': Queue()}) for name in config.sections()]

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default="config.ini", help='Path to the config file')
    parser.add_argument('--users_list', default="authorized_users.txt", help='Path to the users list file')
    parser.add_argument('--log_path', default="access_log.txt", help='Path to the access log file')
    parser.add_argument('--port', type=int, default=8000, help='Port number for the server')
    parser.add_argument('--num_threads', type=int, default=10, help='Number of worker threads for the server')
    args = parser.parse_args()

    print(f"Configuration file: {args.config}")
    print(f"Users list file: {args.users_list}")
    print(f"Access log file: {args.log_path}")
    print(f"Port number: {args.port}")
    print(f"Number of worker threads: {args.num_threads}")

    VllmProxyServer(args.config, args.users_list, args.log_path, args.num_threads).start()
