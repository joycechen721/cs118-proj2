import os
import shutil
import subprocess
import traceback
import time
import random

SERVER_PORT = random.randint(40000, 45000)

class CompileTest:
    def __init__(self):
        self.success = False
        self.status = ""

    def run(self):
        try:
            os.remove('project/server')
            os.remove('project/client')
        except OSError:
            pass

        try:
            subprocess.run(['make', '-C', 'project'],
                           capture_output=True, check=True, text=True, timeout=30)
        except subprocess.TimeoutExpired:
            self.status = 'Compilation timeout'
            return
        except subprocess.CalledProcessError as err:
            self.status = 'Compilation Error: ' + err.stderr
            return

        if not os.path.exists('project/server'):
            self.status = 'Compilation failed: no server binary'
            return
        if not os.path.exists('project/client'):
            self.status = 'Compilation failed: no client binary'
            return

        self.success = True

    def get_result(self):
        return {
            'status': 'passed' if self.success else 'failed',
            'name': 'Compilation',
            'output': self.status,
            'visibility': 'visible'
        }


class TransferTest:
    name: str
    success: bool = False
    status: str = ""
    max_score: int = 0
    cli_file: str
    server_file: str
    security: bool = False
    visible: bool = False
    should_fail: bool = False
    use_reference_client: bool = False
    use_reference_server: bool = False

    proxy_loss: float = 0
    proxy_reorder: float = 0
    test_time: int = 3

    server_priv_key: str
    server_cert: str
    ca_pub_key: str
    security_mac: bool = False

    def __init__(
            self,
            name: str,
            score: int,
            cli_file: str,
            server_file: str,
            security: bool = False,
            visible: bool = False,
            should_fail: bool = False,
            use_reference_client: bool = False,
            use_reference_server: bool = False,
            proxy_loss: float = 0,
            proxy_reorder: float = 0,
            test_time: int = 3,

            server_priv_key: str = 'other/priv_key.bin',
            server_cert: str = 'other/cert.bin',
            ca_pub_key: str = 'other/ca_pub_key.bin',
            security_mac: bool = False):

        self.name = name
        self.max_score = score
        self.cli_file = cli_file
        self.server_file = server_file
        self.security = security
        self.visible = visible
        self.should_fail = should_fail

        self.use_reference_client = use_reference_client
        self.use_reference_server = use_reference_server

        self.proxy_loss = proxy_loss
        self.proxy_reorder = proxy_reorder
        self.test_time = test_time

        self.server_priv_key = server_priv_key
        self.server_cert = server_cert
        self.ca_pub_key = ca_pub_key
        self.security_mac = security_mac

    def run(self):
        self.run_i()

        if self.should_fail:
            if self.success:
                self.status = 'Transfer passed but should have failed'
                self.success = False
            else:
                self.success = True

    def run_i(self):
        global SERVER_PORT
        SERVER_PORT += 1
        self.success = False

        try:
            server_input = open(self.server_file, 'rb')
            server_output = open('server_out.tmp', 'wb')
            client_input = open(self.cli_file, 'rb')
            client_output = open('client_out.tmp', 'wb')

            client_exec = 'project/client' if not self.use_reference_client else 'reference/client'
            server_exec = 'project/server' if not self.use_reference_server else 'reference/server'

            proxy: subprocess.Popen = None
            CONNECT_PORT = SERVER_PORT
            if self.proxy_loss > 0 or self.proxy_reorder > 0:
                CONNECT_PORT = SERVER_PORT + 1000
                proxy = subprocess.Popen(['python3', 'other/proxy.py', str(CONNECT_PORT), str(SERVER_PORT), str(self.proxy_loss), str(self.proxy_reorder)])
                time.sleep(1)

            # Start server and client
            sec_flag = '1' if self.security else '0'
            sec_mac_flag = '1' if self.security_mac else '0'

            server_cmd = [server_exec, sec_flag, str(SERVER_PORT), self.server_priv_key, self.server_cert]
            client_cmd = [client_exec, sec_flag, 'localhost', str(CONNECT_PORT), self.ca_pub_key]

            if self.use_reference_server:
                server_cmd += [sec_mac_flag]
            if self.use_reference_client:
                client_cmd += [sec_mac_flag]

            time.sleep(1)
            server = subprocess.Popen(server_cmd, stdin=server_input, stdout=server_output)
            time.sleep(0.5)
            client = subprocess.Popen(client_cmd, stdin=client_input, stdout=client_output)

            # Run until timeout; checking if processes died to restart
            start = time.time()
            while time.time() - start < self.test_time:
                if server.poll():
                    server = subprocess.Popen(server_cmd, stdin=server_input, stdout=server_output)
                    server_input.seek(0, 0)
                    server_output.seek(0, 0)
                    time.sleep(1)
                    start = time.time()
                if client.poll(): 
                    client = subprocess.Popen(client_cmd, stdin=client_input, stdout=client_output)
                    client_input.seek(0, 0)
                    client_output.seek(0, 0)
                    time.sleep(1)
                    start = time.time()

            # Graceful flush?
            client.send_signal(subprocess.signal.SIGINT)
            server.send_signal(subprocess.signal.SIGINT)
            time.sleep(0.5)

            # Close processes
            client.kill()
            server.kill()
            if proxy:
                proxy.kill()

            # Close files
            server_output.flush()
            client_output.flush()
            server_output.close()
            client_output.close()
            server_input.close()
            client_input.close()

            # Compare output
            if subprocess.run(['diff', self.cli_file, 'server_out.tmp']).returncode != 0:
                self.status = 'client -> server transfer failed'
                return
            if subprocess.run(['diff', self.server_file, 'client_out.tmp']).returncode != 0:
                self.status = 'server -> client transfer failed'
                return

            self.status = 'Transfer successful'
            self.success = True
        except Exception as e:
            self.status = traceback.format_exception_only(type(e), e)[-1]
            self.success = False
        finally:
            try:
                os.remove('server_out.tmp')
                os.remove('client_out.tmp')
            except OSError:
                pass

    def get_result(self):
        return {
            'status': 'passed' if self.success else 'failed',
            'name': self.name,
            'output': self.status,
            'visibility': 'visible' if self.visible else 'after_published',
            'score': self.max_score if self.success else 0,
            'max_score': self.max_score,
        }