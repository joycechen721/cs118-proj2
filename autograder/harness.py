#! /usr/bin/env python3
# Version: 0.15.1

import grequests
import requests
import os
import time
import os.path
import shutil
import errno
import json
import subprocess
import sys
import traceback
import codecs
import logging
import re
from threading import Timer


class HTTPFailure(Exception):
    pass


def safe_request(method, url, attempts=5, timeout=30, **kwargs):
    attempt = 0
    while attempt < attempts:
        try:
            response = requests.request(method, url, timeout=timeout, **kwargs)
            return response
        except:
            attempt += 1
            time.sleep(1)
    raise HTTPFailure()


def safe_get(url, attempts=5, timeout=30, **kwargs):
    return safe_request('get', url, attempts, timeout, **kwargs)


def safe_post(url, attempts=5, timeout=60, **kwargs):
    return safe_request('post', url, attempts, timeout, **kwargs)


def safe_patch(url, attempts=5, timeout=60, **kwargs):
    return safe_request('patch', url, attempts, timeout, **kwargs)


def safe_delete(url, attempts=5, timeout=60, **kwargs):
    return safe_request('delete', url, attempts, timeout, **kwargs)


def grequests_exception_handler(request, exception):
    print("Exception in grequests:")
    print(exception)
    raise HTTPFailure()


def safe_parallel_get(urls, attempts=2, timeout=30):
    attempt = 0
    while attempt < attempts:
        try:
            requests = (grequests.get(url, timeout=timeout) for url in urls)
            responses = grequests.map(
                requests,
                size=10,
                exception_handler=grequests_exception_handler
            )
            return responses
        except:
            attempt += 1
            time.sleep(1)
    raise HTTPFailure()


def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

VERSION_START_STRING = "# Version: "
def version(file_string):
    """ Returns the version from the second line, which looks like
    # Version: 0.10.0
    """
    lines = file_string.split("\n")
    for line in lines:
        if line.startswith(VERSION_START_STRING):
            version_string = line[len(VERSION_START_STRING):]
            break
    else:
        return None
    version_array = []
    for part in version_string.split("."):
        if part.isdigit() is False:
            return None
        version_array.append(int(part))
    return version_array


def is_at_least_version(new, minimum_version):
    if new is None:
        return False
    for digit in range(0, max(len(new), len(minimum_version))):
        if digit >= len(new):
            new_digit = 0
        else:
            new_digit = new[digit]
        if digit >= len(minimum_version):
            minimum_version_digit = 0
        else:
            minimum_version_digit = minimum_version[digit]
        # If new digit matches old, keep checking next digit
        if new_digit == minimum_version_digit:
            continue
        # If new digit is greater, the version is higher, else, it's lower
        return new_digit > minimum_version_digit
    # This case is only reached when the digits are exactly the same
    return True

SSH_LOG_FILE = "/etc/ssh_log"
def logged_in_users_count():
    if os.path.isfile(SSH_LOG_FILE) is False:
        return 0
    # Safe extract the first UUID if it exists on the line otherwise return None
    extract_uuid = lambda line: next(iter(re.findall(r'^\[([0-9a-zA-Z-]+)\]', line)), None)
    with open(SSH_LOG_FILE, 'r') as f:
        stdout = f.read()
        lines = stdout.split('\n')
        open_sessions = set()
        for line in lines:
            line_uuid = extract_uuid(line)
            if "STARTED" in line:
                if line_uuid:
                    open_sessions.add(line_uuid)
            elif ("ENDED" in line) or ("DISCONNECTED" in line):
                if line_uuid and line_uuid in open_sessions:
                    open_sessions.remove(line_uuid)
        return len(open_sessions)

def kill_proc(proc, timed_out):
    timed_out["value"] = True
    proc.kill()


def timeout_process(proc, timeout_seconds):
    timed_out = {"value": False}
    timer = Timer(timeout_seconds, kill_proc, [proc, timed_out])

    try:
        timer.start()
        start_time = time.time()
        proc.wait()
        end_time = time.time()
    finally:
        timer.cancel()
    elapsed_time = end_time - start_time

    return proc.returncode, elapsed_time, timed_out["value"]

LAST_LOGOUT_TIMEOUT = 10
def timeout_sshd(proc, timeout_seconds):
    timed_out = {"value": False}
    timer = Timer(timeout_seconds, kill_proc, [proc, timed_out])
    user_logged_out_time = None
    user_has_logged_in = False

    try:
        timer.start()
        start_time = time.time()
        while True:
            proc.wait()
            liuc = logged_in_users_count()
            if user_has_logged_in and liuc == 0:
                # No one is logged in and we have timed out
                if user_logged_out_time and time.time() > user_logged_out_time + LAST_LOGOUT_TIMEOUT:
                    logging.debug("0 logged in users! Killing....")
                    proc.kill()
                    break
                # No one is logged in and we have not timed out yet
                elif user_logged_out_time is None:
                    logging.debug(f"All users logged out! Timing out in {LAST_LOGOUT_TIMEOUT} seconds")
                    user_logged_out_time = time.time()
                # No one is logged in and we have set a timeout
                else:
                    logging.debug("All users logged out! Timing out soon if no one logs back in!")
            else: # user has not logged in OR logged in user count > 0
                # Set if we have seen a user log in
                if liuc > 0:
                    user_has_logged_in = True
                if user_has_logged_in:
                    logging.debug(f"{liuc} user(s) are still logged in! Keeping session alive...")
                    user_logged_out_time = None
                else:
                    logging.debug(f"Waiting for user to log in!")
            time.sleep(1)
        end_time = time.time()
    finally:
        timer.cancel()
    elapsed_time = end_time - start_time

    return proc.returncode, elapsed_time, timed_out["value"]

def pretty_time_delta(seconds):
    seconds = int(seconds)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    if days > 0:
        return '%dd%dh%dm%ds' % (days, hours, minutes, seconds)
    elif hours > 0:
        return '%dh%dm%ds' % (hours, minutes, seconds)
    elif minutes > 0:
        return '%dm%ds' % (minutes, seconds)
    else:
        return '%ds' % (seconds,)

def warn_user_for_timeout(remaining_seconds):
    warning_msg = f"[Warning] Your SSH session will end in {pretty_time_delta(remaining_seconds)}"
    print(f"Sending warning message: {warning_msg}")
    os.system(f"echo {warning_msg} | wall -n")

def clean_string(string):
    """Replaces null characters which are found in some autograder output"""
    return string.replace('\x00', u'\uFFFD')


MAX_OUTPUT_LENGTH = 100000
TRUNCATION_MESSAGE = "[...(truncated)...]"


def truncate_output(output):
    """Truncate output so that it is shorter than MAX_OUTPUT_LENGTH"""
    if output is not None and len(output) > MAX_OUTPUT_LENGTH:
        half_of_max_output_length = \
            (MAX_OUTPUT_LENGTH - len(TRUNCATION_MESSAGE)) // 2
        output_start = output[:half_of_max_output_length]
        output_end = output[len(output) - half_of_max_output_length:]
        return f"{output_start}{TRUNCATION_MESSAGE}{output_end}"
    return output


def truncate_results(results):
    if results is None:
        return
    if 'output' in results:
        results['output'] = truncate_output(results['output'])
    if results.get('tests'):
        for test in results['tests']:
            if 'output' in test:
                test['output'] = truncate_output(test['output'])

class AutograderHarness(object):
    def __init__(self):
        self._devel = os.getenv("DEVEL")
        self.elapsed_time = 0
        self.raw_results = ""
        self.submission_path = "/autograder/submission"
        self.results_path = "/autograder/results"

    def prepare_submission(self):
        shutil.rmtree(self.submission_path, ignore_errors=True)
        os.mkdir(self.submission_path)

        shutil.rmtree(self.results_path, ignore_errors=True)
        os.mkdir(self.results_path)

    def load_payload(self):
        if self._devel:
            self._load_devel_payload()
        else:
            self._load_payload()
        os.environ.pop('START_SSHD', None)
        os.environ.pop('AUTHENTICATION_TOKEN', None)

    def _load_devel_payload(self):
        self._load_payload()
        self.submit_results_url = self.submission_url[0:-5] + "/submit_results"

    def _load_payload(self):
        self.authentication_token = os.getenv("AUTHENTICATION_TOKEN")
        self.submission_url = os.getenv("SUBMISSION_URL")
        self.submit_results_url = os.getenv("SUBMIT_RESULTS_URL")
        self.asset_host = os.getenv("ASSET_HOST")
        self.timeout_seconds = int(os.getenv("TIMEOUT_SECONDS", default=20 * 60))
        self.start_sshd = os.getenv("START_SSHD") == 'true'
        self.sshd_timeout_warning_seconds = int(os.getenv("SSHD_TIMEOUT_WARNING_SECONDS", default=5 * 60))
        self.authorized_keys = os.getenv("AUTHORIZED_KEYS")

        basic_auth = os.getenv("BASIC_AUTH")
        if basic_auth is not None:
            self.basic_auth = tuple(basic_auth.split(":"))
        else:
            self.basic_auth = None

    def report_status(self, status):
        kwargs = {}
        if self.basic_auth is not None:
            kwargs["auth"] = self.basic_auth

        kwargs["headers"] = {"access-token": self.authentication_token}
        payload = {
            "programming_assignment_submission": {
                "status": status
            }
        }
        kwargs["json"] = payload
        safe_patch(self.submission_url, **kwargs)

    def report_ssh_status(self, status):
        ssh_session_url = self.submission_url[0:-5] + "/ssh_session"
        kwargs = {}
        if self.basic_auth is not None:
            kwargs["auth"] = self.basic_auth

        kwargs["headers"] = {"access-token": self.authentication_token}
        payload = {}
        kwargs["json"] = payload
        if status == 'started':
            safe_patch(ssh_session_url, **kwargs)
        elif status == 'stopped':
            safe_delete(ssh_session_url, **kwargs)

    def report_failure(self, error_code, error_message, output_message, stdout=""):
        kwargs = {}
        if self.basic_auth is not None:
            kwargs["auth"] = self.basic_auth

        kwargs["headers"] = {"access-token": self.authentication_token}
        results = {
            "score": 0,
            "output": output_message,
        }

        payload = {
                    "programming_assignment": {
                        "stdout": stdout,
                        "results": results,
                        "error_code": error_code,
                        "error_message": error_message,
                        "elapsed_time": self.elapsed_time
                    }
                  }

        kwargs["json"] = payload

        safe_post(self.submit_results_url, **kwargs)
        sys.exit(1)

    def report_http_failure(self, error_message):
        output_message = "The autograder failed to execute correctly. Please try submitting it again. Contact us at help@gradescope.com if the autograder continues to fail."
        self.report_failure('http', error_message, output_message)

    def report_autograder_failure(self, error_message, stdout):
        output_message = "The autograder failed to execute correctly. Please ensure that your submission is valid. Contact your course staff for help in debugging this issue. Make sure to include a link to this page so that they can help you most effectively."
        self.report_failure('autograder', error_message, output_message, stdout)

    def fetch_submission(self):
        print("Fetching submission")

        kwargs = {}
        if self.basic_auth is not None:
            kwargs["auth"] = self.basic_auth
        kwargs["headers"] = {"access-token": self.authentication_token}

        response = safe_get(self.submission_url, **kwargs)

        self.submission_json = response.json()
        self.write_metadata()
        self.fetch_files()

    def prepare_file_metadata(self):
        self.files = []
        for file in self.submission_json['files']:
            url = file['url']
            if url[0] == '/' and self.asset_host:
                url = self.asset_host + url

            path = file['path']
            local_path = os.path.join(self.submission_path, path)

            file['url'] = url
            file['path'] = local_path

            self.files.append(file)

    def fetch_files(self):
        self.prepare_file_metadata()

        print("Fetching files...")
        urls = [f['url'] for f in self.files]
        responses = safe_parallel_get(urls)

        for file, response in zip(self.files, responses):
            path = file['path']
            mkdir_p(os.path.dirname(path))
            with open(path, 'wb') as f:
                f.write(response.content)

        print("Files downloaded.")

    def write_metadata(self):
        with open('/autograder/submission_metadata.json', 'w') as f:
            metadata = {
                "id": self.submission_json['id'],
                "users": self.submission_json['active_users'],
                "created_at": self.submission_json["created_at"],
                "assignment_id": self.submission_json.get("assignment_id"),
                "assignment": self.submission_json.get("assignment"),
                "submission_method": self.submission_json.get("submission_method"),
                "previous_submissions": self.submission_json['previous_submissions']
            }
            json.dump(metadata, f)

    def run_autograder(self):
        print("Running autograder.")
        with open('/autograder/results/stdout', 'w') as stdoutf:
            p = subprocess.Popen("./run_autograder", cwd="/autograder", stdout=stdoutf, stderr=subprocess.STDOUT)
            exit_status, elapsed_time, timed_out = timeout_process(p, self.timeout_seconds)
            self.elapsed_time = elapsed_time
            self.exit_status = exit_status

            if timed_out:
                result = {
                    "score": 0,
                    "output": "Your submission timed out. It took longer than {0} seconds to run.".format(self.timeout_seconds),
                    "execution_time": self.elapsed_time,
                }
                results_path = os.path.join(self.results_path, 'results.json')
                with open(results_path, 'w') as f:
                    json.dump(result, f)

    def read_stdout(self):
        stdout = ""
        stdout_path = os.path.join(self.results_path, 'stdout')
        if os.path.exists(stdout_path):
            with codecs.open(stdout_path, 'r', encoding='utf-8', errors='replace') as f:
                stdout = f.read()
        return clean_string(stdout)

    def read_results(self):
        results_path = os.path.join(self.results_path, 'results.json')

        if not os.path.exists(results_path):
            return None

        with codecs.open(results_path, 'r', encoding='utf-8', errors='replace') as f:
            self.raw_results = f.read()
            try:
                results = json.loads(clean_string(self.raw_results))
            except ValueError:
                return self.raw_results

        return results

    def submit_results(self):
        stdout = truncate_output(self.read_stdout())
        results = self.read_results()
        error_code = None

        if isinstance(results, str):
            stdout += "\nYour results.json file could not be parsed as JSON. Its contents are as follows:\n\n"
            stdout += results

            results = {
                "score": 0,
                "output": "The autograder failed to execute correctly. Please ensure that your submission is valid. Contact your course staff for help in debugging this issue. Make sure to include a link to this page so that they can help you most effectively."
            }
            error_code = "invalid_json"

        truncate_results(results)

        payload = {
                    "programming_assignment": {
                        "stdout": stdout,
                        "results": results,
                        "elapsed_time": self.elapsed_time,
                        "exit_status": self.exit_status,
                        "error_code": error_code,
                        "raw_results": truncate_output(self.raw_results)
                    }
                  }

        kwargs = {}
        if self.basic_auth is not None:
            kwargs["auth"] = self.basic_auth
        kwargs["headers"] = {"access-token": self.authentication_token}
        kwargs["json"] = payload

        safe_post(self.submit_results_url, **kwargs)

    def add_authorized_keys(self):
        with open('/root/.ssh/authorized_keys', 'w') as f:
            f.write(self.authorized_keys)



    def run_sshd(self):
        sshd_subprocess_file = "/usr/local/sbin/start_sshd.sh"
        child = subprocess.Popen(sshd_subprocess_file)
        self.report_ssh_status('started')
        warning_time_seconds = self.sshd_timeout_warning_seconds
        warning_timer = Timer(self.timeout_seconds - warning_time_seconds, warn_user_for_timeout, [warning_time_seconds])
        warning_timer.start()
        with open("/usr/local/sbin/ssh_wrapper.sh", "r") as f:
            ssh_wrapper_version = version(f.read())
        with open(sshd_subprocess_file, "r") as f:
            sshd_subprocess_file_version = version(f.read())
        # Updated ssh wrapper with a fix for exiting.
        v1p0p1 = [1, 0, 1]
        if is_at_least_version(ssh_wrapper_version, v1p0p1) and is_at_least_version(sshd_subprocess_file_version, v1p0p1):
            print("Using new timeout method")
            timeout_sshd(child, self.timeout_seconds)
        # We are using an out of date SSH Wrapper.
        else:
            print("Using old timeout method")
            with open("/etc/motd", "ab") as f:
                f.write(b"++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
                f.write(b"[Warning] Your base image has an update avaliable to improves ssh sessions!\n")
                f.write(b"[Info] Please rebuild your autograder to get the latest updates.\n")
                f.write(b"++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
                f.write(b"\n\n")
            timeout_process(child, self.timeout_seconds)
        warning_timer.cancel()
        self.report_ssh_status('stopped')

    def run(self):
        self.load_payload()
        self.prepare_submission()

        if not self.submission_url:
            raise Exception("SUBMISSION_URL or PAYLOAD_FILE required")

        self.report_status('harness_started')
        try:
            self.fetch_submission()
        except:
            self.report_http_failure("The autograder failed while fetching the submission from Gradescope.")

        if self.start_sshd:
            self.add_authorized_keys()
            self.run_sshd()
            return

        try:
            self.run_autograder()
        except Exception as e:
            self.report_autograder_failure("The autograder failed to run.",
                                           traceback.format_exc())

        try:
            self.submit_results()
        except:
            self.report_http_failure("The autograder failed while submitting results to Gradescope.")


if __name__ == '__main__':
    harness = AutograderHarness()
    harness.run()
