#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import xmlrpclib
import argparse
import time
from datetime import datetime

import psutil
import requests
import cjson

from supervisor import childutils
from supervisor.xmlrpc import SupervisorTransport
from supervisor.states import SupervisorStates
from supervisor.states import ProcessStates

def write_stderr(msg):
    sys.stderr.write(' '.join([datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f"), msg]))
    sys.stderr.flush()

def get_process_by_group(group, rpc):
    return [p for p in rpc.supervisor.getAllProcessInfo() if p['group'].startswith(group)]

def get_processes_by_name(name, rpc):
    return [p for p in rpc.supervisor.getAllProcessInfo() if p['name'].startswith(name)]

def get_process_by_name(name, rpc):
    return [p for p in rpc.supervisor.getAllProcessInfo() if p['name'] == name]

def get_running_time(processes):
    r = []
    for process in [p for p in processes if p['state'] == ProcessStates.RUNNING]:
        r.append({
                 'name':process['name'],
                 'group':process['group'],
                 'state':process['state'],
                 'pid':process['pid'],
                 'start':process['start'],
                 'duration':process['now'] - process['start']
                })
    return r

def get_process_connections(pid, conn_status):
    return [c for c in psutil.Process(pid).connections() if c.status.startswith(conn_status)]

def send_to_endpoint(url, payload):
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    if type(payload) == dict:
       response = requests.post(url, data = cjson.encode(payload), headers = headers)
    else:
       response = requests.post(url, data = payload)

    if response.status_code <> 200:
       write_stderr("Error when posting data to endpoint. HTTP code: %s\n" % (response.status_code))

    response.close()

class EventLog:
    def __init__(self, http_endpoint, http_error_endpoint, strip_streams, verbose, stdout = sys.stdout, stderr = sys.stderr, stdin = sys.stdin):
        self.http_endpoint = http_endpoint
        self.http_error_endpoint = http_error_endpoint
        self.strip_streams = strip_streams
        self.stdout = stdout
        self.stderr = stderr
        self.stdin = stdin
        self.verbose = verbose
        self.part = None
        self.combined = False
        self.parts = {}
        self.processed = {}

    def process_event(self, header, payload):
        payload_header, payload_data = payload.split('\n', 1)

        if self.verbose: write_stderr("Payload header: %s\n" % (payload_header))
        if self.verbose: write_stderr("Payload data: %s\n" % (payload_data))

        headers = dict([x.split(':') for x in payload_header.split()])
        process_pid = int(headers['pid'])

        payload_fixed = payload_data.replace('nan','0') # Fix errors in iperf3 JSON output. Sometimes get 'nan'

        # If we have first part, add current payload to it
        if process_pid in self.parts:
           if self.verbose: write_stderr("We have first part saved. Assume we got second part. Process: %s. Length: %s\n" % (process_pid, len(payload_fixed)))
           payload_fixed = ''.join([self.parts[process_pid], payload_fixed])
           _ = self.parts.pop(process_pid)
           self.processed[process_pid] = True # Enabling combined flag
           if self.verbose: write_stderr("Full payload. Length: %s\n" % (len(payload_fixed)))
           if self.verbose: write_stderr("Current payload: \n%s\n" % (payload_fixed))

        try:
           payload_parsed = cjson.decode(payload_fixed)
           if self.verbose: write_stderr("JSON validated\n")
        except cjson.DecodeError as err: # Got JSON parsing error
           if self.verbose: write_stderr("JSON parsing error: %s\n" % (err.message))

           if process_pid in self.processed: # If combined flag already set, disable it and send payload to error endpoint
              if self.verbose: write_stderr("Payload already combined. Sending JSON to error endpoint if defined\n")
              if self.http_error_endpoint: send_to_endpoint(self.http_error_endpoint, payload_fixed)
              _ = self.processed.pop(process_pid)
              return

           if not process_pid in self.parts: # If we got JSON parsing error, assume that JSON is splitted
              if self.verbose: write_stderr("Detected splitted payload. First parted detected. Process: %s. Length: %s\n" % (process_pid, len(payload_fixed)))
              self.parts[process_pid] = payload_fixed
              self.processed[process_pid] = False
              return

        # Removing 'intervals' key before sending to endpoint
        if self.strip_streams:
           if self.verbose: write_stderr("Remove 'intervals' part from JSON\n")
           if 'intervals' in payload_parsed:
              _ = payload_parsed.pop('intervals')

        if self.verbose: write_stderr("Posting to endpoint: %s\n" % (self.http_endpoint))
        send_to_endpoint(self.http_endpoint, payload_parsed)

class EventTick:
    def __init__(self, rpc, duration, status, group, process, kill, kill_timeout, verbose, stdout = sys.stdout, stderr = sys.stderr, stdin = sys.stdin):
        self.server = rpc
        self.duration = duration
        self.status = status
        self.group = group
        self.process = process
        self.kill = kill
        self.kill_timeout = kill_timeout
        self.stdout = stdout
        self.stderr = stderr
        self.stdin = stdin
        self.verbose = verbose

        self.status_track = {}

    def process_event(self, header, payload):
        if self.verbose: write_stderr("Get process list and running time for %s group\n" % (self.group))

        # Get process list from supervisor by defined group
        process_list = get_process_by_group(self.group, self.server)

        # Calculate run duration
        running_time = get_running_time(process_list)

        # Check duration
        for process in running_time:
            if process['duration'] >= self.duration:
                if self.verbose: write_stderr("Process with pid %s is running more than %s seconds (%s s)\n" % (
                process['pid'], self.duration, process['duration']))

                # Get process network connection
                if get_process_connections(process['pid'], self.status):
                    if self.verbose: write_stderr("Process with pid %s have %s connections in %s state\n" % (
                    process['pid'], len(get_process_connections(process['pid'], 'ESTABLISHED')), 'ESTABLISHED'))

                    # Check, if process already tracking
                    # If yes, check connection duration and if duration limit is exceeded, kill process (if enabled)
                    if process['pid'] in self.status_track:
                        write_stderr("Process with pid %s is tracking. Connection duration: %s\n" % (
                        process['pid'], int(time.time()) - self.status_track[process['pid']]))
                        if int(time.time()) - self.status_track[process['pid']] >= self.kill_timeout:
                            write_stderr("Connection duration for process with pid %s is exceeded %s. Killing\n" % (
                            process['pid'], self.kill_timeout))
                            if self.kill:
                                psutil.Process(process['pid']).kill()
                            self.status_track.pop(process['pid'])
                    # If process not tracking and has connection, enable tracking
                    else:
                        write_stderr(
                            "Start tracking process with pid %s (it's have network connection)\n" % (process['pid']))
                        self.status_track[process['pid']] = int(time.time())  # record detect time

        # Update process tracking table
        status_track_old = self.status_track.copy()
        for s in status_track_old:
            if not s in [e['pid'] for e in process_list]:
                if self.verbose: write_stderr("Pid %s not found in process table. Removing it.\n" % (s))
                self.status_track.pop(s)

def create_argument_parser():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-c', '--connection-monitor', dest = 'connection_monitor', action = "store_true", default = False,
                       help = "Enable connection monitoring")
    group.add_argument('-o', '--output-collect', dest = 'output_collect', action = "store_true", default = False,
                      help = "Collect iPerf output in JSON format")


    group = parser.add_argument_group('Connection monitoring')
    group.add_argument('-d', '--duration', dest = 'duration', type = int, default = 60, help = "How long process is running")
    group.add_argument('-s', '--status', dest = 'status', type = str, default = 'ESTABLISHED', help = "TCP connection status to check after process reached duration")
    group.add_argument('-g', '--process-group', dest = 'group', type = str, help = "Process group to monitor")
    group.add_argument('-n', '--process-name', dest = 'process', type = str, help = "Process name to monitor")
    group.add_argument('-k', '--kill', dest = 'kill', action = "store_true", default = False, help = "Send SIGKILL signal to found process")
    group.add_argument('-t', '--kill-timeout', dest = 'kill_timeout', type = int, default = 30, help = "How long we wait after detecting needed TCP connection status")
    group.add_argument('-r', '--rpc', dest = 'rpc_url', type = str, default = 'unix:///var/run/supervisor.sock', help = "Supervisor RPC url (http or socket)")

    group = parser.add_argument_group('Statistic collection')
    group.add_argument('-u', '--http-endpoint', dest = 'http_endpoint', type = str, default = None, help = "HTTP endpoint for posting data")
    group.add_argument('-e', '--http-error-endpoint', dest = 'http_error_endpoint', type = str, default = None, help = "HTTP endpoint for posting data with JSON parsing errors")
    group.add_argument('-i', '--strip-streams', dest = 'strip_streams', action = "store_true", default = False, help = "Remove 'intervals' key from JSON before sending")

    parser.add_argument('-v', '--verbose', dest = 'verbose', action = "store_true", default = False, help = "Enable verbose output to stderr")

    return parser


def main():
    arg_parser = create_argument_parser()
    args = arg_parser.parse_args()

    if not args.connection_monitor and not args.output_collect:
       arg_parser.print_help()
       sys.exit("\n\n--connection-monitor or --output-collect is required.")


    if args.connection_monitor:
        if not args.group:
            sys.exit("--process-group must be defined")

        if args.rpc_url.startswith('http://'):
           server = xmlrpclib.Server(args.rpc_url)
        elif args.rpc_url.startswith('unix://'):
           server = xmlrpclib.ServerProxy('http://localhost:9001/RPC2',SupervisorTransport('', '', args.rpc_url))
        else:
           write_stderr("Can't select method for connect to supervisor")
           sys.exit(1)

        if server.supervisor.getState()['statecode'] == SupervisorStates.RUNNING:
           write_stderr("Connected to RPC\n")
           write_stderr("Supervisor status: %s\n" % (server.supervisor.getState()['statename']))

        process_tick_event = EventTick(server, args.duration, args.status, args.group, args.process, args.kill, args.kill_timeout, args.verbose)


    if args.output_collect:
        env = os.environ

        if not args.http_endpoint:
            if 'HTTP_ENDPOINT' in env.keys():
                http_endpoint = env['HTTP_ENDPOINT']
            else:
                sys.exit("HTTP_ENDPOINT is required.")
        else:
            http_endpoint = args.http_endpoint

        if not args.http_error_endpoint:
            if 'HTTP_ERROR_ENDPOINT' in env.keys():
                http_error_endpoint = env['HTTP_ERROR_ENDPOINT']
            else:
                write_stderr("Endpoint for errors not found.")
                http_error_endpoint = None
        else:
            http_error_endpoint = args.http_error_endpoint

        process_log_event = EventLog(http_endpoint, http_error_endpoint, args.strip_streams, args.verbose)

    # Main loop
    while 1:
        headers, payload = childutils.listener.wait(sys.stdin, sys.stdout)

        if args.verbose: write_stderr("Get event with headers: " + str(headers) + ". And payload: " + str(payload) + "\n")

        if args.connection_monitor and headers['eventname'].startswith('TICK'):
               process_tick_event.process_event(headers, payload)

        if args.output_collect and headers['eventname'].startswith('PROCESS_LOG'):
                process_log_event.process_event(headers, payload)

        childutils.listener.ok(sys.stdout) # Ready for next event


if __name__ == '__main__':
    main()

