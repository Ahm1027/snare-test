import requests
from urllib.parse import urljoin
import time
import sys
import os
import json
import re
from datetime import datetime

#argument = sys.argv[1:]
du_name = 'cloud/snare'
time.sleep(5)
logserver = "203.124.40.28"
url = 'http://' + logserver + ':8080'
url = urljoin(url, "sendlogs")


def tail(stream_file):
    stream_file.seek(0, os.SEEK_END)  # Go to the end of file

    while True:
        if stream_file.closed:
            raise StopIteration

        line = stream_file.readline()

        yield line

def is_json(myjson):
#  try:
#    json_object = json.loads(myjson)
#  except ValueError as e:
#    return False
  return True



"""
format_access_request
Function that adds fields to intermediate access request logs dictionary
Params:
	=> _idx: int (line indicating index for request type in log string that can be used for positioning of other parameters)
	=> _chunks : list (log string divided into chunks based on space delimiter)
	=> method: str (specifying GET or POST)
Returns:
	=> log : Dictionary
	{
	'method': str/null,
	'request': str/null,
	'http': str/null,
	'status': str/null,
	'port': str/null,
	'dump' (useragent and non formatted characters): str/null
	}
"""
def format_access_request(idx, chunks, method):
    request = {}
    request['method'] = method
    request['request'] = chunks[idx+1].rstrip()
    request['http'] = chunks[idx+2]
    request['status'] = chunks[idx+3]
    request['port'] = chunks[idx+4]
    request['dump'] = ' '.join(chunks[idx+6: len(chunks)-1])
    return request



"""
parses_access_requests
Function that parses Aiohttp access request type logs
Params:
	=> _logs: str (single line from .log file)
Returns:
	=> log : Dictionary
	{
	'type': str/null,
	'timestamp': str/null,
	'destination_IP': str/null,
	'method': str/null,
	'request': str/null,
	'http': str/null,
	'status': str/null,
	'port': str/null,
	'dump' (useragent and non formatted characters): str/null
	}
"""
def parse_access_requests(_log):
    request = {}
    request['type'] = 'aiohttp.access:log'
    request['timestamp'] = re.match(r'[\d]{4}-[\d]{2}-[\d]{2} [\d]{2}:[\d]{2}:[\d]{2}', _log, re.M|re.I).group()
    
    chunks = _log.split(" ")
    for idx, partition in enumerate(chunks):
        match_IP = re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', partition, re.M|re.I)
        if match_IP:
            request["destination_IP"] = match_IP.group()
            continue
        
        if partition == r'"GET' or partition == 'GET':
            return {**request, **format_access_request(idx, chunks, 'GET')}
        if partition == r'"POST' or partition == 'POST':
            return {**request, **format_access_request(idx, chunks, 'POST')}



"""
format_handle_request
Function that adds fields to intermediate handle request logs dictionary
Params:
	=> _request_id: int (line indicating index for request_path in log string)
	=> _log : str (single line from .log file)
Returns:
	=> log : Dictionary
	{
	'method': str/null,
	'request': str/null,
	'http': str/null,
	'status': str/null,
	'port': str/null,
	'dump' (useragent and non formatted characters): str/null
	}
"""
def format_handle_request(request_id, _log):
    request = {}
    request['method'] = None
    request['request'] = _log[request_id+14:].rstrip() if request_id != -1 else None
    request['http'] = None
    request['status'] = None
    request['port'] = None
    request['dump'] = None
    return request



"""
parse_handle_requests
Function that parses snare handle request type logs
Params:
	=> _logs: str (single line from .log file)
Returns:
	=> log : Dictionary
	{
	'type': str/null,
	'timestamp': str/null,
	'destination_IP': str/null,
	'method': str/null,
	'request': str/null,
	'http': str/null,
	'status': str/null,
	'port': str/null,
	'dump' (useragent and non formatted characters): str/null
	}
"""
def parse_handle_requests(_log):
    request = {}
    request['type'] = 'snare.server:handle_request'
    request['timestamp'] = re.match(r'[\d]{4}-[\d]{2}-[\d]{2} [\d]{2}:[\d]{2}:[\d]{2}', _log, re.M|re.I).group()
    request_id = _log.find('Request path: ')
    return {**request, **format_handle_request(request_id, _log)}


def send_log(log_data, decoy_name):
    if log_data:
        log_data.update({'decoy_name': decoy_name, 'du_name': du_name})
        r = requests.post(url, json={"logs": log_data })
        if r.content.decode("utf-8"):
            print("Log sent to %s successfully"%(url))
            pass
        else:
            print("Failed to write log in file")
    else:
        print("Malformed log, not sent")

def log_to_db():
    
    with open("/opt/snare/snare.log", "r") as log_file:
    #with open("cowrie.json", "r") as log_file:
        for line in log_file:
            decoy_name = str(datetime.date(datetime.now()))
            decoy_name = decoy_name+".json"
            try:
            	# For Aiohttp Access type logs
                log_data = ''
                if re.search(r'aiohttp\.access:log', line, re.M|re.I):
                    log_data = parse_access_requests(line)
                    send_log(log_data, decoy_name)
                # For clients snare handle request type logs
                elif re.search(r'snare\.server:handle_request', line, re.M|re.I):
                    log_data = parse_handle_requests(line)
                    send_log(log_data, decoy_name)
                 
            except :
                time.sleep(5)        # Bad json format, maybe corrupted...
                continue  # Read next line
               

        for line in tail(log_file):
            decoy_name = str(datetime.date(datetime.now()))
            decoy_name = decoy_name+".json"
            try:
            	# For Snare's Aiohttp Access type logs
                if re.search(r'aiohttp\.access:log', line, re.M|re.I):
                    log_data = json.dumps(parse_access_requests(line), indent=1)
                    send_log(log_data, decoy_name)
                # For clients snare handle request type logs
                elif re.search(r'snare\.server:handle_request', line, re.M|re.I):
                    log_data = json.dumps(parse_handle_requests(line), indent=1)
                    send_log(log_data, decoy_name)


                 
            except :
                time.sleep(5)        # Bad json format, maybe corrupted...
                continue  # Read next line
            # Do what you want with data:
            # db.execute("INSERT INTO ...", log_data["level"], ...)
            
log_to_db()
