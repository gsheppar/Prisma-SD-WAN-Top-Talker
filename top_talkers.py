#!/usr/bin/env python3
import cloudgenix
import argparse
from cloudgenix import jd, jd_detailed, jdout
import yaml
import cloudgenix_settings
import sys
import logging
import ipcalc
import ipaddress
import os
import datetime
from datetime import datetime, timedelta
import dateutil
from dateutil.relativedelta import relativedelta
import sys
import csv


# Global Vars
TIME_BETWEEN_API_UPDATES = 60       # seconds
REFRESH_LOGIN_TOKEN_INTERVAL = 7    # hours
SDK_VERSION = cloudgenix.version
SCRIPT_NAME = 'CloudGenix: Alarm Report'
SCRIPT_VERSION = "1"

# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)

####################################################################
# Read cloudgenix_settings file for auth token or username/password
####################################################################

sys.path.append(os.getcwd())
try:
    from cloudgenix_settings import CLOUDGENIX_AUTH_TOKEN

except ImportError:
    # Get AUTH_TOKEN/X_AUTH_TOKEN from env variable, if it exists. X_AUTH_TOKEN takes priority.
    if "X_AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('X_AUTH_TOKEN')
    elif "AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
    else:
        # not set
        CLOUDGENIX_AUTH_TOKEN = None

def top_talker(cgx, site_name, time_check, detailed):
    if detailed:
        times = 24
        interval = 2.5
        print("Running detailed report")
    else:
        times = 6
        interval = 10
    site_id = None
    for site in cgx.get.sites().cgx_content['items']:
        if site["name"] == site_name:
            site_id = site["id"]
    if not site_id:
        print("Unable to find site " + site_name)
        return
    
    top_talkers = {}
    if time_check:
        end = datetime.strptime(time_check, '%Y-%m-%d  %H:%M:%S.%f')
        end = end + timedelta(microseconds=10)
        start_check = end - timedelta(minutes=60)
    else:
        end = datetime.utcnow()
        start_check = end - timedelta(minutes=60)
    
    csv_file = "top_talkers-" + str(end.strftime("%m-%d-%Y %H:%M")) + ".csv"
    print("Top Talkers from " + str(start_check.strftime("%m-%d-%Y %H:%M")) + " to " + str(end.strftime("%m-%d-%Y %H:%M")))
    for x in range(times):
        num = (x / times) * 100
        num = format(num, '.0f')
        print(str(num) + "% Complete")
        start = start_check
        end = start_check + timedelta(minutes=interval)
        start_check = start_check + timedelta(minutes=interval)
        end_time = end.isoformat()[:-3]+'Z'
        start_time = start.isoformat()[:-3]+'Z'
        data = {"start_time":start_time,"end_time":end_time,"filter":{"site":[site_id]},"debug_level":"all"}
        resp = cgx.post.monitor_flows(data).cgx_content['flows']
        flows = resp['items']
        for flow in flows:
            source_ip = flow["source_ip"]
            destination_ip = flow["destination_ip"]
            source_port = flow["source_port"]
            destination_port = flow["destination_port"]
            start_flow = flow["flow_start_time_ms"]
            end_flow = flow["flow_end_time_ms"]
            bytes_count = flow["bytes_s2c"]
            bytes_count += flow["bytes_c2s"]
            packets = flow["packets_s2c"]
            packets += flow["packets_c2s"]
            if flow['lan_to_wan']:
                direction = "lan_to_wan"
            else:
                direction = "wan_to_lan"
            if source_ip in top_talkers.keys():
                top_talkers_list = top_talkers[source_ip]
                flow_check = True
                for i in range(len(top_talkers_list)):
                    if top_talkers_list[i]["source_ip"] == source_ip  and top_talkers_list[i]["destination_ip"] == destination_ip and top_talkers_list[i]["source_port"] == source_port and top_talkers_list[i]["destination_port"] == destination_port and top_talkers_list[i]["start"] == start_flow:
                        flow_check = False
                        bytes_count += top_talkers_list[i]["bytes"]
                        top_talkers_list[i]["bytes"] = bytes_count
                        packets += top_talkers_list[i]["packets"]
                        top_talkers_list[i]["packets"] = packets
                        top_talkers_list[i]["end"] = end_flow
                if flow_check:
                    top_talkers_users = {}
                    top_talkers_users["source_ip"] = source_ip
                    top_talkers_users["destination_ip"] = destination_ip
                    top_talkers_users["source_port"] = source_port
                    top_talkers_users["destination_port"] = destination_port
                    top_talkers_users["direction"] = direction
                    top_talkers_users["start"] = start_flow
                    top_talkers_users["end"] = end_flow
                    top_talkers_users["bytes"] = bytes_count
                    top_talkers_users["packets"] = packets
                    top_talkers_list.append(top_talkers_users)
                    top_talkers[source_ip] = top_talkers_list
            else:
                top_talkers_users = {}
                top_talkers_list = []
                top_talkers_users["source_ip"] = source_ip
                top_talkers_users["destination_ip"] = destination_ip
                top_talkers_users["source_port"] = source_port
                top_talkers_users["destination_port"] = destination_port
                top_talkers_users["direction"] = direction
                top_talkers_users["start"] = start_flow
                top_talkers_users["end"] = end_flow
                top_talkers_users["bytes"] = bytes_count
                top_talkers_users["packets"] = packets
                top_talkers_list.append(top_talkers_users)
                top_talkers[source_ip] = top_talkers_list

    return_top_talker = {}
    for item in top_talkers:
        top_list = top_talkers[item]
        for i in range(len(top_list)):
            source_ip = top_list[i]['source_ip']
            if source_ip in return_top_talker.keys():
                return_top_talker[source_ip]["bytes"] += top_list[i]['bytes']
                return_top_talker[source_ip]["packets"] += top_list[i]['packets']
                return_top_talker[source_ip]["flow"] += 1
            else:
                add = {}
                add["source_ip"] = source_ip
                add["bytes"] = top_list[i]['bytes']
                add["packets"] = top_list[i]['packets']
                add["direction"] = top_list[i]['direction']
                add["flow"] = 1
                return_top_talker[source_ip] = add

    top_talker = []
    for item in return_top_talker:
        top_talker.append(return_top_talker[item])

    print("100% Complete")

    sort = sorted(top_talker, key = lambda i: float(i['bytes']),reverse=True)
    sort  = sort[0:20]

    return_sort = []
    for item in sort:
        add = item
        bytes_count = item['bytes']
        bytes_count = bytes_count /1024
        bytes_count = bytes_count /1024
        bytes_count = format(bytes_count, '.2f')
        add["bytes"] = format(float(bytes_count),",")
        return_sort.append(add)
    
    csv_columns = []        
    for key in (return_sort)[0]:
        csv_columns.append(key)
    
    with open(csv_file, 'w', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
        writer.writeheader()
        for data in return_sort:
            try:
                writer.writerow(data)
            except:
                print("Failed to write data for row")
        print("Saved " + csv_file + " file")
            

    return
                                 
def go():
    ############################################################################
    # Begin Script, parse arguments.
    ############################################################################

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0}.".format(SCRIPT_NAME))

    # Allow Controller modification and debug level sets.
    config_group = parser.add_argument_group('Name', 'These options change how the configuration is loaded.')
    config_group.add_argument("--name", "-N", help="Site Name", required=True, default=None)
    config_group.add_argument("--time", "-T", help="End Time", required=False, default=None)
    config_group.add_argument("--detailed", "-V", help="End Time", action='store_true')
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. "
                                       "Alpha: https://api-alpha.elcapitan.cloudgenix.com"
                                       "C-Prod: https://api.elcapitan.cloudgenix.com",
                                  default=None)
    controller_group.add_argument("--insecure", "-I", help="Disable SSL certificate and hostname verification",
                                  dest='verify', action='store_false', default=True)
    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of prompting",
                             default=None)
    login_group.add_argument("--pass", "-PW", help="Use this Password instead of prompting",
                             default=None)
    debug_group = parser.add_argument_group('Debug', 'These options enable debugging output')
    debug_group.add_argument("--debug", "-D", help="Verbose Debug info, levels 0-2", type=int,
                             default=0)
                             
    args = vars(parser.parse_args())
    
    ############################################################################
    # Instantiate API
    ############################################################################
    cgx_session = cloudgenix.API(controller=args["controller"], ssl_verify=args["verify"])

    # set debug
    cgx_session.set_debug(args["debug"])

    ##
    # ##########################################################################
    # Draw Interactive login banner, run interactive login including args above.
    ############################################################################
    print("{0} v{1} ({2})\n".format(SCRIPT_NAME, SCRIPT_VERSION, cgx_session.controller))

    # login logic. Use cmdline if set, use AUTH_TOKEN next, finally user/pass from config file, then prompt.
    # check for token
    if CLOUDGENIX_AUTH_TOKEN and not args["email"] and not args["pass"]:
        cgx_session.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if cgx_session.tenant_id is None:
            print("AUTH_TOKEN login failure, please check token.")
            sys.exit()

    else:
        while cgx_session.tenant_id is None:
            cgx_session.interactive.login(user_email, user_password)
            # clear after one failed login, force relogin.
            if not cgx_session.tenant_id:
                user_email = None
                user_password = None

    ############################################################################
    # End Login handling, begin script..
    ############################################################################

    # get time now.
    curtime_str = datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')

    # create file-system friendly tenant str.
    tenant_str = "".join(x for x in cgx_session.tenant_name if x.isalnum()).lower()
    cgx = cgx_session
    site_name = args["name"]
    time_check = args["time"]
    detailed = args["detailed"]
    top_talker(cgx, site_name, time_check, detailed) 
    # end of script, run logout to clear session.
    print("End of script. Logout!")
    cgx_session.get.logout()

if __name__ == "__main__":
    go()