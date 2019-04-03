# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
# from attivo_consts import *
import requests
import json
import socket
import time
import os
from datetime import datetime
from base64 import b64encode


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class BSAPI:
    BS_DEFAULT_PORT = 8443
    TIMEOUT = 20

    def __init__(self, bs_host, bs_port=BS_DEFAULT_PORT, verify_ssl=False, timeout=TIMEOUT):
        self.bs_host = bs_host
        self.bs_port = bs_port
        self.timeout = timeout
        self.session_key = None
        self.base_url = "https://{host}:{port}/api".format(host=self.bs_host, port=self.bs_port)
        self.verify_ssl = verify_ssl

    def do_request(self, url, data=None, headers=None, files=None, method=None, content_type='application/json', json_dump=True):
        # Guess the method if not provided
        if not method:
            if data:
                method = 'post'
            else:
                method = 'get'

        headers = {}
        if self.session_key:
            headers = {'sessionKey': self.session_key}
        if content_type:
            headers['content-type'] = content_type

        url = self.base_url + url
        # Convert data dictionary to a string
        if data and json_dump:
            data = json.dumps(data)

        request_func = getattr(requests, method)
        r = None

        try:
            r = request_func(url, headers=headers, data=data, files=files, verify=self.verify_ssl)
        except requests.exceptions.SSLError as e:
            return("SSL verification failed")
        except requests.exceptions.ConnectionError as e:
            return("Could not connect to {host} ({exception})".format(host=self.bs_host, exception=e))
        except Exception, e:
            return("Generic Exception: {exception}\nType is: {exception_type}".format(exception=e, exception_type=e.__class__.__name__))

        if r.status_code in (401, 404):
           return (r.text)
        elif r and r.content:
           return r.json()
        else:
           return None

    def login(self, bs_user, bs_pass):
        url = "/auth/login"
        login_data = {'userName': b64encode(bs_user), 'password': b64encode(bs_pass)}
        login_status = self.do_request(url, data=login_data)
        if login_status and 'sessionKey' in login_status:
            self.session_key = login_status['sessionKey']

        return (login_status)

    def logout(self):
        url = "/auth/logout"
        logout_status = self.do_request(url)
        return (logout_status)

    def deploy_decoys(self, target_ip, vlan=None, decoy_number=1):
        url = "/autodeploy/config"
        if vlan:
           data = {"config": [{"ipAddress": target_ip, "vlanID": vlan, "numberOfIPsToAcquire": decoy_number}]}
        else:
           data = {"config": [{"ipAddress": target_ip, "numberOfIPsToAcquire": decoy_number}]}

        deploy_status = self.do_request(url, data=data, content_type=None)
        return (deploy_status)

    def get_threatdirect_rules(self):
        url = "/nwinterfaces/get"
        td_decoys = self.do_request(url)
        return (td_decoys)

    def get_bs_health(self):
        url = "/device/health"
        health = self.do_request(url)
        return health

    def get_monitoring_rules(self):
       url = "/interfaces/get"
       monitoring_rules = self.do_request(url, data='{}', method='post', json_dump=None)
       return (monitoring_rules)

    def get_deceptive_objects(self, object_type, object_id):
        if object_type == 'USERS':
            if object_id == 'ALL':
                url = "/obj_group_cfg/summary/user"
            else:
                url = "/obj_group_cfg/user/{}".format(object_id)
        else:
            response = "Unknown option: {}".format(object_type)
            return (response)

        deceptive_objects = self.do_request(url)
        return (deceptive_objects)

    def get_playbooks(self):
       url = '/pb/getAll'
       return self.do_request(url)

    def run_playbook(self, playbook_id, attacker_ip):
       'This simulates an internal playbook execution based on the attacker IP'
       url = '/pb/runplaybook'
       data = {'attacker_ip': attacker_ip, 'playbook_id': playbook_id}
       return self.do_request(url, data=data)

    def get_events(self, severity_start=None, severity_end=None, timestampStart=None, timestampEnd=None,
                    offset=None, acknowledged='unacknowledged', attackerIP=[], category=[],
                    device=[], service=[], targetOs=[], targetHost=[], targetIP=[],
                    targetVLAN=[], keywords=[], description=[], comments=[]):

        url = "/eventsquery/alerts"

        if attackerIP and attackerIP[0] is None:
            attackerIP = []
        if targetIP and targetIP[0] is None:
            targetIP = []
        if targetVLAN and targetVLAN[0] is None:
            targetVLAN = []

        query_data = {'severity_start': severity_start, 'severity_end': severity_end, 'timestampStart': timestampStart,
                      'timestampEnd': timestampEnd, 'offset': offset, 'acknowledged': acknowledged, 'attackerIp': attackerIP,
                      'category': category, 'device': device, 'service': service, 'targetOs': targetOs, 'targetHost': targetHost,
                      'targetIP': targetIP, 'targetVLAN': targetVLAN, 'keywords': keywords, 'description': description,
                      'comments': comments}

        event_data = self.do_request(url, data=query_data)
        return (event_data)

    # def convert_kill_chain(self, attack_phase):
    #     # Reconnaissance
    #     # Weaponization
    #     # Delivery
    #     # Exploitation
    #     # Installation
    #     # Command & Control
    #     # Actions on Objectives

    #     conversion = {
    #                  'Access': '',
    #                  'C&C': 'Command & Control',
    #                  'Deceptive Credentials': 'Exploitation',
    #                  'Decoy Data': 'Actions on Objectives',
    #                  'Exploit': 'Exploitation',
    #                  'Information': '',
    #                  'MITM': '',
    #                  'Payload Drop': '',
    #                  'Recon': 'Reconnaissance',
    #                 }

    def convert_severity_phantom(self, severity):
        default = 'low'
        conversion = {
                      'Very High': 'high',
                      'High': 'high',
                      'Medium': 'medium'
                     }
        if severity in conversion:
            return conversion[severity]
        else:
            return default

    def convert_severity(self, severity_string):
        conversion = {
                      'Very High': 14,
                      'High': 11,
                      'Medium': 7,
                      'Low': 4,
                      'Very Low': 3,
                      'System Activity': 0
                     }

        if severity_string in conversion:
            return conversion[severity_string]
        else:
            return None


class AttivoConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(AttivoConnector, self).__init__()
        self._state = {}

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        attivo_api = BSAPI(self.botsink, verify_ssl=self.verify_ssl)
        self.save_progress("Testing connectivity to BOTsink {botsink}".format(botsink=self.botsink))
        login_status = attivo_api.login(self.botsink_user, self.botsink_password)
        # self.save_progress("LOGIN STATUS = ".format(login_status))

        if login_status and 'sessionKey' in login_status:
            self.save_progress("Attivo Login successful (session key = {key})".format(key=(login_status['sessionKey'])))
            logout_status = attivo_api.logout()
            if logout_status and 'status' in logout_status and logout_status['status']:
                self.save_progress("Terminating session")
            else:
                self.save_progress("Could not terminate session ({status})".format(status=logout_status))
            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            self.save_progress("Login to {botsink} failed".format(botsink=self.botsink))
            self.save_progress("API Results: {}".format(login_status))

    def valid_ip(self, host):
        try:
            socket.inet_aton(host)
            return True
        except:
           return False

    def _handle_list_hosts(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        attivo_api = BSAPI(self.botsink, verify_ssl=self.verify_ssl)
        attivo_api.login(self.botsink_user, self.botsink_password)

        # all_hosts = []
        num_hosts = 0

        td_monitoring = attivo_api.get_threatdirect_rules()
        bs_monitoring = attivo_api.get_monitoring_rules()

        try:
            if td_monitoring['forwarder_vm_monitoring_rules']['forwarderVmMonitoringRules']:
                for rule in td_monitoring['forwarder_vm_monitoring_rules']['forwarderVmMonitoringRules']:
                    if rule['type'] == 'onNet':
                        td_type = "EP"
                    else:
                        td_type = "VM"

                    host_names = []
                    if 'dnsName' in rule and rule['dnsName']:
                        host_names.append(rule['dnsName'])

                    host_entry = {
                                    'ip': rule['ip'],
                                    'mac': rule['customized_mac'],
                                    'vlan': rule['vlanID'],
                                    'dhcp': rule['dhcpip'],
                                    'td_name': rule['threatDirectName'],
                                    'td_type': td_type,
                                    'host': ', '.join(host_names)
                                }

                    self.save_progress("ThreatDirect host entry: {}".format(host_entry))

                    num_hosts += 1
                    action_result.add_data(host_entry)
                    # all_hosts.append(host_entry)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR,
                                'Error occurred while fetching threat direct rules. Error: {0}. Detailed error: {1}'.format(td_monitoring, str(e)))

        try:
            if bs_monitoring['cfg_monitoring_rules']['monitoringRules']:
                for rule in bs_monitoring['cfg_monitoring_rules']['monitoringRules']:
                    vlan = rule['vlanID']
                    if vlan == -1:
                        vlan = None

                    host_names = []
                    if 'dnsName' in rule and rule['dnsName']:
                        host_names.append(rule['dnsName'])
                    if 'interfaceName' in rule and rule['interfaceName']:
                        host_names.append(rule['interfaceName'])

                    host_entry = {
                                    'ip': rule['ipAddress'],
                                    'mac': rule['externalMAC'],
                                    'dhcp': rule['isDHCPIP'],
                                    'vlan': vlan,
                                    'user_defined': rule['userDefined'],
                                    'host': ", ".join(host_names)
                                }

                    if td_monitoring is not None:
                        host_entry['td_name'] = ''
                        host_entry['td_type'] = ''

                    self.save_progress("BOTSink host entry: {}".format(host_entry))
                    action_result.add_data(host_entry)
                    num_hosts += 1
                    # all_hosts.append(host_entry)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR,
                                'Error occurred while fetching monitoring rules. Error: {0}. Detailed error: {1}'.format(bs_monitoring, str(e)))

    # if td_monitoring['forwarder_vm_monitoring_rules']['forwarderVmMonitoringRules']:
    #     headers.append('TD Name')
    #     headers.append('TD Type')

        attivo_api.logout()
        message = "{} decoy hosts present in the Attivo deception environment".format(num_hosts)
        # action_result.add_data(all_hosts)
        return action_result.set_status(phantom.APP_SUCCESS, status_message=message)

    def _handle_check_host(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        attivo_api = BSAPI(self.botsink, verify_ssl=self.verify_ssl)

        summary = action_result.update_summary({})
        host = param.get('host')
        summary['is_deceptive'] = False
        summary['host'] = host
        message = "Host {} is NOT part of the Attivo deception environment".format(host)

        # Generate BOTsink session key
        attivo_api.login(self.botsink_user, self.botsink_password)

        if self.valid_ip(host):
           ip_address = host
           host_name = None
        else:
           host_name = host
           ip_address = None

        # Check native Monitoring Rules
        bs_monitoring = attivo_api.get_monitoring_rules()

        try:
            if bs_monitoring is not None:
                for rule in bs_monitoring['cfg_monitoring_rules']['monitoringRules']:
                    this_ip = rule['ipAddress']
                    mac = rule['externalMAC']
                    dhcp = rule['isDHCPIP']
                    vlan = rule['vlanID']
                    if vlan == -1:
                        vlan = None
                    user_defined = rule['userDefined']
                    this_host_name = []
                    if 'dnsName' in rule and rule['dnsName']:
                        this_host_name.append(rule['dnsName'])
                    if rule['interfaceName']:
                        this_host_name.append(rule['interfaceName'])

                    if ip_address and this_ip == ip_address:
                        summary['is_deceptive'] = True
                        message = "Host {} IS part of the Attivo deception environment".format(host)
                        self.save_progress("BOTSink IP MATCH ({ip}) ({name}) ({user_defined}) ({mac}) ({dhcp}) ({vlan})".format(
                            ip=this_ip, name=this_host_name, user_defined=user_defined, mac=mac, dhcp=dhcp, vlan=vlan)
                        )
                        break
                    elif host_name and this_host_name and host_name in this_host_name:
                        summary['is_deceptive'] = True
                        message = "Host {} IS part of the Attivo deception environment".format(host)
                        self.save_progress("BOTSink HOST MATCH ({ip}) ({name}) ({user_defined}) ({mac}) ({dhcp}) ({vlan})".format(
                            ip=this_ip, name=this_host_name, user_defined=user_defined, mac=mac, dhcp=dhcp, vlan=vlan)
                        )
                        break
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR,
                                'Error occurred while fetching Attivo monitoring rules. Error: {0}. Detailed error: {1}'.format(bs_monitoring, str(e)))

        if not summary['is_deceptive']:
            # Check ThreatDirect Monitoring Rules
            td_monitoring = attivo_api.get_threatdirect_rules()
            if td_monitoring is not None:
                for rule in td_monitoring['forwarder_vm_monitoring_rules']['forwarderVmMonitoringRules']:
                    this_ip = rule['ip']
                    this_host_name = []
                    mac = rule['customized_mac']
                    vlan = rule['vlanID']
                    dhcp = rule['dhcpip']
                    td_name = rule['threatDirectName']
                    if rule['type'] == 'onNet':
                        td_type = "EP"
                    else:
                        td_type = "VM"
                    if 'dnsName' in rule and rule['dnsName']:
                        this_host_name.append(rule['dnsName'])

                    if ip_address and this_ip == ip_address:
                       summary['is_deceptive'] = True
                       message = "Host {} IS part of the Attivo deception environment".format(host)
                       self.save_progress("TD IP MATCH ({ip}) ({host}) (mac}) ({dhcp}) ({vlan}) (td_name}) (td_type)".format(
                           ip=this_ip, name=this_host_name, mac=mac, dhcp=dhcp, vlan=vlan, td_name=td_name, td_type=td_type)
                       )
                       break
                    elif host_name and this_host_name and host_name in this_host_name:
                        summary['is_deceptive'] = True
                        message = "Host {} IS part of the Attivo deception environment".format(host)
                        self.save_progress("TD HOST MATCH ({ip}) ({name}) ({user_defined}) ({mac}) ({dhcp}) ({vlan})".format(
                            ip=this_ip, name=this_host_name, user_defined=user_defined, mac=mac, dhcp=dhcp, vlan=vlan)
                        )
                        break

            if summary['is_deceptive']:
                summary['td_name'] = td_name
                summary['td_type'] = td_type
            else:
                summary['td_name'] = ''
                summary['td_type'] = ''

        if summary['is_deceptive']:
            summary['ip'] = this_ip
            summary['host_name'] = this_host_name
            summary['user_defined'] = user_defined
            summary['mac'] = mac
            summary['dhcp'] = dhcp
            summary['vlan'] = vlan

        attivo_api.logout()

        action_result.add_data(summary)
        return action_result.set_status(phantom.APP_SUCCESS, status_message=message)

    def _handle_list_users(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        attivo_api = BSAPI(self.botsink, verify_ssl=self.verify_ssl)
        attivo_api.login(self.botsink_user, self.botsink_password)

        user_groups = attivo_api.get_deceptive_objects('USERS', 'ALL')
        users = {}
        try:
            for user_group in user_groups['objGroup']:
                group_id = user_group['esid']
                group_name = user_group['name']
                users_in_group = attivo_api.get_deceptive_objects('USERS', group_id)

                self.save_progress("USERS IN GROUP: {}".format(users_in_group))

                for user_object in users_in_group['objGroup']['objects']:
                    user = user_object['username']
                    if user in users:
                        users[user].append(group_name)
                    else:
                        users[user] = [group_name]
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR,
                                'Error occurred while fetching user groups. Error: {0}. Detailed error: {1}'.format(user_groups, str(e)))

        attivo_api.logout()
        # all_users = []
        for user in sorted(users.keys(), key=lambda x: x.lower()):
            user_entry = {'user': user, 'groups': ", ".join(users[user])}
            # all_users.append(user_entry)
            action_result.add_data(user_entry)

        # action_result.add_data(all_users)
        message = "{} users retireved from Attivo"
        return action_result.set_status(phantom.APP_SUCCESS, status_message=message)

    def _handle_check_user(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        attivo_api = BSAPI(self.botsink, verify_ssl=self.verify_ssl)

        summary = action_result.update_summary({})
        user = param.get('user')
        summary['is_deceptive'] = False
        summary['user'] = user
        message = "User {} is NOT part of Attivo deception".format(user)

        # Lookup user
        self.save_progress("Checking to see if \'{user}\' is a deceptive credential".format(user=user))
        attivo_api.login(self.botsink_user, self.botsink_password)
        this_user = None

        user_groups = attivo_api.get_deceptive_objects('USERS', 'ALL')
        in_groups = []

        try:
            for user_group in user_groups['objGroup']:
                group_id = user_group['esid']

                # self.save_progress("GROUP ID {}".format(group_id))

                users_in_group = attivo_api.get_deceptive_objects('USERS', group_id)
                for user_object in users_in_group['objGroup']['objects']:
                    this_user = user_object['username']
                    if this_user == user:
                        self.save_progress("BOTSink USER MATCH ({user}) ({groups})".format(user=this_user, groups=user_group['name']))
                        summary['is_deceptive'] = True
                        message = "User {} IS part of Attivo deception".format(user)
                        in_groups.append(user_group['name'])
                        break
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR,
                                'Error occurred while fetching User Groups. Error: {0}. Detailed error: {1}'.format(user_groups, str(e)))

        if summary['is_deceptive']:
            summary['user_group'] = in_groups

        attivo_api.logout()

        action_result.add_data(summary)
        return action_result.set_status(phantom.APP_SUCCESS, status_message=message)

    def _handle_list_playbooks(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        # summary = action_result.update_summary({})
        attivo_api = BSAPI(self.botsink, verify_ssl=self.verify_ssl)
        attivo_api.login(self.botsink_user, self.botsink_password)

        all_playbooks = attivo_api.get_playbooks()
        attivo_api.logout()
        try:
            brief_playbook = {}
            for playbook in all_playbooks['pb']:
                brief_playbook = {
                    'id': playbook['id'],
                    'name': playbook['name']
                }

                if len(playbook['investigate']) > 0:
                    investigate_names = []
                    for investigate in playbook['investigate']:
                        investigate_names.append(investigate['name'])
                    brief_playbook['investigate'] = ', '.join(investigate_names)
                else:
                    brief_playbook['investigate'] = []

                if len(playbook['analyze']) > 0:
                    analyze_names = []
                    for analyze in playbook['analyze']:
                        analyze_names.append(analyze['name'])
                    brief_playbook['analyze'] = ', '.join(analyze_names)
                else:
                    brief_playbook['analyze'] = []

                if len(playbook['manage']) > 0:
                    manage_names = []
                    for manage in playbook['manage']:
                        manage_names.append(manage['name'])
                    brief_playbook['manage'] = ', '.join(manage_names)
                else:
                    brief_playbook['manage'] = []

                if len(playbook['isolate']) > 0:
                    isolate_names = []
                    for isolate in playbook['isolate']:
                        isolate_names.append(isolate['name'])
                    brief_playbook['isolate'] = ', '.join(isolate_names)
                else:
                    brief_playbook['isolate'] = []

                self.save_progress("Attivo Playbooks: {}".format(brief_playbook))
                action_result.add_data(brief_playbook)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR,
                                'Error occurred while fetching playbook. Error: {0}. Detailed error: {1}'.format(all_playbooks, str(e)))

        message = "{} Attivo playbooks found".format(len(all_playbooks['pb']))
        return action_result.set_status(phantom.APP_SUCCESS, status_message=message)

    def _handle_run_playbook(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        summary = action_result.update_summary({})
        attivo_api = BSAPI(self.botsink, verify_ssl=self.verify_ssl)

        playbook_name = param['playbook_name']
        attacker_ip = param['attacker_ip']
        playbook_id = None

        # Generate BOTsink session key
        attivo_api.login(self.botsink_user, self.botsink_password)

        # Find playbook ID
        all_playbooks = attivo_api.get_playbooks()
        try:
            for playbook in all_playbooks['pb']:
                if playbook['name'] == playbook_name:
                    playbook_id = playbook['id']
                    break
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR,
                                'Error occurred while fetching playbooks. Error: {0}. Detailed error: {1}'.format(all_playbooks, str(e)))

        if not playbook_id:
            self.save_progress("ID not found for Attivo playbook named: {}".format(playbook_name))
        else:
            self.save_progress("Running playbook \'{name}\' ({id}) with attacker IP {attacker}".format(name=playbook_name, id=playbook_id, attacker=attacker_ip))
            playbook_status = attivo_api.run_playbook(playbook_id, attacker_ip)
            self.save_progress("Run Attivo playbook status = {}".format(playbook_status))
            action_result.add_data(playbook_status)
            attivo_api.logout()

            if playbook_status is None:
                playbook_status = {'error': 'Unknown Error'}
                summary['status'] = "Failed"
                return RetVal(action_result.set_status(phantom.APP_ERROR, playbook_status), None)
            if 'error' in playbook_status:
                summary['status'] = "Failed"
                return RetVal(action_result.set_status(phantom.APP_ERROR, playbook_status), None)
            elif 'status' in playbook_status:
                summary['status'] = playbook_status['status']
                if summary['status'] == 'submitted':
                    return action_result.set_status(phantom.APP_SUCCESS)
                else:
                    return RetVal(action_result.set_status(phantom.APP_SUCCESS, playbook_status), None)
            else:
                summary['status'] = "Failed"
                return RetVal(action_result.set_status(phantom.APP_ERROR, playbook_status), None)

    def _handle_get_events(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        attivo_api = BSAPI(self.botsink, verify_ssl=self.verify_ssl)
        attivo_api.login(self.botsink_user, self.botsink_password)

        summary = action_result.update_summary({})
        attacker_ips = []
        attacker_ip = param['attacker_ip']
        attacker_ips.append(attacker_ip)
        hours_back = param['hours_back']
        severity_string = str(param['severity'])
        severity = str(attivo_api.convert_severity(severity_string))

        timestampEnd = str(int(time.time()) * 1000)
        severity_end = "15"

        self.save_progress("Getting events for source IP: {source_ip}, severity: {severity}, hours back: {hours_back}".format(
            source_ip=attacker_ips[0], severity=severity, hours_back=hours_back)
        )

        seconds_back = int(hours_back) * 60 * 60
        timestampStart = str((int(time.time()) - seconds_back) * 1000)
        events = attivo_api.get_events(severity_start=severity, severity_end=severity_end, timestampStart=timestampStart, timestampEnd=timestampEnd, attackerIP=attacker_ips)

        try:
            if events is None:
                events = []
                self.save_progress("Total events retrieved: None")
            else:
                self.save_progress("Total events retrieved: {event_count}".format(event_count=len(events['eventdata'])))
                # self.save_progress("EVENTS: {}".format(events))

            attivo_api.logout()

            # brief_events = []
            for event in events['eventdata']:
                attack_name = event['attackName']
                severity = event['details']['Severity']
                target_ip = event['details']['Target IP']
                target_os = event['details']['Target OS']
                timestamp = event['details']['Timestamp']
                brief_event = {'attack_name': attack_name, 'target_ip': target_ip, 'target_os': target_os, 'timestamp': timestamp, 'severity': severity}
                # brief_events.append(brief_event)
                action_result.add_data(brief_event)

                self.save_progress("Event: {time},{severity},{name},{target_ip},{target_os}".format(
                    time=timestamp, severity=severity, name=attack_name, target_ip=target_ip, target_os=target_os)
                )
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR,
                                'Error occurred while fetching events. Error: {0}. Detailed error: {1}'.format(events, str(e)))

        summary['ip'] = attacker_ips[0]
        summary['hours_back'] = hours_back
        summary['severity'] = severity_string
        summary['total_events'] = len(events['eventdata'])

        # action_result.add_data(brief_events)
        message = "Retrieved {} events from {}".format(len(events['eventdata']), attacker_ip)
        return action_result.set_status(phantom.APP_SUCCESS, status_message=message)

    def _handle_deploy_decoy(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        summary = action_result.update_summary({})
        attivo_api = BSAPI(self.botsink, verify_ssl=self.verify_ssl)

        vulnerable_endpoint = param['vulnerable_endpoint']
        decoy_number = param.get('decoy_number', '1')
        self.save_progress("Generating {num} decoys based on {ip}".format(num=decoy_number, ip=vulnerable_endpoint))

        attivo_api.login(self.botsink_user, self.botsink_password)

        deploy_status = attivo_api.deploy_decoys(vulnerable_endpoint, decoy_number=decoy_number)
        attivo_api.logout()
        action_result.add_data(deploy_status)

        if 'result' in deploy_status and 'success' in deploy_status['result'][0] and deploy_status['result'][0]['success']:
           summary['status'] = deploy_status['result'][0]['success']
           return action_result.set_status(phantom.APP_SUCCESS)
        else:
           summary['status'] = "Failed"
           return RetVal(action_result.set_status(phantom.APP_ERROR, deploy_status), None)

    def _handle_on_poll(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        date_pattern = "%Y-%m-%dT%H:%M:%S.%fZ"
        os.environ['TZ'] = 'UTC'

        config = self.get_config()
        attivo_api = BSAPI(self.botsink, verify_ssl=self.verify_ssl)
        attivo_api.login(self.botsink_user, self.botsink_password)

        # botsink = config['botsink']
        ingest_severity = config['ingest_severity']

        severity_start = attivo_api.convert_severity(ingest_severity)
        severity_end = "15"

        if not severity_start:
            self.save_progress("Attivo on_poll: Unknown severity specified ('{}'), using 'High'".format(ingest_severity))
            ingest_severity = "High"
            severity_start = "11"

        last_run = {}
        try:
           last_run = self._state['last_run']
        except KeyError:
           pass

        if not last_run or 'timestamp' not in last_run or last_run['timestamp'] == 0:
            self.save_progress("Attivo on_poll: No previous last_run time discovered")
            one_day_seconds = 24 * 60 * 60
            days_back = int(config.get('first_fetch', 0))
            first_fetch_seconds = (int(time.time()) - (one_day_seconds * days_back)) * 1000
            last_run_time = first_fetch_seconds
        else:
            last_run_time = last_run['timestamp']

        self.save_progress("Attivo on_poll: Getting new events of severity '{}' since {}".format(ingest_severity, last_run_time))

        events = attivo_api.get_events(severity_start=severity_start, severity_end=severity_end,
                                              timestampStart=last_run_time, timestampEnd='now')
        if 'error' in events:
            self.save_progress("Attivo on_poll ERROR: {}".format(events['error']))
            return

        self.save_progress("Attivo on_poll: Total new events: {}".format(len(events['eventdata'])))
        new_last_run_time = 0
        for event in events['eventdata']:
            attack_name = event['attackName']
            alert_id = event['esID']
            severity_string = event['details']['Severity']
            destination_ip = event['details']['Target IP']
            destination_os = event['details']['Target OS']
            destination_hostname = event['destIpDomain']
            source_ip = event['details']['Attacker']
            source_hostname = event['sourceIPDomain']
            attack_description = event['attackDesc']
            # phase = event['details']['Attack Phase']
            # service = event['details']['Service']

            event_time = event['details']['Timestamp']
            date_obj = datetime.strptime(event_time, date_pattern)
            event_timestamp = int((date_obj - datetime(1970, 1, 1)).total_seconds()) * 1000 + date_obj.microsecond / 1000
            new_last_run_time = max(new_last_run_time, event_timestamp)

            # kill_chain = attivo_api.convert_kill_chain(phase)
            phantom_severity = str(attivo_api.convert_severity_phantom(severity_string))

            self.save_progress("New Event: {time} ({timestamp}),{severity},{name},{source_ip},{destination_ip},{destination_os}".format(
                time=event_time, timestamp=event_timestamp, severity=severity_string, name=attack_name, source_ip=source_ip,
                destination_ip=destination_ip, destination_os=destination_os)
            )

            cef = {
                   'sourceAddress': source_ip,
                   'destinationAddress': destination_ip,
                   'sourceHostName': source_hostname,
                   'destinationHostName': destination_hostname,
                   'message': attack_description
                  }

            artifact = {
                         'name': attack_name,
                         'cef': cef,
                         'severity': phantom_severity,
                         'label': 'event',
                         # 'ingest_app_id': 'Attivo BOTsink',
                         'source_data_identifier': alert_id
                       }

            container = {
                          'name': attack_name,
                          'severity': phantom_severity,
                          'source_data_identifier': alert_id,
                          'artifacts': [artifact],
                          'label': 'events'
                        }

            # Using the esID as the contianer ID.  If there is a duplicate, it will not be added
            ret_val, msg, cid = self.save_container(container)
            self.save_progress("Attivo on_poll: CONTAINER result {}, {}, {}".format(ret_val, cid, msg))
            if phantom.is_fail(ret_val):
                return self.set_status(phantom.APP_ERROR, "Error saving container: {}".format(msg))

        if len(events['eventdata']) > 0 and new_last_run_time > 0:
            new_last_run_time += 1
            self.save_progress("Attivo on_poll: Setting new last run time to {}".format(new_last_run_time))
            last_run = {'timestamp': new_last_run_time}
            self._state['last_run'] = last_run

        return self.set_status(phantom.APP_SUCCESS)

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)
        elif action_id == 'deploy_decoy':
            ret_val = self._handle_deploy_decoy(param)
        elif action_id == 'get_events':
            ret_val = self._handle_get_events(param)
        elif action_id == 'list_playbooks':
            ret_val = self._handle_list_playbooks(param)
        elif action_id == 'run_playbook':
            ret_val = self._handle_run_playbook(param)
        elif action_id == 'list_hosts':
            ret_val = self._handle_list_hosts(param)
        elif action_id == 'check_host':
            ret_val = self._handle_check_host(param)
        elif action_id == 'list_users':
            ret_val = self._handle_list_users(param)
        elif action_id == 'check_user':
            ret_val = self._handle_check_user(param)
        elif action_id == 'on_poll':
            ret_val = self._handle_on_poll(param)

        return ret_val

    def initialize(self):

        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        botsink = config['botsink']
        botsink_user = config['botsink_user']
        botsink_password = config['botsink_password']
        verify_ssl = config['verify_ssl']

        self._base_url = "https://" + botsink + ":8443/api"
        self.botsink = botsink
        self.botsink_user = botsink_user
        self.botsink_password = botsink_password
        self.verify_ssl = verify_ssl

        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        login_url = BaseConnector._get_phantom_base_url() + "login"
        try:
            print ("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print ("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = AttivoConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
