#!/usr/bin/env python

###################################################################################
# Empire client script                                                            #
# Author: @xorrior                                                                #
# Purpose: This script will allow you to connect to an Empire multi-user instance #
# License: BSD3-Clause                                                            #
###################################################################################


import sys
import rpyc
import json
import requests
import argparse
import cmd
import shlex
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

introArt = """
   /\:::::/\            /\:::::/\
  /::\:::/::\          /==\:::/::\
 /::::\_/::::\   .--. /====\_/::::\
/_____/ \_____\-' .-.`-----' \_____\
\:::::\_/:::::/-. `-'.-----._/:::::/
 \::::/:\::::/   `--' \::::/:\::::/
  \::/:::\::/          \::/:::\::/
   \/_____\/            \/_____\/

           EMPIRE CLIENT BETA-1.0
"""

class ClientMenu(cmd.Cmd):
    
    def __init__(self, args=None):
        cmd.Cmd.__init__(self)

        if args.hostname and args.restport and args.restUser and args.restPass:
            self.hostname = args.hostname[0] 
            self.restport = args.restport[0]
            self.restuser = args.restUser[0]
            self.restpassword = args.restPass[0]
            self.certfile = args.certfile
            self.keyfile = args.keyfile

            loginuri = "https://"+self.hostname+":"+self.restport+"/api/admin/login"
            headers = {'Content-Type':'application/json'}
            data = json.dumps({"username":self.restuser,"password":self.restpassword})

            # attempt to auth with the rest api
            try:
                r = requests.post(loginuri, data=data, headers=headers, verify=False)
            except:
                print "[-] Unable to connect/authenticate with the rest endpoint"
                sys.exit(-1)

            if r.status_code != 200:
                print "[-] Unable to connect the rest api. Response from server:\n" + str(r.status_code)
                sys.exit(-1)

            self.restToken = json.loads(r.text)['token']
        else:
            print "[-] Not enough arguments given"
            sys.exit(-1)

        self.session = None
        self.agentLocalCache = []
        self.intro = introArt
        self.prompt = "console > "


    def showActiveAgents(self):
        '''Displays all of the active agents in the console'''
        
        agents = self.getLiveAgents()
        if agents != "":
            
            print "[Name]\t\t[Lang]\t\t[Hostname]\t\t[Username]\t\t[ProcName]\t\t[ProcID]\t\t[LastSeen]"
            for agent in agents:
                if agent['language'] == 'powershell':
                    lang = 'ps'
                else:
                    lang = 'py'

                if agent['name'] not in self.agentLocalCache:
                    self.agentLocalCache.append(agent['name'])

                print "%s\t\t%s\t\t%s\t\t%s\t\t%s\t\t%s\t\t%s" % (agent['name'], lang, agent['hostname'], agent['username'], agent['process_name'], agent['process_id'], agent['lastseen_time'])
    
    def getLiveAgents(self):
        '''Responsible for obtaining a list of all the active agents'''
        uri = "https://%s:%s/api/agents" % (self.hostname, self.restport)
        params = {"token":self.restToken}

        try:
            r = requests.get(uri, params=params, verify=False)
        except:
            print "[-] The request to the server failed"
            return ""

        if r.status_code != 200:
            print "[-] The server responded with the status code: %s" % (str(r.status_code))
            return ""
        else:
            return json.loads(r.text)['agents']

    def getLiveListeners(self):
        '''Responsible for obtaining a list of all the active listeners'''
            
    def showActivelisteners(self):
        '''Fetches all of the active listeners'''

    def do_interact(self, line):
        '''Interact with an active agent'''

        sessionID = line.strip()
        exists = False
        username = ""

        for agent in self.getLiveAgents():
            if sessionID == agent['session_id']:
                exists = True

        if not exists:
            print "[-] Agent not found"
            return ""

        if not self.session:
            print "[-] You are not currently connected to the server"
            username = raw_input("Please enter the desired username: ")
            port = raw_input("Please enter the port for the multi-session server: ")

            self.session = rpyc.ssl_connect(self.hostname, port, keyfile=self.keyfile, certfile=self.certfile, config={"allow_all_attrs":True})
            

        self.session.root.handler(sessionID, username, sys.stdin, sys.stdout)
            

    def do_agents(self, line):
        '''Show all active agents'''
        self.showActiveAgents()

    def do_listeners(self, line):
        '''Show all active listeners'''
        self.showActivelisteners()
    
    def do_exit(self, line):
        '''Exit the client'''

        if self.session:
            self.session.close()
        
        sys.exit(0)

    def complete_interact(self, text, line, begidx, endidx):
        '''Tab-complete an interact command'''

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in self.agentLocalCache if s.startswith(mline)] 





if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    mainGroup = parser.add_argument_group('Empire Client Options')
    mainGroup.add_argument('--hostname',nargs=1,help='Hostname or IP address of the Empire server')
    mainGroup.add_argument('--restport',nargs=1, help='Port that is configured for the rest API on the Empire server.')
    mainGroup.add_argument('--restUser',nargs=1, help='The rest user to connect to the API.')
    mainGroup.add_argument('--restPass',nargs=1, help='Password for the rest user.')
    mainGroup.add_argument('--keyfile', help='Private key for SSL')
    mainGroup.add_argument('--certfile', help='Certificate for SSL')

    args = parser.parse_args()

    menu = ClientMenu(args=args)

    menu.cmdloop()
