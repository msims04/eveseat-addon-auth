#!/usr/bin/env python
#
# The MIT License (MIT)
#
# Copyright (c) 2015 msims04
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import Ice
import atexit
import configobj
import logging
import requests
import re
import sys
import threading
import time
import xml.etree.cElementTree as ET

from daemon import runner

class App():

	def __init__(self):
		self.stdin_path = '/dev/null'
		self.stdout_path = '/dev/tty'
		self.stderr_path = '/dev/tty'
		self.pidfile_path =  '/var/run/mumble-authenticator/lock.pid'
		self.pidfile_timeout = 5

		self.authcb = None
		self.metacb = None

	def run(self):
		try:
			# Load the configuration file and verify that the required values are present.
			config = configobj.ConfigObj('/etc/mumble-authenticator.ini')

			config['seat'  ]['address'   ]
			config['seat'  ]['token'     ]
			config['seat'  ]['verify_ssl']
			config['ice'   ]['host'      ]
			config['ice'   ]['port'      ]
			config['ice'   ]['secret'    ]
			config['ice'   ]['slicedir'  ]
			config['ice'   ]['slice'     ]
			config['ice'   ]['raw'       ]
			config['murmur']['servers'   ]
			config['cache' ]['tickers'   ]

		except Exception, e:
			logging.critical('There was an error reading the configuration file "/etc/mumble-authenticator.ini"')
			return

		# Initialize and setup Ice.
		slicedir = Ice.getSliceDir()
		if not slicedir: slicedir = [config['ice']['slicedir'], '-I/usr/share/Ice/slice', '-I/usr/share/slice']
		else: slicedir = ['-I' + slicedir]
		Ice.loadSlice('', slicedir + [config['ice']['slice']])
		import Murmur

		class MetaCallback(Murmur.MetaCallback):

			def __init__(self, config):
				self.config = config

			def started(self, server, current = None):
				return

			def stopped(self, server, current = None):
				return

		class AuthCallback(Murmur.ServerUpdatingAuthenticator):

			def __init__(self, config):
				self.config = config
				self.users  = {}

			def getCorporationTicker(self, corporationID):
				# Get the corporation ticker from the config file.
				if str(corporationID) in self.config['cache']['tickers']:
					return self.config['cache']['tickers'][str(corporationID)]

				# Get the corporation ticker from the eve online api.
				try:
					result = requests.get('http://api.eveonline.com/corp/CorporationSheet.xml.aspx', params = {'corporationID': corporationID}, timeout = 10)
					root   = ET.fromstring(result.text)
					ticker = root.find('.//ticker').text
					self.config['cache']['tickers'][str(corporationID)] = ticker

					# Update the list of corporation tickers in the configuration file.
					self.config.write()

					return ticker

				except:
					return '-----'

			def authenticate(self, username, pw, certificates, certhash, cerstrong, current = None):
				logger.info('A client (%s:%s) has connected.' % (username, certhash))

				# Do not allow empty usernames.
				if username == None:
					logger.info('Authentication failed: The client did not provide a username.')
					return (-1, None, None)

				# Do not allow empty passwords.
				if pw == None:
					logger.info('Authentication failed: The client did not provide a password.')
					return (-1, None, None)

				# Use requests to communicate with the seat api.
				try:
					address             = self.config['seat']['address'   ] + '/ex/auth/login'
					verify              = self.config['seat']['verify_ssl'] == 'True'
					headers             = {}
					headers['username'] = username
					headers['password'] = pw
					headers['X-Token' ] = self.config['seat']['token']
					headers['service' ] = 'mumble'

					response = requests.post(address, headers = headers, verify = verify)
					response = response.json()

				except Exception, e:
					logger.info('Authentication failed: The SeAT server did not provide a valid response.')
					logger.exception(e)
					return (-1, None, None)

				# Verify the seat response.
				try:
					error = response['result']

				except Exception, e:
					logger.info('Authentication failed: The SeAT server did not provide a valid response.')
					logger.exception(e)
					return (-1, None, None)

				if not response['result']:
					logger.info('Authentication failed: ' + response['error'])
					return (-1, None, None)

				# Get character information.
				guest         = bool(response['data']['guest'          ])
				userID        = int (response['data']['userID'         ])
				userRoles     =     (response['data']['userRoles'      ])
				characterID   = int (response['data']['characterID'    ])
				characterName = str (response['data']['characterName'  ])
				corporationID = int (response['data']['corporationID'  ])
				ticker        = self.getCorporationTicker(corporationID)

				# Initialize username and groups.
				mumbleGroups = []
				mumbleTags   = []
				mumbleName   = ""

				if guest:
					mumbleGroups.append('guest')
					mumbleTags  .append('Guest')

				else:
					if 'MumbleAdmin' in userRoles:
						mumbleGroups.append('admin')
						mumbleTags  .append('Admin')

					if 'Diplomat' in userRoles:
						mumbleGroups.append('diplomat')
						mumbleTags.append('Diplomat')

					if 'FC' in userRoles:
						mumbleGroups.append('fc')
						mumbleTags.append('FC')

					#if 'Leadership' in userRoles:
						mumbleGroups.append('leadership')
						mumbleTags.append('Leadership')

					#if 'Recruiter' in userRoles:
						mumbleGroups.append('recruiter')
						mumbleTags.append('Recruiter')

					mumbleGroups.append('member')

				# Format the users name.
				if len(mumbleTags): mumbleName = '[{0}] {1} ({2})'.format(ticker, characterName, '|'.join(mumbleTags))
				else:               mumbleName = '[{0}] {1}'      .format(ticker, characterName)

				# Return the authenticated user.
				logger.info('Authentication successful: Returning "%s" as the username.' % mumbleName)
				logger.info('User belongs to groups: %s', mumbleGroups)

				self.users[characterID] = {'name': mumbleName, 'groups': mumbleGroups}

				return (characterID, mumbleName, mumbleGroups)

			def getInfo(self, id, info, current = None):
				result = {}
				result[Murmur.UserInfo.UserName] = self.users[id]['name']

				return (True, result)

			def nameToId(self, name, current = None):
				return -2

			def idToName(self, id, current = None):
				return ""

			def idToTexture(self, id, current = None):
				return ""

			def registerUser(self, name, current = None):
				return -1

			def unregisterUser(self, id, current = None):
				return -1

			def getRegisteredUsers(self, filter, current = None):
				return {}

			def setInfo(self, id, info, current = None):
				return -1

			def setTexture(self, id, texture, current = None):
				return -1

		class Application(Ice.Application):

			def __init__(self, config):
				self.config = config
				self.connected = {}
				self.authcb = None
				self.metacb = None
				self.meta = None
				self.timer = None

			def run(self, args):
				self.shutdownOnInterrupt()

				communicator = self.communicator()
				context = communicator.getImplicitContext()

				if self.config['ice']['secret']:
					context.put('secret', str(self.config['ice']['secret']))

				logger.info('Connecting to Ice server (%s:%d).'           % (str(self.config['ice']['host']), int(self.config['ice']['port'])))
				proxy = communicator.stringToProxy('Meta:tcp -h %s -p %d' % (str(self.config['ice']['host']), int(self.config['ice']['port'])))
				self.meta = Murmur.MetaPrx.uncheckedCast(proxy)

				adapter = communicator.createObjectAdapterWithEndpoints('Callback.Client', 'tcp -h %s' % str(self.config['ice']['host']))
				adapter.activate()

				metacbprx = adapter.addWithUUID(MetaCallback(self.config))
				self.metacb = Murmur.MetaCallbackPrx.uncheckedCast(metacbprx)

				authprx = adapter.addWithUUID(AuthCallback(self.config))
				self.authcb = Murmur.ServerUpdatingAuthenticatorPrx.uncheckedCast(authprx)

				self.setCallbacks()

				communicator.waitForShutdown()
				self.timer.cancel()

			def resetConnectedStatus(self):
				for key, value in self.connected.iteritems():
					self.connected[key] = False

			def setCallbacks(self):
				try:
					self.meta.addCallback(self.metacb)

					for server in self.meta.getBootedServers():
						if not self.config['murmur']['servers'] or server.id() in self.config['murmur']['servers']:
							if not str(server.id()) in self.connected:
								self.connected[str(server.id())] = False

							if self.connected[str(server.id())] == False:
								logger.info('Connecting authenticator callback for server %d.', server.id())

							server.setAuthenticator(self.authcb)
							self.connected[str(server.id())] = True

				except (Murmur.InvalidSecretException, Ice.UnknownUserException, Ice.ConnectionRefusedException), e:
					if isinstance(e, Ice.ConnectionRefusedException):
						logger.error('The server refused the connection.')
						self.resetConnectedStatus()

					elif isinstance(e, Murmur.InvalidSecretException) or isinstance(e, Ice.UnknownUserException) and (e.unknown == 'Murmur::InvalidSecretException'):
						logger.error('Your Ice secret is invalid.')
						self.resetConnectedStatus()

					else:
						exception(e)
						self.resetConnectedStatus()
						raise e

				self.timer = threading.Timer(10.0, self.setCallbacks)
				self.timer.start()

		initdata = Ice.InitializationData()
		initdata.properties = Ice.createProperties([], initdata.properties)
		for key, value in config['ice']['raw'].iteritems(): initdata.properties.setProperty(key, value)
		initdata.properties.setProperty('Ice.ImplicitContext', 'Shared')

		app = Application(config)
		app.main(sys.argv[:1], initData = initdata)

app = App()

logger = logging.getLogger('MumbleAuthenticator')
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler = logging.FileHandler('/var/log/mumble-authenticator/mumble-authenticator.log')
handler.setFormatter(formatter)
logger.addHandler(handler)

daemon_runner = runner.DaemonRunner(app)
daemon_runner.daemon_context.files_preserve=[handler.stream]
daemon_runner.do_action()
