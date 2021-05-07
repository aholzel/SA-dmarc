#!/usr/bin/env python
'''
Copyright 2017-2019 Arnold Holzel

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the 'Software'), to deal
in the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''
##################################################################
# Description   : Class to check if the script is running in a searchhead cluster
#                 and if so what the current role is in the cluster (member or captain)
#
# Version history
# Date          Version     Author              Description
# 2017-12-12    1.0         Arnold Holzel       initial version
# 2017-12-14    1.1         Arnold Holzel       Added the SHC role shc_deployer
# 2017-12-18    1.2         Arnold Holzel       Added the get_credetials and the write_credentials methods
# 2017-12-19    1.3         Arnold Holzel       added the write_config method
# 2017-12-22    1.4         Arnold Holzel       the get_credetials method will now give back "NO_PASSWORD_FOUND_FOR_THIS_USER"  
#                                               if no password was found
# 2017-12-28    1.5         Arnold Holzel       made the Splunk_Info class more generic by using the app name as custom conf file name.
# 2018-11-08    1.6         Arnold Holzel       add the create_kv_if_needed function
# 2019-05-29    2.0         Arnold Holzel       made sure you always get an log_level back, even if the option doesn't exist in the config file
#                                               changed license to GPL 3.0    
##################################################################
import logging, logging.handlers
import os
import sys
import configparser

import splunklib.client as client
import splunk.entity as entity

__author__ = 'Arnold Holzel'
__version__ = '2.0'
__license__ = 'GPL 3.0'

class Splunk_Info(object):
    def __init__(self, sessionKey=None, app="-", logger=None):
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.splunk_paths = self.give_splunk_paths(self.script_dir)
        
        if app is not "-":
            custom_conf_file = str(app.lower()) + ".conf"
        else:
            custom_conf_file = str(self.splunk_paths['app_name'].lower()) + ".conf"
        
        if os.path.isfile(custom_conf_file):
            # Set the log level based on the value in the config file
            # 10=DEBUG, 20=INFO, 30=WARNING, 40=ERROR, 50=CRITICAL
            log_level = self.get_config(custom_conf_file, 'main', 'log_level')
        else:
            log_level = 30

        given_sessionKey = sessionKey
        
        if logger is not None:
            self.logger = logger
        else:
            log_format = logging.Formatter('%(asctime)s loglevel=%(levelname)s file=%(filename)s line=%(lineno)d function=%(funcName)s message="%(message)s"')
            log_file = os.path.normpath(os.path.dirname(os.path.abspath(__file__)) + os.sep + "splunk_info.log")
            
            handler = logging.handlers.RotatingFileHandler(filename=log_file, maxBytes=10485760, backupCount=5)
            handler.setFormatter(log_format)
 
            logger = logging.getLogger("splunk_info")
            logger.propagate = False
            logger.setLevel(log_level)
            logger.addHandler(handler)
            
            self.logger = logger
            
        if given_sessionKey in [None, ''] or len(given_sessionKey) == 0:
            # Get the sessionKey for the system user for this to work you need to set 
            # passAuth = splunk-system-user
            # in the inputs [script://...] stanza 
            sessionKey = sys.stdin.readline().strip()
            logger.debug("Reading sessionKey from stdin")
            
            if len(sessionKey) == 0 or sessionKey == None:
                self.logger.critical("Did not receive a session key from splunkd. Please enable passAuth in inputs.conf for this script.")
            else:
                self.logger.debug("sessionKey: " + str(sessionKey))
                self.connection = client.connect(token=sessionKey, app=app)
        elif given_sessionKey == "NA":
            self.logger.debug("sessionKey is passed in with the class call, sessionKey: " + str(given_sessionKey))
            sessionKey = None
        else:
            sessionKey = given_sessionKey
            self.logger.debug("sessionKey is passed in with the class call, sessionKey: " + str(given_sessionKey))
            self.connection = client.connect(token=sessionKey, app=app)
 
        if app in [None, '']:
            self.app = "-"
        else:
            self.app = app
        
        self.sessionKey = sessionKey
            
    def shcluster_status(self):
        if len(self.sessionKey) == 0:
            self.logger.critical("Did not receive a session key from splunkd. Please enable passAuth in inputs.conf for this script.")
            shc_status = "unknown"
        else:
            self.logger.debug("sessionKey: " + str(self.sessionKey))
            
            # Get the Splunk info, this is mainly the info that is stored in the server.conf 
            # info() will return a json with (among other things) the roles this Splunk installation has:
            # 'server_roles': ['indexer','license_master','kv_store','shc_captain']
            splunk_info = self.connection.info()
            server_roles = splunk_info['server_roles']
    
            if 'shc_member' in server_roles:
                self.logger.debug("The script is part of a Searchhead cluster, this system is MEMBER")
                shc_status = "shc_member"
            elif 'shc_captain' in server_roles:
                self.logger.debug("The script is part of a Searchhead cluster, this system is CAPTAIN")
                shc_status = "shc_captain"
            elif 'shc_deployer' in server_roles:
                self.logger.debug("The script is part of a Searchhead cluster, this system is DEPLOYER")
                shc_status = "shc_deployer"
            else:
                self.logger.debug("The script is not part of a Searchhead cluster, or no cluster roles could be determined, current roles: " + str(server_roles))
                shc_status = "shc_none"
        
        return shc_status

    def give_splunk_paths(self, script_location):
        splunk_home_dir = os.environ['SPLUNK_HOME']
        splunk_apps_dir = os.path.normpath(splunk_home_dir + os.sep + "etc" + os.sep + "apps")
        app_name = script_location.replace(splunk_apps_dir + "/", "").split(os.sep,1)[0]
        app_root_dir = os.path.normpath(splunk_apps_dir + os.sep + app_name)
        
        current_dir = script_location
        locationInfo = { 'splunk_home_dir': splunk_home_dir, 'splunk_apps_dir': splunk_apps_dir, 'app_name': app_name, 'app_root_dir': app_root_dir, 'current_dir': current_dir}
        
        return locationInfo
        
    def get_config(self, conf_file, stanza=None, option=None):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        splunk_paths = self.give_splunk_paths(script_dir)
        app_dir = splunk_paths['app_root_dir']
        
        if not conf_file.endswith(".conf") and not conf_file.endswith(".meta"):
            conf_file = conf_file + ".conf"
        
        if not conf_file.endswith(".meta"):
            default_file = os.path.normpath(app_dir + os.sep + "default" + os.sep + conf_file)
            local_file = os.path.normpath(app_dir + os.sep + "local" + os.sep + conf_file)
        else:
            default_file = os.path.normpath(app_dir + os.sep + "metadata" + os.sep + "default.meta")
            local_file = os.path.normpath(app_dir + os.sep + "metadata" + os.sep + "local.meta")
        
        config = configparser.RawConfigParser()
    
        # check if the requested config file is in the default dir, if so read the content, else create a empty list to prevent errors
        if os.path.exists(default_file):
            config.read(default_file)
            if stanza == None:
                default_config = config._sections
            else:
                default_config = config._sections[stanza]
        else:
            default_config = []
            
        # check if the requested config file is in the local dir, if so read the content, else create a empty list to prevent errors
        if os.path.exists(local_file):
            config.read(local_file)
            if stanza == None:
                local_config = config._sections
            else:
                local_config = config._sections[stanza]
        else:
            local_config = []
            
        # search for the requested option, first in the local config if it is not found there check the default config.
        if option is not None:
            if option in local_config: 
                active_config = local_config[option]
            elif option in default_config:
                active_config = default_config[option]
            else:
                active_config = None
                
        # If the log_level is requested make sure to give a value back that can be used
        if option == "log_level":
            if active_config == None:
                active_config = 20
            elif int(active_config) > 0 and int(active_config) < 20:
                active_config = 10
            elif int(active_config) >= 20 and int(active_config) < 30:
                active_config = 20
            elif int(active_config) >= 30 and int(active_config) < 40:
                active_config = 30
            elif int(active_config) >= 40 and int(active_config) < 50:
                active_config = 40
            elif int(active_config) >= 50:
                active_config = 50
            else:
                active_config = 20 
            
        return active_config
    
    def write_config(self, conf_file, stanza, key, value=""):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        splunk_paths = self.give_splunk_paths(script_dir)
        app_dir = splunk_paths['app_root_dir']
        
        if not conf_file.endswith(".conf") and not conf_file.endswith(".meta"):
            conf_file = conf_file + ".conf"
        
        if not conf_file.endswith(".meta"):
            local_file = os.path.normpath(app_dir + os.sep + "local" + os.sep + conf_file)
        else:
            local_file = os.path.normpath(app_dir + os.sep + "metadata" + os.sep + "local.meta")
            
        config = configparser.RawConfigParser()
    
        if os.path.exists(local_file):
            config.read(local_file)
            if not config.has_section(stanza):
                config.add_section(stanza)
        else:
            config.add_section(stanza)
            
        config.set(stanza, key, value)
    
        if not os.path.exists(os.path.dirname(local_file)):
            os.makedirs(os.path.dirname(local_file))
        
        with open(local_file, 'wb') as configfile:
            config.write(configfile)
        
    def get_credetials(self, username=None, app="-"):        
        if app in [None, '','-']:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            splunk_paths = self.give_splunk_paths(script_dir)
            app = splunk_paths['app_name']
            
        try:
            # list all credentials available 
            entities = entity.getEntities(['admin', 'passwords'], namespace=app, owner='nobody', sessionKey=self.sessionKey)
            self.logger.debug("entities: " + str(entities))
        except Exception:
            self.logger.exception("Could not get " + str(app) + " credentials from splunk.")
        
        found = 0
        # make a dict when the correct info is found
        for i, c in entities.items():
            if c['username'] == username:
                credentials = {c['username']: c['clear_password']}
                password = credentials[username]
                found = 1
                break
        
        if found == 0:
            password = "NO_PASSWORD_FOUND_FOR_THIS_USER"
            
        return password 

    def write_credentials(self, username, password, app="-"):
        # Rename the username and password to make it clear what is what later on..
        write_username = username
        write_password = password
        
        if app in [None, '','-']:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            splunk_paths = self.give_splunk_paths(script_dir)
            app = splunk_paths['app_name']
        
        try:
            # If the credential already exists, delete it.
            for storage_password in self.service.storage_passwords:
                if storage_password.username == write_username:
                    self.service.storage_passwords.delete(username=storage_password.username)
                    self.logger.info("The given credentials already exist, assuming new password so first delete them en then write them again")
                    break

            # Create the credentials 
            self.service.storage_passwords.create(write_password, write_username)

        except Exception:
            self.logger.exception("An error occurred updating credentials. Please ensure your user account has admin_all_objects and/or list_storage_passwords capabilities.")
            
    def create_kv_if_needed(self, collection_name, collection_fields, kwargs):
        service = client.connect(
            token=self.sessionKey,
            owner="nobody",
            app=self.app)

        export_fields_list_kv = []
        export_fields_list_kv.extend(collection_fields.iterkeys())

        if collection_name in service.kvstore:
            return export_fields_list_kv

        splunk_info = self.connection.info()

        # The collection doesn't exist so create it now,
        # and also create the collections.conf file with the correct fields
        self.logger.debug("The KV Store " + str(collection_name) +
                          " doesn't exist so create it")

        # Create and select the KVstore collection
        service.kvstore.create(
            name=collection_name,
            fields=collection_fields,
            **kwargs
        )

        # The kvstore.create command only creates the kvstore but doesn't
        # mean you can use it in a search.
        # To be able to use it a search we need to add a stanza with the
        # definition for the collection in transforms.conf.
        fields_list = ','.join(map(str, export_fields_list_kv))
        splunk_info.write_config(
            "transforms.conf",
            collection_name,
            "external_type",
            "kvstore")
        splunk_info.write_config(
            "transforms.conf",
            collection_name,
            "collection",
            collection_name)
        splunk_info.write_config(
            "transforms.conf",
            collection_name,
            "fields_list",
            fields_list)

        return export_fields_list_kv