#!/usr/bin/env python

"""
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
##################################################################
# Description   : Class to set up a logger that can handle multiple log formats and files
#
# Version history
# Date          Version     Author              Description
# ?             1.0.2       Arnold Holzel       Initial version 
# 2017-12-11    1.1         Arnold Holzel       Rewritten everything to make sure the logger can handle 
#                                               multiple log formats and gives more info in case of problems.
#                                               Added this change log
# 2017-12-15    1.2         Arnold Holzel       Make use of the give_splunk_paths function that was added to the Splunk_Info class
# 
##################################################################
import logging
import logging.handlers
import os
import re 
import sys

import splunk_info as si
__author__ = 'Arnold Holzel'
__version__ = '1.2'
__license__ = 'Apache License 2.0'

splunk_info = si.Splunk_Info(sessionKey="NA")
script_dir = os.path.dirname(os.path.abspath(__file__))                 # The directory of this script
splunk_paths = splunk_info.give_splunk_paths(script_dir)                # Get info about the Splunk installation
script_log_file = os.path.normpath(splunk_paths['app_root_dir'] + os.sep + 'logs' + os.sep + splunk_paths['app_name'] + '.log')

class Logger:
    def logger_setup(self, name, log_file=script_log_file, level=logging.INFO, format="normal"):
        # Example usage:
        #   log_level = 20 # 10=DEBUG, 20=INFO, 30=WARNING, 40=ERROR, 50=CRITICAL
        #   logger = Logger()
        #   script_logger = logger.logger_setup("script_logger", "/path/to/log/file.log", log_level, "full")
        #   script_logger.debug("With a log_level of 20 this message will not be logged to the file")
        #   script_logger.critical("This message will be logged!!")
        #   
        #   error_logger = logger.logger_setup("error_and_higher", "/path/to/log/error_file.log", 40, "minimal")
        #   (x,y) = (5,0)
        #   try:
        #       z = x/y
        #   except ZeroDivisionError:
        #       error_logger.exception("Are you trying to destroy the world???")
        
        if format == "full":
            log_format = logging.Formatter('%(asctime)s loglevel=%(levelname)s file=%(filename)s line=%(lineno)d function=%(funcName)s message="%(message)s"')
        elif format =="normal":
            log_format = logging.Formatter('%(asctime)s loglevel=%(levelname)s file=%(filename)s line=%(lineno)d message="%(message)s"')
        elif format == "minimal":
            log_format = logging.Formatter('%(asctime)s loglevel=%(levelname)s line=%(lineno)d message="%(message)s"')
        elif format == "raw":
            log_format = logging.Formatter('%(message)s')
        
        if not os.path.exists(os.path.dirname(log_file)):
            try:
                os.makedirs(os.path.dirname(log_file))
            except Exception:
                sys.exit(2)
            
        handler = logging.handlers.RotatingFileHandler(filename=log_file, maxBytes=10485760, backupCount=5)
        handler.setFormatter(log_format)
 
        logger = logging.getLogger(name)
        logger.propagate = False
        logger.setLevel(level)
        logger.addHandler(handler)
    
        return logger

