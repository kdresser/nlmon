#> !P3!

#> 1v0 - initial version

###
### nlmon
###
###     Watch an nginx log folder to document a log roll.
###
###         Nginx's log file naming:
###           Current log file is "*.log", where * is either 
###             "access" or "error".
###           Penultimate log files are named "*.log.1".
###           Older log files are named "*.log.#.gz", where 
###             # is 2..n.
###
###     Recreate and test thoroughly:
###
###         Every observation cycle, look at all files to to get
###         their current state.  Inodes are the file ID.
###         Filenames are derived from inodes whenever a name is
###         needed.
###
###         Missing files (via name) are allowed -- they should 
###         reappear on the next observation.
###
###         ##########
###
###         New simplified method:
###
###           1. Filename patterns: access.log* & error.log* .
###              -> access.log, access.log.1 & access.log.2.gz
###
###           2. If more than one file of a pattern exists, then
###              the older one(s) are static files. This age
###              (from the current "dynamic" file) should prevent 
###              screwups.
###
###           3. When a static file has been processed, it 
###              is moved to a subdirectory (NL2XLOG) and its
###              name is prefixed with a seqn-within-folder.
###              The prefix is needed bcs nginx's renumbering will,
###              once all *.log.*.gz files are processed, 
###              end up producing a steady stream of *.log.1 files.
###
###           4. When only one file of a pattern exists, it is 
###              treated as "live" and is monitored for new growth.
###
###           5. Nginx log rolling should be ignored.
###              If a file disappears (its name changes), recover
###                and POR.
###              When processing a history file, do it all in one 
###                go and use the file handle for the move performed
###                after processing.
###              Downstream processing should still be resistant to
###                resent data.
###
###           6. Survive having a current "live" file being extended
###              and turned into a static penultimate file.
###              A (processed size < file size)-controlled process
###              should work for all situations.
###
###           7. Inode numbers, despite being only a very good, but
###              not guaranteed, stable id, will be used to id files.
###
###           8. A small sqlite3 db will be used for data persistence.
###              ??? Or just a json'd dict textfile?
###

"""
Usage:
  nl2xlog.py [--ini=<ini> --srcid=<srcid> --subid=<subid> \
  --wpath=<wpath> --donesd=<donesd> --interval=<interval> \
  --dotdiv=<dotdiv>  --txtlen=<txtlen> --ofile=<ofile> \
  --txrate=<txrate>]
  nl2xlog.py (-h | --help)
  nl2xlog.py --version

Options:
  -h --help              Show help.
  --version              Show version.
  --ini=<ini>            Overrides default ini pfn.
  --srcid=<srcid>        Source ID ("nx01" for nginx).
  --subid=<subid>        Sub    ID ("____" for nginx).
  --wpath=<wpath>        Path to watched "access.log" and "error.log".
  --donesd=<donesd>      Subdir of wpath for done files. Null disables.
  --interval=<interval>  Logfile watch interval (seconds).
  --dotdiv=<dotdiv>      Nonzero -> dots to screen, with this divisor.
  --txtlen=<txtlen>      Nonzero -> text to screen, with this maxlen.
  --ofile=<ofile>        TCP/IP address (usually) or a file path (dev/test).
  --txrate=<txrate>      Nonzero -> max transmissions per sec.
"""

import os, sys, stat
import time, datetime, calendar
import shutil
import collections
import pickle
import copy
import json
import configparser
import threading
import re
import gzip
import pytz

###import docopt

gP2 = (sys.version_info[0] == 2)
gP3 = (sys.version_info[0] == 3)
assert gP3, 'requires Python 3'

gWIN = sys.platform.startswith('win')
gLIN = sys.platform.startswith('lin')
assert (gLIN or gWIN), 'requires either Linux or Windows'

import pythonpath
pythonpath.set()

import l_dummy
import l_dt as _dt             
import l_misc as _m
import f_helpers as _h

import l_screen_writer
_sw = l_screen_writer.ScreenWriter()             

"""... Not required -- the rpt kv instead.
# A personal logging file? 
# It's hard-coded here in advance of setting up simple logging,
# although there's a backlog queue available to obviate this.
LFPFN = 'LOG.txt'         
if LFPFN:
    LF = open(LFPFN, 'a', encoding=ENCODING, errors=ERRORS)
else:
    LF = None
..."""


import l_simple_logger 
_sl = l_simple_logger.SimpleLogger(screen_writer=_sw, log_file_queue=True)###, log_file=LF)

import l_args as _a                                         # INI + command line args
ME = _a.get_args(version='1.0', docopt=False, clkvs=True)   # No docopt; Yes clkvs.

gRPFN = gRFILE = None
###---gNFILES = gINODES = gSIZES = 0      # Totals for detecting environmental change.

####################################################################################################

SRCID = None                # Client source ID. Immutable, from INI.
SUBID = None                # Client subid. Set by message.
WPATH = None                # Everything is here, until it's sent.
DONESD = None               # Then it's here.                       
INTERVAL = 6                # Seconds.
DOTDIV = None               # Nonzero -> dots to screen, with this divisor.
TXTLEN = None               # Nonzero -> text to screen, with this maxlen. 
OXLOG = None                # Socket connection to an xlog server.
OFILE = None                # Flatfile connection (dev/test).
XFILE = None                # Parameter string -> either OXLOG or OFILE.
NLCODING = 'utf-8'          # Just a guess, for now, that nginx uses UTF-8 for its logs.
ENCODING = 'utf-8'          # Start a utf-8 chain, whether to file or xlog.
ERRORS = 'strict'
OXLOGTS = 0                 # Time of last Tx to xlog.
TXRATE = 0                  # Max number of transmissions per sec.
                            # Transformed to 1 / TXRATE after INI read.
AEL, ASL = '0', '?'         # !MAGIC!  ACCESS EL and SL (error and sub levels).
EEL, ESL = '0', '?'         # !MAGIC!  ERROR  ... 
                            # *EL = 0: unset
                            # *SL = 'a'/'e' for access/error logs.
SELF_SRCID = '0002'         # Self logging source ID.  Defined here, immutable.
SELF_SUBID = '____'         # Self logging subid. Set by message.

####################################################################################################

"""...
import l_dt as _dt          # Date, time helpers.
import l_misc as _m              

import l_screen_writer
_sw = l_screen_writer.ScreenWriter()
..."""

TEST = False                # Hunting short-logrec bug.
TESTONLY = False            # Hunting short-logrec bug.
ONECHECK = False		    # Once around watcher_thread loop.
TIMINGS = False             # Timing in watcher_thread loop.
TRACINGS = False            # Extra details

HEARTBEAT = True            # Emit ae='h' heartbeat records (OFILE and OXLOG).
WAIT4OXLOG = True           # Wait for OXLOG to empty (static files only).

# Extra debugging? (To simple logger, for now.)
DEBUG = False
# Controls which filenames are watched.
DO_ACCESS = True            # access.*
DO_ERROR  = True            # error.*
DO_GZ     = True            # *.gz
DO_N      = True            # #.1..n
DO_LOG    = True            # #.log
DO_MON    = True            # Mode is monitor. 

def doFilename(fn):
    if not ( (DO_ACCESS and fn.startswith('access.')) or 
             (DO_ERROR  and fn.startswith('error.' )) ):
        return False
    return ( (DO_GZ  and fn.endswith('.gz') ) or 
             (DO_N   and fn[-1].isdigit()   ) or 
             (DO_LOG and fn.endswith('.log')) )

"""...
import l_simple_logger 
_sl = l_simple_logger.SimpleLogger(screen_writer=_sw, log_file=LF)

'''...
if LF:
    _sl.extra('----------------------------------------')
...'''

import l_args as _a         # INI + command line args.
ME = _a.get_args(__doc__, '0.1')
..."""

'''... !TEMP!
# XLog Transmit/Receive.
from l_xlogtxrx import XLogTxRx 
...'''

####################################################################################################

#
# As sqlite3 database stores info about log files in watched directory: nlmon.s3:
#   Table logfiles: ('inode', 'ae', 'modified', 'size', 'acquired', 'processed', 'static', 'filename', 'extra')
# Module ffwdb does the db work.
# Note: sqlite3 db must be opened in watcherThread.
# 

FFWDBPFN = FFWDB = None
import ffwdb

####################################################################################################

SQUAWKED = False            # To stop exception message cascades.
def DOSQUAWK(errmsg, beep=3):
    """For exception blocks."""
    global SQUAWKED
    if not SQUAWKED:
        _m.beep(beep)
        for em in errmsg.split('\n'):
            _sl.error(em)
        SQUAWKED = True

####################################################################################################

# Trim whitespace.  Remove trailing comma.  Remove quotes.  '-', ' ', '' -> None.
def _S(s):
    if s is None:
        return
    s = s.strip()
    if s == '':
        return
    s = s.rstrip(',').replace('"', '')
    if s in ['-', ' ', '']:
        s = None
    return s

_LOCTZ = pytz.timezone('America/Vancouver')

# Common Log Format local time str to utc unix-time.
# Depends on whether access or error log.
def CLFlocstr2utcut(ae, locstr):
    # CLF local time to utc.
    # ae==a: [03/Apr/2015:16:56:14 -0700]
    # ae==e: 2015/07/05 23:02:54
    if ae == 'a':
        locstr = locstr[1:-1]
        locdt = datetime.datetime.strptime(locstr, '%d/%b/%Y:%H:%M:%S %z')
        utcdt = locdt.astimezone(pytz.utc)
        utcut = calendar.timegm(utcdt.timetuple())
        pass
    elif ae == 'e':
        locstr = locstr.strip()
        locnaive = datetime.datetime.strptime(locstr, '%Y/%m/%d %H:%M:%S')
        locdt = _LOCTZ.localize(locnaive, is_dst=None)
        utcdt = locdt.astimezone(pytz.utc)
        utcut = calendar.timegm(utcdt.timetuple())
        pass
    else:
        return
    #$#z = _dt.ut2iso(utcut)#$#
    #$#z = z#$#
    return utcut

def tsBDstr(ts):
    # Format timestamp with blank decimal digits.  Decimal point is retained to aid downstream pattern matching.
    return ('%15.4f' % ts).replace('.0000', '.    ')

# Pad IP address to 3 character segments.
def ip15(ip, zeros=True):
    try:
        if zeros:
            y = [('%03d' % int(z.strip())) for z in ip.split('.')]
        else:
            y = [('%3d'  % int(z.strip())) for z in ip.split('.')]
        x = '.'.join(y)
        if len(x) != 15:
            return ip
        return x
    except Exception as E:
        errmsg = str(E)
        return ip

####################################################################################################

# Example access and error log data:

''' ACCESS...
50.138.70.144 - - [05/Jul/2015:07:24:19 -0700] "GET /static/pix/0005/0021-tn.jpg HTTP/1.1" 200 11730 "http://worldofmen.yuku.com/topic/9735/American-Eros-by-Mark-Henderson" "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko"
104.197.107.164 - - [05/Jul/2015:08:03:38 -0700] "GET / HTTP/1.0" 200 144 "-" "NerdyBot"
184.69.80.202 - - [05/Jul/2015:08:47:15 -0700] "GET /dcm/charts_main HTTP/1.1" 200 2969 "http://184.69.80.202/dcm/charts_main" "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.130 Safari/537.36"
104.197.105.249 - - [05/Jul/2015:09:45:06 -0700] "GET / HTTP/1.0" 200 160 "-" "NerdyBot"
184.69.80.202 - - [05/Jul/2015:09:58:51 -0700] "GET /dcm/charts_main HTTP/1.1" 200 2969 "http://184.69.80.202/dcm/charts_main" "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.130 Safari/537.36"
184.69.80.202 - - [05/Jul/2015:10:22:46 -0700] "GET /dcm/charts_main HTTP/1.1" 200 2969 "http://184.69.80.202/dcm/charts_main" "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.130 Safari/537.36"
37.115.191.104 - - [05/Jul/2015:10:44:47 -0700] "GET / HTTP/1.1" 200 154 "http://modabutik.ru/" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322; Alexa Toolbar; (R1 1.5))"
37.115.191.104 - - [05/Jul/2015:10:44:48 -0700] "GET / HTTP/1.1" 200 154 "http://modabutik.ru/" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322; Alexa Toolbar; (R1 1.5))"
37.115.191.104 - - [05/Jul/2015:10:44:49 -0700] "GET / HTTP/1.1" 200 154 "http://modabutik.ru/" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322; Alexa Toolbar; (R1 1.5))"
...'''

''' ERROR...
2015/07/05 23:02:54 [error] 24153#0: *10758 open() "/var/www/184.69.80.202/testproxy.php" failed (2: No such file or directory), client: 185.49.15.23, server: 184.69.80.202, request: "GET http://testp1.piwo.pila.pl/testproxy.php HTTP/1.1", host: "testp1.piwo.pila.pl"
2015/07/06 04:40:59 [error] 24153#0: *10795 open() "/var/www/micromegadesigns/default.php" failed (2: No such file or directory), client: 87.255.31.98, server: micromegadesigns.com, request: "POST /default.php HTTP/1.1", host: "micromegadesigns.com", referrer: "http://micromegadesigns.com/default.php"
2015/07/06 09:35:34 [error] 24153#0: *10860 "/var/www/184.69.80.202/wp-login/index.html" is not found (2: No such file or directory), client: 126.5.87.16, server: 184.69.80.202, request: "GET /wp-login/ HTTP/1.1", host: "www.m14s.com"
2015/07/12 13:29:00 [error] 1203#0: *458 "/var/www/184.69.80.202/wp-login/index.html" is not found (2: No such file or directory), client: 178.165.56.247, server: 184.69.80.202, request: "GET /wp-login/ HTTP/1.1", host: "www.m14s.com"
2015/07/13 01:57:48 [error] 1203#0: *485 connect() failed (111: Connection refused) while connecting to upstream, client: 104.167.184.100, server: 184.69.80.202, request: "GET /pix/t/Banners%202012%20Solos HTTP/1.1", upstream: "http://192.168.100.6:8080/pix/t/Banners%202012%20Solos", host: "184.69.80.202", referrer: "http://worldofmen.yuku.com/topic/9731/Solos-banners-from-2012"
2015/07/13 01:58:54 [error] 1203#0: *487 connect() failed (111: Connection refused) while connecting to upstream, client: 104.167.184.100, server: 184.69.80.202, request: "GET /pix/t/Banners%202013%20Solos HTTP/1.1", upstream: "http://192.168.100.6:8080/pix/t/Banners%202013%20Solos", host: "184.69.80.202", referrer: "http://worldofmen.yuku.com/topic/9732/Solos-banners-from-2013"
2015/07/11 08:51:09 [error] 1203#0: *137 connect() failed (111: Connection refused) while connecting to upstream, client: 50.128.166.78, server: 184.69.80.202, request: "GET /pix/t/American%20Eros%20by%20Mark%20Henderson HTTP/1.1", upstream: "http://192.168.100.6:8080/pix/t/American%20Eros%20by%20Mark%20Henderson", host: "184.69.80.202", referrer: "http://worldofmen.yuku.com/topic/9735/American-Eros-by-Mark-Henderson"
2015/07/11 05:41:17 [error] 1204#0: *117 connect() failed (111: Connection refused) while connecting to upstream, client: 50.153.128.8, server: 184.69.80.202, request: "GET /pix/t/Banners%202014%20Solos HTTP/1.1", upstream: "http://192.168.100.6:8080/pix/t/Banners%202014%20Solos", host: "184.69.80.202", referrer: "http://worldofmen.yuku.com/topic/9733/Solos-banners-from-2014"
...'''

# Detect a host:port string (IPv4).
def detectHP(s):
    h = p = None
    try:    a, b = s.split(':')
    except: return h, p
    if not b.isdigit():
        return h, p
    for x, c in enumerate(a.split('.')):
        if not c.isdigit():
            return h, p
    if not x == 3:
        return h, p
    h, p = a, int(b)
    return h, p

#
# Example ACCESS and ERROR log records.
#

# '184.69.80.202|-|-|[07/Dec/2015:15:04:31|-0800]|"GET /dcm/dcTnPD/T1/0/4/15/-.-? HTTP/1.1"|200|1504|"http://184.69.80.202/dcm/dcTnPD/T1/1/4/15/-.-"|"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.86 Safari/537.36"'

A0 = '108.212.110.142 - - [03/Aug/2015:12:53:06 -0700] "GET /pix/t/American%20Eros%20by%20Mark%20Henderson HTTP/1.1" 200 46 "http://worldofmen.yuku.com/topic/9735/American-Eros-by-Mark-Henderson" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.7.12 (KHTML, like Gecko) Version/7.1.7 Safari/537.85.16"'
A1 = '{"_el": "0", "_id": "TEST", "_ip": null, "_si": "test", "_sl": "_", "_ts": "1438631586.    ", "ae": "a", "body_bytes_sent": 46, "http_referer": "http://worldofmen.yuku.com/topic/9735/American-Eros-by-Mark-Henderson", "http_user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.7.12 (KHTML, like Gecko) Version/7.1.7 Safari/537.85.16", "remote_addr": "108.212.110.142", "remote_user": null, "request": "GET /pix/t/American%20Eros%20by%20Mark%20Henderson HTTP/1.1", "status": 200, "time_local": "[03/Aug/2015:12:53:06 -0700]", "time_utc": 1438631586}'

A2 = '169.229.3.94 - - [05/Jun/2015:23:16:10 -0700] " " 400 181 "-" "-"'
A3 = '{"_el": "0", "_id": "TEST", "_ip": null, "_si": "test", "_sl": "_", "_ts": "1433571370.    ", "ae": "a", "body_bytes_sent": 181, "http_referer": null, "http_user_agent": null, "remote_addr": "169.229.3.94", "remote_user": null, "request": "_", "status": 400, "time_local": "[05/Jun/2015:23:16:10 -0700]", "time_utc": 1433571370}'

A4 = '184.69.80.202 - - [07/Dec/2015:15:04:31 -0800] "GET /dcm/dcTnPD/T1/0/4/15/-.-? HTTP/1.1" 200 1504 "http://184.69.80.202/dcm/dcTnPD/T1/1/4/15/-.-" "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.86 Safari/537.36"'
A5 = '{"_el": "0", "_id": "TEST", "_ip": null, "_si": "test", "_sl": "_", "_ts": "1449529471.    ", "ae": "a", "body_bytes_sent": 1504, "http_referer": "http://184.69.80.202/dcm/dcTnPD/T1/1/4/15/-.-", "http_user_agent": "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.86 Safari/537.36", "remote_addr": "184.69.80.202", "remote_user": null, "request": "GET /dcm/dcTnPD/T1/0/4/15/-.-? HTTP/1.1", "status": 200, "time_local": "[07/Dec/2015:15:04:31 -0800]", "time_utc": 1449529471}'

A6 = '80.69.249.123 - - [11/Dec/2015:14:58:49 -0800] "HEAD / HTTP/1.0" 200 0 "-" "-"'
A7 = '{"_el": "0", "_id": "TEST", "_ip": null, "_si": "test", "_sl": "_", "_ts": "1449874729.    ", "ae": "a", "body_bytes_sent": 0, "http_referer": null, "http_user_agent": null, "remote_addr": "80.69.249.123", "remote_user": null, "request": "HEAD / HTTP/1.0", "status": 200, "time_local": "[11/Dec/2015:14:58:49 -0800]", "time_utc": 1449874729}'

E0 = '2015/08/03 17:48:28 [error] 1199#0: *2502 open() "/var/www/184.69.80.202/wordpress/wp-login.php" failed (2: No such file or directory), client: 58.8.154.9, server: 184.69.80.202, request: "GET /wordpress/wp-login.php HTTP/1.1", host: "wp.go-print.com"'
E1 = '{"_el": "0", "_id": "TEST", "_ip": null, "_si": "test", "_sl": "_", "_ts": "1438649308.    ", "ae": "e", "status": "[error]", "stuff": "1199#0:\\t*2502\\topen()\\t\\"/var/www/184.69.80.202/wordpress/wp-login.php\\"\\tfailed\\t(2:\\tNo\\tsuch\\tfile\\tor\\tdirectory),\\tclient:\\t58.8.154.9,\\tserver:\\t184.69.80.202,\\trequest:\\t\\"GET /wordpress/wp-login.php HTTP/1.1\\",\\thost:\\t\\"wp.go-print.com\\"", "time_local": "2015/08/03 17:48:28", "time_utc": 1438649308}'

E2 = '2015/11/24 07:59:59 [error] 32408#0: *1 open() "/usr/share/nginx/html/pages/j-kelly-dresser.html" failed (2: No such file or directory), client: 184.69.80.202, server: kellydresser.com, request: "GET / HTTP/1.1", host: "kellydresser.com"'
E3 = '{"_el": "0", "_id": "TEST", "_ip": null, "_si": "test", "_sl": "_", "_ts": "1448380799.    ", "ae": "e", "status": "[error]", "stuff": "32408#0:\\t*1\\topen()\\t\\"/usr/share/nginx/html/pages/j-kelly-dresser.html\\"\\tfailed\\t(2:\\tNo\\tsuch\\tfile\\tor\\tdirectory),\\tclient:\\t184.69.80.202,\\tserver:\\tkellydresser.com,\\trequest:\\t\\"GET / HTTP/1.1\\",\\thost:\\t\\"kellydresser.com\\"", "time_local": "2015/11/24 07:59:59", "time_utc": 1448380799}'

E4 = '2015/11/24 07:59:56 [warn] 32401#0: only the last index in "index" directive should be absolute in /etc/nginx/vhosts.cfg:113'
E5 = '{"_el": "0", "_id": "TEST", "_ip": null, "_si": "test", "_sl": "_", "_ts": "1448380796.    ", "ae": "e", "status": "[warn]", "stuff": "32401#0:\\tonly\\tthe\\tlast\\tindex\\tin\\t\\"index\\"\\tdirective\\tshould\\tbe\\tabsolute\\tin\\t/etc/nginx/vhosts.cfg:113", "time_local": "2015/11/24 07:59:56", "time_utc": 1448380796}'

E6 = '2015/07/08 10:18:54 [error] 24152#0: *11229 open() "/var/www/184.69.80.202/ROADS/cgi-bin/search.plHTTP/1.0"" failed (2: No such file or directory), client: 31.184.194.114, server: 184.69.80.202, request: "GET /ROADS/cgi-bin/search.plHTTP/1.0" HTTP/1.1", host: "184.69.80.202"'
#6 = '2015/07/08 10:18:54 [error] 24152#0: *11229 open() "/var/www/184.69.80.202/ROADS/cgi-bin/search.pl" failed (2: No such file or directory), client: 31.184.194.114, server: 184.69.80.202, request: "GET /ROADS/cgi-bin/search.pl HTTP/1.1", host: "184.69.80.202"'
E7 = '{"_el": "0", "_id": "TEST", "_ip": null, "_si": "test", "_sl": "_", "_ts": "1436375934.    ", "ae": "e", "status": "[error]", "stuff": "24152#0:\\t*11229\\topen()\\t\\"/var/www/184.69.80.202/ROADS/cgi-bin/search.pl\\"\\tfailed\\t(2:\\tNo\\tsuch\\tfile\\tor\\tdirectory),\\tclient:\\t31.184.194.114,\\tserver:\\t184.69.80.202,\\trequest:\\t\\"GET /ROADS/cgi-bin/search.pl HTTP/1.1\\",\\thost:\\t\\"184.69.80.202\\"", "time_local": "2015/07/08 10:18:54", "time_utc": 1436375934}'

#
# parseLogrec   
#               
def parseLogrec(ae, logrec):
    """Parse logrec into chunks."""
    me = 'parseLogrec(%s, %s)' % (repr(ae), repr(logrec))
    rc, rm, chunks = -1, '???', None
    try:

        # Blanks and quoted blanks.
        z = logrec
        if '  ' in logrec:
            logrec = logrec.replace('  ', ' ')
        logrec = logrec.replace(' " " ', ' "_" ')   # OK to lose a quoted blank.  Shouldn't appear at front or back.
        if logrec != z:
            z, logrec = z, logrec

        # nginx has a quirk: 
        z = logrec
        y = 'HTTP/1.0"'                             # These are inserted randomly and the extra '"' screws up quoting.
        undo_lc = False
        while True:
            x = logrec.find(y)
            if x == -1:
                break
            if logrec[x-1] == ' ':
                logrec = logrec.replace(y, y.lower())   # Hide.
                undo_lc = True
            else:
                logrec = logrec.replace(y, '')          # !!! Zap!
        if undo_lc:
            logrec = logrec.replace(y.lower(), y)
        if logrec != z:
            z, logrec = z, logrec

        # Find blank separated words.
        words = logrec.split(' ')
        chunks = []
        quoted = False

        # Recombine quoted chunks.  Keep quotes.
        for wrd in words:
            if quoted:
                chk += (' ' + wrd)
                if wrd.endswith('"') or wrd.endswith('",'):
                    chunks.append(chk)
                    chk = ''
                    quoted = False
                else:
                    1/1
            else:
                if wrd[0] == '"':
                    if wrd.endswith('"') or wrd.endswith('",'):
                        chk = wrd
                        chunks.append(chk)
                    else:
                        chk = wrd
                        quoted = True
                else:
                    chunks.append(wrd)
        chunks = chunks

        # Check quoted chunks.
        for chk in chunks:
            if chk[0] == '"':
                if not ((chk[-1] == '"') or chk.endswith('",')):
                    _m.beep(1)
                    logrec = logrec
                    chk = chk
                    chunks = chunks
                    errmsg = 'bad chunk: {}: {}'.format(chk, logrec)
                    ###_sl.error(errmsg)
                    rc, rm = 1, errmsg
                    return rc, rm, chunks

        # Done.
        rc, rm, chunks = 0, 'OK', chunks
        return rc, rm, chunks

    except Exception as E:
        ###---rc, rm, chunks = 1, errmsg, None
        errmsg = '%s: %s @ %s' % (me, E, _m.tblineno())
        DOSQUAWK(errmsg)
        raise
    finally:
        if rc != 0:
            rc, rm, chunks = rc, rm, chunks
        ###---return rc, rm, chunks
        1/1

#
# genACCESSorec
#
def genACCESSorec(chunks, ae, el, sl, srcid, subid, decorated=False):
    """Generate an ACCESS orec from chunks."""
    me = 'genACCESSorec'
    rc, rm, orec, vrec = -1, '???', None, None
    try:

        if len(chunks) != 10:
            errmsg = 'expecting 10 fields but got %d from: %s' % (len(chunks), repr('|'.join(chunks)))
            rc, rm = 1, errmsg
            return rc, rm, orec, vrec

        (remote_addr, ignored, remote_user, 
            a, b, request, status, 
            body_bytes_sent, http_referer, http_user_agent) = chunks
        if request in ('', '""', '"_"'):
            request = None
        time_local = a + ' ' + b                    # '[03/Aug/2015:12:53:06' + ' ' + '-0700]'
        if remote_user == '-':
            remote_user = None

        time_utc = CLFlocstr2utcut(ae, time_local)  # 1438631586                # '1438631586.    '
        time_utc_iso = _dt.ut2iso(time_utc)         # '2015-08-03 19:53:06'
        status = int(status)
        body_bytes_sent = int(body_bytes_sent)
        remote_addr     = remote_addr
        ignored         = ignored
        remote_user     = remote_user
        time_local      = time_local
        time_utc        = time_utc
        time_utc_iso    = time_utc_iso
        status          = status
        request         = request
        body_bytes_sent = body_bytes_sent
        http_referer    = http_referer
        http_user_agent = http_user_agent
        logdict = {
            '_ip'             : None,               # Will be filled in by logging server.
            '_ts'             : tsBDstr(time_utc),  # '1234567890.    ' format.
            '_id'             : srcid,
            '_si'             : subid,
            '_el'             : el,                 # Raw, base error_level.
            '_sl'             : sl,                 # Raw, base sub_level.
            'ae'              : ae,                 # Access or Error.
            'remote_addr'     : remote_addr,
            'remote_user'     : remote_user,
            'time_local'      : time_local,
            'time_utc'        : time_utc,
            'status'          : status,
            'request'         : _S(request),
            'body_bytes_sent' : body_bytes_sent,
            'http_referer'    : _S(http_referer), 
            'http_user_agent' : _S(http_user_agent)
        }

        rc, rm = 0, 'OK'        
        ldj = json.dumps(logdict, ensure_ascii=True, sort_keys=True)
        if decorated:
            # Prepend a copy of the timetamp (for sorting).
            orec = '%s|%s|%s' % (logdict['_ts'], ae, ldj)  
        else:
            orec = ldj

        if TXTLEN > 0:
            vrec = ('%s|%s|%s|%s|%s' % (ip15(remote_addr), str(el), str(sl), ae, str(request)))[:TXTLEN]
            vrec = vrec

        return rc, rm, orec, vrec

    except Exception as E:
        ###---rc, rm, orec = 1, errmsg, None
        errmsg = '%s: %s @ %s' % (me, E, _m.tblineno())
        DOSQUAWK(errmsg)
        raise
    finally:
        ###---return rc, rm, orec, vrec
        1/1

#
# genERRORorec
#
def genERRORorec(chunks, ae, el, sl, srcid, subid, decorated=False):
    """Generate an ERROR orec from chunks."""
    me = 'genERRORorec'
    rc, rm, orec, vrec = -1, '???', None, None
    try:

        time_local = chunks.pop(0) + ' ' + chunks.pop(0)
        time_utc = CLFlocstr2utcut(ae, time_local)
        time_utc_iso = _dt.ut2iso(time_utc)

        status = chunks.pop(0)
        if status not in ('[warn]', '[error]'):  
            errmsg = 'unexpected status: ' + repr(status)
            pass        # POR

        if status == '[warn]':
            pass

        # The remaining chunks are inconsistently formatted "stuff".
        stuff = '\t'.join(chunks)

        # But try to find "remote_addr", "request", "server".
        remote_addr, request, server = '999.999.999.999', '', ''
        z = copy.copy(chunks)
        while z:
            y = z.pop(0)
            if y == 'client:':
                remote_addr = z.pop(0).rstrip(',')
                continue
            if y == 'server:':
                server = z.pop(0).rstrip(',')
                continue
            if y == 'request:':
                request = z.pop(0).rstrip(',')
        remote_addr, request, server = remote_addr, request, server
        if not request:
            chunks = chunks

        # Skeleton ERROR logdict.
        logdict = {
            '_ip'             : None,               # Will be filled in by logging server.
            '_ts'             : tsBDstr(time_utc),  # '1234567890.    ' format.
            '_id'             : srcid,
            '_si'             : subid,
            '_el'             : el,                 # Raw, base error_level.
            '_sl'             : sl,                 # Raw, base sub_level.
            'ae'              : ae,                 # Access or Error.
            'time_local'      : time_local,
            'time_utc'        : time_utc,
            'status'          : status,             # In ('[warn]', '[error]').
            'stuff'           : stuff               # Inconsistently formatted stuff. 
        }

        rc, rm = 0, 'OK'        
        ldj = json.dumps(logdict, ensure_ascii=True, sort_keys=True)
        if decorated:
            # Prepend a copy of the timetamp (for sorting).
            orec = '%s|%s|%s' % (logdict['_ts'], ae, ldj)  
        else:
            orec = ldj

        if TXTLEN > 0:
            vrec = ('%s|%s|%s|%s|%s %s' % 
                    (ip15(remote_addr), str(el), str(sl), ae, server, request))[:TXTLEN]
            vrec = vrec

        return rc, rm, orec, vrec

    except Exception as E:
        ###---rc, rm, orec = 1, errmsg, None
        errmsg = '%s: %s @ %s' % (me, E, _m.tblineno())
        DOSQUAWK(errmsg)
        raise
    finally:
        if rc != 0:
            rc, rm, orec = rc, rm, orec
        ###---return rc, rm, orec, vrec
        1/1

####################################################################################################

#
# shutDown
#
def shutDown():
    try:  OXLOG.disconnect()
    except:  pass
    try:  OFILE.close()
    except:  pass

#
# inode2filename
#
def inode2filename(inode):
    for filename in os.listdir(WPATH):
        fi = getFI(filename)
        if fi['inode'] == inode:
            return filename

#
# exportLogrec
#
def exportLogrec(ae, logrec):
    """Export a raw log record: parse, gen a/e orec, output to xlog/file."""
    me = 'exportLogrec(%s, %s)' % (repr(ae), repr(logrec))
    try:

        # logrec?
        try:  logrec = logrec.strip()
        except:  pass
        if not logrec:
            return
            
        # Parse logrec.
        rc, rm, chunks = parseLogrec(ae, logrec)
        if rc != 0:
            _m.beep(1)
            try:    z = '|'.join(chunks)
            except: z = ''
            errmsg = '%s: parse_logrec: %d:, %s, %s' % (me, rc, rm, z)
            _sl.error(errmsg)
            return

        # ACCESS log?
        if   ae == 'a':
            rc, rm, orec, vrec = genACCESSorec(chunks, 'a', AEL, 'a', SRCID, SUBID)
            if rc != 0:
                _m.beep(1)
                try:    z = '|'.join(chunks)
                except: z = ''
                errmsg = '%s: gen_access_orec: %d:, %s, %s' % (me, rc, rm, z)
                _sl.error(errmsg)
                return
            
        # ERROR log?
        elif ae == 'e':
            rc, rm, orec, vrec = genERRORorec(chunks, 'e', EEL, 'e', SRCID, SUBID)
            if rc != 0:
                _m.beep(1)
                try:    z = '|'.join(chunks)
                except: z = ''
                errmsg = '%s: parse_gen_error_orec: %d:, %s, %s' % (me, rc, rm, z)
                _sl.error(errmsg)
                return

        else:
            raise ValueError('export: bad _ae: ' + repr(ae))

        # TCP/IP?
        if OXLOG:
            try:
                rc = OXLOG.send(orec.encode(encoding=ENCODING, errors=ERRORS))
            except Exception as E:
                errmsg = '%s: oxlog: %s' % (me, E)
                DOSQUAWK(errmsg)
                raise

        # Flatfile?
        if OFILE:
            try:
                OFILE.write(orec + '\n')    # Opened with encoding=ENCODING, errors=ERRORS.
            except Exception as E:
                errmsg = '%s: ofile: %s' % (me, E)
                DOSQUAWK(errmsg)
                raise

        # Screen?
        if TXTLEN > 0:
            pass
            _sl.extra(vrec)

    except Exception as E:
        errmsg = '%s: %s @ %s' % (me, E, _m.tblineno())
        DOSQUAWK(errmsg)
        raise

def testS2E(ae, s2e):
    if not (TEST and ae and s2e):
        return
    me = 'testS2E'
    _sl.info()
    _sl.info('{:s}:  {:s}  {:,d} bytes'.format(me, ae, len(s2e)))
    ne = 0
    try:
        if s2e[-1] == '\n':
            _sl.info('ends with \\n')
        else:
            _sl.info('does not end with \\n')
        for x, logrec in enumerate(s2e.split('\n')):
            if not logrec:
                continue
            rc, rm, chunks = parseLogrec(ae, logrec)
            if rc:
                _sl.error('%6d: %s' % (x+1, repr(logrec)))
                _sl.error('%6d: %d  %s  %d chunks' % (x+1, rc, rm, len(chunks)))
                ne += 1
                continue
            if ae == 'e':
                if TRACINGS:
                    _sl.info('%6d: %s' % (x+1, repr(logrec)))
                _sl.info('%6d: %d  %s  %d chunks' % (x+1, rc, rm, len(chunks)))
                continue
            if len(chunks) == 10:
                if TRACINGS:
                    _sl.info('%6d: %s' % (x+1, repr(logrec)))
                _sl.info('%6d: %d  %s  %d chunks' % (x+1, rc, rm, len(chunks)))
                continue
            else:
                _sl.error('%6d: %s' % (x+1, repr(logrec)))
                _sl.error('%6d: %d  %s  %d chunks' % (x+1, rc, rm, len(chunks)))
                ne += 1
                continue
            pass
        return (ne == 0)
    except Exception as E:
        rc = False
        errmsg = '%s: %s @ %s' % (me, E, _m.tblineno())
        DOSQUAWK(errmsg)
        pass
    finally:
        ###---return (ne == 0)
        1/1

#
# Export a file, either history (whole file) or live (incremental).
#
def exportFile(fi):
    """Export a file (from info dict)."""
    global FWTSTOP
    ae = fi['ae']
    fn = fi['filename']
    me = 'exportFile(%d  %s  %s)' % (fi['inode'], ae, fn)
    _sl.info('%s  %s' % (_dt.ut2iso(_dt.locut()), fn))#$#
    if DEBUG:
        _sl.debug('%s  >> export  %s  %s' %(_dt.ut2iso(_dt.locut()), ae, fn))
        dumpFI(_sl.debug, fi)
    try:

        # A flag to indicate that processing happened.
        processed2db = False        

        # How many bytes of file is to be exported?
        fprocessed = fi['processed']
        fsize = fi['size']
        if fprocessed >= fsize:
            return

        # Still exists (not renamed)?
        pfn = os.path.normpath(WPATH + '/' + fn)
        if not os.path.isfile(pfn):
            return                      # Skip and do it later.

        # .gz files are always treated as static, and 
        # the whole file is read. (No seek!)
        if pfn.endswith('.gz'):          
            with gzip.open(pfn, 'r') as f:      # Can't decode on the fly.
                for x, logrec in enumerate(f):
                    if FWTSTOP:
                        break
                    logrec = logrec.decode(encoding=ENCODING, errors=ERRORS)
                    # Dots?
                    if DOTDIV and not (x % DOTDIV):
                        _sw.iw('.')
                    #
                    exportLogrec(ae, logrec)
            fprocessed = fsize
            processed2db = True
            return

        # Uncompressed files are read as text, with an initial
        # seek from the SOF. The file is read to its end, even
        # if this goes beyond the size given, which will 
        # happen if NGINX appends to this file while we're 
        # processing it. This will result in the appendage 
        # being reprocessed next time around, but this is 
        # harmless bcs logrec processing is able to handle (skip)
        # duplicates.
        with open(pfn, 'r', encoding=ENCODING, errors=ERRORS) as f:
            if fprocessed > 0:
                _sl.info('skipping {:,d} bytes'.format(fprocessed))
                f.seek(fprocessed)
            for x, logrec in enumerate(f):
                if FWTSTOP:
                    break
                if not (x % 1000):
                    _sw.iw('.')
                exportLogrec(ae, logrec)
            fprocessed = fsize
            processed2db = True
            return

    except Exception as E:
        errmsg = '%s: %s @ %s' % (me, E, _m.tblineno())
        DOSQUAWK(errmsg)
        raise
    finally:
        # End dots.
        _sw.nl()
        # Close src file.
        try:  f.close
        except:  pass
        # Update 'processed'?
        if processed2db and not TESTONLY:
            fi['processed'] = fprocessed
            z = {'inode': fi['inode'], 'processed': fprocessed}
            FFWDB.update(z)
            if DEBUG:
                _sl.debug('%s  >> db processed: %d' %(_dt.ut2iso(_dt.locut()), fprocessed))
        # Wait for OXLOG to flush?
        if fi['static'] and WAIT4OXLOG and OXLOG:
            action = 'WAIT4OXLOG'
            nsw = 0
            try:
                while len(OXLOG.txbacklog) > 1:
                    _sw.iw('|')
                    time.sleep(1)
                    nsw += 1
                    if nsw > 180:                        # !MAGIC!  Give up after three minutes.
                        raise Exception('timeout')
                _sw.nl()
            except Exception as E:
                errmsg = '%s: %s' % (action, E)
                DOSQUAWK(errmsg)
                raise

#
# doneWithFile
#
def doneWithFile(_ino, _fn):
    """Move _fn to DONESD."""
    me = 'doneWithFile(%d, %s)' % (_ino, repr(_fn))
    _sl.info(me)
    moved = False   # Pessimistic.
    try:
        # Moving?
        if not DONESD:
            return
        # Count files in sink path to make a seqn prefix for 
        # the sink filename.
        snk = os.path.normpath(WPATH + '/' + DONESD)
        n = 0
        for filename in os.listdir(snk):
            n += 1
        pfx = '%06d-' % (n+1)
        # First try at moving the file.
        src = os.path.normpath(WPATH + '/' + _fn)
        snk = os.path.normpath(WPATH + '/' + DONESD + '/' + pfx + _fn)
        try:
            shutil.move(src, snk)
            moved = True
            return                  # Early exit!
        except Exception as E:
            _m.beep(3)
            errmsg = 'moving %s to %s failed: %s' % (_fn, DONESD, E)
            _sl.warning(errmsg)
            pass                    # POR
        # Find current (rolled?) filename for _ino.
        _fn = inode2filename(_ino)
        '''...
        _fn = None
        for filename in os.listdir(WPATH):
            fi = getFI(filename)
            if fi['inode'] == _ino:
                _fn = fi['filename']
                break
        ...'''
        if _fn is None:
            errmsg = 'cannot find filename for inode %d' % _ino
            raise ValueError(errmsg)
        msg = 'found filename %s for inode %d' % (_fn, _ino)
        _sl.warning(msg)
        # Second & final try at moving the file.
        src = os.path.normpath(WPATH + '/' + _fn)
        snk = os.path.normpath(WPATH + '/' + DONESD + '/' + pfx + _fn)
        try:
            shutil.move(src, snk)
            moved = True
        except Exception as E:
            errmsg = 'moving %s to %s failed: %s' % (_fn, DONESD, E)
            DOSQUAWK(errmsg)
            raise
        _sl.info('moved %s to %s' % (_fn, DONESD))
    except Exception as E:
        errmsg = '%s: E: %s @ %s' % (me, E, _m.tblineno())
        DOSQUAWK(errmsg)
        raise
    finally:
        if moved:
            FFWDB.delete(_ino)

#
# dumpFI
#
def dumpFI(sl, fi, pfx=''):
    '''...
    inode       integer,
    ae          text,
    modified    real,
    size	    integer,
    acquired    real,
    processed	integer,
    static      integer,
    filename    text,
    extra       text)
    ...'''
    try:
        sl('{}     inode: {}'.format(pfx, fi.get('inode')))
        sl('{}        ae: {}'.format(pfx, fi.get('ae')))
        sl('{}  modified: {}'.format(pfx, fi.get('modified')))
        sl('{}      size: {}'.format(pfx, fi.get('size')))
        sl('{}  acquired: {}'.format(pfx, fi.get('acquired')))
        sl('{} processed: {}'.format(pfx, fi.get('processed')))
        sl('{}    static: {}'.format(pfx, fi.get('static')))
        sl('{}  filename: {}'.format(pfx, fi.get('filename')))
        sl('{}     extra: {}'.format(pfx, fi.get('extra')))
    except Exception as E:
        errmsg = 'dumpFI: E: %s' % E
        DOSQUAWK(errmsg)
        raise
        '''...
        _sl.error(errmsg)
        raise RuntimeError(errmsg)
        ...'''

#
# deltaFIs
#
def deltaFIs(sl, fi0, fi1, pfx0='', pfx1='', both=False):
    '''
                inode       integer,
                ae          text,
                modified    real,
                size	    integer,
                acquired    real,
                processed	integer,
                static  	integer,
                filename    text,
                extra       text)
    '''
    if both or (fi0['inode']     != fi1['inode']):
        sl('{}     inode: {}'.format(pfx0, fi0['inode']))
        sl('{}          : {}'.format(pfx1, fi1['inode']))
    if both or (fi0['ae']        != fi1['ae']):
        sl('{}        ae: {}'.format(pfx0, fi0['ae']))
        sl('{}          : {}'.format(pfx1, fi1['ae']))
    if both or (fi0['modified']  != fi1['modified']):
        sl('{}  modified: {}'.format(pfx0, fi0['modified']))
        sl('{}          : {}'.format(pfx1, fi1['modified']))
    if both or (fi0['size']      != fi1['size']):
        sl('{}      size: {}'.format(pfx0, fi0['size']))
        sl('{}          : {}'.format(pfx1, fi1['size']))
    if both or (fi0['acquired']  != fi1['acquired']):
        sl('{}  acquired: {}'.format(pfx0, fi0['acquired']))
        sl('{}          : {}'.format(pfx1, fi1['acquired']))
    if both or (fi0['processed'] != fi1['processed']):
        sl('{} processed: {}'.format(pfx0, fi0['processed']))
        sl('{}          : {}'.format(pfx1, fi1['processed']))
    if both or (fi0['static']    != fi1['static']):
        sl('{}    static: {}'.format(pfx0, fi0['static']))
        sl('{}          : {}'.format(pfx1, fi1['static']))
    if both or (fi0['filename']  != fi1['filename']):
        sl('{}  filename: {}'.format(pfx0, fi0['filename']))
        sl('{}          : {}'.format(pfx1, fi1['filename']))
    if both or (fi0['extra']     != fi1['extra']):
        sl('{}     extra: {}'.format(pfx0, fi0['extra']))
        sl('{}          : {}'.format(pfx1, fi1['extra']))

#
# diffFIs
#
def diffFIs(fi0, fi1):
    '''
                inode       integer,
                ae          text,
                modified    real,
                size	    integer,
                acquired    real,
                processed	integer,
                static  	integer,
                filename    text,
                extra       text)
    '''
    return ( (fi0['inode']     != fi1['inode']    ) or \
             (fi0['ae']        != fi1['ae']       ) or \
             (fi0['modified']  != fi1['modified'] ) or \
             (fi0['size']      != fi1['size']     ) or \
             (fi0['processed'] != fi1['processed']) or \
             (fi0['static']    != fi1['static']   ) or \
             (fi0['filename']  != fi1['filename'] ) or \
             (fi0['extra']     != fi1['extra']    ) )
    #        (fi0['acquired']  != fi1['acquired'] ) or \    # 'acquired' not part of comparison.

#
# updateDB: Add to or update FFWDB, given a file info dict.
#
def updateDB(fi):
    """Update FFWDB from given file info dict.  Returns db_fi."""
    me = 'updateDB'
    db_fi = None
    try:
        db_fi = FFWDB.select(fi['inode'])
        # Insert?
        if not db_fi:
            if DEBUG:
                _sl.debug('%s  ++ db add:' % (_dt.ut2iso(_dt.locut())))
                dumpFI(_sl.debug, db_fi, 'ins: ')
            z = copy.copy(db_fi)
            z['processed'] = 0
            db_fi = FFWDB.insert(z)
            z = None
            if not db_fi:
                raise ValueError('db insertion failed')
        # Update:
        else:
            #       'inode'
            #       'ae'
            #       'acquired'
            #       'processed'
            if db_fi['modified'] != fi['modified'] or \
               db_fi['size']     != fi['size'] or \
               db_fi['static']   != fi['static'] or \
               db_fi['filename'] != fi['filename'] or \
               db_fi['extra']    != fi['extra']:
                fi0 = copy.copy(db_fi)
                z = {}
                z['inode']    = fi['inode']
                z['acquired'] = fi['acquired']
                z['modified'] = fi['modified']
                z['size']     = fi['size']
                z['static']   = fi['static']
                z['extra']    = fi['extra']
                db_fi = FFWDB.update(z)
                fi1 = copy.copy(db_fi)
                z = None
                if DEBUG:
                    _sl.debug('%s  ~~ db update:' %(_dt.ut2iso(_dt.locut())))
                    deltaFIs(_sl.debug, fi0, fi1, 'b: ', 'a: ')
            else:
                pass
            pass
        return db_fi
    except Exception as E:
        ###---db_fi = None
        errmsg = '%s: E: %s @ %s' % (me, E, _m.tblineno())
        DOSQUAWK(errmsg)
        raise
    finally:
        ###---return db_fi
        1/1

#
# watcherThread
#
FWTRUNNING = False  # File Watcher Thread Running.
FWTSTOP = False     # To signal a thread stop.
FWTSTOPPED = False  # To acknowledge a thread stop.
def watcherThread():                                                # !WT! 
    """A thread to watch WPATH for files to process."""
    global FFWDB, FWTRUNNING, FWTSTOP, FWTSTOPPED
    me = 'FWT'
    _sl.info(me + ' starts')
    try:
        FWTRUNNING = True

        # Connect to FlatFileWatchDataBase.
        FFWDB = ffwdb.FFWDB(FFWDBPFN)
        # Initialize extra dict.
        ed = FFWDB.extra()
        if not ed:
            ed = FFWDB.extra({'nfiles': 0})
        uu = 0                                                  # Unix Utc.
        while not FWTSTOP:
           
            # Wait out INTERVAL.
            z = time.time()
            w = INTERVAL - (z - uu)
            if w > 0:
                _sw.wait(w)
            uu = _dt.utcut()
            ul = _dt.locut(uu)
            uuts = '%15.4f' % uu                                # 15.4, unblanked fraction.
            uuiosfs = _dt.ut2isofs(uu)
            uliosfs = _dt.ut2isofs(ul)

            """...
            # Heartbeat?
            if HEARTBEAT:
                try:
                    logdict = {
                        '_ip'             : None,               # Will be filled in by logging server.
                        '_ts'             : uuts,               # '1234567890.9876' format.
                        '_id'             : SRCID,
                        '_si'             : SUBID,
                        '_el'             : '0',                # Raw, base error_level.
                        '_sl'             : 'h',                # Heartbeat.
                        'ae'              : 'h',                # Access or Error or Heartbeat.
                        'dt_utc'          : uuiosfs,    
                        'dt_loc'          : uliosfs
                    }
                    orec = json.dumps(logdict, ensure_ascii=True, sort_keys=True) 
                    if OXLOG:
                        try:
                            rc = OXLOG.send(orec.encode(encoding=ENCODING, errors=ERRORS))
                        except Exception as E:
                            errmsg = '%s: heartbeat oxlog: %s' % (me, E)
                            DOSQUAWK(errmsg)
                            raise
                    if OFILE:
                        try:
                            OFILE.write(orec + '\n')    # Opened with encoding=ENCODING, errors=ERRORS.
                        except Exception as E:
                            errmsg = '%s: heartbeat ofile: %s' % (me, E)
                            DOSQUAWK(errmsg)
                            raise
                except Exception as E:
                    errmsg = '%s: heartbeat E: %s' % (me, E)
                    DOSQUAWK(errmsg)
                    raise
            ..."""

            ####!!!
            #_sl.extra('Hello World!')
            #continue
            ####!!!

            #
            # Get current file FIs.
            #
            1/1
            t0 = time.perf_counter();
            c_fis = getFIs(uu)
            c_fis_in = {c_fi['inode'   ]: c_fi for c_fi in c_fis}
            c_fis_fn = {c_fi['filename']: c_fi for c_fi in c_fis}
            t1 = time.perf_counter();
            if TIMINGS:
                _sl.warning('   getFIs: {:9,.1f} ms'.format((1000*(t1-t0))))
            if DEBUG:
                _sl.debug('%s  ## %d cfiles found' % (_dt.ut2iso(_dt.locut()), len(c_fis)))

            #
            # Get database file FIs.
            #
            1/1
            t0 = time.perf_counter();
            db_fis = FFWDB.all()
            db_fis_in = {db_fi['inode'   ]: db_fi for db_fi in db_fis}
            db_fis_fn = {db_fi['filename']: db_fi for db_fi in db_fis}
            t1 = time.perf_counter();
            if TIMINGS:
                _sl.warning('FFWDB.all: {:9,.1f} ms'.format((1000*(t1-t0))))
            if DEBUG:
                _sl.debug('%s  ## %d dbfiles found' % (_dt.ut2iso(_dt.locut()), len(db_fis)))

            if True:

                #
                # Compare current vs database by inode.
                #
                1/1
                c_ins = set([c_fi['inode'] for c_fi in c_fis])
                db_ins = set([db_fi['inode'] for db_fi in db_fis])
                db_drops_ins = list(db_ins - c_ins)
                db_adds_ins = list(c_ins - db_ins)
                db_same_ins = list(c_ins & db_ins)
                #
                if db_drops_ins:
                    _sl.extra()
                    _sl.extra('inoded drops...')
                    for din in db_drops_ins:
                        _sl.extra()
                        db_fi = db_fis_in[din]
                        dumpFI(_sl.extra, db_fi, 'id: ')
                #
                if db_adds_ins:
                    _sl.extra()
                    _sl.extra('inoded adds...')
                    for ain in db_adds_ins:
                        _sl.extra()
                        c_fi = c_fis_in[ain]
                        dumpFI(_sl.extra, c_fi, 'ia: ')
                # Compare common inodes.
                db_upds = []
                for sin in db_same_ins:
                    c_fi, db_fi = c_fis_in[sin], db_fis_in[sin]
                    if diffFIs(c_fi, db_fi):
                        db_upds.append((c_fi, db_fi))
                if db_upds:
                    ###---_sl.extra()
                    ###---_sl.extra('inoded updates...')
                    for c_fi, db_fi in db_upds:
                        sl = _sl.extra if c_fi['static'] and db_fi['static'] else _sl.warning
                        sl()
                        sl('inode updated: {} @ {}'.format(c_fi['inode'], _dt.ut2iso(_dt.utc2loc(c_fi['modified']), ' ')))
                        deltaFIs(sl, db_fi, c_fi, 'd: ', 'c: ')

                #
                # Compare current vs database by filename.
                #
                1/1
                c_fns = set([c_fi['filename'] for c_fi in c_fis])
                db_fns = set([db_fi['filename'] for db_fi in db_fis])
                db_drops_fns = list(db_fns - c_fns)
                db_adds_fns = list(c_fns - db_fns)
                db_same_fns = list(c_fns & db_fns)
                if db_drops_fns:
                    _sl.extra()
                    _sl.extra('filenamed drops...')
                    for dfn in db_drops_fns:
                        db_fi = db_fis_fn[dfn]
                        _sl.extra()
                        dumpFI(_sl.extra, db_fi, 'fd: ')
                if db_adds_fns:
                    _sl.extra()
                    _sl.extra('filenamed adds...')
                    for afn in db_adds_fns:
                        c_fi = c_fis_fn[afn]
                        _sl.extra()
                        dumpFI(_sl.extra, c_fi, 'fa: ')
                # Compare common filenames.
                z_upds = []
                for sfn in db_same_fns:
                    c_fi, db_fi = c_fis_fn[sfn], db_fis_fn[sfn]
                    if diffFIs(c_fi, db_fi):
                        z_upds.append((c_fi, db_fi))
                if z_upds:
                    ###---_sl.extra()
                    ###---_sl.extra('filenamed updates...')
                    for c_fi, db_fi in z_upds:
                        sl = _sl.extra if c_fi['static'] and db_fi['static'] else _sl.warning
                        sl()
                        sl('fname updated: {} @ {}'.format(c_fi['filename'], _dt.ut2iso(_dt.utc2loc(c_fi['modified']), ' ')))
                        deltaFIs(sl, db_fi, c_fi, 'd: ', 'c: ')

            if False:
                # Number of files different than DB?
                if len(c_fis) != ed['nfiles']:
                    _sl.extra()
                    msg = 'from {} to {} files'.format(ed['nfiles'], len(c_fis))
                    _sl.extra(msg)
                    # Examine current FIs.
                    for c_fi in c_fis:
                        _sl.extra()
                        # Current inode and filename.
                        cin = c_fi['inode']
                        cfn = c_fi['filename']
                        msg = 'cin {}  cfn \'{}\''.format(cin, cfn)
                        _sl.extra(msg)
                        # Get DB FI for cin.
                        db_fi = FFWDB.select(cin)
                        if db_fi:
                            # DB filename for current inode.
                            dbfn = db_fi['filename']   
                            # Same as current filename?
                            if dbfn == cfn:
                                msg = 'same'
                            else:
                                msg = 'd: {} -> \'{}\''.format(cin, dbfn, cfn)
                                _sl.extra(msg)
                            # Dump current and database FIs, interleaved.
                            deltaFIs(_sl.extra, db_fi, c_fi, 'd: ', 'c: ', both=True)
                        else:
                            # Current inode not in DB.
                            dbfn = '<DNE>'
                            # Dump current FI
                            _sl.extra()
                            #~dumpFI(_sl.extra, c_fi, 'c: ')
                            deltaFIs(_sl.extra, nullFI(), c_fi, 'd: ', 'c: ', both=True)
                    _sl.extra()
                    #
                    ed['nfiles'] = len(c_fis)
                    ed = FFWDB.extra(ed)
     
            if False:
                # Update FFWDB.
                if c_fis:
                    t0 = time.perf_counter();
                    inodes = tuple(c_fi['inode'] for c_fi in c_fis)
                    FFWDB.acquired(inodes, uu)
                    for c_fi in c_fis:
                        db_fi = updateDB(c_fi)
                    t1 = time.perf_counter();
                    if TIMINGS:
                        _sl.warning('updateDBs: {:9,.1f} ms'.format((1000*(t1-t0))))

            if False:
                # Remove drops from DB.
                cinodes = [c_fi['inode'] for c_fi in c_fis]
                dbinodes = FFWDB.inodes()
                nd = 0
                for dbinode in dbinodes:
                    if dbinode not in cinodes:
                        FFWDB.delete(dbinode)
                        nd += 1
                if nd:
                    dbinodes = FFWDB.inodes()

            if False:
                # Update ed['nfiles'].
                ed['nfiles'] = len(dbinodes)
                ed = FFWDB.extra(ed)
     
            if True:

                # Update DB (NEW).
                1/1
                t0 = time.perf_counter();
                inodes = tuple(c_fi['inode'] for c_fi in c_fis)
                FFWDB.acquired(inodes, uu)
                for c_fi, db_fi in db_upds:
                    z = updateDB(c_fi)
                    c_fi, z = c_fi, z
                t1 = time.perf_counter();
                if TIMINGS:
                    _sl.warning('updateDBs: {:9,.1f} ms'.format((1000*(t1-t0))))

            if True:

                # Adds to DB (NEW).
                1/1
                for ain in db_adds_ins:
                    c_fi = c_fis_in[ain]
                    FFWDB.insert(c_fi)

                # Drops from DB (NEW).
                1/1
                for din in db_drops_ins:
                    FFWDB.delete(din)

            if True:

                # Update ed['nfiles'].
                1/1
                db_ins = FFWDB.inodes()
                ed['nfiles'] = len(db_ins)
                ed = FFWDB.extra(ed)

            ###!!!
            continue
            ###!!!

            # Find the oldest unfinished file in DB.
            t0 = time.perf_counter();
            db_fi = FFWDB.oldest()
            t1 = time.perf_counter();
            if TIMINGS:
                _sl.warning('   oldest: {:9,.1f} ms'.format((1000*(t1-t0))))
            if not db_fi:
                continue
            if not doFilename(db_fi['filename']):
                continue

            # Export the file.
            exportFile(db_fi)

            # Move logfile to DONESD?
            if DONESD and db_fi['static'] and db_fi['processed'] >= db_fi['size']:
                t0 = time.perf_counter();
                doneWithFile(db_fi['inode'], db_fi['filename'])
                t1 = time.perf_counter();
                if TIMINGS:
                    _sl.warning('    moved: {:9,.1f} ms'.format((1000*(t1-t0))))

            if ONECHECK:
                FWTSTOP = True

    except KeyboardInterrupt as E:
        # watcherThread:
        _m.beep(1)
        msg = '{}: KeyboardInterrupt: {}'.format(me, E)
        _sl.warning(msg)
        ###---DOSQUAWK(errmsg, beep=1)
        pass###raise                # Let the thread exit.  Avoids "Exception in thread...".
    except Exception as E:
        errmsg = '%s: E: %s @ %s' % (me, E, _m.tblineno())
        DOSQUAWK(errmsg)
        raise      
    finally:
        if FWTSTOP:
            FWTSTOPPED = True
        FFWDB.disconnect()
        _sl.info('%s exits. STOPPED: %s' % (me, str(FWTSTOPPED)))
        FWTRUNNING = False
        1/1

#
# getFI
#
def getFI(fn, ts=None):
    """Return a FileInfo dict for fn."""
    me = 'getFI(%s)' % repr(fn)
    fi = None
    try:
        if   fn.startswith('access.log'):
            ae = 'a'
        elif fn.startswith('error.log'):
            ae = 'e'
        else:
            return fi
        pfn = os.path.normpath(WPATH + '/' + fn)
        try:
            st    = os.stat(pfn)
            inode = st.st_ino
            size  = st.st_size
            mtime = st.st_mtime
        except:
            # fn possible got renamed
            return fi
        static = not fn.endswith('.log')
        extra = None
        if ts == 0:
            ts = _dt.utcut()
        '''
                inode       integer,
                ae          text,
                modified    real,
                size	    integer,
                acquired    real,
                processed	integer,
                static  	integer,
                filename    text,
                extra       text)
        '''
        fi = {'inode': inode,
              'ae': ae,
              'modified': mtime,
              'size': size,
              'acquired': ts,
              'processed': 0,
              'static': static,
              'filename': fn,
              'extra': extra}
        return fi
    except Exception as E:
        ###---fi = None               # Zap!
        errmsg = '%s: %s @ %s' % (me, E, _m.tblineno())
        DOSQUAWK(errmsg)
        raise
    finally:
        ###---return fi
        1/1

#
# nullFI
#
def nullFI():
    '''
                inode       integer,
                ae          text,
                modified    real,
                size	    integer,
                acquired    real,
                processed	integer,
                static  	integer,
                filename    text,
                extra       text)
    '''
    fi = {'inode': None,
          'ae': None,
          'modified': None,
          'size': None,
          'acquired': None,
          'processed': None,
          'static': None,
          'filename': None,
          'extra': None}
    return fi

#
# getFIs
#
def getFIs(ts):
    """Return a list of FileInfo dicts of current files."""
    me = 'getFIS'
    fis = []
    try:
        for filename in os.listdir(WPATH):
            if not doFilename(filename):
                continue
            fi = getFI(filename, ts)
            if not fi:
                continue
            fis.append(fi)
        return fis
    except Exception as E:
        ###---fis = None              # ??? Zap all?
        errmsg = '%s: %s @ %s' % (me, E, _m.tblineno())
        DOSQUAWK(errmsg)
        raise
    finally:
        ###---return fis
        1/1

#
# maininits
#
def maininits():
    global gRPFN, gRFILE
    global WPATH, INTERVAL
    me = 'maininits'
    _sl.info(me)
    try:

        _a.argSL(_sl)

        gRPFN, gRFILE = _a.argString('rpt', 'report pfn'), None
        if gRPFN:
            gRFILE = open(gRPFN, 'a', encoding=ENCODING, errors=ERRORS)
            _sl._log_file(gRFILE)

        WPATH = _a.argString('wpath', 'watched path', WPATH)
        INTERVAL = _a.argFloat('interval', 'cylce interval', INTERVAL)

    except Exception as E:
        errmsg = '{}: {} @ {}'.format(me, E, _m.tblineno())
        DOSQUAWK(errmsg)
        raise

#
# main
#
def main():
    global WPATH, INTERVAL
    global FFWDBPFN, FWTSTOP, FWTSTOPPED
    me = 'main'
    watcher_thread = None
    try:
        _sl.info(me + ' begins')#$#

        _sl.info()
        _sl.info('    wpath: ' + WPATH)
        _sl.info(' interval: ' + str(INTERVAL))
        _sl.info()

        # FFW DB PFN.  DB creation must be done in watcherThread.
        FFWDBPFN = os.path.normpath(WPATH + '/nlmon.s3')

        # Start watcher() in a thread.
        watcher_thread = threading.Thread(target=watcherThread)
        watcher_thread.start()
        # Wait for startup.
        while not FWTRUNNING:           
            time.sleep(0.010)          

        # Wait for thread stop.
        while FWTRUNNING:
            time.sleep(1)

        # Ctrl-c to stop & exit.

    except KeyboardInterrupt as E:
        # nl2xlog:
        _m.beep(1)
        msg = '{}: KeyboardInterrupt: {}'.format(me, E)
        _sl.warning(msg)
        raise
    except Exception as E:
        errmsg = '{}: E: {} @ {}'.format(me, E, _m.tblineno())
        DOSQUAWK(errmsg)
        raise             
    finally:
        if watcher_thread and FWTRUNNING:
            FWTSTOP = True
            watcher_thread.join(3 * INTERVAL)
            _sl.info('thread STOPPED: %s' % FWTSTOPPED)
        1/1

#
# test
#
def test():
    global FFWDBPFN, FFWDB
    me = 'test'
    try:

        _sl.info(me + ' begins')#$#

        FFWDBPFN = os.path.normpath(WPATH + '/nlmon.s3')

        FFWDB = ffwdb.FFWDB(FFWDBPFN)

        z = FFWDB.inodes()
        z = z

        return

        z = FFWDB.select(-1)
        z = z

        ed = FFWDB.extra({'nfiles': 0})

        z = FFWDB.extra()
        z = z

        z = FFWDB.select(-1)
        z = z

        ed['nfiles'] = 99
        z = FFWDB.extra(ed)
        z = z

        z = FFWDB.select(-1)
        z = z

    except KeyboardInterrupt as E:
        # nl2xlog:
        _m.beep(1)
        msg = '{}: KeyboardInterrupt: {}'.format(me, E)
        _sl.warning(msg)
        pass
    except Exception as E:
        errmsg = '{}: E: {} @ {}'.format(me, E, _m.tblineno())
        DOSQUAWK(errmsg)
        raise             
    finally:
        _sl.info(me + ' ends')#$#
        1/1


"""...
  nl2xlog.py [--ini=<ini> --srcid=<srcid> --subid=<subid> \
  --wpath=<wpath> --donesd=<donesd> --interval=<interval> \
  --dotdiv=<dotdiv>  --txtlen=<txtlen> --ofile=<ofile> \
  --txrate=<txrate>]
..."""
"""...
#
# main: nl2xlog
#      
def nl2xlog():
    global SRCID, SUBID, WPATH, INTERVAL, OXLOG, OFILE, XFILE
    global FFWDBPFN, DONESD, FWTSTOP, FWTSTOPPED
    global DOTDIV, TXTLEN
    me = 'nlx2log'
    watcher_thread = None
    try:
        _sl.info(me + ' begins')#$#
        
        SRCID = _a.ARGS['--srcid']
        SUBID = _a.ARGS['--subid']
        WPATH = _a.ARGS['--wpath'].rstrip('/').rstrip('/')
        DONESD = _a.ARGS['--donesd']
        INTERVAL = float(_a.ARGS['--interval'])
        try:    DOTDIV = int(_a.ARGS['--dotdiv'])
        except: DOTDIV = 0
        try:    TXTLEN = int(_a.ARGS['--txtlen'])
        except: TXTLEN = 0
        XFILE = _a.ARGS['--ofile']
        try:    TXRATE = int(_a.ARGS['--txrate'])
        except: TXRATE = 0                      # Unthrottled.

        if len(SRCID) != 4:
            raise ValueError('bad len srcid: ' + SRCID)

        _sl.info()
        _sl.info('    srcid: ' + SRCID)
        _sl.info('    subid: ' + SUBID)
        _sl.info('    wpath: ' + WPATH)
        _sl.info('  done sd: ' + DONESD)
        _sl.info(' interval: ' + str(INTERVAL))
        _sl.info('   dotdiv: ' + str(DOTDIV))
        _sl.info('   txtlen: ' + str(TXTLEN))
        _sl.info('    ofile: ' + XFILE)
        _sl.info('   txrate: ' + str(TXRATE))
        _sl.info()

        # Express TXRATE as min sec between transmissions.
        if TXRATE > 0:  TXRATE = 1 / TXRATE
        else:           TXRATE = 0              # Unthrottled.

        # XFILE: output to OXLOG (via host:port) or to a dev/test filename (via OFILE).
        OXLOG = OFILE = None
        host, port = detectHP(XFILE)
        if host and port:
            try:
                OXLOG = XLogTxRx((host, port), txrate=TXRATE)
            except Exception as E:
                errmsg = 'cannot create XLogTxRX: %s' % E
                DOSQUAWK(errmsg)
                raise
        else:
            try:
                if XFILE:
                    opfn = XFILE
                    if os.path.isfile(opfn):
                        OFILE = open(opfn, 'a', encoding=ENCODING, errors=ERRORS)
                    else:
                        OFILE = open(opfn, 'w', encoding=ENCODING, errors=ERRORS)
            except Exception as E:
                errmsg = 'cannot open output file %s: %s' % (opfn, E)
                DOSQUAWK(errmsg)
                raise

        # FFW DB PFN.  DB creation must be done in watcherThread.
        FFWDBPFN = os.path.normpath(WPATH + '/nlmon.s3')

        # Start watcher() in a thread.
        watcher_thread = threading.Thread(target=watcherThread)
        watcher_thread.start()
        # Wait for startup.
        while not FWTRUNNING:           
            time.sleep(0.010)          

        # Wait for thread stop.
        while FWTRUNNING:
            time.sleep(1)

        # Ctrl-c to stop & exit.

    except KeyboardInterrupt as E:
        # nl2xlog:
        _m.beep(1)
        msg = '{}: KeyboardInterrupt: {}'.format(me, E)
        _sl.warning(msg)
        ###---DOSQUAWK(errmsg, beep=1)
        pass###raise
    except Exception as E:
        errmsg = '{}: E: {} @ {}'.format(me, E, _m.tblineno())
        DOSQUAWK(errmsg)
        raise             
    finally:
        if watcher_thread and FWTRUNNING:
            FWTSTOP = True
            watcher_thread.join(3 * INTERVAL)
            _sl.info('thread STOPPED: %s' % FWTSTOPPED)
..."""

if __name__ == '__main__':

    if True:

        try:
            _a.sepBegin(_sl)
            msg = '{} begins'.format(ME)
            _sl.info(msg)
            maininits()
            main()
            '''...
            if LF:
                _sl.extra('----------------------------------------  %s' % (_dt.ut2iso(_dt.locut())))
            nl2xlog()
            ...'''
        except KeyboardInterrupt as E:
            # __main__:
            _m.beep(1)
            msg = '{}: KeyboardInterrupt: {}'.format(ME, E)
            _sl.warning(msg)
            ###---DOSQUAWK(errmsg, beep=1)
            pass###raise
        except Exception as E:
            errmsg = '{}: E: {}'.format(ME, E)
            DOSQUAWK(errmsg)
            raise  
        else:
            pass    # No exceptions.           
        finally:
            shutDown()
            '''...
            if LF:
                _sl.extra('========================================  %s' % (_dt.ut2iso(_dt.locut())))
            ...'''
            msg = '{} ends'.format(ME)
            _sl.info(msg)
            _a.sepEnd(_sl)
            try:    gRFILE.close()
            except: pass
            '''...
            try: LF.close
            except: pass
            if gPAUSE:
                _ = input('.done.')   
            ...'''

    if False:

        try:
            _a.sepBegin(_sl)
            msg = '{} begins'.format(ME)
            _sl.info(msg)
            maininits()
            test()
        except KeyboardInterrupt as E:
            # __main__:
            _m.beep(1)
            msg = '{}: KeyboardInterrupt: {}'.format(ME, E)
            _sl.warning(msg)
            pass
        except Exception as E:
            errmsg = '{}: E: {}'.format(ME, E)
            DOSQUAWK(errmsg)
            raise###pass###raise  
        else:
            pass    # No exceptions.           
        finally:
            msg = '{} ends'.format(ME)
            _sl.info(msg)
            _a.sepEnd(_sl)
            try:    gRFILE.close()
            except: pass
            1/1

    if False:

        # TEST parseLogrec & making orecs.

        EEL, ESL, SRCID, SUBID = '0', '_', 'TEST', 'test'

        rc, rm, chunks = parseLogrec('a', A0)
        rc, rm, orec, vrec = genACCESSorec(chunks, 'a', EEL, ESL, SRCID, SUBID)
        if rc != 0:
            1/1

        rc, rm, chunks = parseLogrec('a', A2)
        rc, rm, orec, vrec = genACCESSorec(chunks, 'a', EEL, ESL, SRCID, SUBID)
        if rc != 0:
            1/1

        rc, rm, chunks = parseLogrec('a', A4)
        rc, rm, orec, vrec = genACCESSorec(chunks, 'a', EEL, ESL, SRCID, SUBID)
        if rc != 0:
            1/1

        rc, rm, chunks = parseLogrec('a', A6)
        rc, rm, orec, vrec = genACCESSorec(chunks, 'a', EEL, ESL, SRCID, SUBID)
        if rc != 0:
            1/1

        rc, rm, chunks = parseLogrec('e', E0)
        rc, rm, orec, vrec = genERRORorec(chunks, 'e', EEL, ESL, SRCID, SUBID)
        if rc != 0:
            1/1

        rc, rm, chunks = parseLogrec('e', E2)
        rc, rm, orec, vrec = genERRORorec(chunks, 'e', EEL, ESL, SRCID, SUBID)
        if rc != 0:
            1/1

        rc, rm, chunks = parseLogrec('e', E4)
        rc, rm, orec, vrec = genERRORorec(chunks, 'e', EEL, ESL, SRCID, SUBID)
        if rc != 0:
            1/1

        rc, rm, chunks = parseLogrec('e', E6)
        rc, rm, orec, vrec = genERRORorec(chunks, 'e', EEL, ESL, SRCID, SUBID)
        if rc != 0:
            1/1

"""
VERBOSE  = _a.x2bool(_a.ARGS.get('-v'), False) or \
           _a.x2bool(_a.ARGS.get('--verbose'), False)
if VERBOSE:
    VIEWER = _a.ARGS.get('--viewer')
    if not VIEWER:
        errmsg = 'no VIEWER module name'
        raise ValueError(errmsg)
    VM = importlib.import_module(VIEWER)
    _sl.info('imported %s -> %s' % (VIEWER, repr(VM)))
else:
    VIEWER = VM = None
    _sl.info('not VERBOSE')
###
        if VERBOSE:
            _sl.info('   viewer: ' + str(VIEWER))
            _sl.info('       vm: ' + repr(VM))
        _sl.info()
###
                # VERBOSE? (Custom output to screen.)
                if VERBOSE:
                    try:    
                        a = logrec.split(_, 9)
                        ffv = a.pop(0)
                        b = json.loads(a.pop(-1))
                        b['sl'] = _sl
                        ###
                        id, si, el, sl, msg = b['_id'], b['_si'], b['_el'], b['_sl'], b.get('_msg', 'None')
                        ###
                        VM.main(*a, **b)
                    except Exception as E: 
                        errmsg = str(E)
                        # In case _sl is incapacitated...
                        _m.beep(3)
                        print('!! ' + logrec + ' !! ' + errmsg + ' !!')
"""

###
### srcid=<srcid> subid=<subid> wpath=<wpath> donesd=<donesd> interval=<interval> dotdiv=<dotdiv> txtlen=<txtlen> ofile=<ofile> txrate=<txrate>
###
### wpath=C:/NLMON/test/ interval=6.7 rpt=C:/NLMON/app/~me~.rpt
###

###