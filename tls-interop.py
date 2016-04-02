#!/usr/bin/python
import os
import re
import pexpect
import sys
import argparse
import unittest
import commands
import time

def die(msg):
    sys.stderr.write("%s\n"%msg)
    sys.exit()

def debug(msg):
    if options.verbose:
        sys.stderr.write("%s\n"%msg)

def error(msg):
    sys.stderr.write(msg)

def should_skip():
    name = sys._getframe(1).f_code.co_name

    # First check for explicitly listed tests (default is all)
    m = re.search(options.tests, name)
    if m is None:
        # OK, this doesn't match so we skip
        return True
    else:
        # OK, we matched the listed tests, now check for exclusion
        if options.excludetests is not None:
            m = re.search(options.excludetests, name)
            if m is None:
                return False
            else:
                return True
        else:
            # No exclusions, so don't skip
            return False

    
class TestAgent(object):
    def __init__(self, ctx, config):
        super(TestAgent, self).__init__()
        self.config_ = config
        self.results_ = []
        self.cmd_ = None
        self.args_ = []
        self.ctx_ = ctx
        self.env_ = dict(os.environ)

    def timeout(self):
        return 10
    
    def start(self):
        if self.cmd_ is None:
            die("Need to specify a command to run")

        self.make_args()
        debug("Running %s %s"%(self.cmd_, " ".join(self.args_)))
        self.sub_ = pexpect.spawn(self.cmd_, self.args_, env=self.env_)

        if options.verbose:
            self.sub_.logfile = sys.stdout
            
        if self.sub_ is None:
            return "Couldn't start program"
        
        return None

    def wait_for(self, string):
        if string is None:
            time.sleep(1)
            return None

        debug("Waiting for... %s"%string)
        if options.verbose:
            self.sub_.logfile = sys.stdout
        try:
            self.sub_.expect(string, self.timeout())
        except pexpect.EOF:
            return "%s: Error starting; EOF"%self.identity()
        except pexpect.TIMEOUT:
            return "%s: Error starting; TIMEOUT"%self.identity()

        # Record data plus whatever else is available
        available = ""
        while True:
            try:
                available += self.sub_.read_nonblocking(1,0)
            except:
                break

        alldata = self.sub_.before + self.sub_.after
        
        debug("All data is %s"%alldata)
        for l in alldata.split("\n"):
            self.results_.append(l)

        
        debug("Found")
        return None

    def find_in_results(self, rex):
        for l in self.results_:
            m = re.search(rex, l)
            if m is not None:
                return m.group(1)

        error("Could not find %s"%rex)
        error(str(self.results_))
        return None

    def close(self):
        self.sub_.close()
        
    def unimplemented(self):
        raise Exception("%s: function unimplemented"%self.identity())



def MakeAgent(ctx, config, mode):
    if mode == "client":
        if config['impl'] == "openssl":
            return TestOpenSSLClient(ctx, config)
        elif config['impl'] == "nss":
            return TestNSSClient(ctx, config)
        else:
            die("Could not make a %s client"%config['impl'])
    else:
        if config['impl'] == "openssl":
            return TestOpenSSLServer(ctx, config)
        elif config['impl'] == "nss" and "dtls" in config:
            return TestNSSDTLSServer(ctx, config)
        else:
            die("Could not make a %s server"%config['impl'])
    


class TestOpenSSL(TestAgent):
    def __init__(self, ctx, config):
        super(TestOpenSSL, self).__init__(ctx, config)
        self.cmd_ = options.openssldir + "apps/openssl"
        
    def make_args(self):
        if ('dtls' in self.config_):
            self.args_.append("-dtls1")
        if ('exporter' in self.config_):
            self.args_.append("-keymatexport")
            self.args_.append(self.config_['exporter'])
        if ('srtp' in self.config_):
            self.args_.append("-use_srtp")
            self.args_.append(self.config_["srtp"])

    def get_exporter_result(self):
        return self.find_in_results("Keying material: ([0-9A-F]+)")

    def get_srtp_result(self):
        return self.find_in_results("SRTP Extension negotiated, profile=([0-9A-Z_]+)")

    
class TestOpenSSLClient(TestOpenSSL):
    def __init__(self, ctx, config):
        super(TestOpenSSLClient, self).__init__(ctx, config)

    def identity(self):
        return "OpenSSL client"
    
    def make_args(self):
        self.args_.append("s_client")
        super(TestOpenSSLClient, self).make_args()
        self.args_.append("-key")
        self.args_.append("%s/apps/client.pem"%options.openssldir)
        self.args_.append("-cert")
        self.args_.append("%s/apps/client.pem"%options.openssldir)

    def ready_str(self):
        return None

    def connected_str(self):
        if "exporter" in self.config_:
            return "Keying material: [A-F0-9]+"
        else:
            return "Verify return code"

        
    
class TestOpenSSLServer(TestOpenSSL):
    def __init__(self, ctx, config):
        super(TestOpenSSLServer, self).__init__(ctx, config)


    def identity(self):
        return "OpenSSL server"

    def make_args(self):
        self.args_.append("s_server")
        super(TestOpenSSLServer, self).make_args()
        self.args_.append("-key")
        self.args_.append("%s/apps/server.pem"%options.openssldir)
        self.args_.append("-cert")
        self.args_.append("%s/apps/server.pem"%options.openssldir)
        

    def ready_str(self):
        return "ACCEPT"

    def connected_str(self):
        if "exporter" in self.config_:
            return "Keying material: [A-F0-9]{40}"
        else:
            return "Secure Renegotiation.*supported"
    
#NSS
class TestNSS(TestAgent):
    SRTP_MAP_FWD = {
        "SRTP_AES128_CM_SHA1_80":                     "A",
        "SRTP_AES128_CM_SHA1_32":                     "B",
        "SRTP_NULL_SHA1_80":                          "C",
        "SRTP_NULL_SHA1_32":                          "D"
        };

    SRTP_MAP_BWD = {
        "1":"SRTP_AES128_CM_SHA1_80",
        "2":"SRTP_AES128_CM_SHA1_32",
        "3":"SRTP_NULL_SHA1_80",
        "4":"SRTP_NULL_SHA1_32"
        };

    
    def __init__(self, ctx, config):
        super(TestNSS, self).__init__(ctx, config)
        # TODO: Update for non-Mac
        self.env_['DYLD_LIBRARY_PATH']=self.lib_directory()
                           
    def make_args(self):
        if ('exporter' in self.config_):
            self.args_.append("-X")
            self.args_.append(self.config_['exporter'])
        self.args_.append("-d")
        self.args_.append(self.cert_db())

    def bin_directory(self):
        uname = commands.getoutput('uname')
        version = commands.getoutput('uname -r')
        return options.nssdir + "/dist/%s%s_64_DBG.OBJ/bin"%(uname, version)
    
    def lib_directory(self):
        uname = commands.getoutput('uname')
        version = commands.getoutput('uname -r')
        return options.nssdir + "/dist/%s%s_64_DBG.OBJ/lib"%(uname, version)

    def cert_db(self):
        return options.nss_cert_dir
    
    def get_srtp_result(self):
        index = self.find_in_results("SRTP ciphers negotiated: number = ([0-9]+)")
        return TestNSS.SRTP_MAP_BWD[index]

class TestNSSClient(TestNSS):
    def __init__(self, ctx, config):
        super(TestNSSClient, self).__init__(ctx, config)
        self.cmd_ = self.bin_directory() + '/tstclnt';

    def identity(self):
        return "NSS Client"

    def make_args(self):
        super(TestNSSClient, self).make_args()
        self.args_.append("-h")
        self.args_.append("127.0.0.1")
        self.args_.append("-p")
        self.args_.append("4433")
        self.args_.append("-o")
        if "dtls" in self.config_:
            self.args_.append("-D")
        if "srtp" in self.config_:
            self.args_.append("-A")
            self.args_.append("".join([TestNSSClient.SRTP_MAP_FWD[x] for x in self.config_["srtp"].split(":")]))
        
    def ready_str(self):
        return None

    def connected_str(self):
        return "stateless resumes"
    

class TestNSSServer(TestNSS):
    def __init__(self, ctx, config):
        super(TestNSSServer, self).__init__(ctx, config)
        self.cmd_ = self.bin_directory() + '/selfser';

    def identity(self):
        return "NSS Server"

    def make_args(self):
        super(TestNSSServer, self).make_args()
        self.args_.append("-n")
        self.args_.append("server")
        self.args_.append("-p")
        self.args_.append("4433")
        if "dtls" in self.config_:
            die("No NSS Server support for DTLS")
        if "srtp" in self.config_:
            die("No NSS Server support for SRTP")
        
    def ready_str(self):
        return None

    def connected_str(self):
        return "stateless resumes"
    


    
        
# GENERIC AGAIN
class TestSSLInterop(unittest.TestCase):
    def setUp(self):
        self.client_ = None
        self.server_ = None
        pass
        
    def connect(self, client_config, server_config):
        self.ctx_ = {}
        self.client_config_ = client_config
        self.server_config_ = server_config
        
        self.server_ = MakeAgent(self.ctx_, server_config, "server")
        self.assertEqual(None, self.server_.start())
        self.assertEqual(None, self.server_.wait_for(self.server_.ready_str()))
        self.client_ = MakeAgent(self.ctx_, client_config, "client")
        self.assertEqual(None, self.client_.start())
        self.assertEqual(None, self.client_.wait_for(self.client_.ready_str()))        
        self.assertEqual(None, self.client_.wait_for(self.client_.connected_str()))
        self.assertEqual(None, self.server_.wait_for(self.server_.connected_str()))
        
    def tearDown(self):
        if self.client_ is not None:
            self.client_.close()
        if self.server_ is not None:            
            self.server_.close()

    def test_OpenSSL_OpenSSL_TLS(self):
        if should_skip():
            self.skipTest("")
        self.connect({"impl":"openssl"}, {"impl":"openssl"})
        
    def test_OpenSSL_OpenSSL_TLS_Exporter(self):
        if should_skip():
            self.skipTest("")
        self.connect(
             {
                 "impl":"openssl",
                 "exporter":"abc"
             },
             {
                 "impl":"openssl",
                 "exporter":"abc"
             }
             )
        self.assertNotEqual(None, self.client_.get_exporter_result())
        self.assertEqual(self.client_.get_exporter_result(),
                          self.server_.get_exporter_result())

    def test_OpenSSL_OpenSSL_TLS_ExporterMismatch(self):
        if should_skip():
            self.skipTest("")
        self.connect(
             {
                 "impl":"openssl",
                 "exporter":"abc"
             },
             {
                 "impl":"openssl",
                 "exporter":"def"
             }
             )

        self.assertNotEqual(None, self.client_.get_exporter_result())
        self.assertNotEqual(None, self.server_.get_exporter_result())
        self.assertNotEqual(self.client_.get_exporter_result(),
                            self.server_.get_exporter_result())

    def test_OpenSSL_OpenSSL_DTLS(self):
        if should_skip():
            self.skipTest("")
        self.connect({"impl":"openssl", "dtls":True}, {"impl":"openssl", "dtls":"True"})

    def test_OpenSSL_OpenSSL_DTLS_SRTP(self):
        if should_skip():
            self.skipTest("")
        self.connect(
            {
                "impl":"openssl",
                "dtls":True,
                "srtp":"SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32"
                },
            {
                "impl":"openssl",
                "dtls":True,
                "srtp":"SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32"
                })
        self.assertEqual("SRTP_AES128_CM_SHA1_80", self.client_.get_srtp_result())
        self.assertEqual("SRTP_AES128_CM_SHA1_80", self.server_.get_srtp_result())


    def test_NSS_OpenSSL_TLS(self):
        if should_skip():
            self.skipTest("")
        self.connect({"impl":"nss"}, {"impl":"openssl"})



# Main
parser = argparse.ArgumentParser()
parser.add_argument('-o', '--openssldir', required=True,  dest="openssldir", help="OpenSSL directory")
parser.add_argument('-n', '--nssdir',   dest="nssdir", help="NSS directory")
parser.add_argument('-N', '--nss_cert_dir',   dest="nss_cert_dir", help="Test nss cert directory")
parser.add_argument('-v', '--verbose', default=False, dest="verbose", help="Verbose mode", action="store_true")
parser.add_argument('-t', '--tests', default="", dest="tests", help="Tests pattern")
parser.add_argument('-T', '--exclude-tests', default=None, dest="excludetests", help="Tests to exclude pattern")
options = parser.parse_args()

# Run the tests
suite = unittest.TestLoader().loadTestsFromTestCase(TestSSLInterop)
unittest.TextTestRunner(verbosity=2).run(suite)


