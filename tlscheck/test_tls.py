import socket
import smtplib
from imapclient import imap4
from imapclient import tls as TLS
import poplib
from ssl import SSLError, SSLContext, create_default_context, DER_cert_to_PEM_cert, _create_unverified_context

SOCK_TIMEOUT=2

class TLStest:
    def __init__(self, ports = 443, port = 80,timeout = SOCK_TIMEOUT):
        self.timeout = timeout
        self.ports = ports
        self.port = port

    def get_tls_info(self, sock, dict):
        """
        TLC connect info
        :param sock: wrapped sock
        :param dict: dict to return
        :return:
        """
        tlscert = sock.getpeercert(binary_form=True)
        dict["version"] = sock.version()
        dict["cipher"] = sock.cipher()
        dict["tls ca"] = DER_cert_to_PEM_cert(tlscert)
        return

    def get_auth_info(self, server, dict):
        pass

    def server_quit(self, server):
        pass

    def tls_handshake(self, ssl_context, hostname, port, timeout):
        pass

    def has_stls(self, server):
        pass

    def stls_handshake(self, server, ssl_context):
        pass

    def handshake(self, hostname, port, timeout):
        pass
    def test_tls(self, hostname, port = None, ssl_context = None, timeout = None):
        """
        Attempt to connect to an server and validate TLS support

        :param hostname(str): The hostname
        :param port(int): The port
        :param ssl_context : A SSL context
        :param timeout: Connect Timeout
        :return: bool-TLS supported, dict-TLS info
         """

        tls = False
        redict = {"error":[]}
        if port is None:
            port = self.ports
        if ssl_context is None:
            ssl_context = create_default_context()
        if timeout is None:
            timeout = self.timeout

        #print(f"Start TLS test {hostname}:{port}")

        try:
            try:
                server = self.tls_handshake(ssl_context, hostname, port, timeout)
            except SSLError as e:   # SSL cert verify
                redict["error"].append(f"SSL error: {e}")
                ssl_context = _create_unverified_context()  # don't verify cert
                server = self.tls_handshake(ssl_context, hostname, port, timeout)

            try:
                self.get_tls_info(server.sock, redict)
            except:
                print("Fail to get tlsinfo")
            try:
                self.get_auth_info(server, redict)
            except:
                print("Fail to get authinfo")
            tls = True
            try:
                self.server_quit(server)
            except Exception as e:
                #TODO: what time need to handle exception
                pass
            finally:
                return (tls, redict)
        except OSError as e:
            error = e.__str__()
            redict["error"].append(f"OS error : {error}")
            return (tls, redict)
        except Exception as e:
            error = f"%r : %r"%(type(e), e)
            redict["error"].append(f"{error}")
            return (tls, redict)

    def test_stls(self, hostname, port=None, ssl_context=None, timeout=None):
        """
        Attempt to connect to an server and validate STARTTLS support

        :param hostname(str): The hostname
        :param port(int): The port
        :param ssl_context : A SSL context
        :param timeout: Connect Timeout
        :return: bool-STARTTLS supported, dict-STARTTLS info
        """

        starttls = False
        redict = {"error":[]}
        if port is None:
            port = self.port
        if ssl_context is None:
            ssl_context = create_default_context()
        if timeout is None:
            timeout = self.timeout

        #print(f"Start STARTTLS test {hostname}:{port}")

        try:
            server = self.handshake(hostname, port, timeout)
            # server = smtplib.SMTP(hostname, timeout=SOCK_TIMEOUT)

            if (self.has_stls(server)):
                try:
                    self.stls_handshake(server, ssl_context)
                except SSLError as e:  # SSL cert verify
                    redict["error"].append(f"SSL error: {e}")
                    ssl_context = _create_unverified_context()  # don't verify cert
                    server = self.handshake(hostname, port, timeout)
                    self.stls_handshake(server, ssl_context)
                try:
                    self.get_tls_info(server.sock, redict)
                except:
                    print("Fail to get stlsinfo")
                try:
                    self.get_auth_info(server, redict)
                except:
                    print("Fail to get authinfo")
                starttls = True
                try:
                    self.server_quit(server)
                except Exception as e:
                    # TODO: what time need to handle exception
                    pass
            else:
                redict["starttls"] = "no starttls"
            return (starttls, redict)

        except OSError as e:
            error = e.__str__()
            redict["error"].append(f"OS error : {error}")
            return (starttls, redict)
        except Exception as e:
            error = f"%r : %r" % (type(e), e)
            redict["error"].append(f"{error}")
            return (starttls, redict)

    def test_plain(self, hostname, port=None, timeout=None):
        """
        Attempt to connect to an server and validate STARTTLS support

        :param hostname(str): The hostname
        :param port(int): The port
        :param timeout: Connect Timeout
        :return: bool-plain supported, dict-plain info
        """
        connect = False
        redict = {"error": []}
        if port is None:
            port = self.ports
        if timeout is None:
            timeout = self.timeout

        #print(f"Start connect test {hostname}:{port}")

        try:
            server = self.handshake(hostname, port, timeout)
            try:
                self.get_auth_info(server, redict)
            except:
                print("Fail to get authinfo")
            connect = True
            try:
                self.server_quit(server)
            except Exception as e:
                # TODO: what time need to handle exception
                pass
            return (connect, redict)
        except OSError as e:
            error = e.__str__()
            redict["error"].append(f"OS error : {error}")
            return (connect, redict)
        except Exception as e:
            error = f"%r : %r" % (type(e), e)
            redict["error"].append(f"{error}")
            return (connect, redict)


class SMTPtest(TLStest):
    def __init__(self, ports=465, port=25, timeout=SOCK_TIMEOUT):
        super().__init__(ports, port, timeout)

    def get_auth_info(self, server, dict):
        server.ehlo_or_helo_if_needed()
        dict["enable esmtp"] = server.does_esmtp
        dict["auth"] = server.esmtp_features

    def server_quit(self, server):
        server.quit()
        server.close()

    def tls_handshake(self, ssl_context, hostname, port, timeout):
        return smtplib.SMTP_SSL(hostname, port, context=ssl_context, timeout=timeout)

    def has_stls(self, server):
        server.ehlo_or_helo_if_needed()
        if server.has_extn("starttls"):
            return True
        return False

    def stls_handshake(self, server, ssl_context):
        server.starttls(context=ssl_context)

    def handshake(self, hostname, port, timeout):
        return smtplib.SMTP(hostname, port, timeout=timeout)

class IMAPtest(TLStest):
    def __init__(self, ports=993, port=143, timeout=SOCK_TIMEOUT):
        super().__init__(ports, port, timeout)

    def get_auth_info(self, server, dict):
        dict["auth"] = server.capabilities

    def server_quit(self, server):
        server.shutdown()

    def tls_handshake(self, ssl_context, hostname, port, timeout):
        return TLS.IMAP4_TLS(hostname, port, ssl_context=ssl_context, timeout=timeout)

    def has_stls(self, server):
        return "STARTTLS" in server.capabilities

    def stls_handshake(self, server, ssl_context):
        return server.starttls(ssl_context=ssl_context)

    def handshake(self, hostname, port, timeout):
        return imap4.IMAP4WithTimeout(hostname, port, timeout=timeout)

class POPtest(TLStest):
    def __init__(self,  ports=995, port=110, timeout=SOCK_TIMEOUT):
        super().__init__( ports, port, timeout)

    def get_auth_info(self, server, dict):
        dict["auth"] = server.capa()

    def server_quit(self, server):
        server.quit()

    def tls_handshake(self, ssl_context, hostname, port, timeout):
        return poplib.POP3_SSL(hostname, port, context=ssl_context, timeout=timeout)

    def has_stls(self, server):
        caps = server.capa()
        return "STLS" in caps

    def stls_handshake(self, server, ssl_context):
        return server.stls(context=ssl_context)

    def handshake(self, hostname, port, timeout):
        return poplib.POP3(hostname, port, timeout=timeout)


def max_merge(re, dict):
    for key in dict:
        if key not in re or re[key]< dict[key]:
            re[key] = dict[key]

imaptest = IMAPtest()
smtptest = SMTPtest()
pop3test = POPtest()

testdict={"smtp" : smtptest, "imap" : imaptest, "pop3" : pop3test}

def get_testinfo(testfun, hostname, port, socketType):
    if socketType == "starttls":
        (res, info) = testfun.test_stls(hostname, port)
    elif socketType == "ssl":
        (res, info) = testfun.test_tls(hostname, port)
    else:  # plain
        (res, info) = testfun.test_plain(hostname, port)
    return (res, info)

def testconnect(tree):
    for key, item in tree.items():
        if key not in testdict:
            continue
        testfun = testdict[key]
        for hostname, item1 in item.items():
            host_dict = {}
            for port, item2 in item1.items():
                port_dict = {}
                for socketType, item3 in item2.items():
                    (res,info) = get_testinfo(testfun, hostname, port, socketType)
                    item3["connect"] = {"result": res, "info": info}
                    port_dict[socketType] = res
                if "starttls" not in port_dict and "plain" in port_dict and port_dict["plain"] :  # starttls didn't test and plain can be connected
                    (res, info) = testfun.test_stls(hostname, port)
                    port_dict["starttls"] = res
                    if res:  # this port have starttls
                        item2["lagging"] = {"strarttls": True, "info": info}
                max_merge(host_dict, port_dict)
            if "ssl" not in  host_dict or not host_dict["ssl"]:     #no ssl
                if str(testfun.ports) not in item1 or "ssl" not in item1[str(testfun.ports)]:       #defult port didn't test ssl
                    (res, info) = testfun.test_tls(hostname)
                    if res:     # default port have tls
                        item1["lagging"] = {"ssl": True, "info": info}
            #TODO: if ssl fail and plain did not test , then test default plain port use starttls

def testconnect2(protocoltype, hostname, port, socketType):
    testfun = testdict[protocoltype]
    (res, info) = get_testinfo(testfun, hostname, port, socketType)
    return (res, info)

# if __name__=="__main__":
#     import json

#     f = open("/www/wwwroot/Golang/autodiscover-checker/backend/tlscheck/data2.json", 'r')
#     item = f.read()
#     f.close()
#     datadict = json.loads(item)
#     testconnect(datadict)
#     json_string = json.dumps(datadict, indent=4, default=lambda obj: obj.__dict__)
#     print(json_string)

import argparse
import json

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocol", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True)
    parser.add_argument("--mode", required=True)
    args = parser.parse_args()

    try:
        res, info = testconnect2(args.protocol, args.host, int(args.port), args.mode)
        output = {
            "success": res,
            "info": info if res else None,
        }
        if not res:
            error_list = info.get("error", [])
            output["error"] = error_list[0] if error_list else "Unknown error"
    except Exception as e:
        output = {
            "success": False,
            "info": None,
            "error": str(e)
        }

    print(json.dumps(output))