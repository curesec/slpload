import struct
import random

SLP_SVC_REQ = 0x1
SLP_SVC_REG = 0x3
SLP_SVC_DEREG = 0x4
SLP_ATTR_REQ = 0x6
SLP_SVC_TYPE_REQ = 0x9

SLP_TRANSX_RAND = True
SLP_XID_RAND = True
CRAFT_AUTO_LEN = True
DEBUG_PROTO = True

#####################
###### SLP v2 #######
#####################

def build_slp_base_v2(slp_ver=2, slp_func=0, slp_pkt_len=0, slp_flags=0, slp_next_offset=0, slp_xid=0x299, slp_ltag_len=2, slp_ltag=0x656e):

    if SLP_XID_RAND:
        slp_xid = random.randint(1, 65535)

    # basic pkt structure v2
    pkt = struct.pack('>BBBHHBHHHH', slp_ver, slp_func, 0, slp_pkt_len,
                      slp_flags, 0, slp_next_offset, slp_xid, slp_ltag_len, slp_ltag)

    return pkt


def compute_len_v2(pkt):

    pkt_len = len(pkt)

    pkt_byte_len = struct.pack('>bH', 0, pkt_len)
    pkt = pkt[:2] + pkt_byte_len + pkt[5:]

    return pkt


#########SLP_SVC_REQ = 0x1
def build_slp_svc_req_v2(svc_type_op):
    pkt1 = build_slp_base_v2(slp_func=svc_type_op)
    #pkt1 = build_slp_base_v2(slp_func=SLP_SVC_REQ)
    pkt2 = _slp_svc_req_v2()

    pkt = pkt1+pkt2
    pkt_rdy = compute_len_v2(pkt)

    return pkt_rdy


def _slp_svc_req_v2(slp_prev_res_list=0, slp_svc_type_len=0, slp_svc_type=b'service:wbem', slp_scope_len=7, slp_scope=b'default'):
    '''
    '''

    pkt2 = struct.pack('>HH'+str(slp_svc_type_len)+'sH'+str(slp_scope_len)+'sHH', slp_prev_res_list,
                       slp_svc_type_len, slp_svc_type, slp_scope_len, slp_scope, 0, 0)

    return pkt2
##########

##### SLP_SVC_REG = 0x3
def build_slp_svc_reg_v2():
    pkt1 = build_slp_base_v2(slp_func=SLP_SVC_REG)
    pkt2 = _slp_svc_reg_v2()

    pkt = pkt1+pkt2
    pkt_rdy = compute_len_v2(pkt)

    return pkt_rdy


def _slp_svc_reg_v2(slp_reserved=0, svc_url_lifetime=666, svc_url_len=19, svc_url=b'slpTest://test:31337/a', slp_num_auth=0, svc_type_len=38,
                    svc_type=b'slpTest://test:31337/aaaaaaaaaaaaaaaaaaaa', scope_list_len=7, scope_list=b'default', attr_list_len=0, attr_auths=0):
    '''
    '''

    pkt2 = struct.pack('>BHH' + str(svc_url_len) + 'sBH' + str(svc_type_len) +
                       'sH'+str(scope_list_len)+'sHB',    slp_reserved,
                       svc_url_lifetime,
                       svc_url_len,
                       svc_url,
                       slp_num_auth,
                       svc_type_len,
                       svc_type,
                       scope_list_len,
                       scope_list,
                       attr_list_len,
                       attr_auths)

    return pkt2
###################

#######SLP_SVC_DEREG = 0x4


def build_slp_svc_dereg_v2():
    pkt1 = build_slp_base_v2(slp_func=SLP_SVC_DEREG)
    pkt2 = _slp_svc_dereg_v2()

    pkt = pkt1+pkt2
    pkt_rdy = compute_len_v2(pkt)

    return pkt_rdy


def _slp_svc_dereg_v2(scope_list_len=7, scope_list=b'default', reserved=0, attr_list_len=0, svc_url_lifetime=666, svc_url_len=19, svc_url=b'slpTest://test:31337/a',
                      attr_auths=0):
    '''
    '''

    pkt2 = struct.pack('>H'+str(scope_list_len)+'sBHH'+str(svc_url_len)+'sHB',
                       scope_list_len,
                       scope_list,
                       reserved,
                       svc_url_lifetime,
                       svc_url_len,
                       svc_url,
                       attr_list_len,
                       attr_auths)

    return pkt2

######SLP_ATTR_REQ = 0x6
def build_slp_attr_req_v2():
    pkt1 = build_slp_base_v2(slp_func=SLP_ATTR_REQ)
    pkt2 = _slp_attr_req_v2()

    pkt = pkt1+pkt2
    pkt_rdy = compute_len_v2(pkt)

    return pkt_rdy


def _slp_attr_req_v2(slp_prev_res_list=0, slp_svc_url_len=12, slp_svc_url=b'service:wbem', slp_scope_len=0, slp_scope=b'', slp_tag_len=0, slp_tag=b''):

    pkt2 = struct.pack('>HH'+str(slp_svc_url_len)+'sH'+str(slp_scope_len)+'sH'+str(slp_tag_len)+'sH', slp_prev_res_list,
                       slp_svc_url_len, slp_svc_url, slp_scope_len, slp_scope, slp_tag_len, slp_tag, 0)

    return pkt2
#######################

#####SLP_SVC_TYPE_REQ = 0x9
def build_slp_svc_type_req_v2():
    pkt1 = build_slp_base_v2(slp_func=SLP_SVC_TYPE_REQ)
    pkt2 = _slp_svc_type_req_v2()

    pkt = pkt1+pkt2
    pkt_rdy = compute_len_v2(pkt)

    return pkt_rdy


def _slp_svc_type_req_v2(slp_prev_res_list=0, slp_all=65535, slp_scope=b'default', slp_scope_len=7):

    pkt2 = struct.pack('>HHH'+str(slp_scope_len)+'s', slp_prev_res_list,
                       slp_all, slp_scope_len, slp_scope)

    return pkt2
########################
