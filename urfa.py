#coding=utf-8

""" main class of urfa-module """
from urfa_connection import *
from collections import defaultdict

def blocked2ret(blockcode, retdict):
    if blockcode:
        retdict['block_flags'] = []
        if U_BL_SYS == blockcode & U_BL_SYS:
            retdict['block_flags'].append('U_BL_SYS')
            if U_BL_SYS_REC_AB == blockcode & U_BL_SYS_REC_AB:
                retdict['block_flags'].append('U_BL_SYS_REC_AB')
            if U_BL_SYS_REC_PAY == blockcode & U_BL_SYS_REC_PAY:
                retdict['block_flags'].append('U_BL_SYS_REC_PAY')
        if U_BL_MAN == blockcode & U_BL_MAN:
            retdict['block_flags'].append('U_BL_MAN')
            if U_BL_MAN_REC_AB == blockcode & U_BL_MAN_REC_AB:
                retdict['block_flags'].append('U_BL_MAN_REC_AB')
            if U_BL_MAN_REC_PAY == blockcode & U_BL_MAN_REC_PAY:
                retdict['block_flags'].append('U_BL_MAN_REC_PAY')


class urfa_client(connection):
    """ URFA-client class - container of URFA-functions and interfase of URFA """

    def rpcf_liburfa_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  size :	(i)  - 
        :(s)    module :	(s)  - 
        :(s)    version :	(s)  - 
        :(s)    path :	(s)  - 
        """
        if not self.urfa_call(0x0040):
            raise Exception("Fail of urfa_call(0x0040) [rpcf_liburfa_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['size']): 
            self.pck.recv(self.sck)
            ret['module'][i] = self.pck.get_data(U_TP_S)
            ret['version'][i] = self.pck.get_data(U_TP_S)
            ret['path'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_liburfa_symtab(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    name :	(s)  - 
        :(s)    module :	(s)  - 
        """
        if not self.urfa_call(0x0044):
            raise Exception("Fail of urfa_call(0x0044) [rpcf_liburfa_symtab]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['name'][i] = self.pck.get_data(U_TP_S)
            ret['module'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_core_version(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  core_version :	(s)  - 
        """
        if not self.urfa_call(0x0045):
            raise Exception("Fail of urfa_call(0x0045) [rpcf_core_version]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['core_version'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_core_build(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  build :	(s)  - 
        """
        if not self.urfa_call(0x0046):
            raise Exception("Fail of urfa_call(0x0046) [rpcf_core_build]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['build'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_stats(self, params):
        """ description
        @params: 
        :(s)  type :	(i)  - 
        @returns: 
        :(s)  status :	(i)  - 
        :(s)  uptime :	(i)  - 
        :(s)  uptime_last :	(i)  - 
        :(s)  events :	(i)  - 
        :(s)  events_last :	(i)  - 
        :(s)  errors :	(i)  - 
        :(s)  errors_last :	(i)  - 
        """
        if not self.urfa_call(0x0047):
            raise Exception("Fail of urfa_call(0x0047) [rpcf_get_stats]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['type'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['status'] = self.pck.get_data(U_TP_I)
        ret['uptime'] = self.pck.get_data(U_TP_I)
        ret['uptime_last'] = self.pck.get_data(U_TP_I)
        ret['events'] = self.pck.get_data(U_TP_I)
        ret['events_last'] = self.pck.get_data(U_TP_I)
        ret['errors'] = self.pck.get_data(U_TP_I)
        ret['errors_last'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_new_secret(self, params):
        """ description
        @params: 
        :(s)  secret_size :	(i) = _def_  - 
        @returns: 
        :(s)  error :	(s)  - 
        :(s)  secret :	(s)  - 
        """
        if not self.urfa_call(0x0060):
            raise Exception("Fail of urfa_call(0x0060) [rpcf_get_new_secret]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'secret_size' not in params: params['secret_size'] = 8
        self.pck.add_data(params['secret_size'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['error'] = self.pck.get_data(U_TP_S)
        ret['secret'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_system_currency(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  currency_id :	(i)  - 
        """
        if not self.urfa_call(0x0101):
            raise Exception("Fail of urfa_call(0x0101) [rpcf_get_system_currency]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['currency_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_ippool(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        @returns: 
        :(s)  id :	(i)  - 
        :(s)  name :	(s)  - 
        :(s)  address :	(i)  - 
        :(s)  mask :	(i)  - 
        """
        if not self.urfa_call(0x1066):
            raise Exception("Fail of urfa_call(0x1066) [rpcf_get_ippool]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['id'] = self.pck.get_data(U_TP_I)
        ret['name'] = self.pck.get_data(U_TP_S)
        ret['address'] = self.pck.get_data(U_TP_IP)
        ret['mask'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_ippools_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    name :	(s)  - 
        :(s)    address :	(i)  - 
        :(s)    mask :	(i)  - 
        """
        if not self.urfa_call(0x1067):
            raise Exception("Fail of urfa_call(0x1067) [rpcf_get_ippools_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['name'][i] = self.pck.get_data(U_TP_S)
            ret['address'][i] = self.pck.get_data(U_TP_IP)
            ret['mask'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_ippool(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        :(s)  name :	(s)  - 
        :(s)  address :	(i)  - 
        :(s)  mask :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x1068):
            raise Exception("Fail of urfa_call(0x1068) [rpcf_add_ippool]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.add_data(params['address'], U_TP_I)
        self.pck.add_data(params['mask'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_ippool(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        :(s)  name :	(s)  - 
        :(s)  address :	(i)  - 
        :(s)  mask :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x1069):
            raise Exception("Fail of urfa_call(0x1069) [rpcf_edit_ippool]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.add_data(params['address'], U_TP_IP)
        self.pck.add_data(params['mask'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_del_ippool(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        :(s)  name :	(s)  - 
        :(s)  address :	(i)  - 
        :(s)  mask :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x1064):
            raise Exception("Fail of urfa_call(0x1064) [rpcf_del_ippool]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.add_data(params['address'], U_TP_IP)
        self.pck.add_data(params['mask'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_radius_get_active_sessions(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  traffic_sessions_count :	(i)  - 
        :(s)    traf_id :	(i)  - 
        :(s)    traf_acct_session_id :	(s)  - 
        :(s)    traf_user_name :	(s)  - 
        :(s)    traf_nas_ip :	(i)  - 
        :(s)    traf_recv_date :	(i)  - 
        :(s)    traf_last_update_date :	(i)  - 
        :(s)    framed_ip4 :	(i)  - 
        :(s)    framed_ip6 :	(i)  - 
        :(s)  tel_sessions_count :	(i)  - 
        :(s)    tel_id :	(i)  - 
        :(s)    tel_acct_session_id :	(s)  - 
        :(s)    tel_user_name :	(s)  - 
        :(s)    tel_nas_ip :	(i)  - 
        :(s)    tel_recv_date :	(i)  - 
        :(s)    tel_last_update_date :	(i)  - 
        :(s)    called_station_id :	(s)  - 
        :(s)    calling_station_id :	(s)  - 
        """
        if not self.urfa_call(0x1070):
            raise Exception("Fail of urfa_call(0x1070) [rpcf_radius_get_active_sessions]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['traffic_sessions_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['traffic_sessions_count']): 
            self.pck.recv(self.sck)
            ret['traf_id'][i] = self.pck.get_data(U_TP_I)
            ret['traf_acct_session_id'][i] = self.pck.get_data(U_TP_S)
            ret['traf_user_name'][i] = self.pck.get_data(U_TP_S)
            ret['traf_nas_ip'][i] = self.pck.get_data(U_TP_IP)
            ret['traf_recv_date'][i] = self.pck.get_data(U_TP_I)
            ret['traf_last_update_date'][i] = self.pck.get_data(U_TP_I)
            ret['framed_ip4'][i] = self.pck.get_data(U_TP_IP)
            ret['framed_ip6'][i] = self.pck.get_data(U_TP_IP)
        self.pck.recv(self.sck)
        ret['tel_sessions_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['tel_sessions_count']): 
            self.pck.recv(self.sck)
            ret['tel_id'][i] = self.pck.get_data(U_TP_I)
            ret['tel_acct_session_id'][i] = self.pck.get_data(U_TP_S)
            ret['tel_user_name'][i] = self.pck.get_data(U_TP_S)
            ret['tel_nas_ip'][i] = self.pck.get_data(U_TP_IP)
            ret['tel_recv_date'][i] = self.pck.get_data(U_TP_I)
            ret['tel_last_update_date'][i] = self.pck.get_data(U_TP_I)
            ret['called_station_id'][i] = self.pck.get_data(U_TP_S)
            ret['calling_station_id'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_radius_disconnect_session(self, params):
        """ description
        @params: 
        :(s)  acct_session_id :	(s)  - 
        :(s)  nas_ip :	(i)  - 
        @returns: 
        :(s)  error_code :	(i)  - 
        """
        if not self.urfa_call(0x1071):
            raise Exception("Fail of urfa_call(0x1071) [rpcf_radius_disconnect_session]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['acct_session_id'], U_TP_S)
        self.pck.add_data(params['nas_ip'], U_TP_IP)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['error_code'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_radius_drop_session(self, params):
        """ description
        @params: 
        :(s)  acct_session_id :	(s)  - 
        :(s)  nas_ip :	(i)  - 
        @returns: 
        :(s)  error_code :	(i)  - 
        """
        if not self.urfa_call(0x1072):
            raise Exception("Fail of urfa_call(0x1072) [rpcf_radius_drop_session]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['acct_session_id'], U_TP_S)
        self.pck.add_data(params['nas_ip'], U_TP_IP)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['error_code'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_radius_get_attributes_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  objects_count :	(i)  - 
        :(s)    object_id :	(i)  - 
        :(s)    object_type :	(i)  - 
        :(s)    attrs_count :	(i)  - 
        :(s)      vendor_type :	(i)  - 
        :(s)      attr_code :	(i)  - 
        :(s)      attr_data_type :	(i)  - 
        :(s)        attr_data_int :	(i)  - 
        :(s)        attr_data_string :	(s)  - 
        :(s)        attr_data_ip :	(i)  - 
        """
        if not self.urfa_call(0x1065):
            raise Exception("Fail of urfa_call(0x1065) [rpcf_radius_get_attributes_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['objects_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['objects_count']): 
            self.pck.recv(self.sck)
            ret['object_id'][i] = self.pck.get_data(U_TP_I)
            ret['object_type'][i] = self.pck.get_data(U_TP_I)
            ret['attrs_count'][i] = self.pck.get_data(U_TP_I)
            for j in range(ret['attrs_count'][i]): 
                self.pck.recv(self.sck)
                if not i in ret['vendor_type']:ret['vendor_type'][i] = dict()
                ret['vendor_type'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['attr_code']:ret['attr_code'][i] = dict()
                ret['attr_code'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['attr_data_type']:ret['attr_data_type'][i] = dict()
                ret['attr_data_type'][i][j] = self.pck.get_data(U_TP_I)
                if ret['attr_data_type'][i][j]  ==  1:
                    if not i in ret['attr_data_int']:ret['attr_data_int'][i] = dict()
                    ret['attr_data_int'][i][j] = self.pck.get_data(U_TP_I)
                if ret['attr_data_type'][i][j]  ==  2:
                    if not i in ret['attr_data_string']:ret['attr_data_string'][i] = dict()
                    ret['attr_data_string'][i][j] = self.pck.get_data(U_TP_S)
                if ret['attr_data_type'][i][j]  ==  3:
                    if not i in ret['attr_data_ip']:ret['attr_data_ip'][i] = dict()
                    ret['attr_data_ip'][i][j] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_search_cards(self, params):
        """ description
        @params: 
        :(s)  select_type :	(i)  - 
        :(s)  patterns_count :	(i) = _def_  - 
        :(s)    what_id :	(i)  - 
        :(s)    criteria_id :	(i)  - 
        :(s)    pattern :	(s)  - 
        @returns: 
        :(s)  cards_size :	(i)  - 
        :(s)    card_id :	(i)  - 
        :(s)    pool_id :	(i)  - 
        :(s)    secret :	(s)  - 
        :(s)    balance :	(d)  - 
        :(s)    currency :	(i)  - 
        :(s)    expire :	(i)  - 
        :(s)    days :	(i)  - 
        :(s)    is_used :	(i)  - 
        :(s)    tp_id :	(i)  - 
        """
        if not self.urfa_call(0x1201):
            raise Exception("Fail of urfa_call(0x1201) [rpcf_search_cards]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['select_type'], U_TP_I)
        if 'patterns_count' not in params: params['patterns_count'] = len(params['what_id'])
        self.pck.add_data(params['patterns_count'], U_TP_I)
        for i in range(len(params['what_id'])):
            self.pck.add_data(params['what_id'][i], U_TP_I)
            self.pck.add_data(params['criteria_id'][i], U_TP_I)
            self.pck.add_data(params['pattern'][i], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['cards_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['cards_size']): 
            self.pck.recv(self.sck)
            ret['card_id'][i] = self.pck.get_data(U_TP_I)
            ret['pool_id'][i] = self.pck.get_data(U_TP_I)
            ret['secret'][i] = self.pck.get_data(U_TP_S)
            ret['balance'][i] = self.pck.get_data(U_TP_D)
            ret['currency'][i] = self.pck.get_data(U_TP_I)
            ret['expire'][i] = self.pck.get_data(U_TP_I)
            ret['days'][i] = self.pck.get_data(U_TP_I)
            ret['is_used'][i] = self.pck.get_data(U_TP_I)
            ret['tp_id'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_search_users_lite(self, params):
        """ description
        @params: 
        :(s)  login :	(s)  - 
        :(s)  email :	(s)  - 
        :(s)  fname :	(s)  - 
        @returns: 
        :(s)  success :	(i)  - 
        :(s)  total :	(i)  - 
        :(s)  show_count :	(i)  - 
        :(s)      id :	(i)  - 
        :(s)      login :	(s)  - 
        :(s)      email :	(s)  - 
        :(s)      name :	(s)  - 
        """
        if not self.urfa_call(0x1202):
            raise Exception("Fail of urfa_call(0x1202) [rpcf_search_users_lite]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['login'], U_TP_S)
        self.pck.add_data(params['email'], U_TP_S)
        self.pck.add_data(params['fname'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['success'] = self.pck.get_data(U_TP_I)
        ret['total'] = self.pck.get_data(U_TP_I)
        ret['show_count'] = self.pck.get_data(U_TP_I)
        if ret['show_count']  !=  0:
            for i in range(ret['show_count']): 
                self.pck.recv(self.sck)
                ret['id'][i] = self.pck.get_data(U_TP_I)
                ret['login'][i] = self.pck.get_data(U_TP_S)
                ret['email'][i] = self.pck.get_data(U_TP_S)
                ret['name'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_search_users_new(self, params):
        """ description
        @params: 
        :(s)  poles_count :	(i) = _def_  - 
        :(s)    pole_code_array :	(i)  - 
        :(s)  select_type :	(i)  - 
        :(s)  patterns_count :	(i) = _def_  - 
        :(s)    what_id :	(i)  - 
        :(s)    criteria_id :	(i)  - 
        :(s)      data_pattern :	(i)  - 
        :(s)      data_pattern :	(i)  - 
        :(s)      data_pattern :	(i)  - 
        :(s)          pattern :	(s)  - 
        @returns: 
        :(s)  user_data_size :	(i)  - 
        :(s)    user_id :	(i)  - 
        :(s)    login :	(s)  - 
        :(s)    basic_account :	(i)  - 
        :(s)    full_name :	(s)  - 
        :(s)    is_blocked :	(i)  - 
        :(s)    balance :	(d)  - 
        :(s)    ip_address_size :	(i)  - 
        :(s)      ip_group_size :	(i)  - 
        :(s)        type :	(i)  - 
        :(s)        ip :	(i)  - 
        :(s)        mask :	(i)  - 
        :(s)        discount_period_id :	(i)  - 
        :(s)        create_date :	(i)  - 
        :(s)        last_change_date :	(i)  - 
        :(s)        who_create :	(i)  - 
        :(s)        who_change :	(i)  - 
        :(s)        is_juridical :	(i)  - 
        :(s)        juridical_address :	(s)  - 
        :(s)        actual_address :	(s)  - 
        :(s)        work_telephone :	(s)  - 
        :(s)        home_telephone :	(s)  - 
        :(s)        mobile_telephone :	(s)  - 
        :(s)        web_page :	(s)  - 
        :(s)        icq_number :	(s)  - 
        :(s)        tax_number :	(s)  - 
        :(s)        kpp_number :	(s)  - 
        :(s)        house_id :	(i)  - 
        :(s)        flat_number :	(s)  - 
        :(s)        entrance :	(s)  - 
        :(s)        floor :	(s)  - 
        :(s)        email :	(s)  - 
        :(s)        passport :	(s)  - 
        :(s)        district :	(s)  - 
        :(s)        building :	(s)  - 
        :(s)        external_id :	(s)  - 
        """
        if not self.urfa_call(0x1206):
            raise Exception("Fail of urfa_call(0x1206) [rpcf_search_users_new]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'poles_count' not in params: params['poles_count'] = len(params['pole_code_array'])
        self.pck.add_data(params['poles_count'], U_TP_I)
        for i in range(len(params['pole_code_array'])):
            self.pck.add_data(params['pole_code_array'][i], U_TP_I)
        self.pck.add_data(params['select_type'], U_TP_I)
        if 'patterns_count' not in params: params['patterns_count'] = len(params['what_id'])
        self.pck.add_data(params['patterns_count'], U_TP_I)
        for i in range(len(params['what_id'])):
            self.pck.add_data(params['what_id'][i], U_TP_I)
            self.pck.add_data(params['criteria_id'][i], U_TP_I)
            if params['what_id']  ==  33:
                self.pck.add_data(params['data_pattern'][i], U_TP_I)
            if params['what_id']  ==  6:
                self.pck.add_data(params['data_pattern'][i], U_TP_I)
            if params['what_id']  ==  7:
                self.pck.add_data(params['data_pattern'][i], U_TP_I)
            if params['what_id']  !=  33:
                if params['what_id']  !=  6:
                    if params['what_id']  !=  7:
                        self.pck.add_data(params['pattern'][i], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['user_data_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['user_data_size']): 
            self.pck.recv(self.sck)
            ret['user_id'][i] = self.pck.get_data(U_TP_I)
            ret['login'][i] = self.pck.get_data(U_TP_S)
            ret['basic_account'][i] = self.pck.get_data(U_TP_I)
            ret['full_name'][i] = self.pck.get_data(U_TP_S)
            ret['is_blocked'][i] = self.pck.get_data(U_TP_I)
            ret['balance'][i] = self.pck.get_data(U_TP_D)
            ret['ip_address_size'] = self.pck.get_data(U_TP_I)
            ret['ip_address_size_array'][i]=ret['ip_address_size']
            for j in range(ret['ip_address_size']): 
                self.pck.recv(self.sck)
                ret['ip_group_size'] = self.pck.get_data(U_TP_I)
                ret['ip_group_size_array'][i][j]=ret['ip_group_size']
                for x in range(ret['ip_group_size']): 
                    self.pck.recv(self.sck)
                    if not i in ret['type']:ret['type'][i] = dict()
                    if not j in ret['type'][i]:ret['type'][i][j] = dict()
                    ret['type'][i][j][x] = self.pck.get_data(U_TP_I)
                    if not i in ret['ip']:ret['ip'][i] = dict()
                    if not j in ret['ip'][i]:ret['ip'][i][j] = dict()
                    ret['ip'][i][j][x] = self.pck.get_data(U_TP_IP)
                    if not i in ret['mask']:ret['mask'][i] = dict()
                    if not j in ret['mask'][i]:ret['mask'][i][j] = dict()
                    ret['mask'][i][j][x] = self.pck.get_data(U_TP_I)
            self.pck.recv(self.sck)
            for z in range(len(params['pole_code_array'])): 
                self.pck.recv(self.sck)
                ret['pole_code']=params['pole_code_array'][z]
                if ret['pole_code']  ==  4:
                    ret['discount_period_id'][i] = self.pck.get_data(U_TP_I)
                if ret['pole_code']  ==  6:
                    ret['create_date'][i] = self.pck.get_data(U_TP_I)
                if ret['pole_code']  ==  7:
                    ret['last_change_date'][i] = self.pck.get_data(U_TP_I)
                if ret['pole_code']  ==  8:
                    ret['who_create'][i] = self.pck.get_data(U_TP_I)
                if ret['pole_code']  ==  9:
                    ret['who_change'][i] = self.pck.get_data(U_TP_I)
                if ret['pole_code']  ==  10:
                    ret['is_juridical'][i] = self.pck.get_data(U_TP_I)
                if ret['pole_code']  ==  11:
                    ret['juridical_address'][i] = self.pck.get_data(U_TP_S)
                if ret['pole_code']  ==  12:
                    ret['actual_address'][i] = self.pck.get_data(U_TP_S)
                if ret['pole_code']  ==  13:
                    ret['work_telephone'][i] = self.pck.get_data(U_TP_S)
                if ret['pole_code']  ==  14:
                    ret['home_telephone'][i] = self.pck.get_data(U_TP_S)
                if ret['pole_code']  ==  15:
                    ret['mobile_telephone'][i] = self.pck.get_data(U_TP_S)
                if ret['pole_code']  ==  16:
                    ret['web_page'][i] = self.pck.get_data(U_TP_S)
                if ret['pole_code']  ==  17:
                    ret['icq_number'][i] = self.pck.get_data(U_TP_S)
                if ret['pole_code']  ==  18:
                    ret['tax_number'][i] = self.pck.get_data(U_TP_S)
                if ret['pole_code']  ==  19:
                    ret['kpp_number'][i] = self.pck.get_data(U_TP_S)
                if ret['pole_code']  ==  21:
                    ret['house_id'][i] = self.pck.get_data(U_TP_I)
                if ret['pole_code']  ==  22:
                    ret['flat_number'][i] = self.pck.get_data(U_TP_S)
                if ret['pole_code']  ==  23:
                    ret['entrance'][i] = self.pck.get_data(U_TP_S)
                if ret['pole_code']  ==  24:
                    ret['floor'][i] = self.pck.get_data(U_TP_S)
                if ret['pole_code']  ==  25:
                    ret['email'][i] = self.pck.get_data(U_TP_S)
                if ret['pole_code']  ==  26:
                    ret['passport'][i] = self.pck.get_data(U_TP_S)
                if ret['pole_code']  ==  40:
                    ret['district'][i] = self.pck.get_data(U_TP_S)
                if ret['pole_code']  ==  41:
                    ret['building'][i] = self.pck.get_data(U_TP_S)
                if ret['pole_code']  ==  44:
                    ret['external_id'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_users_list(self, params):
        """ description
        @params: 
        :(s)  from :	(i)  - 
        :(s)  to :	(i)  - 
        :(s)  card_user :	(i) = _def_  - 
        @returns: 
        :(s)  cnt :	(i)  - 
        :(s)    user_id_array :	(i)  - 
        :(s)    login_array :	(s)  - 
        :(s)    basic_account :	(i)  - 
        :(s)    full_name :	(s)  - 
        :(s)    is_blocked :	(i)  - 
        :(s)    balance :	(d)  - 
        :(s)    ip_adr_size :	(i)  - 
        :(s)      group_size :	(i)  - 
        :(s)        ip_address :	(i)  - 
        :(s)        mask :	(i)  - 
        :(s)        group_type :	(i)  - 
        :(s)    user_int_status :	(i)  - 
        """
        if not self.urfa_call(0x2044):
            raise Exception("Fail of urfa_call(0x2044) [rpcf_get_users_list]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['from'], U_TP_I)
        self.pck.add_data(params['to'], U_TP_I)
        if 'card_user' not in params: params['card_user'] = 0
        self.pck.add_data(params['card_user'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['cnt'] = self.pck.get_data(U_TP_I)
        for i in range(ret['cnt']): 
            self.pck.recv(self.sck)
            ret['user_id_array'][i] = self.pck.get_data(U_TP_I)
            ret['login_array'][i] = self.pck.get_data(U_TP_S)
            ret['basic_account'][i] = self.pck.get_data(U_TP_I)
            ret['full_name'][i] = self.pck.get_data(U_TP_S)
            ret['is_blocked'][i] = self.pck.get_data(U_TP_I)
            ret['balance'][i] = self.pck.get_data(U_TP_D)
            ret['ip_adr_size'] = self.pck.get_data(U_TP_I)
            ret['ip_adr_size_array'][i]=ret['ip_adr_size']
            for j in range(ret['ip_adr_size']): 
                self.pck.recv(self.sck)
                ret['group_size'] = self.pck.get_data(U_TP_I)
                ret['group_size_array'][i][j]=ret['group_size']
                for x in range(ret['group_size']): 
                    self.pck.recv(self.sck)
                    if not i in ret['ip_address']:ret['ip_address'][i] = dict()
                    if not j in ret['ip_address'][i]:ret['ip_address'][i][j] = dict()
                    ret['ip_address'][i][j][x] = self.pck.get_data(U_TP_IP)
                    if not i in ret['mask']:ret['mask'][i] = dict()
                    if not j in ret['mask'][i]:ret['mask'][i][j] = dict()
                    ret['mask'][i][j][x] = self.pck.get_data(U_TP_I)
                    if not i in ret['group_type']:ret['group_type'][i] = dict()
                    if not j in ret['group_type'][i]:ret['group_type'][i][j] = dict()
                    ret['group_type'][i][j][x] = self.pck.get_data(U_TP_I)
            self.pck.recv(self.sck)
            ret['user_int_status'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_change_intstat_for_user(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  need_block :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x2003):
            raise Exception("Fail of urfa_call(0x2003) [rpcf_change_intstat_for_user]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['need_block'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_user(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i) = _def_  - 
        :(s)  login :	(s)  - 
        :(s)  password :	(s)  - 
        :(s)  full_name :	(s)  - 
        :(s)    unused :	(i) = _def_  - 
        :(s)  is_juridical :	(i) = _def_  - 
        :(s)  jur_address :	(s)  - 
        :(s)  act_address :	(s)  - 
        :(s)  flat_number :	(s)  - 
        :(s)  entrance :	(s)  - 
        :(s)  floor :	(s)  - 
        :(s)  district :	(s)  - 
        :(s)  building :	(s)  - 
        :(s)  passport :	(s)  - 
        :(s)  house_id :	(i) = _def_  - 
        :(s)  work_tel :	(s)  - 
        :(s)  home_tel :	(s)  - 
        :(s)  mob_tel :	(s)  - 
        :(s)  web_page :	(s)  - 
        :(s)  icq_number :	(s)  - 
        :(s)  tax_number :	(s)  - 
        :(s)  kpp_number :	(s)  - 
        :(s)  email :	(s)  - 
        :(s)  bank_id :	(i) = _def_  - 
        :(s)  bank_account :	(s)  - 
        :(s)  comments :	(s)  - 
        :(s)  personal_manager :	(s)  - 
        :(s)  connect_date :	(i) = _def_  - 
        :(s)  is_send_invoice :	(i) = _def_  - 
        :(s)  advance_payment :	(i) = _def_  - 
        :(s)  parameters_count :	(i) = _def_  - 
        :(s)    parameter_id :	(i)  - 
        :(s)    parameter_value :	(s)  - 
        @returns: 
        :(s)  user_id :	(i)  - 
        :(s)  error_msg :	(s)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        """
        if not self.urfa_call(0x2005):
            raise Exception("Fail of urfa_call(0x2005) [rpcf_add_user]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'user_id' not in params: params['user_id'] = 0
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['login'], U_TP_S)
        self.pck.add_data(params['password'], U_TP_S)
        self.pck.add_data(params['full_name'], U_TP_S)
        if params['user_id']  ==  0:
            if 'unused' not in params: params['unused'] = 0
            self.pck.add_data(params['unused'], U_TP_I)
        if 'is_juridical' not in params: params['is_juridical'] = 0
        self.pck.add_data(params['is_juridical'], U_TP_I)
        self.pck.add_data(params['jur_address'], U_TP_S)
        self.pck.add_data(params['act_address'], U_TP_S)
        self.pck.add_data(params['flat_number'], U_TP_S)
        self.pck.add_data(params['entrance'], U_TP_S)
        self.pck.add_data(params['floor'], U_TP_S)
        self.pck.add_data(params['district'], U_TP_S)
        self.pck.add_data(params['building'], U_TP_S)
        self.pck.add_data(params['passport'], U_TP_S)
        if 'house_id' not in params: params['house_id'] = 0
        self.pck.add_data(params['house_id'], U_TP_I)
        self.pck.add_data(params['work_tel'], U_TP_S)
        self.pck.add_data(params['home_tel'], U_TP_S)
        self.pck.add_data(params['mob_tel'], U_TP_S)
        self.pck.add_data(params['web_page'], U_TP_S)
        self.pck.add_data(params['icq_number'], U_TP_S)
        self.pck.add_data(params['tax_number'], U_TP_S)
        self.pck.add_data(params['kpp_number'], U_TP_S)
        self.pck.add_data(params['email'], U_TP_S)
        if 'bank_id' not in params: params['bank_id'] = 0
        self.pck.add_data(params['bank_id'], U_TP_I)
        self.pck.add_data(params['bank_account'], U_TP_S)
        self.pck.add_data(params['comments'], U_TP_S)
        self.pck.add_data(params['personal_manager'], U_TP_S)
        if 'connect_date' not in params: params['connect_date'] = 0
        self.pck.add_data(params['connect_date'], U_TP_I)
        if 'is_send_invoice' not in params: params['is_send_invoice'] = 0
        self.pck.add_data(params['is_send_invoice'], U_TP_I)
        if 'advance_payment' not in params: params['advance_payment'] = 0
        self.pck.add_data(params['advance_payment'], U_TP_I)
        if 'parameters_count' not in params: params['parameters_count'] = len(params['parameter_value'])
        self.pck.add_data(params['parameters_count'], U_TP_I)
        for i in range(len(params['parameter_value'])):
            self.pck.add_data(params['parameter_id'][i], U_TP_I)
            self.pck.add_data(params['parameter_value'][i], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['user_id'] = self.pck.get_data(U_TP_I)
        ret['error_msg'] = self.pck.get_data(U_TP_S)
        if params['user_id']  ==  0:
            ret['error'] = dict({10:"unable to add or edit user"})
        if params['user_id']  ==  -1:
            ret['error'] = dict({10:"unable to add user, probably login exists"})
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_userinfo(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        @returns: 
        :(s)  user_id :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        :(s)  accounts_count :	(i)  - 
        :(s)    account_id_array :	(i)  - 
        :(s)    account_name_array :	(s)  - 
        :(s)  login :	(s)  - 
        :(s)  password :	(s)  - 
        :(s)  basic_account :	(i)  - 
        :(s)  full_name :	(s)  - 
        :(s)  create_date :	(i)  - 
        :(s)  last_change_date :	(i)  - 
        :(s)  who_create :	(i)  - 
        :(s)  who_change :	(i)  - 
        :(s)  is_juridical :	(i)  - 
        :(s)  jur_address :	(s)  - 
        :(s)  act_address :	(s)  - 
        :(s)  work_tel :	(s)  - 
        :(s)  home_tel :	(s)  - 
        :(s)  mob_tel :	(s)  - 
        :(s)  web_page :	(s)  - 
        :(s)  icq_number :	(s)  - 
        :(s)  tax_number :	(s)  - 
        :(s)  kpp_number :	(s)  - 
        :(s)  bank_id :	(i)  - 
        :(s)  bank_account :	(s)  - 
        :(s)  comments :	(s)  - 
        :(s)  personal_manager :	(s)  - 
        :(s)  connect_date :	(i)  - 
        :(s)  email :	(s)  - 
        :(s)  is_send_invoice :	(i)  - 
        :(s)  advance_payment :	(i)  - 
        :(s)  house_id :	(i)  - 
        :(s)  flat_number :	(s)  - 
        :(s)  entrance :	(s)  - 
        :(s)  floor :	(s)  - 
        :(s)  district :	(s)  - 
        :(s)  building :	(s)  - 
        :(s)  passport :	(s)  - 
        :(s)  parameters_size :	(i)  - 
        :(s)    parameter_id :	(i)  - 
        :(s)    parameter_value :	(s)  - 
        """
        if not self.urfa_call(0x2006):
            raise Exception("Fail of urfa_call(0x2006) [rpcf_get_userinfo]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['user_id'] = self.pck.get_data(U_TP_I)
        if params['user_id']  ==  0:
            ret['error'] = dict({10:"user not found"})
        ret['accounts_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['accounts_count']): 
            self.pck.recv(self.sck)
            ret['account_id_array'][i] = self.pck.get_data(U_TP_I)
            ret['account_name_array'][i] = self.pck.get_data(U_TP_S)
        self.pck.recv(self.sck)
        ret['login'] = self.pck.get_data(U_TP_S)
        ret['password'] = self.pck.get_data(U_TP_S)
        ret['basic_account'] = self.pck.get_data(U_TP_I)
        ret['full_name'] = self.pck.get_data(U_TP_S)
        ret['create_date'] = self.pck.get_data(U_TP_I)
        ret['last_change_date'] = self.pck.get_data(U_TP_I)
        ret['who_create'] = self.pck.get_data(U_TP_I)
        ret['who_change'] = self.pck.get_data(U_TP_I)
        ret['is_juridical'] = self.pck.get_data(U_TP_I)
        ret['jur_address'] = self.pck.get_data(U_TP_S)
        ret['act_address'] = self.pck.get_data(U_TP_S)
        ret['work_tel'] = self.pck.get_data(U_TP_S)
        ret['home_tel'] = self.pck.get_data(U_TP_S)
        ret['mob_tel'] = self.pck.get_data(U_TP_S)
        ret['web_page'] = self.pck.get_data(U_TP_S)
        ret['icq_number'] = self.pck.get_data(U_TP_S)
        ret['tax_number'] = self.pck.get_data(U_TP_S)
        ret['kpp_number'] = self.pck.get_data(U_TP_S)
        ret['bank_id'] = self.pck.get_data(U_TP_I)
        ret['bank_account'] = self.pck.get_data(U_TP_S)
        ret['comments'] = self.pck.get_data(U_TP_S)
        ret['personal_manager'] = self.pck.get_data(U_TP_S)
        ret['connect_date'] = self.pck.get_data(U_TP_I)
        ret['email'] = self.pck.get_data(U_TP_S)
        ret['is_send_invoice'] = self.pck.get_data(U_TP_I)
        ret['advance_payment'] = self.pck.get_data(U_TP_I)
        ret['house_id'] = self.pck.get_data(U_TP_I)
        ret['flat_number'] = self.pck.get_data(U_TP_S)
        ret['entrance'] = self.pck.get_data(U_TP_S)
        ret['floor'] = self.pck.get_data(U_TP_S)
        ret['district'] = self.pck.get_data(U_TP_S)
        ret['building'] = self.pck.get_data(U_TP_S)
        ret['passport'] = self.pck.get_data(U_TP_S)
        ret['parameters_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['parameters_size']): 
            self.pck.recv(self.sck)
            ret['parameter_id'][i] = self.pck.get_data(U_TP_I)
            ret['parameter_value'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_login_for_slink(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i)  - 
        @returns: 
        :(s)  user_data_full_login :	(s)  - 
        """
        if not self.urfa_call(0x200d):
            raise Exception("Fail of urfa_call(0x200d) [rpcf_get_login_for_slink]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['user_data_full_login'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_remove_user(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x200e):
            raise Exception("Fail of urfa_call(0x200e) [rpcf_remove_user]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_users_count(self, params):
        """ description
        @params: 
        :(s)  card_user :	(i) = _def_  - 
        @returns: 
        :(s)  count :	(i)  - 
        """
        if not self.urfa_call(0x2011):
            raise Exception("Fail of urfa_call(0x2011) [rpcf_get_users_count]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'card_user' not in params: params['card_user'] = 0
        self.pck.add_data(params['card_user'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['count'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_user_contacts(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        @returns: 
        :(s)  size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    person :	(s)  - 
        :(s)    descr :	(s)  - 
        :(s)    contact :	(s)  - 
        :(s)    email :	(s)  - 
        :(s)    email_notify :	(i)  - 
        :(s)    short_name :	(s)  - 
        :(s)    birthday :	(s)  - 
        :(s)    id_exec_man :	(i)  - 
        """
        if not self.urfa_call(0x2021):
            raise Exception("Fail of urfa_call(0x2021) [rpcf_get_user_contacts]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['person'][i] = self.pck.get_data(U_TP_S)
            ret['descr'][i] = self.pck.get_data(U_TP_S)
            ret['contact'][i] = self.pck.get_data(U_TP_S)
            ret['email'][i] = self.pck.get_data(U_TP_S)
            ret['email_notify'][i] = self.pck.get_data(U_TP_I)
            ret['short_name'][i] = self.pck.get_data(U_TP_S)
            ret['birthday'][i] = self.pck.get_data(U_TP_S)
            ret['id_exec_man'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_put_user_contact(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        :(s)  user_id :	(i)  - 
        :(s)  person :	(s)  - 
        :(s)  descr :	(s)  - 
        :(s)  contact :	(s)  - 
        :(s)  email :	(s)  - 
        :(s)  email_notify :	(i)  - 
        :(s)  short_name :	(s)  - 
        :(s)  birthday :	(s)  - 
        :(s)  id_exec_man :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x2022):
            raise Exception("Fail of urfa_call(0x2022) [rpcf_put_user_contact]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['person'], U_TP_S)
        self.pck.add_data(params['descr'], U_TP_S)
        self.pck.add_data(params['contact'], U_TP_S)
        self.pck.add_data(params['email'], U_TP_S)
        self.pck.add_data(params['email_notify'], U_TP_I)
        self.pck.add_data(params['short_name'], U_TP_S)
        self.pck.add_data(params['birthday'], U_TP_S)
        self.pck.add_data(params['id_exec_man'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_del_user_contact(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x2023):
            raise Exception("Fail of urfa_call(0x2023) [rpcf_del_user_contact]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_user_log(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  tstart :	(i)  - 
        :(s)  tstop :	(i)  - 
        :(s)  group_id :	(i)  - 
        :(s)  action :	(i)  - 
        @returns: 
        :(s)  size :	(i)  - 
        :(s)    user_id :	(i)  - 
        :(s)    ud_login :	(s)  - 
        :(s)    who :	(i)  - 
        :(s)    usd_login :	(s)  - 
        :(s)    date :	(i)  - 
        :(s)    action :	(i)  - 
        :(s)    want :	(s)  - 
        :(s)    comment :	(s)  - 
        """
        if not self.urfa_call(0x2136):
            raise Exception("Fail of urfa_call(0x2136) [rpcf_get_user_log]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['tstart'], U_TP_I)
        self.pck.add_data(params['tstop'], U_TP_I)
        self.pck.add_data(params['group_id'], U_TP_I)
        self.pck.add_data(params['action'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['size']): 
            self.pck.recv(self.sck)
            ret['user_id'][i] = self.pck.get_data(U_TP_I)
            ret['ud_login'][i] = self.pck.get_data(U_TP_S)
            ret['who'][i] = self.pck.get_data(U_TP_I)
            ret['usd_login'][i] = self.pck.get_data(U_TP_S)
            ret['date'][i] = self.pck.get_data(U_TP_I)
            ret['action'][i] = self.pck.get_data(U_TP_I)
            ret['want'][i] = self.pck.get_data(U_TP_S)
            ret['comment'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_user_log(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  what :	(i)  - 
        :(s)  comment :	(s)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x1510c):
            raise Exception("Fail of urfa_call(0x1510c) [rpcf_add_user_log]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['what'], U_TP_I)
        self.pck.add_data(params['comment'], U_TP_S)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_user_by_account(self, params):
        """ description
        @params: 
        :(s)  account_id :	(i)  - 
        @returns: 
        :(s)  user_id :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        """
        if not self.urfa_call(0x2026):
            raise Exception("Fail of urfa_call(0x2026) [rpcf_get_user_by_account]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['user_id'] = self.pck.get_data(U_TP_I)
        if ret['user_id']  ==  0:
            ret['error'] = dict({19:"No such account linked with user"})
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_accountinfo(self, params):
        """ description
        @params: 
        :(s)  account_id :	(i)  - 
        @returns: 
        :(s)  is_blocked :	(i)  - 
        :(s)  vat_rate :	(d)  - 
        :(s)  sale_tax_rate :	(d)  - 
        :(s)  credit :	(d)  - 
        :(s)  balance :	(d)  - 
        :(s)  int_status :	(i)  - 
        :(s)  unlimited :	(i)  - 
        :(s)  auto_enable_inet :	(i)  - 
        :(s)  external_id :	(s)  - 
        """
        if not self.urfa_call(0x15109):
            raise Exception("Fail of urfa_call(0x15109) [rpcf_get_accountinfo]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['is_blocked'] = self.pck.get_data(U_TP_I)
        ret['vat_rate'] = self.pck.get_data(U_TP_D)
        ret['sale_tax_rate'] = self.pck.get_data(U_TP_D)
        ret['credit'] = self.pck.get_data(U_TP_D)
        ret['balance'] = self.pck.get_data(U_TP_D)
        ret['int_status'] = self.pck.get_data(U_TP_I)
        ret['unlimited'] = self.pck.get_data(U_TP_I)
        ret['auto_enable_inet'] = self.pck.get_data(U_TP_I)
        ret['external_id'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_account(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  is_basic :	(i) = _def_  - 
        :(s)  is_blocked :	(i) = _def_  - 
        :(s)  balance :	(d) = _def_  - 
        :(s)  credit :	(d) = _def_  - 
        :(s)  vat_rate :	(d) = _def_  - 
        :(s)  sale_tax_rate :	(d) = _def_  - 
        :(s)  int_status :	(i) = _def_  - 
        :(s)  unlimited :	(i) = _def_  - 
        :(s)  auto_enable_inet :	(i) = _def_  - 
        :(s)  external_id :	(i)  - 
        @returns: 
        :(s)  account_id :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        """
        if not self.urfa_call(0x1510a):
            raise Exception("Fail of urfa_call(0x1510a) [rpcf_add_account]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'is_basic' not in params: params['is_basic'] = 1
        self.pck.add_data(params['is_basic'], U_TP_I)
        if 'is_blocked' not in params: params['is_blocked'] = 0
        self.pck.add_data(params['is_blocked'], U_TP_I)
        if 'balance' not in params: params['balance'] = 0.0
        self.pck.add_data(params['balance'], U_TP_D)
        if 'credit' not in params: params['credit'] = 0.0
        self.pck.add_data(params['credit'], U_TP_D)
        if 'vat_rate' not in params: params['vat_rate'] = 0.0
        self.pck.add_data(params['vat_rate'], U_TP_D)
        if 'sale_tax_rate' not in params: params['sale_tax_rate'] = 0.0
        self.pck.add_data(params['sale_tax_rate'], U_TP_D)
        if 'int_status' not in params: params['int_status'] = 1
        self.pck.add_data(params['int_status'], U_TP_I)
        if 'unlimited' not in params: params['unlimited'] = 0
        self.pck.add_data(params['unlimited'], U_TP_I)
        if 'auto_enable_inet' not in params: params['auto_enable_inet'] = 1
        self.pck.add_data(params['auto_enable_inet'], U_TP_I)
        self.pck.add_data(params['external_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['account_id'] = self.pck.get_data(U_TP_I)
        if ret['account_id']  ==  0:
            ret['error'] = dict({11:"unable to add account"})
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_save_account(self, params):
        """ description
        @params: 
        :(s)  account_id :	(i)  - 
        :(s)  credit :	(d)  - 
        :(s)  is_blocked :	(i)  - 
        :(s)    block_start_date :	(i) = _def_  - 
        :(s)    block_end_date :	(i) = _def_  - 
        :(s)  vat_rate :	(d)  - 
        :(s)  sale_tax_rate :	(d)  - 
        :(s)  int_status :	(i)  - 
        :(s)  unlimited :	(i)  - 
        :(s)  auto_enable_inet :	(i)  - 
        :(s)  external_id :	(s)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x1510b):
            raise Exception("Fail of urfa_call(0x1510b) [rpcf_save_account]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['credit'], U_TP_D)
        self.pck.add_data(params['is_blocked'], U_TP_I)
        if params['is_blocked']  !=  0:
            if 'block_start_date' not in params: params['block_start_date'] = now()
            self.pck.add_data(params['block_start_date'], U_TP_I)
            if 'block_end_date' not in params: params['block_end_date'] = max_time()
            self.pck.add_data(params['block_end_date'], U_TP_I)
        self.pck.add_data(params['vat_rate'], U_TP_D)
        self.pck.add_data(params['sale_tax_rate'], U_TP_D)
        self.pck.add_data(params['int_status'], U_TP_I)
        self.pck.add_data(params['unlimited'], U_TP_I)
        self.pck.add_data(params['auto_enable_inet'], U_TP_I)
        self.pck.add_data(params['external_id'], U_TP_S)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_user_account_list(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        @returns: 
        :(s)  accounts_count :	(i)  - 
        :(s)    account :	(i)  - 
        :(s)    account_name :	(s)  - 
        """
        if not self.urfa_call(0x2033):
            raise Exception("Fail of urfa_call(0x2033) [rpcf_get_user_account_list]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['accounts_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['accounts_count']): 
            self.pck.recv(self.sck)
            ret['account'][i] = self.pck.get_data(U_TP_I)
            ret['account_name'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_remove_account(self, params):
        """ description
        @params: 
        :(s)  account_id :	(i)  - 
        @returns: 
        :(s)  ret_code :	(i)  - 
        """
        if not self.urfa_call(0x2034):
            raise Exception("Fail of urfa_call(0x2034) [rpcf_remove_account]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['ret_code'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_sys_settings(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  block_recalc_abon :	(i)  - 
        :(s)  block_recalc_prepaid :	(i)  - 
        :(s)  default_vat_rate :	(d)  - 
        """
        if not self.urfa_call(0x2035):
            raise Exception("Fail of urfa_call(0x2035) [rpcf_get_sys_settings]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['block_recalc_abon'] = self.pck.get_data(U_TP_I)
        ret['block_recalc_prepaid'] = self.pck.get_data(U_TP_I)
        ret['default_vat_rate'] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_block_account(self, params):
        """ description
        @params: 
        :(s)  account_id :	(i)  - 
        :(s)  is_blocked :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x2037):
            raise Exception("Fail of urfa_call(0x2037) [rpcf_block_account]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['is_blocked'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_delete_quota(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i)  - 
        :(s)  tc_id :	(i)  - 
        @returns: 
        :(s)  res :	(i)  - 
        """
        if not self.urfa_call(0x20ff):
            raise Exception("Fail of urfa_call(0x20ff) [rpcf_delete_quota]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.add_data(params['tc_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['res'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_services_list(self, params):
        """ description
        @params: 
        :(s)  which_service :	(i) = _def_  - 
        @returns: 
        :(s)  services_count :	(i)  - 
        :(s)    service_id_array :	(i)  - 
        :(s)    service_name_array :	(s)  - 
        :(s)    service_type_array :	(i)  - 
        :(s)    service_comment_array :	(s)  - 
        :(s)    service_status_array :	(i)  - 
        :(s)      tariff_name_array :	(s)  - 
        """
        if not self.urfa_call(0x2101):
            raise Exception("Fail of urfa_call(0x2101) [rpcf_get_services_list]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'which_service' not in params: params['which_service'] = -1
        self.pck.add_data(params['which_service'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['services_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['services_count']): 
            self.pck.recv(self.sck)
            ret['service_id_array'][i] = self.pck.get_data(U_TP_I)
            ret['service_name_array'][i] = self.pck.get_data(U_TP_S)
            ret['service_type_array'][i] = self.pck.get_data(U_TP_I)
            ret['service_comment_array'][i] = self.pck.get_data(U_TP_S)
            ret['service_status_array'][i] = self.pck.get_data(U_TP_I)
            ret['service_status']=ret['service_status_array'][i][i]
            if ret['service_status']  ==  2:
                ret['tariff_name_array'][i] = self.pck.get_data(U_TP_S)
            if ret['service_status']  !=  2:
                ret['tariff_name_array'][i]=""
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_periodic_service(self, params):
        """ description
        @params: 
        :(s)  sid :	(i)  - 
        @returns: 
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  deprecated :	(i)  - 
        :(s)  discount_method :	(i)  - 
        :(s)  start_date :	(i)  - 
        :(s)  expire_date :	(i)  - 
        :(s)  param :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        """
        if not self.urfa_call(0x2104):
            raise Exception("Fail of urfa_call(0x2104) [rpcf_get_periodic_service]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['sid'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['service_name'] = self.pck.get_data(U_TP_S)
        ret['comment'] = self.pck.get_data(U_TP_S)
        ret['link_by_default'] = self.pck.get_data(U_TP_I)
        ret['cost'] = self.pck.get_data(U_TP_D)
        ret['deprecated'] = self.pck.get_data(U_TP_I)
        ret['discount_method'] = self.pck.get_data(U_TP_I)
        ret['start_date'] = self.pck.get_data(U_TP_I)
        ret['expire_date'] = self.pck.get_data(U_TP_I)
        ret['param'] = self.pck.get_data(U_TP_I)
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        ret['parent_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_iptraffic_service(self, params):
        """ description
        @params: 
        :(s)  sid :	(i)  - 
        @returns: 
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  is_dynamic :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  deprecated :	(i)  - 
        :(s)  discount_method :	(i)  - 
        :(s)  start_date :	(i)  - 
        :(s)  expire_date :	(i)  - 
        :(s)  null_service_prepaid :	(i)  - 
        :(s)  borders_count :	(i)  - 
        :(s)    tclass :	(i)  - 
        :(s)      borders_size :	(l)  - 
        :(s)        border_id :	(l)  - 
        :(s)        border_cost :	(d)  - 
        :(s)  prepaid_count :	(i)  - 
        :(s)    tclass :	(i)  - 
        :(s)      prepaid_amount :	(l)  - 
        :(s)      prepaid_max :	(l)  - 
        :(s)  tclass_id2group_size :	(i)  - 
        :(s)    tclass_id :	(i)  - 
        :(s)    tclass_group_id :	(i)  - 
        :(s)  service_data_parent_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        """
        if not self.urfa_call(0x2105):
            raise Exception("Fail of urfa_call(0x2105) [rpcf_get_iptraffic_service]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['sid'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['service_name'] = self.pck.get_data(U_TP_S)
        ret['comment'] = self.pck.get_data(U_TP_S)
        ret['link_by_default'] = self.pck.get_data(U_TP_I)
        ret['is_dynamic'] = self.pck.get_data(U_TP_I)
        ret['cost'] = self.pck.get_data(U_TP_D)
        ret['deprecated'] = self.pck.get_data(U_TP_I)
        ret['discount_method'] = self.pck.get_data(U_TP_I)
        ret['start_date'] = self.pck.get_data(U_TP_I)
        ret['expire_date'] = self.pck.get_data(U_TP_I)
        ret['null_service_prepaid'] = self.pck.get_data(U_TP_I)
        ret['borders_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['borders_count']): 
            self.pck.recv(self.sck)
            ret['tclass'][i] = self.pck.get_data(U_TP_I)
            if ret['tclass'][i]  !=  -1:
                ret['borders_size'] = self.pck.get_data(U_TP_L)
                ret['borders_size_array'][i]=ret['borders_size']
                for j in range(ret['borders_size']): 
                    self.pck.recv(self.sck)
                    if not i in ret['border_id']:ret['border_id'][i] = dict()
                    ret['border_id'][i][j] = self.pck.get_data(U_TP_L)
                    if not i in ret['border_cost']:ret['border_cost'][i] = dict()
                    ret['border_cost'][i][j] = self.pck.get_data(U_TP_D)
        self.pck.recv(self.sck)
        ret['prepaid_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['prepaid_count']): 
            self.pck.recv(self.sck)
            ret['tclass'][i] = self.pck.get_data(U_TP_I)
            if ret['tclass'][i]  !=  -1:
                ret['prepaid_amount'][i] = self.pck.get_data(U_TP_L)
                ret['prepaid_max'][i] = self.pck.get_data(U_TP_L)
        self.pck.recv(self.sck)
        ret['tclass_id2group_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['tclass_id2group_size']): 
            self.pck.recv(self.sck)
            ret['tclass_id'][i] = self.pck.get_data(U_TP_I)
            ret['tclass_group_id'][i] = self.pck.get_data(U_TP_I)
        self.pck.recv(self.sck)
        ret['service_data_parent_id'] = self.pck.get_data(U_TP_I)
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        ret['parent_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_periodic_service(self, params):
        """ description
        @params: 
        :(s)  fictive :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  service_id :	(i)  - 
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  param1 :	(i)  - 
        :(s)  discount_method :	(i)  - 
        :(s)  start_date :	(i)  - 
        :(s)  expire_date :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x2106):
            raise Exception("Fail of urfa_call(0x2106) [rpcf_add_periodic_service]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['fictive'], U_TP_I)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.add_data(params['service_name'], U_TP_S)
        self.pck.add_data(params['comment'], U_TP_S)
        self.pck.add_data(params['link_by_default'], U_TP_I)
        self.pck.add_data(params['cost'], U_TP_D)
        self.pck.add_data(params['param1'], U_TP_I)
        self.pck.add_data(params['discount_method'], U_TP_I)
        self.pck.add_data(params['start_date'], U_TP_I)
        self.pck.add_data(params['expire_date'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_hotspot_service(self, params):
        """ description
        @params: 
        :(s)  fictive :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  service_id :	(i)  - 
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  is_dynamic :	(i)  - 
        :(s)  param1 :	(i)  - 
        :(s)  discount_method :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  start_date :	(i)  - 
        :(s)  expire_date :	(i)  - 
        :(s)  null_service_prepaid :	(i)  - 
        :(s)  radius_sessions_limit :	(i)  - 
        :(s)  recv_cost :	(d)  - 
        :(s)  rate_limit :	(s)  - 
        :(s)  allowed_net_size :	(i)  - 
        :(s)    ip :	(i)  - 
        :(s)    value1 :	(i)  - 
        :(s)  periodic_service_size :	(i)  - 
        :(s)    cost_p :	(d)  - 
        :(s)    id_p :	(i)  - 
        @returns: 
        :(s)  sid :	(i)  - 
        """
        if not self.urfa_call(0x2108):
            raise Exception("Fail of urfa_call(0x2108) [rpcf_add_hotspot_service]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['fictive'], U_TP_I)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.add_data(params['service_name'], U_TP_S)
        self.pck.add_data(params['comment'], U_TP_S)
        self.pck.add_data(params['link_by_default'], U_TP_I)
        self.pck.add_data(params['is_dynamic'], U_TP_I)
        self.pck.add_data(params['param1'], U_TP_I)
        self.pck.add_data(params['discount_method'], U_TP_I)
        self.pck.add_data(params['cost'], U_TP_D)
        self.pck.add_data(params['start_date'], U_TP_I)
        self.pck.add_data(params['expire_date'], U_TP_I)
        self.pck.add_data(params['null_service_prepaid'], U_TP_I)
        self.pck.add_data(params['radius_sessions_limit'], U_TP_I)
        self.pck.add_data(params['recv_cost'], U_TP_D)
        self.pck.add_data(params['rate_limit'], U_TP_S)
        self.pck.add_data(params['allowed_net_size'], U_TP_I)
        for i in range(params['allowed_net_size']):
            self.pck.add_data(params['ip'][i], U_TP_IP)
            self.pck.add_data(params['value1'][i], U_TP_I)
        self.pck.add_data(params['periodic_service_size'], U_TP_I)
        for i in range(params['periodic_service_size']):
            self.pck.add_data(params['cost_p'][i], U_TP_D)
            self.pck.add_data(params['id_p'][i], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['sid'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_hotspot_service(self, params):
        """ description
        @params: 
        :(s)  sid :	(i)  - 
        @returns: 
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  is_dynamic :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  deprecated :	(i)  - 
        :(s)  discount_method :	(i)  - 
        :(s)  start_date :	(i)  - 
        :(s)  expire_date :	(i)  - 
        :(s)  null_service_prepaid :	(i)  - 
        :(s)  radius_sessions_limit :	(i)  - 
        :(s)  recv_cost :	(d)  - 
        :(s)  rate_limit :	(s)  - 
        :(s)  hsd_allowed_net_size :	(i)  - 
        :(s)    allowed_net_id :	(i)  - 
        :(s)    allowed_net_value :	(i)  - 
        :(s)  cost_size :	(i)  - 
        :(s)    tr_time :	(s)  - 
        :(s)    param1 :	(d)  - 
        :(s)    param2 :	(i)  - 
        :(s)  service_data_parent_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        """
        if not self.urfa_call(0x2109):
            raise Exception("Fail of urfa_call(0x2109) [rpcf_get_hotspot_service]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['sid'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['service_name'] = self.pck.get_data(U_TP_S)
        ret['comment'] = self.pck.get_data(U_TP_S)
        ret['link_by_default'] = self.pck.get_data(U_TP_I)
        ret['is_dynamic'] = self.pck.get_data(U_TP_I)
        ret['cost'] = self.pck.get_data(U_TP_D)
        ret['deprecated'] = self.pck.get_data(U_TP_I)
        ret['discount_method'] = self.pck.get_data(U_TP_I)
        ret['start_date'] = self.pck.get_data(U_TP_I)
        ret['expire_date'] = self.pck.get_data(U_TP_I)
        ret['null_service_prepaid'] = self.pck.get_data(U_TP_I)
        ret['radius_sessions_limit'] = self.pck.get_data(U_TP_I)
        ret['recv_cost'] = self.pck.get_data(U_TP_D)
        ret['rate_limit'] = self.pck.get_data(U_TP_S)
        ret['hsd_allowed_net_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['hsd_allowed_net_size']): 
            self.pck.recv(self.sck)
            ret['allowed_net_id'][i] = self.pck.get_data(U_TP_I)
            ret['allowed_net_value'][i] = self.pck.get_data(U_TP_I)
        self.pck.recv(self.sck)
        ret['cost_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['cost_size']): 
            self.pck.recv(self.sck)
            ret['tr_time'][i] = self.pck.get_data(U_TP_S)
            ret['param1'][i] = self.pck.get_data(U_TP_D)
            ret['param2'][i] = self.pck.get_data(U_TP_I)
        self.pck.recv(self.sck)
        ret['service_data_parent_id'] = self.pck.get_data(U_TP_I)
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        ret['parent_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_once_service(self, params):
        """ description
        @params: 
        :(s)  sid :	(i)  - 
        @returns: 
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  is_parent_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        """
        if not self.urfa_call(0x210a):
            raise Exception("Fail of urfa_call(0x210a) [rpcf_get_once_service]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['sid'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['service_name'] = self.pck.get_data(U_TP_S)
        ret['comment'] = self.pck.get_data(U_TP_S)
        ret['link_by_default'] = self.pck.get_data(U_TP_I)
        ret['cost'] = self.pck.get_data(U_TP_D)
        ret['is_parent_id'] = self.pck.get_data(U_TP_I)
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        ret['parent_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_once_service(self, params):
        """ description
        @params: 
        :(s)  parent_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  service_id :	(i)  - 
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  cost :	(d)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x210b):
            raise Exception("Fail of urfa_call(0x210b) [rpcf_add_once_service]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['parent_id'], U_TP_I)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.add_data(params['service_name'], U_TP_S)
        self.pck.add_data(params['comment'], U_TP_S)
        self.pck.add_data(params['link_by_default'], U_TP_I)
        self.pck.add_data(params['cost'], U_TP_D)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_dialup_service(self, params):
        """ description
        @params: 
        :(s)  sid :	(i)  - 
        @returns: 
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  is_dynamic :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  deprecated :	(i)  - 
        :(s)  discount_method :	(i)  - 
        :(s)  start_date :	(i)  - 
        :(s)  expire_date :	(i)  - 
        :(s)  pool_name :	(s)  - 
        :(s)  max_timeout :	(i)  - 
        :(s)  null_service_prepaid :	(i)  - 
        :(s)  radius_sessions_limit :	(i)  - 
        :(s)  login_prefix :	(s)  - 
        :(s)  cost_size :	(i)  - 
        :(s)    tr_time :	(s)  - 
        :(s)    param :	(d)  - 
        :(s)    id :	(i)  - 
        :(s)  is_parent_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        """
        if not self.urfa_call(0x210c):
            raise Exception("Fail of urfa_call(0x210c) [rpcf_get_dialup_service]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['sid'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['service_name'] = self.pck.get_data(U_TP_S)
        ret['comment'] = self.pck.get_data(U_TP_S)
        ret['link_by_default'] = self.pck.get_data(U_TP_I)
        ret['is_dynamic'] = self.pck.get_data(U_TP_I)
        ret['cost'] = self.pck.get_data(U_TP_D)
        ret['deprecated'] = self.pck.get_data(U_TP_I)
        ret['discount_method'] = self.pck.get_data(U_TP_I)
        ret['start_date'] = self.pck.get_data(U_TP_I)
        ret['expire_date'] = self.pck.get_data(U_TP_I)
        ret['pool_name'] = self.pck.get_data(U_TP_S)
        ret['max_timeout'] = self.pck.get_data(U_TP_I)
        ret['null_service_prepaid'] = self.pck.get_data(U_TP_I)
        ret['radius_sessions_limit'] = self.pck.get_data(U_TP_I)
        ret['login_prefix'] = self.pck.get_data(U_TP_S)
        ret['cost_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['cost_size']): 
            self.pck.recv(self.sck)
            ret['tr_time'][i] = self.pck.get_data(U_TP_S)
            ret['param'][i] = self.pck.get_data(U_TP_D)
            ret['id'][i] = self.pck.get_data(U_TP_I)
        self.pck.recv(self.sck)
        ret['is_parent_id'] = self.pck.get_data(U_TP_I)
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        ret['parent_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_dialup_service(self, params):
        """ description
        @params: 
        :(s)  parent_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  service_id :	(i)  - 
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  is_dynamic :	(i)  - 
        :(s)  periodic_param :	(i) = _def_  - 
        :(s)  discount_method :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  start_date :	(i)  - 
        :(s)  expire_date :	(i)  - 
        :(s)  pool_name :	(s)  - 
        :(s)  max_timeout :	(i)  - 
        :(s)  null_service_prepaid :	(i)  - 
        :(s)  radius_sessions_limit :	(i)  - 
        :(s)  login_prefix :	(s)  - 
        :(s)  cost_size :	(i) = _def_  - 
        :(s)    range_cost :	(d)  - 
        :(s)    range_id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x210d):
            raise Exception("Fail of urfa_call(0x210d) [rpcf_add_dialup_service]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['parent_id'], U_TP_I)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.add_data(params['service_name'], U_TP_S)
        self.pck.add_data(params['comment'], U_TP_S)
        self.pck.add_data(params['link_by_default'], U_TP_I)
        self.pck.add_data(params['is_dynamic'], U_TP_I)
        if 'periodic_param' not in params: params['periodic_param'] = 0
        self.pck.add_data(params['periodic_param'], U_TP_I)
        self.pck.add_data(params['discount_method'], U_TP_I)
        self.pck.add_data(params['cost'], U_TP_D)
        self.pck.add_data(params['start_date'], U_TP_I)
        self.pck.add_data(params['expire_date'], U_TP_I)
        self.pck.add_data(params['pool_name'], U_TP_S)
        self.pck.add_data(params['max_timeout'], U_TP_I)
        self.pck.add_data(params['null_service_prepaid'], U_TP_I)
        self.pck.add_data(params['radius_sessions_limit'], U_TP_I)
        self.pck.add_data(params['login_prefix'], U_TP_S)
        if 'cost_size' not in params: params['cost_size'] = len(params['range_id'])
        self.pck.add_data(params['cost_size'], U_TP_I)
        for i in range(len(params['range_id'])):
            self.pck.add_data(params['range_cost'][i], U_TP_D)
            self.pck.add_data(params['range_id'][i], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_remove_service(self, params):
        """ description
        @params: 
        :(s)  sid :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x210e):
            raise Exception("Fail of urfa_call(0x210e) [rpcf_remove_service]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['sid'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_hotspot_services_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  services_size :	(i)  - 
        :(s)    service_id :	(i)  - 
        :(s)      service_name :	(s)  - 
        :(s)      service_type :	(i)  - 
        :(s)      commect :	(s)  - 
        """
        if not self.urfa_call(0x210f):
            raise Exception("Fail of urfa_call(0x210f) [rpcf_get_hotspot_services_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['services_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['services_size']): 
            self.pck.recv(self.sck)
            ret['service_id'][i] = self.pck.get_data(U_TP_I)
            if ret['service_id'][i]  !=  -1:
                ret['service_name'][i] = self.pck.get_data(U_TP_S)
                ret['service_type'][i] = self.pck.get_data(U_TP_I)
                ret['commect'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_fictive_services_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  services_size :	(i)  - 
        :(s)    service_id :	(i)  - 
        :(s)      service_name :	(s)  - 
        :(s)      service_type :	(i)  - 
        :(s)      commect :	(s)  - 
        """
        if not self.urfa_call(0x2110):
            raise Exception("Fail of urfa_call(0x2110) [rpcf_get_fictive_services_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['services_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['services_size']): 
            self.pck.recv(self.sck)
            ret['service_id'][i] = self.pck.get_data(U_TP_I)
            if ret['service_id'][i]  !=  -1:
                ret['service_name'][i] = self.pck.get_data(U_TP_S)
                ret['service_type'][i] = self.pck.get_data(U_TP_I)
                ret['commect'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_once_service_new(self, params):
        """ description
        @params: 
        :(s)  sid :	(i)  - 
        @returns: 
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  drop_from_group :	(i)  - 
        :(s)  is_parent_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        """
        if not self.urfa_call(0x2115):
            raise Exception("Fail of urfa_call(0x2115) [rpcf_get_once_service_new]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['sid'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['service_name'] = self.pck.get_data(U_TP_S)
        ret['comment'] = self.pck.get_data(U_TP_S)
        ret['link_by_default'] = self.pck.get_data(U_TP_I)
        ret['cost'] = self.pck.get_data(U_TP_D)
        ret['drop_from_group'] = self.pck.get_data(U_TP_I)
        ret['is_parent_id'] = self.pck.get_data(U_TP_I)
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        ret['parent_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_once_service_new(self, params):
        """ description
        @params: 
        :(s)  parent_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  service_id :	(i)  - 
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  drop_from_group :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x2116):
            raise Exception("Fail of urfa_call(0x2116) [rpcf_add_once_service_new]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['parent_id'], U_TP_I)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.add_data(params['service_name'], U_TP_S)
        self.pck.add_data(params['comment'], U_TP_S)
        self.pck.add_data(params['link_by_default'], U_TP_I)
        self.pck.add_data(params['cost'], U_TP_D)
        self.pck.add_data(params['drop_from_group'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_periodic_service_batch(self, params):
        """ description
        @params: 
        :(s)  fictive :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  service_id :	(i)  - 
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  parameter :	(i)  - 
        :(s)  discount_method_t :	(i)  - 
        :(s)  start_date :	(i)  - 
        :(s)  expire_date :	(i)  - 
        @returns: 
        :(s)  service_id :	(i)  - 
        """
        if not self.urfa_call(0x2120):
            raise Exception("Fail of urfa_call(0x2120) [rpcf_add_periodic_service_batch]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['fictive'], U_TP_I)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.add_data(params['service_name'], U_TP_S)
        self.pck.add_data(params['comment'], U_TP_S)
        self.pck.add_data(params['link_by_default'], U_TP_I)
        self.pck.add_data(params['cost'], U_TP_D)
        self.pck.add_data(params['parameter'], U_TP_I)
        self.pck.add_data(params['discount_method_t'], U_TP_I)
        self.pck.add_data(params['start_date'], U_TP_I)
        self.pck.add_data(params['expire_date'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['service_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_iptraffic_service(self, params):
        """ description
        @params: 
        :(s)  parent_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  service_id :	(i)  - 
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  is_dynamic :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  param1 :	(i)  - 
        :(s)  discount_method :	(i)  - 
        :(s)  start_date :	(i)  - 
        :(s)  expire_date :	(i)  - 
        :(s)  null_service_prepaid :	(i)  - 
        :(s)  borders_numbers :	(i) = _def_  - 
        :(s)    tclass_b :	(i)  - 
        :(s)    size_b :	(l)  - 
        :(s)    cost_b :	(d)  - 
        :(s)  prepaid_numbers :	(i) = _def_  - 
        :(s)    tclass_p :	(i)  - 
        :(s)    size_p :	(l)  - 
        :(s)    size_max_p :	(l)  - 
        :(s)  num_of_groups :	(i) = _def_  - 
        :(s)    tcid :	(i)  - 
        :(s)    gid :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x2107):
            raise Exception("Fail of urfa_call(0x2107) [rpcf_add_iptraffic_service]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['parent_id'], U_TP_I)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.add_data(params['service_name'], U_TP_S)
        self.pck.add_data(params['comment'], U_TP_S)
        self.pck.add_data(params['link_by_default'], U_TP_I)
        self.pck.add_data(params['is_dynamic'], U_TP_I)
        self.pck.add_data(params['cost'], U_TP_D)
        self.pck.add_data(params['param1'], U_TP_I)
        self.pck.add_data(params['discount_method'], U_TP_I)
        self.pck.add_data(params['start_date'], U_TP_I)
        self.pck.add_data(params['expire_date'], U_TP_I)
        self.pck.add_data(params['null_service_prepaid'], U_TP_I)
        if 'borders_numbers' not in params: params['borders_numbers'] = len(params['tclass_b'])
        self.pck.add_data(params['borders_numbers'], U_TP_I)
        for i in range(len(params['tclass_b'])):
            self.pck.add_data(params['tclass_b'][i], U_TP_I)
            self.pck.add_data(params['size_b'][i], U_TP_L)
            self.pck.add_data(params['cost_b'][i], U_TP_D)
        if 'prepaid_numbers' not in params: params['prepaid_numbers'] = len(params['tclass_p'])
        self.pck.add_data(params['prepaid_numbers'], U_TP_I)
        for i in range(len(params['tclass_p'])):
            self.pck.add_data(params['tclass_p'][i], U_TP_I)
            self.pck.add_data(params['size_p'][i], U_TP_L)
            self.pck.add_data(params['size_max_p'][i], U_TP_L)
        if 'num_of_groups' not in params: params['num_of_groups'] = len(params['tcid'])
        self.pck.add_data(params['num_of_groups'], U_TP_I)
        for i in range(len(params['tcid'])):
            self.pck.add_data(params['tcid'][i], U_TP_I)
            self.pck.add_data(params['gid'][i], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_iptraffic_service_link_ipv6(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  account_id :	(i)  - 
        :(s)  service_id :	(i)  - 
        :(s)  tplink_id :	(i)  - 
        :(s)  discount_period_id :	(i)  - 
        :(s)  start_date :	(i)  - 
        :(s)  expire_date :	(i)  - 
        :(s)  policy_id :	(i)  - 
        :(s)  unabon :	(i)  - 
        :(s)  cost_coef :	(d) = _def_  - 
        :(s)  unprepay :	(i)  - 
        :(s)  ip_groups_count :	(i)  - 
        :(s)    ip :	(i)  - 
        :(s)    mask :	(i)  - 
        :(s)    mac :	(s)  - 
        :(s)    login :	(s)  - 
        :(s)    allowed_cid :	(s)  - 
        :(s)    password :	(s)  - 
        :(s)    pool_name :	(s)  - 
        :(s)    is_skip_radius :	(i)  - 
        :(s)    is_skip_rfw :	(i)  - 
        :(s)    router_id :	(i)  - 
        :(s)    switch_id :	(i) = _def_  - 
        :(s)    port_id :	(i) = _def_  - 
        :(s)    vlan_id :	(i) = _def_  - 
        :(s)    pool_id :	(i) = _def_  - 
        :(s)  quotas_count :	(i)  - 
        :(s)    tc_id :	(i)  - 
        :(s)    quota :	(l)  - 
        @returns: 
        :(s)  slink_id :	(i)  - 
        """
        if not self.urfa_call(0x293a):
            raise Exception("Fail of urfa_call(0x293a) [rpcf_add_iptraffic_service_link_ipv6]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.add_data(params['tplink_id'], U_TP_I)
        self.pck.add_data(params['discount_period_id'], U_TP_I)
        self.pck.add_data(params['start_date'], U_TP_I)
        self.pck.add_data(params['expire_date'], U_TP_I)
        self.pck.add_data(params['policy_id'], U_TP_I)
        self.pck.add_data(params['unabon'], U_TP_I)
        if 'cost_coef' not in params: params['cost_coef'] = 1.0
        self.pck.add_data(params['cost_coef'], U_TP_D)
        self.pck.add_data(params['unprepay'], U_TP_I)
        self.pck.add_data(params['ip_groups_count'], U_TP_I)
        for i in range(params['ip_groups_count']):
            self.pck.add_data(params['ip'][i], U_TP_IP)
            self.pck.add_data(params['mask'][i], U_TP_I)
            self.pck.add_data(params['mac'][i], U_TP_S)
            self.pck.add_data(params['login'][i], U_TP_S)
            self.pck.add_data(params['allowed_cid'][i], U_TP_S)
            self.pck.add_data(params['password'][i], U_TP_S)
            self.pck.add_data(params['pool_name'][i], U_TP_S)
            self.pck.add_data(params['is_skip_radius'][i], U_TP_I)
            self.pck.add_data(params['is_skip_rfw'][i], U_TP_I)
            self.pck.add_data(params['router_id'][i], U_TP_I)
            if 'switch_id' not in params: params['switch_id'] = 0
            self.pck.add_data(params['switch_id'][i], U_TP_I)
            if 'port_id' not in params: params['port_id'] = 0
            self.pck.add_data(params['port_id'][i], U_TP_I)
            if 'vlan_id' not in params: params['vlan_id'] = 0
            self.pck.add_data(params['vlan_id'][i], U_TP_I)
            if 'pool_id' not in params: params['pool_id'] = 0
            self.pck.add_data(params['pool_id'][i], U_TP_I)
        self.pck.add_data(params['quotas_count'], U_TP_I)
        for i in range(params['quotas_count']):
            self.pck.add_data(params['tc_id'][i], U_TP_I)
            self.pck.add_data(params['quota'][i], U_TP_L)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['slink_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_iptraffic_service_batch(self, params):
        """ description
        @params: 
        :(s)  parent_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  service_id :	(i)  - 
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  is_dynamic :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  parameter :	(i)  - 
        :(s)  discount_method_t :	(i)  - 
        :(s)  start_date :	(i)  - 
        :(s)  expire_date :	(i)  - 
        :(s)  null_service_prepaid :	(i)  - 
        :(s)  num_of_borders :	(i) = _def_  - 
        :(s)    tclass_b :	(i)  - 
        :(s)    size_b :	(l)  - 
        :(s)    cost_b :	(d)  - 
        :(s)  num_of_prepaid :	(i) = _def_  - 
        :(s)    tclass_p :	(i)  - 
        :(s)    size_p :	(l)  - 
        :(s)    size_max_p :	(l)  - 
        :(s)  num_of_groups :	(i) = _def_  - 
        :(s)    tcid :	(i)  - 
        :(s)    gid :	(i)  - 
        @returns: 
        :(s)  service_id :	(i)  - 
        """
        if not self.urfa_call(0x2121):
            raise Exception("Fail of urfa_call(0x2121) [rpcf_add_iptraffic_service_batch]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['parent_id'], U_TP_I)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.add_data(params['service_name'], U_TP_S)
        self.pck.add_data(params['comment'], U_TP_S)
        self.pck.add_data(params['link_by_default'], U_TP_I)
        self.pck.add_data(params['is_dynamic'], U_TP_I)
        self.pck.add_data(params['cost'], U_TP_D)
        self.pck.add_data(params['parameter'], U_TP_I)
        self.pck.add_data(params['discount_method_t'], U_TP_I)
        self.pck.add_data(params['start_date'], U_TP_I)
        self.pck.add_data(params['expire_date'], U_TP_I)
        self.pck.add_data(params['null_service_prepaid'], U_TP_I)
        if 'num_of_borders' not in params: params['num_of_borders'] = len(params['tclass_b'])
        self.pck.add_data(params['num_of_borders'], U_TP_I)
        for i in range(len(params['tclass_b'])):
            self.pck.add_data(params['tclass_b'][i], U_TP_I)
            self.pck.add_data(params['size_b'][i], U_TP_L)
            self.pck.add_data(params['cost_b'][i], U_TP_D)
        if 'num_of_prepaid' not in params: params['num_of_prepaid'] = len(params['tclass_p'])
        self.pck.add_data(params['num_of_prepaid'], U_TP_I)
        for i in range(len(params['tclass_p'])):
            self.pck.add_data(params['tclass_p'][i], U_TP_I)
            self.pck.add_data(params['size_p'][i], U_TP_L)
            self.pck.add_data(params['size_max_p'][i], U_TP_L)
        if 'num_of_groups' not in params: params['num_of_groups'] = len(params['tcid'])
        self.pck.add_data(params['num_of_groups'], U_TP_I)
        for i in range(len(params['tcid'])):
            self.pck.add_data(params['tcid'][i], U_TP_I)
            self.pck.add_data(params['gid'][i], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['service_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_time_ranges(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  size_tr :	(i)  - 
        :(s)    range_id :	(i)  - 
        :(s)    tr_name :	(s)  - 
        :(s)    priority :	(i)  - 
        :(s)    size_trd :	(i)  - 
        :(s)      id :	(i)  - 
        :(s)      sec_start :	(i)  - 
        :(s)      sec_stop :	(i)  - 
        :(s)      min_start :	(i)  - 
        :(s)      min_stop :	(i)  - 
        :(s)      hour_start :	(i)  - 
        :(s)      hour_stop :	(i)  - 
        :(s)      wday_start :	(i)  - 
        :(s)      wday_stop :	(i)  - 
        :(s)    days_size :	(i)  - 
        :(s)      internal_id :	(i)  - 
        :(s)      mday :	(i)  - 
        :(s)      month :	(i)  - 
        """
        if not self.urfa_call(0x10350):
            raise Exception("Fail of urfa_call(0x10350) [rpcf_get_time_ranges]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['size_tr'] = self.pck.get_data(U_TP_I)
        for i in range(ret['size_tr']): 
            self.pck.recv(self.sck)
            ret['range_id'][i] = self.pck.get_data(U_TP_I)
            ret['tr_name'][i] = self.pck.get_data(U_TP_S)
            ret['priority'][i] = self.pck.get_data(U_TP_I)
            ret['size_trd'] = self.pck.get_data(U_TP_I)
            ret['size_trd_array'][i]=ret['size_trd']
            for j in range(ret['size_trd']): 
                self.pck.recv(self.sck)
                if not i in ret['id']:ret['id'][i] = dict()
                ret['id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['sec_start']:ret['sec_start'][i] = dict()
                ret['sec_start'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['sec_stop']:ret['sec_stop'][i] = dict()
                ret['sec_stop'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['min_start']:ret['min_start'][i] = dict()
                ret['min_start'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['min_stop']:ret['min_stop'][i] = dict()
                ret['min_stop'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['hour_start']:ret['hour_start'][i] = dict()
                ret['hour_start'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['hour_stop']:ret['hour_stop'][i] = dict()
                ret['hour_stop'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['wday_start']:ret['wday_start'][i] = dict()
                ret['wday_start'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['wday_stop']:ret['wday_stop'][i] = dict()
                ret['wday_stop'][i][j] = self.pck.get_data(U_TP_I)
            self.pck.recv(self.sck)
            ret['days_size'] = self.pck.get_data(U_TP_I)
            ret['days_size_array'][i]=ret['days_size']
            for j in range(ret['days_size']): 
                self.pck.recv(self.sck)
                if not i in ret['internal_id']:ret['internal_id'][i] = dict()
                ret['internal_id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['mday']:ret['mday'][i] = dict()
                ret['mday'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['month']:ret['month'][i] = dict()
                ret['month'][i][j] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_time_range(self, params):
        """ description
        @params: 
        :(s)  tr_name :	(s)  - 
        :(s)  priority :	(i)  - 
        :(s)  size_trd :	(i) = _def_  - 
        :(s)    sec_start :	(i)  - 
        :(s)    sec_stop :	(i)  - 
        :(s)    min_start :	(i)  - 
        :(s)    min_stop :	(i)  - 
        :(s)    hour_start :	(i)  - 
        :(s)    hour_stop :	(i)  - 
        :(s)    wday_start :	(i)  - 
        :(s)    wday_stop :	(i)  - 
        :(s)  days_size :	(i) = _def_  - 
        :(s)    internal_id :	(i)  - 
        :(s)    mday :	(i)  - 
        :(s)    month :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x10351):
            raise Exception("Fail of urfa_call(0x10351) [rpcf_add_time_range]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['tr_name'], U_TP_S)
        self.pck.add_data(params['priority'], U_TP_I)
        if 'size_trd' not in params: params['size_trd'] = len(params['sec_start'])
        self.pck.add_data(params['size_trd'], U_TP_I)
        for i in range(len(params['sec_start'])):
            self.pck.add_data(params['sec_start'][i], U_TP_I)
            self.pck.add_data(params['sec_stop'][i], U_TP_I)
            self.pck.add_data(params['min_start'][i], U_TP_I)
            self.pck.add_data(params['min_stop'][i], U_TP_I)
            self.pck.add_data(params['hour_start'][i], U_TP_I)
            self.pck.add_data(params['hour_stop'][i], U_TP_I)
            self.pck.add_data(params['wday_start'][i], U_TP_I)
            self.pck.add_data(params['wday_stop'][i], U_TP_I)
        if 'days_size' not in params: params['days_size'] = len(params['internal_id'])
        self.pck.add_data(params['days_size'], U_TP_I)
        for i in range(len(params['internal_id'])):
            self.pck.add_data(params['internal_id'][i], U_TP_I)
            self.pck.add_data(params['mday'][i], U_TP_I)
            self.pck.add_data(params['month'][i], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_save_time_range(self, params):
        """ description
        @params: 
        :(s)  tr_id :	(i)  - 
        :(s)  tr_name :	(s)  - 
        :(s)  priority :	(i)  - 
        :(s)  size_trd :	(i) = _def_  - 
        :(s)    tr_entry_id :	(i)  - 
        :(s)    sec_start :	(i)  - 
        :(s)    sec_stop :	(i)  - 
        :(s)    min_start :	(i)  - 
        :(s)    min_stop :	(i)  - 
        :(s)    hour_start :	(i)  - 
        :(s)    hour_stop :	(i)  - 
        :(s)    wday_start :	(i)  - 
        :(s)    wday_stop :	(i)  - 
        :(s)  days_size :	(i) = _def_  - 
        :(s)    internal_id :	(i)  - 
        :(s)    mday :	(i)  - 
        :(s)    month :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x10352):
            raise Exception("Fail of urfa_call(0x10352) [rpcf_save_time_range]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['tr_id'], U_TP_I)
        self.pck.add_data(params['tr_name'], U_TP_S)
        self.pck.add_data(params['priority'], U_TP_I)
        if 'size_trd' not in params: params['size_trd'] = len(params['sec_start'])
        self.pck.add_data(params['size_trd'], U_TP_I)
        for i in range(len(params['sec_start'])):
            self.pck.add_data(params['tr_entry_id'][i], U_TP_I)
            self.pck.add_data(params['sec_start'][i], U_TP_I)
            self.pck.add_data(params['sec_stop'][i], U_TP_I)
            self.pck.add_data(params['min_start'][i], U_TP_I)
            self.pck.add_data(params['min_stop'][i], U_TP_I)
            self.pck.add_data(params['hour_start'][i], U_TP_I)
            self.pck.add_data(params['hour_stop'][i], U_TP_I)
            self.pck.add_data(params['wday_start'][i], U_TP_I)
            self.pck.add_data(params['wday_stop'][i], U_TP_I)
        if 'days_size' not in params: params['days_size'] = len(params['internal_id'])
        self.pck.add_data(params['days_size'], U_TP_I)
        for i in range(len(params['internal_id'])):
            self.pck.add_data(params['internal_id'][i], U_TP_I)
            self.pck.add_data(params['mday'][i], U_TP_I)
            self.pck.add_data(params['month'][i], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_del_time_range(self, params):
        """ description
        @params: 
        :(s)  time_range_id :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x10353):
            raise Exception("Fail of urfa_call(0x10353) [rpcf_del_time_range]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['time_range_id'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_tclasses(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  tclass_list_size :	(i)  - 
        :(s)    tclass_id :	(i)  - 
        :(s)    tclass_name :	(s)  - 
        :(s)    graph_color :	(i)  - 
        :(s)    is_display :	(i)  - 
        :(s)    is_fill :	(i)  - 
        """
        if not self.urfa_call(0x2300):
            raise Exception("Fail of urfa_call(0x2300) [rpcf_get_tclasses]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['tclass_list_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['tclass_list_size']): 
            self.pck.recv(self.sck)
            ret['tclass_id'][i] = self.pck.get_data(U_TP_I)
            ret['tclass_name'][i] = self.pck.get_data(U_TP_S)
            ret['graph_color'][i] = self.pck.get_data(U_TP_I)
            ret['is_display'][i] = self.pck.get_data(U_TP_I)
            ret['is_fill'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_tclass2(self, params):
        """ description
        @params: 
        :(s)  tclass_id :	(i)  - 
        :(s)  tclass_name :	(s)  - 
        :(s)  graph_color :	(i)  - 
        :(s)  is_display :	(i)  - 
        :(s)  is_fill :	(i)  - 
        :(s)  time_range_id :	(i)  - 
        :(s)  dont_save :	(i)  - 
        :(s)  local_traf_policy :	(i)  - 
        :(s)  tclass_count :	(i)  - 
        :(s)    saddr :	(i)  - 
        :(s)    saddr_mask :	(i)  - 
        :(s)    sport :	(i)  - 
        :(s)    input :	(i)  - 
        :(s)    src_as :	(i)  - 
        :(s)    daddr :	(i)  - 
        :(s)    daddr_mask :	(i)  - 
        :(s)    dport :	(i)  - 
        :(s)    output :	(i)  - 
        :(s)    dst_as :	(i)  - 
        :(s)    proto :	(i)  - 
        :(s)    tos :	(i)  - 
        :(s)    nexthop :	(i)  - 
        :(s)    tcp_flags :	(i)  - 
        :(s)    ip_from :	(i)  - 
        :(s)    use_sport :	(i)  - 
        :(s)    use_input :	(i)  - 
        :(s)    use_src_as :	(i)  - 
        :(s)    use_dport :	(i)  - 
        :(s)    use_output :	(i)  - 
        :(s)    use_dst_as :	(i)  - 
        :(s)    use_proto :	(i)  - 
        :(s)    use_tos :	(i)  - 
        :(s)    use_nexthop :	(i)  - 
        :(s)    use_tcp_flags :	(i)  - 
        :(s)    skip :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x2305):
            raise Exception("Fail of urfa_call(0x2305) [rpcf_add_tclass2]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['tclass_id'], U_TP_I)
        self.pck.add_data(params['tclass_name'], U_TP_S)
        self.pck.add_data(params['graph_color'], U_TP_I)
        self.pck.add_data(params['is_display'], U_TP_I)
        self.pck.add_data(params['is_fill'], U_TP_I)
        self.pck.add_data(params['time_range_id'], U_TP_I)
        self.pck.add_data(params['dont_save'], U_TP_I)
        self.pck.add_data(params['local_traf_policy'], U_TP_I)
        self.pck.add_data(params['tclass_count'], U_TP_I)
        for i in range(params['tclass_count']):
            self.pck.add_data(params['saddr'][i], U_TP_IP)
            self.pck.add_data(params['saddr_mask'][i], U_TP_I)
            self.pck.add_data(params['sport'][i], U_TP_I)
            self.pck.add_data(params['input'][i], U_TP_I)
            self.pck.add_data(params['src_as'][i], U_TP_I)
            self.pck.add_data(params['daddr'][i], U_TP_IP)
            self.pck.add_data(params['daddr_mask'][i], U_TP_I)
            self.pck.add_data(params['dport'][i], U_TP_I)
            self.pck.add_data(params['output'][i], U_TP_I)
            self.pck.add_data(params['dst_as'][i], U_TP_I)
            self.pck.add_data(params['proto'][i], U_TP_I)
            self.pck.add_data(params['tos'][i], U_TP_I)
            self.pck.add_data(params['nexthop'][i], U_TP_IP)
            self.pck.add_data(params['tcp_flags'][i], U_TP_I)
            self.pck.add_data(params['ip_from'][i], U_TP_IP)
            self.pck.add_data(params['use_sport'][i], U_TP_I)
            self.pck.add_data(params['use_input'][i], U_TP_I)
            self.pck.add_data(params['use_src_as'][i], U_TP_I)
            self.pck.add_data(params['use_dport'][i], U_TP_I)
            self.pck.add_data(params['use_output'][i], U_TP_I)
            self.pck.add_data(params['use_dst_as'][i], U_TP_I)
            self.pck.add_data(params['use_proto'][i], U_TP_I)
            self.pck.add_data(params['use_tos'][i], U_TP_I)
            self.pck.add_data(params['use_nexthop'][i], U_TP_I)
            self.pck.add_data(params['use_tcp_flags'][i], U_TP_I)
            self.pck.add_data(params['skip'][i], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_tclass(self, params):
        """ description
        @params: 
        :(s)  tclass_id :	(i)  - 
        @returns: 
        :(s)  tclass_name :	(s)  - 
        :(s)  graph_color :	(i)  - 
        :(s)  is_display :	(i)  - 
        :(s)  is_fill :	(i)  - 
        :(s)  time_range_id :	(i)  - 
        :(s)  dont_save :	(i)  - 
        :(s)  local_traf_policy :	(i)  - 
        :(s)  tclass_count :	(i)  - 
        :(s)    saddr :	(i)  - 
        :(s)    saddr_mask :	(i)  - 
        :(s)    sport :	(i)  - 
        :(s)    input :	(i)  - 
        :(s)    src_as :	(i)  - 
        :(s)    daddr :	(i)  - 
        :(s)    daddr_mask :	(i)  - 
        :(s)    dport :	(i)  - 
        :(s)    output :	(i)  - 
        :(s)    dst_as :	(i)  - 
        :(s)    proto :	(i)  - 
        :(s)    tos :	(i)  - 
        :(s)    nexthop :	(i)  - 
        :(s)    tcp_flags :	(i)  - 
        :(s)    ip_from :	(i)  - 
        :(s)    use_sport :	(i)  - 
        :(s)    use_input :	(i)  - 
        :(s)    use_src_as :	(i)  - 
        :(s)    use_dport :	(i)  - 
        :(s)    use_output :	(i)  - 
        :(s)    use_dst_as :	(i)  - 
        :(s)    use_proto :	(i)  - 
        :(s)    use_tos :	(i)  - 
        :(s)    use_nexthop :	(i)  - 
        :(s)    use_tcp_flags :	(i)  - 
        :(s)    skip :	(i)  - 
        """
        if not self.urfa_call(0x2306):
            raise Exception("Fail of urfa_call(0x2306) [rpcf_get_tclass]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['tclass_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['tclass_name'] = self.pck.get_data(U_TP_S)
        ret['graph_color'] = self.pck.get_data(U_TP_I)
        ret['is_display'] = self.pck.get_data(U_TP_I)
        ret['is_fill'] = self.pck.get_data(U_TP_I)
        ret['time_range_id'] = self.pck.get_data(U_TP_I)
        ret['dont_save'] = self.pck.get_data(U_TP_I)
        ret['local_traf_policy'] = self.pck.get_data(U_TP_I)
        ret['tclass_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['tclass_count']): 
            self.pck.recv(self.sck)
            ret['saddr'][i] = self.pck.get_data(U_TP_IP)
            ret['saddr_mask'][i] = self.pck.get_data(U_TP_I)
            ret['sport'][i] = self.pck.get_data(U_TP_I)
            ret['input'][i] = self.pck.get_data(U_TP_I)
            ret['src_as'][i] = self.pck.get_data(U_TP_I)
            ret['daddr'][i] = self.pck.get_data(U_TP_IP)
            ret['daddr_mask'][i] = self.pck.get_data(U_TP_I)
            ret['dport'][i] = self.pck.get_data(U_TP_I)
            ret['output'][i] = self.pck.get_data(U_TP_I)
            ret['dst_as'][i] = self.pck.get_data(U_TP_I)
            ret['proto'][i] = self.pck.get_data(U_TP_I)
            ret['tos'][i] = self.pck.get_data(U_TP_I)
            ret['nexthop'][i] = self.pck.get_data(U_TP_IP)
            ret['tcp_flags'][i] = self.pck.get_data(U_TP_I)
            ret['ip_from'][i] = self.pck.get_data(U_TP_IP)
            ret['use_sport'][i] = self.pck.get_data(U_TP_I)
            ret['use_input'][i] = self.pck.get_data(U_TP_I)
            ret['use_src_as'][i] = self.pck.get_data(U_TP_I)
            ret['use_dport'][i] = self.pck.get_data(U_TP_I)
            ret['use_output'][i] = self.pck.get_data(U_TP_I)
            ret['use_dst_as'][i] = self.pck.get_data(U_TP_I)
            ret['use_proto'][i] = self.pck.get_data(U_TP_I)
            ret['use_tos'][i] = self.pck.get_data(U_TP_I)
            ret['use_nexthop'][i] = self.pck.get_data(U_TP_I)
            ret['use_tcp_flags'][i] = self.pck.get_data(U_TP_I)
            ret['skip'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_tclass(self, params):
        """ description
        @params: 
        :(s)  tclass_id :	(i)  - 
        :(s)  tclass_name :	(s)  - 
        :(s)  graph_color :	(i)  - 
        :(s)  is_display :	(i)  - 
        :(s)  is_fill :	(i)  - 
        :(s)  time_range_id :	(i)  - 
        :(s)  dont_save :	(i)  - 
        :(s)  local_traf_policy :	(i)  - 
        :(s)  tclass_count :	(i)  - 
        :(s)    saddr :	(i)  - 
        :(s)    saddr_mask :	(i)  - 
        :(s)    sport :	(i)  - 
        :(s)    input :	(i)  - 
        :(s)    src_as :	(i)  - 
        :(s)    daddr :	(i)  - 
        :(s)    daddr_mask :	(i)  - 
        :(s)    dport :	(i)  - 
        :(s)    output :	(i)  - 
        :(s)    dst_as :	(i)  - 
        :(s)    proto :	(i)  - 
        :(s)    tos :	(i)  - 
        :(s)    nexthop :	(i)  - 
        :(s)    tcp_flags :	(i)  - 
        :(s)    ip_from :	(i)  - 
        :(s)    use_sport :	(i)  - 
        :(s)    use_input :	(i)  - 
        :(s)    use_src_as :	(i)  - 
        :(s)    use_dport :	(i)  - 
        :(s)    use_output :	(i)  - 
        :(s)    use_dst_as :	(i)  - 
        :(s)    use_proto :	(i)  - 
        :(s)    use_tos :	(i)  - 
        :(s)    use_nexthop :	(i)  - 
        :(s)    use_tcp_flags :	(i)  - 
        :(s)    skip :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x2307):
            raise Exception("Fail of urfa_call(0x2307) [rpcf_edit_tclass]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['tclass_id'], U_TP_I)
        self.pck.add_data(params['tclass_name'], U_TP_S)
        self.pck.add_data(params['graph_color'], U_TP_I)
        self.pck.add_data(params['is_display'], U_TP_I)
        self.pck.add_data(params['is_fill'], U_TP_I)
        self.pck.add_data(params['time_range_id'], U_TP_I)
        self.pck.add_data(params['dont_save'], U_TP_I)
        self.pck.add_data(params['local_traf_policy'], U_TP_I)
        self.pck.add_data(params['tclass_count'], U_TP_I)
        for x in range(params['tclass_count']):
            self.pck.add_data(params['saddr'][i], U_TP_IP)
            self.pck.add_data(params['saddr_mask'][i], U_TP_I)
            self.pck.add_data(params['sport'][i], U_TP_I)
            self.pck.add_data(params['input'][i], U_TP_I)
            self.pck.add_data(params['src_as'][i], U_TP_I)
            self.pck.add_data(params['daddr'][i], U_TP_IP)
            self.pck.add_data(params['daddr_mask'][i], U_TP_I)
            self.pck.add_data(params['dport'][i], U_TP_I)
            self.pck.add_data(params['output'][i], U_TP_I)
            self.pck.add_data(params['dst_as'][i], U_TP_I)
            self.pck.add_data(params['proto'][i], U_TP_I)
            self.pck.add_data(params['tos'][i], U_TP_I)
            self.pck.add_data(params['nexthop'][i], U_TP_IP)
            self.pck.add_data(params['tcp_flags'][i], U_TP_I)
            self.pck.add_data(params['ip_from'][i], U_TP_IP)
            self.pck.add_data(params['use_sport'][i], U_TP_I)
            self.pck.add_data(params['use_input'][i], U_TP_I)
            self.pck.add_data(params['use_src_as'][i], U_TP_I)
            self.pck.add_data(params['use_dport'][i], U_TP_I)
            self.pck.add_data(params['use_output'][i], U_TP_I)
            self.pck.add_data(params['use_dst_as'][i], U_TP_I)
            self.pck.add_data(params['use_proto'][i], U_TP_I)
            self.pck.add_data(params['use_tos'][i], U_TP_I)
            self.pck.add_data(params['use_nexthop'][i], U_TP_I)
            self.pck.add_data(params['use_tcp_flags'][i], U_TP_I)
            self.pck.add_data(params['skip'][i], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_remove_tclass(self, params):
        """ description
        @params: 
        :(s)  tclass_id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x2304):
            raise Exception("Fail of urfa_call(0x2304) [rpcf_remove_tclass]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['tclass_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_groups_list(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        @returns: 
        :(s)  groups_count :	(i)  - 
        :(s)    group_id :	(i)  - 
        :(s)    group_name :	(s)  - 
        """
        if not self.urfa_call(0x2400):
            raise Exception("Fail of urfa_call(0x2400) [rpcf_get_groups_list]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['groups_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['groups_count']): 
            self.pck.recv(self.sck)
            ret['group_id'][i] = self.pck.get_data(U_TP_I)
            ret['group_name'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_group(self, params):
        """ description
        @params: 
        :(s)  group_id :	(i)  - 
        :(s)  group_name :	(s)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x2401):
            raise Exception("Fail of urfa_call(0x2401) [rpcf_add_group]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['group_id'], U_TP_I)
        self.pck.add_data(params['group_name'], U_TP_S)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_group(self, params):
        """ description
        @params: 
        :(s)  group_id :	(i)  - 
        :(s)  group_name :	(s)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x2402):
            raise Exception("Fail of urfa_call(0x2402) [rpcf_edit_group]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['group_id'], U_TP_I)
        self.pck.add_data(params['group_name'], U_TP_S)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_sysgroups_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  groups_size :	(i)  - 
        :(s)    group_id :	(i)  - 
        :(s)    group_name :	(s)  - 
        :(s)    group_info :	(s)  - 
        """
        if not self.urfa_call(0x2403):
            raise Exception("Fail of urfa_call(0x2403) [rpcf_get_sysgroups_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['groups_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['groups_size']): 
            self.pck.recv(self.sck)
            ret['group_id'][i] = self.pck.get_data(U_TP_I)
            ret['group_name'][i] = self.pck.get_data(U_TP_S)
            ret['group_info'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_sysgroup(self, params):
        """ description
        @params: 
        :(s)  group_id :	(i)  - 
        :(s)  group_name :	(s)  - 
        :(s)  group_info :	(s)  - 
        :(s)  num_of_fids :	(i)  - 
        :(s)    fid :	(i)  - 
        :(s)    allowed :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x2404):
            raise Exception("Fail of urfa_call(0x2404) [rpcf_add_sysgroup]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['group_id'], U_TP_I)
        self.pck.add_data(params['group_name'], U_TP_S)
        self.pck.add_data(params['group_info'], U_TP_S)
        self.pck.add_data(params['num_of_fids'], U_TP_I)
        for i in range(params['num_of_fids']):
            self.pck.add_data(params['fid'][i], U_TP_I)
            self.pck.add_data(params['allowed'][i], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_sysgroup(self, params):
        """ description
        @params: 
        :(s)  group_id :	(i)  - 
        :(s)  group_name :	(s)  - 
        :(s)  group_info :	(s)  - 
        :(s)  num_of_fids :	(i) = _def_  - 
        :(s)    fid :	(i)  - 
        :(s)    allowed :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x2405):
            raise Exception("Fail of urfa_call(0x2405) [rpcf_edit_sysgroup]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['group_id'], U_TP_I)
        self.pck.add_data(params['group_name'], U_TP_S)
        self.pck.add_data(params['group_info'], U_TP_S)
        if 'num_of_fids' not in params: params['num_of_fids'] = len(params['fid'])
        self.pck.add_data(params['num_of_fids'], U_TP_I)
        for i in range(len(params['fid'])):
            self.pck.add_data(params['fid'][i], U_TP_I)
            self.pck.add_data(params['allowed'][i], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_sysgroup(self, params):
        """ description
        @params: 
        :(s)  group_id :	(i)  - 
        @returns: 
        :(s)  group_name :	(s)  - 
        :(s)  group_info :	(s)  - 
        :(s)  info_size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    name :	(s)  - 
        :(s)    module :	(s)  - 
        :(s)    fids :	(i)  - 
        """
        if not self.urfa_call(0x2406):
            raise Exception("Fail of urfa_call(0x2406) [rpcf_get_sysgroup]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['group_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['group_name'] = self.pck.get_data(U_TP_S)
        ret['group_info'] = self.pck.get_data(U_TP_S)
        ret['info_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['info_size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['name'][i] = self.pck.get_data(U_TP_S)
            ret['module'][i] = self.pck.get_data(U_TP_S)
            ret['fids'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_users_to_group(self, params):
        """ description
        @params: 
        :(s)  group_id :	(i)  - 
        :(s)  count :	(i) = _def_  - 
        :(s)    user_id :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x2407):
            raise Exception("Fail of urfa_call(0x2407) [rpcf_add_users_to_group]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['group_id'], U_TP_I)
        if 'count' not in params: params['count'] = len(params['user_id'])
        self.pck.add_data(params['count'], U_TP_I)
        for i in range(len(params['user_id'])):
            self.pck.add_data(params['user_id'][i], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_remove_user_from_group(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  group_id :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x2408):
            raise Exception("Fail of urfa_call(0x2408) [rpcf_remove_user_from_group]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['group_id'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_group_info(self, params):
        """ description
        @params: 
        :(s)  group_id :	(i)  - 
        @returns: 
        :(s)  group_name :	(s)  - 
        :(s)  user_id_size :	(i)  - 
        :(s)    user_id :	(i)  - 
        :(s)    login :	(s)  - 
        """
        if not self.urfa_call(0x2409):
            raise Exception("Fail of urfa_call(0x2409) [rpcf_get_group_info]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['group_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['group_name'] = self.pck.get_data(U_TP_S)
        ret['user_id_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['user_id_size']): 
            self.pck.recv(self.sck)
            ret['user_id'][i] = self.pck.get_data(U_TP_I)
            ret['login'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_group_op(self, params):
        """ description
        @params: 
        :(s)  group_id :	(i)  - 
        :(s)  group_op :	(i)  - 
        :(s)    tpid_from :	(i)  - 
        :(s)    tpid_to :	(i)  - 
        :(s)    old_policy :	(i)  - 
        :(s)    new_policy :	(i)  - 
        @returns: 
        :(s)  error_code :	(i)  - 
        :(s)  error_msg :	(s)  - 
        """
        if not self.urfa_call(0x240a):
            raise Exception("Fail of urfa_call(0x240a) [rpcf_group_op]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['group_id'], U_TP_I)
        self.pck.add_data(params['group_op'], U_TP_I)
        if params['group_op']  ==  4:
            self.pck.add_data(params['tpid_from'], U_TP_I)
            self.pck.add_data(params['tpid_to'], U_TP_I)
        if params['group_op']  ==  5:
            self.pck.add_data(params['old_policy'], U_TP_I)
            self.pck.add_data(params['new_policy'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['error_code'] = self.pck.get_data(U_TP_I)
        ret['error_msg'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_del_group(self, params):
        """ description
        @params: 
        :(s)  group_id :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x240b):
            raise Exception("Fail of urfa_call(0x240b) [rpcf_del_group]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['group_id'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_group_id_by_name(self, params):
        """ description
        @params: 
        :(s)  group_name :	(s)  - 
        @returns: 
        :(s)  group_id :	(i)  - 
        """
        if not self.urfa_call(0x240c):
            raise Exception("Fail of urfa_call(0x240c) [rpcf_get_group_id_by_name]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['group_name'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['group_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_groups_for_user(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        @returns: 
        :(s)  groups_size :	(i)  - 
        :(s)    group_id :	(i)  - 
        :(s)    group_name :	(s)  - 
        """
        if not self.urfa_call(0x2550):
            raise Exception("Fail of urfa_call(0x2550) [rpcf_get_groups_for_user]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['groups_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['groups_size']): 
            self.pck.recv(self.sck)
            ret['group_id'][i] = self.pck.get_data(U_TP_I)
            ret['group_name'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_group_to_user(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  group_id :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x2552):
            raise Exception("Fail of urfa_call(0x2552) [rpcf_add_group_to_user]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['group_id'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_once_service_link_new(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i)  - 
        @returns: 
        :(s)  discount_date :	(i)  - 
        :(s)  quantity :	(d)  - 
        :(s)  invoice_id :	(i)  - 
        :(s)  cost_coef :	(d) = _def_  - 
        """
        if not self.urfa_call(0x2556):
            raise Exception("Fail of urfa_call(0x2556) [rpcf_get_once_service_link_new]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['discount_date'] = self.pck.get_data(U_TP_I)
        ret['quantity'] = self.pck.get_data(U_TP_D)
        ret['invoice_id'] = self.pck.get_data(U_TP_I)
        if 'cost_coef' not in params: params['cost_coef'] = 1.0
        ret['cost_coef'] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_discount_periods(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  discount_periods_count :	(i)  - 
        :(s)    static_id :	(i)  - 
        :(s)    discount_period_id :	(i)  - 
        :(s)    start_date :	(i)  - 
        :(s)    end_date :	(i)  - 
        :(s)    periodic_type :	(i)  - 
        :(s)    custom_duration :	(i)  - 
        :(s)    next_discount_period_id :	(i)  - 
        :(s)    canonical_length :	(i)  - 
        """
        if not self.urfa_call(0x2600):
            raise Exception("Fail of urfa_call(0x2600) [rpcf_get_discount_periods]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['discount_periods_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['discount_periods_count']): 
            self.pck.recv(self.sck)
            ret['static_id'][i] = self.pck.get_data(U_TP_I)
            ret['discount_period_id'][i] = self.pck.get_data(U_TP_I)
            ret['start_date'][i] = self.pck.get_data(U_TP_I)
            ret['end_date'][i] = self.pck.get_data(U_TP_I)
            ret['periodic_type'][i] = self.pck.get_data(U_TP_I)
            ret['custom_duration'][i] = self.pck.get_data(U_TP_I)
            ret['next_discount_period_id'][i] = self.pck.get_data(U_TP_I)
            ret['canonical_length'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_all_discount_periods(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  discount_periods_count :	(i)  - 
        :(s)    static_id :	(i)  - 
        :(s)    discount_period_id :	(i)  - 
        :(s)    start_date :	(i)  - 
        :(s)    end_date :	(i)  - 
        :(s)    periodic_type :	(i)  - 
        :(s)    custom_duration :	(i)  - 
        :(s)    next_discount_period_id :	(i)  - 
        :(s)    canonical_length :	(i)  - 
        """
        if not self.urfa_call(0x2607):
            raise Exception("Fail of urfa_call(0x2607) [rpcf_get_all_discount_periods]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['discount_periods_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['discount_periods_count']): 
            self.pck.recv(self.sck)
            ret['static_id'][i] = self.pck.get_data(U_TP_I)
            ret['discount_period_id'][i] = self.pck.get_data(U_TP_I)
            ret['start_date'][i] = self.pck.get_data(U_TP_I)
            ret['end_date'][i] = self.pck.get_data(U_TP_I)
            ret['periodic_type'][i] = self.pck.get_data(U_TP_I)
            ret['custom_duration'][i] = self.pck.get_data(U_TP_I)
            ret['next_discount_period_id'][i] = self.pck.get_data(U_TP_I)
            ret['canonical_length'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_first_discount_period_id(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  id :	(i)  - 
        """
        if not self.urfa_call(0x2601):
            raise Exception("Fail of urfa_call(0x2601) [rpcf_get_first_discount_period_id]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_discount_period(self, params):
        """ description
        @params: 
        :(s)  discount_period_id :	(i)  - 
        @returns: 
        :(s)  start_date :	(i)  - 
        :(s)  end_date :	(i)  - 
        :(s)  periodic_type :	(i)  - 
        :(s)  custom_duration :	(i)  - 
        :(s)  discounts_per_week :	(i)  - 
        :(s)  next_discount_period_id :	(i)  - 
        :(s)  invoice_month :	(i)  - 
        """
        if not self.urfa_call(0x2609):
            raise Exception("Fail of urfa_call(0x2609) [rpcf_get_discount_period]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['discount_period_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['start_date'] = self.pck.get_data(U_TP_I)
        ret['end_date'] = self.pck.get_data(U_TP_I)
        ret['periodic_type'] = self.pck.get_data(U_TP_I)
        ret['custom_duration'] = self.pck.get_data(U_TP_I)
        ret['discounts_per_week'] = self.pck.get_data(U_TP_I)
        ret['next_discount_period_id'] = self.pck.get_data(U_TP_I)
        ret['invoice_month'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_discount_period(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        :(s)  start :	(i)  - 
        :(s)  expire :	(i)  - 
        :(s)  periodic_type_t :	(i)  - 
        :(s)  cd :	(i)  - 
        :(s)  di :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x2603):
            raise Exception("Fail of urfa_call(0x2603) [rpcf_add_discount_period]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['start'], U_TP_I)
        self.pck.add_data(params['expire'], U_TP_I)
        self.pck.add_data(params['periodic_type_t'], U_TP_I)
        self.pck.add_data(params['cd'], U_TP_I)
        self.pck.add_data(params['di'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_discount_period_return(self, params):
        """ description
        @params: 
        :(s)  static_id :	(i) = _def_  - 
        :(s)  start_date :	(i)  - 
        :(s)  expire_date :	(i) = _def_  - 
        :(s)  periodic_type :	(i) = _def_  - 
        :(s)  custom_duration :	(i) = _def_  - 
        :(s)  discount_interval :	(i) = _def_  - 
        :(s)  invoice_month :	(i) = _def_  - 
        @returns: 
        :(s)  discount_period_id :	(i)  - 
        """
        if not self.urfa_call(0x2608):
            raise Exception("Fail of urfa_call(0x2608) [rpcf_add_discount_period_return]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'static_id' not in params: params['static_id'] = 0
        self.pck.add_data(params['static_id'], U_TP_I)
        self.pck.add_data(params['start_date'], U_TP_I)
        if 'expire_date' not in params: params['expire_date'] = 0
        self.pck.add_data(params['expire_date'], U_TP_I)
        if 'periodic_type' not in params: params['periodic_type'] = 3
        self.pck.add_data(params['periodic_type'], U_TP_I)
        if 'custom_duration' not in params: params['custom_duration'] = 86400
        self.pck.add_data(params['custom_duration'], U_TP_I)
        if 'discount_interval' not in params: params['discount_interval'] = 7
        self.pck.add_data(params['discount_interval'], U_TP_I)
        if 'invoice_month' not in params: params['invoice_month'] = 0
        self.pck.add_data(params['invoice_month'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['discount_period_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_expire_discount_period(self, params):
        """ description
        @params: 
        :(s)  dpid :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x2606):
            raise Exception("Fail of urfa_call(0x2606) [rpcf_expire_discount_period]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['dpid'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_all_services_for_user(self, params):
        """ description
        @params: 
        :(s)  account_id :	(i)  - 
        @returns: 
        :(s)  slink_id_count :	(i)  - 
        :(s)    service_id :	(i)  - 
        :(s)      service_type_array :	(i)  - 
        :(s)      service_name_array :	(s)  - 
        :(s)      tariff_name_array :	(s)  - 
        :(s)      service_cost_array :	(d)  - 
        :(s)      slink_id_array :	(i)  - 
        :(s)      discount_period_id_array :	(i)  - 
        """
        if not self.urfa_call(0x2700):
            raise Exception("Fail of urfa_call(0x2700) [rpcf_get_all_services_for_user]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['slink_id_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['slink_id_count']): 
            self.pck.recv(self.sck)
            ret['service_id'] = self.pck.get_data(U_TP_I)
            if ret['service_id']  !=  -1:
                ret['service_id_array'][i]=ret['service_id']
                ret['service_type_array'][i] = self.pck.get_data(U_TP_I)
                ret['service_name_array'][i] = self.pck.get_data(U_TP_S)
                ret['tariff_name_array'][i] = self.pck.get_data(U_TP_S)
                ret['service_cost_array'][i] = self.pck.get_data(U_TP_D)
                ret['slink_id_array'][i] = self.pck.get_data(U_TP_I)
                ret['discount_period_id_array'][i] = self.pck.get_data(U_TP_I)
            if ret['service_id']  ==  -1:
                ret['service_id_array'][i]="-1"
                ret['service_type_array'][i]="-1"
                ret['service_name_array'][i]=""
                ret['tariff_name_array'][i]=""
                ret['service_cost_array'][i]="-1"
                ret['slink_id_array'][i]="-1"
                ret['discount_period_id_array'][i]="-1"
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_periodic_service_link(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i)  - 
        @returns: 
        :(s)  tariff_link_id :	(i)  - 
        :(s)  is_blocked :	(i)  - 
        :(s)  discount_period_id :	(i)  - 
        :(s)  start_date :	(i)  - 
        :(s)  expire_date :	(i)  - 
        :(s)  policy_id :	(i)  - 
        :(s)  cost_coef :	(d)  - 
        :(s)  is_unabon_period :	(i)  - 
        :(s)  is_unprepay_period :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        """
        if not self.urfa_call(0x271a):
            raise Exception("Fail of urfa_call(0x271a) [rpcf_get_periodic_service_link]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['tariff_link_id'] = self.pck.get_data(U_TP_I)
        ret['is_blocked'] = self.pck.get_data(U_TP_I)
        ret['discount_period_id'] = self.pck.get_data(U_TP_I)
        ret['start_date'] = self.pck.get_data(U_TP_I)
        ret['expire_date'] = self.pck.get_data(U_TP_I)
        ret['policy_id'] = self.pck.get_data(U_TP_I)
        ret['cost_coef'] = self.pck.get_data(U_TP_D)
        ret['is_unabon_period'] = self.pck.get_data(U_TP_I)
        ret['is_unprepay_period'] = self.pck.get_data(U_TP_I)
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        ret['parent_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_iptraffic_service_link(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i)  - 
        @returns: 
        :(s)  tariff_link_id :	(i)  - 
        :(s)  is_blocked :	(i)  - 
        :(s)  discount_period_id :	(i)  - 
        :(s)  start_date :	(i)  - 
        :(s)  expire_date :	(i)  - 
        :(s)  unabon :	(i)  - 
        :(s)  unprepay :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        :(s)  ip_groups_count :	(i)  - 
        :(s)    ip_address :	(i)  - 
        :(s)    mask :	(i)  - 
        :(s)    mac :	(s)  - 
        :(s)    iptraffic_login :	(s)  - 
        :(s)    iptraffic_password :	(s)  - 
        :(s)    iptraffic_allowed_cid :	(s)  - 
        :(s)    ip_not_vpn :	(i)  - 
        :(s)    dont_use_fw :	(i)  - 
        :(s)    router_id :	(i)  - 
        :(s)  quotas_count :	(i)  - 
        :(s)    tclass_id :	(i)  - 
        :(s)    tclass_name :	(s)  - 
        :(s)    quota :	(l)  - 
        """
        if not self.urfa_call(0x2702):
            raise Exception("Fail of urfa_call(0x2702) [rpcf_get_iptraffic_service_link]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['tariff_link_id'] = self.pck.get_data(U_TP_I)
        ret['is_blocked'] = self.pck.get_data(U_TP_I)
        ret['discount_period_id'] = self.pck.get_data(U_TP_I)
        ret['start_date'] = self.pck.get_data(U_TP_I)
        ret['expire_date'] = self.pck.get_data(U_TP_I)
        ret['unabon'] = self.pck.get_data(U_TP_I)
        ret['unprepay'] = self.pck.get_data(U_TP_I)
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        ret['parent_id'] = self.pck.get_data(U_TP_I)
        ret['ip_groups_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['ip_groups_count']): 
            self.pck.recv(self.sck)
            ret['ip_address'][i] = self.pck.get_data(U_TP_I)
            ret['mask'][i] = self.pck.get_data(U_TP_I)
            ret['mac'][i] = self.pck.get_data(U_TP_S)
            ret['iptraffic_login'][i] = self.pck.get_data(U_TP_S)
            ret['iptraffic_password'][i] = self.pck.get_data(U_TP_S)
            ret['iptraffic_allowed_cid'][i] = self.pck.get_data(U_TP_S)
            ret['ip_not_vpn'][i] = self.pck.get_data(U_TP_I)
            ret['dont_use_fw'][i] = self.pck.get_data(U_TP_I)
            ret['router_id'][i] = self.pck.get_data(U_TP_I)
        self.pck.recv(self.sck)
        ret['quotas_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['quotas_count']): 
            self.pck.recv(self.sck)
            ret['tclass_id'][i] = self.pck.get_data(U_TP_I)
            ret['tclass_name'][i] = self.pck.get_data(U_TP_S)
            ret['quota'][i] = self.pck.get_data(U_TP_L)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_iptraffic_service_link_ipv6(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i)  - 
        @returns: 
        :(s)  tariff_link_id :	(i)  - 
        :(s)  is_blocked :	(i)  - 
        :(s)  discount_period_id :	(i)  - 
        :(s)  start_date :	(i)  - 
        :(s)  expire_date :	(i)  - 
        :(s)  policy_id :	(i)  - 
        :(s)  cost_coef :	(d)  - 
        :(s)  unabon :	(i)  - 
        :(s)  unprepay :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        :(s)  bandwidth_in :	(i)  - 
        :(s)  bandwidth_out :	(i)  - 
        :(s)  ip_groups_count :	(i)  - 
        :(s)    ip_address :	(i)  - 
        :(s)    mask :	(i)  - 
        :(s)    mac :	(s)  - 
        :(s)    iptraffic_login :	(s)  - 
        :(s)    iptraffic_password :	(s)  - 
        :(s)    iptraffic_allowed_cid :	(s)  - 
        :(s)    pool_name :	(s)  - 
        :(s)    ip_not_vpn :	(i)  - 
        :(s)    dont_use_fw :	(i)  - 
        :(s)    is_dynamic :	(i)  - 
        :(s)    router_id :	(i)  - 
        :(s)    switch_id :	(i)  - 
        :(s)    port_id :	(i)  - 
        :(s)    vlan_id :	(i)  - 
        :(s)    pool_id :	(i)  - 
        :(s)  quotas_count :	(i)  - 
        :(s)    tclass_id :	(i)  - 
        :(s)    tclass_name :	(s)  - 
        :(s)    quota :	(l)  - 
        """
        if not self.urfa_call(0x271e):
            raise Exception("Fail of urfa_call(0x271e) [rpcf_get_iptraffic_service_link_ipv6]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['tariff_link_id'] = self.pck.get_data(U_TP_I)
        ret['is_blocked'] = self.pck.get_data(U_TP_I)
        ret['discount_period_id'] = self.pck.get_data(U_TP_I)
        ret['start_date'] = self.pck.get_data(U_TP_I)
        ret['expire_date'] = self.pck.get_data(U_TP_I)
        ret['policy_id'] = self.pck.get_data(U_TP_I)
        ret['cost_coef'] = self.pck.get_data(U_TP_D)
        ret['unabon'] = self.pck.get_data(U_TP_I)
        ret['unprepay'] = self.pck.get_data(U_TP_I)
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        ret['parent_id'] = self.pck.get_data(U_TP_I)
        ret['bandwidth_in'] = self.pck.get_data(U_TP_I)
        ret['bandwidth_out'] = self.pck.get_data(U_TP_I)
        ret['ip_groups_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['ip_groups_count']): 
            self.pck.recv(self.sck)
            ret['ip_address'][i] = self.pck.get_data(U_TP_IP)
            ret['mask'][i] = self.pck.get_data(U_TP_I)
            ret['mac'][i] = self.pck.get_data(U_TP_S)
            ret['iptraffic_login'][i] = self.pck.get_data(U_TP_S)
            ret['iptraffic_password'][i] = self.pck.get_data(U_TP_S)
            ret['iptraffic_allowed_cid'][i] = self.pck.get_data(U_TP_S)
            ret['pool_name'][i] = self.pck.get_data(U_TP_S)
            ret['ip_not_vpn'][i] = self.pck.get_data(U_TP_I)
            ret['dont_use_fw'][i] = self.pck.get_data(U_TP_I)
            ret['is_dynamic'][i] = self.pck.get_data(U_TP_I)
            ret['router_id'][i] = self.pck.get_data(U_TP_I)
            ret['switch_id'][i] = self.pck.get_data(U_TP_I)
            ret['port_id'][i] = self.pck.get_data(U_TP_I)
            ret['vlan_id'][i] = self.pck.get_data(U_TP_I)
            ret['pool_id'][i] = self.pck.get_data(U_TP_I)
        self.pck.recv(self.sck)
        ret['quotas_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['quotas_count']): 
            self.pck.recv(self.sck)
            ret['tclass_id'][i] = self.pck.get_data(U_TP_I)
            ret['tclass_name'][i] = self.pck.get_data(U_TP_S)
            ret['quota'][i] = self.pck.get_data(U_TP_L)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_hotspot_service_link(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i)  - 
        @returns: 
        :(s)  tariff_link_id :	(i)  - 
        :(s)  is_blocked :	(i)  - 
        :(s)  discount_period_id :	(i)  - 
        :(s)  start_date :	(i)  - 
        :(s)  expire_date :	(i)  - 
        :(s)  policy_id :	(i)  - 
        :(s)  cost_coef :	(d)  - 
        :(s)  login :	(s)  - 
        :(s)  password :	(s)  - 
        :(s)  is_unabon_period :	(i)  - 
        :(s)  is_unprepay_period :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        """
        if not self.urfa_call(0x271c):
            raise Exception("Fail of urfa_call(0x271c) [rpcf_get_hotspot_service_link]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['tariff_link_id'] = self.pck.get_data(U_TP_I)
        ret['is_blocked'] = self.pck.get_data(U_TP_I)
        ret['discount_period_id'] = self.pck.get_data(U_TP_I)
        ret['start_date'] = self.pck.get_data(U_TP_I)
        ret['expire_date'] = self.pck.get_data(U_TP_I)
        ret['policy_id'] = self.pck.get_data(U_TP_I)
        ret['cost_coef'] = self.pck.get_data(U_TP_D)
        ret['login'] = self.pck.get_data(U_TP_S)
        ret['password'] = self.pck.get_data(U_TP_S)
        ret['is_unabon_period'] = self.pck.get_data(U_TP_I)
        ret['is_unprepay_period'] = self.pck.get_data(U_TP_I)
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        ret['parent_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_once_service_link(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i)  - 
        @returns: 
        :(s)  discount_date :	(i)  - 
        """
        if not self.urfa_call(0x2704):
            raise Exception("Fail of urfa_call(0x2704) [rpcf_get_once_service_link]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['discount_date'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_dialup_service_link(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i)  - 
        @returns: 
        :(s)  tariff_link_id :	(i)  - 
        :(s)  is_blocked :	(i)  - 
        :(s)  discount_period_id :	(i)  - 
        :(s)  start_date :	(i)  - 
        :(s)  expire_date :	(i)  - 
        :(s)  policy_id :	(i)  - 
        :(s)  cost_coef :	(d)  - 
        :(s)  login :	(s)  - 
        :(s)  password :	(s)  - 
        :(s)  allowed_cid :	(s)  - 
        :(s)  allowed_csid :	(s)  - 
        :(s)  callback_enabled :	(i)  - 
        :(s)  is_unabon_period :	(i)  - 
        :(s)  is_unprepay_period :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        """
        if not self.urfa_call(0x271d):
            raise Exception("Fail of urfa_call(0x271d) [rpcf_get_dialup_service_link]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['tariff_link_id'] = self.pck.get_data(U_TP_I)
        ret['is_blocked'] = self.pck.get_data(U_TP_I)
        ret['discount_period_id'] = self.pck.get_data(U_TP_I)
        ret['start_date'] = self.pck.get_data(U_TP_I)
        ret['expire_date'] = self.pck.get_data(U_TP_I)
        ret['policy_id'] = self.pck.get_data(U_TP_I)
        ret['cost_coef'] = self.pck.get_data(U_TP_D)
        ret['login'] = self.pck.get_data(U_TP_S)
        ret['password'] = self.pck.get_data(U_TP_S)
        ret['allowed_cid'] = self.pck.get_data(U_TP_S)
        ret['allowed_csid'] = self.pck.get_data(U_TP_S)
        ret['callback_enabled'] = self.pck.get_data(U_TP_I)
        ret['is_unabon_period'] = self.pck.get_data(U_TP_I)
        ret['is_unprepay_period'] = self.pck.get_data(U_TP_I)
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        ret['parent_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_ipzones_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  zones_count :	(i)  - 
        :(s)    zone_id :	(i)  - 
        :(s)    zone_name :	(s)  - 
        """
        if not self.urfa_call(0x2800):
            raise Exception("Fail of urfa_call(0x2800) [rpcf_get_ipzones_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['zones_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['zones_count']): 
            self.pck.recv(self.sck)
            ret['zone_id'][i] = self.pck.get_data(U_TP_I)
            ret['zone_name'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_ipzone(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        :(s)  name :	(s)  - 
        :(s)  count :	(i)  - 
        :(s)    net :	(i)  - 
        :(s)    mask :	(i)  - 
        :(s)    gateaway :	(i)  - 
        @returns: 
        :(s)  id :	(i)  - 
        """
        if not self.urfa_call(0x2801):
            raise Exception("Fail of urfa_call(0x2801) [rpcf_add_ipzone]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.add_data(params['count'], U_TP_I)
        for i in range(params['count']):
            self.pck.add_data(params['net'][i], U_TP_I)
            self.pck.add_data(params['mask'][i], U_TP_I)
            self.pck.add_data(params['gateaway'][i], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_ipzone_ipv6(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        :(s)  name :	(s)  - 
        :(s)  count :	(i)  - 
        :(s)    net :	(i)  - 
        :(s)    mask :	(i)  - 
        :(s)    gateaway :	(i)  - 
        @returns: 
        :(s)  id :	(i)  - 
        """
        if not self.urfa_call(0x2803):
            raise Exception("Fail of urfa_call(0x2803) [rpcf_add_ipzone_ipv6]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.add_data(params['count'], U_TP_I)
        for i in range(params['count']):
            self.pck.add_data(params['net'][i], U_TP_IP)
            self.pck.add_data(params['mask'][i], U_TP_I)
            self.pck.add_data(params['gateaway'][i], U_TP_IP)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_ipzone(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        @returns: 
        :(s)  name :	(s)  - 
        :(s)  count :	(i)  - 
        :(s)    net :	(i)  - 
        :(s)    mask :	(i)  - 
        :(s)    gateaway :	(i)  - 
        """
        if not self.urfa_call(0x2802):
            raise Exception("Fail of urfa_call(0x2802) [rpcf_get_ipzone]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['name'] = self.pck.get_data(U_TP_S)
        ret['count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['count']): 
            self.pck.recv(self.sck)
            ret['net'][i] = self.pck.get_data(U_TP_I)
            ret['mask'][i] = self.pck.get_data(U_TP_I)
            ret['gateaway'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_ipzone_ipv6(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        @returns: 
        :(s)  name :	(s)  - 
        :(s)  count :	(i)  - 
        :(s)    net :	(i)  - 
        :(s)    mask :	(i)  - 
        :(s)    gateaway :	(i)  - 
        """
        if not self.urfa_call(0x2804):
            raise Exception("Fail of urfa_call(0x2804) [rpcf_get_ipzone_ipv6]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['name'] = self.pck.get_data(U_TP_S)
        ret['count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['count']): 
            self.pck.recv(self.sck)
            ret['net'][i] = self.pck.get_data(U_TP_IP)
            ret['mask'][i] = self.pck.get_data(U_TP_I)
            ret['gateaway'][i] = self.pck.get_data(U_TP_IP)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_houses_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  houses_size :	(i)  - 
        :(s)    house_id :	(i)  - 
        :(s)    ip_zone_id :	(i)  - 
        :(s)    connect_date :	(i)  - 
        :(s)    post_code :	(s)  - 
        :(s)    country :	(s)  - 
        :(s)    region :	(s)  - 
        :(s)    city :	(s)  - 
        :(s)    street :	(s)  - 
        :(s)    number :	(s)  - 
        :(s)    building :	(s)  - 
        """
        if not self.urfa_call(0x2810):
            raise Exception("Fail of urfa_call(0x2810) [rpcf_get_houses_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['houses_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['houses_size']): 
            self.pck.recv(self.sck)
            ret['house_id'][i] = self.pck.get_data(U_TP_I)
            ret['ip_zone_id'][i] = self.pck.get_data(U_TP_I)
            ret['connect_date'][i] = self.pck.get_data(U_TP_I)
            ret['post_code'][i] = self.pck.get_data(U_TP_S)
            ret['country'][i] = self.pck.get_data(U_TP_S)
            ret['region'][i] = self.pck.get_data(U_TP_S)
            ret['city'][i] = self.pck.get_data(U_TP_S)
            ret['street'][i] = self.pck.get_data(U_TP_S)
            ret['number'][i] = self.pck.get_data(U_TP_S)
            ret['building'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_house(self, params):
        """ description
        @params: 
        :(s)  house_id :	(i)  - 
        :(s)  connect_date :	(i)  - 
        :(s)  post_code :	(s)  - 
        :(s)  country :	(s)  - 
        :(s)  region :	(s)  - 
        :(s)  city :	(s)  - 
        :(s)  street :	(s)  - 
        :(s)  number :	(s)  - 
        :(s)  building :	(s)  - 
        :(s)  count :	(i) = _def_  - 
        :(s)    ipzone_id :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x2811):
            raise Exception("Fail of urfa_call(0x2811) [rpcf_add_house]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['house_id'], U_TP_I)
        self.pck.add_data(params['connect_date'], U_TP_I)
        self.pck.add_data(params['post_code'], U_TP_S)
        self.pck.add_data(params['country'], U_TP_S)
        self.pck.add_data(params['region'], U_TP_S)
        self.pck.add_data(params['city'], U_TP_S)
        self.pck.add_data(params['street'], U_TP_S)
        self.pck.add_data(params['number'], U_TP_S)
        self.pck.add_data(params['building'], U_TP_S)
        if 'count' not in params: params['count'] = len(params['ipzone_id'])
        self.pck.add_data(params['count'], U_TP_I)
        for i in range(len(params['ipzone_id'])):
            self.pck.add_data(params['ipzone_id'][i], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_house(self, params):
        """ description
        @params: 
        :(s)  house_id :	(i)  - 
        @returns: 
        :(s)  house_id :	(i)  - 
        :(s)  connect_date :	(i)  - 
        :(s)  post_code :	(s)  - 
        :(s)  country :	(s)  - 
        :(s)  region :	(s)  - 
        :(s)  city :	(s)  - 
        :(s)  street :	(s)  - 
        :(s)  number :	(s)  - 
        :(s)  building :	(s)  - 
        :(s)  count :	(i)  - 
        :(s)    ipzone_id :	(i)  - 
        :(s)    ipzone_name :	(s)  - 
        """
        if not self.urfa_call(0x2812):
            raise Exception("Fail of urfa_call(0x2812) [rpcf_get_house]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['house_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['house_id'] = self.pck.get_data(U_TP_I)
        ret['connect_date'] = self.pck.get_data(U_TP_I)
        ret['post_code'] = self.pck.get_data(U_TP_S)
        ret['country'] = self.pck.get_data(U_TP_S)
        ret['region'] = self.pck.get_data(U_TP_S)
        ret['city'] = self.pck.get_data(U_TP_S)
        ret['street'] = self.pck.get_data(U_TP_S)
        ret['number'] = self.pck.get_data(U_TP_S)
        ret['building'] = self.pck.get_data(U_TP_S)
        ret['count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['count']): 
            self.pck.recv(self.sck)
            ret['ipzone_id'][i] = self.pck.get_data(U_TP_I)
            ret['ipzone_name'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_free_ips_for_house(self, params):
        """ description
        @params: 
        :(s)  house_id :	(i)  - 
        @returns: 
        :(s)  ips_size :	(i)  - 
        :(s)    ips_ip :	(i)  - 
        :(s)    mask :	(i)  - 
        :(s)    zone_name :	(s)  - 
        :(s)  error :	(s)  - 
        """
        if not self.urfa_call(0x15101):
            raise Exception("Fail of urfa_call(0x15101) [rpcf_get_free_ips_for_house]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['house_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['ips_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['ips_size']): 
            self.pck.recv(self.sck)
            ret['ips_ip'][i] = self.pck.get_data(U_TP_IP)
            ret['mask'][i] = self.pck.get_data(U_TP_I)
            ret['zone_name'][i] = self.pck.get_data(U_TP_S)
        self.pck.recv(self.sck)
        ret['error'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_charge_policy_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  policy_count :	(i)  - 
        :(s)    policy_id_array :	(i)  - 
        :(s)    flags_array :	(i)  - 
        :(s)    name_array :	(s)  - 
        :(s)    tm_count :	(i)  - 
        :(s)      timemark :	(i)  - 
        """
        if not self.urfa_call(0x15102):
            raise Exception("Fail of urfa_call(0x15102) [rpcf_get_charge_policy_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['policy_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['policy_count']): 
            self.pck.recv(self.sck)
            ret['policy_id_array'][i] = self.pck.get_data(U_TP_I)
            ret['flags_array'][i] = self.pck.get_data(U_TP_I)
            ret['name_array'][i] = self.pck.get_data(U_TP_S)
            ret['tm_count'][i] = self.pck.get_data(U_TP_I)
            for e in range(ret['tm_count'][i]): 
                self.pck.recv(self.sck)
                if not i in ret['timemark']:ret['timemark'][i] = dict()
                ret['timemark'][i][e] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_charge_policy(self, params):
        """ description
        @params: 
        :(s)  flags :	(i)  - 
        :(s)  name :	(s)  - 
        :(s)  tm_count :	(i)  - 
        :(s)    timemark :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x15103):
            raise Exception("Fail of urfa_call(0x15103) [rpcf_add_charge_policy]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['flags'], U_TP_I)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.add_data(params['tm_count'], U_TP_I)
        for i in range(params['tm_count']):
            self.pck.add_data(params['timemark'][i], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_charge_policy(self, params):
        """ description
        @params: 
        :(s)  policy_id :	(i)  - 
        :(s)  flags :	(i)  - 
        :(s)  name :	(s)  - 
        :(s)  tm_count :	(i)  - 
        :(s)    timemark :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x15104):
            raise Exception("Fail of urfa_call(0x15104) [rpcf_edit_charge_policy]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['policy_id'], U_TP_I)
        self.pck.add_data(params['flags'], U_TP_I)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.add_data(params['tm_count'], U_TP_I)
        for i in range(params['tm_count']):
            self.pck.add_data(params['timemark'][i], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_remove_charge_policy(self, params):
        """ description
        @params: 
        :(s)  policy_id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x15105):
            raise Exception("Fail of urfa_call(0x15105) [rpcf_remove_charge_policy]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['policy_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_set_charge_policy_for_service(self, params):
        """ description
        @params: 
        :(s)  service_id :	(i)  - 
        :(s)  policy_id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x15106):
            raise Exception("Fail of urfa_call(0x15106) [rpcf_set_charge_policy_for_service]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.add_data(params['policy_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_charge_policy_for_service(self, params):
        """ description
        @params: 
        :(s)  service_id :	(i)  - 
        @returns: 
        :(s)  charge_policy :	(i)  - 
        """
        if not self.urfa_call(0x15107):
            raise Exception("Fail of urfa_call(0x15107) [rpcf_get_charge_policy_for_service]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['charge_policy'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_periodic_link_stats(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        :(s)    is_active :	(i)  - 
        :(s)    fee_recalc_start :	(i)  - 
        :(s)    fee_recalc_duration :	(i)  - 
        :(s)    ip_recalc_start :	(i)  - 
        :(s)    ip_recalc_durtation :	(i)  - 
        :(s)    tel_recalc_start :	(i)  - 
        :(s)    tel_recalc_duration :	(i)  - 
        :(s)    charged :	(d)  - 
        :(s)    repaid :	(d)  - 
        """
        if not self.urfa_call(0x15108):
            raise Exception("Fail of urfa_call(0x15108) [rpcf_get_periodic_link_stats]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if ret['result']  !=  -1:
            ret['is_active'] = self.pck.get_data(U_TP_I)
            ret['fee_recalc_start'] = self.pck.get_data(U_TP_I)
            ret['fee_recalc_duration'] = self.pck.get_data(U_TP_I)
            ret['ip_recalc_start'] = self.pck.get_data(U_TP_I)
            ret['ip_recalc_durtation'] = self.pck.get_data(U_TP_I)
            ret['tel_recalc_start'] = self.pck.get_data(U_TP_I)
            ret['tel_recalc_duration'] = self.pck.get_data(U_TP_I)
            ret['charged'] = self.pck.get_data(U_TP_D)
            ret['repaid'] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_ip_mac(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  ip_mac_size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    name :	(s)  - 
        """
        if not self.urfa_call(0x2814):
            raise Exception("Fail of urfa_call(0x2814) [rpcf_get_ip_mac]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['ip_mac_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['ip_mac_size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['name'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_remove_house(self, params):
        """ description
        @params: 
        :(s)  hid :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x2815):
            raise Exception("Fail of urfa_call(0x2815) [rpcf_remove_house]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['hid'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_ipgroups_list_ipv6(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  groups_size :	(i)  - 
        :(s)    count :	(i)  - 
        :(s)      id :	(i)  - 
        :(s)      ip :	(i)  - 
        :(s)      mask :	(i)  - 
        :(s)      mac :	(s)  - 
        :(s)      login :	(s)  - 
        :(s)      allowed_cid :	(s)  - 
        """
        if not self.urfa_call(0x292e):
            raise Exception("Fail of urfa_call(0x292e) [rpcf_get_ipgroups_list_ipv6]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['groups_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['groups_size']): 
            self.pck.recv(self.sck)
            ret['count'] = self.pck.get_data(U_TP_I)
            ret['count_array'][i]=ret['count']
            for j in range(ret['count']): 
                self.pck.recv(self.sck)
                if not i in ret['id']:ret['id'][i] = dict()
                ret['id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['ip']:ret['ip'][i] = dict()
                ret['ip'][i][j] = self.pck.get_data(U_TP_IP)
                if not i in ret['mask']:ret['mask'][i] = dict()
                ret['mask'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['mac']:ret['mac'][i] = dict()
                ret['mac'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['login']:ret['login'][i] = dict()
                ret['login'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['allowed_cid']:ret['allowed_cid'][i] = dict()
                ret['allowed_cid'][i][j] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_ipgroup(self, params):
        """ description
        @params: 
        :(s)  ipgroup_id :	(i)  - 
        @returns: 
        :(s)  name :	(s)  - 
        :(s)  ipzone_count :	(i)  - 
        :(s)    ip :	(i)  - 
        :(s)    mask :	(i)  - 
        :(s)    gateaway :	(i)  - 
        """
        if not self.urfa_call(0x2902):
            raise Exception("Fail of urfa_call(0x2902) [rpcf_get_ipgroup]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['ipgroup_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['name'] = self.pck.get_data(U_TP_S)
        ret['ipzone_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['ipzone_count']): 
            self.pck.recv(self.sck)
            ret['ip'][i] = self.pck.get_data(U_TP_IP)
            ret['mask'][i] = self.pck.get_data(U_TP_IP)
            ret['gateaway'][i] = self.pck.get_data(U_TP_IP)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_currency_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  currency_size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    currency_brief_name :	(s)  - 
        :(s)    currency_full_name :	(s)  - 
        :(s)    percent :	(d)  - 
        :(s)    rates :	(d)  - 
        """
        if not self.urfa_call(0x2910):
            raise Exception("Fail of urfa_call(0x2910) [rpcf_get_currency_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['currency_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['currency_size']): 
            self.pck.recv(self.sck)
            ret['id'] = self.pck.get_data(U_TP_I)
            ret['currency_brief_name'][i] = self.pck.get_data(U_TP_S)
            ret['currency_full_name'][i] = self.pck.get_data(U_TP_S)
            ret['percent'][i] = self.pck.get_data(U_TP_D)
            ret['rates'][i] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_currency(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        :(s)  currency_brief_name :	(s)  - 
        :(s)  currency_full_name :	(s)  - 
        :(s)  date :	(i)  - 
        :(s)  rate :	(d)  - 
        :(s)  percent :	(d)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x2911):
            raise Exception("Fail of urfa_call(0x2911) [rpcf_add_currency]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['currency_brief_name'], U_TP_S)
        self.pck.add_data(params['currency_full_name'], U_TP_S)
        self.pck.add_data(params['date'], U_TP_I)
        self.pck.add_data(params['rate'], U_TP_D)
        self.pck.add_data(params['percent'], U_TP_D)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_currency(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        :(s)  currency_brief_name :	(s)  - 
        :(s)  currency_full_name :	(s)  - 
        :(s)  date :	(i)  - 
        :(s)  rate :	(d)  - 
        :(s)  percent :	(d)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x2912):
            raise Exception("Fail of urfa_call(0x2912) [rpcf_edit_currency]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['currency_brief_name'], U_TP_S)
        self.pck.add_data(params['currency_full_name'], U_TP_S)
        self.pck.add_data(params['date'], U_TP_I)
        self.pck.add_data(params['rate'], U_TP_D)
        self.pck.add_data(params['percent'], U_TP_D)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_currency_rate_history(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        @returns: 
        :(s)  size :	(i)  - 
        :(s)    time :	(i)  - 
        :(s)    value :	(d)  - 
        """
        if not self.urfa_call(0x2913):
            raise Exception("Fail of urfa_call(0x2913) [rpcf_get_currency_rate_history]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['size']): 
            self.pck.recv(self.sck)
            ret['time'][i] = self.pck.get_data(U_TP_I)
            ret['value'][i] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_currency_rate_rbc(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        @returns: 
        :(s)  rate :	(d)  - 
        :(s)  error :	(s)  - 
        """
        if not self.urfa_call(0x2914):
            raise Exception("Fail of urfa_call(0x2914) [rpcf_get_currency_rate_rbc]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['rate'] = self.pck.get_data(U_TP_D)
        ret['error'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_remove_currency(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x2915):
            raise Exception("Fail of urfa_call(0x2915) [rpcf_remove_currency]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_service_report_new(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i) = _def_  - 
        :(s)  account_id :	(i) = _def_  - 
        :(s)  group_id :	(i) = _def_  - 
        :(s)  apid :	(i) = _def_  - 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i) = _def_  - 
        @returns: 
        :(s)  accounts_count :	(i)  - 
        :(s)    atr_size :	(i)  - 
        :(s)      account_id :	(i)  - 
        :(s)      login :	(s)  - 
        :(s)      full_name :	(s)  - 
        :(s)      discount_date :	(i)  - 
        :(s)      discount_period_id :	(i)  - 
        :(s)      discount :	(d)  - 
        :(s)      service_name :	(s)  - 
        :(s)      service_type :	(i)  - 
        """
        if not self.urfa_call(0x3021):
            raise Exception("Fail of urfa_call(0x3021) [rpcf_service_report_new]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'user_id' not in params: params['user_id'] = 0
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        if 'group_id' not in params: params['group_id'] = 0
        self.pck.add_data(params['group_id'], U_TP_I)
        if 'apid' not in params: params['apid'] = 0
        self.pck.add_data(params['apid'], U_TP_I)
        self.pck.add_data(params['time_start'], U_TP_I)
        if 'time_end' not in params: params['time_end'] = now()
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['accounts_count'] = self.pck.get_data(U_TP_I)
        for j in range(ret['accounts_count']): 
            self.pck.recv(self.sck)
            ret['atr_size'] = self.pck.get_data(U_TP_I)
            ret['atr_size_array'][j]=ret['atr_size']
            for i in range(ret['atr_size']): 
                self.pck.recv(self.sck)
                if not j in ret['account_id']:ret['account_id'][j] = dict()
                ret['account_id'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['login']:ret['login'][j] = dict()
                ret['login'][j][i] = self.pck.get_data(U_TP_S)
                if not j in ret['full_name']:ret['full_name'][j] = dict()
                ret['full_name'][j][i] = self.pck.get_data(U_TP_S)
                if not j in ret['discount_date']:ret['discount_date'][j] = dict()
                ret['discount_date'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['discount_period_id']:ret['discount_period_id'][j] = dict()
                ret['discount_period_id'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['discount']:ret['discount'][j] = dict()
                ret['discount'][j][i] = self.pck.get_data(U_TP_D)
                if not j in ret['service_name']:ret['service_name'][j] = dict()
                ret['service_name'][j][i] = self.pck.get_data(U_TP_S)
                if not j in ret['service_type']:ret['service_type'][j] = dict()
                ret['service_type'][j][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_other_charges_report(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i) = _def_  - 
        :(s)  account_id :	(i) = _def_  - 
        :(s)  group_id :	(i) = _def_  - 
        :(s)  apid :	(i) = _def_  - 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i) = _def_  - 
        @returns: 
        :(s)  accounts_count :	(i)  - 
        :(s)    atr_size :	(i)  - 
        :(s)      account_id :	(i)  - 
        :(s)      login :	(s)  - 
        :(s)      full_name :	(s)  - 
        :(s)      discount_date :	(i)  - 
        :(s)      discount :	(d)  - 
        :(s)      charge_type :	(i)  - 
        """
        if not self.urfa_call(0x3023):
            raise Exception("Fail of urfa_call(0x3023) [rpcf_other_charges_report]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'user_id' not in params: params['user_id'] = 0
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        if 'group_id' not in params: params['group_id'] = 0
        self.pck.add_data(params['group_id'], U_TP_I)
        if 'apid' not in params: params['apid'] = 0
        self.pck.add_data(params['apid'], U_TP_I)
        self.pck.add_data(params['time_start'], U_TP_I)
        if 'time_end' not in params: params['time_end'] = now()
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['accounts_count'] = self.pck.get_data(U_TP_I)
        for j in range(ret['accounts_count']): 
            self.pck.recv(self.sck)
            ret['atr_size'] = self.pck.get_data(U_TP_I)
            ret['atr_size_array'][j]=ret['atr_size']
            for i in range(ret['atr_size']): 
                self.pck.recv(self.sck)
                if not j in ret['account_id']:ret['account_id'][j] = dict()
                ret['account_id'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['login']:ret['login'][j] = dict()
                ret['login'][j][i] = self.pck.get_data(U_TP_S)
                if not j in ret['full_name']:ret['full_name'][j] = dict()
                ret['full_name'][j][i] = self.pck.get_data(U_TP_S)
                if not j in ret['discount_date']:ret['discount_date'][j] = dict()
                ret['discount_date'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['discount']:ret['discount'][j] = dict()
                ret['discount'][j][i] = self.pck.get_data(U_TP_D)
                if not j in ret['charge_type']:ret['charge_type'][j] = dict()
                ret['charge_type'][j][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_blocks_report(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i) = _def_  - 
        :(s)  account_id :	(i) = _def_  - 
        :(s)  group_id :	(i) = _def_  - 
        :(s)  apid :	(i) = _def_  - 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i) = _def_  - 
        :(s)  show_all :	(i) = _def_  - 
        @returns: 
        :(s)  accounts_count :	(i)  - 
        :(s)    atr_size :	(i)  - 
        :(s)      account_id :	(i)  - 
        :(s)      login :	(s)  - 
        :(s)      start_date :	(i)  - 
        :(s)      expire_date :	(i)  - 
        :(s)      what_blocked :	(i)  - 
        :(s)      block_type :	(i)  - 
        :(s)      comment :	(s)  - 
        """
        if not self.urfa_call(0x3004):
            raise Exception("Fail of urfa_call(0x3004) [rpcf_blocks_report]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'user_id' not in params: params['user_id'] = 0
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        if 'group_id' not in params: params['group_id'] = 0
        self.pck.add_data(params['group_id'], U_TP_I)
        if 'apid' not in params: params['apid'] = 0
        self.pck.add_data(params['apid'], U_TP_I)
        self.pck.add_data(params['time_start'], U_TP_I)
        if 'time_end' not in params: params['time_end'] = now()
        self.pck.add_data(params['time_end'], U_TP_I)
        if 'show_all' not in params: params['show_all'] = 1
        self.pck.add_data(params['show_all'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['accounts_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['accounts_count']): 
            self.pck.recv(self.sck)
            ret['atr_size'] = self.pck.get_data(U_TP_I)
            ret['atr_size_array'][i]=ret['atr_size']
            for j in range(ret['atr_size']): 
                self.pck.recv(self.sck)
                if not i in ret['account_id']:ret['account_id'][i] = dict()
                ret['account_id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['login']:ret['login'][i] = dict()
                ret['login'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['start_date']:ret['start_date'][i] = dict()
                ret['start_date'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['expire_date']:ret['expire_date'][i] = dict()
                ret['expire_date'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['what_blocked']:ret['what_blocked'][i] = dict()
                ret['what_blocked'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['block_type']:ret['block_type'][i] = dict()
                ret['block_type'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['comment']:ret['comment'][i] = dict()
                ret['comment'][i][j] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_blocks_report_ex(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i) = _def_  - 
        :(s)  account_id :	(i) = _def_  - 
        :(s)  group_id :	(i) = _def_  - 
        :(s)  apid :	(i) = _def_  - 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i) = _def_  - 
        :(s)  show_all :	(i) = _def_  - 
        @returns: 
        :(s)  accounts_count :	(i)  - 
        :(s)    atr_size :	(i)  - 
        :(s)      account_id :	(i)  - 
        :(s)      login :	(s)  - 
        :(s)      start_date :	(i)  - 
        :(s)      expire_date :	(i)  - 
        :(s)      block_type :	(i)  - 
        :(s)      id :	(i)  - 
        :(s)      unabon :	(i)  - 
        :(s)      unprepay :	(i)  - 
        :(s)      is_deleted :	(i)  - 
        """
        if not self.urfa_call(0x300b):
            raise Exception("Fail of urfa_call(0x300b) [rpcf_blocks_report_ex]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'user_id' not in params: params['user_id'] = 0
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        if 'group_id' not in params: params['group_id'] = 0
        self.pck.add_data(params['group_id'], U_TP_I)
        if 'apid' not in params: params['apid'] = 0
        self.pck.add_data(params['apid'], U_TP_I)
        self.pck.add_data(params['time_start'], U_TP_I)
        if 'time_end' not in params: params['time_end'] = now()
        self.pck.add_data(params['time_end'], U_TP_I)
        if 'show_all' not in params: params['show_all'] = 1
        self.pck.add_data(params['show_all'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['accounts_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['accounts_count']): 
            self.pck.recv(self.sck)
            ret['atr_size'] = self.pck.get_data(U_TP_I)
            ret['atr_size_array'][i]=ret['atr_size']
            for j in range(ret['atr_size']): 
                self.pck.recv(self.sck)
                if not i in ret['account_id']:ret['account_id'][i] = dict()
                ret['account_id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['login']:ret['login'][i] = dict()
                ret['login'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['start_date']:ret['start_date'][i] = dict()
                ret['start_date'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['expire_date']:ret['expire_date'][i] = dict()
                ret['expire_date'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['block_type']:ret['block_type'][i] = dict()
                ret['block_type'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['id']:ret['id'][i] = dict()
                ret['id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['unabon']:ret['unabon'][i] = dict()
                ret['unabon'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['unprepay']:ret['unprepay'][i] = dict()
                ret['unprepay'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['is_deleted']:ret['is_deleted'][i] = dict()
                ret['is_deleted'][i][j] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_block(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i)  - 
        :(s)  unabon :	(i)  - 
        :(s)  unprepay :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x300c):
            raise Exception("Fail of urfa_call(0x300c) [rpcf_edit_block]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['time_start'], U_TP_I)
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.add_data(params['unabon'], U_TP_I)
        self.pck.add_data(params['unprepay'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_delete_block(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x300d):
            raise Exception("Fail of urfa_call(0x300d) [rpcf_delete_block]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_payments_timed_report(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i) = _def_  - 
        :(s)  account_id :	(i)  - 
        :(s)  group_id :	(i) = _def_  - 
        :(s)  apid :	(i)  - 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i)  - 
        @returns: 
        :(s)  accounts_size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)      login :	(s)  - 
        :(s)      first_date :	(i)  - 
        :(s)      last_date :	(i)  - 
        :(s)      burn_date :	(i)  - 
        :(s)      amount :	(d)  - 
        :(s)      already_discounted :	(d)  - 
        """
        if not self.urfa_call(0x3006):
            raise Exception("Fail of urfa_call(0x3006) [rpcf_payments_timed_report]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'user_id' not in params: params['user_id'] = 0
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['account_id'], U_TP_I)
        if 'group_id' not in params: params['group_id'] = 0
        self.pck.add_data(params['group_id'], U_TP_I)
        self.pck.add_data(params['apid'], U_TP_I)
        self.pck.add_data(params['time_start'], U_TP_I)
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['accounts_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['accounts_size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            if ret['id'][i]  !=  -1:
                ret['login'][i] = self.pck.get_data(U_TP_S)
                ret['first_date'][i] = self.pck.get_data(U_TP_I)
                ret['last_date'][i] = self.pck.get_data(U_TP_I)
                ret['burn_date'][i] = self.pck.get_data(U_TP_I)
                ret['amount'][i] = self.pck.get_data(U_TP_D)
                ret['already_discounted'][i] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_payments_report_owner_ex(self, params):
        """ description
        @params: 
        :(s)  time_start :	(i) = _def_  - 
        :(s)  time_end :	(i) = _def_  - 
        @returns: 
        :(s)  rows_count :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    account_id :	(i)  - 
        :(s)    login :	(s)  - 
        :(s)    user_id :	(i)  - 
        :(s)    full_name :	(s)  - 
        :(s)    actual_date :	(i)  - 
        :(s)    payment_enter_date :	(i)  - 
        :(s)    payment :	(d)  - 
        :(s)    payment_incurrency :	(d)  - 
        :(s)    currency_id :	(i)  - 
        :(s)    method :	(i)  - 
        :(s)    who_receved :	(i)  - 
        :(s)    admin_comment :	(s)  - 
        :(s)    payment_ext_number :	(s)  - 
        """
        if not self.urfa_call(0x300a):
            raise Exception("Fail of urfa_call(0x300a) [rpcf_payments_report_owner_ex]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'time_start' not in params: params['time_start'] = 0
        self.pck.add_data(params['time_start'], U_TP_I)
        if 'time_end' not in params: params['time_end'] = now()
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['rows_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['rows_count']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['account_id'][i] = self.pck.get_data(U_TP_I)
            ret['login'][i] = self.pck.get_data(U_TP_S)
            ret['user_id'][i] = self.pck.get_data(U_TP_I)
            ret['full_name'][i] = self.pck.get_data(U_TP_S)
            ret['actual_date'][i] = self.pck.get_data(U_TP_I)
            ret['payment_enter_date'][i] = self.pck.get_data(U_TP_I)
            ret['payment'][i] = self.pck.get_data(U_TP_D)
            ret['payment_incurrency'][i] = self.pck.get_data(U_TP_D)
            ret['currency_id'][i] = self.pck.get_data(U_TP_I)
            ret['method'][i] = self.pck.get_data(U_TP_I)
            ret['who_receved'][i] = self.pck.get_data(U_TP_I)
            ret['admin_comment'][i] = self.pck.get_data(U_TP_S)
            ret['payment_ext_number'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_traffic_report_ex(self, params):
        """ description
        @params: 
        :(s)  type :	(i)  - 
        :(s)  user_id :	(i)  - 
        :(s)  account_id :	(i)  - 
        :(s)  group_id :	(i)  - 
        :(s)  apid :	(i)  - 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i)  - 
        @returns: 
        :(s)  bytes_in_kbyte :	(d)  - 
        :(s)  users_count :	(i)  - 
        :(s)    atr_size :	(i)  - 
        :(s)      account_id :	(i)  - 
        :(s)      login :	(s)  - 
        :(s)        add_param :	(i)  - 
        :(s)      tclass :	(i)  - 
        :(s)      base_cost :	(d)  - 
        :(s)      bytes :	(l)  - 
        :(s)      discount :	(d)  - 
        """
        if not self.urfa_call(0x3009):
            raise Exception("Fail of urfa_call(0x3009) [rpcf_traffic_report_ex]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['type'], U_TP_I)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['group_id'], U_TP_I)
        self.pck.add_data(params['apid'], U_TP_I)
        self.pck.add_data(params['time_start'], U_TP_I)
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['bytes_in_kbyte'] = self.pck.get_data(U_TP_D)
        ret['users_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['users_count']): 
            self.pck.recv(self.sck)
            ret['atr_size'] = self.pck.get_data(U_TP_I)
            ret['atr_size_array'][i]=ret['atr_size']
            for j in range(ret['atr_size']): 
                self.pck.recv(self.sck)
                if not i in ret['account_id']:ret['account_id'][i] = dict()
                ret['account_id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['login']:ret['login'][i] = dict()
                ret['login'][i][j] = self.pck.get_data(U_TP_S)
                if params['type']  !=  0:
                    if not i in ret['add_param']:ret['add_param'][i] = dict()
                    ret['add_param'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['tclass']:ret['tclass'][i] = dict()
                ret['tclass'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['base_cost']:ret['base_cost'][i] = dict()
                ret['base_cost'][i][j] = self.pck.get_data(U_TP_D)
                if not i in ret['bytes']:ret['bytes'][i] = dict()
                ret['bytes'][i][j] = self.pck.get_data(U_TP_L)
                if not i in ret['discount']:ret['discount'][i] = dict()
                ret['discount'][i][j] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_tariffs_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  tariffs_count :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    name :	(s)  - 
        :(s)    create_date :	(i)  - 
        :(s)    who_create :	(i)  - 
        :(s)    login :	(s)  - 
        :(s)    change_create :	(i)  - 
        :(s)    who_change :	(i)  - 
        :(s)    login_change :	(s)  - 
        :(s)    expire_date :	(i)  - 
        :(s)    is_blocked :	(i)  - 
        :(s)    balance_rollover :	(i)  - 
        :(s)    comment :	(s)  - 
        """
        if not self.urfa_call(0x3024):
            raise Exception("Fail of urfa_call(0x3024) [rpcf_get_tariffs_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['tariffs_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['tariffs_count']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['name'][i] = self.pck.get_data(U_TP_S)
            ret['create_date'][i] = self.pck.get_data(U_TP_I)
            ret['who_create'][i] = self.pck.get_data(U_TP_I)
            ret['login'][i] = self.pck.get_data(U_TP_S)
            ret['change_create'][i] = self.pck.get_data(U_TP_I)
            ret['who_change'][i] = self.pck.get_data(U_TP_I)
            ret['login_change'][i] = self.pck.get_data(U_TP_S)
            ret['expire_date'][i] = self.pck.get_data(U_TP_I)
            ret['is_blocked'][i] = self.pck.get_data(U_TP_I)
            ret['balance_rollover'][i] = self.pck.get_data(U_TP_I)
            ret['comment'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_tariff(self, params):
        """ description
        @params: 
        :(s)  tariff_id :	(i)  - 
        @returns: 
        :(s)  tariff_name :	(s)  - 
        :(s)  tariff_create_date :	(i)  - 
        :(s)  who_create :	(i)  - 
        :(s)  who_create_login :	(s)  - 
        :(s)  tariff_change_date :	(i)  - 
        :(s)  who_change :	(i)  - 
        :(s)  who_change_login :	(s)  - 
        :(s)  tariff_expire_date :	(i)  - 
        :(s)  tariff_is_blocked :	(i)  - 
        :(s)  tariff_balance_rollover :	(i)  - 
        :(s)  services_count :	(i)  - 
        :(s)    service_id_array :	(i)  - 
        :(s)    service_type_array :	(i)  - 
        :(s)    service_name_array :	(s)  - 
        :(s)    comment_array :	(s)  - 
        :(s)    link_by_default_array :	(i)  - 
        :(s)    is_dynamic_array :	(i)  - 
        """
        if not self.urfa_call(0x3011):
            raise Exception("Fail of urfa_call(0x3011) [rpcf_get_tariff]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['tariff_name'] = self.pck.get_data(U_TP_S)
        ret['tariff_create_date'] = self.pck.get_data(U_TP_I)
        ret['who_create'] = self.pck.get_data(U_TP_I)
        ret['who_create_login'] = self.pck.get_data(U_TP_S)
        ret['tariff_change_date'] = self.pck.get_data(U_TP_I)
        ret['who_change'] = self.pck.get_data(U_TP_I)
        ret['who_change_login'] = self.pck.get_data(U_TP_S)
        ret['tariff_expire_date'] = self.pck.get_data(U_TP_I)
        ret['tariff_is_blocked'] = self.pck.get_data(U_TP_I)
        ret['tariff_balance_rollover'] = self.pck.get_data(U_TP_I)
        ret['services_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['services_count']): 
            self.pck.recv(self.sck)
            ret['service_id_array'][i] = self.pck.get_data(U_TP_I)
            ret['service_type_array'][i] = self.pck.get_data(U_TP_I)
            ret['service_name_array'][i] = self.pck.get_data(U_TP_S)
            ret['comment_array'][i] = self.pck.get_data(U_TP_S)
            ret['link_by_default_array'][i] = self.pck.get_data(U_TP_I)
            ret['is_dynamic_array'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_tariff(self, params):
        """ description
        @params: 
        :(s)  name :	(s)  - 
        :(s)  expire_date :	(i)  - 
        :(s)  is_blocked :	(i)  - 
        :(s)  balance_rollover :	(i)  - 
        @returns: 
        :(s)  tp_id :	(i)  - 
        """
        if not self.urfa_call(0x3012):
            raise Exception("Fail of urfa_call(0x3012) [rpcf_add_tariff]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.add_data(params['expire_date'], U_TP_I)
        self.pck.add_data(params['is_blocked'], U_TP_I)
        self.pck.add_data(params['balance_rollover'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['tp_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_tariff(self, params):
        """ description
        @params: 
        :(s)  tp_id :	(i)  - 
        :(s)  name :	(s)  - 
        :(s)  expire_date :	(i)  - 
        :(s)  is_blocked :	(i)  - 
        :(s)  balance_rollover :	(i)  - 
        @returns: 
        :(s)  tp_id :	(i)  - 
        """
        if not self.urfa_call(0x3013):
            raise Exception("Fail of urfa_call(0x3013) [rpcf_edit_tariff]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['tp_id'], U_TP_I)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.add_data(params['expire_date'], U_TP_I)
        self.pck.add_data(params['is_blocked'], U_TP_I)
        self.pck.add_data(params['balance_rollover'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['tp_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_del_service_from_tariff(self, params):
        """ description
        @params: 
        :(s)  tp_id :	(i)  - 
        :(s)  sid :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x3015):
            raise Exception("Fail of urfa_call(0x3015) [rpcf_del_service_from_tariff]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['tp_id'], U_TP_I)
        self.pck.add_data(params['sid'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_user_tariffs(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  account_id :	(i) = _def_  - 
        @returns: 
        :(s)  user_tariffs_size :	(i)  - 
        :(s)    tariff_current_array :	(i)  - 
        :(s)    tariff_next_array :	(i)  - 
        :(s)    discount_period_id_array :	(i)  - 
        :(s)    tariff_link_id_array :	(i)  - 
        """
        if not self.urfa_call(0x3017):
            raise Exception("Fail of urfa_call(0x3017) [rpcf_get_user_tariffs]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['user_tariffs_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['user_tariffs_size']): 
            self.pck.recv(self.sck)
            ret['tariff_current_array'][i] = self.pck.get_data(U_TP_I)
            ret['tariff_next_array'][i] = self.pck.get_data(U_TP_I)
            ret['discount_period_id_array'][i] = self.pck.get_data(U_TP_I)
            ret['tariff_link_id_array'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_link_user_tariff(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  account_id :	(i) = _def_  - 
        :(s)  tariff_current :	(i)  - 
        :(s)  tariff_next :	(i) = _def_  - 
        :(s)  discount_period_id :	(i)  - 
        :(s)  tariff_link_id :	(i) = _def_  - 
        :(s)  change_now :	(i)  - 
        @returns: 
        :(s)  tariff_link_id :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        """
        if not self.urfa_call(0x301f):
            raise Exception("Fail of urfa_call(0x301f) [rpcf_link_user_tariff]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['tariff_current'], U_TP_I)
        if 'tariff_next' not in params: params['tariff_next'] = params['tariff_current']
        self.pck.add_data(params['tariff_next'], U_TP_I)
        self.pck.add_data(params['discount_period_id'], U_TP_I)
        if 'tariff_link_id' not in params: params['tariff_link_id'] = 0
        self.pck.add_data(params['tariff_link_id'], U_TP_I)
        self.pck.add_data(params['change_now'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['tariff_link_id'] = self.pck.get_data(U_TP_I)
        if params['tariff_link_id']  ==  0:
            ret['error'] = dict({13:"unable to link user tariff"})
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_unlink_user_tariff(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  account_id :	(i) = _def_  - 
        :(s)  tariff_link_id :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x3019):
            raise Exception("Fail of urfa_call(0x3019) [rpcf_unlink_user_tariff]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['tariff_link_id'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_tps_for_user(self, params):
        """ description
        @params: 
        :(s)  uid :	(i)  - 
        :(s)  aid :	(i)  - 
        :(s)  tpid :	(i)  - 
        :(s)  tplink :	(i)  - 
        :(s)  unused :	(i)  - 
        @returns: 
        :(s)  service_size :	(i)  - 
        :(s)    sid :	(i)  - 
        :(s)    service_name :	(s)  - 
        :(s)    service_type :	(i)  - 
        :(s)    comment :	(s)  - 
        :(s)    slink :	(i)  - 
        :(s)    value :	(i)  - 
        """
        if not self.urfa_call(0x301a):
            raise Exception("Fail of urfa_call(0x301a) [rpcf_get_tps_for_user]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['uid'], U_TP_I)
        self.pck.add_data(params['aid'], U_TP_I)
        self.pck.add_data(params['tpid'], U_TP_I)
        self.pck.add_data(params['tplink'], U_TP_I)
        self.pck.add_data(params['unused'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['service_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['service_size']): 
            self.pck.recv(self.sck)
            ret['sid'][i] = self.pck.get_data(U_TP_I)
            ret['service_name'][i] = self.pck.get_data(U_TP_S)
            ret['service_type'][i] = self.pck.get_data(U_TP_I)
            ret['comment'][i] = self.pck.get_data(U_TP_S)
            ret['slink'][i] = self.pck.get_data(U_TP_I)
            ret['value'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_remove_tariff(self, params):
        """ description
        @params: 
        :(s)  tid :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x301b):
            raise Exception("Fail of urfa_call(0x301b) [rpcf_remove_tariff]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['tid'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_tariffs_history(self, params):
        """ description
        @params: 
        :(s)  aid :	(i)  - 
        @returns: 
        :(s)  th_count :	(i)  - 
        :(s)    tariff_id :	(i)  - 
        :(s)    link_date :	(i)  - 
        :(s)    unlink_date :	(i)  - 
        :(s)    tariff_name :	(s)  - 
        """
        if not self.urfa_call(0x301c):
            raise Exception("Fail of urfa_call(0x301c) [rpcf_get_tariffs_history]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['aid'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['th_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['th_count']): 
            self.pck.recv(self.sck)
            ret['tariff_id'][i] = self.pck.get_data(U_TP_I)
            ret['link_date'][i] = self.pck.get_data(U_TP_I)
            ret['unlink_date'][i] = self.pck.get_data(U_TP_I)
            ret['tariff_name'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_tariff_id_by_name(self, params):
        """ description
        @params: 
        :(s)  name :	(s)  - 
        @returns: 
        :(s)  tid :	(i)  - 
        """
        if not self.urfa_call(0x301d):
            raise Exception("Fail of urfa_call(0x301d) [rpcf_get_tariff_id_by_name]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['tid'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_general_report_new(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i) = _def_  - 
        :(s)  account_id :	(i) = _def_  - 
        :(s)  group_id :	(i) = _def_  - 
        :(s)  discount_period_id :	(i) = _def_  - 
        :(s)  start_date :	(i)  - 
        :(s)  end_date :	(i) = _def_  - 
        @returns: 
        :(s)  accounts_count :	(i)  - 
        :(s)    account_id :	(i)  - 
        :(s)    login :	(s)  - 
        :(s)    full_name :	(s)  - 
        :(s)    incoming_rest :	(d)  - 
        :(s)    discounted_once :	(d)  - 
        :(s)    discounted_periodic :	(d)  - 
        :(s)    discounted_iptraffic :	(d)  - 
        :(s)    discounted_hotspot :	(d)  - 
        :(s)    discounted_dialup :	(d)  - 
        :(s)    discounted_telephony :	(d)  - 
        :(s)    discounted_other_charges :	(d)  - 
        :(s)    tax :	(d)  - 
        :(s)    discounted_with_tax :	(d)  - 
        :(s)    payments :	(d)  - 
        :(s)    outgoing_rest :	(d)  - 
        """
        if not self.urfa_call(0x3022):
            raise Exception("Fail of urfa_call(0x3022) [rpcf_general_report_new]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'user_id' not in params: params['user_id'] = 0
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        if 'group_id' not in params: params['group_id'] = 0
        self.pck.add_data(params['group_id'], U_TP_I)
        if 'discount_period_id' not in params: params['discount_period_id'] = 0
        self.pck.add_data(params['discount_period_id'], U_TP_I)
        self.pck.add_data(params['start_date'], U_TP_I)
        if 'end_date' not in params: params['end_date'] = now()
        self.pck.add_data(params['end_date'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['accounts_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['accounts_count']): 
            self.pck.recv(self.sck)
            ret['account_id'][i] = self.pck.get_data(U_TP_I)
            ret['login'][i] = self.pck.get_data(U_TP_S)
            ret['full_name'][i] = self.pck.get_data(U_TP_S)
            ret['incoming_rest'][i] = self.pck.get_data(U_TP_D)
            ret['discounted_once'][i] = self.pck.get_data(U_TP_D)
            ret['discounted_periodic'][i] = self.pck.get_data(U_TP_D)
            ret['discounted_iptraffic'][i] = self.pck.get_data(U_TP_D)
            ret['discounted_hotspot'][i] = self.pck.get_data(U_TP_D)
            ret['discounted_dialup'][i] = self.pck.get_data(U_TP_D)
            ret['discounted_telephony'][i] = self.pck.get_data(U_TP_D)
            ret['discounted_other_charges'][i] = self.pck.get_data(U_TP_D)
            ret['tax'][i] = self.pck.get_data(U_TP_D)
            ret['discounted_with_tax'][i] = self.pck.get_data(U_TP_D)
            ret['payments'][i] = self.pck.get_data(U_TP_D)
            ret['outgoing_rest'][i] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_payment_methods_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  payments_list_count :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    name :	(s)  - 
        """
        if not self.urfa_call(0x3100):
            raise Exception("Fail of urfa_call(0x3100) [rpcf_get_payment_methods_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['payments_list_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['payments_list_count']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['name'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_payment_method(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        :(s)  name :	(s)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x3101):
            raise Exception("Fail of urfa_call(0x3101) [rpcf_add_payment_method]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_payment_method(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        :(s)  name :	(s)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x3102):
            raise Exception("Fail of urfa_call(0x3102) [rpcf_edit_payment_method]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_payment_for_account(self, params):
        """ description
        @params: 
        :(s)  account_id :	(i)  - 
        :(s)  unused :	(i) = _def_  - 
        :(s)  payment :	(d)  - 
        :(s)  currency_id :	(i) = _def_  - 
        :(s)  payment_date :	(i) = _def_  - 
        :(s)  burn_date :	(i) = _def_  - 
        :(s)  payment_method :	(i) = _def_  - 
        :(s)  admin_comment :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  payment_ext_number :	(s)  - 
        :(s)  payment_to_invoice :	(i) = _def_  - 
        :(s)  turn_on_inet :	(i) = _def_  - 
        @returns: 
        :(s)  payment_transaction_id :	(i)  - 
        """
        if not self.urfa_call(0x3110):
            raise Exception("Fail of urfa_call(0x3110) [rpcf_add_payment_for_account]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['account_id'], U_TP_I)
        if 'unused' not in params: params['unused'] = 0
        self.pck.add_data(params['unused'], U_TP_I)
        self.pck.add_data(params['payment'], U_TP_D)
        if 'currency_id' not in params: params['currency_id'] = 810
        self.pck.add_data(params['currency_id'], U_TP_I)
        if 'payment_date' not in params: params['payment_date'] = now()
        self.pck.add_data(params['payment_date'], U_TP_I)
        if 'burn_date' not in params: params['burn_date'] = 0
        self.pck.add_data(params['burn_date'], U_TP_I)
        if 'payment_method' not in params: params['payment_method'] = 1
        self.pck.add_data(params['payment_method'], U_TP_I)
        self.pck.add_data(params['admin_comment'], U_TP_S)
        self.pck.add_data(params['comment'], U_TP_S)
        self.pck.add_data(params['payment_ext_number'], U_TP_S)
        if 'payment_to_invoice' not in params: params['payment_to_invoice'] = 0
        self.pck.add_data(params['payment_to_invoice'], U_TP_I)
        if 'turn_on_inet' not in params: params['turn_on_inet'] = 1
        self.pck.add_data(params['turn_on_inet'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['payment_transaction_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_cancel_payment_for_account(self, params):
        """ description
        @params: 
        :(s)  pay_t_id :	(i)  - 
        :(s)  com_for_user :	(s)  - 
        :(s)  com_for_admin :	(s)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x3111):
            raise Exception("Fail of urfa_call(0x3111) [rpcf_cancel_payment_for_account]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['pay_t_id'], U_TP_I)
        self.pck.add_data(params['com_for_user'], U_TP_S)
        self.pck.add_data(params['com_for_admin'], U_TP_S)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_payment_for_account_notify(self, params):
        """ description
        @params: 
        :(s)  account_id :	(i)  - 
        :(s)  param :	(i)  - 
        :(s)  payment_incurrency :	(d)  - 
        :(s)  currency_id :	(i)  - 
        :(s)  actual_date :	(i)  - 
        :(s)  burn_time :	(i)  - 
        :(s)  method :	(i)  - 
        :(s)  admin_comment :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  payment_ext_number :	(s)  - 
        :(s)  payment_to_invoice :	(i)  - 
        :(s)  turn_on_inet :	(i)  - 
        :(s)  notify :	(i)  - 
        :(s)  hash :	(s)  - 
        @returns: 
        :(s)  payment_transaction_id :	(i)  - 
        """
        if not self.urfa_call(0x3113):
            raise Exception("Fail of urfa_call(0x3113) [rpcf_add_payment_for_account_notify]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['param'], U_TP_I)
        self.pck.add_data(params['payment_incurrency'], U_TP_D)
        self.pck.add_data(params['currency_id'], U_TP_I)
        self.pck.add_data(params['actual_date'], U_TP_I)
        self.pck.add_data(params['burn_time'], U_TP_I)
        self.pck.add_data(params['method'], U_TP_I)
        self.pck.add_data(params['admin_comment'], U_TP_S)
        self.pck.add_data(params['comment'], U_TP_S)
        self.pck.add_data(params['payment_ext_number'], U_TP_S)
        self.pck.add_data(params['payment_to_invoice'], U_TP_I)
        self.pck.add_data(params['turn_on_inet'], U_TP_I)
        self.pck.add_data(params['notify'], U_TP_I)
        self.pck.add_data(params['hash'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['payment_transaction_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_custom_services_report(self, params):
        """ description
        @params: 
        :(s)  t_start :	(i) = _def_  - 
        :(s)  t_end :	(i) = _def_  - 
        :(s)  account_id :	(i) = _def_  - 
        :(s)  user_id :	(i) = _def_  - 
        @returns: 
        :(s)  count :	(i)  - 
        :(s)    account_id :	(i)  - 
        :(s)    login :	(s)  - 
        :(s)    date :	(i)  - 
        :(s)    mark :	(s)  - 
        :(s)    amount :	(d)  - 
        :(s)    amount_with_tax :	(d)  - 
        :(s)    service_name :	(s)  - 
        :(s)    service_key :	(s)  - 
        :(s)    revoked :	(i)  - 
        """
        if not self.urfa_call(0x3114):
            raise Exception("Fail of urfa_call(0x3114) [rpcf_custom_services_report]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 't_start' not in params: params['t_start'] = 0
        self.pck.add_data(params['t_start'], U_TP_I)
        if 't_end' not in params: params['t_end'] = now()
        self.pck.add_data(params['t_end'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        if 'user_id' not in params: params['user_id'] = 0
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['count']): 
            self.pck.recv(self.sck)
            ret['account_id'] = self.pck.get_data(U_TP_I)
            ret['login'] = self.pck.get_data(U_TP_S)
            ret['date'] = self.pck.get_data(U_TP_I)
            ret['mark'] = self.pck.get_data(U_TP_S)
            ret['amount'] = self.pck.get_data(U_TP_D)
            ret['amount_with_tax'] = self.pck.get_data(U_TP_D)
            ret['service_name'] = self.pck.get_data(U_TP_S)
            ret['service_key'] = self.pck.get_data(U_TP_S)
            ret['revoked'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_card_list(self, params):
        """ description
        @params: 
        :(s)  pool_id :	(i)  - 
        @returns: 
        :(s)  cpi_owners_size :	(i)  - 
        :(s)    owners :	(i)  - 
        :(s)  info_size :	(i)  - 
        :(s)  time0 :	(i)  - 
        :(s)    card_id :	(i)  - 
        :(s)    pool_id :	(i)  - 
        :(s)    secret :	(s)  - 
        :(s)    balance :	(d)  - 
        :(s)    currency :	(i)  - 
        :(s)    expire :	(i)  - 
        :(s)    days :	(i)  - 
        :(s)    is_used :	(i)  - 
        :(s)    tp_id :	(i)  - 
        :(s)    is_blocked :	(i)  - 
        """
        if not self.urfa_call(0x4200):
            raise Exception("Fail of urfa_call(0x4200) [rpcf_card_list]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['pool_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['cpi_owners_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['cpi_owners_size']): 
            self.pck.recv(self.sck)
            ret['owners'][i] = self.pck.get_data(U_TP_I)
        self.pck.recv(self.sck)
        ret['info_size'] = self.pck.get_data(U_TP_I)
        ret['time0'] = self.pck.get_data(U_TP_I)
        for i in range(ret['info_size']): 
            self.pck.recv(self.sck)
            ret['card_id'][i] = self.pck.get_data(U_TP_I)
            ret['pool_id'][i] = self.pck.get_data(U_TP_I)
            ret['secret'][i] = self.pck.get_data(U_TP_S)
            ret['balance'][i] = self.pck.get_data(U_TP_D)
            ret['currency'][i] = self.pck.get_data(U_TP_I)
            ret['expire'][i] = self.pck.get_data(U_TP_I)
            ret['days'][i] = self.pck.get_data(U_TP_I)
            ret['is_used'][i] = self.pck.get_data(U_TP_I)
            ret['tp_id'][i] = self.pck.get_data(U_TP_I)
            ret['is_blocked'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_card_pool_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  info_size :	(i)  - 
        :(s)    pool_id :	(i)  - 
        :(s)    cards :	(i)  - 
        :(s)    cards_used :	(i)  - 
        :(s)    first_update :	(i)  - 
        :(s)    last_update :	(i)  - 
        """
        if not self.urfa_call(0x4201):
            raise Exception("Fail of urfa_call(0x4201) [rpcf_card_pool_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['info_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['info_size']): 
            self.pck.recv(self.sck)
            ret['pool_id'][i] = self.pck.get_data(U_TP_I)
            ret['cards'][i] = self.pck.get_data(U_TP_I)
            ret['cards_used'][i] = self.pck.get_data(U_TP_I)
            ret['first_update'][i] = self.pck.get_data(U_TP_I)
            ret['last_update'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_card_add(self, params):
        """ description
        @params: 
        :(s)  secret :	(s)  - 
        :(s)  balance :	(d)  - 
        :(s)  currency :	(i)  - 
        :(s)  expire :	(i)  - 
        :(s)  days :	(i)  - 
        :(s)  is_used :	(i)  - 
        :(s)  tp_id :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x4202):
            raise Exception("Fail of urfa_call(0x4202) [rpcf_card_add]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['secret'], U_TP_S)
        self.pck.add_data(params['balance'], U_TP_D)
        self.pck.add_data(params['currency'], U_TP_I)
        self.pck.add_data(params['expire'], U_TP_I)
        self.pck.add_data(params['days'], U_TP_I)
        self.pck.add_data(params['is_used'], U_TP_I)
        self.pck.add_data(params['tp_id'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_card_pool_add(self, params):
        """ description
        @params: 
        :(s)  pool_id :	(i) = _def_  - 
        :(s)  sec_size :	(i) = _def_  - 
        :(s)  delay :	(i) = _def_  - 
        :(s)  size :	(i)  - 
        :(s)  balance :	(d)  - 
        :(s)  currency :	(i) = _def_  - 
        :(s)  expire :	(i) = _def_  - 
        :(s)  days :	(i) = _def_  - 
        :(s)  service_id :	(i) = _def_  - 
        :(s)  random :	(i) = _def_  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x4203):
            raise Exception("Fail of urfa_call(0x4203) [rpcf_card_pool_add]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'pool_id' not in params: params['pool_id'] = 0
        self.pck.add_data(params['pool_id'], U_TP_I)
        if 'sec_size' not in params: params['sec_size'] = 8
        self.pck.add_data(params['sec_size'], U_TP_I)
        if 'delay' not in params: params['delay'] = 0
        self.pck.add_data(params['delay'], U_TP_I)
        self.pck.add_data(params['size'], U_TP_I)
        self.pck.add_data(params['balance'], U_TP_D)
        if 'currency' not in params: params['currency'] = 810
        self.pck.add_data(params['currency'], U_TP_I)
        if 'expire' not in params: params['expire'] = max_time()
        self.pck.add_data(params['expire'], U_TP_I)
        if 'days' not in params: params['days'] = 0
        self.pck.add_data(params['days'], U_TP_I)
        if 'service_id' not in params: params['service_id'] = 0
        self.pck.add_data(params['service_id'], U_TP_I)
        if 'random' not in params: params['random'] = 0
        self.pck.add_data(params['random'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_block_card(self, params):
        """ description
        @params: 
        :(s)  card_id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x4204):
            raise Exception("Fail of urfa_call(0x4204) [rpcf_block_card]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['card_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_unblock_card(self, params):
        """ description
        @params: 
        :(s)  card_id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x4205):
            raise Exception("Fail of urfa_call(0x4205) [rpcf_unblock_card]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['card_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_move_expired_cards(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x4206):
            raise Exception("Fail of urfa_call(0x4206) [rpcf_move_expired_cards]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_delete_card_owner(self, params):
        """ description
        @params: 
        :(s)  pool_id :	(i)  - 
        :(s)  owned_id :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x4290):
            raise Exception("Fail of urfa_call(0x4290) [rpcf_delete_card_owner]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['pool_id'], U_TP_I)
        self.pck.add_data(params['owned_id'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_card_owner(self, params):
        """ description
        @params: 
        :(s)  pool_id :	(i)  - 
        :(s)  owned_id :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x4291):
            raise Exception("Fail of urfa_call(0x4291) [rpcf_add_card_owner]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['pool_id'], U_TP_I)
        self.pck.add_data(params['owned_id'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_settings_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  values_size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    name :	(s)  - 
        :(s)    value :	(s)  - 
        """
        if not self.urfa_call(0x4400):
            raise Exception("Fail of urfa_call(0x4400) [rpcf_get_settings_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['values_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['values_size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['name'][i] = self.pck.get_data(U_TP_S)
            ret['value'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_setting(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        :(s)  variable :	(s)  - 
        :(s)  old_value :	(s)  - 
        :(s)  new_value :	(s)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x4401):
            raise Exception("Fail of urfa_call(0x4401) [rpcf_add_setting]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['variable'], U_TP_S)
        self.pck.add_data(params['old_value'], U_TP_S)
        self.pck.add_data(params['new_value'], U_TP_S)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_setting(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        :(s)  variable :	(s)  - 
        :(s)  param :	(s)  - 
        :(s)  new_value :	(s)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x4402):
            raise Exception("Fail of urfa_call(0x4402) [rpcf_edit_setting]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['variable'], U_TP_S)
        self.pck.add_data(params['param'], U_TP_S)
        self.pck.add_data(params['new_value'], U_TP_S)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_remove_setting(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x4403):
            raise Exception("Fail of urfa_call(0x4403) [rpcf_remove_setting]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_setting(self, params):
        """ description
        @params: 
        :(s)  variable :	(s)  - 
        @returns: 
        :(s)  values_count :	(i)  - 
        :(s)    value :	(s)  - 
        """
        if not self.urfa_call(0x4404):
            raise Exception("Fail of urfa_call(0x4404) [rpcf_get_setting]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['variable'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['values_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['values_count']): 
            self.pck.recv(self.sck)
            ret['value'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_sys_users_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  info_size :	(i)  - 
        :(s)    user_id :	(i)  - 
        :(s)    login :	(s)  - 
        :(s)    ip4_address :	(i)  - 
        :(s)    mask4 :	(i)  - 
        :(s)    ip6_address :	(i)  - 
        :(s)    mask6 :	(i)  - 
        """
        if not self.urfa_call(0x4413):
            raise Exception("Fail of urfa_call(0x4413) [rpcf_get_sys_users_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['info_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['info_size']): 
            self.pck.recv(self.sck)
            ret['user_id'][i] = self.pck.get_data(U_TP_I)
            ret['login'][i] = self.pck.get_data(U_TP_S)
            ret['ip4_address'][i] = self.pck.get_data(U_TP_IP)
            ret['mask4'][i] = self.pck.get_data(U_TP_I)
            ret['ip6_address'][i] = self.pck.get_data(U_TP_IP)
            ret['mask6'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_sys_user(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  login :	(s)  - 
        :(s)  password :	(s)  - 
        :(s)  ip4_address :	(i)  - 
        :(s)  mask4 :	(i)  - 
        :(s)  ip6_address :	(i)  - 
        :(s)  mask6 :	(i)  - 
        :(s)  groups_size :	(i)  - 
        :(s)    group_id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x4415):
            raise Exception("Fail of urfa_call(0x4415) [rpcf_add_sys_user]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['login'], U_TP_S)
        self.pck.add_data(params['password'], U_TP_S)
        self.pck.add_data(params['ip4_address'], U_TP_IP)
        self.pck.add_data(params['mask4'], U_TP_I)
        self.pck.add_data(params['ip6_address'], U_TP_IP)
        self.pck.add_data(params['mask6'], U_TP_I)
        self.pck.add_data(params['groups_size'], U_TP_I)
        for i in range(len(params['group_id'])):
            self.pck.add_data(params['group_id'][i], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_sys_user(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  login :	(s)  - 
        :(s)  password :	(s)  - 
        :(s)  ip4_address :	(i)  - 
        :(s)  mask4 :	(i)  - 
        :(s)  ip6_address :	(i)  - 
        :(s)  mask6 :	(i)  - 
        :(s)  groups_size :	(i)  - 
        :(s)    group_id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x4416):
            raise Exception("Fail of urfa_call(0x4416) [rpcf_edit_sys_user]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['login'], U_TP_S)
        self.pck.add_data(params['password'], U_TP_S)
        self.pck.add_data(params['ip4_address'], U_TP_IP)
        self.pck.add_data(params['mask4'], U_TP_I)
        self.pck.add_data(params['ip6_address'], U_TP_IP)
        self.pck.add_data(params['mask6'], U_TP_I)
        self.pck.add_data(params['groups_size'], U_TP_I)
        for i in range(len(params['group_id'])):
            self.pck.add_data(params['group_id'][i], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_sysuser_name(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        @returns: 
        :(s)  login :	(s)  - 
        """
        if not self.urfa_call(0x4408):
            raise Exception("Fail of urfa_call(0x4408) [rpcf_get_sysuser_name]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['login'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_sys_user(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        @returns: 
        :(s)  login :	(s)  - 
        :(s)  ip4 :	(i)  - 
        :(s)  mask4 :	(i)  - 
        :(s)  ip6 :	(i)  - 
        :(s)  mask6 :	(i)  - 
        :(s)  groups_size :	(i)  - 
        :(s)    group_id :	(i)  - 
        :(s)    group_name :	(s)  - 
        :(s)    group_info :	(s)  - 
        """
        if not self.urfa_call(0x4414):
            raise Exception("Fail of urfa_call(0x4414) [rpcf_get_sys_user]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['login'] = self.pck.get_data(U_TP_S)
        ret['ip4'] = self.pck.get_data(U_TP_IP)
        ret['mask4'] = self.pck.get_data(U_TP_I)
        ret['ip6'] = self.pck.get_data(U_TP_IP)
        ret['mask6'] = self.pck.get_data(U_TP_I)
        ret['groups_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['groups_size']): 
            self.pck.recv(self.sck)
            ret['group_id'][i] = self.pck.get_data(U_TP_I)
            ret['group_name'][i] = self.pck.get_data(U_TP_S)
            ret['group_info'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_whoami(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  my_uid :	(i)  - 
        :(s)  login :	(s)  - 
        :(s)  user_ip4 :	(i)  - 
        :(s)  user_mask4 :	(i)  - 
        :(s)  user_ip6 :	(i)  - 
        :(s)  user_mask6 :	(i)  - 
        :(s)  system_group_size :	(i)  - 
        :(s)    system_group_id :	(i)  - 
        :(s)    system_group_name :	(s)  - 
        :(s)    system_group_info :	(s)  - 
        :(s)  allowed_fids_size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    name :	(s)  - 
        :(s)    module :	(s)  - 
        :(s)  not_allowed_size :	(i)  - 
        :(s)    id_not_allowed :	(i)  - 
        :(s)    name_not_allowed :	(s)  - 
        :(s)    module_not_allowed :	(s)  - 
        """
        if not self.urfa_call(0x4417):
            raise Exception("Fail of urfa_call(0x4417) [rpcf_whoami]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['my_uid'] = self.pck.get_data(U_TP_I)
        ret['login'] = self.pck.get_data(U_TP_S)
        ret['user_ip4'] = self.pck.get_data(U_TP_IP)
        ret['user_mask4'] = self.pck.get_data(U_TP_I)
        ret['user_ip6'] = self.pck.get_data(U_TP_IP)
        ret['user_mask6'] = self.pck.get_data(U_TP_I)
        ret['system_group_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['system_group_size']): 
            self.pck.recv(self.sck)
            ret['system_group_id'][i] = self.pck.get_data(U_TP_I)
            ret['system_group_name'][i] = self.pck.get_data(U_TP_S)
            ret['system_group_info'][i] = self.pck.get_data(U_TP_S)
        self.pck.recv(self.sck)
        ret['allowed_fids_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['allowed_fids_size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['name'][i] = self.pck.get_data(U_TP_S)
            ret['module'][i] = self.pck.get_data(U_TP_S)
        self.pck.recv(self.sck)
        ret['not_allowed_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['not_allowed_size']): 
            self.pck.recv(self.sck)
            ret['id_not_allowed'][i] = self.pck.get_data(U_TP_I)
            ret['name_not_allowed'][i] = self.pck.get_data(U_TP_S)
            ret['module_not_allowed'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_uaparam_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  uparam_size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    name :	(s)  - 
        :(s)    display_name :	(s)  - 
        :(s)    visible :	(i)  - 
        """
        if not self.urfa_call(0x440b):
            raise Exception("Fail of urfa_call(0x440b) [rpcf_get_uaparam_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['uparam_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['uparam_size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['name'][i] = self.pck.get_data(U_TP_S)
            ret['display_name'][i] = self.pck.get_data(U_TP_S)
            ret['visible'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_uaparam(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        :(s)  name :	(s)  - 
        :(s)  display_name :	(s)  - 
        :(s)  visible :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x440c):
            raise Exception("Fail of urfa_call(0x440c) [rpcf_add_uaparam]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.add_data(params['display_name'], U_TP_S)
        self.pck.add_data(params['visible'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_del_uaparam(self, params):
        """ description
        @params: 
        :(s)  uaparam_id :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x440d):
            raise Exception("Fail of urfa_call(0x440d) [rpcf_del_uaparam]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['uaparam_id'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_uaparam(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        :(s)  name :	(s)  - 
        :(s)  display_name :	(s)  - 
        :(s)  visible :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x440e):
            raise Exception("Fail of urfa_call(0x440e) [rpcf_edit_uaparam]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.add_data(params['display_name'], U_TP_S)
        self.pck.add_data(params['visible'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_delete_sys_user(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x4410):
            raise Exception("Fail of urfa_call(0x4410) [rpcf_delete_sys_user]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_messages_list(self, params):
        """ description
        @params: 
        :(s)  time_start :	(l)  - 
        :(s)  time_end :	(l)  - 
        :(s)  deprecated :	(i)  - 
        @returns: 
        :(s)  message_size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    send_date :	(i)  - 
        :(s)    recv_date :	(i)  - 
        :(s)    sender_id :	(i)  - 
        :(s)    subject :	(s)  - 
        :(s)    message :	(s)  - 
        :(s)    mime :	(s)  - 
        :(s)    state :	(i)  - 
        """
        if not self.urfa_call(0x5000):
            raise Exception("Fail of urfa_call(0x5000) [rpcf_get_messages_list]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['time_start'], U_TP_L)
        self.pck.add_data(params['time_end'], U_TP_L)
        self.pck.add_data(params['deprecated'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['message_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['message_size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['send_date'][i] = self.pck.get_data(U_TP_I)
            ret['recv_date'][i] = self.pck.get_data(U_TP_I)
            ret['sender_id'][i] = self.pck.get_data(U_TP_I)
            ret['subject'][i] = self.pck.get_data(U_TP_S)
            ret['message'][i] = self.pck.get_data(U_TP_S)
            ret['mime'][i] = self.pck.get_data(U_TP_S)
            ret['state'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_message(self, params):
        """ description
        @params: 
        :(s)  receiver_id :	(i)  - 
        :(s)  subject :	(s)  - 
        :(s)  message :	(s)  - 
        :(s)  mime :	(s)  - 
        :(s)  is_for_all :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x5001):
            raise Exception("Fail of urfa_call(0x5001) [rpcf_add_message]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['receiver_id'], U_TP_I)
        self.pck.add_data(params['subject'], U_TP_S)
        self.pck.add_data(params['message'], U_TP_S)
        self.pck.add_data(params['mime'], U_TP_S)
        self.pck.add_data(params['is_for_all'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_routers_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  routers_size :	(i)  - 
        :(s)    router_id :	(i)  - 
        :(s)    router_type :	(i)  - 
        :(s)    router_ip :	(s)  - 
        :(s)    login :	(s)  - 
        :(s)    password :	(s)  - 
        :(s)    router_comments :	(s)  - 
        :(s)    router_bin_ip :	(i)  - 
        :(s)    is_online :	(i)  - 
        """
        if not self.urfa_call(0x5043):
            raise Exception("Fail of urfa_call(0x5043) [rpcf_get_routers_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['routers_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['routers_size']): 
            self.pck.recv(self.sck)
            ret['router_id'][i] = self.pck.get_data(U_TP_I)
            ret['router_type'][i] = self.pck.get_data(U_TP_I)
            ret['router_ip'][i] = self.pck.get_data(U_TP_S)
            ret['login'][i] = self.pck.get_data(U_TP_S)
            ret['password'][i] = self.pck.get_data(U_TP_S)
            ret['router_comments'][i] = self.pck.get_data(U_TP_S)
            ret['router_bin_ip'][i] = self.pck.get_data(U_TP_IP)
            ret['is_online'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_put_router(self, params):
        """ description
        @params: 
        :(s)  router_id :	(i) = _def_  - 
        :(s)  router_type :	(i)  - 
        :(s)  router_ip :	(s)  - 
        :(s)  login :	(s)  - 
        :(s)  password :	(s)  - 
        :(s)  router_comments :	(s)  - 
        :(s)  router_bin_ip :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x501d):
            raise Exception("Fail of urfa_call(0x501d) [rpcf_put_router]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'router_id' not in params: params['router_id'] = 0
        self.pck.add_data(params['router_id'], U_TP_I)
        self.pck.add_data(params['router_type'], U_TP_I)
        self.pck.add_data(params['router_ip'], U_TP_S)
        self.pck.add_data(params['login'], U_TP_S)
        self.pck.add_data(params['password'], U_TP_S)
        self.pck.add_data(params['router_comments'], U_TP_S)
        self.pck.add_data(params['router_bin_ip'], U_TP_IP)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_del_router(self, params):
        """ description
        @params: 
        :(s)  router_id :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x5007):
            raise Exception("Fail of urfa_call(0x5007) [rpcf_del_router]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['router_id'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_version_info(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  name :	(s)  - 
        :(s)  country :	(s)  - 
        :(s)  region :	(s)  - 
        :(s)  city :	(s)  - 
        :(s)  address :	(s)  - 
        :(s)  email :	(s)  - 
        :(s)  tel :	(s)  - 
        :(s)  web :	(s)  - 
        """
        if not self.urfa_call(0x5010):
            raise Exception("Fail of urfa_call(0x5010) [rpcf_get_version_info]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['name'] = self.pck.get_data(U_TP_S)
        ret['country'] = self.pck.get_data(U_TP_S)
        ret['region'] = self.pck.get_data(U_TP_S)
        ret['city'] = self.pck.get_data(U_TP_S)
        ret['address'] = self.pck.get_data(U_TP_S)
        ret['email'] = self.pck.get_data(U_TP_S)
        ret['tel'] = self.pck.get_data(U_TP_S)
        ret['web'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_nas_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  nas_size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    nas_id :	(s)  - 
        :(s)    auth_secret :	(s)  - 
        :(s)    acct_secret :	(s)  - 
        :(s)    dac_secret :	(s)  - 
        :(s)    das_port :	(i)  - 
        :(s)    flags :	(i)  - 
        """
        if not self.urfa_call(0x5040):
            raise Exception("Fail of urfa_call(0x5040) [rpcf_get_nas_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['nas_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['nas_size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['nas_id'][i] = self.pck.get_data(U_TP_S)
            ret['auth_secret'][i] = self.pck.get_data(U_TP_S)
            ret['acct_secret'][i] = self.pck.get_data(U_TP_S)
            ret['dac_secret'][i] = self.pck.get_data(U_TP_S)
            ret['das_port'][i] = self.pck.get_data(U_TP_I)
            ret['flags'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_put_nas(self, params):
        """ description
        @params: 
        :(s)  mode :	(i)  - 
        :(s)  id :	(i)  - 
        :(s)  nas_id :	(s)  - 
        :(s)  auth_secret :	(s)  - 
        :(s)  acct_secret :	(s)  - 
        :(s)  dac_secret :	(s)  - 
        :(s)  das_port :	(i)  - 
        :(s)  flags :	(i)  - 
        :(s)  nas_size :	(i)  - 
        :(s)    variable :	(s)  - 
        :(s)    value :	(s)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x5044):
            raise Exception("Fail of urfa_call(0x5044) [rpcf_put_nas]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['mode'], U_TP_I)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['nas_id'], U_TP_S)
        self.pck.add_data(params['auth_secret'], U_TP_S)
        self.pck.add_data(params['acct_secret'], U_TP_S)
        self.pck.add_data(params['dac_secret'], U_TP_S)
        self.pck.add_data(params['das_port'], U_TP_I)
        self.pck.add_data(params['flags'], U_TP_I)
        self.pck.add_data(params['nas_size'], U_TP_I)
        for i in range(params['nas_size']):
            self.pck.add_data(params['variable'][i], U_TP_S)
            self.pck.add_data(params['value'][i], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_traffic_detailed(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i) = _def_  - 
        :(s)  account_id :	(i)  - 
        :(s)  apid :	(i)  - 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i)  - 
        @returns: 
        :(s)  nf5a_size :	(i)  - 
        :(s)    timestamp :	(i)  - 
        :(s)    slink_id :	(i)  - 
        :(s)    account_id :	(i)  - 
        :(s)    tclass :	(i)  - 
        :(s)    saddr :	(i)  - 
        :(s)    daddr :	(i)  - 
        :(s)    d_pkt :	(i)  - 
        :(s)    d_oct :	(i)  - 
        :(s)    sport :	(i)  - 
        :(s)    dport :	(i)  - 
        :(s)    tcp_flags :	(i)  - 
        :(s)    proto :	(i)  - 
        :(s)    tos :	(i)  - 
        """
        if not self.urfa_call(0x5018):
            raise Exception("Fail of urfa_call(0x5018) [rpcf_get_traffic_detailed]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'user_id' not in params: params['user_id'] = 0
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['apid'], U_TP_I)
        self.pck.add_data(params['time_start'], U_TP_I)
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['nf5a_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['nf5a_size']): 
            self.pck.recv(self.sck)
            ret['timestamp'][i] = self.pck.get_data(U_TP_I)
            ret['slink_id'][i] = self.pck.get_data(U_TP_I)
            ret['account_id'][i] = self.pck.get_data(U_TP_I)
            ret['tclass'][i] = self.pck.get_data(U_TP_I)
            ret['saddr'][i] = self.pck.get_data(U_TP_IP)
            ret['daddr'][i] = self.pck.get_data(U_TP_IP)
            ret['d_pkt'][i] = self.pck.get_data(U_TP_I)
            ret['d_oct'][i] = self.pck.get_data(U_TP_I)
            ret['sport'][i] = self.pck.get_data(U_TP_I)
            ret['dport'][i] = self.pck.get_data(U_TP_I)
            ret['tcp_flags'][i] = self.pck.get_data(U_TP_I)
            ret['proto'][i] = self.pck.get_data(U_TP_I)
            ret['tos'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_dhs_report(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  account_id :	(i)  - 
        :(s)  apid :	(i)  - 
        :(s)  t_start :	(i)  - 
        :(s)  t_end :	(i)  - 
        @returns: 
        :(s)  dhs_log_size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    account_id :	(i)  - 
        :(s)    slink_id :	(i)  - 
        :(s)    recv_date :	(i)  - 
        :(s)    last_update_date :	(i)  - 
        :(s)    Called_Station_Id :	(s)  - 
        :(s)    Calling_Station_Id :	(s)  - 
        :(s)    framed_ip4 :	(i)  - 
        :(s)    framed_ip6 :	(i)  - 
        :(s)    nas_port :	(i)  - 
        :(s)    acct_session_id :	(s)  - 
        :(s)    nas_port_type :	(i)  - 
        :(s)    uname :	(s)  - 
        :(s)    service_type :	(i)  - 
        :(s)    framed_protocol :	(i)  - 
        :(s)    nas_ip :	(i)  - 
        :(s)    nas_id :	(s)  - 
        :(s)    acct_status_type :	(i)  - 
        :(s)    acct_inp_pack :	(l)  - 
        :(s)    acct_inp_oct :	(l)  - 
        :(s)    acct_inp_giga :	(l)  - 
        :(s)    acct_out_pack :	(l)  - 
        :(s)    acct_out_oct :	(l)  - 
        :(s)    acct_out_giga :	(l)  - 
        :(s)    acct_sess_time :	(l)  - 
        :(s)    acct_term_cause :	(i)  - 
        :(s)    total_cost :	(d)  - 
        """
        if not self.urfa_call(0x5019):
            raise Exception("Fail of urfa_call(0x5019) [rpcf_get_dhs_report]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['apid'], U_TP_I)
        self.pck.add_data(params['t_start'], U_TP_I)
        self.pck.add_data(params['t_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['dhs_log_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['dhs_log_size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['account_id'][i] = self.pck.get_data(U_TP_I)
            ret['slink_id'][i] = self.pck.get_data(U_TP_I)
            ret['recv_date'][i] = self.pck.get_data(U_TP_I)
            ret['last_update_date'][i] = self.pck.get_data(U_TP_I)
            ret['Called_Station_Id'][i] = self.pck.get_data(U_TP_S)
            ret['Calling_Station_Id'][i] = self.pck.get_data(U_TP_S)
            ret['framed_ip4'][i] = self.pck.get_data(U_TP_IP)
            ret['framed_ip6'][i] = self.pck.get_data(U_TP_IP)
            ret['nas_port'][i] = self.pck.get_data(U_TP_I)
            ret['acct_session_id'][i] = self.pck.get_data(U_TP_S)
            ret['nas_port_type'][i] = self.pck.get_data(U_TP_I)
            ret['uname'][i] = self.pck.get_data(U_TP_S)
            ret['service_type'][i] = self.pck.get_data(U_TP_I)
            ret['framed_protocol'][i] = self.pck.get_data(U_TP_I)
            ret['nas_ip'][i] = self.pck.get_data(U_TP_I)
            ret['nas_id'][i] = self.pck.get_data(U_TP_S)
            ret['acct_status_type'][i] = self.pck.get_data(U_TP_I)
            ret['acct_inp_pack'][i] = self.pck.get_data(U_TP_L)
            ret['acct_inp_oct'][i] = self.pck.get_data(U_TP_L)
            ret['acct_inp_giga'][i] = self.pck.get_data(U_TP_L)
            ret['acct_out_pack'][i] = self.pck.get_data(U_TP_L)
            ret['acct_out_oct'][i] = self.pck.get_data(U_TP_L)
            ret['acct_out_giga'][i] = self.pck.get_data(U_TP_L)
            ret['acct_sess_time'][i] = self.pck.get_data(U_TP_L)
            ret['acct_term_cause'][i] = self.pck.get_data(U_TP_I)
            ret['total_cost'][i] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_dhcp_leases_report(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  account_id :	(i)  - 
        :(s)  apid :	(i)  - 
        :(s)  t_start :	(i)  - 
        :(s)  t_end :	(i)  - 
        @returns: 
        :(s)  lases_size :	(i)  - 
        :(s)    user_id :	(i)  - 
        :(s)    user_login :	(s)  - 
        :(s)    ip :	(i)  - 
        :(s)    mac :	(s)  - 
        :(s)    relay_agent_info :	(s)  - 
        :(s)    updated :	(i)  - 
        :(s)    expired :	(i)  - 
        """
        if not self.urfa_call(0x1354):
            raise Exception("Fail of urfa_call(0x1354) [rpcf_get_dhcp_leases_report]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['apid'], U_TP_I)
        self.pck.add_data(params['t_start'], U_TP_I)
        self.pck.add_data(params['t_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['lases_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['lases_size']): 
            self.pck.recv(self.sck)
            ret['user_id'][i] = self.pck.get_data(U_TP_I)
            ret['user_login'][i] = self.pck.get_data(U_TP_S)
            ret['ip'][i] = self.pck.get_data(U_TP_IP)
            ret['mac'][i] = self.pck.get_data(U_TP_S)
            ret['relay_agent_info'][i] = self.pck.get_data(U_TP_S)
            ret['updated'][i] = self.pck.get_data(U_TP_I)
            ret['expired'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_tel_report(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  account_id :	(i)  - 
        :(s)  apid :	(i)  - 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i)  - 
        @returns: 
        :(s)  dhs_log_size :	(i)  - 
        :(s)    count :	(i)  - 
        :(s)      id :	(i)  - 
        :(s)      account_id :	(i)  - 
        :(s)      slink_id :	(i)  - 
        :(s)      recv_date :	(i)  - 
        :(s)      start_time :	(i)  - 
        :(s)      end_time :	(i)  - 
        :(s)      Called_Station_Id :	(s)  - 
        :(s)      Calling_Station_Id :	(s)  - 
        :(s)      nas_port :	(i)  - 
        :(s)      acct_session_id :	(s)  - 
        :(s)      nas_port_type :	(i)  - 
        :(s)      uname :	(s)  - 
        :(s)      service_type :	(i)  - 
        :(s)      framed_protocol :	(i)  - 
        :(s)      nas_ip :	(i)  - 
        :(s)      nas_id :	(s)  - 
        :(s)      acct_status_type :	(i)  - 
        :(s)      acct_inp_pack :	(l)  - 
        :(s)      acct_inp_oct :	(l)  - 
        :(s)      acct_out_pack :	(l)  - 
        :(s)      acct_out_oct :	(l)  - 
        :(s)      zone_id :	(i)  - 
        :(s)      did :	(i)  - 
        :(s)      acct_sess_time :	(l)  - 
        :(s)      incoming_trunk :	(s)  - 
        :(s)      outgoing_trunk :	(s)  - 
        :(s)      pbx_id :	(s)  - 
        :(s)      flags :	(i)  - 
        :(s)      dcause :	(s)  - 
        :(s)      duration :	(l)  - 
        :(s)      base_cost :	(d)  - 
        :(s)      cost_mult :	(d)  - 
        :(s)      sum_cost :	(d)  - 
        """
        if not self.urfa_call(0x5037):
            raise Exception("Fail of urfa_call(0x5037) [rpcf_get_tel_report]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['apid'], U_TP_I)
        self.pck.add_data(params['time_start'], U_TP_I)
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['dhs_log_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['dhs_log_size']): 
            self.pck.recv(self.sck)
            ret['count'] = self.pck.get_data(U_TP_I)
            ret['count_array'][i]=ret['count']
            for j in range(ret['count']): 
                self.pck.recv(self.sck)
                if not i in ret['id']:ret['id'][i] = dict()
                ret['id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['account_id']:ret['account_id'][i] = dict()
                ret['account_id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['slink_id']:ret['slink_id'][i] = dict()
                ret['slink_id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['recv_date']:ret['recv_date'][i] = dict()
                ret['recv_date'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['start_time']:ret['start_time'][i] = dict()
                ret['start_time'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['end_time']:ret['end_time'][i] = dict()
                ret['end_time'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['Called_Station_Id']:ret['Called_Station_Id'][i] = dict()
                ret['Called_Station_Id'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['Calling_Station_Id']:ret['Calling_Station_Id'][i] = dict()
                ret['Calling_Station_Id'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['nas_port']:ret['nas_port'][i] = dict()
                ret['nas_port'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['acct_session_id']:ret['acct_session_id'][i] = dict()
                ret['acct_session_id'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['nas_port_type']:ret['nas_port_type'][i] = dict()
                ret['nas_port_type'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['uname']:ret['uname'][i] = dict()
                ret['uname'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['service_type']:ret['service_type'][i] = dict()
                ret['service_type'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['framed_protocol']:ret['framed_protocol'][i] = dict()
                ret['framed_protocol'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['nas_ip']:ret['nas_ip'][i] = dict()
                ret['nas_ip'][i][j] = self.pck.get_data(U_TP_IP)
                if not i in ret['nas_id']:ret['nas_id'][i] = dict()
                ret['nas_id'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['acct_status_type']:ret['acct_status_type'][i] = dict()
                ret['acct_status_type'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['acct_inp_pack']:ret['acct_inp_pack'][i] = dict()
                ret['acct_inp_pack'][i][j] = self.pck.get_data(U_TP_L)
                if not i in ret['acct_inp_oct']:ret['acct_inp_oct'][i] = dict()
                ret['acct_inp_oct'][i][j] = self.pck.get_data(U_TP_L)
                if not i in ret['acct_out_pack']:ret['acct_out_pack'][i] = dict()
                ret['acct_out_pack'][i][j] = self.pck.get_data(U_TP_L)
                if not i in ret['acct_out_oct']:ret['acct_out_oct'][i] = dict()
                ret['acct_out_oct'][i][j] = self.pck.get_data(U_TP_L)
                if not i in ret['zone_id']:ret['zone_id'][i] = dict()
                ret['zone_id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['did']:ret['did'][i] = dict()
                ret['did'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['acct_sess_time']:ret['acct_sess_time'][i] = dict()
                ret['acct_sess_time'][i][j] = self.pck.get_data(U_TP_L)
                if not i in ret['incoming_trunk']:ret['incoming_trunk'][i] = dict()
                ret['incoming_trunk'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['outgoing_trunk']:ret['outgoing_trunk'][i] = dict()
                ret['outgoing_trunk'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['pbx_id']:ret['pbx_id'][i] = dict()
                ret['pbx_id'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['flags']:ret['flags'][i] = dict()
                ret['flags'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['dcause']:ret['dcause'][i] = dict()
                ret['dcause'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['duration']:ret['duration'][i] = dict()
                ret['duration'][i][j] = self.pck.get_data(U_TP_L)
                if not i in ret['base_cost']:ret['base_cost'][i] = dict()
                ret['base_cost'][i][j] = self.pck.get_data(U_TP_D)
                if not i in ret['cost_mult']:ret['cost_mult'][i] = dict()
                ret['cost_mult'][i][j] = self.pck.get_data(U_TP_D)
                if not i in ret['sum_cost']:ret['sum_cost'][i] = dict()
                ret['sum_cost'][i][j] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_nas(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        @returns: 
        :(s)  nas_id :	(s)  - 
        :(s)  auth_secret :	(s)  - 
        :(s)  acct_secret :	(s)  - 
        :(s)  dac_secret :	(s)  - 
        :(s)  das_port :	(i)  - 
        :(s)  flags :	(i)  - 
        :(s)  nas_size :	(i)  - 
        :(s)    variable :	(s)  - 
        :(s)    value :	(s)  - 
        """
        if not self.urfa_call(0x5045):
            raise Exception("Fail of urfa_call(0x5045) [rpcf_get_nas]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['nas_id'] = self.pck.get_data(U_TP_S)
        ret['auth_secret'] = self.pck.get_data(U_TP_S)
        ret['acct_secret'] = self.pck.get_data(U_TP_S)
        ret['dac_secret'] = self.pck.get_data(U_TP_S)
        ret['das_port'] = self.pck.get_data(U_TP_I)
        ret['flags'] = self.pck.get_data(U_TP_I)
        ret['nas_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['nas_size']): 
            self.pck.recv(self.sck)
            ret['variable'][i] = self.pck.get_data(U_TP_S)
            ret['value'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_del_nas(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x501a):
            raise Exception("Fail of urfa_call(0x501a) [rpcf_del_nas]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_update_message_state(self, params):
        """ description
        @params: 
        :(s)  mid :	(i)  - 
        :(s)  state :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x5029):
            raise Exception("Fail of urfa_call(0x5029) [rpcf_update_message_state]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['mid'], U_TP_I)
        self.pck.add_data(params['state'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_telephony_service_link(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i)  - 
        @returns: 
        :(s)  tariff_link_id :	(i)  - 
        :(s)  is_blocked :	(i)  - 
        :(s)  discount_period_id :	(i)  - 
        :(s)  start_date :	(i)  - 
        :(s)  expire_date :	(i)  - 
        :(s)  unabon :	(i)  - 
        :(s)  unprepay :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        :(s)  numbers_size :	(i)  - 
        :(s)    item_id :	(i)  - 
        :(s)    number :	(s)  - 
        :(s)    login :	(s)  - 
        :(s)    password :	(s)  - 
        :(s)    allowed_cid :	(s)  - 
        """
        if not self.urfa_call(0x5058):
            raise Exception("Fail of urfa_call(0x5058) [rpcf_get_telephony_service_link]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['tariff_link_id'] = self.pck.get_data(U_TP_I)
        ret['is_blocked'] = self.pck.get_data(U_TP_I)
        ret['discount_period_id'] = self.pck.get_data(U_TP_I)
        ret['start_date'] = self.pck.get_data(U_TP_I)
        ret['expire_date'] = self.pck.get_data(U_TP_I)
        ret['unabon'] = self.pck.get_data(U_TP_I)
        ret['unprepay'] = self.pck.get_data(U_TP_I)
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        ret['parent_id'] = self.pck.get_data(U_TP_I)
        ret['numbers_size'] = self.pck.get_data(U_TP_I)
        for numbers in range(ret['numbers_size']): 
            self.pck.recv(self.sck)
            ret['item_id'][numbers] = self.pck.get_data(U_TP_I)
            ret['number'][numbers] = self.pck.get_data(U_TP_S)
            ret['login'][numbers] = self.pck.get_data(U_TP_S)
            ret['password'][numbers] = self.pck.get_data(U_TP_S)
            ret['allowed_cid'][numbers] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_copy_voip_price(self, params):
        """ description
        @params: 
        :(s)  src_id :	(i)  - 
        :(s)  dst_id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x5080):
            raise Exception("Fail of urfa_call(0x5080) [rpcf_copy_voip_price]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['src_id'], U_TP_I)
        self.pck.add_data(params['dst_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_graph(self, params):
        """ description
        @params: 
        :(s)  uid :	(i)  - 
        :(s)  aid :	(i)  - 
        :(s)  t_start :	(i)  - 
        :(s)  t_end :	(i)  - 
        @returns: 
        :(s)  account_id :	(i)  - 
        :(s)  graph_data_size :	(i)  - 
        :(s)      graph_param :	(i)  - 
        :(s)    st_size :	(i)  - 
        :(s)      id :	(i)  - 
        :(s)      tclass_name :	(s)  - 
        :(s)      min :	(l)  - 
        :(s)      avg :	(l)  - 
        :(s)      max :	(l)  - 
        """
        if not self.urfa_call(0x5090):
            raise Exception("Fail of urfa_call(0x5090) [rpcf_get_graph]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['uid'], U_TP_I)
        self.pck.add_data(params['aid'], U_TP_I)
        self.pck.add_data(params['t_start'], U_TP_I)
        self.pck.add_data(params['t_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['account_id'] = self.pck.get_data(U_TP_I)
        ret['graph_data_size'] = self.pck.get_data(U_TP_I)
        if ret['graph_data_size']  !=  0:
            for i in range(ret['graph_data_size']): 
                self.pck.recv(self.sck)
                ret['graph_param'][i] = self.pck.get_data(U_TP_I)
            self.pck.recv(self.sck)
            ret['st_size'] = self.pck.get_data(U_TP_I)
            for i in range(ret['st_size']): 
                self.pck.recv(self.sck)
                ret['id'][i] = self.pck.get_data(U_TP_I)
                ret['tclass_name'][i] = self.pck.get_data(U_TP_S)
                ret['min'][i] = self.pck.get_data(U_TP_L)
                ret['avg'][i] = self.pck.get_data(U_TP_L)
                ret['max'][i] = self.pck.get_data(U_TP_L)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_graph_data_iptraffic(self, params):
        """ description
        @params: 
        :(s)  uid :	(i)  - 
        :(s)  aid :	(i)  - 
        :(s)  t_start :	(i)  - 
        :(s)  t_end :	(i)  - 
        @returns: 
        :(s)  traffic_discount_size :	(i)  - 
        :(s)    time :	(i)  - 
        :(s)    size :	(i)  - 
        :(s)      tclass :	(i)  - 
        :(s)      bytes :	(d)  - 
        """
        if not self.urfa_call(0x5091):
            raise Exception("Fail of urfa_call(0x5091) [rpcf_get_graph_data_iptraffic]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['uid'], U_TP_I)
        self.pck.add_data(params['aid'], U_TP_I)
        self.pck.add_data(params['t_start'], U_TP_I)
        self.pck.add_data(params['t_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['traffic_discount_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['traffic_discount_size']): 
            self.pck.recv(self.sck)
            ret['time'][i] = self.pck.get_data(U_TP_I)
            ret['size'] = self.pck.get_data(U_TP_I)
            ret['size_array'][i]=ret['size']
            for j in range(ret['size']): 
                self.pck.recv(self.sck)
                if not i in ret['tclass']:ret['tclass'][i] = dict()
                ret['tclass'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['bytes']:ret['bytes'][i] = dict()
                ret['bytes'][i][j] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_graph_data_dialup(self, params):
        """ description
        @params: 
        :(s)  uid :	(i)  - 
        :(s)  aid :	(i)  - 
        :(s)  t_start :	(i)  - 
        :(s)  t_end :	(i)  - 
        @returns: 
        :(s)  gdata_size :	(i)  - 
        :(s)    date :	(i)  - 
        :(s)    size :	(i)  - 
        :(s)      name :	(s)  - 
        :(s)      bytes :	(d)  - 
        """
        if not self.urfa_call(0x5092):
            raise Exception("Fail of urfa_call(0x5092) [rpcf_get_graph_data_dialup]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['uid'], U_TP_I)
        self.pck.add_data(params['aid'], U_TP_I)
        self.pck.add_data(params['t_start'], U_TP_I)
        self.pck.add_data(params['t_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['gdata_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['gdata_size']): 
            self.pck.recv(self.sck)
            ret['date'][i] = self.pck.get_data(U_TP_I)
            ret['size'] = self.pck.get_data(U_TP_I)
            ret['size_array'][i]=ret['size']
            for j in range(ret['size']): 
                self.pck.recv(self.sck)
                if not i in ret['name']:ret['name'][i] = dict()
                ret['name'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['bytes']:ret['bytes'][i] = dict()
                ret['bytes'][i][j] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_graph_data_telephony(self, params):
        """ description
        @params: 
        :(s)  uid :	(i)  - 
        :(s)  aid :	(i)  - 
        :(s)  t_start :	(i)  - 
        :(s)  t_end :	(i)  - 
        @returns: 
        :(s)  gdata_size :	(i)  - 
        :(s)    date :	(i)  - 
        :(s)    size :	(i)  - 
        :(s)      name :	(s)  - 
        :(s)      bytes :	(d)  - 
        """
        if not self.urfa_call(0x5093):
            raise Exception("Fail of urfa_call(0x5093) [rpcf_get_graph_data_telephony]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['uid'], U_TP_I)
        self.pck.add_data(params['aid'], U_TP_I)
        self.pck.add_data(params['t_start'], U_TP_I)
        self.pck.add_data(params['t_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['gdata_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['gdata_size']): 
            self.pck.recv(self.sck)
            ret['date'][i] = self.pck.get_data(U_TP_I)
            ret['size'] = self.pck.get_data(U_TP_I)
            ret['size_array'][i]=ret['size']
            for j in range(ret['size']): 
                self.pck.recv(self.sck)
                if not i in ret['name']:ret['name'][i] = dict()
                ret['name'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['bytes']:ret['bytes'][i] = dict()
                ret['bytes'][i][j] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_delete_slink(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i)  - 
        @returns: 
        :(s)  error_code :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        """
        if not self.urfa_call(0x5100):
            raise Exception("Fail of urfa_call(0x5100) [rpcf_delete_slink]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['error_code'] = self.pck.get_data(U_TP_I)
        if ret['error_code']  !=  0:
            ret['error'] = dict({13:"unable to delete service link"})
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_prepaid_units(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i)  - 
        @returns: 
        :(s)  bytes_in_mbyte :	(i)  - 
        :(s)  pinfo_size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    old :	(l)  - 
        :(s)    cur :	(l)  - 
        """
        if not self.urfa_call(0x5500):
            raise Exception("Fail of urfa_call(0x5500) [rpcf_get_prepaid_units]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['bytes_in_mbyte'] = self.pck.get_data(U_TP_I)
        ret['pinfo_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['pinfo_size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['old'][i] = self.pck.get_data(U_TP_L)
            ret['cur'][i] = self.pck.get_data(U_TP_L)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_put_prepaid_units(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i)  - 
        :(s)  tclass_id :	(i)  - 
        :(s)  prepaid_units :	(l)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x5501):
            raise Exception("Fail of urfa_call(0x5501) [rpcf_put_prepaid_units]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.add_data(params['tclass_id'], U_TP_I)
        self.pck.add_data(params['prepaid_units'], U_TP_L)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_put_unif_iptr(self, params):
        """ description
        @params: 
        :(s)  count :	(i) = _def_  - 
        :(s)    login :	(s)  - 
        :(s)    ipid :	(i)  - 
        :(s)    tclass :	(i)  - 
        :(s)    d_oct :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x5511):
            raise Exception("Fail of urfa_call(0x5511) [rpcf_put_unif_iptr]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'count' not in params: params['count'] = len(params['login'])
        self.pck.add_data(params['count'], U_TP_I)
        for i in range(len(params['login'])):
            self.pck.add_data(params['login'][i], U_TP_S)
            self.pck.add_data(params['ipid'][i], U_TP_I)
            self.pck.add_data(params['tclass'][i], U_TP_I)
            self.pck.add_data(params['d_oct'][i], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_put_banks(self, params):
        """ description
        @params: 
        :(s)  banks_size :	(i) = _def_  - 
        :(s)    bic :	(s)  - 
        :(s)    name :	(s)  - 
        :(s)    city :	(s)  - 
        :(s)    kschet :	(s)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x6001):
            raise Exception("Fail of urfa_call(0x6001) [rpcf_put_banks]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'banks_size' not in params: params['banks_size'] = len(params['bic'])
        self.pck.add_data(params['banks_size'], U_TP_I)
        for i in range(len(params['bic'])):
            self.pck.add_data(params['bic'][i], U_TP_S)
            self.pck.add_data(params['name'][i], U_TP_S)
            self.pck.add_data(params['city'][i], U_TP_S)
            self.pck.add_data(params['kschet'][i], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_banks(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  banks_size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    bic :	(s)  - 
        :(s)    name :	(s)  - 
        :(s)    city :	(s)  - 
        :(s)    kschet :	(s)  - 
        """
        if not self.urfa_call(0x6002):
            raise Exception("Fail of urfa_call(0x6002) [rpcf_get_banks]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['banks_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['banks_size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['bic'][i] = self.pck.get_data(U_TP_S)
            ret['name'][i] = self.pck.get_data(U_TP_S)
            ret['city'][i] = self.pck.get_data(U_TP_S)
            ret['kschet'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_del_bank(self, params):
        """ description
        @params: 
        :(s)  bank_id :	(i)  - 
        :(s)  bic :	(s)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x6003):
            raise Exception("Fail of urfa_call(0x6003) [rpcf_del_bank]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['bank_id'], U_TP_I)
        self.pck.add_data(params['bic'], U_TP_S)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_doc_template(self, params):
        """ description
        @params: 
        :(s)  doc_type_id :	(i)  - 
        :(s)  doc_template_id :	(i)  - 
        :(s)  doc_name :	(s)  - 
        :(s)  doc_text :	(s)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x7020):
            raise Exception("Fail of urfa_call(0x7020) [rpcf_add_doc_template]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['doc_type_id'], U_TP_I)
        self.pck.add_data(params['doc_template_id'], U_TP_I)
        self.pck.add_data(params['doc_name'], U_TP_S)
        self.pck.add_data(params['doc_text'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_save_doc_template(self, params):
        """ description
        @params: 
        :(s)  doc_type_id :	(i)  - 
        :(s)  needInsert :	(i)  - 
        :(s)  doc_template_id :	(i)  - 
        :(s)  doc_id :	(i)  - 
        :(s)  doc_name :	(s)  - 
        :(s)  doc_text :	(s)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x7021):
            raise Exception("Fail of urfa_call(0x7021) [rpcf_save_doc_template]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['doc_type_id'], U_TP_I)
        self.pck.add_data(params['needInsert'], U_TP_I)
        self.pck.add_data(params['doc_template_id'], U_TP_I)
        self.pck.add_data(params['doc_id'], U_TP_I)
        self.pck.add_data(params['doc_name'], U_TP_S)
        self.pck.add_data(params['doc_text'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_doc_templates_list(self, params):
        """ description
        @params: 
        :(s)  doc_type_id :	(i)  - 
        @returns: 
        :(s)  count :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    doc_id :	(i)  - 
        :(s)    date :	(i)  - 
        :(s)    doc_name :	(s)  - 
        :(s)    def :	(i)  - 
        """
        if not self.urfa_call(0x7022):
            raise Exception("Fail of urfa_call(0x7022) [rpcf_get_doc_templates_list]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['doc_type_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['count']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['doc_id'][i] = self.pck.get_data(U_TP_I)
            ret['date'][i] = self.pck.get_data(U_TP_I)
            ret['doc_name'][i] = self.pck.get_data(U_TP_S)
            ret['def'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_doc_template_text(self, params):
        """ description
        @params: 
        :(s)  doc_template_id :	(i)  - 
        @returns: 
        :(s)  id :	(i)  - 
        :(s)    doc_text :	(s)  - 
        :(s)    landscape :	(i)  - 
        """
        if not self.urfa_call(0x7023):
            raise Exception("Fail of urfa_call(0x7023) [rpcf_get_doc_template_text]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['doc_template_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['id'] = self.pck.get_data(U_TP_I)
        if ret['id']  !=  0:
            ret['doc_text'] = self.pck.get_data(U_TP_S)
            ret['landscape'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_doc_types_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  count :	(i)  - 
        :(s)    doc_name :	(s)  - 
        :(s)    id :	(i)  - 
        """
        if not self.urfa_call(0x7024):
            raise Exception("Fail of urfa_call(0x7024) [rpcf_get_doc_types_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['count']): 
            self.pck.recv(self.sck)
            ret['doc_name'][i] = self.pck.get_data(U_TP_S)
            ret['id'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_set_default_doc_template(self, params):
        """ description
        @params: 
        :(s)  template_id :	(i)  - 
        :(s)  doc_type :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x7025):
            raise Exception("Fail of urfa_call(0x7025) [rpcf_set_default_doc_template]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['template_id'], U_TP_I)
        self.pck.add_data(params['doc_type'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_delete_doc_template(self, params):
        """ description
        @params: 
        :(s)  doc_templ_id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x7026):
            raise Exception("Fail of urfa_call(0x7026) [rpcf_delete_doc_template]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['doc_templ_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_save_doc_for_user(self, params):
        """ description
        @params: 
        :(s)  doc_tmplate_id :	(i)  - 
        :(s)  doc_text :	(s)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x7031):
            raise Exception("Fail of urfa_call(0x7031) [rpcf_save_doc_for_user]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['doc_tmplate_id'], U_TP_I)
        self.pck.add_data(params['doc_text'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_doc_for_user(self, params):
        """ description
        @params: 
        :(s)  doc_data_id :	(i)  - 
        @returns: 
        :(s)  id :	(i)  - 
        :(s)    text_count :	(i)  - 
        :(s)      dynamic_text :	(s)  - 
        :(s)    landscape :	(i)  - 
        """
        if not self.urfa_call(0x7032):
            raise Exception("Fail of urfa_call(0x7032) [rpcf_get_doc_for_user]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['doc_data_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['id'] = self.pck.get_data(U_TP_I)
        if ret['id']  !=  0:
            ret['text_count'] = self.pck.get_data(U_TP_I)
            for i in range(ret['text_count']): 
                self.pck.recv(self.sck)
                ret['dynamic_text'][i] = self.pck.get_data(U_TP_S)
            self.pck.recv(self.sck)
            ret['landscape'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_docs_list_for_aid(self, params):
        """ description
        @params: 
        :(s)  aid :	(i)  - 
        @returns: 
        :(s)  ret_code_count :	(i)  - 
        :(s)      id :	(i)  - 
        :(s)      doc_template_id :	(i)  - 
        :(s)      base_id :	(i)  - 
        :(s)      gen_date :	(i)  - 
        :(s)      is_sign :	(i)  - 
        """
        if not self.urfa_call(0x7033):
            raise Exception("Fail of urfa_call(0x7033) [rpcf_get_docs_list_for_aid]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['aid'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['ret_code_count'] = self.pck.get_data(U_TP_I)
        if ret['ret_code_count']  !=  -1:
            for i in range(ret['ret_code_count']): 
                self.pck.recv(self.sck)
                ret['id'][i] = self.pck.get_data(U_TP_I)
                ret['doc_template_id'][i] = self.pck.get_data(U_TP_I)
                ret['base_id'][i] = self.pck.get_data(U_TP_I)
                ret['gen_date'][i] = self.pck.get_data(U_TP_I)
                ret['is_sign'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_sign_doc(self, params):
        """ description
        @params: 
        :(s)  doc_id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x7034):
            raise Exception("Fail of urfa_call(0x7034) [rpcf_sign_doc]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['doc_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_del_doc(self, params):
        """ description
        @params: 
        :(s)  doc_id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x7035):
            raise Exception("Fail of urfa_call(0x7035) [rpcf_del_doc]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['doc_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_docs_list(self, params):
        """ description
        @params: 
        :(s)  doc_type :	(i)  - 
        :(s)  account_id :	(i)  - 
        @returns: 
        :(s)  ret_code_count :	(i)  - 
        :(s)      id :	(i)  - 
        :(s)      doc_template_id :	(i)  - 
        :(s)      base_id :	(i)  - 
        :(s)      gen_date :	(i)  - 
        :(s)      is_sign :	(i)  - 
        """
        if not self.urfa_call(0x7036):
            raise Exception("Fail of urfa_call(0x7036) [rpcf_get_docs_list]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['doc_type'], U_TP_I)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['ret_code_count'] = self.pck.get_data(U_TP_I)
        if ret['ret_code_count']  !=  -1:
            for i in range(ret['ret_code_count']): 
                self.pck.recv(self.sck)
                ret['id'][i] = self.pck.get_data(U_TP_I)
                ret['doc_template_id'][i] = self.pck.get_data(U_TP_I)
                ret['base_id'][i] = self.pck.get_data(U_TP_I)
                ret['gen_date'][i] = self.pck.get_data(U_TP_I)
                ret['is_sign'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_vendor_doc_text(self, params):
        """ description
        @params: 
        :(s)  doc_type :	(i)  - 
        @returns: 
        :(s)  vendor_doc_text :	(s)  - 
        """
        if not self.urfa_call(0x7038):
            raise Exception("Fail of urfa_call(0x7038) [rpcf_get_vendor_doc_text]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['doc_type'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['vendor_doc_text'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_invoices_list(self, params):
        """ description
        @params: 
        :(s)  aid :	(i)  - 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i)  - 
        :(s)  gid :	(i)  - 
        @returns: 
        :(s)  accts_size :	(i)  - 
        :(s)    count_of_invoice :	(i)  - 
        :(s)      currency_id :	(i)  - 
        :(s)      currency_name :	(s)  - 
        :(s)      payment_rule :	(s)  - 
        :(s)      id :	(i)  - 
        :(s)      ext_num :	(s)  - 
        :(s)      invoice_date :	(i)  - 
        :(s)      uid :	(i)  - 
        :(s)      payment_transaction_id :	(i)  - 
        :(s)      expire_date :	(i)  - 
        :(s)      tmp_is_payed :	(i)  - 
        :(s)      is_printed :	(i)  - 
        :(s)      account_id :	(i)  - 
        :(s)      full_name :	(s)  - 
        :(s)        accInvcInfo_id :	(i)  - 
        :(s)        accInvcInfo_date :	(i)  - 
        :(s)        accInvcInfo_payed_date :	(i)  - 
        :(s)        payment_ext_number :	(s)  - 
        :(s)        is_printed :	(i)  - 
        :(s)      entry_size :	(i)  - 
        :(s)        name :	(s)  - 
        :(s)        invoice_id :	(i)  - 
        :(s)        slink_id :	(i)  - 
        :(s)        service_type :	(i)  - 
        :(s)        discount_period_id :	(i)  - 
        :(s)        date :	(i)  - 
        :(s)        qnt :	(d)  - 
        :(s)        base :	(d)  - 
        :(s)        sum :	(d)  - 
        :(s)        tax :	(d)  - 
        :(s)        total_sum :	(d)  - 
        :(s)        total_tax :	(d)  - 
        :(s)        total_sum_plus_total_tax :	(d)  - 
        """
        if not self.urfa_call(0x8001):
            raise Exception("Fail of urfa_call(0x8001) [rpcf_get_invoices_list]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['aid'], U_TP_I)
        self.pck.add_data(params['time_start'], U_TP_I)
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.add_data(params['gid'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['accts_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['accts_size']): 
            self.pck.recv(self.sck)
            ret['count_of_invoice'] = self.pck.get_data(U_TP_I)
            ret['count_of_invoice_array'][i]=ret['count_of_invoice']
            if ret['count_of_invoice']  !=  0:
                ret['currency_id'][i] = self.pck.get_data(U_TP_I)
                ret['currency_name'][i] = self.pck.get_data(U_TP_S)
                ret['payment_rule'][i] = self.pck.get_data(U_TP_S)
            for j in range(ret['count_of_invoice']): 
                self.pck.recv(self.sck)
                if not i in ret['id']:ret['id'][i] = dict()
                ret['id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['ext_num']:ret['ext_num'][i] = dict()
                ret['ext_num'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['invoice_date']:ret['invoice_date'][i] = dict()
                ret['invoice_date'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['uid']:ret['uid'][i] = dict()
                ret['uid'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['payment_transaction_id']:ret['payment_transaction_id'][i] = dict()
                ret['payment_transaction_id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['expire_date']:ret['expire_date'][i] = dict()
                ret['expire_date'][i][j] = self.pck.get_data(U_TP_I)
                ret['tmp_is_payed'] = self.pck.get_data(U_TP_I)
                ret['is_payed'][i][j]=ret['tmp_is_payed']
                if not i in ret['is_printed']:ret['is_printed'][i] = dict()
                ret['is_printed'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['account_id']:ret['account_id'][i] = dict()
                ret['account_id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['full_name']:ret['full_name'][i] = dict()
                ret['full_name'][i][j] = self.pck.get_data(U_TP_S)
                if ret['tmp_is_payed']  !=  0:
                    if not i in ret['accInvcInfo_id']:ret['accInvcInfo_id'][i] = dict()
                    ret['accInvcInfo_id'][i][j] = self.pck.get_data(U_TP_I)
                    if not i in ret['accInvcInfo_date']:ret['accInvcInfo_date'][i] = dict()
                    ret['accInvcInfo_date'][i][j] = self.pck.get_data(U_TP_I)
                    if not i in ret['accInvcInfo_payed_date']:ret['accInvcInfo_payed_date'][i] = dict()
                    ret['accInvcInfo_payed_date'][i][j] = self.pck.get_data(U_TP_I)
                    if not i in ret['payment_ext_number']:ret['payment_ext_number'][i] = dict()
                    ret['payment_ext_number'][i][j] = self.pck.get_data(U_TP_S)
                    if not i in ret['is_printed']:ret['is_printed'][i] = dict()
                    ret['is_printed'][i][j] = self.pck.get_data(U_TP_I)
                if ret['tmp_is_payed']  ==  0:
                    ret['accInvcInfo_id'][i][j]="0"
                    ret['accInvcInfo_date'][i][j]="0"
                    ret['accInvcInfo_payed_date'][i][j]="0"
                    ret['payment_ext_number'][i][j]=""
                    ret['is_printed'][i][j]="0"
                ret['entry_size'] = self.pck.get_data(U_TP_I)
                ret['entry_size_array'][i][j]=ret['entry_size']
                for x in range(ret['entry_size']): 
                    self.pck.recv(self.sck)
                    if not i in ret['name']:ret['name'][i] = dict()
                    if not j in ret['name'][i]:ret['name'][i][j] = dict()
                    ret['name'][i][j][x] = self.pck.get_data(U_TP_S)
                    if not i in ret['invoice_id']:ret['invoice_id'][i] = dict()
                    if not j in ret['invoice_id'][i]:ret['invoice_id'][i][j] = dict()
                    ret['invoice_id'][i][j][x] = self.pck.get_data(U_TP_I)
                    if not i in ret['slink_id']:ret['slink_id'][i] = dict()
                    if not j in ret['slink_id'][i]:ret['slink_id'][i][j] = dict()
                    ret['slink_id'][i][j][x] = self.pck.get_data(U_TP_I)
                    if not i in ret['service_type']:ret['service_type'][i] = dict()
                    if not j in ret['service_type'][i]:ret['service_type'][i][j] = dict()
                    ret['service_type'][i][j][x] = self.pck.get_data(U_TP_I)
                    if not i in ret['discount_period_id']:ret['discount_period_id'][i] = dict()
                    if not j in ret['discount_period_id'][i]:ret['discount_period_id'][i][j] = dict()
                    ret['discount_period_id'][i][j][x] = self.pck.get_data(U_TP_I)
                    if not i in ret['date']:ret['date'][i] = dict()
                    if not j in ret['date'][i]:ret['date'][i][j] = dict()
                    ret['date'][i][j][x] = self.pck.get_data(U_TP_I)
                    if not i in ret['qnt']:ret['qnt'][i] = dict()
                    if not j in ret['qnt'][i]:ret['qnt'][i][j] = dict()
                    ret['qnt'][i][j][x] = self.pck.get_data(U_TP_D)
                    if not i in ret['base']:ret['base'][i] = dict()
                    if not j in ret['base'][i]:ret['base'][i][j] = dict()
                    ret['base'][i][j][x] = self.pck.get_data(U_TP_D)
                    if not i in ret['sum']:ret['sum'][i] = dict()
                    if not j in ret['sum'][i]:ret['sum'][i][j] = dict()
                    ret['sum'][i][j][x] = self.pck.get_data(U_TP_D)
                    if not i in ret['tax']:ret['tax'][i] = dict()
                    if not j in ret['tax'][i]:ret['tax'][i][j] = dict()
                    ret['tax'][i][j][x] = self.pck.get_data(U_TP_D)
                self.pck.recv(self.sck)
                if ret['entry_size']  !=  0:
                    if not i in ret['total_sum']:ret['total_sum'][i] = dict()
                    ret['total_sum'][i][j] = self.pck.get_data(U_TP_D)
                    if not i in ret['total_tax']:ret['total_tax'][i] = dict()
                    ret['total_tax'][i][j] = self.pck.get_data(U_TP_D)
                    if not i in ret['total_sum_plus_total_tax']:ret['total_sum_plus_total_tax'][i] = dict()
                    ret['total_sum_plus_total_tax'][i][j] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_invc_lst_addpay(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  account_id :	(i)  - 
        @returns: 
        :(s)  accounts_size :	(i)  - 
        :(s)    aid :	(i)  - 
        :(s)    binded_currency :	(i)  - 
        :(s)    inv_size :	(i)  - 
        :(s)      aid :	(i)  - 
        :(s)      id :	(i)  - 
        :(s)      ext_num :	(s)  - 
        :(s)      invoice_date :	(i)  - 
        :(s)      system_cur_sum :	(d)  - 
        :(s)      binded_cur_sum :	(d)  - 
        :(s)      total :	(d)  - 
        """
        if not self.urfa_call(0x8002):
            raise Exception("Fail of urfa_call(0x8002) [rpcf_get_invc_lst_addpay]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['accounts_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['accounts_size']): 
            self.pck.recv(self.sck)
            ret['aid'][i] = self.pck.get_data(U_TP_I)
            ret['binded_currency'][i] = self.pck.get_data(U_TP_I)
            ret['inv_size'][i] = self.pck.get_data(U_TP_I)
            for j in range(ret['inv_size'][i]): 
                self.pck.recv(self.sck)
                if not i in ret['aid']:ret['aid'][i] = dict()
                ret['aid'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['id']:ret['id'][i] = dict()
                ret['id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['ext_num']:ret['ext_num'][i] = dict()
                ret['ext_num'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['invoice_date']:ret['invoice_date'][i] = dict()
                ret['invoice_date'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['system_cur_sum']:ret['system_cur_sum'][i] = dict()
                ret['system_cur_sum'][i][j] = self.pck.get_data(U_TP_D)
                if not i in ret['binded_cur_sum']:ret['binded_cur_sum'][i] = dict()
                ret['binded_cur_sum'][i][j] = self.pck.get_data(U_TP_D)
                if not i in ret['total']:ret['total'][i] = dict()
                ret['total'][i][j] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_currency_rate_to_date(self, params):
        """ description
        @params: 
        :(s)  date :	(i)  - 
        :(s)  code :	(i)  - 
        @returns: 
        :(s)  result :	(d)  - 
        """
        if not self.urfa_call(0x8003):
            raise Exception("Fail of urfa_call(0x8003) [rpcf_get_currency_rate_to_date]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['date'], U_TP_I)
        self.pck.add_data(params['code'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_sendInvoice2mail(self, params):
        """ description
        @params: 
        :(s)  aid :	(i)  - 
        :(s)  invc_id :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x8004):
            raise Exception("Fail of urfa_call(0x8004) [rpcf_sendInvoice2mail]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['aid'], U_TP_I)
        self.pck.add_data(params['invc_id'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_supplier(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        @returns: 
        :(s)  id :	(i)  - 
        :(s)  name :	(s)  - 
        :(s)  short_name :	(s)  - 
        :(s)  jur_adress :	(s)  - 
        :(s)  act_adress :	(s)  - 
        :(s)  inn :	(s)  - 
        :(s)  kpp :	(s)  - 
        :(s)  bank_id :	(i)  - 
        :(s)  account :	(s)  - 
        :(s)  headman :	(s)  - 
        :(s)  bookeeper :	(s)  - 
        :(s)  short_headman :	(s)  - 
        :(s)  short_bookeeper :	(s)  - 
        :(s)  supp_balance :	(d)  - 
        :(s)  tax_rate :	(d)  - 
        :(s)  type :	(i)  - 
        """
        if not self.urfa_call(0x8013):
            raise Exception("Fail of urfa_call(0x8013) [rpcf_get_supplier]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['id'] = self.pck.get_data(U_TP_I)
        ret['name'] = self.pck.get_data(U_TP_S)
        ret['short_name'] = self.pck.get_data(U_TP_S)
        ret['jur_adress'] = self.pck.get_data(U_TP_S)
        ret['act_adress'] = self.pck.get_data(U_TP_S)
        ret['inn'] = self.pck.get_data(U_TP_S)
        ret['kpp'] = self.pck.get_data(U_TP_S)
        ret['bank_id'] = self.pck.get_data(U_TP_I)
        ret['account'] = self.pck.get_data(U_TP_S)
        ret['headman'] = self.pck.get_data(U_TP_S)
        ret['bookeeper'] = self.pck.get_data(U_TP_S)
        ret['short_headman'] = self.pck.get_data(U_TP_S)
        ret['short_bookeeper'] = self.pck.get_data(U_TP_S)
        ret['supp_balance'] = self.pck.get_data(U_TP_D)
        ret['tax_rate'] = self.pck.get_data(U_TP_D)
        ret['type'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_suppliers_zones(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  ret_code :	(i)  - 
        :(s)  size :	(i)  - 
        :(s)    zone_id :	(i)  - 
        :(s)    supplier_id :	(i)  - 
        """
        if not self.urfa_call(0x8019):
            raise Exception("Fail of urfa_call(0x8019) [rpcf_get_suppliers_zones]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['ret_code'] = self.pck.get_data(U_TP_I)
        ret['size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['size']): 
            self.pck.recv(self.sck)
            ret['zone_id'][i] = self.pck.get_data(U_TP_I)
            ret['supplier_id'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_user_instructions(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        @returns: 
        :(s)  basic_account :	(i)  - 
        :(s)  login :	(s)  - 
        :(s)  password :	(s)  - 
        :(s)  count :	(i)  - 
        :(s)    group_size :	(i)  - 
        :(s)      ip :	(i)  - 
        :(s)      mask :	(i)  - 
        :(s)      ulogin :	(s)  - 
        :(s)      password :	(s)  - 
        :(s)      mac :	(s)  - 
        """
        if not self.urfa_call(0x8020):
            raise Exception("Fail of urfa_call(0x8020) [rpcf_get_user_instructions]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['basic_account'] = self.pck.get_data(U_TP_I)
        ret['login'] = self.pck.get_data(U_TP_S)
        ret['password'] = self.pck.get_data(U_TP_S)
        ret['count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['count']): 
            self.pck.recv(self.sck)
            ret['group_size'] = self.pck.get_data(U_TP_I)
            ret['group_size_array'][i]=ret['group_size']
            for j in range(ret['group_size']): 
                self.pck.recv(self.sck)
                if not i in ret['ip']:ret['ip'][i] = dict()
                ret['ip'][i][j] = self.pck.get_data(U_TP_IP)
                if not i in ret['mask']:ret['mask'][i] = dict()
                ret['mask'][i][j] = self.pck.get_data(U_TP_IP)
                if not i in ret['ulogin']:ret['ulogin'][i] = dict()
                ret['ulogin'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['password']:ret['password'][i] = dict()
                ret['password'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['mac']:ret['mac'][i] = dict()
                ret['mac'][i][j] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_supplier_id_for_service(self, params):
        """ description
        @params: 
        :(s)  service_id :	(i)  - 
        @returns: 
        :(s)  invoice_sup_id :	(i)  - 
        """
        if not self.urfa_call(0x8021):
            raise Exception("Fail of urfa_call(0x8021) [rpcf_get_supplier_id_for_service]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['invoice_sup_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_set_supplier_id_for_service(self, params):
        """ description
        @params: 
        :(s)  service_id :	(i)  - 
        :(s)  invoice_sup_id :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x8022):
            raise Exception("Fail of urfa_call(0x8022) [rpcf_set_supplier_id_for_service]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.add_data(params['invoice_sup_id'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_tech_param_by_uid(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  account_id :	(i)  - 
        @returns: 
        :(s)  size_tp :	(i)  - 
        :(s)    size_vec_ltp :	(i)  - 
        :(s)      id :	(i)  - 
        :(s)      type_id :	(i)  - 
        :(s)      type_name :	(s)  - 
        :(s)      param :	(s)  - 
        :(s)      reg_date :	(i)  - 
        :(s)      slink_id :	(i)  - 
        :(s)      service_name :	(s)  - 
        :(s)      password :	(s)  - 
        """
        if not self.urfa_call(0x9000):
            raise Exception("Fail of urfa_call(0x9000) [rpcf_get_tech_param_by_uid]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['size_tp'] = self.pck.get_data(U_TP_I)
        for i in range(ret['size_tp']): 
            self.pck.recv(self.sck)
            ret['size_vec_ltp'] = self.pck.get_data(U_TP_I)
            ret['size_vec_ltp_array'][i]=ret['size_vec_ltp']
            for j in range(ret['size_vec_ltp']): 
                self.pck.recv(self.sck)
                if not i in ret['id']:ret['id'][i] = dict()
                ret['id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['type_id']:ret['type_id'][i] = dict()
                ret['type_id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['type_name']:ret['type_name'][i] = dict()
                ret['type_name'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['param']:ret['param'][i] = dict()
                ret['param'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['reg_date']:ret['reg_date'][i] = dict()
                ret['reg_date'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['slink_id']:ret['slink_id'][i] = dict()
                ret['slink_id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['service_name']:ret['service_name'][i] = dict()
                ret['service_name'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['password']:ret['password'][i] = dict()
                ret['password'][i][j] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_del_tech_param(self, params):
        """ description
        @params: 
        :(s)  tpid :	(i)  - 
        :(s)  slink :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x9001):
            raise Exception("Fail of urfa_call(0x9001) [rpcf_del_tech_param]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['tpid'], U_TP_I)
        self.pck.add_data(params['slink'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_tech_param_type(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  count :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    name :	(s)  - 
        """
        if not self.urfa_call(0x9002):
            raise Exception("Fail of urfa_call(0x9002) [rpcf_get_tech_param_type]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['count']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['name'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_techparam_slink_by_uid(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  account_id :	(i)  - 
        @returns: 
        :(s)  count :	(i)  - 
        :(s)    slink_id :	(i)  - 
        :(s)    service_name :	(s)  - 
        """
        if not self.urfa_call(0x9003):
            raise Exception("Fail of urfa_call(0x9003) [rpcf_get_techparam_slink_by_uid]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['count']): 
            self.pck.recv(self.sck)
            ret['slink_id'][i] = self.pck.get_data(U_TP_I)
            ret['service_name'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_tech_param(self, params):
        """ description
        @params: 
        :(s)  type_id :	(i)  - 
        :(s)  slink_id :	(i)  - 
        :(s)  param :	(s)  - 
        :(s)  reg_date :	(i)  - 
        :(s)  passwd :	(s)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x9004):
            raise Exception("Fail of urfa_call(0x9004) [rpcf_add_tech_param]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['type_id'], U_TP_I)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.add_data(params['param'], U_TP_S)
        self.pck.add_data(params['reg_date'], U_TP_I)
        self.pck.add_data(params['passwd'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_save_tech_param(self, params):
        """ description
        @params: 
        :(s)  type_id :	(i)  - 
        :(s)  slink_id :	(i)  - 
        :(s)  id :	(i)  - 
        :(s)  param :	(s)  - 
        :(s)  reg_date :	(i)  - 
        :(s)  passwd :	(s)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x9005):
            raise Exception("Fail of urfa_call(0x9005) [rpcf_save_tech_param]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['type_id'], U_TP_I)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['param'], U_TP_S)
        self.pck.add_data(params['reg_date'], U_TP_I)
        self.pck.add_data(params['passwd'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_user_staticsets(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        @returns: 
        :(s)  count_of_sets :	(i)  - 
        :(s)    num_of_type_of_sets :	(i)  - 
        :(s)    count :	(i)  - 
        :(s)      router_info :	(s)  - 
        :(s)      currency_id :	(i)  - 
        """
        if not self.urfa_call(0x9020):
            raise Exception("Fail of urfa_call(0x9020) [rpcf_get_user_staticsets]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['count_of_sets'] = self.pck.get_data(U_TP_I)
        if ret['count_of_sets']  !=  0:
            ret['num_of_type_of_sets'] = self.pck.get_data(U_TP_I)
            ret['count'] = self.pck.get_data(U_TP_I)
            for i in range(ret['count']): 
                self.pck.recv(self.sck)
                ret['router_info'][i] = self.pck.get_data(U_TP_S)
                ret['currency_id'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_user_othersets(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        @returns: 
        :(s)  count :	(i)  - 
        :(s)    type :	(i)  - 
        :(s)      switch_id :	(i)  - 
        :(s)      port :	(i)  - 
        :(s)      cur_id :	(i)  - 
        :(s)      name :	(s)  - 
        """
        if not self.urfa_call(0x9021):
            raise Exception("Fail of urfa_call(0x9021) [rpcf_get_user_othersets]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['count']): 
            self.pck.recv(self.sck)
            ret['type'] = self.pck.get_data(U_TP_I)
            if ret['type']  ==  1:
                ret['switch_id'] = self.pck.get_data(U_TP_I)
                ret['port'] = self.pck.get_data(U_TP_I)
            if ret['type']  ==  3:
                ret['cur_id'] = self.pck.get_data(U_TP_I)
                ret['name'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_save_user_othersets(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  count :	(i)  - 
        :(s)    type :	(i)  - 
        :(s)      id :	(i)  - 
        :(s)      port :	(i)  - 
        :(s)      currency_id :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x9022):
            raise Exception("Fail of urfa_call(0x9022) [rpcf_save_user_othersets]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['count'], U_TP_I)
        for i in range(params['count']):
            self.pck.add_data(params['type'][i], U_TP_I)
            if params['type'][i]  ==  1:
                self.pck.add_data(params['id'], U_TP_I)
                self.pck.add_data(params['port'], U_TP_I)
            if params['type'][i]  ==  3:
                self.pck.add_data(params['currency_id'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_periodic_component_of_cost(self, params):
        """ description
        @params: 
        :(s)  sid :	(i)  - 
        @returns: 
        :(s)  cost :	(d)  - 
        """
        if not self.urfa_call(0x10000):
            raise Exception("Fail of urfa_call(0x10000) [rpcf_get_periodic_component_of_cost]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['sid'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['cost'] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_is_service_used(self, params):
        """ description
        @params: 
        :(s)  sid :	(i)  - 
        @returns: 
        :(s)  links_count :	(i)  - 
        """
        if not self.urfa_call(0x10001):
            raise Exception("Fail of urfa_call(0x10001) [rpcf_is_service_used]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['sid'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['links_count'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_bytes_in_kb(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  bytes_in_kb :	(i)  - 
        """
        if not self.urfa_call(0x10002):
            raise Exception("Fail of urfa_call(0x10002) [rpcf_get_bytes_in_kb]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['bytes_in_kb'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_set_radius_attr(self, params):
        """ description
        @params: 
        :(s)  sid :	(i)  - 
        :(s)  st :	(i)  - 
        :(s)  cnt :	(i)  - 
        :(s)    vendor :	(i)  - 
        :(s)    attr :	(i)  - 
        :(s)    usage_flags :	(i)  - 
        :(s)    param1 :	(i)  - 
        :(s)      cval :	(s)  - 
        :(s)      ival :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x10100):
            raise Exception("Fail of urfa_call(0x10100) [rpcf_set_radius_attr]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['sid'], U_TP_I)
        self.pck.add_data(params['st'], U_TP_I)
        self.pck.add_data(params['cnt'], U_TP_I)
        for i in range(params['cnt']):
            self.pck.add_data(params['vendor'][i], U_TP_I)
            self.pck.add_data(params['attr'][i], U_TP_I)
            self.pck.add_data(params['usage_flags'][i], U_TP_I)
            self.pck.add_data(params['param1'][i], U_TP_I)
            if params['param1'][i]  ==  1:
                self.pck.add_data(params['cval'][i], U_TP_S)
            if params['param1'][i]  !=  1:
                self.pck.add_data(params['ival'][i], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_radius_attr(self, params):
        """ description
        @params: 
        :(s)  sid :	(i)  - 
        :(s)  st :	(i)  - 
        @returns: 
        :(s)  radius_data_size :	(i)  - 
        :(s)    vendor :	(i)  - 
        :(s)    attr :	(i)  - 
        :(s)    usage_flags :	(i)  - 
        :(s)    expire_date :	(i)  - 
        :(s)    param1 :	(i)  - 
        :(s)      val :	(i)  - 
        :(s)      val :	(s)  - 
        :(s)      val :	(i)  - 
        :(s)      val :	(s)  - 
        """
        if not self.urfa_call(0x10101):
            raise Exception("Fail of urfa_call(0x10101) [rpcf_get_radius_attr]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['sid'], U_TP_I)
        self.pck.add_data(params['st'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['radius_data_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['radius_data_size']): 
            self.pck.recv(self.sck)
            ret['vendor'][i] = self.pck.get_data(U_TP_I)
            ret['attr'][i] = self.pck.get_data(U_TP_I)
            ret['usage_flags'][i] = self.pck.get_data(U_TP_I)
            ret['expire_date'][i] = self.pck.get_data(U_TP_I)
            ret['param1'][i] = self.pck.get_data(U_TP_I)
            ret['tmp_type']=ret['param1'][i][i]
            if ret['tmp_type']  ==  0:
                ret['val'][i] = self.pck.get_data(U_TP_I)
            if ret['tmp_type']  ==  1:
                ret['val'][i] = self.pck.get_data(U_TP_S)
            if ret['tmp_type']  ==  2:
                ret['val'][i] = self.pck.get_data(U_TP_I)
            if ret['tmp_type']  ==  3:
                ret['val'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_new_invoice(self, params):
        """ description
        @params: 
        :(s)  account_id :	(i)  - 
        :(s)  gen_date :	(i)  - 
        :(s)  count :	(i) = _def_  - 
        :(s)    name :	(s)  - 
        :(s)    qnt :	(d)  - 
        :(s)    base_cost :	(d)  - 
        :(s)    sum_cost :	(d)  - 
        @returns: 
        :(s)  id :	(i)  - 
        """
        if not self.urfa_call(0x10200):
            raise Exception("Fail of urfa_call(0x10200) [rpcf_new_invoice]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['gen_date'], U_TP_I)
        if 'count' not in params: params['count'] = len(params['name'])
        self.pck.add_data(params['count'], U_TP_I)
        for i in range(len(params['name'])):
            self.pck.add_data(params['name'][i], U_TP_S)
            self.pck.add_data(params['qnt'][i], U_TP_D)
            self.pck.add_data(params['base_cost'][i], U_TP_D)
            self.pck.add_data(params['sum_cost'][i], U_TP_D)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_tel_direction(self, params):
        """ description
        @params: 
        :(s)  zone_id :	(i) = _def_  - 
        :(s)  name :	(s)  - 
        :(s)  calling_prefix :	(s)  - 
        :(s)  called_prefix :	(s)  - 
        :(s)  incoming_trunk :	(s)  - 
        :(s)  outgoing_trunk :	(s)  - 
        :(s)  pbx_id :	(s)  - 
        :(s)  calling_prefix_regexp :	(i) = _def_  - 
        :(s)  called_prefix_regexp :	(i) = _def_  - 
        :(s)  skip :	(i) = _def_  - 
        :(s)  dir_type :	(i)  - 
        @returns: 
        :(s)  dir_id :	(i)  - 
        """
        if not self.urfa_call(0x10300):
            raise Exception("Fail of urfa_call(0x10300) [rpcf_add_tel_direction]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'zone_id' not in params: params['zone_id'] = 0
        self.pck.add_data(params['zone_id'], U_TP_I)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.add_data(params['calling_prefix'], U_TP_S)
        self.pck.add_data(params['called_prefix'], U_TP_S)
        self.pck.add_data(params['incoming_trunk'], U_TP_S)
        self.pck.add_data(params['outgoing_trunk'], U_TP_S)
        self.pck.add_data(params['pbx_id'], U_TP_S)
        if 'calling_prefix_regexp' not in params: params['calling_prefix_regexp'] = 1
        self.pck.add_data(params['calling_prefix_regexp'], U_TP_I)
        if 'called_prefix_regexp' not in params: params['called_prefix_regexp'] = 1
        self.pck.add_data(params['called_prefix_regexp'], U_TP_I)
        if 'skip' not in params: params['skip'] = 0
        self.pck.add_data(params['skip'], U_TP_I)
        self.pck.add_data(params['dir_type'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['dir_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_tel_direction(self, params):
        """ description
        @params: 
        :(s)  dir_id :	(i)  - 
        :(s)  zone_id :	(i) = _def_  - 
        :(s)  name :	(s)  - 
        :(s)  calling_prefix :	(s)  - 
        :(s)  called_prefix :	(s)  - 
        :(s)  incoming_trunk :	(s)  - 
        :(s)  outgoing_trunk :	(s)  - 
        :(s)  pbx_id :	(s)  - 
        :(s)  calling_prefix_regexp :	(i) = _def_  - 
        :(s)  called_prefix_regexp :	(i) = _def_  - 
        :(s)  skip :	(i) = _def_  - 
        :(s)  dir_type :	(i)  - 
        @returns: 
        :(s)  dir_id :	(i)  - 
        """
        if not self.urfa_call(0x10301):
            raise Exception("Fail of urfa_call(0x10301) [rpcf_edit_tel_direction]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['dir_id'], U_TP_I)
        if 'zone_id' not in params: params['zone_id'] = 0
        self.pck.add_data(params['zone_id'], U_TP_I)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.add_data(params['calling_prefix'], U_TP_S)
        self.pck.add_data(params['called_prefix'], U_TP_S)
        self.pck.add_data(params['incoming_trunk'], U_TP_S)
        self.pck.add_data(params['outgoing_trunk'], U_TP_S)
        self.pck.add_data(params['pbx_id'], U_TP_S)
        if 'calling_prefix_regexp' not in params: params['calling_prefix_regexp'] = 1
        self.pck.add_data(params['calling_prefix_regexp'], U_TP_I)
        if 'called_prefix_regexp' not in params: params['called_prefix_regexp'] = 1
        self.pck.add_data(params['called_prefix_regexp'], U_TP_I)
        if 'skip' not in params: params['skip'] = 0
        self.pck.add_data(params['skip'], U_TP_I)
        self.pck.add_data(params['dir_type'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['dir_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_remove_tel_direction(self, params):
        """ description
        @params: 
        :(s)  dir_id :	(i)  - 
        @returns: 
        :(s)  dir_id :	(i)  - 
        """
        if not self.urfa_call(0x10302):
            raise Exception("Fail of urfa_call(0x10302) [rpcf_remove_tel_direction]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['dir_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['dir_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_tel_zone(self, params):
        """ description
        @params: 
        :(s)  name :	(s)  - 
        :(s)  zone_type :	(i)  - 
        @returns: 
        :(s)  zone_id :	(i)  - 
        """
        if not self.urfa_call(0x10303):
            raise Exception("Fail of urfa_call(0x10303) [rpcf_add_tel_zone]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.add_data(params['zone_type'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['zone_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_tel_zone(self, params):
        """ description
        @params: 
        :(s)  zone_id :	(i)  - 
        :(s)  name :	(s)  - 
        :(s)  zone_type :	(i)  - 
        @returns: 
        :(s)  zone_id :	(i)  - 
        """
        if not self.urfa_call(0x10304):
            raise Exception("Fail of urfa_call(0x10304) [rpcf_edit_tel_zone]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['zone_id'], U_TP_I)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.add_data(params['zone_type'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['zone_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_remove_tel_zone(self, params):
        """ description
        @params: 
        :(s)  zone_id :	(i)  - 
        @returns: 
        :(s)  zone_id :	(i)  - 
        """
        if not self.urfa_call(0x10305):
            raise Exception("Fail of urfa_call(0x10305) [rpcf_remove_tel_zone]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['zone_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['zone_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_tel_direction(self, params):
        """ description
        @params: 
        :(s)  dir_id :	(i)  - 
        @returns: 
        :(s)  dir_id :	(i)  - 
        :(s)    zone_id :	(i)  - 
        :(s)    supplier_id :	(i)  - 
        :(s)    name :	(s)  - 
        :(s)    calling_prefix :	(s)  - 
        :(s)    called_prefix :	(s)  - 
        :(s)    incoming_trunk :	(s)  - 
        :(s)    outgoing_trunk :	(s)  - 
        :(s)    pbx_id :	(s)  - 
        :(s)    calling_prefix_regexp :	(i)  - 
        :(s)    called_prefix_regexp :	(i)  - 
        :(s)    skip :	(i)  - 
        :(s)    create_date :	(i)  - 
        :(s)    update_date :	(i)  - 
        """
        if not self.urfa_call(0x10306):
            raise Exception("Fail of urfa_call(0x10306) [rpcf_get_tel_direction]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['dir_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['dir_id'] = self.pck.get_data(U_TP_I)
        if params['dir_id']  !=  -1:
            ret['zone_id'] = self.pck.get_data(U_TP_I)
            ret['supplier_id'] = self.pck.get_data(U_TP_I)
            ret['name'] = self.pck.get_data(U_TP_S)
            ret['calling_prefix'] = self.pck.get_data(U_TP_S)
            ret['called_prefix'] = self.pck.get_data(U_TP_S)
            ret['incoming_trunk'] = self.pck.get_data(U_TP_S)
            ret['outgoing_trunk'] = self.pck.get_data(U_TP_S)
            ret['pbx_id'] = self.pck.get_data(U_TP_S)
            ret['calling_prefix_regexp'] = self.pck.get_data(U_TP_I)
            ret['called_prefix_regexp'] = self.pck.get_data(U_TP_I)
            ret['skip'] = self.pck.get_data(U_TP_I)
            ret['create_date'] = self.pck.get_data(U_TP_I)
            ret['update_date'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_tel_zone(self, params):
        """ description
        @params: 
        :(s)  zone_id :	(i)  - 
        @returns: 
        :(s)  zone_id :	(i)  - 
        :(s)    supplier_id :	(i)  - 
        :(s)    name :	(s)  - 
        :(s)    create_date :	(i)  - 
        :(s)    update_date :	(i)  - 
        :(s)    dir_count :	(i)  - 
        :(s)      dir_id_array :	(i)  - 
        :(s)      dir_name_array :	(s)  - 
        """
        if not self.urfa_call(0x10307):
            raise Exception("Fail of urfa_call(0x10307) [rpcf_get_tel_zone]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['zone_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['zone_id'] = self.pck.get_data(U_TP_I)
        if params['zone_id']  !=  -1:
            ret['supplier_id'] = self.pck.get_data(U_TP_I)
            ret['name'] = self.pck.get_data(U_TP_S)
            ret['create_date'] = self.pck.get_data(U_TP_I)
            ret['update_date'] = self.pck.get_data(U_TP_I)
            ret['dir_count'] = self.pck.get_data(U_TP_I)
            for i in range(ret['dir_count']): 
                self.pck.recv(self.sck)
                ret['dir_id_array'][i] = self.pck.get_data(U_TP_I)
                ret['dir_name_array'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_tel_directions_list(self, params):
        """ description
        @params: 
        :(s)  start :	(i)  - 
        :(s)  count :	(i)  - 
        :(s)  skip_ids_cnt :	(i)  - 
        :(s)    skip_id :	(i)  - 
        @returns: 
        :(s)  dir_count :	(i)  - 
        :(s)    dir_id_array :	(i)  - 
        :(s)    zone_id_array :	(i)  - 
        :(s)    supplier_id_array :	(i)  - 
        :(s)    dir_name_array :	(s)  - 
        :(s)    calling_prefix_array :	(s)  - 
        :(s)    called_prefix_array :	(s)  - 
        :(s)    create_date_array :	(i)  - 
        :(s)    update_date_array :	(i)  - 
        """
        if not self.urfa_call(0x1031d):
            raise Exception("Fail of urfa_call(0x1031d) [rpcf_tel_directions_list]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['start'], U_TP_I)
        self.pck.add_data(params['count'], U_TP_I)
        self.pck.add_data(params['skip_ids_cnt'], U_TP_I)
        for i in range(params['skip_ids_cnt']):
            self.pck.add_data(params['skip_id'][i], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['dir_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['dir_count']): 
            self.pck.recv(self.sck)
            ret['dir_id_array'][i] = self.pck.get_data(U_TP_I)
            ret['zone_id_array'][i] = self.pck.get_data(U_TP_I)
            ret['supplier_id_array'][i] = self.pck.get_data(U_TP_I)
            ret['dir_name_array'][i] = self.pck.get_data(U_TP_S)
            ret['calling_prefix_array'][i] = self.pck.get_data(U_TP_S)
            ret['called_prefix_array'][i] = self.pck.get_data(U_TP_S)
            ret['create_date_array'][i] = self.pck.get_data(U_TP_I)
            ret['update_date_array'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_tel_directions_count(self, params):
        """ description
        @params: 
        :(s)  skip_ids_cnt :	(i)  - 
        :(s)    skip_id :	(i)  - 
        @returns: 
        :(s)  count :	(i)  - 
        """
        if not self.urfa_call(0x1031e):
            raise Exception("Fail of urfa_call(0x1031e) [rpcf_get_tel_directions_count]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['skip_ids_cnt'], U_TP_I)
        for i in range(params['skip_ids_cnt']):
            self.pck.add_data(params['skip_id'][i], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['count'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_search_tel_dirs(self, params):
        """ description
        @params: 
        :(s)  status :	(i)  - 
        :(s)  params_cnt :	(i)  - 
        :(s)    field :	(i)  - 
        :(s)    criteria :	(i)  - 
        :(s)    value :	(s)  - 
        :(s)  skip_ids_cnt :	(i)  - 
        :(s)    skip_id :	(i)  - 
        :(s)  offset :	(i)  - 
        :(s)  count :	(i)  - 
        @returns: 
        :(s)  dir_count :	(i)  - 
        :(s)    dir_id_array :	(i)  - 
        :(s)    zone_id_array :	(i)  - 
        :(s)    supplier_id_array :	(i)  - 
        :(s)    dir_name_array :	(s)  - 
        :(s)    calling_prefix_array :	(s)  - 
        :(s)    called_prefix_array :	(s)  - 
        :(s)    create_date_array :	(i)  - 
        :(s)    update_date_array :	(i)  - 
        """
        if not self.urfa_call(0x1032b):
            raise Exception("Fail of urfa_call(0x1032b) [rpcf_search_tel_dirs]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['status'], U_TP_I)
        self.pck.add_data(params['params_cnt'], U_TP_I)
        for i in range(params['params_cnt']):
            self.pck.add_data(params['field'][i], U_TP_I)
            self.pck.add_data(params['criteria'][i], U_TP_I)
            self.pck.add_data(params['value'][i], U_TP_S)
        self.pck.add_data(params['skip_ids_cnt'], U_TP_I)
        for i in range(params['skip_ids_cnt']):
            self.pck.add_data(params['skip_id'][i], U_TP_I)
        self.pck.add_data(params['offset'], U_TP_I)
        self.pck.add_data(params['count'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['dir_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['dir_count']): 
            self.pck.recv(self.sck)
            ret['dir_id_array'][i] = self.pck.get_data(U_TP_I)
            ret['zone_id_array'][i] = self.pck.get_data(U_TP_I)
            ret['supplier_id_array'][i] = self.pck.get_data(U_TP_I)
            ret['dir_name_array'][i] = self.pck.get_data(U_TP_S)
            ret['calling_prefix_array'][i] = self.pck.get_data(U_TP_S)
            ret['called_prefix_array'][i] = self.pck.get_data(U_TP_S)
            ret['create_date_array'][i] = self.pck.get_data(U_TP_I)
            ret['update_date_array'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_founded_tel_dirs_count(self, params):
        """ description
        @params: 
        :(s)  status :	(i)  - 
        :(s)  params_cnt :	(i)  - 
        :(s)    field :	(i)  - 
        :(s)    criteria :	(i)  - 
        :(s)    value :	(s)  - 
        :(s)  skip_ids_cnt :	(i)  - 
        :(s)    skip_id :	(i)  - 
        @returns: 
        :(s)  count :	(i)  - 
        """
        if not self.urfa_call(0x1031f):
            raise Exception("Fail of urfa_call(0x1031f) [rpcf_get_founded_tel_dirs_count]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['status'], U_TP_I)
        self.pck.add_data(params['params_cnt'], U_TP_I)
        for i in range(params['params_cnt']):
            self.pck.add_data(params['field'][i], U_TP_I)
            self.pck.add_data(params['criteria'][i], U_TP_I)
            self.pck.add_data(params['value'][i], U_TP_S)
        self.pck.add_data(params['skip_ids_cnt'], U_TP_I)
        for i in range(params['skip_ids_cnt']):
            self.pck.add_data(params['skip_id'][i], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['count'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_tel_zones_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  zone_count :	(i)  - 
        :(s)    zone_id_array :	(i)  - 
        :(s)    supplier_id_array :	(i)  - 
        :(s)    name_array :	(s)  - 
        :(s)    create_date_array :	(i)  - 
        :(s)    update_date_array :	(i)  - 
        """
        if not self.urfa_call(0x10309):
            raise Exception("Fail of urfa_call(0x10309) [rpcf_tel_zones_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['zone_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['zone_count']): 
            self.pck.recv(self.sck)
            ret['zone_id_array'][i] = self.pck.get_data(U_TP_I)
            ret['supplier_id_array'][i] = self.pck.get_data(U_TP_I)
            ret['name_array'][i] = self.pck.get_data(U_TP_S)
            ret['create_date_array'][i] = self.pck.get_data(U_TP_I)
            ret['update_date_array'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_tel_service(self, params):
        """ description
        @params: 
        :(s)  parent_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  is_dynamic :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  discount_method :	(i)  - 
        :(s)  radius_sessions_limit :	(i)  - 
        :(s)  tariff_class_count :	(i)  - 
        :(s)    tariff_class :	(i)  - 
        :(s)    border_count :	(i)  - 
        :(s)      border :	(i)  - 
        :(s)      cost_mult :	(d)  - 
        :(s)    timerange_count :	(i)  - 
        :(s)      timerange_id :	(i)  - 
        :(s)      cost :	(d)  - 
        :(s)    prepaid_array :	(i)  - 
        :(s)    fixed_cost_array :	(i)  - 
        :(s)  free_time :	(i)  - 
        :(s)  first_period_length :	(i)  - 
        :(s)  first_period_step :	(i)  - 
        :(s)  second_period_step :	(i)  - 
        :(s)  time_unit_size :	(i)  - 
        :(s)  discount_free_time :	(i)  - 
        :(s)  min_charge :	(d)  - 
        @returns: 
        :(s)  service_id :	(i)  - 
        """
        if not self.urfa_call(0x1033d):
            raise Exception("Fail of urfa_call(0x1033d) [rpcf_add_tel_service]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['parent_id'], U_TP_I)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.add_data(params['service_name'], U_TP_S)
        self.pck.add_data(params['comment'], U_TP_S)
        self.pck.add_data(params['link_by_default'], U_TP_I)
        self.pck.add_data(params['is_dynamic'], U_TP_I)
        self.pck.add_data(params['cost'], U_TP_D)
        self.pck.add_data(params['discount_method'], U_TP_I)
        self.pck.add_data(params['radius_sessions_limit'], U_TP_I)
        self.pck.add_data(params['tariff_class_count'], U_TP_I)
        for i in range(params['tariff_class_count']):
            self.pck.add_data(params['tariff_class'][i], U_TP_I)
            self.pck.add_data(params['border_count'][i], U_TP_I)
            for j in range(params['border_count'][i]):
                self.pck.add_data(params['border'][i][j], U_TP_I)
                self.pck.add_data(params['cost_mult'][i][j], U_TP_D)
            self.pck.add_data(params['timerange_count'], U_TP_I)
            for j in range(params['timerange_count']):
                self.pck.add_data(params['timerange_id'][i][j], U_TP_I)
                self.pck.add_data(params['cost'][i][j], U_TP_D)
            self.pck.add_data(params['prepaid_array'][i], U_TP_I)
            self.pck.add_data(params['fixed_cost_array'][i], U_TP_I)
        self.pck.add_data(params['free_time'], U_TP_I)
        self.pck.add_data(params['first_period_length'], U_TP_I)
        self.pck.add_data(params['first_period_step'], U_TP_I)
        self.pck.add_data(params['second_period_step'], U_TP_I)
        self.pck.add_data(params['time_unit_size'], U_TP_I)
        self.pck.add_data(params['discount_free_time'], U_TP_I)
        self.pck.add_data(params['min_charge'], U_TP_D)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['service_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_tel_service(self, params):
        """ description
        @params: 
        :(s)  service_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  is_dynamic :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  discount_method :	(i)  - 
        :(s)  radius_sessions_limit :	(i)  - 
        :(s)  tariff_class_count :	(i)  - 
        :(s)    tariff_class :	(i)  - 
        :(s)    border_count :	(i)  - 
        :(s)      border :	(i)  - 
        :(s)      cost_mult :	(d)  - 
        :(s)    timerange_count :	(i)  - 
        :(s)      timerange_id :	(i)  - 
        :(s)      cost :	(d)  - 
        :(s)    prepaid_array :	(i)  - 
        :(s)    fixed_cost_array :	(i)  - 
        :(s)  free_time :	(i)  - 
        :(s)  first_period_length :	(i)  - 
        :(s)  first_period_step :	(i)  - 
        :(s)  second_period_step :	(i)  - 
        :(s)  time_unit_size :	(i)  - 
        :(s)  discount_free_time :	(i)  - 
        :(s)  min_charge :	(d)  - 
        @returns: 
        :(s)  service_id :	(i)  - 
        """
        if not self.urfa_call(0x1033e):
            raise Exception("Fail of urfa_call(0x1033e) [rpcf_edit_tel_service]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.add_data(params['parent_id'], U_TP_I)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.add_data(params['service_name'], U_TP_S)
        self.pck.add_data(params['comment'], U_TP_S)
        self.pck.add_data(params['link_by_default'], U_TP_I)
        self.pck.add_data(params['is_dynamic'], U_TP_I)
        self.pck.add_data(params['cost'], U_TP_D)
        self.pck.add_data(params['discount_method'], U_TP_I)
        self.pck.add_data(params['radius_sessions_limit'], U_TP_I)
        self.pck.add_data(params['tariff_class_count'], U_TP_I)
        for i in range(params['tariff_class_count']):
            self.pck.add_data(params['tariff_class'][i], U_TP_I)
            self.pck.add_data(params['border_count'][i], U_TP_I)
            for j in range(params['border_count'][i]):
                self.pck.add_data(params['border'][i][j], U_TP_I)
                self.pck.add_data(params['cost_mult'][i][j], U_TP_D)
            self.pck.add_data(params['timerange_count'], U_TP_I)
            for j in range(params['timerange_count']):
                self.pck.add_data(params['timerange_id'][i][j], U_TP_I)
                self.pck.add_data(params['cost'][i][j], U_TP_D)
            self.pck.add_data(params['prepaid_array'][i], U_TP_I)
            self.pck.add_data(params['fixed_cost_array'][i], U_TP_I)
        self.pck.add_data(params['free_time'], U_TP_I)
        self.pck.add_data(params['first_period_length'], U_TP_I)
        self.pck.add_data(params['first_period_step'], U_TP_I)
        self.pck.add_data(params['second_period_step'], U_TP_I)
        self.pck.add_data(params['time_unit_size'], U_TP_I)
        self.pck.add_data(params['discount_free_time'], U_TP_I)
        self.pck.add_data(params['min_charge'], U_TP_D)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['service_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_tel_service(self, params):
        """ description
        @params: 
        :(s)  sid :	(i)  - 
        @returns: 
        :(s)  service_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  is_dynamic :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  discount_method :	(i)  - 
        :(s)  radius_sessions_limit :	(i)  - 
        :(s)  tariff_class_count :	(i)  - 
        :(s)    tariff_class :	(i)  - 
        :(s)    border_count :	(i)  - 
        :(s)      border :	(i)  - 
        :(s)      cost_mult :	(d)  - 
        :(s)    timerange_count :	(i)  - 
        :(s)      timerange_id :	(i)  - 
        :(s)      cost :	(d)  - 
        :(s)    prepaid_array :	(i)  - 
        :(s)    fixed_cost_array :	(i)  - 
        :(s)  free_time :	(i)  - 
        :(s)  first_period_length :	(i)  - 
        :(s)  first_period_step :	(i)  - 
        :(s)  second_period_step :	(i)  - 
        :(s)  time_unit_size :	(i)  - 
        :(s)  discount_free_time :	(i)  - 
        :(s)  min_charge :	(d)  - 
        """
        if not self.urfa_call(0x1033f):
            raise Exception("Fail of urfa_call(0x1033f) [rpcf_get_tel_service]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['sid'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['service_id'] = self.pck.get_data(U_TP_I)
        ret['parent_id'] = self.pck.get_data(U_TP_I)
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        ret['service_name'] = self.pck.get_data(U_TP_S)
        ret['comment'] = self.pck.get_data(U_TP_S)
        ret['link_by_default'] = self.pck.get_data(U_TP_I)
        ret['is_dynamic'] = self.pck.get_data(U_TP_I)
        ret['cost'] = self.pck.get_data(U_TP_D)
        ret['discount_method'] = self.pck.get_data(U_TP_I)
        ret['radius_sessions_limit'] = self.pck.get_data(U_TP_I)
        ret['tariff_class_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['tariff_class_count']): 
            self.pck.recv(self.sck)
            ret['tariff_class'][i] = self.pck.get_data(U_TP_I)
            ret['border_count'][i] = self.pck.get_data(U_TP_I)
            for j in range(ret['border_count'][i]): 
                self.pck.recv(self.sck)
                if not i in ret['border']:ret['border'][i] = dict()
                ret['border'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['cost_mult']:ret['cost_mult'][i] = dict()
                ret['cost_mult'][i][j] = self.pck.get_data(U_TP_D)
            self.pck.recv(self.sck)
            ret['timerange_count'] = self.pck.get_data(U_TP_I)
            for j in range(ret['timerange_count']): 
                self.pck.recv(self.sck)
                if not i in ret['timerange_id']:ret['timerange_id'][i] = dict()
                ret['timerange_id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['cost']:ret['cost'][i] = dict()
                ret['cost'][i][j] = self.pck.get_data(U_TP_D)
            self.pck.recv(self.sck)
            ret['prepaid_array'][i] = self.pck.get_data(U_TP_I)
            ret['fixed_cost_array'][i] = self.pck.get_data(U_TP_I)
        self.pck.recv(self.sck)
        ret['free_time'] = self.pck.get_data(U_TP_I)
        ret['first_period_length'] = self.pck.get_data(U_TP_I)
        ret['first_period_step'] = self.pck.get_data(U_TP_I)
        ret['second_period_step'] = self.pck.get_data(U_TP_I)
        ret['time_unit_size'] = self.pck.get_data(U_TP_I)
        ret['discount_free_time'] = self.pck.get_data(U_TP_I)
        ret['min_charge'] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_tel_service_link(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  account_id :	(i)  - 
        :(s)  service_id :	(i)  - 
        :(s)  tplink_id :	(i)  - 
        :(s)  discount_period_id :	(i)  - 
        :(s)  start_date :	(i)  - 
        :(s)  expire_date :	(i)  - 
        :(s)  policy_id :	(i)  - 
        :(s)  recalc_fee :	(i)  - 
        :(s)  cost_coef :	(d) = _def_  - 
        :(s)  login_count :	(i)  - 
        :(s)    login :	(s)  - 
        :(s)    number :	(s)  - 
        :(s)    incoming_trunk :	(s)  - 
        :(s)    outgoing_trunk :	(s)  - 
        :(s)    pbx_id :	(s)  - 
        :(s)    password :	(s)  - 
        :(s)    allowed_cid :	(s)  - 
        @returns: 
        :(s)  slink_id :	(i)  - 
        """
        if not self.urfa_call(0x1031a):
            raise Exception("Fail of urfa_call(0x1031a) [rpcf_add_tel_service_link]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.add_data(params['tplink_id'], U_TP_I)
        self.pck.add_data(params['discount_period_id'], U_TP_I)
        self.pck.add_data(params['start_date'], U_TP_I)
        self.pck.add_data(params['expire_date'], U_TP_I)
        self.pck.add_data(params['policy_id'], U_TP_I)
        self.pck.add_data(params['recalc_fee'], U_TP_I)
        if 'cost_coef' not in params: params['cost_coef'] = 1.0
        self.pck.add_data(params['cost_coef'], U_TP_D)
        self.pck.add_data(params['login_count'], U_TP_I)
        for i in range(params['login_count']):
            self.pck.add_data(params['login'][i], U_TP_S)
            self.pck.add_data(params['number'][i], U_TP_S)
            self.pck.add_data(params['incoming_trunk'][i], U_TP_S)
            self.pck.add_data(params['outgoing_trunk'][i], U_TP_S)
            self.pck.add_data(params['pbx_id'][i], U_TP_S)
            self.pck.add_data(params['password'][i], U_TP_S)
            self.pck.add_data(params['allowed_cid'][i], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['slink_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_tel_service_link(self, params):
        """ description
        @params: 
        :(s)  slinkId :	(i)  - 
        :(s)  start_date :	(i)  - 
        :(s)  expire_date :	(i)  - 
        :(s)  policy_id :	(i)  - 
        :(s)  cost_coef :	(d)  - 
        :(s)  loginCount :	(i)  - 
        :(s)    login :	(s)  - 
        :(s)    number :	(s)  - 
        :(s)    incoming_trunk :	(s)  - 
        :(s)    outgoing_trunk :	(s)  - 
        :(s)    pbx_id :	(s)  - 
        :(s)    password :	(s)  - 
        :(s)    allowed_cid :	(s)  - 
        @returns: 
        :(s)  slinkId :	(i)  - 
        """
        if not self.urfa_call(0x1031b):
            raise Exception("Fail of urfa_call(0x1031b) [rpcf_edit_tel_service_link]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slinkId'], U_TP_I)
        self.pck.add_data(params['start_date'], U_TP_I)
        self.pck.add_data(params['expire_date'], U_TP_I)
        self.pck.add_data(params['policy_id'], U_TP_I)
        self.pck.add_data(params['cost_coef'], U_TP_D)
        self.pck.add_data(params['loginCount'], U_TP_I)
        for i in range(params['loginCount']):
            self.pck.add_data(params['login'][i], U_TP_S)
            self.pck.add_data(params['number'][i], U_TP_S)
            self.pck.add_data(params['incoming_trunk'][i], U_TP_S)
            self.pck.add_data(params['outgoing_trunk'][i], U_TP_S)
            self.pck.add_data(params['pbx_id'][i], U_TP_S)
            self.pck.add_data(params['password'][i], U_TP_S)
            self.pck.add_data(params['allowed_cid'][i], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['slinkId'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_tel_service_link(self, params):
        """ description
        @params: 
        :(s)  slinkId :	(i)  - 
        @returns: 
        :(s)  accounting_period_id :	(i)  - 
        :(s)  start_date :	(i)  - 
        :(s)  expire_date :	(i)  - 
        :(s)  policy_id :	(i)  - 
        :(s)  cost_coef :	(d)  - 
        :(s)  numSize :	(i)  - 
        :(s)    login :	(s)  - 
        :(s)    number :	(s)  - 
        :(s)    incoming_trunk :	(s)  - 
        :(s)    outgoing_trunk :	(s)  - 
        :(s)    pbx_id :	(s)  - 
        :(s)    password :	(s)  - 
        :(s)    allowed_cid :	(s)  - 
        :(s)  slinkId :	(i)  - 
        """
        if not self.urfa_call(0x1031c):
            raise Exception("Fail of urfa_call(0x1031c) [rpcf_get_tel_service_link]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slinkId'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['accounting_period_id'] = self.pck.get_data(U_TP_I)
        ret['start_date'] = self.pck.get_data(U_TP_I)
        ret['expire_date'] = self.pck.get_data(U_TP_I)
        ret['policy_id'] = self.pck.get_data(U_TP_I)
        ret['cost_coef'] = self.pck.get_data(U_TP_D)
        ret['numSize'] = self.pck.get_data(U_TP_I)
        for i in range(ret['numSize']): 
            self.pck.recv(self.sck)
            ret['login'][i] = self.pck.get_data(U_TP_S)
            ret['number'][i] = self.pck.get_data(U_TP_S)
            ret['incoming_trunk'][i] = self.pck.get_data(U_TP_S)
            ret['outgoing_trunk'][i] = self.pck.get_data(U_TP_S)
            ret['pbx_id'][i] = self.pck.get_data(U_TP_S)
            ret['password'][i] = self.pck.get_data(U_TP_S)
            ret['allowed_cid'][i] = self.pck.get_data(U_TP_S)
        self.pck.recv(self.sck)
        ret['slinkId'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_put_tel_call(self, params):
        """ description
        @params: 
        :(s)  calling_number :	(s)  - 
        :(s)  called_number :	(s)  - 
        :(s)  incoming_trunk :	(s)  - 
        :(s)  outgoing_trunk :	(s)  - 
        :(s)  session_id :	(s)  - 
        :(s)  pbx_id :	(s)  - 
        :(s)  login :	(s)  - 
        :(s)  disconnect_cause :	(s)  - 
        :(s)  call_start_date :	(i) = _def_  - 
        :(s)  call_duration :	(i) = _def_  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x10310):
            raise Exception("Fail of urfa_call(0x10310) [rpcf_put_tel_call]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['calling_number'], U_TP_S)
        self.pck.add_data(params['called_number'], U_TP_S)
        self.pck.add_data(params['incoming_trunk'], U_TP_S)
        self.pck.add_data(params['outgoing_trunk'], U_TP_S)
        self.pck.add_data(params['session_id'], U_TP_S)
        self.pck.add_data(params['pbx_id'], U_TP_S)
        self.pck.add_data(params['login'], U_TP_S)
        self.pck.add_data(params['disconnect_cause'], U_TP_S)
        if 'call_start_date' not in params: params['call_start_date'] = 0
        self.pck.add_data(params['call_start_date'], U_TP_I)
        if 'call_duration' not in params: params['call_duration'] = 0
        self.pck.add_data(params['call_duration'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_tel_number_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  count :	(i)  - 
        :(s)    num_id :	(i)  - 
        :(s)    slink_id :	(i)  - 
        :(s)    login :	(s)  - 
        :(s)    number :	(s)  - 
        :(s)    incoming_trunk :	(s)  - 
        :(s)    outgoing_trunk :	(s)  - 
        :(s)    pbx_id :	(s)  - 
        :(s)    password :	(s)  - 
        :(s)    allowed_cid :	(s)  - 
        """
        if not self.urfa_call(0x10319):
            raise Exception("Fail of urfa_call(0x10319) [rpcf_get_tel_number_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['count']): 
            self.pck.recv(self.sck)
            ret['num_id'][i] = self.pck.get_data(U_TP_I)
            ret['slink_id'][i] = self.pck.get_data(U_TP_I)
            ret['login'][i] = self.pck.get_data(U_TP_S)
            ret['number'][i] = self.pck.get_data(U_TP_S)
            ret['incoming_trunk'][i] = self.pck.get_data(U_TP_S)
            ret['outgoing_trunk'][i] = self.pck.get_data(U_TP_S)
            ret['pbx_id'][i] = self.pck.get_data(U_TP_S)
            ret['password'][i] = self.pck.get_data(U_TP_S)
            ret['allowed_cid'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_validate_tel_supplier_dirs(self, params):
        """ description
        @params: 
        :(s)  supplier_id :	(i)  - 
        :(s)  dirs_cnt :	(i)  - 
        :(s)    dir :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        :(s)  founded_dir_id :	(i)  - 
        :(s)  founded_zone_id :	(i)  - 
        :(s)  founded_supplier_id :	(i)  - 
        """
        if not self.urfa_call(0x10321):
            raise Exception("Fail of urfa_call(0x10321) [rpcf_validate_tel_supplier_dirs]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['supplier_id'], U_TP_I)
        self.pck.add_data(params['dirs_cnt'], U_TP_I)
        for i in range(params['dirs_cnt']):
            self.pck.add_data(params['dir'][i], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        ret['founded_dir_id'] = self.pck.get_data(U_TP_I)
        ret['founded_zone_id'] = self.pck.get_data(U_TP_I)
        ret['founded_supplier_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_tel_suppliers_directions(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  dirs_cnt :	(i)  - 
        :(s)    dir_id :	(i)  - 
        :(s)    supplier_id :	(i)  - 
        """
        if not self.urfa_call(0x8023):
            raise Exception("Fail of urfa_call(0x8023) [rpcf_get_tel_suppliers_directions]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['dirs_cnt'] = self.pck.get_data(U_TP_I)
        for i in range(ret['dirs_cnt']): 
            self.pck.recv(self.sck)
            ret['dir_id'][i] = self.pck.get_data(U_TP_I)
            ret['supplier_id'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_core_time(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  time :	(i)  - 
        :(s)  tzname :	(s)  - 
        """
        if not self.urfa_call(0x11112):
            raise Exception("Fail of urfa_call(0x11112) [rpcf_get_core_time]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['time'] = self.pck.get_data(U_TP_I)
        ret['tzname'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_unused_prepaid(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  bytes_in_mbyte :	(i)  - 
        :(s)  links_size :	(i)  - 
        :(s)    pinfo_size :	(i)  - 
        :(s)      id :	(i)  - 
        :(s)      value :	(l)  - 
        """
        if not self.urfa_call(-0x5502):
            raise Exception("Fail of urfa_call(-0x5502) [rpcf_user5_get_unused_prepaid]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['bytes_in_mbyte'] = self.pck.get_data(U_TP_I)
        ret['links_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['links_size']): 
            self.pck.recv(self.sck)
            ret['pinfo_size'] = self.pck.get_data(U_TP_I)
            ret['pinfo_size_array'][i]=ret['pinfo_size']
            for j in range(ret['pinfo_size']): 
                self.pck.recv(self.sck)
                if not i in ret['id']:ret['id'][i] = dict()
                ret['id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['value']:ret['value'][i] = dict()
                ret['value'][i][j] = self.pck.get_data(U_TP_L)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_card_payment(self, params):
        """ description
        @params: 
        :(s)  account_id :	(i)  - 
        :(s)  card_id :	(i)  - 
        :(s)  secret :	(s)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(-0x4205):
            raise Exception("Fail of urfa_call(-0x4205) [rpcf_user5_card_payment]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['card_id'], U_TP_I)
        self.pck.add_data(params['secret'], U_TP_S)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_card_payment_new(self, params):
        """ description
        @params: 
        :(s)  account_id :	(i)  - 
        :(s)  card_id :	(i)  - 
        :(s)  secret :	(s)  - 
        @returns: 
        :(s)  result :	(i)  - 
        :(s)    error :	(s)  - 
        """
        if not self.urfa_call(-0x4045):
            raise Exception("Fail of urfa_call(-0x4045) [rpcf_user5_card_payment_new]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['card_id'], U_TP_I)
        self.pck.add_data(params['secret'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if ret['result']  ==  0:
            ret['error'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_tel_report(self, params):
        """ description
        @params: 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i)  - 
        @returns: 
        :(s)  accounts_size :	(i)  - 
        :(s)    dhs_log_size :	(i)  - 
        :(s)      recv_date :	(i)  - 
        :(s)      recv_date_plus_acct_sess_time :	(i)  - 
        :(s)      acct_sess_time :	(i)  - 
        :(s)      setup_time :	(i)  - 
        :(s)      Calling_Station_Id :	(s)  - 
        :(s)      Called_Station_Id :	(s)  - 
        :(s)      dname :	(s)  - 
        :(s)      total_cost :	(d)  - 
        """
        if not self.urfa_call(-0x4099):
            raise Exception("Fail of urfa_call(-0x4099) [rpcf_user5_get_tel_report]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['time_start'], U_TP_I)
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['accounts_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['accounts_size']): 
            self.pck.recv(self.sck)
            ret['dhs_log_size'] = self.pck.get_data(U_TP_I)
            ret['dhs_log_size_array'][i]=ret['dhs_log_size']
            for j in range(ret['dhs_log_size']): 
                self.pck.recv(self.sck)
                if not i in ret['recv_date']:ret['recv_date'][i] = dict()
                ret['recv_date'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['recv_date_plus_acct_sess_time']:ret['recv_date_plus_acct_sess_time'][i] = dict()
                ret['recv_date_plus_acct_sess_time'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['acct_sess_time']:ret['acct_sess_time'][i] = dict()
                ret['acct_sess_time'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['setup_time']:ret['setup_time'][i] = dict()
                ret['setup_time'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['Calling_Station_Id']:ret['Calling_Station_Id'][i] = dict()
                ret['Calling_Station_Id'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['Called_Station_Id']:ret['Called_Station_Id'][i] = dict()
                ret['Called_Station_Id'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['dname']:ret['dname'][i] = dict()
                ret['dname'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['total_cost']:ret['total_cost'][i] = dict()
                ret['total_cost'][i][j] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_accounts(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  accounts_size :	(i)  - 
        :(s)    account_id :	(i)  - 
        :(s)    balance :	(d)  - 
        :(s)    credit :	(d)  - 
        """
        if not self.urfa_call(-0x4055):
            raise Exception("Fail of urfa_call(-0x4055) [rpcf_user5_get_accounts]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['accounts_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['accounts_size']): 
            self.pck.recv(self.sck)
            ret['account_id'][i] = self.pck.get_data(U_TP_I)
            ret['balance'][i] = self.pck.get_data(U_TP_D)
            ret['credit'][i] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_tariff_name(self, params):
        """ description
        @params: 
        :(s)  tariff_id :	(i)  - 
        @returns: 
        :(s)  tariff_name :	(s)  - 
        """
        if not self.urfa_call(-0x4039):
            raise Exception("Fail of urfa_call(-0x4039) [rpcf_user5_get_tariff_name]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['tariff_name'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_remaining_prepaid_traffic(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(-0x4038):
            raise Exception("Fail of urfa_call(-0x4038) [rpcf_user5_get_remaining_prepaid_traffic]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_currency_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  currency_size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    currency_brief_name :	(s)  - 
        :(s)    currency_full_name :	(s)  - 
        :(s)    percent :	(d)  - 
        :(s)    rates :	(d)  - 
        """
        if not self.urfa_call(-0x4037):
            raise Exception("Fail of urfa_call(-0x4037) [rpcf_user5_get_currency_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['currency_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['currency_size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['currency_brief_name'][i] = self.pck.get_data(U_TP_S)
            ret['currency_full_name'][i] = self.pck.get_data(U_TP_S)
            ret['percent'][i] = self.pck.get_data(U_TP_D)
            ret['rates'][i] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_add_mime_message(self, params):
        """ description
        @params: 
        :(s)  subject :	(s)  - 
        :(s)  message :	(s)  - 
        :(s)  mime :	(s)  - 
        :(s)  state :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(-0x4034):
            raise Exception("Fail of urfa_call(-0x4034) [rpcf_user5_add_mime_message]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['subject'], U_TP_S)
        self.pck.add_data(params['message'], U_TP_S)
        self.pck.add_data(params['mime'], U_TP_S)
        self.pck.add_data(params['state'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_mime_messages_list_to_now(self, params):
        """ description
        @params: 
        :(s)  time_start :	(i)  - 
        @returns: 
        :(s)  time_end :	(i)  - 
        :(s)  messages_size :	(i)  - 
        :(s)    send_date :	(i)  - 
        :(s)    recv_date :	(i)  - 
        :(s)    subject :	(s)  - 
        :(s)    message :	(s)  - 
        :(s)    mime :	(s)  - 
        :(s)    state :	(i)  - 
        """
        if not self.urfa_call(-0x4033):
            raise Exception("Fail of urfa_call(-0x4033) [rpcf_user5_mime_messages_list_to_now]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['time_start'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['time_end'] = self.pck.get_data(U_TP_I)
        ret['messages_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['messages_size']): 
            self.pck.recv(self.sck)
            ret['send_date'][i] = self.pck.get_data(U_TP_I)
            ret['recv_date'][i] = self.pck.get_data(U_TP_I)
            ret['subject'][i] = self.pck.get_data(U_TP_S)
            ret['message'][i] = self.pck.get_data(U_TP_S)
            ret['mime'][i] = self.pck.get_data(U_TP_S)
            ret['state'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_mime_messages_list(self, params):
        """ description
        @params: 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i)  - 
        @returns: 
        :(s)  messages_size :	(i)  - 
        :(s)    send_date :	(i)  - 
        :(s)    recv_date :	(i)  - 
        :(s)    subject :	(s)  - 
        :(s)    message :	(s)  - 
        :(s)    mime :	(s)  - 
        :(s)    state :	(i)  - 
        """
        if not self.urfa_call(-0x4032):
            raise Exception("Fail of urfa_call(-0x4032) [rpcf_user5_mime_messages_list]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['time_start'], U_TP_I)
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['messages_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['messages_size']): 
            self.pck.recv(self.sck)
            ret['send_date'][i] = self.pck.get_data(U_TP_I)
            ret['recv_date'][i] = self.pck.get_data(U_TP_I)
            ret['subject'][i] = self.pck.get_data(U_TP_S)
            ret['message'][i] = self.pck.get_data(U_TP_S)
            ret['mime'][i] = self.pck.get_data(U_TP_S)
            ret['state'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_traffic_report_detail(self, params):
        """ description
        @params: 
        :(s)  limit_size :	(i)  - 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i)  - 
        @returns: 
        :(s)  nf5a_size :	(i)  - 
        :(s)    timestamp :	(i)  - 
        :(s)    slink_id :	(i)  - 
        :(s)    sname :	(s)  - 
        :(s)    account_id :	(i)  - 
        :(s)    tclass :	(i)  - 
        :(s)    tcd_name :	(s)  - 
        :(s)    saddr :	(i)  - 
        :(s)    daddr :	(i)  - 
        :(s)    d_pkt :	(i)  - 
        :(s)    d_okt :	(i)  - 
        :(s)    sport :	(i)  - 
        :(s)    dport :	(i)  - 
        :(s)    tcp_flags :	(i)  - 
        :(s)    proto :	(i)  - 
        :(s)    tos :	(i)  - 
        """
        if not self.urfa_call(-0x4031):
            raise Exception("Fail of urfa_call(-0x4031) [rpcf_user5_traffic_report_detail]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['limit_size'], U_TP_I)
        self.pck.add_data(params['time_start'], U_TP_I)
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['nf5a_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['nf5a_size']): 
            self.pck.recv(self.sck)
            ret['timestamp'][i] = self.pck.get_data(U_TP_I)
            ret['slink_id'][i] = self.pck.get_data(U_TP_I)
            ret['sname'][i] = self.pck.get_data(U_TP_S)
            ret['account_id'][i] = self.pck.get_data(U_TP_I)
            ret['tclass'][i] = self.pck.get_data(U_TP_I)
            ret['tcd_name'][i] = self.pck.get_data(U_TP_S)
            ret['saddr'][i] = self.pck.get_data(U_TP_I)
            ret['daddr'][i] = self.pck.get_data(U_TP_I)
            ret['d_pkt'][i] = self.pck.get_data(U_TP_I)
            ret['d_okt'][i] = self.pck.get_data(U_TP_I)
            ret['sport'][i] = self.pck.get_data(U_TP_I)
            ret['dport'][i] = self.pck.get_data(U_TP_I)
            ret['tcp_flags'][i] = self.pck.get_data(U_TP_I)
            ret['proto'][i] = self.pck.get_data(U_TP_I)
            ret['tos'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_switch_internet_on_disconnect(self, params):
        """ description
        @params: 
        :(s)  on :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(-0x4030):
            raise Exception("Fail of urfa_call(-0x4030) [rpcf_user5_switch_internet_on_disconnect]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['on'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_discount_period_info(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        @returns: 
        :(s)  id :	(i)  - 
        :(s)  begin :	(i)  - 
        :(s)  end :	(i)  - 
        :(s)  periodic_type :	(i)  - 
        :(s)  next_discount_period_id :	(i)  - 
        :(s)  discount_interval :	(i)  - 
        :(s)  canonical_len :	(i)  - 
        :(s)  custom_duration :	(i)  - 
        :(s)  static_id :	(i)  - 
        """
        if not self.urfa_call(-0x402e):
            raise Exception("Fail of urfa_call(-0x402e) [rpcf_user5_get_discount_period_info]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['id'] = self.pck.get_data(U_TP_I)
        ret['begin'] = self.pck.get_data(U_TP_I)
        ret['end'] = self.pck.get_data(U_TP_I)
        ret['periodic_type'] = self.pck.get_data(U_TP_I)
        ret['next_discount_period_id'] = self.pck.get_data(U_TP_I)
        ret['discount_interval'] = self.pck.get_data(U_TP_I)
        ret['canonical_len'] = self.pck.get_data(U_TP_I)
        ret['custom_duration'] = self.pck.get_data(U_TP_I)
        ret['static_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcs_user5_get_services_name(self, params):
        """ description
        @params: 
        :(s)  service_id :	(i)  - 
        @returns: 
        :(s)  service_type :	(i)  - 
        :(s)  service_id :	(i)  - 
        :(s)  service_name :	(s)  - 
        :(s)  service_comment :	(s)  - 
        :(s)  periodic_cost :	(d)  - 
        """
        if not self.urfa_call(-0x402b):
            raise Exception("Fail of urfa_call(-0x402b) [rpcs_user5_get_services_name]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['service_type'] = self.pck.get_data(U_TP_I)
        ret['service_id'] = self.pck.get_data(U_TP_I)
        ret['service_name'] = self.pck.get_data(U_TP_S)
        ret['service_comment'] = self.pck.get_data(U_TP_S)
        ret['periodic_cost'] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_tpayment(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  is_exist :	(i)  - 
        :(s)    first_payment_time :	(i)  - 
        :(s)    last_payment_date :	(i)  - 
        :(s)    time2burn :	(i)  - 
        :(s)    payment_value :	(d)  - 
        :(s)    already_discounted :	(d)  - 
        """
        if not self.urfa_call(-0x4029):
            raise Exception("Fail of urfa_call(-0x4029) [rpcf_user5_tpayment]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['is_exist'] = self.pck.get_data(U_TP_I)
        if ret['is_exist']  !=  0:
            ret['first_payment_time'] = self.pck.get_data(U_TP_I)
            ret['last_payment_date'] = self.pck.get_data(U_TP_I)
            ret['time2burn'] = self.pck.get_data(U_TP_I)
            ret['payment_value'] = self.pck.get_data(U_TP_D)
            ret['already_discounted'] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_messages_list_to_now(self, params):
        """ description
        @params: 
        :(s)  time_start :	(i)  - 
        @returns: 
        :(s)  time_end :	(i)  - 
        :(s)  messages_size :	(i)  - 
        :(s)    send_date :	(i)  - 
        :(s)    recv_date :	(i)  - 
        :(s)    subject :	(s)  - 
        :(s)    message :	(s)  - 
        """
        if not self.urfa_call(-0x4028):
            raise Exception("Fail of urfa_call(-0x4028) [rpcf_user5_messages_list_to_now]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['time_start'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['time_end'] = self.pck.get_data(U_TP_I)
        ret['messages_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['messages_size']): 
            self.pck.recv(self.sck)
            ret['send_date'][i] = self.pck.get_data(U_TP_I)
            ret['recv_date'][i] = self.pck.get_data(U_TP_I)
            ret['subject'][i] = self.pck.get_data(U_TP_S)
            ret['message'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_prepaid_and_downloaded(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  bytes_in_mbyte :	(i)  - 
        :(s)    unk1 :	(i)  - 
        :(s)      iptraffic_service_name :	(s)  - 
        :(s)        unk2 :	(i)  - 
        :(s)          old_tclass_id_array :	(i)  - 
        :(s)          old_tclass_name_array :	(s)  - 
        :(s)          old_prepaid_array :	(l)  - 
        :(s)        unk2 :	(i)  - 
        :(s)          tclass_id_array :	(i)  - 
        :(s)          tclass_name_array :	(s)  - 
        :(s)          prepaid_array :	(l)  - 
        :(s)        unk2 :	(i)  - 
        :(s)          downloaded_tclass_id_array :	(i)  - 
        :(s)          downloaded_tclass_name_array :	(s)  - 
        :(s)          downloaded_array :	(l)  - 
        """
        if not self.urfa_call(-0x4027):
            raise Exception("Fail of urfa_call(-0x4027) [rpcf_user5_get_prepaid_and_downloaded]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['bytes_in_mbyte'] = self.pck.get_data(U_TP_I)
        for i in range(1000): 
            self.pck.recv(self.sck)
            ret['unk1'] = self.pck.get_data(U_TP_I)
            if ret['unk1']  ==  1:
                ret['iptraffic_service_name'] = self.pck.get_data(U_TP_S)
                for j in range(1000): 
                    self.pck.recv(self.sck)
                    ret['unk2'] = self.pck.get_data(U_TP_I)
                    if ret['unk2']  ==  1:
                        if not i in ret['old_tclass_id_array']:ret['old_tclass_id_array'][i] = dict()
                        ret['old_tclass_id_array'][i][j] = self.pck.get_data(U_TP_I)
                        if not i in ret['old_tclass_name_array']:ret['old_tclass_name_array'][i] = dict()
                        ret['old_tclass_name_array'][i][j] = self.pck.get_data(U_TP_S)
                        if not i in ret['old_prepaid_array']:ret['old_prepaid_array'][i] = dict()
                        ret['old_prepaid_array'][i][j] = self.pck.get_data(U_TP_L)
                    if ret['unk2']  ==  0:
                        break
                self.pck.recv(self.sck)
                for j in range(1000): 
                    self.pck.recv(self.sck)
                    ret['unk2'] = self.pck.get_data(U_TP_I)
                    if ret['unk2']  ==  1:
                        if not i in ret['tclass_id_array']:ret['tclass_id_array'][i] = dict()
                        ret['tclass_id_array'][i][j] = self.pck.get_data(U_TP_I)
                        if not i in ret['tclass_name_array']:ret['tclass_name_array'][i] = dict()
                        ret['tclass_name_array'][i][j] = self.pck.get_data(U_TP_S)
                        if not i in ret['prepaid_array']:ret['prepaid_array'][i] = dict()
                        ret['prepaid_array'][i][j] = self.pck.get_data(U_TP_L)
                    if ret['unk2']  ==  0:
                        break
                self.pck.recv(self.sck)
                for j in range(1000): 
                    self.pck.recv(self.sck)
                    ret['unk2'] = self.pck.get_data(U_TP_I)
                    if ret['unk2']  ==  1:
                        if not i in ret['downloaded_tclass_id_array']:ret['downloaded_tclass_id_array'][i] = dict()
                        ret['downloaded_tclass_id_array'][i][j] = self.pck.get_data(U_TP_I)
                        if not i in ret['downloaded_tclass_name_array']:ret['downloaded_tclass_name_array'][i] = dict()
                        ret['downloaded_tclass_name_array'][i][j] = self.pck.get_data(U_TP_S)
                        if not i in ret['downloaded_array']:ret['downloaded_array'][i] = dict()
                        ret['downloaded_array'][i][j] = self.pck.get_data(U_TP_L)
                    if ret['unk2']  ==  0:
                        break
            if ret['unk1']  ==  0:
                break
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_brief_report_for_wintray(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  user_int_status :	(i)  - 
        :(s)  balance :	(d)  - 
        """
        if not self.urfa_call(-0x4026):
            raise Exception("Fail of urfa_call(-0x4026) [rpcf_user5_brief_report_for_wintray]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['user_int_status'] = self.pck.get_data(U_TP_I)
        ret['balance'] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_change_password_service(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i)  - 
        :(s)  item_id :	(i)  - 
        :(s)  old_password :	(s)  - 
        :(s)  new_password :	(s)  - 
        :(s)  new_password_ret :	(s)  - 
        @returns: 
        :(s)  status :	(i)  - 
        """
        if not self.urfa_call(-0x4025):
            raise Exception("Fail of urfa_call(-0x4025) [rpcf_user5_change_password_service]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.add_data(params['item_id'], U_TP_I)
        self.pck.add_data(params['old_password'], U_TP_S)
        self.pck.add_data(params['new_password'], U_TP_S)
        self.pck.add_data(params['new_password_ret'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['status'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_services_info(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i)  - 
        @returns: 
        :(s)  service_type :	(i)  - 
        :(s)  service_id :	(i)  - 
        :(s)  service_name :	(s)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  discounted_in_curr_period :	(d)  - 
        :(s)  cost :	(d)  - 
        :(s)    bytes_in_mbyte :	(i)  - 
        :(s)    iptsl_downloaded_size :	(i)  - 
        :(s)      tclass :	(s)  - 
        :(s)      downloaded :	(l)  - 
        :(s)    iptsl_old_prepaid_size :	(i)  - 
        :(s)      tclass :	(s)  - 
        :(s)      prepaid :	(l)  - 
        :(s)    ipgroup_size :	(i)  - 
        :(s)      item_id :	(i)  - 
        :(s)      ip :	(i)  - 
        :(s)      mask :	(i)  - 
        :(s)      login :	(s)  - 
        :(s)    iptsd_borders_size :	(i)  - 
        :(s)      tclass_name :	(s)  - 
        :(s)      bytes :	(l)  - 
        :(s)      cost1 :	(d)  - 
        :(s)      group_type :	(i)  - 
        :(s)    iptsd_prepaid_size :	(i)  - 
        :(s)      tclass_name_p :	(s)  - 
        :(s)      prepaid_p :	(l)  - 
        :(s)    tsl_numbers_size :	(i)  - 
        :(s)      number :	(s)  - 
        :(s)      login :	(s)  - 
        :(s)      allowed_cid :	(s)  - 
        :(s)      item_id :	(i)  - 
        :(s)      null_param :	(i)  - 
        """
        if not self.urfa_call(-0x404a):
            raise Exception("Fail of urfa_call(-0x404a) [rpcf_user5_get_services_info]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['service_type'] = self.pck.get_data(U_TP_I)
        ret['service_id'] = self.pck.get_data(U_TP_I)
        ret['service_name'] = self.pck.get_data(U_TP_S)
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        ret['discounted_in_curr_period'] = self.pck.get_data(U_TP_D)
        ret['cost'] = self.pck.get_data(U_TP_D)
        if ret['service_type']  ==  3:
            ret['bytes_in_mbyte'] = self.pck.get_data(U_TP_I)
            ret['iptsl_downloaded_size'] = self.pck.get_data(U_TP_I)
            for i in range(ret['iptsl_downloaded_size']): 
                self.pck.recv(self.sck)
                ret['tclass'][i] = self.pck.get_data(U_TP_S)
                ret['downloaded'][i] = self.pck.get_data(U_TP_L)
            self.pck.recv(self.sck)
            ret['iptsl_old_prepaid_size'] = self.pck.get_data(U_TP_I)
            for i in range(ret['iptsl_old_prepaid_size']): 
                self.pck.recv(self.sck)
                ret['tclass'][i] = self.pck.get_data(U_TP_S)
                ret['prepaid'][i] = self.pck.get_data(U_TP_L)
            self.pck.recv(self.sck)
            ret['ipgroup_size'] = self.pck.get_data(U_TP_I)
            for i in range(ret['ipgroup_size']): 
                self.pck.recv(self.sck)
                ret['item_id'][i] = self.pck.get_data(U_TP_I)
                ret['ip'][i] = self.pck.get_data(U_TP_IP)
                ret['mask'][i] = self.pck.get_data(U_TP_I)
                ret['login'][i] = self.pck.get_data(U_TP_S)
            self.pck.recv(self.sck)
            ret['iptsd_borders_size'] = self.pck.get_data(U_TP_I)
            for i in range(ret['iptsd_borders_size']): 
                self.pck.recv(self.sck)
                ret['tclass_name'][i] = self.pck.get_data(U_TP_S)
                ret['bytes'][i] = self.pck.get_data(U_TP_L)
                ret['cost1'][i] = self.pck.get_data(U_TP_D)
                ret['group_type'][i] = self.pck.get_data(U_TP_I)
            self.pck.recv(self.sck)
            ret['iptsd_prepaid_size'] = self.pck.get_data(U_TP_I)
            for i in range(ret['iptsd_prepaid_size']): 
                self.pck.recv(self.sck)
                ret['tclass_name_p'][i] = self.pck.get_data(U_TP_S)
                ret['prepaid_p'][i] = self.pck.get_data(U_TP_L)
        if ret['service_type']  ==  6:
            ret['tsl_numbers_size'] = self.pck.get_data(U_TP_I)
            for i in range(ret['tsl_numbers_size']): 
                self.pck.recv(self.sck)
                ret['number'][i] = self.pck.get_data(U_TP_S)
                ret['login'][i] = self.pck.get_data(U_TP_S)
                ret['allowed_cid'][i] = self.pck.get_data(U_TP_S)
                ret['item_id'][i] = self.pck.get_data(U_TP_I)
        if ret['service_type']  !=  3:
            if ret['service_type']  !=  6:
                ret['null_param'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_services(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  links_size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    service_id :	(i)  - 
        :(s)    service_type :	(i)  - 
        :(s)    service_name :	(s)  - 
        :(s)    tariff_name :	(s)  - 
        :(s)    discount_period :	(s)  - 
        :(s)    cost :	(d)  - 
        :(s)    discounted_in_curr_period :	(d)  - 
        """
        if not self.urfa_call(-0x4023):
            raise Exception("Fail of urfa_call(-0x4023) [rpcf_user5_get_services]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['links_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['links_size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['service_id'][i] = self.pck.get_data(U_TP_I)
            ret['service_type'][i] = self.pck.get_data(U_TP_I)
            ret['service_name'][i] = self.pck.get_data(U_TP_S)
            ret['tariff_name'][i] = self.pck.get_data(U_TP_S)
            ret['discount_period'][i] = self.pck.get_data(U_TP_S)
            ret['cost'][i] = self.pck.get_data(U_TP_D)
            ret['discounted_in_curr_period'][i] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_services_ex(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  links_size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    service_id :	(i)  - 
        :(s)    service_type :	(i)  - 
        :(s)    service_name :	(s)  - 
        :(s)    tariff_name :	(s)  - 
        :(s)    discount_period_start :	(i)  - 
        :(s)    discount_period_end :	(i)  - 
        :(s)    cost :	(d)  - 
        :(s)    discounted_in_curr_period :	(d)  - 
        """
        if not self.urfa_call(-0x402f):
            raise Exception("Fail of urfa_call(-0x402f) [rpcf_user5_get_services_ex]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['links_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['links_size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['service_id'][i] = self.pck.get_data(U_TP_I)
            ret['service_type'][i] = self.pck.get_data(U_TP_I)
            ret['service_name'][i] = self.pck.get_data(U_TP_S)
            ret['tariff_name'][i] = self.pck.get_data(U_TP_S)
            ret['discount_period_start'][i] = self.pck.get_data(U_TP_I)
            ret['discount_period_end'][i] = self.pck.get_data(U_TP_I)
            ret['cost'][i] = self.pck.get_data(U_TP_D)
            ret['discounted_in_curr_period'][i] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_invoice_data(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  full_name :	(s)  - 
        :(s)  actual_address :	(s)  - 
        :(s)  juridical_address :	(s)  - 
        :(s)  basic_account :	(i)  - 
        :(s)  payment_recv :	(s)  - 
        :(s)  inn :	(s)  - 
        :(s)  bank_account :	(s)  - 
        :(s)  bank_name :	(s)  - 
        :(s)  bank_city :	(s)  - 
        :(s)  bank_bic :	(s)  - 
        :(s)  bank_ks :	(s)  - 
        """
        if not self.urfa_call(-0x4022):
            raise Exception("Fail of urfa_call(-0x4022) [rpcf_user5_get_invoice_data]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['full_name'] = self.pck.get_data(U_TP_S)
        ret['actual_address'] = self.pck.get_data(U_TP_S)
        ret['juridical_address'] = self.pck.get_data(U_TP_S)
        ret['basic_account'] = self.pck.get_data(U_TP_I)
        ret['payment_recv'] = self.pck.get_data(U_TP_S)
        ret['inn'] = self.pck.get_data(U_TP_S)
        ret['bank_account'] = self.pck.get_data(U_TP_S)
        ret['bank_name'] = self.pck.get_data(U_TP_S)
        ret['bank_city'] = self.pck.get_data(U_TP_S)
        ret['bank_bic'] = self.pck.get_data(U_TP_S)
        ret['bank_ks'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_change_password(self, params):
        """ description
        @params: 
        :(s)  old_password :	(s)  - 
        :(s)  new_password :	(s)  - 
        :(s)  new_password_ret :	(s)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(-0x4021):
            raise Exception("Fail of urfa_call(-0x4021) [rpcf_user5_change_password]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['old_password'], U_TP_S)
        self.pck.add_data(params['new_password'], U_TP_S)
        self.pck.add_data(params['new_password_ret'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_service_id_by_name(self, params):
        """ description
        @params: 
        :(s)  name :	(s)  - 
        @returns: 
        :(s)  id :	(i)  - 
        """
        if not self.urfa_call(-0x401e):
            raise Exception("Fail of urfa_call(-0x401e) [rpcf_user5_get_service_id_by_name]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_user_group_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  groups_count :	(i)  - 
        :(s)    id :	(i)  - 
        """
        if not self.urfa_call(-0x401c):
            raise Exception("Fail of urfa_call(-0x401c) [rpcf_user5_get_user_group_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['groups_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['groups_count']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_group_id_by_name(self, params):
        """ description
        @params: 
        :(s)  name :	(s)  - 
        @returns: 
        :(s)  id :	(i)  - 
        """
        if not self.urfa_call(-0x401b):
            raise Exception("Fail of urfa_call(-0x401b) [rpcf_user5_get_group_id_by_name]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_tariff_id_by_name(self, params):
        """ description
        @params: 
        :(s)  name :	(s)  - 
        @returns: 
        :(s)  tid :	(i)  - 
        """
        if not self.urfa_call(-0x401a):
            raise Exception("Fail of urfa_call(-0x401a) [rpcf_user5_get_tariff_id_by_name]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['tid'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_traffic_report_group_by_ip(self, params):
        """ description
        @params: 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i)  - 
        @returns: 
        :(s)  unused :	(i)  - 
        :(s)  unused :	(i)  - 
        :(s)  bytes_in_kbyte :	(d)  - 
        :(s)  ipid_count :	(i)  - 
        :(s)    ipid :	(i)  - 
        :(s)    traffic_report_entry_size :	(i)  - 
        :(s)      tclass :	(i)  - 
        :(s)      tclass_name :	(s)  - 
        :(s)      bytes :	(l)  - 
        """
        if not self.urfa_call(-0x404c):
            raise Exception("Fail of urfa_call(-0x404c) [rpcf_user5_traffic_report_group_by_ip]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['time_start'], U_TP_I)
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['unused'] = self.pck.get_data(U_TP_I)
        ret['unused'][i] = self.pck.get_data(U_TP_I)
        ret['bytes_in_kbyte'][i] = self.pck.get_data(U_TP_D)
        ret['ipid_count'] = self.pck.get_data(U_TP_I)
        for j in range(ret['ipid_count']): 
            self.pck.recv(self.sck)
            ret['ipid'][j] = self.pck.get_data(U_TP_IP)
            ret['traffic_report_entry_size'] = self.pck.get_data(U_TP_I)
            ret['traffic_report_entry_size_array'][j]=ret['traffic_report_entry_size']
            for x in range(ret['traffic_report_entry_size']): 
                self.pck.recv(self.sck)
                if not j in ret['tclass']:ret['tclass'][j] = dict()
                ret['tclass'][j][x] = self.pck.get_data(U_TP_I)
                if not j in ret['tclass_name']:ret['tclass_name'][j] = dict()
                ret['tclass_name'][j][x] = self.pck.get_data(U_TP_S)
                if not j in ret['bytes']:ret['bytes'][j] = dict()
                ret['bytes'][j][x] = self.pck.get_data(U_TP_L)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_dhs_report(self, params):
        """ description
        @params: 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i)  - 
        @returns: 
        :(s)  dhs_log_size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    account_id :	(i)  - 
        :(s)    slink_id :	(i)  - 
        :(s)    recv_date :	(i)  - 
        :(s)    last_update_date :	(i)  - 
        :(s)    framed_ip4 :	(i)  - 
        :(s)    framed_ip6 :	(i)  - 
        :(s)    nas_port :	(i)  - 
        :(s)    acct_session_id :	(s)  - 
        :(s)    nas_port_type :	(i)  - 
        :(s)    uname :	(s)  - 
        :(s)    service_type :	(i)  - 
        :(s)    framed_protocol :	(i)  - 
        :(s)    nas_ip :	(i)  - 
        :(s)    nas_id :	(s)  - 
        :(s)    acct_status_type :	(i)  - 
        :(s)    acct_inp_pack :	(l)  - 
        :(s)    acct_inp_oct :	(l)  - 
        :(s)    acct_out_pack :	(l)  - 
        :(s)    acct_out_oct :	(l)  - 
        :(s)    acct_sess_time :	(l)  - 
        :(s)    dhs_sessions_detail_size :	(i)  - 
        :(s)      trange_id :	(i)  - 
        :(s)      account_id :	(i)  - 
        :(s)      duration :	(l)  - 
        :(s)      base_cost :	(d)  - 
        :(s)      sum_cost :	(d)  - 
        """
        if not self.urfa_call(-0x4017):
            raise Exception("Fail of urfa_call(-0x4017) [rpcf_user5_dhs_report]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['time_start'], U_TP_I)
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['dhs_log_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['dhs_log_size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['account_id'][i] = self.pck.get_data(U_TP_I)
            ret['slink_id'][i] = self.pck.get_data(U_TP_I)
            ret['recv_date'][i] = self.pck.get_data(U_TP_I)
            ret['last_update_date'][i] = self.pck.get_data(U_TP_I)
            ret['framed_ip4'][i] = self.pck.get_data(U_TP_I)
            ret['framed_ip6'][i] = self.pck.get_data(U_TP_I)
            ret['nas_port'][i] = self.pck.get_data(U_TP_I)
            ret['acct_session_id'][i] = self.pck.get_data(U_TP_S)
            ret['nas_port_type'][i] = self.pck.get_data(U_TP_I)
            ret['uname'][i] = self.pck.get_data(U_TP_S)
            ret['service_type'][i] = self.pck.get_data(U_TP_I)
            ret['framed_protocol'][i] = self.pck.get_data(U_TP_I)
            ret['nas_ip'][i] = self.pck.get_data(U_TP_I)
            ret['nas_id'][i] = self.pck.get_data(U_TP_S)
            ret['acct_status_type'][i] = self.pck.get_data(U_TP_I)
            ret['acct_inp_pack'][i] = self.pck.get_data(U_TP_L)
            ret['acct_inp_oct'][i] = self.pck.get_data(U_TP_L)
            ret['acct_out_pack'][i] = self.pck.get_data(U_TP_L)
            ret['acct_out_oct'][i] = self.pck.get_data(U_TP_L)
            ret['acct_sess_time'][i] = self.pck.get_data(U_TP_L)
            ret['dhs_sessions_detail_size'] = self.pck.get_data(U_TP_I)
            ret['dhs_sessions_detail_size_array'][i]=ret['dhs_sessions_detail_size']
            for j in range(ret['dhs_sessions_detail_size']): 
                self.pck.recv(self.sck)
                if not i in ret['trange_id']:ret['trange_id'][i] = dict()
                ret['trange_id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['account_id']:ret['account_id'][i] = dict()
                ret['account_id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['duration']:ret['duration'][i] = dict()
                ret['duration'][i][j] = self.pck.get_data(U_TP_L)
                if not i in ret['base_cost']:ret['base_cost'][i] = dict()
                ret['base_cost'][i][j] = self.pck.get_data(U_TP_D)
                if not i in ret['sum_cost']:ret['sum_cost'][i] = dict()
                ret['sum_cost'][i][j] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_add_message(self, params):
        """ description
        @params: 
        :(s)  subject :	(s)  - 
        :(s)  message :	(s)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(-0x4015):
            raise Exception("Fail of urfa_call(-0x4015) [rpcf_user5_add_message]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['subject'], U_TP_S)
        self.pck.add_data(params['message'], U_TP_S)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_messages_list(self, params):
        """ description
        @params: 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i)  - 
        @returns: 
        :(s)  messages_size :	(i)  - 
        :(s)    send_date :	(i)  - 
        :(s)    recv_date :	(i)  - 
        :(s)    subject :	(s)  - 
        :(s)    message :	(s)  - 
        """
        if not self.urfa_call(-0x4014):
            raise Exception("Fail of urfa_call(-0x4014) [rpcf_user5_messages_list]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['time_start'], U_TP_I)
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['messages_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['messages_size']): 
            self.pck.recv(self.sck)
            ret['send_date'][i] = self.pck.get_data(U_TP_I)
            ret['recv_date'][i] = self.pck.get_data(U_TP_I)
            ret['subject'][i] = self.pck.get_data(U_TP_S)
            ret['message'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_blocks_report(self, params):
        """ description
        @params: 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i)  - 
        @returns: 
        :(s)  blocks_size :	(i)  - 
        :(s)    account_id :	(i)  - 
        :(s)    start_date :	(i)  - 
        :(s)    expire_date :	(i)  - 
        :(s)    what_blocked :	(i)  - 
        :(s)    block_type :	(i)  - 
        :(s)    comment :	(s)  - 
        """
        if not self.urfa_call(-0x4013):
            raise Exception("Fail of urfa_call(-0x4013) [rpcf_user5_blocks_report]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['time_start'], U_TP_I)
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['blocks_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['blocks_size']): 
            self.pck.recv(self.sck)
            ret['account_id'][i] = self.pck.get_data(U_TP_I)
            ret['start_date'][i] = self.pck.get_data(U_TP_I)
            ret['expire_date'][i] = self.pck.get_data(U_TP_I)
            ret['what_blocked'][i] = self.pck.get_data(U_TP_I)
            ret['block_type'][i] = self.pck.get_data(U_TP_I)
            ret['comment'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_payments_report(self, params):
        """ description
        @params: 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i)  - 
        @returns: 
        :(s)  accounts_count :	(i)  - 
        :(s)    atr_size :	(i)  - 
        :(s)      account_id :	(i)  - 
        :(s)      actual_date :	(i)  - 
        :(s)      payment_enter_date :	(i)  - 
        :(s)      payment :	(d)  - 
        :(s)      payment_incurrency :	(d)  - 
        :(s)      currency_id :	(i)  - 
        :(s)      payment_method_id :	(i)  - 
        :(s)      payment_method :	(s)  - 
        :(s)      comment :	(s)  - 
        """
        if not self.urfa_call(-0x4019):
            raise Exception("Fail of urfa_call(-0x4019) [rpcf_user5_payments_report]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['time_start'], U_TP_I)
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['accounts_count'] = self.pck.get_data(U_TP_I)
        for j in range(ret['accounts_count']): 
            self.pck.recv(self.sck)
            ret['atr_size'] = self.pck.get_data(U_TP_I)
            for i in range(ret['atr_size']): 
                self.pck.recv(self.sck)
                if not j in ret['account_id']:ret['account_id'][j] = dict()
                ret['account_id'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['actual_date']:ret['actual_date'][j] = dict()
                ret['actual_date'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['payment_enter_date']:ret['payment_enter_date'][j] = dict()
                ret['payment_enter_date'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['payment']:ret['payment'][j] = dict()
                ret['payment'][j][i] = self.pck.get_data(U_TP_D)
                if not j in ret['payment_incurrency']:ret['payment_incurrency'][j] = dict()
                ret['payment_incurrency'][j][i] = self.pck.get_data(U_TP_D)
                if not j in ret['currency_id']:ret['currency_id'][j] = dict()
                ret['currency_id'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['payment_method_id']:ret['payment_method_id'][j] = dict()
                ret['payment_method_id'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['payment_method']:ret['payment_method'][j] = dict()
                ret['payment_method'][j][i] = self.pck.get_data(U_TP_S)
                if not j in ret['comment']:ret['comment'][j] = dict()
                ret['comment'][j][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_service_report(self, params):
        """ description
        @params: 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i)  - 
        @returns: 
        :(s)  aids_size :	(i)  - 
        :(s)    asr_size :	(i)  - 
        :(s)      account_id :	(i)  - 
        :(s)      discount_date :	(i)  - 
        :(s)      discount :	(d)  - 
        :(s)      discount_with_tax :	(d)  - 
        :(s)      service_name :	(s)  - 
        :(s)      service_type :	(i)  - 
        :(s)      comment :	(s)  - 
        """
        if not self.urfa_call(-0x4011):
            raise Exception("Fail of urfa_call(-0x4011) [rpcf_user5_service_report]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['time_start'], U_TP_I)
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['aids_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['aids_size']): 
            self.pck.recv(self.sck)
            ret['asr_size'] = self.pck.get_data(U_TP_I)
            ret['asr_size_array'][i]=ret['asr_size']
            for j in range(ret['asr_size']): 
                self.pck.recv(self.sck)
                if not i in ret['account_id']:ret['account_id'][i] = dict()
                ret['account_id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['discount_date']:ret['discount_date'][i] = dict()
                ret['discount_date'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['discount']:ret['discount'][i] = dict()
                ret['discount'][i][j] = self.pck.get_data(U_TP_D)
                if not i in ret['discount_with_tax']:ret['discount_with_tax'][i] = dict()
                ret['discount_with_tax'][i][j] = self.pck.get_data(U_TP_D)
                if not i in ret['service_name']:ret['service_name'][i] = dict()
                ret['service_name'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['service_type']:ret['service_type'][i] = dict()
                ret['service_type'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['comment']:ret['comment'][i] = dict()
                ret['comment'][i][j] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_traffic_report_group(self, params):
        """ description
        @params: 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i)  - 
        :(s)  unused :	(i) = _def_  - 
        @returns: 
        :(s)  unused :	(i)  - 
        :(s)  unused :	(i)  - 
        :(s)  bytes_in_kbyte :	(d)  - 
        :(s)  date_count :	(i)  - 
        :(s)    date :	(i)  - 
        :(s)    rows_count :	(i)  - 
        :(s)      tclass :	(i)  - 
        :(s)      class_name :	(s)  - 
        :(s)      bytes :	(l)  - 
        :(s)      base_cost :	(d)  - 
        :(s)      discount :	(d)  - 
        """
        if not self.urfa_call(-0x4010):
            raise Exception("Fail of urfa_call(-0x4010) [rpcf_user5_traffic_report_group]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['time_start'], U_TP_I)
        self.pck.add_data(params['time_end'], U_TP_I)
        if 'unused' not in params: params['unused'] = 2
        self.pck.add_data(params['unused'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['unused'] = self.pck.get_data(U_TP_I)
        ret['unused'][i] = self.pck.get_data(U_TP_I)
        ret['bytes_in_kbyte'][i] = self.pck.get_data(U_TP_D)
        ret['date_count'] = self.pck.get_data(U_TP_I)
        for j in range(ret['date_count']): 
            self.pck.recv(self.sck)
            ret['date'][j] = self.pck.get_data(U_TP_I)
            ret['rows_count'] = self.pck.get_data(U_TP_I)
            ret['rows_count_array'][j]=ret['date_count']
            for x in range(ret['rows_count']): 
                self.pck.recv(self.sck)
                if not j in ret['tclass']:ret['tclass'][j] = dict()
                ret['tclass'][j][x] = self.pck.get_data(U_TP_I)
                if not j in ret['class_name']:ret['class_name'][j] = dict()
                ret['class_name'][j][x] = self.pck.get_data(U_TP_S)
                if not j in ret['bytes']:ret['bytes'][j] = dict()
                ret['bytes'][j][x] = self.pck.get_data(U_TP_L)
                if not j in ret['base_cost']:ret['base_cost'][j] = dict()
                ret['base_cost'][j][x] = self.pck.get_data(U_TP_D)
                if not j in ret['discount']:ret['discount'][j] = dict()
                ret['discount'][j][x] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_traffic_report(self, params):
        """ description
        @params: 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i) = _def_  - 
        @returns: 
        :(s)  unused :	(i)  - 
        :(s)  bytes_in_kbyte :	(d)  - 
        :(s)  rows_count :	(i)  - 
        :(s)    tclass :	(i)  - 
        :(s)    tclass_name :	(s)  - 
        :(s)    bytes :	(l)  - 
        :(s)    base_cost :	(d)  - 
        :(s)    discount :	(d)  - 
        :(s)    discount_with_tax :	(d)  - 
        """
        if not self.urfa_call(-0x4009):
            raise Exception("Fail of urfa_call(-0x4009) [rpcf_user5_traffic_report]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['time_start'], U_TP_I)
        if 'time_end' not in params: params['time_end'] = now()
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['unused'] = self.pck.get_data(U_TP_I)
        ret['bytes_in_kbyte'] = self.pck.get_data(U_TP_D)
        ret['rows_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['rows_count']): 
            self.pck.recv(self.sck)
            ret['tclass'][i] = self.pck.get_data(U_TP_I)
            ret['tclass_name'][i] = self.pck.get_data(U_TP_S)
            ret['bytes'][i] = self.pck.get_data(U_TP_L)
            ret['base_cost'][i] = self.pck.get_data(U_TP_D)
            ret['discount'][i] = self.pck.get_data(U_TP_D)
            ret['discount_with_tax'][i] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_change_int_status(self, params):
        """ description
        @params: 
        :(s)  deprecated :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(-0x4007):
            raise Exception("Fail of urfa_call(-0x4007) [rpcf_user5_change_int_status]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['deprecated'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_user_info(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  user_id :	(i)  - 
        :(s)  login :	(s)  - 
        :(s)  basic_account :	(i)  - 
        :(s)  balance :	(d)  - 
        :(s)  credit :	(d)  - 
        :(s)  is_blocked :	(i)  - 
        :(s)  create_date :	(i)  - 
        :(s)  last_change_date :	(i)  - 
        :(s)  who_create :	(i)  - 
        :(s)  who_change :	(i)  - 
        :(s)  is_juridical :	(i)  - 
        :(s)  full_name :	(s)  - 
        :(s)  juridical_address :	(s)  - 
        :(s)  actual_address :	(s)  - 
        :(s)  work_telephone :	(s)  - 
        :(s)  home_telephone :	(s)  - 
        :(s)  mobile_telephone :	(s)  - 
        :(s)  web_page :	(s)  - 
        :(s)  icq_number :	(s)  - 
        :(s)  tax_number :	(s)  - 
        :(s)  kpp_number :	(s)  - 
        :(s)  bank_id :	(i)  - 
        :(s)  bank_account :	(s)  - 
        :(s)  int_status :	(i)  - 
        :(s)  vat_rate :	(d)  - 
        :(s)  passport :	(s)  - 
        :(s)  locked_in_funds :	(d)  - 
        :(s)  email :	(s)  - 
        """
        if not self.urfa_call(-0x4052):
            raise Exception("Fail of urfa_call(-0x4052) [rpcf_user5_get_user_info]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['user_id'] = self.pck.get_data(U_TP_I)
        ret['login'] = self.pck.get_data(U_TP_S)
        ret['basic_account'] = self.pck.get_data(U_TP_I)
        ret['balance'] = self.pck.get_data(U_TP_D)
        ret['credit'] = self.pck.get_data(U_TP_D)
        ret['is_blocked'] = self.pck.get_data(U_TP_I)
        ret['create_date'] = self.pck.get_data(U_TP_I)
        ret['last_change_date'] = self.pck.get_data(U_TP_I)
        ret['who_create'] = self.pck.get_data(U_TP_I)
        ret['who_change'] = self.pck.get_data(U_TP_I)
        ret['is_juridical'] = self.pck.get_data(U_TP_I)
        ret['full_name'] = self.pck.get_data(U_TP_S)
        ret['juridical_address'] = self.pck.get_data(U_TP_S)
        ret['actual_address'] = self.pck.get_data(U_TP_S)
        ret['work_telephone'] = self.pck.get_data(U_TP_S)
        ret['home_telephone'] = self.pck.get_data(U_TP_S)
        ret['mobile_telephone'] = self.pck.get_data(U_TP_S)
        ret['web_page'] = self.pck.get_data(U_TP_S)
        ret['icq_number'] = self.pck.get_data(U_TP_S)
        ret['tax_number'] = self.pck.get_data(U_TP_S)
        ret['kpp_number'] = self.pck.get_data(U_TP_S)
        ret['bank_id'] = self.pck.get_data(U_TP_I)
        ret['bank_account'] = self.pck.get_data(U_TP_S)
        ret['int_status'] = self.pck.get_data(U_TP_I)
        ret['vat_rate'] = self.pck.get_data(U_TP_D)
        ret['passport'] = self.pck.get_data(U_TP_S)
        ret['locked_in_funds'] = self.pck.get_data(U_TP_D)
        ret['email'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_remaining_seconds(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        @returns: 
        :(s)  remaining_seconds :	(i)  - 
        :(s)  downloaded_seconds :	(i)  - 
        """
        if not self.urfa_call(-0x2027):
            raise Exception("Fail of urfa_call(-0x2027) [rpcf_user5_get_remaining_seconds]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['remaining_seconds'] = self.pck.get_data(U_TP_I)
        ret['downloaded_seconds'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_remaining_traffic(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        @returns: 
        :(s)  traffic_remaining_mb :	(d)  - 
        :(s)  traffic_downloaded_mb :	(d)  - 
        """
        if not self.urfa_call(-0x2026):
            raise Exception("Fail of urfa_call(-0x2026) [rpcf_user5_get_remaining_traffic]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['traffic_remaining_mb'] = self.pck.get_data(U_TP_D)
        ret['traffic_downloaded_mb'] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_core_version_user(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  version :	(s)  - 
        """
        if not self.urfa_call(-0x0045):
            raise Exception("Fail of urfa_call(-0x0045) [rpcf_core_version_user]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['version'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_fwrules_list_new(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  rules_count :	(i)  - 
        :(s)    rule_id :	(i)  - 
        :(s)    flags :	(i)  - 
        :(s)    events :	(l)  - 
        :(s)    router_id :	(i)  - 
        :(s)    tariff_id :	(i)  - 
        :(s)    group_id :	(i)  - 
        :(s)    user_id :	(i)  - 
        :(s)    rule :	(s)  - 
        :(s)    comment :	(s)  - 
        """
        if not self.urfa_call(0x5020):
            raise Exception("Fail of urfa_call(0x5020) [rpcf_get_fwrules_list_new]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['rules_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['rules_count']): 
            self.pck.recv(self.sck)
            ret['rule_id'][i] = self.pck.get_data(U_TP_I)
            ret['flags'][i] = self.pck.get_data(U_TP_I)
            ret['events'][i] = self.pck.get_data(U_TP_L)
            ret['router_id'][i] = self.pck.get_data(U_TP_I)
            ret['tariff_id'][i] = self.pck.get_data(U_TP_I)
            ret['group_id'][i] = self.pck.get_data(U_TP_I)
            ret['user_id'][i] = self.pck.get_data(U_TP_I)
            ret['rule'][i] = self.pck.get_data(U_TP_S)
            ret['comment'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_fwrule_new(self, params):
        """ description
        @params: 
        :(s)  flags :	(i)  - 
        :(s)  events :	(l)  - 
        :(s)  router_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  group_id :	(i)  - 
        :(s)  user_id :	(i)  - 
        :(s)  rule :	(s)  - 
        :(s)  comment :	(s)  - 
        @returns: 
        :(s)  rule_id :	(i)  - 
        """
        if not self.urfa_call(0x5021):
            raise Exception("Fail of urfa_call(0x5021) [rpcf_add_fwrule_new]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['flags'], U_TP_I)
        self.pck.add_data(params['events'], U_TP_L)
        self.pck.add_data(params['router_id'], U_TP_I)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.add_data(params['group_id'], U_TP_I)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['rule'], U_TP_S)
        self.pck.add_data(params['comment'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['rule_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_fwrule_new(self, params):
        """ description
        @params: 
        :(s)  rule_id :	(i)  - 
        :(s)  flags :	(i)  - 
        :(s)  events :	(l)  - 
        :(s)  router_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  group_id :	(i)  - 
        :(s)  user_id :	(i)  - 
        :(s)  rule :	(s)  - 
        :(s)  comment :	(s)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x5022):
            raise Exception("Fail of urfa_call(0x5022) [rpcf_edit_fwrule_new]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['rule_id'], U_TP_I)
        self.pck.add_data(params['flags'], U_TP_I)
        self.pck.add_data(params['events'], U_TP_L)
        self.pck.add_data(params['router_id'], U_TP_I)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.add_data(params['group_id'], U_TP_I)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['rule'], U_TP_S)
        self.pck.add_data(params['comment'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_del_fwrule_new(self, params):
        """ description
        @params: 
        :(s)  rule_id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x5023):
            raise Exception("Fail of urfa_call(0x5023) [rpcf_del_fwrule_new]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['rule_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_ic_get_settings(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  send_users :	(i)  - 
        :(s)  send_inv :	(i)  - 
        :(s)  send_payments :	(i)  - 
        :(s)  recv_payments :	(i)  - 
        :(s)  sync_card :	(i)  - 
        :(s)  sync_empty_name :	(i)  - 
        :(s)  sync_empty_inn :	(i)  - 
        :(s)  sync_empty_kpp :	(i)  - 
        :(s)  sync_users_since :	(i)  - 
        :(s)  sync_users_till :	(i)  - 
        :(s)  sync_inv_since :	(i)  - 
        :(s)  sync_inv_till :	(i)  - 
        :(s)  sync_payments_since :	(i)  - 
        :(s)  sync_payments_till :	(i)  - 
        """
        if not self.urfa_call(0x14001):
            raise Exception("Fail of urfa_call(0x14001) [rpcf_ic_get_settings]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['send_users'] = self.pck.get_data(U_TP_I)
        ret['send_inv'] = self.pck.get_data(U_TP_I)
        ret['send_payments'] = self.pck.get_data(U_TP_I)
        ret['recv_payments'] = self.pck.get_data(U_TP_I)
        ret['sync_card'] = self.pck.get_data(U_TP_I)
        ret['sync_empty_name'] = self.pck.get_data(U_TP_I)
        ret['sync_empty_inn'] = self.pck.get_data(U_TP_I)
        ret['sync_empty_kpp'] = self.pck.get_data(U_TP_I)
        ret['sync_users_since'] = self.pck.get_data(U_TP_I)
        ret['sync_users_till'] = self.pck.get_data(U_TP_I)
        ret['sync_inv_since'] = self.pck.get_data(U_TP_I)
        ret['sync_inv_till'] = self.pck.get_data(U_TP_I)
        ret['sync_payments_since'] = self.pck.get_data(U_TP_I)
        ret['sync_payments_till'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_ic_save_settings(self, params):
        """ description
        @params: 
        :(s)  send_users :	(i)  - 
        :(s)  send_inv :	(i)  - 
        :(s)  send_payments :	(i)  - 
        :(s)  recv_payments :	(i)  - 
        :(s)  sync_card :	(i)  - 
        :(s)  sync_empty_name :	(i)  - 
        :(s)  sync_empty_inn :	(i)  - 
        :(s)  sync_empty_kpp :	(i)  - 
        :(s)  sync_users_since :	(i)  - 
        :(s)  sync_users_till :	(i)  - 
        :(s)  sync_inv_since :	(i)  - 
        :(s)  sync_inv_till :	(i)  - 
        :(s)  sync_payments_since :	(i)  - 
        :(s)  sync_payments_till :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x14002):
            raise Exception("Fail of urfa_call(0x14002) [rpcf_ic_save_settings]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['send_users'], U_TP_I)
        self.pck.add_data(params['send_inv'], U_TP_I)
        self.pck.add_data(params['send_payments'], U_TP_I)
        self.pck.add_data(params['recv_payments'], U_TP_I)
        self.pck.add_data(params['sync_card'], U_TP_I)
        self.pck.add_data(params['sync_empty_name'], U_TP_I)
        self.pck.add_data(params['sync_empty_inn'], U_TP_I)
        self.pck.add_data(params['sync_empty_kpp'], U_TP_I)
        self.pck.add_data(params['sync_users_since'], U_TP_I)
        self.pck.add_data(params['sync_users_till'], U_TP_I)
        self.pck.add_data(params['sync_inv_since'], U_TP_I)
        self.pck.add_data(params['sync_inv_till'], U_TP_I)
        self.pck.add_data(params['sync_payments_since'], U_TP_I)
        self.pck.add_data(params['sync_payments_till'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_ic_invoices_list(self, params):
        """ description
        @params: 
        :(s)  start_date :	(i)  - 
        :(s)  end_date :	(i)  - 
        @returns: 
        :(s)  count :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    login :	(s)  - 
        :(s)    fullname :	(s)  - 
        :(s)    invoice_date :	(i)  - 
        :(s)    sum :	(d)  - 
        :(s)    ic_status :	(i)  - 
        :(s)    last_sync_date :	(i)  - 
        :(s)    ic_id :	(s)  - 
        """
        if not self.urfa_call(0x14004):
            raise Exception("Fail of urfa_call(0x14004) [rpcf_ic_invoices_list]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['start_date'], U_TP_I)
        self.pck.add_data(params['end_date'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['count']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['login'][i] = self.pck.get_data(U_TP_S)
            ret['fullname'][i] = self.pck.get_data(U_TP_S)
            ret['invoice_date'][i] = self.pck.get_data(U_TP_I)
            ret['sum'][i] = self.pck.get_data(U_TP_D)
            ret['ic_status'][i] = self.pck.get_data(U_TP_I)
            ret['last_sync_date'][i] = self.pck.get_data(U_TP_I)
            ret['ic_id'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_ic_payments_list(self, params):
        """ description
        @params: 
        :(s)  start_date :	(i)  - 
        :(s)  end_date :	(i)  - 
        @returns: 
        :(s)  count :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    login :	(s)  - 
        :(s)    fullname :	(s)  - 
        :(s)    actual_date :	(i)  - 
        :(s)    account_id :	(i)  - 
        :(s)    sum :	(d)  - 
        :(s)    currency_id :	(i)  - 
        :(s)    ic_status :	(i)  - 
        :(s)    last_sync_date :	(i)  - 
        :(s)    ic_id :	(s)  - 
        """
        if not self.urfa_call(0x14005):
            raise Exception("Fail of urfa_call(0x14005) [rpcf_ic_payments_list]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['start_date'], U_TP_I)
        self.pck.add_data(params['end_date'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['count']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['login'][i] = self.pck.get_data(U_TP_S)
            ret['fullname'][i] = self.pck.get_data(U_TP_S)
            ret['actual_date'][i] = self.pck.get_data(U_TP_I)
            ret['account_id'][i] = self.pck.get_data(U_TP_I)
            ret['sum'][i] = self.pck.get_data(U_TP_D)
            ret['currency_id'][i] = self.pck.get_data(U_TP_I)
            ret['ic_status'][i] = self.pck.get_data(U_TP_I)
            ret['last_sync_date'][i] = self.pck.get_data(U_TP_I)
            ret['ic_id'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_license_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  lic_count :	(i)  - 
        :(s)    license_id :	(i)  - 
        :(s)    license_since :	(i)  - 
        :(s)    license_till :	(i)  - 
        :(s)    features_count :	(i)  - 
        :(s)      feature_id :	(i)  - 
        :(s)      feature_value :	(s)  - 
        """
        if not self.urfa_call(0x2122):
            raise Exception("Fail of urfa_call(0x2122) [rpcf_get_license_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['lic_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['lic_count']): 
            self.pck.recv(self.sck)
            ret['license_id'][i] = self.pck.get_data(U_TP_I)
            ret['license_since'][i] = self.pck.get_data(U_TP_I)
            ret['license_till'][i] = self.pck.get_data(U_TP_I)
            ret['features_count'] = self.pck.get_data(U_TP_I)
            for j in range(ret['features_count']): 
                self.pck.recv(self.sck)
                if not i in ret['feature_id']:ret['feature_id'][i] = dict()
                ret['feature_id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['feature_value']:ret['feature_value'][i] = dict()
                ret['feature_value'][i][j] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_session_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  count :	(i)  - 
        :(s)    sid :	(i)  - 
        :(s)    type :	(i)  - 
        :(s)    staff_id :	(i)  - 
        :(s)    host :	(s)  - 
        :(s)    port :	(i)  - 
        """
        if not self.urfa_call(0x2123):
            raise Exception("Fail of urfa_call(0x2123) [rpcf_get_session_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['count']): 
            self.pck.recv(self.sck)
            ret['sid'][i] = self.pck.get_data(U_TP_I)
            ret['type'][i] = self.pck.get_data(U_TP_I)
            ret['staff_id'][i] = self.pck.get_data(U_TP_I)
            ret['host'][i] = self.pck.get_data(U_TP_S)
            ret['port'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_change_own_password(self, params):
        """ description
        @params: 
        :(s)  old_pass :	(s)  - 
        :(s)  new_pass :	(s)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x2124):
            raise Exception("Fail of urfa_call(0x2124) [rpcf_change_own_password]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['old_pass'], U_TP_S)
        self.pck.add_data(params['new_pass'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_user_new(self, params):
        """ description
        @params: 
        :(s)  login :	(s)  - 
        :(s)  password :	(s)  - 
        :(s)  full_name :	(s)  - 
        :(s)  is_juridical :	(i) = _def_  - 
        :(s)  jur_address :	(s)  - 
        :(s)  act_address :	(s)  - 
        :(s)  flat_number :	(s)  - 
        :(s)  entrance :	(s)  - 
        :(s)  floor :	(s)  - 
        :(s)  district :	(s)  - 
        :(s)  building :	(s)  - 
        :(s)  passport :	(s)  - 
        :(s)  house_id :	(i) = _def_  - 
        :(s)  work_tel :	(s)  - 
        :(s)  home_tel :	(s)  - 
        :(s)  mob_tel :	(s)  - 
        :(s)  web_page :	(s)  - 
        :(s)  icq_number :	(s)  - 
        :(s)  tax_number :	(s)  - 
        :(s)  kpp_number :	(s)  - 
        :(s)  email :	(s)  - 
        :(s)  bank_id :	(i) = _def_  - 
        :(s)  bank_account :	(s)  - 
        :(s)  comments :	(s)  - 
        :(s)  personal_manager :	(s)  - 
        :(s)  connect_date :	(i) = _def_  - 
        :(s)  is_send_invoice :	(i) = _def_  - 
        :(s)  advance_payment :	(i) = _def_  - 
        :(s)  switch_id :	(i) = _def_  - 
        :(s)  port_number :	(i) = _def_  - 
        :(s)  binded_currency_id :	(i) = _def_  - 
        :(s)  parameters_count :	(i) = _def_  - 
        :(s)    parameter_id :	(i)  - 
        :(s)    parameter_value :	(s)  - 
        :(s)  groups_count :	(i) = _def_  - 
        :(s)    groups :	(i)  - 
        :(s)  is_blocked :	(i) = _def_  - 
        :(s)  balance :	(d) = _def_  - 
        :(s)  credit :	(d) = _def_  - 
        :(s)  vat_rate :	(d) = _def_  - 
        :(s)  sale_tax_rate :	(d) = _def_  - 
        :(s)  int_status :	(i) = _def_  - 
        @returns: 
        :(s)  user_id :	(i)  - 
        :(s)    error_code :	(i)  - 
        :(s)    error_description :	(s)  - 
        :(s)    basic_account :	(i)  - 
        """
        if not self.urfa_call(0x2125):
            raise Exception("Fail of urfa_call(0x2125) [rpcf_add_user_new]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['login'], U_TP_S)
        self.pck.add_data(params['password'], U_TP_S)
        self.pck.add_data(params['full_name'], U_TP_S)
        if 'is_juridical' not in params: params['is_juridical'] = 0
        self.pck.add_data(params['is_juridical'], U_TP_I)
        self.pck.add_data(params['jur_address'], U_TP_S)
        self.pck.add_data(params['act_address'], U_TP_S)
        self.pck.add_data(params['flat_number'], U_TP_S)
        self.pck.add_data(params['entrance'], U_TP_S)
        self.pck.add_data(params['floor'], U_TP_S)
        self.pck.add_data(params['district'], U_TP_S)
        self.pck.add_data(params['building'], U_TP_S)
        self.pck.add_data(params['passport'], U_TP_S)
        if 'house_id' not in params: params['house_id'] = 0
        self.pck.add_data(params['house_id'], U_TP_I)
        self.pck.add_data(params['work_tel'], U_TP_S)
        self.pck.add_data(params['home_tel'], U_TP_S)
        self.pck.add_data(params['mob_tel'], U_TP_S)
        self.pck.add_data(params['web_page'], U_TP_S)
        self.pck.add_data(params['icq_number'], U_TP_S)
        self.pck.add_data(params['tax_number'], U_TP_S)
        self.pck.add_data(params['kpp_number'], U_TP_S)
        self.pck.add_data(params['email'], U_TP_S)
        if 'bank_id' not in params: params['bank_id'] = 0
        self.pck.add_data(params['bank_id'], U_TP_I)
        self.pck.add_data(params['bank_account'], U_TP_S)
        self.pck.add_data(params['comments'], U_TP_S)
        self.pck.add_data(params['personal_manager'], U_TP_S)
        if 'connect_date' not in params: params['connect_date'] = 0
        self.pck.add_data(params['connect_date'], U_TP_I)
        if 'is_send_invoice' not in params: params['is_send_invoice'] = 0
        self.pck.add_data(params['is_send_invoice'], U_TP_I)
        if 'advance_payment' not in params: params['advance_payment'] = 0
        self.pck.add_data(params['advance_payment'], U_TP_I)
        if 'switch_id' not in params: params['switch_id'] = 0
        self.pck.add_data(params['switch_id'], U_TP_I)
        if 'port_number' not in params: params['port_number'] = 0
        self.pck.add_data(params['port_number'], U_TP_I)
        if 'binded_currency_id' not in params: params['binded_currency_id'] = 810
        self.pck.add_data(params['binded_currency_id'], U_TP_I)
        if 'parameters_count' not in params: params['parameters_count'] = len(params['parameter_value'])
        self.pck.add_data(params['parameters_count'], U_TP_I)
        for i in range(len(params['parameter_value'])):
            self.pck.add_data(params['parameter_id'][i], U_TP_I)
            self.pck.add_data(params['parameter_value'][i], U_TP_S)
        if 'groups_count' not in params: params['groups_count'] = len(params['groups'])
        self.pck.add_data(params['groups_count'], U_TP_I)
        for i in range(len(params['groups'])):
            self.pck.add_data(params['groups'][i], U_TP_I)
        if 'is_blocked' not in params: params['is_blocked'] = 0
        self.pck.add_data(params['is_blocked'], U_TP_I)
        if 'balance' not in params: params['balance'] = 0.0
        self.pck.add_data(params['balance'], U_TP_D)
        if 'credit' not in params: params['credit'] = 0.0
        self.pck.add_data(params['credit'], U_TP_D)
        if 'vat_rate' not in params: params['vat_rate'] = 0.0
        self.pck.add_data(params['vat_rate'], U_TP_D)
        if 'sale_tax_rate' not in params: params['sale_tax_rate'] = 0.0
        self.pck.add_data(params['sale_tax_rate'], U_TP_D)
        if 'int_status' not in params: params['int_status'] = 1
        self.pck.add_data(params['int_status'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['user_id'] = self.pck.get_data(U_TP_I)
        if ret['user_id']  ==  0:
            ret['error_code'] = self.pck.get_data(U_TP_I)
            ret['error_description'] = self.pck.get_data(U_TP_S)
        if ret['user_id']  !=  0:
            ret['basic_account'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_user_new(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  login :	(s)  - 
        :(s)  password :	(s)  - 
        :(s)  full_name :	(s)  - 
        :(s)  is_juridical :	(i) = _def_  - 
        :(s)  jur_address :	(s)  - 
        :(s)  act_address :	(s)  - 
        :(s)  flat_number :	(s)  - 
        :(s)  entrance :	(s)  - 
        :(s)  floor :	(s)  - 
        :(s)  district :	(s)  - 
        :(s)  building :	(s)  - 
        :(s)  passport :	(s)  - 
        :(s)  house_id :	(i) = _def_  - 
        :(s)  work_tel :	(s)  - 
        :(s)  home_tel :	(s)  - 
        :(s)  mob_tel :	(s)  - 
        :(s)  web_page :	(s)  - 
        :(s)  icq_number :	(s)  - 
        :(s)  tax_number :	(s)  - 
        :(s)  kpp_number :	(s)  - 
        :(s)  email :	(s)  - 
        :(s)  bank_id :	(i) = _def_  - 
        :(s)  bank_account :	(s)  - 
        :(s)  comments :	(s)  - 
        :(s)  personal_manager :	(s)  - 
        :(s)  connect_date :	(i) = _def_  - 
        :(s)  is_send_invoice :	(i) = _def_  - 
        :(s)  advance_payment :	(i) = _def_  - 
        :(s)  switch_id :	(i) = _def_  - 
        :(s)  port_number :	(i) = _def_  - 
        :(s)  binded_currency_id :	(i) = _def_  - 
        :(s)  parameters_count :	(i) = _def_  - 
        :(s)    parameter_id :	(i)  - 
        :(s)    parameter_value :	(s)  - 
        @returns: 
        :(s)  user_id :	(i)  - 
        :(s)    error_code :	(i)  - 
        :(s)    error_description :	(s)  - 
        """
        if not self.urfa_call(0x2126):
            raise Exception("Fail of urfa_call(0x2126) [rpcf_edit_user_new]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['login'], U_TP_S)
        self.pck.add_data(params['password'], U_TP_S)
        self.pck.add_data(params['full_name'], U_TP_S)
        if 'is_juridical' not in params: params['is_juridical'] = 0
        self.pck.add_data(params['is_juridical'], U_TP_I)
        self.pck.add_data(params['jur_address'], U_TP_S)
        self.pck.add_data(params['act_address'], U_TP_S)
        self.pck.add_data(params['flat_number'], U_TP_S)
        self.pck.add_data(params['entrance'], U_TP_S)
        self.pck.add_data(params['floor'], U_TP_S)
        self.pck.add_data(params['district'], U_TP_S)
        self.pck.add_data(params['building'], U_TP_S)
        self.pck.add_data(params['passport'], U_TP_S)
        if 'house_id' not in params: params['house_id'] = 0
        self.pck.add_data(params['house_id'], U_TP_I)
        self.pck.add_data(params['work_tel'], U_TP_S)
        self.pck.add_data(params['home_tel'], U_TP_S)
        self.pck.add_data(params['mob_tel'], U_TP_S)
        self.pck.add_data(params['web_page'], U_TP_S)
        self.pck.add_data(params['icq_number'], U_TP_S)
        self.pck.add_data(params['tax_number'], U_TP_S)
        self.pck.add_data(params['kpp_number'], U_TP_S)
        self.pck.add_data(params['email'], U_TP_S)
        if 'bank_id' not in params: params['bank_id'] = 0
        self.pck.add_data(params['bank_id'], U_TP_I)
        self.pck.add_data(params['bank_account'], U_TP_S)
        self.pck.add_data(params['comments'], U_TP_S)
        self.pck.add_data(params['personal_manager'], U_TP_S)
        if 'connect_date' not in params: params['connect_date'] = 0
        self.pck.add_data(params['connect_date'], U_TP_I)
        if 'is_send_invoice' not in params: params['is_send_invoice'] = 0
        self.pck.add_data(params['is_send_invoice'], U_TP_I)
        if 'advance_payment' not in params: params['advance_payment'] = 0
        self.pck.add_data(params['advance_payment'], U_TP_I)
        if 'switch_id' not in params: params['switch_id'] = 0
        self.pck.add_data(params['switch_id'], U_TP_I)
        if 'port_number' not in params: params['port_number'] = 0
        self.pck.add_data(params['port_number'], U_TP_I)
        if 'binded_currency_id' not in params: params['binded_currency_id'] = 810
        self.pck.add_data(params['binded_currency_id'], U_TP_I)
        if 'parameters_count' not in params: params['parameters_count'] = len(params['parameter_value'])
        self.pck.add_data(params['parameters_count'], U_TP_I)
        for i in range(len(params['parameter_value'])):
            self.pck.add_data(params['parameter_id'][i], U_TP_I)
            self.pck.add_data(params['parameter_value'][i], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['user_id'] = self.pck.get_data(U_TP_I)
        if params['user_id']  ==  0:
            ret['error_code'] = self.pck.get_data(U_TP_I)
            ret['error_description'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_tray_settings(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  count :	(i)  - 
        :(s)    attribute :	(s)  - 
        :(s)    value :	(s)  - 
        """
        if not self.urfa_call(0x212a):
            raise Exception("Fail of urfa_call(0x212a) [rpcf_get_tray_settings]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['count']): 
            self.pck.recv(self.sck)
            ret['attribute'][i] = self.pck.get_data(U_TP_S)
            ret['value'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_save_tray_settings(self, params):
        """ description
        @params: 
        :(s)  count :	(i)  - 
        :(s)    attribute :	(s)  - 
        :(s)    value :	(s)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x212b):
            raise Exception("Fail of urfa_call(0x212b) [rpcf_save_tray_settings]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['count'], U_TP_I)
        for i in range(params['count']):
            self.pck.add_data(params['attribute'][i], U_TP_S)
            self.pck.add_data(params['value'][i], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_cashier_settings(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  count :	(i)  - 
        :(s)    attribute :	(s)  - 
        :(s)    value :	(s)  - 
        """
        if not self.urfa_call(0x212c):
            raise Exception("Fail of urfa_call(0x212c) [rpcf_get_cashier_settings]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['count']): 
            self.pck.recv(self.sck)
            ret['attribute'][i] = self.pck.get_data(U_TP_S)
            ret['value'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_save_cashier_settings(self, params):
        """ description
        @params: 
        :(s)  count :	(i)  - 
        :(s)    attribute :	(s)  - 
        :(s)    value :	(s)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x212d):
            raise Exception("Fail of urfa_call(0x212d) [rpcf_save_cashier_settings]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['count'], U_TP_I)
        for i in range(params['count']):
            self.pck.add_data(params['attribute'][i], U_TP_S)
            self.pck.add_data(params['value'][i], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_tray_settings(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  count :	(i)  - 
        :(s)    attribute :	(s)  - 
        :(s)    value :	(s)  - 
        """
        if not self.urfa_call(-0x403a):
            raise Exception("Fail of urfa_call(-0x403a) [rpcf_user5_get_tray_settings]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['count']): 
            self.pck.recv(self.sck)
            ret['attribute'][i] = self.pck.get_data(U_TP_S)
            ret['value'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_dealer(self, params):
        """ description
        @params: 
        :(s)  login :	(s)  - 
        :(s)  password :	(s)  - 
        :(s)  ip4_address :	(i) = _def_  - 
        :(s)  mask4 :	(i) = _def_  - 
        :(s)  ip6_address :	(i) = _def_  - 
        :(s)  mask6 :	(i) = _def_  - 
        :(s)  full_name :	(s)  - 
        :(s)  act_address :	(s)  - 
        :(s)  passport :	(s)  - 
        :(s)  work_tel :	(s)  - 
        :(s)  home_tel :	(s)  - 
        :(s)  mob_tel :	(s)  - 
        :(s)  web_page :	(s)  - 
        :(s)  icq_number :	(s)  - 
        :(s)  email :	(s)  - 
        :(s)  comments :	(s)  - 
        :(s)  groups_count :	(i) = _def_  - 
        :(s)    group_id :	(i)  - 
        @returns: 
        :(s)  dealer_id :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        """
        if not self.urfa_call(0x13001):
            raise Exception("Fail of urfa_call(0x13001) [rpcf_add_dealer]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['login'], U_TP_S)
        self.pck.add_data(params['password'], U_TP_S)
        if 'ip4_address' not in params: params['ip4_address'] = '0.0.0.0'
        self.pck.add_data(params['ip4_address'], U_TP_IP)
        if 'mask4' not in params: params['mask4'] = 32
        self.pck.add_data(params['mask4'], U_TP_I)
        if 'ip6_address' not in params: params['ip6_address'] = '::0'
        self.pck.add_data(params['ip6_address'], U_TP_IP)
        if 'mask6' not in params: params['mask6'] = 128
        self.pck.add_data(params['mask6'], U_TP_I)
        self.pck.add_data(params['full_name'], U_TP_S)
        self.pck.add_data(params['act_address'], U_TP_S)
        self.pck.add_data(params['passport'], U_TP_S)
        self.pck.add_data(params['work_tel'], U_TP_S)
        self.pck.add_data(params['home_tel'], U_TP_S)
        self.pck.add_data(params['mob_tel'], U_TP_S)
        self.pck.add_data(params['web_page'], U_TP_S)
        self.pck.add_data(params['icq_number'], U_TP_S)
        self.pck.add_data(params['email'], U_TP_S)
        self.pck.add_data(params['comments'], U_TP_S)
        if 'groups_count' not in params: params['groups_count'] = len(params['group_id'])
        self.pck.add_data(params['groups_count'], U_TP_I)
        for i in range(len(params['group_id'])):
            self.pck.add_data(params['group_id'][i], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['dealer_id'] = self.pck.get_data(U_TP_I)
        if ret['dealer_id']  ==  0:
            ret['error'] = dict({10:"error adding dealer. look debug.log for details"})
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_dealer(self, params):
        """ description
        @params: 
        :(s)  dealer_id :	(i)  - 
        :(s)  login :	(s)  - 
        :(s)  password :	(s)  - 
        :(s)  ip4_address :	(i) = _def_  - 
        :(s)  mask4 :	(i) = _def_  - 
        :(s)  ip6_address :	(i) = _def_  - 
        :(s)  mask6 :	(i) = _def_  - 
        :(s)  full_name :	(s)  - 
        :(s)  act_address :	(s)  - 
        :(s)  passport :	(s)  - 
        :(s)  work_tel :	(s)  - 
        :(s)  home_tel :	(s)  - 
        :(s)  mob_tel :	(s)  - 
        :(s)  web_page :	(s)  - 
        :(s)  icq_number :	(s)  - 
        :(s)  email :	(s)  - 
        :(s)  comments :	(s)  - 
        :(s)  groups_count :	(i) = _def_  - 
        :(s)    group_id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        """
        if not self.urfa_call(0x13002):
            raise Exception("Fail of urfa_call(0x13002) [rpcf_edit_dealer]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['dealer_id'], U_TP_I)
        self.pck.add_data(params['login'], U_TP_S)
        self.pck.add_data(params['password'], U_TP_S)
        if 'ip4_address' not in params: params['ip4_address'] = '0.0.0.0'
        self.pck.add_data(params['ip4_address'], U_TP_IP)
        if 'mask4' not in params: params['mask4'] = 32
        self.pck.add_data(params['mask4'], U_TP_I)
        if 'ip6_address' not in params: params['ip6_address'] = '::0'
        self.pck.add_data(params['ip6_address'], U_TP_IP)
        if 'mask6' not in params: params['mask6'] = 128
        self.pck.add_data(params['mask6'], U_TP_I)
        self.pck.add_data(params['full_name'], U_TP_S)
        self.pck.add_data(params['act_address'], U_TP_S)
        self.pck.add_data(params['passport'], U_TP_S)
        self.pck.add_data(params['work_tel'], U_TP_S)
        self.pck.add_data(params['home_tel'], U_TP_S)
        self.pck.add_data(params['mob_tel'], U_TP_S)
        self.pck.add_data(params['web_page'], U_TP_S)
        self.pck.add_data(params['icq_number'], U_TP_S)
        self.pck.add_data(params['email'], U_TP_S)
        self.pck.add_data(params['comments'], U_TP_S)
        if 'groups_count' not in params: params['groups_count'] = len(params['group_id'])
        self.pck.add_data(params['groups_count'], U_TP_I)
        for i in range(len(params['group_id'])):
            self.pck.add_data(params['group_id'][i], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if ret['result']  ==  0:
            ret['error'] = dict({10:"error adding dealer. look debug.log for details"})
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_delete_dealer(self, params):
        """ description
        @params: 
        :(s)  dealer_id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        """
        if not self.urfa_call(0x13003):
            raise Exception("Fail of urfa_call(0x13003) [rpcf_delete_dealer]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['dealer_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if ret['result']  ==  0:
            ret['error'] = dict({10:"error deleting dealer. look debug.log for details"})
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_dealer_info(self, params):
        """ description
        @params: 
        :(s)  dealer_id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        :(s)  login :	(s)  - 
        :(s)  password :	(s)  - 
        :(s)  ip4_address :	(i)  - 
        :(s)  mask4 :	(i)  - 
        :(s)  ip6_address :	(i)  - 
        :(s)  mask6 :	(i)  - 
        :(s)  full_name :	(s)  - 
        :(s)  act_address :	(s)  - 
        :(s)  passport :	(s)  - 
        :(s)  work_tel :	(s)  - 
        :(s)  home_tel :	(s)  - 
        :(s)  mob_tel :	(s)  - 
        :(s)  web_page :	(s)  - 
        :(s)  icq_number :	(s)  - 
        :(s)  email :	(s)  - 
        :(s)  comments :	(s)  - 
        :(s)  who_create :	(i)  - 
        :(s)  who_change :	(i)  - 
        :(s)  create_date :	(i)  - 
        :(s)  change_date :	(i)  - 
        :(s)  groups_count :	(i)  - 
        :(s)    group_id :	(i)  - 
        :(s)    group_name :	(s)  - 
        """
        if not self.urfa_call(0x13004):
            raise Exception("Fail of urfa_call(0x13004) [rpcf_get_dealer_info]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['dealer_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if ret['result']  ==  0:
            ret['error'] = dict({10:"error getting dealer info. look debug.log for details"})
        ret['login'] = self.pck.get_data(U_TP_S)
        ret['password'] = self.pck.get_data(U_TP_S)
        ret['ip4_address'] = self.pck.get_data(U_TP_IP)
        ret['mask4'] = self.pck.get_data(U_TP_I)
        ret['ip6_address'] = self.pck.get_data(U_TP_IP)
        ret['mask6'] = self.pck.get_data(U_TP_I)
        ret['full_name'] = self.pck.get_data(U_TP_S)
        ret['act_address'] = self.pck.get_data(U_TP_S)
        ret['passport'] = self.pck.get_data(U_TP_S)
        ret['work_tel'] = self.pck.get_data(U_TP_S)
        ret['home_tel'] = self.pck.get_data(U_TP_S)
        ret['mob_tel'] = self.pck.get_data(U_TP_S)
        ret['web_page'] = self.pck.get_data(U_TP_S)
        ret['icq_number'] = self.pck.get_data(U_TP_S)
        ret['email'] = self.pck.get_data(U_TP_S)
        ret['comments'] = self.pck.get_data(U_TP_S)
        ret['who_create'] = self.pck.get_data(U_TP_I)
        ret['who_change'] = self.pck.get_data(U_TP_I)
        ret['create_date'] = self.pck.get_data(U_TP_I)
        ret['change_date'] = self.pck.get_data(U_TP_I)
        ret['groups_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['groups_count']): 
            self.pck.recv(self.sck)
            ret['group_id'][i] = self.pck.get_data(U_TP_I)
            ret['group_name'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_report_dealer_users(self, params):
        """ description
        @params: 
        :(s)  dealer_id :	(i)  - 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i)  - 
        @returns: 
        :(s)  users_count :	(i)  - 
        :(s)    user_id_array :	(s)  - 
        :(s)    login_array :	(s)  - 
        :(s)    full_name_array :	(s)  - 
        :(s)    create_date_array :	(i)  - 
        """
        if not self.urfa_call(0x1300e):
            raise Exception("Fail of urfa_call(0x1300e) [rpcf_report_dealer_users]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['dealer_id'], U_TP_I)
        self.pck.add_data(params['time_start'], U_TP_I)
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['users_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['users_count']): 
            self.pck.recv(self.sck)
            ret['user_id_array'][i] = self.pck.get_data(U_TP_S)
            ret['login_array'][i] = self.pck.get_data(U_TP_S)
            ret['full_name_array'][i] = self.pck.get_data(U_TP_S)
            ret['create_date_array'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_report_dealer_payments(self, params):
        """ description
        @params: 
        :(s)  dealer_id :	(i)  - 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i)  - 
        @returns: 
        :(s)  payments_count :	(i)  - 
        :(s)  payments_sum :	(d)  - 
        """
        if not self.urfa_call(0x1300f):
            raise Exception("Fail of urfa_call(0x1300f) [rpcf_report_dealer_payments]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['dealer_id'], U_TP_I)
        self.pck.add_data(params['time_start'], U_TP_I)
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['payments_count'] = self.pck.get_data(U_TP_I)
        ret['payments_sum'] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_report_dealer_payments_ex(self, params):
        """ description
        @params: 
        :(s)  dealer_id :	(i)  - 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i)  - 
        @returns: 
        :(s)  methods_size :	(i)  - 
        :(s)    method_array :	(i)  - 
        :(s)    payments_count_array :	(i)  - 
        :(s)    payments_sum_array :	(d)  - 
        """
        if not self.urfa_call(0x13010):
            raise Exception("Fail of urfa_call(0x13010) [rpcf_report_dealer_payments_ex]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['dealer_id'], U_TP_I)
        self.pck.add_data(params['time_start'], U_TP_I)
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['methods_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['methods_size']): 
            self.pck.recv(self.sck)
            ret['method_array'][i] = self.pck.get_data(U_TP_I)
            ret['payments_count_array'][i] = self.pck.get_data(U_TP_I)
            ret['payments_sum_array'][i] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_dealer_contacts(self, params):
        """ description
        @params: 
        :(s)  dealer_id :	(i)  - 
        @returns: 
        :(s)  size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    person :	(s)  - 
        :(s)    descr :	(s)  - 
        :(s)    contact :	(s)  - 
        :(s)    email :	(s)  - 
        :(s)    email_notify :	(i)  - 
        :(s)    short_name :	(s)  - 
        :(s)    birthday :	(s)  - 
        :(s)    id_exec_man :	(i)  - 
        """
        if not self.urfa_call(0x13011):
            raise Exception("Fail of urfa_call(0x13011) [rpcf_get_dealer_contacts]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['dealer_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['person'][i] = self.pck.get_data(U_TP_S)
            ret['descr'][i] = self.pck.get_data(U_TP_S)
            ret['contact'][i] = self.pck.get_data(U_TP_S)
            ret['email'][i] = self.pck.get_data(U_TP_S)
            ret['email_notify'][i] = self.pck.get_data(U_TP_I)
            ret['short_name'][i] = self.pck.get_data(U_TP_S)
            ret['birthday'][i] = self.pck.get_data(U_TP_S)
            ret['id_exec_man'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_dealer_contact(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        :(s)  user_id :	(i)  - 
        :(s)  person :	(s)  - 
        :(s)  descr :	(s)  - 
        :(s)  contact :	(s)  - 
        :(s)  email :	(s)  - 
        :(s)  email_notify :	(i)  - 
        :(s)  short_name :	(s)  - 
        :(s)  birthday :	(s)  - 
        :(s)  id_exec_man :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x13012):
            raise Exception("Fail of urfa_call(0x13012) [rpcf_add_dealer_contact]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['person'], U_TP_S)
        self.pck.add_data(params['descr'], U_TP_S)
        self.pck.add_data(params['contact'], U_TP_S)
        self.pck.add_data(params['email'], U_TP_S)
        self.pck.add_data(params['email_notify'], U_TP_I)
        self.pck.add_data(params['short_name'], U_TP_S)
        self.pck.add_data(params['birthday'], U_TP_S)
        self.pck.add_data(params['id_exec_man'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_delete_dealer_contact(self, params):
        """ description
        @params: 
        :(s)  contact_id :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x13013):
            raise Exception("Fail of urfa_call(0x13013) [rpcf_delete_dealer_contact]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['contact_id'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_dealers_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  dealers_count :	(i)  - 
        :(s)    dealer_id_array :	(i)  - 
        :(s)    login_array :	(s)  - 
        :(s)    full_name_array :	(s)  - 
        :(s)    ip4_array :	(i)  - 
        :(s)    mask4_array :	(i)  - 
        :(s)    ip6_array :	(i)  - 
        :(s)    mask6_array :	(i)  - 
        """
        if not self.urfa_call(0x13019):
            raise Exception("Fail of urfa_call(0x13019) [rpcf_get_dealers_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['dealers_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['dealers_count']): 
            self.pck.recv(self.sck)
            ret['dealer_id_array'][i] = self.pck.get_data(U_TP_I)
            ret['login_array'][i] = self.pck.get_data(U_TP_S)
            ret['full_name_array'][i] = self.pck.get_data(U_TP_S)
            ret['ip4_array'][i] = self.pck.get_data(U_TP_IP)
            ret['mask4_array'][i] = self.pck.get_data(U_TP_I)
            ret['ip6_array'][i] = self.pck.get_data(U_TP_IP)
            ret['mask6_array'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_grant_privileges_to_dealer(self, params):
        """ description
        @params: 
        :(s)  dealer_id :	(i)  - 
        :(s)  entity_type :	(i)  - 
        :(s)  entity_id_count :	(i) = _def_  - 
        :(s)    entity_id_array :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x1301a):
            raise Exception("Fail of urfa_call(0x1301a) [rpcf_grant_privileges_to_dealer]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['dealer_id'], U_TP_I)
        self.pck.add_data(params['entity_type'], U_TP_I)
        if 'entity_id_count' not in params: params['entity_id_count'] = len(params['entity_id_array'])
        self.pck.add_data(params['entity_id_count'], U_TP_I)
        for i in range(len(params['entity_id_array'])):
            self.pck.add_data(params['entity_id_array'][i], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_dealer_privileges(self, params):
        """ description
        @params: 
        :(s)  dealer_id :	(i)  - 
        :(s)  entity_type :	(i)  - 
        @returns: 
        :(s)  entity_id_count :	(i)  - 
        :(s)    entity_id_array :	(i)  - 
        """
        if not self.urfa_call(0x1301b):
            raise Exception("Fail of urfa_call(0x1301b) [rpcf_get_dealer_privileges]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['dealer_id'], U_TP_I)
        self.pck.add_data(params['entity_type'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['entity_id_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['entity_id_count']): 
            self.pck.recv(self.sck)
            ret['entity_id_array'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_revoke_dealer_privileges(self, params):
        """ description
        @params: 
        :(s)  dealer_id :	(i)  - 
        :(s)  entity_type :	(i)  - 
        :(s)  entity_id_count :	(i) = _def_  - 
        :(s)    entity_id_array :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x1301c):
            raise Exception("Fail of urfa_call(0x1301c) [rpcf_revoke_dealer_privileges]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['dealer_id'], U_TP_I)
        self.pck.add_data(params['entity_type'], U_TP_I)
        if 'entity_id_count' not in params: params['entity_id_count'] = len(params['entity_id_array'])
        self.pck.add_data(params['entity_id_count'], U_TP_I)
        for i in range(len(params['entity_id_array'])):
            self.pck.add_data(params['entity_id_array'][i], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_verify_dealer_cache(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x1301d):
            raise Exception("Fail of urfa_call(0x1301d) [rpcf_verify_dealer_cache]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_dealer_users_map(self, params):
        """ description
        @params: 
        :(s)  from :	(i)  - 
        :(s)  to :	(i)  - 
        @returns: 
        :(s)  users_count :	(i)  - 
        :(s)    user_id :	(i)  - 
        :(s)    login :	(s)  - 
        :(s)    full_name :	(s)  - 
        :(s)    basic_account :	(i)  - 
        :(s)    dealer_id :	(i)  - 
        """
        if not self.urfa_call(0x13027):
            raise Exception("Fail of urfa_call(0x13027) [rpcf_get_dealer_users_map]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['from'], U_TP_I)
        self.pck.add_data(params['to'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['users_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['users_count']): 
            self.pck.recv(self.sck)
            ret['user_id'][i] = self.pck.get_data(U_TP_I)
            ret['login'][i] = self.pck.get_data(U_TP_S)
            ret['full_name'][i] = self.pck.get_data(U_TP_S)
            ret['basic_account'][i] = self.pck.get_data(U_TP_I)
            ret['dealer_id'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_add_user(self, params):
        """ description
        @params: 
        :(s)  login :	(s)  - 
        :(s)  password :	(s)  - 
        :(s)  full_name :	(s)  - 
        :(s)  is_juridical :	(i) = _def_  - 
        :(s)  jur_address :	(s)  - 
        :(s)  act_address :	(s)  - 
        :(s)  flat_number :	(s)  - 
        :(s)  entrance :	(s)  - 
        :(s)  floor :	(s)  - 
        :(s)  district :	(s)  - 
        :(s)  building :	(s)  - 
        :(s)  passport :	(s)  - 
        :(s)  house_id :	(i) = _def_  - 
        :(s)  work_tel :	(s)  - 
        :(s)  home_tel :	(s)  - 
        :(s)  mob_tel :	(s)  - 
        :(s)  web_page :	(s)  - 
        :(s)  icq_number :	(s)  - 
        :(s)  tax_number :	(s)  - 
        :(s)  kpp_number :	(s)  - 
        :(s)  email :	(s)  - 
        :(s)  bank_id :	(i) = _def_  - 
        :(s)  bank_account :	(s)  - 
        :(s)  comments :	(s)  - 
        :(s)  personal_manager :	(s)  - 
        :(s)  connect_date :	(i) = _def_  - 
        :(s)  is_send_invoice :	(i) = _def_  - 
        :(s)  advance_payment :	(i) = _def_  - 
        :(s)  parameters_count :	(i) = _def_  - 
        :(s)    parameter_id :	(i)  - 
        :(s)    parameter_value :	(s)  - 
        @returns: 
        :(s)  user_id :	(i)  - 
        :(s)    account_id :	(i)  - 
        """
        if not self.urfa_call(0x70000001):
            raise Exception("Fail of urfa_call(0x70000001) [rpcf_dealer_add_user]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['login'], U_TP_S)
        self.pck.add_data(params['password'], U_TP_S)
        self.pck.add_data(params['full_name'], U_TP_S)
        if 'is_juridical' not in params: params['is_juridical'] = 0
        self.pck.add_data(params['is_juridical'], U_TP_I)
        self.pck.add_data(params['jur_address'], U_TP_S)
        self.pck.add_data(params['act_address'], U_TP_S)
        self.pck.add_data(params['flat_number'], U_TP_S)
        self.pck.add_data(params['entrance'], U_TP_S)
        self.pck.add_data(params['floor'], U_TP_S)
        self.pck.add_data(params['district'], U_TP_S)
        self.pck.add_data(params['building'], U_TP_S)
        self.pck.add_data(params['passport'], U_TP_S)
        if 'house_id' not in params: params['house_id'] = 0
        self.pck.add_data(params['house_id'], U_TP_I)
        self.pck.add_data(params['work_tel'], U_TP_S)
        self.pck.add_data(params['home_tel'], U_TP_S)
        self.pck.add_data(params['mob_tel'], U_TP_S)
        self.pck.add_data(params['web_page'], U_TP_S)
        self.pck.add_data(params['icq_number'], U_TP_S)
        self.pck.add_data(params['tax_number'], U_TP_S)
        self.pck.add_data(params['kpp_number'], U_TP_S)
        self.pck.add_data(params['email'], U_TP_S)
        if 'bank_id' not in params: params['bank_id'] = 0
        self.pck.add_data(params['bank_id'], U_TP_I)
        self.pck.add_data(params['bank_account'], U_TP_S)
        self.pck.add_data(params['comments'], U_TP_S)
        self.pck.add_data(params['personal_manager'], U_TP_S)
        if 'connect_date' not in params: params['connect_date'] = 0
        self.pck.add_data(params['connect_date'], U_TP_I)
        if 'is_send_invoice' not in params: params['is_send_invoice'] = 0
        self.pck.add_data(params['is_send_invoice'], U_TP_I)
        if 'advance_payment' not in params: params['advance_payment'] = 0
        self.pck.add_data(params['advance_payment'], U_TP_I)
        if 'parameters_count' not in params: params['parameters_count'] = len(params['parameter_value'])
        self.pck.add_data(params['parameters_count'], U_TP_I)
        for i in range(len(params['parameter_value'])):
            self.pck.add_data(params['parameter_id'][i], U_TP_I)
            self.pck.add_data(params['parameter_value'][i], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['user_id'] = self.pck.get_data(U_TP_I)
        if ret['user_id']  !=  0:
            ret['account_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_edit_user(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  login :	(s)  - 
        :(s)  password :	(s)  - 
        :(s)  full_name :	(s)  - 
        :(s)  is_juridical :	(i) = _def_  - 
        :(s)  jur_address :	(s)  - 
        :(s)  act_address :	(s)  - 
        :(s)  flat_number :	(s)  - 
        :(s)  entrance :	(s)  - 
        :(s)  floor :	(s)  - 
        :(s)  district :	(s)  - 
        :(s)  building :	(s)  - 
        :(s)  passport :	(s)  - 
        :(s)  house_id :	(i) = _def_  - 
        :(s)  work_tel :	(s)  - 
        :(s)  home_tel :	(s)  - 
        :(s)  mob_tel :	(s)  - 
        :(s)  web_page :	(s)  - 
        :(s)  icq_number :	(s)  - 
        :(s)  tax_number :	(s)  - 
        :(s)  kpp_number :	(s)  - 
        :(s)  email :	(s)  - 
        :(s)  bank_id :	(i) = _def_  - 
        :(s)  bank_account :	(s)  - 
        :(s)  comments :	(s)  - 
        :(s)  personal_manager :	(s)  - 
        :(s)  connect_date :	(i) = _def_  - 
        :(s)  is_send_invoice :	(i) = _def_  - 
        :(s)  advance_payment :	(i) = _def_  - 
        :(s)  parameters_count :	(i) = _def_  - 
        :(s)    parameter_id :	(i)  - 
        :(s)    parameter_value :	(s)  - 
        @returns: 
        :(s)  user_id :	(i)  - 
        """
        if not self.urfa_call(0x70000002):
            raise Exception("Fail of urfa_call(0x70000002) [rpcf_dealer_edit_user]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['login'], U_TP_S)
        self.pck.add_data(params['password'], U_TP_S)
        self.pck.add_data(params['full_name'], U_TP_S)
        if 'is_juridical' not in params: params['is_juridical'] = 0
        self.pck.add_data(params['is_juridical'], U_TP_I)
        self.pck.add_data(params['jur_address'], U_TP_S)
        self.pck.add_data(params['act_address'], U_TP_S)
        self.pck.add_data(params['flat_number'], U_TP_S)
        self.pck.add_data(params['entrance'], U_TP_S)
        self.pck.add_data(params['floor'], U_TP_S)
        self.pck.add_data(params['district'], U_TP_S)
        self.pck.add_data(params['building'], U_TP_S)
        self.pck.add_data(params['passport'], U_TP_S)
        if 'house_id' not in params: params['house_id'] = 0
        self.pck.add_data(params['house_id'], U_TP_I)
        self.pck.add_data(params['work_tel'], U_TP_S)
        self.pck.add_data(params['home_tel'], U_TP_S)
        self.pck.add_data(params['mob_tel'], U_TP_S)
        self.pck.add_data(params['web_page'], U_TP_S)
        self.pck.add_data(params['icq_number'], U_TP_S)
        self.pck.add_data(params['tax_number'], U_TP_S)
        self.pck.add_data(params['kpp_number'], U_TP_S)
        self.pck.add_data(params['email'], U_TP_S)
        if 'bank_id' not in params: params['bank_id'] = 0
        self.pck.add_data(params['bank_id'], U_TP_I)
        self.pck.add_data(params['bank_account'], U_TP_S)
        self.pck.add_data(params['comments'], U_TP_S)
        self.pck.add_data(params['personal_manager'], U_TP_S)
        if 'connect_date' not in params: params['connect_date'] = 0
        self.pck.add_data(params['connect_date'], U_TP_I)
        if 'is_send_invoice' not in params: params['is_send_invoice'] = 0
        self.pck.add_data(params['is_send_invoice'], U_TP_I)
        if 'advance_payment' not in params: params['advance_payment'] = 0
        self.pck.add_data(params['advance_payment'], U_TP_I)
        if 'parameters_count' not in params: params['parameters_count'] = len(params['parameter_value'])
        self.pck.add_data(params['parameters_count'], U_TP_I)
        for i in range(len(params['parameter_value'])):
            self.pck.add_data(params['parameter_id'][i], U_TP_I)
            self.pck.add_data(params['parameter_value'][i], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['user_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_delete_user(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x70000003):
            raise Exception("Fail of urfa_call(0x70000003) [rpcf_dealer_delete_user]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_users_list(self, params):
        """ description
        @params: 
        :(s)  from :	(i) = _def_  - 
        :(s)  to :	(i) = _def_  - 
        @returns: 
        :(s)  cnt :	(i)  - 
        :(s)    user_id_array :	(i)  - 
        :(s)    login_array :	(s)  - 
        :(s)    basic_account :	(i)  - 
        :(s)    full_name :	(s)  - 
        :(s)    is_blocked :	(i)  - 
        :(s)    balance :	(d)  - 
        :(s)    ip_adr_size :	(i)  - 
        :(s)      group_size :	(i)  - 
        :(s)        ip_address :	(i)  - 
        :(s)        mask :	(i)  - 
        :(s)        group_type :	(i)  - 
        :(s)    user_int_status :	(i)  - 
        """
        if not self.urfa_call(0x70000056):
            raise Exception("Fail of urfa_call(0x70000056) [rpcf_dealer_get_users_list]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'from' not in params: params['from'] = 0
        self.pck.add_data(params['from'], U_TP_I)
        if 'to' not in params: params['to'] = -1
        self.pck.add_data(params['to'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['cnt'] = self.pck.get_data(U_TP_I)
        for i in range(ret['cnt']): 
            self.pck.recv(self.sck)
            ret['user_id_array'][i] = self.pck.get_data(U_TP_I)
            ret['login_array'][i] = self.pck.get_data(U_TP_S)
            ret['basic_account'][i] = self.pck.get_data(U_TP_I)
            ret['full_name'][i] = self.pck.get_data(U_TP_S)
            ret['is_blocked'][i] = self.pck.get_data(U_TP_I)
            ret['balance'][i] = self.pck.get_data(U_TP_D)
            ret['ip_adr_size'] = self.pck.get_data(U_TP_I)
            ret['ip_adr_size_array'][i]=ret['ip_adr_size']
            for j in range(ret['ip_adr_size']): 
                self.pck.recv(self.sck)
                ret['group_size'] = self.pck.get_data(U_TP_I)
                ret['group_size_array'][i][j]=ret['group_size']
                for x in range(ret['group_size']): 
                    self.pck.recv(self.sck)
                    if not i in ret['ip_address']:ret['ip_address'][i] = dict()
                    if not j in ret['ip_address'][i]:ret['ip_address'][i][j] = dict()
                    ret['ip_address'][i][j][x] = self.pck.get_data(U_TP_IP)
                    if not i in ret['mask']:ret['mask'][i] = dict()
                    if not j in ret['mask'][i]:ret['mask'][i][j] = dict()
                    ret['mask'][i][j][x] = self.pck.get_data(U_TP_I)
                    if not i in ret['group_type']:ret['group_type'][i] = dict()
                    if not j in ret['group_type'][i]:ret['group_type'][i][j] = dict()
                    ret['group_type'][i][j][x] = self.pck.get_data(U_TP_I)
            self.pck.recv(self.sck)
            ret['user_int_status'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_user_info(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        @returns: 
        :(s)  user_id :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        :(s)  accounts_count :	(i)  - 
        :(s)    account_id_array :	(i)  - 
        :(s)    account_name_array :	(s)  - 
        :(s)  login :	(s)  - 
        :(s)  password :	(s)  - 
        :(s)  basic_account :	(i)  - 
        :(s)  full_name :	(s)  - 
        :(s)  create_date :	(i)  - 
        :(s)  last_change_date :	(i)  - 
        :(s)  who_create :	(i)  - 
        :(s)  who_change :	(i)  - 
        :(s)  is_juridical :	(i)  - 
        :(s)  jur_address :	(s)  - 
        :(s)  act_address :	(s)  - 
        :(s)  work_tel :	(s)  - 
        :(s)  home_tel :	(s)  - 
        :(s)  mob_tel :	(s)  - 
        :(s)  web_page :	(s)  - 
        :(s)  icq_number :	(s)  - 
        :(s)  tax_number :	(s)  - 
        :(s)  kpp_number :	(s)  - 
        :(s)  bank_id :	(i)  - 
        :(s)  bank_account :	(s)  - 
        :(s)  comments :	(s)  - 
        :(s)  personal_manager :	(s)  - 
        :(s)  connect_date :	(i)  - 
        :(s)  email :	(s)  - 
        :(s)  is_send_invoice :	(i)  - 
        :(s)  advance_payment :	(i)  - 
        :(s)  house_id :	(i)  - 
        :(s)  flat_number :	(s)  - 
        :(s)  entrance :	(s)  - 
        :(s)  floor :	(s)  - 
        :(s)  district :	(s)  - 
        :(s)  building :	(s)  - 
        :(s)  passport :	(s)  - 
        :(s)  parameters_size :	(i)  - 
        :(s)    parameted_id :	(i)  - 
        :(s)    parameter_value :	(s)  - 
        """
        if not self.urfa_call(0x70000005):
            raise Exception("Fail of urfa_call(0x70000005) [rpcf_dealer_get_user_info]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['user_id'] = self.pck.get_data(U_TP_I)
        if params['user_id']  ==  0:
            ret['error'] = dict({10:"user not found"})
        ret['accounts_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['accounts_count']): 
            self.pck.recv(self.sck)
            ret['account_id_array'][i] = self.pck.get_data(U_TP_I)
            ret['account_name_array'][i] = self.pck.get_data(U_TP_S)
        self.pck.recv(self.sck)
        ret['login'] = self.pck.get_data(U_TP_S)
        ret['password'] = self.pck.get_data(U_TP_S)
        ret['basic_account'] = self.pck.get_data(U_TP_I)
        ret['full_name'] = self.pck.get_data(U_TP_S)
        ret['create_date'] = self.pck.get_data(U_TP_I)
        ret['last_change_date'] = self.pck.get_data(U_TP_I)
        ret['who_create'] = self.pck.get_data(U_TP_I)
        ret['who_change'] = self.pck.get_data(U_TP_I)
        ret['is_juridical'] = self.pck.get_data(U_TP_I)
        ret['jur_address'] = self.pck.get_data(U_TP_S)
        ret['act_address'] = self.pck.get_data(U_TP_S)
        ret['work_tel'] = self.pck.get_data(U_TP_S)
        ret['home_tel'] = self.pck.get_data(U_TP_S)
        ret['mob_tel'] = self.pck.get_data(U_TP_S)
        ret['web_page'] = self.pck.get_data(U_TP_S)
        ret['icq_number'] = self.pck.get_data(U_TP_S)
        ret['tax_number'] = self.pck.get_data(U_TP_S)
        ret['kpp_number'] = self.pck.get_data(U_TP_S)
        ret['bank_id'] = self.pck.get_data(U_TP_I)
        ret['bank_account'] = self.pck.get_data(U_TP_S)
        ret['comments'] = self.pck.get_data(U_TP_S)
        ret['personal_manager'] = self.pck.get_data(U_TP_S)
        ret['connect_date'] = self.pck.get_data(U_TP_I)
        ret['email'] = self.pck.get_data(U_TP_S)
        ret['is_send_invoice'] = self.pck.get_data(U_TP_I)
        ret['advance_payment'] = self.pck.get_data(U_TP_I)
        ret['house_id'] = self.pck.get_data(U_TP_I)
        ret['flat_number'] = self.pck.get_data(U_TP_S)
        ret['entrance'] = self.pck.get_data(U_TP_S)
        ret['floor'] = self.pck.get_data(U_TP_S)
        ret['district'] = self.pck.get_data(U_TP_S)
        ret['building'] = self.pck.get_data(U_TP_S)
        ret['passport'] = self.pck.get_data(U_TP_S)
        ret['parameters_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['parameters_size']): 
            self.pck.recv(self.sck)
            ret['parameted_id'][i] = self.pck.get_data(U_TP_I)
            ret['parameter_value'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_groups_for_user(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        @returns: 
        :(s)  groups_size :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        :(s)    group_id :	(i)  - 
        :(s)    group_name :	(s)  - 
        """
        if not self.urfa_call(0x70000006):
            raise Exception("Fail of urfa_call(0x70000006) [rpcf_dealer_get_groups_for_user]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['groups_size'] = self.pck.get_data(U_TP_I)
        if ret['groups_size']  ==  0:
            ret['error'] = dict({10:"user has no groups or you dont have enough privileges"})
        for i in range(ret['groups_size']): 
            self.pck.recv(self.sck)
            ret['group_id'][i] = self.pck.get_data(U_TP_I)
            ret['group_name'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_user_contacts(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        @returns: 
        :(s)  size :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        :(s)    id :	(i)  - 
        :(s)    person :	(s)  - 
        :(s)    descr :	(s)  - 
        :(s)    contact :	(s)  - 
        :(s)    email :	(s)  - 
        :(s)    email_notify :	(i)  - 
        :(s)    short_name :	(s)  - 
        :(s)    birthday :	(s)  - 
        :(s)    id_exec_man :	(i)  - 
        """
        if not self.urfa_call(0x70000009):
            raise Exception("Fail of urfa_call(0x70000009) [rpcf_dealer_get_user_contacts]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['size'] = self.pck.get_data(U_TP_I)
        if ret['size']  ==  0:
            ret['error'] = dict({10:"user has no contacts or you dont have enough privileges"})
        for i in range(ret['size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['person'][i] = self.pck.get_data(U_TP_S)
            ret['descr'][i] = self.pck.get_data(U_TP_S)
            ret['contact'][i] = self.pck.get_data(U_TP_S)
            ret['email'][i] = self.pck.get_data(U_TP_S)
            ret['email_notify'][i] = self.pck.get_data(U_TP_I)
            ret['short_name'][i] = self.pck.get_data(U_TP_S)
            ret['birthday'][i] = self.pck.get_data(U_TP_S)
            ret['id_exec_man'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_add_user_contact(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  person :	(s)  - 
        :(s)  descr :	(s)  - 
        :(s)  contact :	(s)  - 
        :(s)  email :	(s)  - 
        :(s)  email_notify :	(i) = _def_  - 
        :(s)  short_name :	(s)  - 
        :(s)  birthday :	(s)  - 
        :(s)  id_exec_man :	(i) = _def_  - 
        @returns: 
        :(s)  result :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        """
        if not self.urfa_call(0x70000042):
            raise Exception("Fail of urfa_call(0x70000042) [rpcf_dealer_add_user_contact]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['person'], U_TP_S)
        self.pck.add_data(params['descr'], U_TP_S)
        self.pck.add_data(params['contact'], U_TP_S)
        self.pck.add_data(params['email'], U_TP_S)
        if 'email_notify' not in params: params['email_notify'] = 1
        self.pck.add_data(params['email_notify'], U_TP_I)
        self.pck.add_data(params['short_name'], U_TP_S)
        self.pck.add_data(params['birthday'], U_TP_S)
        if 'id_exec_man' not in params: params['id_exec_man'] = 0
        self.pck.add_data(params['id_exec_man'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if ret['result']  ==  0:
            ret['error'] = dict({10:"user not found or you dont have enough privileges"})
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_edit_user_contact(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  id :	(i)  - 
        :(s)  person :	(s)  - 
        :(s)  descr :	(s)  - 
        :(s)  contact :	(s)  - 
        :(s)  email :	(s)  - 
        :(s)  email_notify :	(i)  - 
        :(s)  short_name :	(s)  - 
        :(s)  birthday :	(s)  - 
        :(s)  id_exec_man :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        """
        if not self.urfa_call(0x70000043):
            raise Exception("Fail of urfa_call(0x70000043) [rpcf_dealer_edit_user_contact]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['person'], U_TP_S)
        self.pck.add_data(params['descr'], U_TP_S)
        self.pck.add_data(params['contact'], U_TP_S)
        self.pck.add_data(params['email'], U_TP_S)
        self.pck.add_data(params['email_notify'], U_TP_I)
        self.pck.add_data(params['short_name'], U_TP_S)
        self.pck.add_data(params['birthday'], U_TP_S)
        self.pck.add_data(params['id_exec_man'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if ret['result']  ==  0:
            ret['error'] = dict({10:"user not found or you dont have enough privileges"})
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_delete_user_contact(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        """
        if not self.urfa_call(0x70000044):
            raise Exception("Fail of urfa_call(0x70000044) [rpcf_dealer_delete_user_contact]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if ret['result']  ==  0:
            ret['error'] = dict({10:"contact not found or you dont have enough privileges"})
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_users_count(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  users_count :	(i)  - 
        """
        if not self.urfa_call(0x7000000a):
            raise Exception("Fail of urfa_call(0x7000000a) [rpcf_dealer_get_users_count]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['users_count'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_user_account_list(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        @returns: 
        :(s)  accounts_count :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        :(s)    account :	(i)  - 
        :(s)    account_name :	(s)  - 
        """
        if not self.urfa_call(0x70000008):
            raise Exception("Fail of urfa_call(0x70000008) [rpcf_dealer_get_user_account_list]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['accounts_count'] = self.pck.get_data(U_TP_I)
        if ret['accounts_count']  ==  0:
            ret['error'] = dict({10:"user has no accounts or you dont have enough privileges"})
        for i in range(ret['accounts_count']): 
            self.pck.recv(self.sck)
            ret['account'][i] = self.pck.get_data(U_TP_I)
            ret['account_name'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_generate_doc_for_user(self, params):
        """ description
        @params: 
        :(s)  doc_type_id :	(i)  - 
        :(s)  user_id :	(i)  - 
        :(s)  base_id :	(i)  - 
        :(s)  doc_template_id :	(i)  - 
        @returns: 
        :(s)  text_cnt :	(i)  - 
        :(s)      text :	(s)  - 
        :(s)    landscape :	(i)  - 
        """
        if not self.urfa_call(0x70000072):
            raise Exception("Fail of urfa_call(0x70000072) [rpcf_dealer_generate_doc_for_user]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['doc_type_id'], U_TP_I)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['base_id'], U_TP_I)
        self.pck.add_data(params['doc_template_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['text_cnt'] = self.pck.get_data(U_TP_I)
        if ret['text_cnt']  !=  0:
            for i in range(ret['text_cnt']): 
                self.pck.recv(self.sck)
                ret['text'][i] = self.pck.get_data(U_TP_S)
            self.pck.recv(self.sck)
            ret['landscape'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_houses_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  houses_size :	(i)  - 
        :(s)    house_id :	(i)  - 
        :(s)    ip_zone_id :	(i)  - 
        :(s)    connect_date :	(i)  - 
        :(s)    post_code :	(s)  - 
        :(s)    country :	(s)  - 
        :(s)    region :	(s)  - 
        :(s)    city :	(s)  - 
        :(s)    street :	(s)  - 
        :(s)    number :	(s)  - 
        :(s)    building :	(s)  - 
        """
        if not self.urfa_call(0x7000000d):
            raise Exception("Fail of urfa_call(0x7000000d) [rpcf_dealer_get_houses_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['houses_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['houses_size']): 
            self.pck.recv(self.sck)
            ret['house_id'][i] = self.pck.get_data(U_TP_I)
            ret['ip_zone_id'][i] = self.pck.get_data(U_TP_I)
            ret['connect_date'][i] = self.pck.get_data(U_TP_I)
            ret['post_code'][i] = self.pck.get_data(U_TP_S)
            ret['country'][i] = self.pck.get_data(U_TP_S)
            ret['region'][i] = self.pck.get_data(U_TP_S)
            ret['city'][i] = self.pck.get_data(U_TP_S)
            ret['street'][i] = self.pck.get_data(U_TP_S)
            ret['number'][i] = self.pck.get_data(U_TP_S)
            ret['building'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_banks(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  banks_size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    bic :	(s)  - 
        :(s)    name :	(s)  - 
        :(s)    city :	(s)  - 
        :(s)    kschet :	(s)  - 
        """
        if not self.urfa_call(0x7000000e):
            raise Exception("Fail of urfa_call(0x7000000e) [rpcf_dealer_get_banks]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['banks_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['banks_size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['bic'][i] = self.pck.get_data(U_TP_S)
            ret['name'][i] = self.pck.get_data(U_TP_S)
            ret['city'][i] = self.pck.get_data(U_TP_S)
            ret['kschet'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_sup(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  count :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    name :	(s)  - 
        :(s)    ur_adress :	(s)  - 
        :(s)    act_adress :	(s)  - 
        :(s)    inn :	(s)  - 
        :(s)    kpp :	(s)  - 
        :(s)    bank_id :	(i)  - 
        :(s)    account :	(s)  - 
        :(s)    fio_headman :	(s)  - 
        :(s)    fio_bookeeper :	(s)  - 
        :(s)    fio_headman_sh :	(s)  - 
        :(s)    fio_bookeeper_sh :	(s)  - 
        :(s)    name_sh :	(s)  - 
        :(s)    bank_bic :	(s)  - 
        :(s)    bank_name :	(s)  - 
        :(s)    bank_city :	(s)  - 
        :(s)    bank_kschet :	(s)  - 
        """
        if not self.urfa_call(0x7000000f):
            raise Exception("Fail of urfa_call(0x7000000f) [rpcf_dealer_get_sup]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['count']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['name'][i] = self.pck.get_data(U_TP_S)
            ret['ur_adress'][i] = self.pck.get_data(U_TP_S)
            ret['act_adress'][i] = self.pck.get_data(U_TP_S)
            ret['inn'][i] = self.pck.get_data(U_TP_S)
            ret['kpp'][i] = self.pck.get_data(U_TP_S)
            ret['bank_id'][i] = self.pck.get_data(U_TP_I)
            ret['account'][i] = self.pck.get_data(U_TP_S)
            ret['fio_headman'][i] = self.pck.get_data(U_TP_S)
            ret['fio_bookeeper'][i] = self.pck.get_data(U_TP_S)
            ret['fio_headman_sh'][i] = self.pck.get_data(U_TP_S)
            ret['fio_bookeeper_sh'][i] = self.pck.get_data(U_TP_S)
            ret['name_sh'][i] = self.pck.get_data(U_TP_S)
            ret['bank_bic'][i] = self.pck.get_data(U_TP_S)
            ret['bank_name'][i] = self.pck.get_data(U_TP_S)
            ret['bank_city'][i] = self.pck.get_data(U_TP_S)
            ret['bank_kschet'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_tps_for_user(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  account_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  tplink :	(i)  - 
        :(s)  curr :	(i)  - 
        @returns: 
        :(s)  service_size :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        :(s)    sid :	(i)  - 
        :(s)    service_name :	(s)  - 
        :(s)    service_type :	(i)  - 
        :(s)    comment :	(s)  - 
        :(s)    slink :	(i)  - 
        :(s)    value :	(i)  - 
        """
        if not self.urfa_call(0x70000010):
            raise Exception("Fail of urfa_call(0x70000010) [rpcf_dealer_get_tps_for_user]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.add_data(params['tplink'], U_TP_I)
        self.pck.add_data(params['curr'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['service_size'] = self.pck.get_data(U_TP_I)
        if ret['service_size']  ==  0:
            ret['error'] = dict({13:"tariff not found or you dont have enough privileges"})
        for i in range(ret['service_size']): 
            self.pck.recv(self.sck)
            ret['sid'][i] = self.pck.get_data(U_TP_I)
            ret['service_name'][i] = self.pck.get_data(U_TP_S)
            ret['service_type'][i] = self.pck.get_data(U_TP_I)
            ret['comment'][i] = self.pck.get_data(U_TP_S)
            ret['slink'][i] = self.pck.get_data(U_TP_I)
            ret['value'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_add_account(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  is_basic :	(i) = _def_  - 
        :(s)  is_blocked :	(i) = _def_  - 
        :(s)  account_name :	(s) = _def_  - 
        :(s)  balance :	(d) = _def_  - 
        :(s)  credit :	(d) = _def_  - 
        :(s)  discount_period_id :	(i) = _def_  - 
        :(s)  dealer_account_id :	(i) = _def_  - 
        :(s)  comission_coefficient :	(d) = _def_  - 
        :(s)  default_comission_value :	(d) = _def_  - 
        :(s)  is_dealer :	(i) = _def_  - 
        :(s)  vat_rate :	(d) = _def_  - 
        :(s)  sale_tax_rate :	(d) = _def_  - 
        :(s)  int_status :	(i) = _def_  - 
        @returns: 
        :(s)  account_id :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        """
        if not self.urfa_call(0x70000011):
            raise Exception("Fail of urfa_call(0x70000011) [rpcf_dealer_add_account]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'is_basic' not in params: params['is_basic'] = 1
        self.pck.add_data(params['is_basic'], U_TP_I)
        if 'is_blocked' not in params: params['is_blocked'] = 0
        self.pck.add_data(params['is_blocked'], U_TP_I)
        if 'account_name' not in params: params['account_name'] = 'auto create account'
        self.pck.add_data(params['account_name'], U_TP_S)
        if 'balance' not in params: params['balance'] = 0.0
        self.pck.add_data(params['balance'], U_TP_D)
        if 'credit' not in params: params['credit'] = 0.0
        self.pck.add_data(params['credit'], U_TP_D)
        if 'discount_period_id' not in params: params['discount_period_id'] = 0
        self.pck.add_data(params['discount_period_id'], U_TP_I)
        if 'dealer_account_id' not in params: params['dealer_account_id'] = 0
        self.pck.add_data(params['dealer_account_id'], U_TP_I)
        if 'comission_coefficient' not in params: params['comission_coefficient'] = 0.0
        self.pck.add_data(params['comission_coefficient'], U_TP_D)
        if 'default_comission_value' not in params: params['default_comission_value'] = 0.0
        self.pck.add_data(params['default_comission_value'], U_TP_D)
        if 'is_dealer' not in params: params['is_dealer'] = 0
        self.pck.add_data(params['is_dealer'], U_TP_I)
        if 'vat_rate' not in params: params['vat_rate'] = 0.0
        self.pck.add_data(params['vat_rate'], U_TP_D)
        if 'sale_tax_rate' not in params: params['sale_tax_rate'] = 0.0
        self.pck.add_data(params['sale_tax_rate'], U_TP_D)
        if 'int_status' not in params: params['int_status'] = 1
        self.pck.add_data(params['int_status'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['account_id'] = self.pck.get_data(U_TP_I)
        if ret['account_id']  ==  0:
            ret['error'] = dict({11:"unable to add account or you dont have enough privileges"})
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_delete_account(self, params):
        """ description
        @params: 
        :(s)  account_id :	(i)  - 
        @returns: 
        :(s)  ret_code :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        """
        if not self.urfa_call(0x70000012):
            raise Exception("Fail of urfa_call(0x70000012) [rpcf_dealer_delete_account]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['ret_code'] = self.pck.get_data(U_TP_I)
        if ret['ret_code']  ==  0:
            ret['error'] = dict({11:"account does not exist or you dont have enough privileges"})
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_account_info(self, params):
        """ description
        @params: 
        :(s)  account_id :	(i)  - 
        @returns: 
        :(s)  account_id :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        :(s)  discount_period_id :	(i)  - 
        :(s)  is_blocked :	(i)  - 
        :(s)  vat_rate :	(d)  - 
        :(s)  sale_tax_rate :	(d)  - 
        :(s)  comission_coefficient :	(d)  - 
        :(s)  default_comission_value :	(d)  - 
        :(s)  credit :	(d)  - 
        :(s)  balance :	(d)  - 
        :(s)  int_status :	(i)  - 
        :(s)  block_recalc_abon :	(i)  - 
        :(s)  block_recalc_prepaid :	(i)  - 
        :(s)  unlimited :	(i)  - 
        """
        if not self.urfa_call(0x70000013):
            raise Exception("Fail of urfa_call(0x70000013) [rpcf_dealer_get_account_info]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['account_id'] = self.pck.get_data(U_TP_I)
        if params['account_id']  ==  0:
            ret['error'] = dict({11:" account not found or you dont have enough privileges"})
        ret['discount_period_id'] = self.pck.get_data(U_TP_I)
        ret['is_blocked'] = self.pck.get_data(U_TP_I)
        ret['vat_rate'] = self.pck.get_data(U_TP_D)
        ret['sale_tax_rate'] = self.pck.get_data(U_TP_D)
        ret['comission_coefficient'] = self.pck.get_data(U_TP_D)
        ret['default_comission_value'] = self.pck.get_data(U_TP_D)
        ret['credit'] = self.pck.get_data(U_TP_D)
        ret['balance'] = self.pck.get_data(U_TP_D)
        ret['int_status'] = self.pck.get_data(U_TP_I)
        ret['block_recalc_abon'] = self.pck.get_data(U_TP_I)
        ret['block_recalc_prepaid'] = self.pck.get_data(U_TP_I)
        ret['unlimited'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_block_account(self, params):
        """ description
        @params: 
        :(s)  account_id :	(i)  - 
        :(s)  is_blocked :	(i)  - 
        @returns: 
        :(s)  aid :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        """
        if not self.urfa_call(0x70000014):
            raise Exception("Fail of urfa_call(0x70000014) [rpcf_dealer_block_account]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['is_blocked'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['aid'] = self.pck.get_data(U_TP_I)
        if ret['aid']  ==  0:
            ret['error'] = dict({11:"account not found or you dont have enough privileges"})
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_save_account(self, params):
        """ description
        @params: 
        :(s)  account_id :	(i)  - 
        :(s)  discount_period_id :	(i)  - 
        :(s)  credit :	(d)  - 
        :(s)  is_blocked :	(i)  - 
        :(s)    block_start_date :	(i) = _def_  - 
        :(s)    block_end_date :	(i) = _def_  - 
        :(s)  vat_rate :	(d)  - 
        :(s)  sale_tax_rate :	(d)  - 
        :(s)  int_status :	(i)  - 
        :(s)  block_recalc_abon :	(i)  - 
        :(s)  block_recalc_prepaid :	(i)  - 
        :(s)  unlimited :	(i)  - 
        @returns: 
        :(s)  aid :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        """
        if not self.urfa_call(0x70000015):
            raise Exception("Fail of urfa_call(0x70000015) [rpcf_dealer_save_account]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['discount_period_id'], U_TP_I)
        self.pck.add_data(params['credit'], U_TP_D)
        self.pck.add_data(params['is_blocked'], U_TP_I)
        if params['is_blocked']  !=  0:
            if 'block_start_date' not in params: params['block_start_date'] = now()
            self.pck.add_data(params['block_start_date'], U_TP_I)
            if 'block_end_date' not in params: params['block_end_date'] = max_time()
            self.pck.add_data(params['block_end_date'], U_TP_I)
        self.pck.add_data(params['vat_rate'], U_TP_D)
        self.pck.add_data(params['sale_tax_rate'], U_TP_D)
        self.pck.add_data(params['int_status'], U_TP_I)
        self.pck.add_data(params['block_recalc_abon'], U_TP_I)
        self.pck.add_data(params['block_recalc_prepaid'], U_TP_I)
        self.pck.add_data(params['unlimited'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['aid'] = self.pck.get_data(U_TP_I)
        if ret['aid']  ==  0:
            ret['error'] = dict({11:"account not found or you dont have enough privileges"})
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_charge_policy_for_service(self, params):
        """ description
        @params: 
        :(s)  service_id :	(i)  - 
        @returns: 
        :(s)  charge_policy :	(i)  - 
        """
        if not self.urfa_call(0x70000067):
            raise Exception("Fail of urfa_call(0x70000067) [rpcf_dealer_get_charge_policy_for_service]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['charge_policy'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_periodic_link_stats(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        :(s)    is_active :	(i)  - 
        :(s)    fee_recalc_start :	(i)  - 
        :(s)    fee_recalc_duration :	(i)  - 
        :(s)    ip_recalc_start :	(i)  - 
        :(s)    ip_recalc_durtation :	(i)  - 
        :(s)    tel_recalc_start :	(i)  - 
        :(s)    tel_recalc_duration :	(i)  - 
        :(s)    charged :	(d)  - 
        :(s)    repaid :	(d)  - 
        """
        if not self.urfa_call(0x70000068):
            raise Exception("Fail of urfa_call(0x70000068) [rpcf_dealer_get_periodic_link_stats]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if ret['result']  !=  -1:
            ret['is_active'] = self.pck.get_data(U_TP_I)
            ret['fee_recalc_start'] = self.pck.get_data(U_TP_I)
            ret['fee_recalc_duration'] = self.pck.get_data(U_TP_I)
            ret['ip_recalc_start'] = self.pck.get_data(U_TP_I)
            ret['ip_recalc_durtation'] = self.pck.get_data(U_TP_I)
            ret['tel_recalc_start'] = self.pck.get_data(U_TP_I)
            ret['tel_recalc_duration'] = self.pck.get_data(U_TP_I)
            ret['charged'] = self.pck.get_data(U_TP_D)
            ret['repaid'] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_charge_policy_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  policy_count :	(i)  - 
        :(s)    policy_id_array :	(i)  - 
        :(s)    flags_array :	(i)  - 
        :(s)    name_array :	(s)  - 
        :(s)    tm_count :	(i)  - 
        :(s)      timemark :	(i)  - 
        """
        if not self.urfa_call(0x70000066):
            raise Exception("Fail of urfa_call(0x70000066) [rpcf_dealer_get_charge_policy_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['policy_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['policy_count']): 
            self.pck.recv(self.sck)
            ret['policy_id_array'][i] = self.pck.get_data(U_TP_I)
            ret['flags_array'][i] = self.pck.get_data(U_TP_I)
            ret['name_array'][i] = self.pck.get_data(U_TP_S)
            ret['tm_count'][i] = self.pck.get_data(U_TP_I)
            for e in range(ret['tm_count'][i]): 
                self.pck.recv(self.sck)
                if not i in ret['timemark']:ret['timemark'][i] = dict()
                ret['timemark'][i][e] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_services_list(self, params):
        """ description
        @params: 
        :(s)  service_type :	(i) = _def_  - 
        @returns: 
        :(s)  services_count :	(i)  - 
        :(s)    service_id_array :	(i)  - 
        :(s)      service_name_array :	(s)  - 
        :(s)      service_type_array :	(i)  - 
        :(s)      service_comment_array :	(s)  - 
        :(s)        service_status :	(i)  - 
        :(s)          tariff_name_array :	(s)  - 
        """
        if not self.urfa_call(0x70000021):
            raise Exception("Fail of urfa_call(0x70000021) [rpcf_dealer_get_services_list]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'service_type' not in params: params['service_type'] = -1
        self.pck.add_data(params['service_type'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['services_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['services_count']): 
            self.pck.recv(self.sck)
            ret['service_id_array'][i] = self.pck.get_data(U_TP_I)
            ret['service_id_array_tmp']=ret['service_id_array'][i][i]
            if ret['service_id_array_tmp']  !=  -1:
                ret['service_name_array'][i] = self.pck.get_data(U_TP_S)
                ret['service_type_array'][i] = self.pck.get_data(U_TP_I)
                ret['service_comment_array'][i] = self.pck.get_data(U_TP_S)
                if params['service_type']  !=  0:
                    ret['service_status'] = self.pck.get_data(U_TP_I)
                    ret['service_status_array'][i]=ret['service_status']
                    if ret['service_status']  ==  2:
                        ret['tariff_name_array'][i] = self.pck.get_data(U_TP_S)
                    if ret['service_status']  !=  2:
                        ret['tariff_name_array'][i]=""
                if params['service_type']  ==  0:
                    ret['service_status_array'][i]="0"
                    ret['tariff_name_array'][i]=""
            if ret['service_id_array_tmp']  ==  -1:
                ret['service_name_array'][i]=""
                ret['service_type_array'][i]="0"
                ret['service_comment_array'][i]=""
                ret['service_status_array'][i]="0"
                ret['tariff_name_array'][i]=""
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_hotspot_services_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  services_size :	(i)  - 
        :(s)    service_id :	(i)  - 
        :(s)      service_name :	(s)  - 
        :(s)      service_type :	(i)  - 
        :(s)      comment :	(s)  - 
        """
        if not self.urfa_call(0x70000022):
            raise Exception("Fail of urfa_call(0x70000022) [rpcf_dealer_get_hotspot_services_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['services_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['services_size']): 
            self.pck.recv(self.sck)
            ret['service_id'][i] = self.pck.get_data(U_TP_I)
            ret['service_id_tmp']=ret['service_id'][i][i]
            if ret['service_id_tmp']  !=  -1:
                ret['service_name'][i] = self.pck.get_data(U_TP_S)
                ret['service_type'][i] = self.pck.get_data(U_TP_I)
                ret['comment'][i] = self.pck.get_data(U_TP_S)
            if ret['service_id_tmp']  ==  -1:
                ret['service_name'][i]=""
                ret['service_type'][i]="0"
                ret['comment'][i]=""
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_fictive_services_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  services_size :	(i)  - 
        :(s)    service_id :	(i)  - 
        :(s)      service_name :	(s)  - 
        :(s)      service_type :	(i)  - 
        :(s)      comment :	(s)  - 
        """
        if not self.urfa_call(0x70000023):
            raise Exception("Fail of urfa_call(0x70000023) [rpcf_dealer_get_fictive_services_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['services_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['services_size']): 
            self.pck.recv(self.sck)
            ret['service_id'] = self.pck.get_data(U_TP_I)
            ret['service_id_array'][i]=ret['service_id']
            if ret['service_id']  !=  -1:
                ret['service_name'][i] = self.pck.get_data(U_TP_S)
                ret['service_type'][i] = self.pck.get_data(U_TP_I)
                ret['comment'][i] = self.pck.get_data(U_TP_S)
            if ret['service_id']  ==  -1:
                ret['service_name'][i]=""
                ret['service_type'][i]="0"
                ret['comment'][i]=""
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_hotspot_service(self, params):
        """ description
        @params: 
        :(s)  service_id :	(i)  - 
        @returns: 
        :(s)  sid :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  is_dynamic :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  deprecated :	(i)  - 
        :(s)  discount_method :	(i)  - 
        :(s)  start_date :	(i)  - 
        :(s)  expire_date :	(i)  - 
        :(s)  null_service_prepaid :	(i)  - 
        :(s)  radius_sessions_limit :	(i)  - 
        :(s)  recv_cost :	(d)  - 
        :(s)  rate_limit :	(s)  - 
        :(s)  hsd_allowed_net_size :	(i)  - 
        :(s)    allowed_net_id :	(i)  - 
        :(s)    allowed_net_value :	(i)  - 
        :(s)  cost_size :	(i)  - 
        :(s)    tr_name :	(s)  - 
        :(s)    param1 :	(d)  - 
        :(s)    param2 :	(i)  - 
        :(s)  service_data_parent_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        """
        if not self.urfa_call(0x70000024):
            raise Exception("Fail of urfa_call(0x70000024) [rpcf_dealer_get_hotspot_service]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['sid'] = self.pck.get_data(U_TP_I)
        if ret['sid']  ==  0:
            ret['error'] = dict({11:"service not found or you dont have enough privileges"})
        ret['service_name'] = self.pck.get_data(U_TP_S)
        ret['comment'] = self.pck.get_data(U_TP_S)
        ret['link_by_default'] = self.pck.get_data(U_TP_I)
        ret['is_dynamic'] = self.pck.get_data(U_TP_I)
        ret['cost'] = self.pck.get_data(U_TP_D)
        ret['deprecated'] = self.pck.get_data(U_TP_I)
        ret['discount_method'] = self.pck.get_data(U_TP_I)
        ret['start_date'] = self.pck.get_data(U_TP_I)
        ret['expire_date'] = self.pck.get_data(U_TP_I)
        ret['null_service_prepaid'] = self.pck.get_data(U_TP_I)
        ret['radius_sessions_limit'] = self.pck.get_data(U_TP_I)
        ret['recv_cost'] = self.pck.get_data(U_TP_D)
        ret['rate_limit'] = self.pck.get_data(U_TP_S)
        ret['hsd_allowed_net_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['hsd_allowed_net_size']): 
            self.pck.recv(self.sck)
            ret['allowed_net_id'][i] = self.pck.get_data(U_TP_I)
            ret['allowed_net_value'][i] = self.pck.get_data(U_TP_I)
        self.pck.recv(self.sck)
        ret['cost_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['cost_size']): 
            self.pck.recv(self.sck)
            ret['tr_name'][i] = self.pck.get_data(U_TP_S)
            ret['param1'][i] = self.pck.get_data(U_TP_D)
            ret['param2'][i] = self.pck.get_data(U_TP_I)
        self.pck.recv(self.sck)
        ret['service_data_parent_id'] = self.pck.get_data(U_TP_I)
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        ret['parent_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_dialup_service(self, params):
        """ description
        @params: 
        :(s)  service_id :	(i)  - 
        @returns: 
        :(s)  sid :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  is_dynamic :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  deprecated :	(i)  - 
        :(s)  discount_method :	(i)  - 
        :(s)  start_date :	(i)  - 
        :(s)  expire_date :	(i)  - 
        :(s)  pool_name :	(s)  - 
        :(s)  max_timeout :	(i)  - 
        :(s)  null_service_prepaid :	(i)  - 
        :(s)  radius_sessions_limit :	(i)  - 
        :(s)  login_prefix :	(s)  - 
        :(s)  cost_size :	(i)  - 
        :(s)    tr_name :	(s)  - 
        :(s)    param :	(d)  - 
        :(s)    id :	(i)  - 
        :(s)  is_parent_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        """
        if not self.urfa_call(0x70000045):
            raise Exception("Fail of urfa_call(0x70000045) [rpcf_dealer_get_dialup_service]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['sid'] = self.pck.get_data(U_TP_I)
        if ret['sid']  ==  0:
            ret['error'] = dict({11:"service not found or you dont have enough privileges"})
        ret['service_name'] = self.pck.get_data(U_TP_S)
        ret['comment'] = self.pck.get_data(U_TP_S)
        ret['link_by_default'] = self.pck.get_data(U_TP_I)
        ret['is_dynamic'] = self.pck.get_data(U_TP_I)
        ret['cost'] = self.pck.get_data(U_TP_D)
        ret['deprecated'] = self.pck.get_data(U_TP_I)
        ret['discount_method'] = self.pck.get_data(U_TP_I)
        ret['start_date'] = self.pck.get_data(U_TP_I)
        ret['expire_date'] = self.pck.get_data(U_TP_I)
        ret['pool_name'] = self.pck.get_data(U_TP_S)
        ret['max_timeout'] = self.pck.get_data(U_TP_I)
        ret['null_service_prepaid'] = self.pck.get_data(U_TP_I)
        ret['radius_sessions_limit'] = self.pck.get_data(U_TP_I)
        ret['login_prefix'] = self.pck.get_data(U_TP_S)
        ret['cost_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['cost_size']): 
            self.pck.recv(self.sck)
            ret['tr_name'][i] = self.pck.get_data(U_TP_S)
            ret['param'][i] = self.pck.get_data(U_TP_D)
            ret['id'][i] = self.pck.get_data(U_TP_I)
        self.pck.recv(self.sck)
        ret['is_parent_id'] = self.pck.get_data(U_TP_I)
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        ret['parent_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_iptraffic_service(self, params):
        """ description
        @params: 
        :(s)  service_id :	(i)  - 
        @returns: 
        :(s)  sid :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  is_dynamic :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  deprecated :	(i)  - 
        :(s)  discount_method :	(i)  - 
        :(s)  start_date :	(i)  - 
        :(s)  expire_date :	(i)  - 
        :(s)  null_service_prepaid :	(i)  - 
        :(s)  borders_count :	(i)  - 
        :(s)    tclass :	(i)  - 
        :(s)      borders_size :	(l)  - 
        :(s)        border_id :	(l)  - 
        :(s)        border_cost :	(d)  - 
        :(s)  prepaid_count :	(i)  - 
        :(s)    tclass :	(i)  - 
        :(s)      prepaid_amount :	(l)  - 
        :(s)      prepaid_max :	(l)  - 
        :(s)  tclass_id2group_size :	(i)  - 
        :(s)    tclass_id :	(i)  - 
        :(s)    tclass_group_id :	(i)  - 
        :(s)  service_data_parent_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        """
        if not self.urfa_call(0x70000025):
            raise Exception("Fail of urfa_call(0x70000025) [rpcf_dealer_get_iptraffic_service]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['sid'] = self.pck.get_data(U_TP_I)
        if ret['sid']  ==  0:
            ret['error'] = dict({11:"service not found or you dont have enough privileges"})
        ret['service_name'] = self.pck.get_data(U_TP_S)
        ret['comment'] = self.pck.get_data(U_TP_S)
        ret['link_by_default'] = self.pck.get_data(U_TP_I)
        ret['is_dynamic'] = self.pck.get_data(U_TP_I)
        ret['cost'] = self.pck.get_data(U_TP_D)
        ret['deprecated'] = self.pck.get_data(U_TP_I)
        ret['discount_method'] = self.pck.get_data(U_TP_I)
        ret['start_date'] = self.pck.get_data(U_TP_I)
        ret['expire_date'] = self.pck.get_data(U_TP_I)
        ret['null_service_prepaid'] = self.pck.get_data(U_TP_I)
        ret['borders_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['borders_count']): 
            self.pck.recv(self.sck)
            ret['tclass'][i] = self.pck.get_data(U_TP_I)
            ret['tclass_tmp']=ret['tclass'][i][i]
            if ret['tclass_tmp']  !=  -1:
                ret['borders_size'] = self.pck.get_data(U_TP_L)
                ret['borders_size_array'][i]=ret['borders_size']
                for j in range(ret['borders_size']): 
                    self.pck.recv(self.sck)
                    if not i in ret['border_id']:ret['border_id'][i] = dict()
                    ret['border_id'][i][j] = self.pck.get_data(U_TP_L)
                    if not i in ret['border_cost']:ret['border_cost'][i] = dict()
                    ret['border_cost'][i][j] = self.pck.get_data(U_TP_D)
            if ret['tclass_tmp']  ==  -1:
                ret['borders_size_array'][borders_size]="0"
        self.pck.recv(self.sck)
        ret['prepaid_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['prepaid_count']): 
            self.pck.recv(self.sck)
            ret['tclass'][i] = self.pck.get_data(U_TP_I)
            ret['tclass_tmp']=ret['tclass'][i][i]
            if ret['tclass_tmp']  !=  -1:
                ret['prepaid_amount'][i] = self.pck.get_data(U_TP_L)
                ret['prepaid_max'][i] = self.pck.get_data(U_TP_L)
            if ret['tclass_tmp']  ==  -1:
                ret['prepaid_amount'][i]="0"
                ret['prepaid_max'][i]="0"
        self.pck.recv(self.sck)
        ret['tclass_id2group_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['tclass_id2group_size']): 
            self.pck.recv(self.sck)
            ret['tclass_id'][i] = self.pck.get_data(U_TP_I)
            ret['tclass_group_id'][i] = self.pck.get_data(U_TP_I)
        self.pck.recv(self.sck)
        ret['service_data_parent_id'] = self.pck.get_data(U_TP_I)
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        ret['parent_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_once_service(self, params):
        """ description
        @params: 
        :(s)  service_id :	(i)  - 
        @returns: 
        :(s)  sid :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  drop_from_group :	(i)  - 
        :(s)  is_parent_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        """
        if not self.urfa_call(0x70000026):
            raise Exception("Fail of urfa_call(0x70000026) [rpcf_dealer_get_once_service]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['sid'] = self.pck.get_data(U_TP_I)
        if ret['sid']  ==  0:
            ret['error'] = dict({11:"service not found or you dont have enough privileges"})
        ret['service_name'] = self.pck.get_data(U_TP_S)
        ret['comment'] = self.pck.get_data(U_TP_S)
        ret['link_by_default'] = self.pck.get_data(U_TP_I)
        ret['cost'] = self.pck.get_data(U_TP_D)
        ret['drop_from_group'] = self.pck.get_data(U_TP_I)
        ret['is_parent_id'] = self.pck.get_data(U_TP_I)
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        ret['parent_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_periodic_service(self, params):
        """ description
        @params: 
        :(s)  service_id :	(i)  - 
        @returns: 
        :(s)  sid :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  deprecated :	(i)  - 
        :(s)  discount_method :	(i)  - 
        :(s)  start_date :	(i)  - 
        :(s)  expire_date :	(i)  - 
        :(s)  param :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        """
        if not self.urfa_call(0x70000027):
            raise Exception("Fail of urfa_call(0x70000027) [rpcf_dealer_get_periodic_service]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['sid'] = self.pck.get_data(U_TP_I)
        if ret['sid']  ==  0:
            ret['error'] = dict({11:"service not found or you dont have enough privileges"})
        ret['service_name'] = self.pck.get_data(U_TP_S)
        ret['comment'] = self.pck.get_data(U_TP_S)
        ret['link_by_default'] = self.pck.get_data(U_TP_I)
        ret['cost'] = self.pck.get_data(U_TP_D)
        ret['deprecated'] = self.pck.get_data(U_TP_I)
        ret['discount_method'] = self.pck.get_data(U_TP_I)
        ret['start_date'] = self.pck.get_data(U_TP_I)
        ret['expire_date'] = self.pck.get_data(U_TP_I)
        ret['param'] = self.pck.get_data(U_TP_I)
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        ret['parent_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_telephony_service(self, params):
        """ description
        @params: 
        :(s)  service_id :	(i)  - 
        @returns: 
        :(s)  sid :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  discount_method :	(i)  - 
        :(s)  start_date :	(i)  - 
        :(s)  expire_date :	(i)  - 
        :(s)  radius_sessions_limit :	(i)  - 
        :(s)  count :	(i)  - 
        :(s)    directions :	(i)  - 
        :(s)    borders_count :	(i)  - 
        :(s)      tarif_quantity :	(l)  - 
        :(s)      cost :	(d)  - 
        :(s)    timerange_count :	(i)  - 
        :(s)      timerange_id :	(i)  - 
        :(s)      cost :	(d)  - 
        :(s)  free_time :	(l)  - 
        :(s)  first_interval :	(l)  - 
        :(s)  first_interval_around :	(l)  - 
        :(s)  incremental_interval :	(l)  - 
        :(s)  unit_size :	(l)  - 
        :(s)  fixed_call_cost :	(d)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        """
        if not self.urfa_call(0x70000028):
            raise Exception("Fail of urfa_call(0x70000028) [rpcf_dealer_get_telephony_service]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['sid'] = self.pck.get_data(U_TP_I)
        if ret['sid']  ==  0:
            ret['error'] = dict({11:"service not found or you dont have enough privileges"})
        ret['service_name'] = self.pck.get_data(U_TP_S)
        ret['comment'] = self.pck.get_data(U_TP_S)
        ret['link_by_default'] = self.pck.get_data(U_TP_I)
        ret['cost'] = self.pck.get_data(U_TP_D)
        ret['discount_method'] = self.pck.get_data(U_TP_I)
        ret['start_date'] = self.pck.get_data(U_TP_I)
        ret['expire_date'] = self.pck.get_data(U_TP_I)
        ret['radius_sessions_limit'] = self.pck.get_data(U_TP_I)
        ret['count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['count']): 
            self.pck.recv(self.sck)
            ret['directions'][i] = self.pck.get_data(U_TP_I)
            ret['borders_count'] = self.pck.get_data(U_TP_I)
            ret['borders_count_array'][i]=ret['borders_count']
            for j in range(ret['borders_count']): 
                self.pck.recv(self.sck)
                if not i in ret['tarif_quantity']:ret['tarif_quantity'][i] = dict()
                ret['tarif_quantity'][i][j] = self.pck.get_data(U_TP_L)
                if not i in ret['cost']:ret['cost'][i] = dict()
                ret['cost'][i][j] = self.pck.get_data(U_TP_D)
            self.pck.recv(self.sck)
            ret['timerange_count'] = self.pck.get_data(U_TP_I)
            ret['timerange_count_array'][i]=ret['timerange_count']
            for j in range(ret['timerange_count']): 
                self.pck.recv(self.sck)
                if not i in ret['timerange_id']:ret['timerange_id'][i] = dict()
                ret['timerange_id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['cost']:ret['cost'][i] = dict()
                ret['cost'][i][j] = self.pck.get_data(U_TP_D)
        self.pck.recv(self.sck)
        ret['free_time'] = self.pck.get_data(U_TP_L)
        ret['first_interval'] = self.pck.get_data(U_TP_L)
        ret['first_interval_around'] = self.pck.get_data(U_TP_L)
        ret['incremental_interval'] = self.pck.get_data(U_TP_L)
        ret['unit_size'] = self.pck.get_data(U_TP_L)
        ret['fixed_call_cost'] = self.pck.get_data(U_TP_D)
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        ret['parent_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_all_services_for_user(self, params):
        """ description
        @params: 
        :(s)  account_id :	(i)  - 
        @returns: 
        :(s)  slink_id_count :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        :(s)    service_id :	(i)  - 
        :(s)      service_type_array :	(i)  - 
        :(s)      service_name_array :	(s)  - 
        :(s)      tariff_name_array :	(s)  - 
        :(s)      service_cost_array :	(d)  - 
        :(s)      slink_id_array :	(i)  - 
        :(s)      discount_period_id_array :	(i)  - 
        """
        if not self.urfa_call(0x70000029):
            raise Exception("Fail of urfa_call(0x70000029) [rpcf_dealer_get_all_services_for_user]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['slink_id_count'] = self.pck.get_data(U_TP_I)
        if ret['slink_id_count']  ==  0:
            ret['error'] = dict({11:"services not found or you dont have enough privileges"})
        for i in range(ret['slink_id_count']): 
            self.pck.recv(self.sck)
            ret['service_id'] = self.pck.get_data(U_TP_I)
            if ret['service_id']  !=  -1:
                ret['service_id_array'][i]=ret['service_id']
                ret['service_type_array'][i] = self.pck.get_data(U_TP_I)
                ret['service_name_array'][i] = self.pck.get_data(U_TP_S)
                ret['tariff_name_array'][i] = self.pck.get_data(U_TP_S)
                ret['service_cost_array'][i] = self.pck.get_data(U_TP_D)
                ret['slink_id_array'][i] = self.pck.get_data(U_TP_I)
                ret['discount_period_id_array'][i] = self.pck.get_data(U_TP_I)
            if ret['service_id']  ==  -1:
                ret['service_id_array'][i]="-1"
                ret['service_type_array'][i]="-1"
                ret['service_name_array'][i]=""
                ret['tariff_name_array'][i]=""
                ret['service_cost_array'][i]="-1"
                ret['slink_id_array'][i]="-1"
                ret['discount_period_id_array'][i]="-1"
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_add_service_to_user(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  account_id :	(i)  - 
        :(s)  service_id :	(i)  - 
        :(s)  service_type :	(i)  - 
        :(s)  unused :	(s)  - 
        :(s)  tariff_link_id :	(i) = _def_  - 
        :(s)    discount_date :	(i) = _def_  - 
        :(s)    cost_coef :	(d) = _def_  - 
        :(s)    discount_period_id :	(i)  - 
        :(s)    start_date :	(i) = _def_  - 
        :(s)    expire_date :	(i) = _def_  - 
        :(s)    policy_id :	(i)  - 
        :(s)    unabon :	(i) = _def_  - 
        :(s)    cost_coef :	(d) = _def_  - 
        :(s)    discount_period_id :	(i)  - 
        :(s)    start_date :	(i) = _def_  - 
        :(s)    expire_date :	(i) = _def_  - 
        :(s)    policy_id :	(i)  - 
        :(s)    unabon :	(i) = _def_  - 
        :(s)    cost_coef :	(d) = _def_  - 
        :(s)    unprepay :	(i) = _def_  - 
        :(s)    ip_groups_count :	(i) = _def_  - 
        :(s)      ip_address :	(i)  - 
        :(s)      mask :	(i)  - 
        :(s)      mac :	(s)  - 
        :(s)      iptraffic_login :	(s)  - 
        :(s)      iptraffic_allowed_cid :	(s)  - 
        :(s)      iptraffic_password :	(s)  - 
        :(s)      pool_name :	(s)  - 
        :(s)      ip_not_vpn :	(i) = _def_  - 
        :(s)      dont_use_fw :	(i) = _def_  - 
        :(s)      router_id :	(i) = _def_  - 
        :(s)      switch_id :	(i) = _def_  - 
        :(s)      port_id :	(i) = _def_  - 
        :(s)      vlan_id :	(i) = _def_  - 
        :(s)      pool_id :	(i) = _def_  - 
        :(s)    quotas_count :	(i) = _def_  - 
        :(s)      tclass_id :	(i)  - 
        :(s)      quota :	(l)  - 
        :(s)    discount_period_id :	(i)  - 
        :(s)    start_date :	(i) = _def_  - 
        :(s)    expire_date :	(i) = _def_  - 
        :(s)    policy_id :	(i)  - 
        :(s)    unabon :	(i) = _def_  - 
        :(s)    cost_coef :	(d) = _def_  - 
        :(s)    hotspot_login :	(s)  - 
        :(s)    hotspot_password :	(s)  - 
        :(s)    unabon :	(i) = _def_  - 
        :(s)    discount_period_id :	(i)  - 
        :(s)    start_date :	(i) = _def_  - 
        :(s)    expire_date :	(i) = _def_  - 
        :(s)    policy_id :	(i)  - 
        :(s)    unabon :	(i) = _def_  - 
        :(s)    cost_coef :	(d) = _def_  - 
        :(s)    dialup_login :	(s)  - 
        :(s)    dialup_password :	(s)  - 
        :(s)    dialup_allowed_cid :	(s)  - 
        :(s)    dialup_allowed_csid :	(s)  - 
        :(s)    callback_enabled :	(i) = _def_  - 
        :(s)    unabon :	(i) = _def_  - 
        :(s)    discount_period_id :	(i)  - 
        :(s)    start_date :	(i) = _def_  - 
        :(s)    expire_date :	(i) = _def_  - 
        :(s)    policy_id :	(i)  - 
        :(s)    unabon :	(i) = _def_  - 
        :(s)    cost_coef :	(d) = _def_  - 
        :(s)    unabon :	(i) = _def_  - 
        :(s)    tel_numbers_count :	(i) = _def_  - 
        :(s)      tel_slink_id :	(i) = _def_  - 
        :(s)      tel_number :	(s)  - 
        :(s)      tel_login :	(s)  - 
        :(s)      tel_password :	(s)  - 
        :(s)      tel_allowed_cid :	(s)  - 
        @returns: 
        :(s)  slink_id :	(i)  - 
        """
        if not self.urfa_call(0x7000006b):
            raise Exception("Fail of urfa_call(0x7000006b) [rpcf_dealer_add_service_to_user]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.add_data(params['service_type'], U_TP_I)
        self.pck.add_data(params['unused'], U_TP_S)
        if 'tariff_link_id' not in params: params['tariff_link_id'] = 0
        self.pck.add_data(params['tariff_link_id'], U_TP_I)
        if params['service_type']  ==  1:
            if 'discount_date' not in params: params['discount_date'] = now()
            self.pck.add_data(params['discount_date'], U_TP_I)
            if 'cost_coef' not in params: params['cost_coef'] = 1.0
            self.pck.add_data(params['cost_coef'], U_TP_D)
        if params['service_type']  ==  2:
            self.pck.add_data(params['discount_period_id'], U_TP_I)
            if 'start_date' not in params: params['start_date'] = now()
            self.pck.add_data(params['start_date'], U_TP_I)
            if 'expire_date' not in params: params['expire_date'] = max_time()
            self.pck.add_data(params['expire_date'], U_TP_I)
            self.pck.add_data(params['policy_id'], U_TP_I)
            if 'unabon' not in params: params['unabon'] = 0
            self.pck.add_data(params['unabon'], U_TP_I)
            if 'cost_coef' not in params: params['cost_coef'] = 1
            self.pck.add_data(params['cost_coef'], U_TP_D)
        if params['service_type']  ==  3:
            self.pck.add_data(params['discount_period_id'], U_TP_I)
            if 'start_date' not in params: params['start_date'] = now()
            self.pck.add_data(params['start_date'], U_TP_I)
            if 'expire_date' not in params: params['expire_date'] = max_time()
            self.pck.add_data(params['expire_date'], U_TP_I)
            self.pck.add_data(params['policy_id'], U_TP_I)
            if 'unabon' not in params: params['unabon'] = 0
            self.pck.add_data(params['unabon'], U_TP_I)
            if 'cost_coef' not in params: params['cost_coef'] = 1
            self.pck.add_data(params['cost_coef'], U_TP_D)
            if 'unprepay' not in params: params['unprepay'] = 0
            self.pck.add_data(params['unprepay'], U_TP_I)
            if 'ip_groups_count' not in params: params['ip_groups_count'] = len(params['ip_address'])
            self.pck.add_data(params['ip_groups_count'], U_TP_I)
            for i in range(len(params['ip_address'])):
                self.pck.add_data(params['ip_address'][i], U_TP_IP)
                self.pck.add_data(params['mask'][i], U_TP_I)
                self.pck.add_data(params['mac'][i], U_TP_S)
                self.pck.add_data(params['iptraffic_login'][i], U_TP_S)
                self.pck.add_data(params['iptraffic_allowed_cid'][i], U_TP_S)
                self.pck.add_data(params['iptraffic_password'][i], U_TP_S)
                self.pck.add_data(params['pool_name'][i], U_TP_S)
                if 'ip_not_vpn' not in params: params['ip_not_vpn'] = 0
                self.pck.add_data(params['ip_not_vpn'][i], U_TP_I)
                if 'dont_use_fw' not in params: params['dont_use_fw'] = 0
                self.pck.add_data(params['dont_use_fw'][i], U_TP_I)
                if 'router_id' not in params: params['router_id'] = 0
                self.pck.add_data(params['router_id'][i], U_TP_I)
                if 'switch_id' not in params: params['switch_id'] = 0
                self.pck.add_data(params['switch_id'][i], U_TP_I)
                if 'port_id' not in params: params['port_id'] = 0
                self.pck.add_data(params['port_id'][i], U_TP_I)
                if 'vlan_id' not in params: params['vlan_id'] = 0
                self.pck.add_data(params['vlan_id'][i], U_TP_I)
                if 'pool_id' not in params: params['pool_id'] = 0
                self.pck.add_data(params['pool_id'][i], U_TP_I)
            if 'quotas_count' not in params: params['quotas_count'] = len(params['quota'])
            self.pck.add_data(params['quotas_count'], U_TP_I)
            for i in range(len(params['quota'])):
                self.pck.add_data(params['tclass_id'][i], U_TP_I)
                self.pck.add_data(params['quota'][i], U_TP_L)
        if params['service_type']  ==  4:
            self.pck.add_data(params['discount_period_id'], U_TP_I)
            if 'start_date' not in params: params['start_date'] = now()
            self.pck.add_data(params['start_date'], U_TP_I)
            if 'expire_date' not in params: params['expire_date'] = max_time()
            self.pck.add_data(params['expire_date'], U_TP_I)
            self.pck.add_data(params['policy_id'], U_TP_I)
            if 'unabon' not in params: params['unabon'] = 0
            self.pck.add_data(params['unabon'], U_TP_I)
            if 'cost_coef' not in params: params['cost_coef'] = 1
            self.pck.add_data(params['cost_coef'], U_TP_D)
            self.pck.add_data(params['hotspot_login'], U_TP_S)
            self.pck.add_data(params['hotspot_password'], U_TP_S)
            if 'unabon' not in params: params['unabon'] = 0
            self.pck.add_data(params['unabon'], U_TP_I)
        if params['service_type']  ==  5:
            self.pck.add_data(params['discount_period_id'], U_TP_I)
            if 'start_date' not in params: params['start_date'] = now()
            self.pck.add_data(params['start_date'], U_TP_I)
            if 'expire_date' not in params: params['expire_date'] = max_time()
            self.pck.add_data(params['expire_date'], U_TP_I)
            self.pck.add_data(params['policy_id'], U_TP_I)
            if 'unabon' not in params: params['unabon'] = 0
            self.pck.add_data(params['unabon'], U_TP_I)
            if 'cost_coef' not in params: params['cost_coef'] = 1
            self.pck.add_data(params['cost_coef'], U_TP_D)
            self.pck.add_data(params['dialup_login'], U_TP_S)
            self.pck.add_data(params['dialup_password'], U_TP_S)
            self.pck.add_data(params['dialup_allowed_cid'], U_TP_S)
            self.pck.add_data(params['dialup_allowed_csid'], U_TP_S)
            if 'callback_enabled' not in params: params['callback_enabled'] = 3
            self.pck.add_data(params['callback_enabled'], U_TP_I)
            if 'unabon' not in params: params['unabon'] = 0
            self.pck.add_data(params['unabon'], U_TP_I)
        if params['service_type']  ==  6:
            self.pck.add_data(params['discount_period_id'], U_TP_I)
            if 'start_date' not in params: params['start_date'] = now()
            self.pck.add_data(params['start_date'], U_TP_I)
            if 'expire_date' not in params: params['expire_date'] = max_time()
            self.pck.add_data(params['expire_date'], U_TP_I)
            self.pck.add_data(params['policy_id'], U_TP_I)
            if 'unabon' not in params: params['unabon'] = 0
            self.pck.add_data(params['unabon'], U_TP_I)
            if 'cost_coef' not in params: params['cost_coef'] = 1
            self.pck.add_data(params['cost_coef'], U_TP_D)
            if 'unabon' not in params: params['unabon'] = 0
            self.pck.add_data(params['unabon'], U_TP_I)
            if 'tel_numbers_count' not in params: params['tel_numbers_count'] = len(params['tel_number'])
            self.pck.add_data(params['tel_numbers_count'], U_TP_I)
            for i in range(len(params['tel_number'])):
                if 'tel_slink_id' not in params: params['tel_slink_id'] = 0
                self.pck.add_data(params['tel_slink_id'], U_TP_I)
                self.pck.add_data(params['tel_number'][i], U_TP_S)
                self.pck.add_data(params['tel_login'][i], U_TP_S)
                self.pck.add_data(params['tel_password'][i], U_TP_S)
                self.pck.add_data(params['tel_allowed_cid'][i], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['slink_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_edit_service_for_user(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  account_id :	(i) = _def_  - 
        :(s)  service_id :	(i)  - 
        :(s)  service_type :	(i)  - 
        :(s)  tariff_link_id :	(i)  - 
        :(s)    slink_id :	(i)  - 
        :(s)    discount_date :	(i)  - 
        :(s)    cost_coef :	(d) = _def_  - 
        :(s)    slink_id :	(i)  - 
        :(s)    is_blocked :	(i)  - 
        :(s)    discount_period_id :	(i)  - 
        :(s)    start_date :	(i)  - 
        :(s)    expire_date :	(i)  - 
        :(s)    policy_id :	(i)  - 
        :(s)    cost_coef :	(d) = _def_  - 
        :(s)    slink_id :	(i)  - 
        :(s)    is_blocked :	(i)  - 
        :(s)    discount_period_id :	(i)  - 
        :(s)    start_date :	(i)  - 
        :(s)    expire_date :	(i)  - 
        :(s)    policy_id :	(i)  - 
        :(s)    cost_coef :	(d) = _def_  - 
        :(s)    ip_groups_count :	(i) = _def_  - 
        :(s)      ip_address :	(i)  - 
        :(s)      mask :	(i)  - 
        :(s)      mac :	(s)  - 
        :(s)      iptraffic_login :	(s)  - 
        :(s)      iptraffic_allowed_cid :	(s)  - 
        :(s)      iptraffic_password :	(s)  - 
        :(s)      pool_name :	(s)  - 
        :(s)      ip_not_vpn :	(i)  - 
        :(s)      dont_use_fw :	(i)  - 
        :(s)      router_id :	(i)  - 
        :(s)      switch_id :	(i)  - 
        :(s)      port_id :	(i)  - 
        :(s)      vlan_id :	(i)  - 
        :(s)      pool_id :	(i)  - 
        :(s)    quotas_count :	(i) = _def_  - 
        :(s)      tclass_id :	(i)  - 
        :(s)      quota :	(l)  - 
        :(s)    slink_id :	(i)  - 
        :(s)    is_blocked :	(i)  - 
        :(s)    discount_period_id :	(i)  - 
        :(s)    start_date :	(i)  - 
        :(s)    expire_date :	(i)  - 
        :(s)    policy_id :	(i)  - 
        :(s)    cost_coef :	(d) = _def_  - 
        :(s)    hotspot_login :	(s)  - 
        :(s)    hotspot_password :	(s)  - 
        :(s)    slink_id :	(i)  - 
        :(s)    is_blocked :	(i)  - 
        :(s)    discount_period_id :	(i)  - 
        :(s)    start_date :	(i)  - 
        :(s)    expire_date :	(i)  - 
        :(s)    policy_id :	(i)  - 
        :(s)    cost_coef :	(d) = _def_  - 
        :(s)    dialup_login :	(s)  - 
        :(s)    dialup_password :	(s)  - 
        :(s)    dialup_allowed_cid :	(s)  - 
        :(s)    dialup_allowed_csid :	(s)  - 
        :(s)    callback_enabled :	(i)  - 
        :(s)    slink_id :	(i)  - 
        :(s)    is_blocked :	(i)  - 
        :(s)    discount_period_id :	(i)  - 
        :(s)    start_date :	(i)  - 
        :(s)    expire_date :	(i)  - 
        :(s)    policy_id :	(i)  - 
        :(s)    cost_coef :	(d) = _def_  - 
        :(s)    tel_numbers_count :	(i) = _def_  - 
        :(s)      tel_slink_id :	(i) = _def_  - 
        :(s)      tel_number :	(s)  - 
        :(s)      tel_login :	(s)  - 
        :(s)      tel_password :	(s)  - 
        :(s)      tel_allowed_cid :	(s)  - 
        @returns: 
        :(s)  slink_id :	(i)  - 
        """
        if not self.urfa_call(0x7000006c):
            raise Exception("Fail of urfa_call(0x7000006c) [rpcf_dealer_edit_service_for_user]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.add_data(params['service_type'], U_TP_I)
        self.pck.add_data(params['tariff_link_id'], U_TP_I)
        if params['service_type']  ==  1:
            self.pck.add_data(params['slink_id'], U_TP_I)
            self.pck.add_data(params['discount_date'], U_TP_I)
            if 'cost_coef' not in params: params['cost_coef'] = 1.0
            self.pck.add_data(params['cost_coef'], U_TP_D)
        if params['service_type']  ==  2:
            self.pck.add_data(params['slink_id'], U_TP_I)
            self.pck.add_data(params['is_blocked'], U_TP_I)
            self.pck.add_data(params['discount_period_id'], U_TP_I)
            self.pck.add_data(params['start_date'], U_TP_I)
            self.pck.add_data(params['expire_date'], U_TP_I)
            self.pck.add_data(params['policy_id'], U_TP_I)
            if 'cost_coef' not in params: params['cost_coef'] = 1
            self.pck.add_data(params['cost_coef'], U_TP_D)
        if params['service_type']  ==  3:
            self.pck.add_data(params['slink_id'], U_TP_I)
            self.pck.add_data(params['is_blocked'], U_TP_I)
            self.pck.add_data(params['discount_period_id'], U_TP_I)
            self.pck.add_data(params['start_date'], U_TP_I)
            self.pck.add_data(params['expire_date'], U_TP_I)
            self.pck.add_data(params['policy_id'], U_TP_I)
            if 'cost_coef' not in params: params['cost_coef'] = 1
            self.pck.add_data(params['cost_coef'], U_TP_D)
            if 'ip_groups_count' not in params: params['ip_groups_count'] = len(params['ip_address'])
            self.pck.add_data(params['ip_groups_count'], U_TP_I)
            for i in range(len(params['ip_address'])):
                self.pck.add_data(params['ip_address'][i], U_TP_IP)
                self.pck.add_data(params['mask'][i], U_TP_I)
                self.pck.add_data(params['mac'][i], U_TP_S)
                self.pck.add_data(params['iptraffic_login'][i], U_TP_S)
                self.pck.add_data(params['iptraffic_allowed_cid'][i], U_TP_S)
                self.pck.add_data(params['iptraffic_password'][i], U_TP_S)
                self.pck.add_data(params['pool_name'][i], U_TP_S)
                self.pck.add_data(params['ip_not_vpn'][i], U_TP_I)
                self.pck.add_data(params['dont_use_fw'][i], U_TP_I)
                self.pck.add_data(params['router_id'][i], U_TP_I)
                self.pck.add_data(params['switch_id'][i], U_TP_I)
                self.pck.add_data(params['port_id'][i], U_TP_I)
                self.pck.add_data(params['vlan_id'][i], U_TP_I)
                self.pck.add_data(params['pool_id'][i], U_TP_I)
            if 'quotas_count' not in params: params['quotas_count'] = len(params['quota'])
            self.pck.add_data(params['quotas_count'], U_TP_I)
            for i in range(len(params['quota'])):
                self.pck.add_data(params['tclass_id'][i], U_TP_I)
                self.pck.add_data(params['quota'][i], U_TP_L)
        if params['service_type']  ==  4:
            self.pck.add_data(params['slink_id'], U_TP_I)
            self.pck.add_data(params['is_blocked'], U_TP_I)
            self.pck.add_data(params['discount_period_id'], U_TP_I)
            self.pck.add_data(params['start_date'], U_TP_I)
            self.pck.add_data(params['expire_date'], U_TP_I)
            self.pck.add_data(params['policy_id'], U_TP_I)
            if 'cost_coef' not in params: params['cost_coef'] = 1
            self.pck.add_data(params['cost_coef'], U_TP_D)
            self.pck.add_data(params['hotspot_login'], U_TP_S)
            self.pck.add_data(params['hotspot_password'], U_TP_S)
        if params['service_type']  ==  5:
            self.pck.add_data(params['slink_id'], U_TP_I)
            self.pck.add_data(params['is_blocked'], U_TP_I)
            self.pck.add_data(params['discount_period_id'], U_TP_I)
            self.pck.add_data(params['start_date'], U_TP_I)
            self.pck.add_data(params['expire_date'], U_TP_I)
            self.pck.add_data(params['policy_id'], U_TP_I)
            if 'cost_coef' not in params: params['cost_coef'] = 1
            self.pck.add_data(params['cost_coef'], U_TP_D)
            self.pck.add_data(params['dialup_login'], U_TP_S)
            self.pck.add_data(params['dialup_password'], U_TP_S)
            self.pck.add_data(params['dialup_allowed_cid'], U_TP_S)
            self.pck.add_data(params['dialup_allowed_csid'], U_TP_S)
            self.pck.add_data(params['callback_enabled'], U_TP_I)
        if params['service_type']  ==  6:
            self.pck.add_data(params['slink_id'], U_TP_I)
            self.pck.add_data(params['is_blocked'], U_TP_I)
            self.pck.add_data(params['discount_period_id'], U_TP_I)
            self.pck.add_data(params['start_date'], U_TP_I)
            self.pck.add_data(params['expire_date'], U_TP_I)
            self.pck.add_data(params['policy_id'], U_TP_I)
            if 'cost_coef' not in params: params['cost_coef'] = 1
            self.pck.add_data(params['cost_coef'], U_TP_D)
            if 'tel_numbers_count' not in params: params['tel_numbers_count'] = len(params['tel_number'])
            self.pck.add_data(params['tel_numbers_count'], U_TP_I)
            for i in range(len(params['tel_number'])):
                if 'tel_slink_id' not in params: params['tel_slink_id'] = 0
                self.pck.add_data(params['tel_slink_id'][i], U_TP_I)
                self.pck.add_data(params['tel_number'][i], U_TP_S)
                self.pck.add_data(params['tel_login'][i], U_TP_S)
                self.pck.add_data(params['tel_password'][i], U_TP_S)
                self.pck.add_data(params['tel_allowed_cid'][i], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['slink_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_is_service_used(self, params):
        """ description
        @params: 
        :(s)  service_id :	(i)  - 
        @returns: 
        :(s)  links_count :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        """
        if not self.urfa_call(0x7000002c):
            raise Exception("Fail of urfa_call(0x7000002c) [rpcf_dealer_is_service_used]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['links_count'] = self.pck.get_data(U_TP_I)
        if ret['links_count']  ==  0:
            ret['error'] = dict({11:"service not found or not used or you dont have enough privileges"})
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_tclasses(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  tclass_list_size :	(i)  - 
        :(s)    tclass_id :	(i)  - 
        :(s)    tclass_name :	(s)  - 
        :(s)    graph_color :	(i)  - 
        :(s)    is_display :	(i)  - 
        :(s)    is_fill :	(i)  - 
        """
        if not self.urfa_call(0x7000002d):
            raise Exception("Fail of urfa_call(0x7000002d) [rpcf_dealer_get_tclasses]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['tclass_list_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['tclass_list_size']): 
            self.pck.recv(self.sck)
            ret['tclass_id'][i] = self.pck.get_data(U_TP_I)
            ret['tclass_name'][i] = self.pck.get_data(U_TP_S)
            ret['graph_color'][i] = self.pck.get_data(U_TP_I)
            ret['is_display'][i] = self.pck.get_data(U_TP_I)
            ret['is_fill'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_hotspot_service_link(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i)  - 
        @returns: 
        :(s)  sid :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        :(s)  tariff_link_id :	(i)  - 
        :(s)  is_blocked :	(i)  - 
        :(s)  discount_period_id :	(i)  - 
        :(s)  start_date :	(i)  - 
        :(s)  expire_date :	(i)  - 
        :(s)  policy_id :	(i)  - 
        :(s)  cost_coef :	(d)  - 
        :(s)  login :	(s)  - 
        :(s)  password :	(s)  - 
        :(s)  is_unabon_period :	(i)  - 
        :(s)  is_unprepay_period :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        """
        if not self.urfa_call(0x70000061):
            raise Exception("Fail of urfa_call(0x70000061) [rpcf_dealer_get_hotspot_service_link]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['sid'] = self.pck.get_data(U_TP_I)
        if ret['sid']  ==  0:
            ret['error'] = dict({11:"service link not found or you dont have enough privileges"})
        ret['tariff_link_id'] = self.pck.get_data(U_TP_I)
        ret['is_blocked'] = self.pck.get_data(U_TP_I)
        ret['discount_period_id'] = self.pck.get_data(U_TP_I)
        ret['start_date'] = self.pck.get_data(U_TP_I)
        ret['expire_date'] = self.pck.get_data(U_TP_I)
        ret['policy_id'] = self.pck.get_data(U_TP_I)
        ret['cost_coef'] = self.pck.get_data(U_TP_D)
        ret['login'] = self.pck.get_data(U_TP_S)
        ret['password'] = self.pck.get_data(U_TP_S)
        ret['is_unabon_period'] = self.pck.get_data(U_TP_I)
        ret['is_unprepay_period'] = self.pck.get_data(U_TP_I)
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        ret['parent_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_dialup_service_link(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i)  - 
        @returns: 
        :(s)  sid :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        :(s)  tariff_link_id :	(i)  - 
        :(s)  is_blocked :	(i)  - 
        :(s)  discount_period_id :	(i)  - 
        :(s)  start_date :	(i)  - 
        :(s)  expire_date :	(i)  - 
        :(s)  policy_id :	(i)  - 
        :(s)  cost_coef :	(d)  - 
        :(s)  login :	(s)  - 
        :(s)  password :	(s)  - 
        :(s)  allowed_cid :	(s)  - 
        :(s)  allowed_csid :	(s)  - 
        :(s)  callback_enabled :	(i)  - 
        :(s)  is_unabon_period :	(i)  - 
        :(s)  is_unprepay_period :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        """
        if not self.urfa_call(0x70000062):
            raise Exception("Fail of urfa_call(0x70000062) [rpcf_dealer_get_dialup_service_link]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['sid'] = self.pck.get_data(U_TP_I)
        if ret['sid']  ==  0:
            ret['error'] = dict({11:"service link not found or you dont have enough privileges"})
        ret['tariff_link_id'] = self.pck.get_data(U_TP_I)
        ret['is_blocked'] = self.pck.get_data(U_TP_I)
        ret['discount_period_id'] = self.pck.get_data(U_TP_I)
        ret['start_date'] = self.pck.get_data(U_TP_I)
        ret['expire_date'] = self.pck.get_data(U_TP_I)
        ret['policy_id'] = self.pck.get_data(U_TP_I)
        ret['cost_coef'] = self.pck.get_data(U_TP_D)
        ret['login'] = self.pck.get_data(U_TP_S)
        ret['password'] = self.pck.get_data(U_TP_S)
        ret['allowed_cid'] = self.pck.get_data(U_TP_S)
        ret['allowed_csid'] = self.pck.get_data(U_TP_S)
        ret['callback_enabled'] = self.pck.get_data(U_TP_I)
        ret['is_unabon_period'] = self.pck.get_data(U_TP_I)
        ret['is_unprepay_period'] = self.pck.get_data(U_TP_I)
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        ret['parent_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_iptraffic_service_link(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i)  - 
        @returns: 
        :(s)  sid :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        :(s)  tariff_link_id :	(i)  - 
        :(s)  is_blocked :	(i)  - 
        :(s)  discount_period_id :	(i)  - 
        :(s)  start_date :	(i)  - 
        :(s)  expire_date :	(i)  - 
        :(s)  policy_id :	(i)  - 
        :(s)  cost_coef :	(d)  - 
        :(s)  unabon :	(i)  - 
        :(s)  unprepay :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        :(s)  bandwidth_in :	(i)  - 
        :(s)  bandwidth_out :	(i)  - 
        :(s)  ip_groups_count :	(i)  - 
        :(s)    ip_address :	(i)  - 
        :(s)    mask :	(i)  - 
        :(s)    mac :	(s)  - 
        :(s)    iptraffic_login :	(s)  - 
        :(s)    iptraffic_password :	(s)  - 
        :(s)    iptraffic_allowed_cid :	(s)  - 
        :(s)    pool_name :	(s)  - 
        :(s)    ip_not_vpn :	(i)  - 
        :(s)    dont_use_fw :	(i)  - 
        :(s)    is_dynamic :	(i)  - 
        :(s)    router_id :	(i)  - 
        :(s)    switch_id :	(i)  - 
        :(s)    port_id :	(i)  - 
        :(s)    vlan_id :	(i)  - 
        :(s)    pool_id :	(i)  - 
        :(s)  quotas_count :	(i)  - 
        :(s)    tclass_id :	(i)  - 
        :(s)    tclass_name :	(s)  - 
        :(s)    quota :	(l)  - 
        """
        if not self.urfa_call(0x7000006a):
            raise Exception("Fail of urfa_call(0x7000006a) [rpcf_dealer_get_iptraffic_service_link]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['sid'] = self.pck.get_data(U_TP_I)
        if ret['sid']  ==  0:
            ret['error'] = dict({11:"service link not found or you dont have enough privileges"})
        ret['tariff_link_id'] = self.pck.get_data(U_TP_I)
        ret['is_blocked'] = self.pck.get_data(U_TP_I)
        ret['discount_period_id'] = self.pck.get_data(U_TP_I)
        ret['start_date'] = self.pck.get_data(U_TP_I)
        ret['expire_date'] = self.pck.get_data(U_TP_I)
        ret['policy_id'] = self.pck.get_data(U_TP_I)
        ret['cost_coef'] = self.pck.get_data(U_TP_D)
        ret['unabon'] = self.pck.get_data(U_TP_I)
        ret['unprepay'] = self.pck.get_data(U_TP_I)
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        ret['parent_id'] = self.pck.get_data(U_TP_I)
        ret['bandwidth_in'] = self.pck.get_data(U_TP_I)
        ret['bandwidth_out'] = self.pck.get_data(U_TP_I)
        ret['ip_groups_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['ip_groups_count']): 
            self.pck.recv(self.sck)
            ret['ip_address'][i] = self.pck.get_data(U_TP_IP)
            ret['mask'][i] = self.pck.get_data(U_TP_IP)
            ret['mac'][i] = self.pck.get_data(U_TP_S)
            ret['iptraffic_login'][i] = self.pck.get_data(U_TP_S)
            ret['iptraffic_password'][i] = self.pck.get_data(U_TP_S)
            ret['iptraffic_allowed_cid'][i] = self.pck.get_data(U_TP_S)
            ret['pool_name'][i] = self.pck.get_data(U_TP_S)
            ret['ip_not_vpn'][i] = self.pck.get_data(U_TP_I)
            ret['dont_use_fw'][i] = self.pck.get_data(U_TP_I)
            ret['is_dynamic'][i] = self.pck.get_data(U_TP_I)
            ret['router_id'][i] = self.pck.get_data(U_TP_I)
            ret['switch_id'][i] = self.pck.get_data(U_TP_I)
            ret['port_id'][i] = self.pck.get_data(U_TP_I)
            ret['vlan_id'][i] = self.pck.get_data(U_TP_I)
            ret['pool_id'][i] = self.pck.get_data(U_TP_I)
        self.pck.recv(self.sck)
        ret['quotas_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['quotas_count']): 
            self.pck.recv(self.sck)
            ret['tclass_id'][i] = self.pck.get_data(U_TP_I)
            ret['tclass_name'][i] = self.pck.get_data(U_TP_S)
            ret['quota'][i] = self.pck.get_data(U_TP_L)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_once_service_link(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i)  - 
        @returns: 
        :(s)  sid :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        :(s)  discount_date :	(i)  - 
        :(s)  quantity :	(d)  - 
        :(s)  invoice_id :	(i)  - 
        :(s)  cost_coef :	(d) = _def_  - 
        """
        if not self.urfa_call(0x7000001d):
            raise Exception("Fail of urfa_call(0x7000001d) [rpcf_dealer_get_once_service_link]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['sid'] = self.pck.get_data(U_TP_I)
        if ret['sid']  ==  0:
            ret['error'] = dict({11:"service link not found or you dont have enough privileges"})
        ret['discount_date'] = self.pck.get_data(U_TP_I)
        ret['quantity'] = self.pck.get_data(U_TP_D)
        ret['invoice_id'] = self.pck.get_data(U_TP_I)
        if 'cost_coef' not in params: params['cost_coef'] = 1.0
        ret['cost_coef'] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_periodic_service_link(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i)  - 
        @returns: 
        :(s)  sid :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        :(s)  tariff_link_id :	(i)  - 
        :(s)  is_blocked :	(i)  - 
        :(s)  discount_period_id :	(i)  - 
        :(s)  start_date :	(i)  - 
        :(s)  expire_date :	(i)  - 
        :(s)  policy_id :	(i)  - 
        :(s)  cost_coef :	(d)  - 
        :(s)  is_unabon_period :	(i)  - 
        :(s)  is_unprepay_period :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        """
        if not self.urfa_call(0x70000064):
            raise Exception("Fail of urfa_call(0x70000064) [rpcf_dealer_get_periodic_service_link]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['sid'] = self.pck.get_data(U_TP_I)
        if ret['sid']  ==  0:
            ret['error'] = dict({11:"service link not found or you dont have enough privileges"})
        ret['tariff_link_id'] = self.pck.get_data(U_TP_I)
        ret['is_blocked'] = self.pck.get_data(U_TP_I)
        ret['discount_period_id'] = self.pck.get_data(U_TP_I)
        ret['start_date'] = self.pck.get_data(U_TP_I)
        ret['expire_date'] = self.pck.get_data(U_TP_I)
        ret['policy_id'] = self.pck.get_data(U_TP_I)
        ret['cost_coef'] = self.pck.get_data(U_TP_D)
        ret['is_unabon_period'] = self.pck.get_data(U_TP_I)
        ret['is_unprepay_period'] = self.pck.get_data(U_TP_I)
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        ret['parent_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_telephony_service_link(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i)  - 
        @returns: 
        :(s)  sid :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        :(s)  tariff_link_id :	(i)  - 
        :(s)  is_blocked :	(i)  - 
        :(s)  discount_period_id :	(i)  - 
        :(s)  start_date :	(i)  - 
        :(s)  expire_date :	(i)  - 
        :(s)  policy_id :	(i)  - 
        :(s)  cost_coef :	(d)  - 
        :(s)  numbers_size :	(i)  - 
        :(s)    item_id :	(i)  - 
        :(s)    number :	(s)  - 
        :(s)    login :	(s)  - 
        :(s)    password :	(s)  - 
        :(s)    allowed_cid :	(s)  - 
        """
        if not self.urfa_call(0x70000065):
            raise Exception("Fail of urfa_call(0x70000065) [rpcf_dealer_get_telephony_service_link]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['sid'] = self.pck.get_data(U_TP_I)
        if ret['sid']  ==  0:
            ret['error'] = dict({11:"service link not found or you dont have enough privileges"})
        ret['tariff_link_id'] = self.pck.get_data(U_TP_I)
        ret['is_blocked'] = self.pck.get_data(U_TP_I)
        ret['discount_period_id'] = self.pck.get_data(U_TP_I)
        ret['start_date'] = self.pck.get_data(U_TP_I)
        ret['expire_date'] = self.pck.get_data(U_TP_I)
        ret['policy_id'] = self.pck.get_data(U_TP_I)
        ret['cost_coef'] = self.pck.get_data(U_TP_D)
        ret['numbers_size'] = self.pck.get_data(U_TP_I)
        for numbers in range(ret['numbers_size']): 
            self.pck.recv(self.sck)
            ret['item_id'][numbers] = self.pck.get_data(U_TP_I)
            ret['number'][numbers] = self.pck.get_data(U_TP_S)
            ret['login'][numbers] = self.pck.get_data(U_TP_S)
            ret['password'][numbers] = self.pck.get_data(U_TP_S)
            ret['allowed_cid'][numbers] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_delete_service_link(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i)  - 
        @returns: 
        :(s)  error_code :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        """
        if not self.urfa_call(0x70000020):
            raise Exception("Fail of urfa_call(0x70000020) [rpcf_dealer_delete_service_link]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['error_code'] = self.pck.get_data(U_TP_I)
        if ret['error_code']  ==  0:
            ret['error'] = dict({13:"service link not found or you dont have enough privileges"})
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_link_user_tariff(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  account_id :	(i) = _def_  - 
        :(s)  tariff_current :	(i)  - 
        :(s)  tariff_next :	(i) = _def_  - 
        :(s)  discount_period_id :	(i)  - 
        :(s)  tariff_link_id :	(i) = _def_  - 
        :(s)  change_now :	(i)  - 
        @returns: 
        :(s)  tariff_link_id :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        """
        if not self.urfa_call(0x70000069):
            raise Exception("Fail of urfa_call(0x70000069) [rpcf_dealer_link_user_tariff]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['tariff_current'], U_TP_I)
        if 'tariff_next' not in params: params['tariff_next'] = params['tariff_current']
        self.pck.add_data(params['tariff_next'], U_TP_I)
        self.pck.add_data(params['discount_period_id'], U_TP_I)
        if 'tariff_link_id' not in params: params['tariff_link_id'] = 0
        self.pck.add_data(params['tariff_link_id'], U_TP_I)
        self.pck.add_data(params['change_now'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['tariff_link_id'] = self.pck.get_data(U_TP_I)
        if params['tariff_link_id']  ==  0:
            ret['error'] = dict({13:"unable to link user tariff may by you dont have enough privileges"})
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_unlink_user_tariff(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  account_id :	(i) = _def_  - 
        :(s)  tariff_link_id :	(i)  - 
        @returns: 
        :(s)  tariff_link_id :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        """
        if not self.urfa_call(0x7000002f):
            raise Exception("Fail of urfa_call(0x7000002f) [rpcf_dealer_unlink_user_tariff]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['tariff_link_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['tariff_link_id'] = self.pck.get_data(U_TP_I)
        if params['tariff_link_id']  ==  0:
            ret['error'] = dict({13:"unable to unlink user tariff may by you dont have enough privileges"})
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_edit_tariff(self, params):
        """ description
        @params: 
        :(s)  tariff_id :	(i)  - 
        :(s)  name :	(s)  - 
        :(s)  expire_date :	(i)  - 
        :(s)  is_blocked :	(i)  - 
        :(s)  balance_rollover :	(i)  - 
        @returns: 
        :(s)  tp_id :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        """
        if not self.urfa_call(0x70000030):
            raise Exception("Fail of urfa_call(0x70000030) [rpcf_dealer_edit_tariff]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.add_data(params['expire_date'], U_TP_I)
        self.pck.add_data(params['is_blocked'], U_TP_I)
        self.pck.add_data(params['balance_rollover'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['tp_id'] = self.pck.get_data(U_TP_I)
        if ret['tp_id']  ==  0:
            ret['error'] = dict({13:"unable to edit tariff may by you dont have enough privileges"})
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_tariff(self, params):
        """ description
        @params: 
        :(s)  tariff_id :	(i)  - 
        @returns: 
        :(s)  tariff_id :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        :(s)  tariff_name :	(s)  - 
        :(s)  tariff_create_date :	(i)  - 
        :(s)  who_create :	(i)  - 
        :(s)  who_create_login :	(s)  - 
        :(s)  tariff_change_date :	(i)  - 
        :(s)  who_change :	(i)  - 
        :(s)  who_change_login :	(s)  - 
        :(s)  tariff_expire_date :	(i)  - 
        :(s)  tariff_is_blocked :	(i)  - 
        :(s)  tariff_balance_rollover :	(i)  - 
        :(s)  services_count :	(i)  - 
        :(s)    service_id_array :	(i)  - 
        :(s)    service_type_array :	(i)  - 
        :(s)    service_name_array :	(s)  - 
        :(s)    comment_array :	(s)  - 
        :(s)    link_by_default_array :	(i)  - 
        :(s)    is_dynamic_array :	(i)  - 
        """
        if not self.urfa_call(0x70000031):
            raise Exception("Fail of urfa_call(0x70000031) [rpcf_dealer_get_tariff]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        if params['tariff_id']  ==  0:
            ret['error'] = dict({13:"unable to get tariff may by you dont have enough privileges"})
        ret['tariff_name'] = self.pck.get_data(U_TP_S)
        ret['tariff_create_date'] = self.pck.get_data(U_TP_I)
        ret['who_create'] = self.pck.get_data(U_TP_I)
        ret['who_create_login'] = self.pck.get_data(U_TP_S)
        ret['tariff_change_date'] = self.pck.get_data(U_TP_I)
        ret['who_change'] = self.pck.get_data(U_TP_I)
        ret['who_change_login'] = self.pck.get_data(U_TP_S)
        ret['tariff_expire_date'] = self.pck.get_data(U_TP_I)
        ret['tariff_is_blocked'] = self.pck.get_data(U_TP_I)
        ret['tariff_balance_rollover'] = self.pck.get_data(U_TP_I)
        ret['services_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['services_count']): 
            self.pck.recv(self.sck)
            ret['service_id_array'][i] = self.pck.get_data(U_TP_I)
            ret['service_type_array'][i] = self.pck.get_data(U_TP_I)
            ret['service_name_array'][i] = self.pck.get_data(U_TP_S)
            ret['comment_array'][i] = self.pck.get_data(U_TP_S)
            ret['link_by_default_array'][i] = self.pck.get_data(U_TP_I)
            ret['is_dynamic_array'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_tariff_id_by_name(self, params):
        """ description
        @params: 
        :(s)  name :	(s)  - 
        @returns: 
        :(s)  tid :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        """
        if not self.urfa_call(0x70000032):
            raise Exception("Fail of urfa_call(0x70000032) [rpcf_dealer_get_tariff_id_by_name]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['tid'] = self.pck.get_data(U_TP_I)
        if ret['tid']  ==  0:
            ret['error'] = dict({13:"unable to get tariff may by you dont have enough privileges"})
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_tariffs_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  tariffs_count :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    name :	(s)  - 
        :(s)    create_date :	(i)  - 
        :(s)    who_create :	(i)  - 
        :(s)    login :	(s)  - 
        :(s)    change_create :	(i)  - 
        :(s)    who_change :	(i)  - 
        :(s)    login_change :	(s)  - 
        :(s)    expire_date :	(i)  - 
        :(s)    is_blocked :	(i)  - 
        :(s)    balance_rollover :	(i)  - 
        :(s)    comment :	(s)  - 
        """
        if not self.urfa_call(0x7000007a):
            raise Exception("Fail of urfa_call(0x7000007a) [rpcf_dealer_get_tariffs_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['tariffs_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['tariffs_count']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['name'][i] = self.pck.get_data(U_TP_S)
            ret['create_date'][i] = self.pck.get_data(U_TP_I)
            ret['who_create'][i] = self.pck.get_data(U_TP_I)
            ret['login'][i] = self.pck.get_data(U_TP_S)
            ret['change_create'][i] = self.pck.get_data(U_TP_I)
            ret['who_change'][i] = self.pck.get_data(U_TP_I)
            ret['login_change'][i] = self.pck.get_data(U_TP_S)
            ret['expire_date'][i] = self.pck.get_data(U_TP_I)
            ret['is_blocked'][i] = self.pck.get_data(U_TP_I)
            ret['balance_rollover'][i] = self.pck.get_data(U_TP_I)
            ret['comment'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_user_tariffs(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  account_id :	(i) = _def_  - 
        @returns: 
        :(s)  user_tariffs_size :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        :(s)    tariff_current_array :	(i)  - 
        :(s)    tariff_next_array :	(i)  - 
        :(s)    discount_period_id_array :	(i)  - 
        :(s)    tariff_link_id_array :	(i)  - 
        """
        if not self.urfa_call(0x70000034):
            raise Exception("Fail of urfa_call(0x70000034) [rpcf_dealer_get_user_tariffs]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['user_tariffs_size'] = self.pck.get_data(U_TP_I)
        if ret['user_tariffs_size']  ==  0:
            ret['error'] = dict({13:"user has no tariffs or you dont have enough privileges"})
        for i in range(ret['user_tariffs_size']): 
            self.pck.recv(self.sck)
            ret['tariff_current_array'][i] = self.pck.get_data(U_TP_I)
            ret['tariff_next_array'][i] = self.pck.get_data(U_TP_I)
            ret['discount_period_id_array'][i] = self.pck.get_data(U_TP_I)
            ret['tariff_link_id_array'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_add_payment_for_account(self, params):
        """ description
        @params: 
        :(s)  account_id :	(i)  - 
        :(s)  payment :	(d)  - 
        :(s)  currency_id :	(i) = _def_  - 
        :(s)  payment_date :	(i) = _def_  - 
        :(s)  burn_date :	(i) = _def_  - 
        :(s)  payment_method :	(i) = _def_  - 
        :(s)  admin_comment :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  payment_ext_number :	(s)  - 
        :(s)  payment_to_invoice :	(i) = _def_  - 
        :(s)  turn_on_inet :	(i) = _def_  - 
        @returns: 
        :(s)  payment_transaction_id :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        """
        if not self.urfa_call(0x70000016):
            raise Exception("Fail of urfa_call(0x70000016) [rpcf_dealer_add_payment_for_account]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['payment'], U_TP_D)
        if 'currency_id' not in params: params['currency_id'] = 810
        self.pck.add_data(params['currency_id'], U_TP_I)
        if 'payment_date' not in params: params['payment_date'] = now()
        self.pck.add_data(params['payment_date'], U_TP_I)
        if 'burn_date' not in params: params['burn_date'] = 0
        self.pck.add_data(params['burn_date'], U_TP_I)
        if 'payment_method' not in params: params['payment_method'] = 1
        self.pck.add_data(params['payment_method'], U_TP_I)
        self.pck.add_data(params['admin_comment'], U_TP_S)
        self.pck.add_data(params['comment'], U_TP_S)
        self.pck.add_data(params['payment_ext_number'], U_TP_S)
        if 'payment_to_invoice' not in params: params['payment_to_invoice'] = 0
        self.pck.add_data(params['payment_to_invoice'], U_TP_I)
        if 'turn_on_inet' not in params: params['turn_on_inet'] = 1
        self.pck.add_data(params['turn_on_inet'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['payment_transaction_id'] = self.pck.get_data(U_TP_I)
        if ret['payment_transaction_id']  ==  0:
            ret['error'] = dict({13:"payment failed"})
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_add_payment_for_account_notify(self, params):
        """ description
        @params: 
        :(s)  account_id :	(i)  - 
        :(s)  payment_incurrency :	(d)  - 
        :(s)  currency_id :	(i)  - 
        :(s)  actual_date :	(i) = _def_  - 
        :(s)  burn_date :	(i)  - 
        :(s)  method :	(i)  - 
        :(s)  admin_comment :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  payment_ext_number :	(s)  - 
        :(s)  payment_to_invoice :	(i)  - 
        :(s)  turn_on_inet :	(i)  - 
        :(s)  notify :	(i)  - 
        :(s)  hash :	(s)  - 
        @returns: 
        :(s)  payment_transaction_id :	(i)  - 
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        """
        if not self.urfa_call(0x70000017):
            raise Exception("Fail of urfa_call(0x70000017) [rpcf_dealer_add_payment_for_account_notify]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['payment_incurrency'], U_TP_D)
        self.pck.add_data(params['currency_id'], U_TP_I)
        if 'actual_date' not in params: params['actual_date'] = now()
        self.pck.add_data(params['actual_date'], U_TP_I)
        self.pck.add_data(params['burn_date'], U_TP_I)
        self.pck.add_data(params['method'], U_TP_I)
        self.pck.add_data(params['admin_comment'], U_TP_S)
        self.pck.add_data(params['comment'], U_TP_S)
        self.pck.add_data(params['payment_ext_number'], U_TP_S)
        self.pck.add_data(params['payment_to_invoice'], U_TP_I)
        self.pck.add_data(params['turn_on_inet'], U_TP_I)
        self.pck.add_data(params['notify'], U_TP_I)
        self.pck.add_data(params['hash'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['payment_transaction_id'] = self.pck.get_data(U_TP_I)
        if ret['payment_transaction_id']  ==  0:
            ret['error'] = dict({13:"payment failed"})
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_payment_methods_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  payments_list_count :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    name :	(s)  - 
        """
        if not self.urfa_call(0x70000019):
            raise Exception("Fail of urfa_call(0x70000019) [rpcf_dealer_get_payment_methods_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['payments_list_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['payments_list_count']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['name'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_invoices_list(self, params):
        """ description
        @params: 
        :(s)  account_id :	(i)  - 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i) = _def_  - 
        :(s)  group_id :	(i)  - 
        @returns: 
        :(s)  accts_size :	(i)  - 
        :(s)    count_of_invoice :	(i)  - 
        :(s)      currency_id :	(i)  - 
        :(s)      currency_name :	(s)  - 
        :(s)      payment_rule :	(s)  - 
        :(s)      id :	(i)  - 
        :(s)      ext_num :	(s)  - 
        :(s)      invoice_date :	(i)  - 
        :(s)      uid :	(i)  - 
        :(s)      payment_transaction_id :	(i)  - 
        :(s)      expire_date :	(i)  - 
        :(s)      is_payed :	(i)  - 
        :(s)      is_printed :	(i)  - 
        :(s)      account_id :	(i)  - 
        :(s)      full_name :	(s)  - 
        :(s)        accInvcInfo_id :	(i)  - 
        :(s)        accInvcInfo_date :	(i)  - 
        :(s)        accInvcInfo_payed_date :	(i)  - 
        :(s)        payment_ext_number :	(s)  - 
        :(s)        is_printed :	(i)  - 
        :(s)      entry_size :	(i)  - 
        :(s)        name :	(s)  - 
        :(s)        invoice_id :	(i)  - 
        :(s)        slink_id :	(i)  - 
        :(s)        service_type :	(i)  - 
        :(s)        discount_period_id :	(i)  - 
        :(s)        date :	(i)  - 
        :(s)        qnt :	(d)  - 
        :(s)        base :	(d)  - 
        :(s)        sum :	(d)  - 
        :(s)        tax :	(d)  - 
        :(s)        total_sum :	(d)  - 
        :(s)        total_tax :	(d)  - 
        :(s)        total_sum_plus_total_tax :	(d)  - 
        """
        if not self.urfa_call(0x7000003c):
            raise Exception("Fail of urfa_call(0x7000003c) [rpcf_dealer_get_invoices_list]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['time_start'], U_TP_I)
        if 'time_end' not in params: params['time_end'] = now()
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.add_data(params['group_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['accts_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['accts_size']): 
            self.pck.recv(self.sck)
            ret['count_of_invoice'] = self.pck.get_data(U_TP_I)
            ret['count_of_invoice_array'][i]=ret['count_of_invoice']
            if ret['count_of_invoice']  !=  0:
                ret['currency_id'][i] = self.pck.get_data(U_TP_I)
                ret['currency_name'][i] = self.pck.get_data(U_TP_S)
                ret['payment_rule'][i] = self.pck.get_data(U_TP_S)
            if ret['count_of_invoice']  ==  0:
                ret['currency_id'][i]="0"
                ret['currency_name'][i]=""
                ret['payment_rule'][i]=""
            for j in range(ret['count_of_invoice']): 
                self.pck.recv(self.sck)
                if not i in ret['id']:ret['id'][i] = dict()
                ret['id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['ext_num']:ret['ext_num'][i] = dict()
                ret['ext_num'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['invoice_date']:ret['invoice_date'][i] = dict()
                ret['invoice_date'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['uid']:ret['uid'][i] = dict()
                ret['uid'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['payment_transaction_id']:ret['payment_transaction_id'][i] = dict()
                ret['payment_transaction_id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['expire_date']:ret['expire_date'][i] = dict()
                ret['expire_date'][i][j] = self.pck.get_data(U_TP_I)
                ret['is_payed'] = self.pck.get_data(U_TP_I)
                ret['is_payed_array'][i][j]=ret['is_payed']
                if not i in ret['is_printed']:ret['is_printed'][i] = dict()
                ret['is_printed'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['account_id']:ret['account_id'][i] = dict()
                ret['account_id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['full_name']:ret['full_name'][i] = dict()
                ret['full_name'][i][j] = self.pck.get_data(U_TP_S)
                if ret['is_payed']  !=  0:
                    if not i in ret['accInvcInfo_id']:ret['accInvcInfo_id'][i] = dict()
                    ret['accInvcInfo_id'][i][j] = self.pck.get_data(U_TP_I)
                    if not i in ret['accInvcInfo_date']:ret['accInvcInfo_date'][i] = dict()
                    ret['accInvcInfo_date'][i][j] = self.pck.get_data(U_TP_I)
                    if not i in ret['accInvcInfo_payed_date']:ret['accInvcInfo_payed_date'][i] = dict()
                    ret['accInvcInfo_payed_date'][i][j] = self.pck.get_data(U_TP_I)
                    if not i in ret['payment_ext_number']:ret['payment_ext_number'][i] = dict()
                    ret['payment_ext_number'][i][j] = self.pck.get_data(U_TP_S)
                    if not i in ret['is_printed']:ret['is_printed'][i] = dict()
                    ret['is_printed'][i][j] = self.pck.get_data(U_TP_I)
                if ret['is_payed']  ==  0:
                    ret['accInvcInfo_id'][i][j]="0"
                    ret['accInvcInfo_date'][i][j]="0"
                    ret['accInvcInfo_payed_date'][i][j]="0"
                    ret['payment_ext_number'][i][j]=""
                    ret['is_printed'][i][j]="0"
                ret['entry_size'] = self.pck.get_data(U_TP_I)
                ret['entry_size_array'][i][j]=ret['entry_size']
                for x in range(ret['entry_size']): 
                    self.pck.recv(self.sck)
                    if not i in ret['name']:ret['name'][i] = dict()
                    if not j in ret['name'][i]:ret['name'][i][j] = dict()
                    ret['name'][i][j][x] = self.pck.get_data(U_TP_S)
                    if not i in ret['invoice_id']:ret['invoice_id'][i] = dict()
                    if not j in ret['invoice_id'][i]:ret['invoice_id'][i][j] = dict()
                    ret['invoice_id'][i][j][x] = self.pck.get_data(U_TP_I)
                    if not i in ret['slink_id']:ret['slink_id'][i] = dict()
                    if not j in ret['slink_id'][i]:ret['slink_id'][i][j] = dict()
                    ret['slink_id'][i][j][x] = self.pck.get_data(U_TP_I)
                    if not i in ret['service_type']:ret['service_type'][i] = dict()
                    if not j in ret['service_type'][i]:ret['service_type'][i][j] = dict()
                    ret['service_type'][i][j][x] = self.pck.get_data(U_TP_I)
                    if not i in ret['discount_period_id']:ret['discount_period_id'][i] = dict()
                    if not j in ret['discount_period_id'][i]:ret['discount_period_id'][i][j] = dict()
                    ret['discount_period_id'][i][j][x] = self.pck.get_data(U_TP_I)
                    if not i in ret['date']:ret['date'][i] = dict()
                    if not j in ret['date'][i]:ret['date'][i][j] = dict()
                    ret['date'][i][j][x] = self.pck.get_data(U_TP_I)
                    if not i in ret['qnt']:ret['qnt'][i] = dict()
                    if not j in ret['qnt'][i]:ret['qnt'][i][j] = dict()
                    ret['qnt'][i][j][x] = self.pck.get_data(U_TP_D)
                    if not i in ret['base']:ret['base'][i] = dict()
                    if not j in ret['base'][i]:ret['base'][i][j] = dict()
                    ret['base'][i][j][x] = self.pck.get_data(U_TP_D)
                    if not i in ret['sum']:ret['sum'][i] = dict()
                    if not j in ret['sum'][i]:ret['sum'][i][j] = dict()
                    ret['sum'][i][j][x] = self.pck.get_data(U_TP_D)
                    if not i in ret['tax']:ret['tax'][i] = dict()
                    if not j in ret['tax'][i]:ret['tax'][i][j] = dict()
                    ret['tax'][i][j][x] = self.pck.get_data(U_TP_D)
                self.pck.recv(self.sck)
                if ret['entry_size']  !=  0:
                    if not i in ret['total_sum']:ret['total_sum'][i] = dict()
                    ret['total_sum'][i][j] = self.pck.get_data(U_TP_D)
                    if not i in ret['total_tax']:ret['total_tax'][i] = dict()
                    ret['total_tax'][i][j] = self.pck.get_data(U_TP_D)
                    if not i in ret['total_sum_plus_total_tax']:ret['total_sum_plus_total_tax'][i] = dict()
                    ret['total_sum_plus_total_tax'][i][j] = self.pck.get_data(U_TP_D)
                if ret['entry_size']  ==  0:
                    ret['total_sum'][i][j]="0"
                    ret['total_tax'][i][j]="0"
                    ret['total_sum_plus_total_tax'][i][j]="0"
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_currency_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  currency_size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    currency_brief_name :	(s)  - 
        :(s)    currency_full_name :	(s)  - 
        :(s)    percent :	(d)  - 
        :(s)    rates :	(d)  - 
        """
        if not self.urfa_call(0x7000003e):
            raise Exception("Fail of urfa_call(0x7000003e) [rpcf_dealer_get_currency_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['currency_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['currency_size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['currency_brief_name'][i] = self.pck.get_data(U_TP_S)
            ret['currency_full_name'][i] = self.pck.get_data(U_TP_S)
            ret['percent'][i] = self.pck.get_data(U_TP_D)
            ret['rates'][i] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_system_currency(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  currency_id :	(i)  - 
        """
        if not self.urfa_call(0x7000003f):
            raise Exception("Fail of urfa_call(0x7000003f) [rpcf_dealer_get_system_currency]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['currency_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_blocks_report(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i) = _def_  - 
        :(s)  account_id :	(i) = _def_  - 
        :(s)  group_id :	(i) = _def_  - 
        :(s)  apid :	(i) = _def_  - 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i) = _def_  - 
        :(s)  show_all :	(i) = _def_  - 
        @returns: 
        :(s)  accounts_count :	(i)  - 
        :(s)    atr_size :	(i)  - 
        :(s)      account_id :	(i)  - 
        :(s)      login :	(s)  - 
        :(s)      start_date :	(i)  - 
        :(s)      expire_date :	(i)  - 
        :(s)      what_blocked :	(i)  - 
        :(s)      block_type :	(i)  - 
        :(s)      comment :	(s)  - 
        """
        if not self.urfa_call(0x70000035):
            raise Exception("Fail of urfa_call(0x70000035) [rpcf_dealer_blocks_report]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'user_id' not in params: params['user_id'] = 0
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        if 'group_id' not in params: params['group_id'] = 0
        self.pck.add_data(params['group_id'], U_TP_I)
        if 'apid' not in params: params['apid'] = 0
        self.pck.add_data(params['apid'], U_TP_I)
        self.pck.add_data(params['time_start'], U_TP_I)
        if 'time_end' not in params: params['time_end'] = now()
        self.pck.add_data(params['time_end'], U_TP_I)
        if 'show_all' not in params: params['show_all'] = 1
        self.pck.add_data(params['show_all'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['accounts_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['accounts_count']): 
            self.pck.recv(self.sck)
            ret['atr_size'] = self.pck.get_data(U_TP_I)
            ret['atr_size_array'][i]=ret['atr_size']
            for j in range(ret['atr_size']): 
                self.pck.recv(self.sck)
                if not i in ret['account_id']:ret['account_id'][i] = dict()
                ret['account_id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['login']:ret['login'][i] = dict()
                ret['login'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['start_date']:ret['start_date'][i] = dict()
                ret['start_date'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['expire_date']:ret['expire_date'][i] = dict()
                ret['expire_date'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['what_blocked']:ret['what_blocked'][i] = dict()
                ret['what_blocked'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['block_type']:ret['block_type'][i] = dict()
                ret['block_type'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['comment']:ret['comment'][i] = dict()
                ret['comment'][i][j] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_blocks_report_for_dealer(self, params):
        """ description
        @params: 
        :(s)  dealer_id :	(i)  - 
        :(s)  user_id :	(i) = _def_  - 
        :(s)  account_id :	(i) = _def_  - 
        :(s)  group_id :	(i) = _def_  - 
        :(s)  apid :	(i) = _def_  - 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i) = _def_  - 
        :(s)  show_all :	(i) = _def_  - 
        @returns: 
        :(s)  accounts_count :	(i)  - 
        :(s)    atr_size :	(i)  - 
        :(s)      account_id :	(i)  - 
        :(s)      login :	(s)  - 
        :(s)      start_date :	(i)  - 
        :(s)      expire_date :	(i)  - 
        :(s)      what_blocked :	(i)  - 
        :(s)      block_type :	(i)  - 
        :(s)      comment :	(s)  - 
        """
        if not self.urfa_call(0x1301f):
            raise Exception("Fail of urfa_call(0x1301f) [rpcf_blocks_report_for_dealer]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['dealer_id'], U_TP_I)
        if 'user_id' not in params: params['user_id'] = 0
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        if 'group_id' not in params: params['group_id'] = 0
        self.pck.add_data(params['group_id'], U_TP_I)
        if 'apid' not in params: params['apid'] = 0
        self.pck.add_data(params['apid'], U_TP_I)
        self.pck.add_data(params['time_start'], U_TP_I)
        if 'time_end' not in params: params['time_end'] = now()
        self.pck.add_data(params['time_end'], U_TP_I)
        if 'show_all' not in params: params['show_all'] = 1
        self.pck.add_data(params['show_all'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['accounts_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['accounts_count']): 
            self.pck.recv(self.sck)
            ret['atr_size'] = self.pck.get_data(U_TP_I)
            ret['atr_size_array'][i]=ret['atr_size']
            for j in range(ret['atr_size']): 
                self.pck.recv(self.sck)
                if not i in ret['account_id']:ret['account_id'][i] = dict()
                ret['account_id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['login']:ret['login'][i] = dict()
                ret['login'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['start_date']:ret['start_date'][i] = dict()
                ret['start_date'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['expire_date']:ret['expire_date'][i] = dict()
                ret['expire_date'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['what_blocked']:ret['what_blocked'][i] = dict()
                ret['what_blocked'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['block_type']:ret['block_type'][i] = dict()
                ret['block_type'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['comment']:ret['comment'][i] = dict()
                ret['comment'][i][j] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_general_report(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i) = _def_  - 
        :(s)  account_id :	(i) = _def_  - 
        :(s)  group_id :	(i) = _def_  - 
        :(s)  discount_period_id :	(i) = _def_  - 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i) = _def_  - 
        @returns: 
        :(s)  accounts_count :	(i)  - 
        :(s)    account_id :	(i)  - 
        :(s)    login :	(s)  - 
        :(s)    incoming_rest :	(d)  - 
        :(s)    discounted_once :	(d)  - 
        :(s)    discounted_periodic :	(d)  - 
        :(s)    discounted_iptraffic :	(d)  - 
        :(s)    discounted_hotspot :	(d)  - 
        :(s)    discounted_dialup :	(d)  - 
        :(s)    discounted_telephony :	(d)  - 
        :(s)    tax :	(d)  - 
        :(s)    discounted_with_tax :	(d)  - 
        :(s)    payments :	(d)  - 
        :(s)    outgoing_rest :	(d)  - 
        """
        if not self.urfa_call(0x70000036):
            raise Exception("Fail of urfa_call(0x70000036) [rpcf_dealer_general_report]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'user_id' not in params: params['user_id'] = 0
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        if 'group_id' not in params: params['group_id'] = 0
        self.pck.add_data(params['group_id'], U_TP_I)
        if 'discount_period_id' not in params: params['discount_period_id'] = 0
        self.pck.add_data(params['discount_period_id'], U_TP_I)
        self.pck.add_data(params['time_start'], U_TP_I)
        if 'time_end' not in params: params['time_end'] = now()
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['accounts_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['accounts_count']): 
            self.pck.recv(self.sck)
            ret['account_id'][i] = self.pck.get_data(U_TP_I)
            ret['login'][i] = self.pck.get_data(U_TP_S)
            ret['incoming_rest'][i] = self.pck.get_data(U_TP_D)
            ret['discounted_once'][i] = self.pck.get_data(U_TP_D)
            ret['discounted_periodic'][i] = self.pck.get_data(U_TP_D)
            ret['discounted_iptraffic'][i] = self.pck.get_data(U_TP_D)
            ret['discounted_hotspot'][i] = self.pck.get_data(U_TP_D)
            ret['discounted_dialup'][i] = self.pck.get_data(U_TP_D)
            ret['discounted_telephony'][i] = self.pck.get_data(U_TP_D)
            ret['tax'][i] = self.pck.get_data(U_TP_D)
            ret['discounted_with_tax'][i] = self.pck.get_data(U_TP_D)
            ret['payments'][i] = self.pck.get_data(U_TP_D)
            ret['outgoing_rest'][i] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_general_report_for_dealer(self, params):
        """ description
        @params: 
        :(s)  dealer_id :	(i)  - 
        :(s)  user_id :	(i) = _def_  - 
        :(s)  account_id :	(i) = _def_  - 
        :(s)  group_id :	(i) = _def_  - 
        :(s)  discount_period_id :	(i) = _def_  - 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i) = _def_  - 
        @returns: 
        :(s)  accounts_count :	(i)  - 
        :(s)    account_id :	(i)  - 
        :(s)    login :	(s)  - 
        :(s)    incoming_rest :	(d)  - 
        :(s)    discounted_once :	(d)  - 
        :(s)    discounted_periodic :	(d)  - 
        :(s)    discounted_iptraffic :	(d)  - 
        :(s)    discounted_hotspot :	(d)  - 
        :(s)    discounted_dialup :	(d)  - 
        :(s)    discounted_telephony :	(d)  - 
        :(s)    tax :	(d)  - 
        :(s)    discounted_with_tax :	(d)  - 
        :(s)    payments :	(d)  - 
        :(s)    outgoing_rest :	(d)  - 
        """
        if not self.urfa_call(0x13020):
            raise Exception("Fail of urfa_call(0x13020) [rpcf_general_report_for_dealer]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['dealer_id'], U_TP_I)
        if 'user_id' not in params: params['user_id'] = 0
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        if 'group_id' not in params: params['group_id'] = 0
        self.pck.add_data(params['group_id'], U_TP_I)
        if 'discount_period_id' not in params: params['discount_period_id'] = 0
        self.pck.add_data(params['discount_period_id'], U_TP_I)
        self.pck.add_data(params['time_start'], U_TP_I)
        if 'time_end' not in params: params['time_end'] = now()
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['accounts_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['accounts_count']): 
            self.pck.recv(self.sck)
            ret['account_id'][i] = self.pck.get_data(U_TP_I)
            ret['login'][i] = self.pck.get_data(U_TP_S)
            ret['incoming_rest'][i] = self.pck.get_data(U_TP_D)
            ret['discounted_once'][i] = self.pck.get_data(U_TP_D)
            ret['discounted_periodic'][i] = self.pck.get_data(U_TP_D)
            ret['discounted_iptraffic'][i] = self.pck.get_data(U_TP_D)
            ret['discounted_hotspot'][i] = self.pck.get_data(U_TP_D)
            ret['discounted_dialup'][i] = self.pck.get_data(U_TP_D)
            ret['discounted_telephony'][i] = self.pck.get_data(U_TP_D)
            ret['tax'][i] = self.pck.get_data(U_TP_D)
            ret['discounted_with_tax'][i] = self.pck.get_data(U_TP_D)
            ret['payments'][i] = self.pck.get_data(U_TP_D)
            ret['outgoing_rest'][i] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_tel_report(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i) = _def_  - 
        :(s)  account_id :	(i) = _def_  - 
        :(s)  gid :	(i) = _def_  - 
        :(s)  apid :	(i) = _def_  - 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i) = _def_  - 
        @returns: 
        :(s)  accounts_count :	(i)  - 
        :(s)    dhs_log_size :	(i)  - 
        :(s)      count :	(i)  - 
        :(s)        id :	(i)  - 
        :(s)        account_id :	(i)  - 
        :(s)        slink_id :	(i)  - 
        :(s)        recv_date :	(i)  - 
        :(s)        acct_sess_time_plus_recv_date :	(i)  - 
        :(s)        Called_Station_Id :	(s)  - 
        :(s)        Calling_Station_Id :	(s)  - 
        :(s)        nas_port :	(i)  - 
        :(s)        acct_session_id :	(s)  - 
        :(s)        nas_port_type :	(i)  - 
        :(s)        uname :	(s)  - 
        :(s)        service_type :	(i)  - 
        :(s)        framed_protocol :	(i)  - 
        :(s)        nas_ip :	(i)  - 
        :(s)        nas_id :	(s)  - 
        :(s)        acct_status_type :	(i)  - 
        :(s)        acct_inp_pack :	(l)  - 
        :(s)        acct_inp_oct :	(l)  - 
        :(s)        acct_out_pack :	(l)  - 
        :(s)        acct_out_oct :	(l)  - 
        :(s)        zone_id :	(i)  - 
        :(s)        did :	(i)  - 
        :(s)        acct_sess_time :	(l)  - 
        :(s)        dcause :	(s)  - 
        :(s)        duration :	(l)  - 
        :(s)        base_cost :	(d)  - 
        :(s)        sum_cost :	(d)  - 
        """
        if not self.urfa_call(0x70000059):
            raise Exception("Fail of urfa_call(0x70000059) [rpcf_dealer_tel_report]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'user_id' not in params: params['user_id'] = 0
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        if 'gid' not in params: params['gid'] = 0
        self.pck.add_data(params['gid'], U_TP_I)
        if 'apid' not in params: params['apid'] = 0
        self.pck.add_data(params['apid'], U_TP_I)
        self.pck.add_data(params['time_start'], U_TP_I)
        if 'time_end' not in params: params['time_end'] = now()
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['accounts_count'] = self.pck.get_data(U_TP_I)
        for k in range(ret['accounts_count']): 
            self.pck.recv(self.sck)
            ret['dhs_log_size'] = self.pck.get_data(U_TP_I)
            ret['dhs_log_size_array'][k]=ret['dhs_log_size']
            for i in range(ret['dhs_log_size']): 
                self.pck.recv(self.sck)
                ret['count'] = self.pck.get_data(U_TP_I)
                ret['count_array'][k][i]=ret['count']
                for j in range(ret['count']): 
                    self.pck.recv(self.sck)
                    if not k in ret['id']:ret['id'][k] = dict()
                    if not i in ret['id'][k]:ret['id'][k][i] = dict()
                    ret['id'][k][i][j] = self.pck.get_data(U_TP_I)
                    if not k in ret['account_id']:ret['account_id'][k] = dict()
                    if not i in ret['account_id'][k]:ret['account_id'][k][i] = dict()
                    ret['account_id'][k][i][j] = self.pck.get_data(U_TP_I)
                    if not k in ret['slink_id']:ret['slink_id'][k] = dict()
                    if not i in ret['slink_id'][k]:ret['slink_id'][k][i] = dict()
                    ret['slink_id'][k][i][j] = self.pck.get_data(U_TP_I)
                    if not k in ret['recv_date']:ret['recv_date'][k] = dict()
                    if not i in ret['recv_date'][k]:ret['recv_date'][k][i] = dict()
                    ret['recv_date'][k][i][j] = self.pck.get_data(U_TP_I)
                    if not k in ret['acct_sess_time_plus_recv_date']:ret['acct_sess_time_plus_recv_date'][k] = dict()
                    if not i in ret['acct_sess_time_plus_recv_date'][k]:ret['acct_sess_time_plus_recv_date'][k][i] = dict()
                    ret['acct_sess_time_plus_recv_date'][k][i][j] = self.pck.get_data(U_TP_I)
                    if not k in ret['Called_Station_Id']:ret['Called_Station_Id'][k] = dict()
                    if not i in ret['Called_Station_Id'][k]:ret['Called_Station_Id'][k][i] = dict()
                    ret['Called_Station_Id'][k][i][j] = self.pck.get_data(U_TP_S)
                    if not k in ret['Calling_Station_Id']:ret['Calling_Station_Id'][k] = dict()
                    if not i in ret['Calling_Station_Id'][k]:ret['Calling_Station_Id'][k][i] = dict()
                    ret['Calling_Station_Id'][k][i][j] = self.pck.get_data(U_TP_S)
                    if not k in ret['nas_port']:ret['nas_port'][k] = dict()
                    if not i in ret['nas_port'][k]:ret['nas_port'][k][i] = dict()
                    ret['nas_port'][k][i][j] = self.pck.get_data(U_TP_I)
                    if not k in ret['acct_session_id']:ret['acct_session_id'][k] = dict()
                    if not i in ret['acct_session_id'][k]:ret['acct_session_id'][k][i] = dict()
                    ret['acct_session_id'][k][i][j] = self.pck.get_data(U_TP_S)
                    if not k in ret['nas_port_type']:ret['nas_port_type'][k] = dict()
                    if not i in ret['nas_port_type'][k]:ret['nas_port_type'][k][i] = dict()
                    ret['nas_port_type'][k][i][j] = self.pck.get_data(U_TP_I)
                    if not k in ret['uname']:ret['uname'][k] = dict()
                    if not i in ret['uname'][k]:ret['uname'][k][i] = dict()
                    ret['uname'][k][i][j] = self.pck.get_data(U_TP_S)
                    if not k in ret['service_type']:ret['service_type'][k] = dict()
                    if not i in ret['service_type'][k]:ret['service_type'][k][i] = dict()
                    ret['service_type'][k][i][j] = self.pck.get_data(U_TP_I)
                    if not k in ret['framed_protocol']:ret['framed_protocol'][k] = dict()
                    if not i in ret['framed_protocol'][k]:ret['framed_protocol'][k][i] = dict()
                    ret['framed_protocol'][k][i][j] = self.pck.get_data(U_TP_I)
                    if not k in ret['nas_ip']:ret['nas_ip'][k] = dict()
                    if not i in ret['nas_ip'][k]:ret['nas_ip'][k][i] = dict()
                    ret['nas_ip'][k][i][j] = self.pck.get_data(U_TP_IP)
                    if not k in ret['nas_id']:ret['nas_id'][k] = dict()
                    if not i in ret['nas_id'][k]:ret['nas_id'][k][i] = dict()
                    ret['nas_id'][k][i][j] = self.pck.get_data(U_TP_S)
                    if not k in ret['acct_status_type']:ret['acct_status_type'][k] = dict()
                    if not i in ret['acct_status_type'][k]:ret['acct_status_type'][k][i] = dict()
                    ret['acct_status_type'][k][i][j] = self.pck.get_data(U_TP_I)
                    if not k in ret['acct_inp_pack']:ret['acct_inp_pack'][k] = dict()
                    if not i in ret['acct_inp_pack'][k]:ret['acct_inp_pack'][k][i] = dict()
                    ret['acct_inp_pack'][k][i][j] = self.pck.get_data(U_TP_L)
                    if not k in ret['acct_inp_oct']:ret['acct_inp_oct'][k] = dict()
                    if not i in ret['acct_inp_oct'][k]:ret['acct_inp_oct'][k][i] = dict()
                    ret['acct_inp_oct'][k][i][j] = self.pck.get_data(U_TP_L)
                    if not k in ret['acct_out_pack']:ret['acct_out_pack'][k] = dict()
                    if not i in ret['acct_out_pack'][k]:ret['acct_out_pack'][k][i] = dict()
                    ret['acct_out_pack'][k][i][j] = self.pck.get_data(U_TP_L)
                    if not k in ret['acct_out_oct']:ret['acct_out_oct'][k] = dict()
                    if not i in ret['acct_out_oct'][k]:ret['acct_out_oct'][k][i] = dict()
                    ret['acct_out_oct'][k][i][j] = self.pck.get_data(U_TP_L)
                    if not k in ret['zone_id']:ret['zone_id'][k] = dict()
                    if not i in ret['zone_id'][k]:ret['zone_id'][k][i] = dict()
                    ret['zone_id'][k][i][j] = self.pck.get_data(U_TP_I)
                    if not k in ret['did']:ret['did'][k] = dict()
                    if not i in ret['did'][k]:ret['did'][k][i] = dict()
                    ret['did'][k][i][j] = self.pck.get_data(U_TP_I)
                    if not k in ret['acct_sess_time']:ret['acct_sess_time'][k] = dict()
                    if not i in ret['acct_sess_time'][k]:ret['acct_sess_time'][k][i] = dict()
                    ret['acct_sess_time'][k][i][j] = self.pck.get_data(U_TP_L)
                    if not k in ret['dcause']:ret['dcause'][k] = dict()
                    if not i in ret['dcause'][k]:ret['dcause'][k][i] = dict()
                    ret['dcause'][k][i][j] = self.pck.get_data(U_TP_S)
                    if not k in ret['duration']:ret['duration'][k] = dict()
                    if not i in ret['duration'][k]:ret['duration'][k][i] = dict()
                    ret['duration'][k][i][j] = self.pck.get_data(U_TP_L)
                    if not k in ret['base_cost']:ret['base_cost'][k] = dict()
                    if not i in ret['base_cost'][k]:ret['base_cost'][k][i] = dict()
                    ret['base_cost'][k][i][j] = self.pck.get_data(U_TP_D)
                    if not k in ret['sum_cost']:ret['sum_cost'][k] = dict()
                    if not i in ret['sum_cost'][k]:ret['sum_cost'][k][i] = dict()
                    ret['sum_cost'][k][i][j] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_add_tech_param(self, params):
        """ description
        @params: 
        :(s)  type_id :	(i)  - 
        :(s)  slink_id :	(i)  - 
        :(s)  param :	(s)  - 
        :(s)  reg_date :	(i)  - 
        :(s)  password :	(s)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x70000073):
            raise Exception("Fail of urfa_call(0x70000073) [rpcf_dealer_add_tech_param]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['type_id'], U_TP_I)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.add_data(params['param'], U_TP_S)
        self.pck.add_data(params['reg_date'], U_TP_I)
        self.pck.add_data(params['password'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_save_tech_param(self, params):
        """ description
        @params: 
        :(s)  type_id :	(i)  - 
        :(s)  slink_id :	(i)  - 
        :(s)  id :	(i)  - 
        :(s)  param :	(s)  - 
        :(s)  reg_date :	(i)  - 
        :(s)  password :	(s)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x70000074):
            raise Exception("Fail of urfa_call(0x70000074) [rpcf_dealer_save_tech_param]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['type_id'], U_TP_I)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['param'], U_TP_S)
        self.pck.add_data(params['reg_date'], U_TP_I)
        self.pck.add_data(params['password'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_tech_param_by_uid(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  account_id :	(i)  - 
        @returns: 
        :(s)  slinks_count :	(i)  - 
        :(s)    params_count :	(i)  - 
        :(s)      id :	(i)  - 
        :(s)      type_id :	(i)  - 
        :(s)      type_name :	(s)  - 
        :(s)      param :	(s)  - 
        :(s)      reg_date :	(i)  - 
        :(s)      slink_id :	(i)  - 
        :(s)      service_name :	(s)  - 
        :(s)      passwd :	(s)  - 
        """
        if not self.urfa_call(0x70000075):
            raise Exception("Fail of urfa_call(0x70000075) [rpcf_dealer_get_tech_param_by_uid]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['slinks_count'] = self.pck.get_data(U_TP_I)
        for s in range(ret['slinks_count']): 
            self.pck.recv(self.sck)
            ret['params_count'][s] = self.pck.get_data(U_TP_I)
            for p in range(ret['params_count'][s]): 
                self.pck.recv(self.sck)
                if not s in ret['id']:ret['id'][s] = dict()
                ret['id'][s][p] = self.pck.get_data(U_TP_I)
                if not s in ret['type_id']:ret['type_id'][s] = dict()
                ret['type_id'][s][p] = self.pck.get_data(U_TP_I)
                if not s in ret['type_name']:ret['type_name'][s] = dict()
                ret['type_name'][s][p] = self.pck.get_data(U_TP_S)
                if not s in ret['param']:ret['param'][s] = dict()
                ret['param'][s][p] = self.pck.get_data(U_TP_S)
                if not s in ret['reg_date']:ret['reg_date'][s] = dict()
                ret['reg_date'][s][p] = self.pck.get_data(U_TP_I)
                if not s in ret['slink_id']:ret['slink_id'][s] = dict()
                ret['slink_id'][s][p] = self.pck.get_data(U_TP_I)
                if not s in ret['service_name']:ret['service_name'][s] = dict()
                ret['service_name'][s][p] = self.pck.get_data(U_TP_S)
                if not s in ret['passwd']:ret['passwd'][s] = dict()
                ret['passwd'][s][p] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_del_tech_param(self, params):
        """ description
        @params: 
        :(s)  tp_id :	(i)  - 
        :(s)  slink_id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x70000076):
            raise Exception("Fail of urfa_call(0x70000076) [rpcf_dealer_del_tech_param]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['tp_id'], U_TP_I)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_tel_report_for_dealer(self, params):
        """ description
        @params: 
        :(s)  dealer_id :	(i)  - 
        :(s)  user_id :	(i) = _def_  - 
        :(s)  account_id :	(i) = _def_  - 
        :(s)  gid :	(i) = _def_  - 
        :(s)  apid :	(i) = _def_  - 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i) = _def_  - 
        @returns: 
        :(s)  accounts_count :	(i)  - 
        :(s)    dhs_log_size :	(i)  - 
        :(s)      count :	(i)  - 
        :(s)        id :	(i)  - 
        :(s)        account_id :	(i)  - 
        :(s)        slink_id :	(i)  - 
        :(s)        recv_date :	(i)  - 
        :(s)        acct_sess_time_plus_recv_date :	(i)  - 
        :(s)        Called_Station_Id :	(s)  - 
        :(s)        Calling_Station_Id :	(s)  - 
        :(s)        nas_port :	(i)  - 
        :(s)        acct_session_id :	(s)  - 
        :(s)        nas_port_type :	(i)  - 
        :(s)        uname :	(s)  - 
        :(s)        service_type :	(i)  - 
        :(s)        framed_protocol :	(i)  - 
        :(s)        nas_ip :	(i)  - 
        :(s)        nas_id :	(s)  - 
        :(s)        acct_status_type :	(i)  - 
        :(s)        acct_inp_pack :	(l)  - 
        :(s)        acct_inp_oct :	(l)  - 
        :(s)        acct_out_pack :	(l)  - 
        :(s)        acct_out_oct :	(l)  - 
        :(s)        zone_id :	(i)  - 
        :(s)        did :	(i)  - 
        :(s)        acct_sess_time :	(l)  - 
        :(s)        dcause :	(s)  - 
        :(s)        duration :	(l)  - 
        :(s)        base_cost :	(d)  - 
        :(s)        sum_cost :	(d)  - 
        """
        if not self.urfa_call(0x13028):
            raise Exception("Fail of urfa_call(0x13028) [rpcf_tel_report_for_dealer]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['dealer_id'], U_TP_I)
        if 'user_id' not in params: params['user_id'] = 0
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        if 'gid' not in params: params['gid'] = 0
        self.pck.add_data(params['gid'], U_TP_I)
        if 'apid' not in params: params['apid'] = 0
        self.pck.add_data(params['apid'], U_TP_I)
        self.pck.add_data(params['time_start'], U_TP_I)
        if 'time_end' not in params: params['time_end'] = now()
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['accounts_count'] = self.pck.get_data(U_TP_I)
        for k in range(ret['accounts_count']): 
            self.pck.recv(self.sck)
            ret['dhs_log_size'] = self.pck.get_data(U_TP_I)
            ret['dhs_log_size_array'][k]=ret['dhs_log_size']
            for i in range(ret['dhs_log_size']): 
                self.pck.recv(self.sck)
                ret['count'] = self.pck.get_data(U_TP_I)
                ret['count_array'][k][i]=ret['count']
                for j in range(ret['count']): 
                    self.pck.recv(self.sck)
                    if not k in ret['id']:ret['id'][k] = dict()
                    if not i in ret['id'][k]:ret['id'][k][i] = dict()
                    ret['id'][k][i][j] = self.pck.get_data(U_TP_I)
                    if not k in ret['account_id']:ret['account_id'][k] = dict()
                    if not i in ret['account_id'][k]:ret['account_id'][k][i] = dict()
                    ret['account_id'][k][i][j] = self.pck.get_data(U_TP_I)
                    if not k in ret['slink_id']:ret['slink_id'][k] = dict()
                    if not i in ret['slink_id'][k]:ret['slink_id'][k][i] = dict()
                    ret['slink_id'][k][i][j] = self.pck.get_data(U_TP_I)
                    if not k in ret['recv_date']:ret['recv_date'][k] = dict()
                    if not i in ret['recv_date'][k]:ret['recv_date'][k][i] = dict()
                    ret['recv_date'][k][i][j] = self.pck.get_data(U_TP_I)
                    if not k in ret['acct_sess_time_plus_recv_date']:ret['acct_sess_time_plus_recv_date'][k] = dict()
                    if not i in ret['acct_sess_time_plus_recv_date'][k]:ret['acct_sess_time_plus_recv_date'][k][i] = dict()
                    ret['acct_sess_time_plus_recv_date'][k][i][j] = self.pck.get_data(U_TP_I)
                    if not k in ret['Called_Station_Id']:ret['Called_Station_Id'][k] = dict()
                    if not i in ret['Called_Station_Id'][k]:ret['Called_Station_Id'][k][i] = dict()
                    ret['Called_Station_Id'][k][i][j] = self.pck.get_data(U_TP_S)
                    if not k in ret['Calling_Station_Id']:ret['Calling_Station_Id'][k] = dict()
                    if not i in ret['Calling_Station_Id'][k]:ret['Calling_Station_Id'][k][i] = dict()
                    ret['Calling_Station_Id'][k][i][j] = self.pck.get_data(U_TP_S)
                    if not k in ret['nas_port']:ret['nas_port'][k] = dict()
                    if not i in ret['nas_port'][k]:ret['nas_port'][k][i] = dict()
                    ret['nas_port'][k][i][j] = self.pck.get_data(U_TP_I)
                    if not k in ret['acct_session_id']:ret['acct_session_id'][k] = dict()
                    if not i in ret['acct_session_id'][k]:ret['acct_session_id'][k][i] = dict()
                    ret['acct_session_id'][k][i][j] = self.pck.get_data(U_TP_S)
                    if not k in ret['nas_port_type']:ret['nas_port_type'][k] = dict()
                    if not i in ret['nas_port_type'][k]:ret['nas_port_type'][k][i] = dict()
                    ret['nas_port_type'][k][i][j] = self.pck.get_data(U_TP_I)
                    if not k in ret['uname']:ret['uname'][k] = dict()
                    if not i in ret['uname'][k]:ret['uname'][k][i] = dict()
                    ret['uname'][k][i][j] = self.pck.get_data(U_TP_S)
                    if not k in ret['service_type']:ret['service_type'][k] = dict()
                    if not i in ret['service_type'][k]:ret['service_type'][k][i] = dict()
                    ret['service_type'][k][i][j] = self.pck.get_data(U_TP_I)
                    if not k in ret['framed_protocol']:ret['framed_protocol'][k] = dict()
                    if not i in ret['framed_protocol'][k]:ret['framed_protocol'][k][i] = dict()
                    ret['framed_protocol'][k][i][j] = self.pck.get_data(U_TP_I)
                    if not k in ret['nas_ip']:ret['nas_ip'][k] = dict()
                    if not i in ret['nas_ip'][k]:ret['nas_ip'][k][i] = dict()
                    ret['nas_ip'][k][i][j] = self.pck.get_data(U_TP_IP)
                    if not k in ret['nas_id']:ret['nas_id'][k] = dict()
                    if not i in ret['nas_id'][k]:ret['nas_id'][k][i] = dict()
                    ret['nas_id'][k][i][j] = self.pck.get_data(U_TP_S)
                    if not k in ret['acct_status_type']:ret['acct_status_type'][k] = dict()
                    if not i in ret['acct_status_type'][k]:ret['acct_status_type'][k][i] = dict()
                    ret['acct_status_type'][k][i][j] = self.pck.get_data(U_TP_I)
                    if not k in ret['acct_inp_pack']:ret['acct_inp_pack'][k] = dict()
                    if not i in ret['acct_inp_pack'][k]:ret['acct_inp_pack'][k][i] = dict()
                    ret['acct_inp_pack'][k][i][j] = self.pck.get_data(U_TP_L)
                    if not k in ret['acct_inp_oct']:ret['acct_inp_oct'][k] = dict()
                    if not i in ret['acct_inp_oct'][k]:ret['acct_inp_oct'][k][i] = dict()
                    ret['acct_inp_oct'][k][i][j] = self.pck.get_data(U_TP_L)
                    if not k in ret['acct_out_pack']:ret['acct_out_pack'][k] = dict()
                    if not i in ret['acct_out_pack'][k]:ret['acct_out_pack'][k][i] = dict()
                    ret['acct_out_pack'][k][i][j] = self.pck.get_data(U_TP_L)
                    if not k in ret['acct_out_oct']:ret['acct_out_oct'][k] = dict()
                    if not i in ret['acct_out_oct'][k]:ret['acct_out_oct'][k][i] = dict()
                    ret['acct_out_oct'][k][i][j] = self.pck.get_data(U_TP_L)
                    if not k in ret['zone_id']:ret['zone_id'][k] = dict()
                    if not i in ret['zone_id'][k]:ret['zone_id'][k][i] = dict()
                    ret['zone_id'][k][i][j] = self.pck.get_data(U_TP_I)
                    if not k in ret['did']:ret['did'][k] = dict()
                    if not i in ret['did'][k]:ret['did'][k][i] = dict()
                    ret['did'][k][i][j] = self.pck.get_data(U_TP_I)
                    if not k in ret['acct_sess_time']:ret['acct_sess_time'][k] = dict()
                    if not i in ret['acct_sess_time'][k]:ret['acct_sess_time'][k][i] = dict()
                    ret['acct_sess_time'][k][i][j] = self.pck.get_data(U_TP_L)
                    if not k in ret['dcause']:ret['dcause'][k] = dict()
                    if not i in ret['dcause'][k]:ret['dcause'][k][i] = dict()
                    ret['dcause'][k][i][j] = self.pck.get_data(U_TP_S)
                    if not k in ret['duration']:ret['duration'][k] = dict()
                    if not i in ret['duration'][k]:ret['duration'][k][i] = dict()
                    ret['duration'][k][i][j] = self.pck.get_data(U_TP_L)
                    if not k in ret['base_cost']:ret['base_cost'][k] = dict()
                    if not i in ret['base_cost'][k]:ret['base_cost'][k][i] = dict()
                    ret['base_cost'][k][i][j] = self.pck.get_data(U_TP_D)
                    if not k in ret['sum_cost']:ret['sum_cost'][k] = dict()
                    if not i in ret['sum_cost'][k]:ret['sum_cost'][k][i] = dict()
                    ret['sum_cost'][k][i][j] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_payments_report(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i) = _def_  - 
        :(s)  account_id :	(i) = _def_  - 
        :(s)  group_id :	(i) = _def_  - 
        :(s)  apid :	(i) = _def_  - 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i) = _def_  - 
        @returns: 
        :(s)  accounts_count :	(i)  - 
        :(s)    atr_size :	(i)  - 
        :(s)      id :	(i)  - 
        :(s)      account_id :	(i)  - 
        :(s)      login :	(s)  - 
        :(s)      actual_date :	(i)  - 
        :(s)      payment_enter_date :	(i)  - 
        :(s)      payment :	(d)  - 
        :(s)      payment_incurrency :	(d)  - 
        :(s)      currency_id :	(i)  - 
        :(s)      method :	(i)  - 
        :(s)      who_receved :	(i)  - 
        :(s)      admin_comment :	(s)  - 
        :(s)      payment_ext_number :	(s)  - 
        """
        if not self.urfa_call(0x70000038):
            raise Exception("Fail of urfa_call(0x70000038) [rpcf_dealer_payments_report]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'user_id' not in params: params['user_id'] = 0
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        if 'group_id' not in params: params['group_id'] = 0
        self.pck.add_data(params['group_id'], U_TP_I)
        if 'apid' not in params: params['apid'] = 0
        self.pck.add_data(params['apid'], U_TP_I)
        self.pck.add_data(params['time_start'], U_TP_I)
        if 'time_end' not in params: params['time_end'] = now()
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['accounts_count'] = self.pck.get_data(U_TP_I)
        for j in range(ret['accounts_count']): 
            self.pck.recv(self.sck)
            ret['atr_size'] = self.pck.get_data(U_TP_I)
            ret['atr_size_array'][j]=ret['atr_size']
            for i in range(ret['atr_size']): 
                self.pck.recv(self.sck)
                if not j in ret['id']:ret['id'][j] = dict()
                ret['id'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['account_id']:ret['account_id'][j] = dict()
                ret['account_id'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['login']:ret['login'][j] = dict()
                ret['login'][j][i] = self.pck.get_data(U_TP_S)
                if not j in ret['actual_date']:ret['actual_date'][j] = dict()
                ret['actual_date'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['payment_enter_date']:ret['payment_enter_date'][j] = dict()
                ret['payment_enter_date'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['payment']:ret['payment'][j] = dict()
                ret['payment'][j][i] = self.pck.get_data(U_TP_D)
                if not j in ret['payment_incurrency']:ret['payment_incurrency'][j] = dict()
                ret['payment_incurrency'][j][i] = self.pck.get_data(U_TP_D)
                if not j in ret['currency_id']:ret['currency_id'][j] = dict()
                ret['currency_id'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['method']:ret['method'][j] = dict()
                ret['method'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['who_receved']:ret['who_receved'][j] = dict()
                ret['who_receved'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['admin_comment']:ret['admin_comment'][j] = dict()
                ret['admin_comment'][j][i] = self.pck.get_data(U_TP_S)
                if not j in ret['payment_ext_number']:ret['payment_ext_number'][j] = dict()
                ret['payment_ext_number'][j][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_payments_report_for_dealer(self, params):
        """ description
        @params: 
        :(s)  dealer_id :	(i)  - 
        :(s)  user_id :	(i) = _def_  - 
        :(s)  account_id :	(i) = _def_  - 
        :(s)  group_id :	(i) = _def_  - 
        :(s)  apid :	(i) = _def_  - 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i) = _def_  - 
        @returns: 
        :(s)  accounts_count :	(i)  - 
        :(s)    atr_size :	(i)  - 
        :(s)      id :	(i)  - 
        :(s)      account_id :	(i)  - 
        :(s)      login :	(s)  - 
        :(s)      actual_date :	(i)  - 
        :(s)      payment_enter_date :	(i)  - 
        :(s)      payment :	(d)  - 
        :(s)      payment_incurrency :	(d)  - 
        :(s)      currency_id :	(i)  - 
        :(s)      method :	(i)  - 
        :(s)      who_receved :	(i)  - 
        :(s)      admin_comment :	(s)  - 
        :(s)      payment_ext_number :	(s)  - 
        """
        if not self.urfa_call(0x13022):
            raise Exception("Fail of urfa_call(0x13022) [rpcf_payments_report_for_dealer]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['dealer_id'], U_TP_I)
        if 'user_id' not in params: params['user_id'] = 0
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        if 'group_id' not in params: params['group_id'] = 0
        self.pck.add_data(params['group_id'], U_TP_I)
        if 'apid' not in params: params['apid'] = 0
        self.pck.add_data(params['apid'], U_TP_I)
        self.pck.add_data(params['time_start'], U_TP_I)
        if 'time_end' not in params: params['time_end'] = now()
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['accounts_count'] = self.pck.get_data(U_TP_I)
        for j in range(ret['accounts_count']): 
            self.pck.recv(self.sck)
            ret['atr_size'] = self.pck.get_data(U_TP_I)
            ret['atr_size_array'][j]=ret['atr_size']
            for i in range(ret['atr_size']): 
                self.pck.recv(self.sck)
                if not j in ret['id']:ret['id'][j] = dict()
                ret['id'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['account_id']:ret['account_id'][j] = dict()
                ret['account_id'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['login']:ret['login'][j] = dict()
                ret['login'][j][i] = self.pck.get_data(U_TP_S)
                if not j in ret['actual_date']:ret['actual_date'][j] = dict()
                ret['actual_date'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['payment_enter_date']:ret['payment_enter_date'][j] = dict()
                ret['payment_enter_date'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['payment']:ret['payment'][j] = dict()
                ret['payment'][j][i] = self.pck.get_data(U_TP_D)
                if not j in ret['payment_incurrency']:ret['payment_incurrency'][j] = dict()
                ret['payment_incurrency'][j][i] = self.pck.get_data(U_TP_D)
                if not j in ret['currency_id']:ret['currency_id'][j] = dict()
                ret['currency_id'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['method']:ret['method'][j] = dict()
                ret['method'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['who_receved']:ret['who_receved'][j] = dict()
                ret['who_receved'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['admin_comment']:ret['admin_comment'][j] = dict()
                ret['admin_comment'][j][i] = self.pck.get_data(U_TP_S)
                if not j in ret['payment_ext_number']:ret['payment_ext_number'][j] = dict()
                ret['payment_ext_number'][j][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_service_report(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i) = _def_  - 
        :(s)  account_id :	(i) = _def_  - 
        :(s)  group_id :	(i) = _def_  - 
        :(s)  apid :	(i) = _def_  - 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i) = _def_  - 
        @returns: 
        :(s)  accounts_count :	(i)  - 
        :(s)    atr_size :	(i)  - 
        :(s)      account_id :	(i)  - 
        :(s)      login :	(s)  - 
        :(s)      discount_date :	(i)  - 
        :(s)      discount_period_id :	(i)  - 
        :(s)      discount :	(d)  - 
        :(s)      service_name :	(s)  - 
        :(s)      service_type :	(i)  - 
        :(s)      comment :	(s)  - 
        """
        if not self.urfa_call(0x70000039):
            raise Exception("Fail of urfa_call(0x70000039) [rpcf_dealer_service_report]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'user_id' not in params: params['user_id'] = 0
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        if 'group_id' not in params: params['group_id'] = 0
        self.pck.add_data(params['group_id'], U_TP_I)
        if 'apid' not in params: params['apid'] = 0
        self.pck.add_data(params['apid'], U_TP_I)
        self.pck.add_data(params['time_start'], U_TP_I)
        if 'time_end' not in params: params['time_end'] = now()
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['accounts_count'] = self.pck.get_data(U_TP_I)
        for j in range(ret['accounts_count']): 
            self.pck.recv(self.sck)
            ret['atr_size'] = self.pck.get_data(U_TP_I)
            ret['atr_size_array'][j]=ret['atr_size']
            for i in range(ret['atr_size']): 
                self.pck.recv(self.sck)
                if not j in ret['account_id']:ret['account_id'][j] = dict()
                ret['account_id'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['login']:ret['login'][j] = dict()
                ret['login'][j][i] = self.pck.get_data(U_TP_S)
                if not j in ret['discount_date']:ret['discount_date'][j] = dict()
                ret['discount_date'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['discount_period_id']:ret['discount_period_id'][j] = dict()
                ret['discount_period_id'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['discount']:ret['discount'][j] = dict()
                ret['discount'][j][i] = self.pck.get_data(U_TP_D)
                if not j in ret['service_name']:ret['service_name'][j] = dict()
                ret['service_name'][j][i] = self.pck.get_data(U_TP_S)
                if not j in ret['service_type']:ret['service_type'][j] = dict()
                ret['service_type'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['comment']:ret['comment'][j] = dict()
                ret['comment'][j][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_service_report_for_dealer(self, params):
        """ description
        @params: 
        :(s)  dealer_id :	(i)  - 
        :(s)  user_id :	(i) = _def_  - 
        :(s)  account_id :	(i) = _def_  - 
        :(s)  group_id :	(i) = _def_  - 
        :(s)  apid :	(i) = _def_  - 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i) = _def_  - 
        @returns: 
        :(s)  accounts_count :	(i)  - 
        :(s)    atr_size :	(i)  - 
        :(s)      account_id :	(i)  - 
        :(s)      login :	(s)  - 
        :(s)      discount_date :	(i)  - 
        :(s)      discount_period_id :	(i)  - 
        :(s)      discount :	(d)  - 
        :(s)      service_name :	(s)  - 
        :(s)      service_type :	(i)  - 
        :(s)      comment :	(s)  - 
        """
        if not self.urfa_call(0x13023):
            raise Exception("Fail of urfa_call(0x13023) [rpcf_service_report_for_dealer]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['dealer_id'], U_TP_I)
        if 'user_id' not in params: params['user_id'] = 0
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        if 'group_id' not in params: params['group_id'] = 0
        self.pck.add_data(params['group_id'], U_TP_I)
        if 'apid' not in params: params['apid'] = 0
        self.pck.add_data(params['apid'], U_TP_I)
        self.pck.add_data(params['time_start'], U_TP_I)
        if 'time_end' not in params: params['time_end'] = now()
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['accounts_count'] = self.pck.get_data(U_TP_I)
        for j in range(ret['accounts_count']): 
            self.pck.recv(self.sck)
            ret['atr_size'] = self.pck.get_data(U_TP_I)
            ret['atr_size_array'][j]=ret['atr_size']
            for i in range(ret['atr_size']): 
                self.pck.recv(self.sck)
                if not j in ret['account_id']:ret['account_id'][j] = dict()
                ret['account_id'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['login']:ret['login'][j] = dict()
                ret['login'][j][i] = self.pck.get_data(U_TP_S)
                if not j in ret['discount_date']:ret['discount_date'][j] = dict()
                ret['discount_date'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['discount_period_id']:ret['discount_period_id'][j] = dict()
                ret['discount_period_id'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['discount']:ret['discount'][j] = dict()
                ret['discount'][j][i] = self.pck.get_data(U_TP_D)
                if not j in ret['service_name']:ret['service_name'][j] = dict()
                ret['service_name'][j][i] = self.pck.get_data(U_TP_S)
                if not j in ret['service_type']:ret['service_type'][j] = dict()
                ret['service_type'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['comment']:ret['comment'][j] = dict()
                ret['comment'][j][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_traffic_report(self, params):
        """ description
        @params: 
        :(s)  type :	(i)  - 
        :(s)  user_id :	(i) = _def_  - 
        :(s)  account_id :	(i) = _def_  - 
        :(s)  group_id :	(i) = _def_  - 
        :(s)  apid :	(i) = _def_  - 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i) = _def_  - 
        @returns: 
        :(s)  bytes_in_kbyte :	(d)  - 
        :(s)  users_count :	(i)  - 
        :(s)    atr_size :	(i)  - 
        :(s)      account_id :	(i)  - 
        :(s)      login :	(s)  - 
        :(s)        discount_date :	(i)  - 
        :(s)        discount_date :	(i)  - 
        :(s)        discount_date :	(i)  - 
        :(s)        ip_address :	(i)  - 
        :(s)      tclass :	(i)  - 
        :(s)      base_cost :	(d)  - 
        :(s)      bytes :	(l)  - 
        :(s)      discount :	(d)  - 
        """
        if not self.urfa_call(0x7000003a):
            raise Exception("Fail of urfa_call(0x7000003a) [rpcf_dealer_traffic_report]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['type'], U_TP_I)
        if 'user_id' not in params: params['user_id'] = 0
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        if 'group_id' not in params: params['group_id'] = 0
        self.pck.add_data(params['group_id'], U_TP_I)
        if 'apid' not in params: params['apid'] = 0
        self.pck.add_data(params['apid'], U_TP_I)
        self.pck.add_data(params['time_start'], U_TP_I)
        if 'time_end' not in params: params['time_end'] = now()
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['bytes_in_kbyte'] = self.pck.get_data(U_TP_D)
        ret['users_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['users_count']): 
            self.pck.recv(self.sck)
            ret['atr_size'] = self.pck.get_data(U_TP_I)
            ret['atr_size_array'][i]=ret['atr_size']
            for j in range(ret['atr_size']): 
                self.pck.recv(self.sck)
                if not i in ret['account_id']:ret['account_id'][i] = dict()
                ret['account_id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['login']:ret['login'][i] = dict()
                ret['login'][i][j] = self.pck.get_data(U_TP_S)
                if params['type']  ==  1:
                    if not i in ret['discount_date']:ret['discount_date'][i] = dict()
                    ret['discount_date'][i][j] = self.pck.get_data(U_TP_I)
                if params['type']  ==  2:
                    if not i in ret['discount_date']:ret['discount_date'][i] = dict()
                    ret['discount_date'][i][j] = self.pck.get_data(U_TP_I)
                if params['type']  ==  3:
                    if not i in ret['discount_date']:ret['discount_date'][i] = dict()
                    ret['discount_date'][i][j] = self.pck.get_data(U_TP_I)
                if params['type']  ==  4:
                    if not i in ret['ip_address']:ret['ip_address'][i] = dict()
                    ret['ip_address'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['tclass']:ret['tclass'][i] = dict()
                ret['tclass'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['base_cost']:ret['base_cost'][i] = dict()
                ret['base_cost'][i][j] = self.pck.get_data(U_TP_D)
                if not i in ret['bytes']:ret['bytes'][i] = dict()
                ret['bytes'][i][j] = self.pck.get_data(U_TP_L)
                if not i in ret['discount']:ret['discount'][i] = dict()
                ret['discount'][i][j] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_traffic_report_for_dealer(self, params):
        """ description
        @params: 
        :(s)  dealer_id :	(i)  - 
        :(s)  type :	(i)  - 
        :(s)  user_id :	(i) = _def_  - 
        :(s)  account_id :	(i) = _def_  - 
        :(s)  group_id :	(i) = _def_  - 
        :(s)  apid :	(i) = _def_  - 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i) = _def_  - 
        @returns: 
        :(s)  bytes_in_kbyte :	(d)  - 
        :(s)  users_count :	(i)  - 
        :(s)    atr_size :	(i)  - 
        :(s)      account_id :	(i)  - 
        :(s)      login :	(s)  - 
        :(s)        discount_date :	(i)  - 
        :(s)        discount_date :	(i)  - 
        :(s)        discount_date :	(i)  - 
        :(s)        ip_address :	(i)  - 
        :(s)      tclass :	(i)  - 
        :(s)      base_cost :	(d)  - 
        :(s)      bytes :	(l)  - 
        :(s)      discount :	(d)  - 
        """
        if not self.urfa_call(0x13024):
            raise Exception("Fail of urfa_call(0x13024) [rpcf_traffic_report_for_dealer]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['dealer_id'], U_TP_I)
        self.pck.add_data(params['type'], U_TP_I)
        if 'user_id' not in params: params['user_id'] = 0
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        if 'group_id' not in params: params['group_id'] = 0
        self.pck.add_data(params['group_id'], U_TP_I)
        if 'apid' not in params: params['apid'] = 0
        self.pck.add_data(params['apid'], U_TP_I)
        self.pck.add_data(params['time_start'], U_TP_I)
        if 'time_end' not in params: params['time_end'] = now()
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['bytes_in_kbyte'] = self.pck.get_data(U_TP_D)
        ret['users_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['users_count']): 
            self.pck.recv(self.sck)
            ret['atr_size'] = self.pck.get_data(U_TP_I)
            ret['atr_size_array'][i]=ret['atr_size']
            for j in range(ret['atr_size']): 
                self.pck.recv(self.sck)
                if not i in ret['account_id']:ret['account_id'][i] = dict()
                ret['account_id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['login']:ret['login'][i] = dict()
                ret['login'][i][j] = self.pck.get_data(U_TP_S)
                if params['type']  ==  1:
                    if not i in ret['discount_date']:ret['discount_date'][i] = dict()
                    ret['discount_date'][i][j] = self.pck.get_data(U_TP_I)
                if params['type']  ==  2:
                    if not i in ret['discount_date']:ret['discount_date'][i] = dict()
                    ret['discount_date'][i][j] = self.pck.get_data(U_TP_I)
                if params['type']  ==  3:
                    if not i in ret['discount_date']:ret['discount_date'][i] = dict()
                    ret['discount_date'][i][j] = self.pck.get_data(U_TP_I)
                if params['type']  ==  4:
                    if not i in ret['ip_address']:ret['ip_address'][i] = dict()
                    ret['ip_address'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['tclass']:ret['tclass'][i] = dict()
                ret['tclass'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['base_cost']:ret['base_cost'][i] = dict()
                ret['base_cost'][i][j] = self.pck.get_data(U_TP_D)
                if not i in ret['bytes']:ret['bytes'][i] = dict()
                ret['bytes'][i][j] = self.pck.get_data(U_TP_L)
                if not i in ret['discount']:ret['discount'][i] = dict()
                ret['discount'][i][j] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_dhs_report(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i) = _def_  - 
        :(s)  account_id :	(i) = _def_  - 
        :(s)  gid :	(i) = _def_  - 
        :(s)  apid :	(i) = _def_  - 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i) = _def_  - 
        @returns: 
        :(s)  accounts_count :	(i)  - 
        :(s)    dhs_log_size :	(i)  - 
        :(s)      id :	(i)  - 
        :(s)      account_id :	(i)  - 
        :(s)      slink_id :	(i)  - 
        :(s)      recv_date :	(i)  - 
        :(s)      last_update_date :	(i)  - 
        :(s)      Called_Station_Id :	(s)  - 
        :(s)      Calling_Station_Id :	(s)  - 
        :(s)      framed_ip4 :	(i)  - 
        :(s)      framed_ip6 :	(i)  - 
        :(s)      nas_port :	(i)  - 
        :(s)      acct_session_id :	(s)  - 
        :(s)      nas_port_type :	(i)  - 
        :(s)      uname :	(s)  - 
        :(s)      service_type :	(i)  - 
        :(s)      framed_protocol :	(i)  - 
        :(s)      nas_ip :	(i)  - 
        :(s)      nas_id :	(s)  - 
        :(s)      acct_status_type :	(i)  - 
        :(s)      acct_inp_pack :	(l)  - 
        :(s)      acct_inp_oct :	(l)  - 
        :(s)      acct_inp_giga :	(l)  - 
        :(s)      acct_out_pack :	(l)  - 
        :(s)      acct_out_oct :	(l)  - 
        :(s)      acct_out_giga :	(l)  - 
        :(s)      acct_sess_time :	(l)  - 
        :(s)      acct_term_cause :	(i)  - 
        :(s)      total_cost :	(d)  - 
        """
        if not self.urfa_call(0x7000003b):
            raise Exception("Fail of urfa_call(0x7000003b) [rpcf_dealer_dhs_report]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'user_id' not in params: params['user_id'] = 0
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        if 'gid' not in params: params['gid'] = 0
        self.pck.add_data(params['gid'], U_TP_I)
        if 'apid' not in params: params['apid'] = 0
        self.pck.add_data(params['apid'], U_TP_I)
        self.pck.add_data(params['time_start'], U_TP_I)
        if 'time_end' not in params: params['time_end'] = now()
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['accounts_count'] = self.pck.get_data(U_TP_I)
        for j in range(ret['accounts_count']): 
            self.pck.recv(self.sck)
            ret['dhs_log_size'] = self.pck.get_data(U_TP_I)
            ret['dhs_log_size_array'][j]=ret['dhs_log_size']
            for i in range(ret['dhs_log_size']): 
                self.pck.recv(self.sck)
                if not j in ret['id']:ret['id'][j] = dict()
                ret['id'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['account_id']:ret['account_id'][j] = dict()
                ret['account_id'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['slink_id']:ret['slink_id'][j] = dict()
                ret['slink_id'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['recv_date']:ret['recv_date'][j] = dict()
                ret['recv_date'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['last_update_date']:ret['last_update_date'][j] = dict()
                ret['last_update_date'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['Called_Station_Id']:ret['Called_Station_Id'][j] = dict()
                ret['Called_Station_Id'][j][i] = self.pck.get_data(U_TP_S)
                if not j in ret['Calling_Station_Id']:ret['Calling_Station_Id'][j] = dict()
                ret['Calling_Station_Id'][j][i] = self.pck.get_data(U_TP_S)
                if not j in ret['framed_ip4']:ret['framed_ip4'][j] = dict()
                ret['framed_ip4'][j][i] = self.pck.get_data(U_TP_IP)
                if not j in ret['framed_ip6']:ret['framed_ip6'][j] = dict()
                ret['framed_ip6'][j][i] = self.pck.get_data(U_TP_IP)
                if not j in ret['nas_port']:ret['nas_port'][j] = dict()
                ret['nas_port'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['acct_session_id']:ret['acct_session_id'][j] = dict()
                ret['acct_session_id'][j][i] = self.pck.get_data(U_TP_S)
                if not j in ret['nas_port_type']:ret['nas_port_type'][j] = dict()
                ret['nas_port_type'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['uname']:ret['uname'][j] = dict()
                ret['uname'][j][i] = self.pck.get_data(U_TP_S)
                if not j in ret['service_type']:ret['service_type'][j] = dict()
                ret['service_type'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['framed_protocol']:ret['framed_protocol'][j] = dict()
                ret['framed_protocol'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['nas_ip']:ret['nas_ip'][j] = dict()
                ret['nas_ip'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['nas_id']:ret['nas_id'][j] = dict()
                ret['nas_id'][j][i] = self.pck.get_data(U_TP_S)
                if not j in ret['acct_status_type']:ret['acct_status_type'][j] = dict()
                ret['acct_status_type'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['acct_inp_pack']:ret['acct_inp_pack'][j] = dict()
                ret['acct_inp_pack'][j][i] = self.pck.get_data(U_TP_L)
                if not j in ret['acct_inp_oct']:ret['acct_inp_oct'][j] = dict()
                ret['acct_inp_oct'][j][i] = self.pck.get_data(U_TP_L)
                if not j in ret['acct_inp_giga']:ret['acct_inp_giga'][j] = dict()
                ret['acct_inp_giga'][j][i] = self.pck.get_data(U_TP_L)
                if not j in ret['acct_out_pack']:ret['acct_out_pack'][j] = dict()
                ret['acct_out_pack'][j][i] = self.pck.get_data(U_TP_L)
                if not j in ret['acct_out_oct']:ret['acct_out_oct'][j] = dict()
                ret['acct_out_oct'][j][i] = self.pck.get_data(U_TP_L)
                if not j in ret['acct_out_giga']:ret['acct_out_giga'][j] = dict()
                ret['acct_out_giga'][j][i] = self.pck.get_data(U_TP_L)
                if not j in ret['acct_sess_time']:ret['acct_sess_time'][j] = dict()
                ret['acct_sess_time'][j][i] = self.pck.get_data(U_TP_L)
                if not j in ret['acct_term_cause']:ret['acct_term_cause'][j] = dict()
                ret['acct_term_cause'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['total_cost']:ret['total_cost'][j] = dict()
                ret['total_cost'][j][i] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dhs_report_for_dealer(self, params):
        """ description
        @params: 
        :(s)  dealer_id :	(i)  - 
        :(s)  user_id :	(i) = _def_  - 
        :(s)  account_id :	(i) = _def_  - 
        :(s)  gid :	(i) = _def_  - 
        :(s)  apid :	(i) = _def_  - 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i) = _def_  - 
        @returns: 
        :(s)  accounts_count :	(i)  - 
        :(s)    dhs_log_size :	(i)  - 
        :(s)      id :	(i)  - 
        :(s)      account_id :	(i)  - 
        :(s)      slink_id :	(i)  - 
        :(s)      recv_date :	(i)  - 
        :(s)      last_update_date :	(i)  - 
        :(s)      Called_Station_Id :	(s)  - 
        :(s)      Calling_Station_Id :	(s)  - 
        :(s)      framed_ip :	(i)  - 
        :(s)      nas_port :	(i)  - 
        :(s)      acct_session_id :	(s)  - 
        :(s)      nas_port_type :	(i)  - 
        :(s)      uname :	(s)  - 
        :(s)      service_type :	(i)  - 
        :(s)      framed_protocol :	(i)  - 
        :(s)      nas_ip :	(i)  - 
        :(s)      nas_id :	(s)  - 
        :(s)      acct_status_type :	(i)  - 
        :(s)      acct_inp_pack :	(l)  - 
        :(s)      acct_inp_oct :	(l)  - 
        :(s)      acct_inp_giga :	(l)  - 
        :(s)      acct_out_pack :	(l)  - 
        :(s)      acct_out_oct :	(l)  - 
        :(s)      acct_out_giga :	(l)  - 
        :(s)      acct_sess_time :	(l)  - 
        :(s)      acct_term_cause :	(i)  - 
        :(s)      total_cost :	(d)  - 
        """
        if not self.urfa_call(0x13025):
            raise Exception("Fail of urfa_call(0x13025) [rpcf_dhs_report_for_dealer]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['dealer_id'], U_TP_I)
        if 'user_id' not in params: params['user_id'] = 0
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        if 'gid' not in params: params['gid'] = 0
        self.pck.add_data(params['gid'], U_TP_I)
        if 'apid' not in params: params['apid'] = 0
        self.pck.add_data(params['apid'], U_TP_I)
        self.pck.add_data(params['time_start'], U_TP_I)
        if 'time_end' not in params: params['time_end'] = now()
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['accounts_count'] = self.pck.get_data(U_TP_I)
        for j in range(ret['accounts_count']): 
            self.pck.recv(self.sck)
            ret['dhs_log_size'] = self.pck.get_data(U_TP_I)
            ret['dhs_log_size_array'][j]=ret['dhs_log_size']
            for i in range(ret['dhs_log_size']): 
                self.pck.recv(self.sck)
                if not j in ret['id']:ret['id'][j] = dict()
                ret['id'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['account_id']:ret['account_id'][j] = dict()
                ret['account_id'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['slink_id']:ret['slink_id'][j] = dict()
                ret['slink_id'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['recv_date']:ret['recv_date'][j] = dict()
                ret['recv_date'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['last_update_date']:ret['last_update_date'][j] = dict()
                ret['last_update_date'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['Called_Station_Id']:ret['Called_Station_Id'][j] = dict()
                ret['Called_Station_Id'][j][i] = self.pck.get_data(U_TP_S)
                if not j in ret['Calling_Station_Id']:ret['Calling_Station_Id'][j] = dict()
                ret['Calling_Station_Id'][j][i] = self.pck.get_data(U_TP_S)
                if not j in ret['framed_ip']:ret['framed_ip'][j] = dict()
                ret['framed_ip'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['nas_port']:ret['nas_port'][j] = dict()
                ret['nas_port'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['acct_session_id']:ret['acct_session_id'][j] = dict()
                ret['acct_session_id'][j][i] = self.pck.get_data(U_TP_S)
                if not j in ret['nas_port_type']:ret['nas_port_type'][j] = dict()
                ret['nas_port_type'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['uname']:ret['uname'][j] = dict()
                ret['uname'][j][i] = self.pck.get_data(U_TP_S)
                if not j in ret['service_type']:ret['service_type'][j] = dict()
                ret['service_type'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['framed_protocol']:ret['framed_protocol'][j] = dict()
                ret['framed_protocol'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['nas_ip']:ret['nas_ip'][j] = dict()
                ret['nas_ip'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['nas_id']:ret['nas_id'][j] = dict()
                ret['nas_id'][j][i] = self.pck.get_data(U_TP_S)
                if not j in ret['acct_status_type']:ret['acct_status_type'][j] = dict()
                ret['acct_status_type'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['acct_inp_pack']:ret['acct_inp_pack'][j] = dict()
                ret['acct_inp_pack'][j][i] = self.pck.get_data(U_TP_L)
                if not j in ret['acct_inp_oct']:ret['acct_inp_oct'][j] = dict()
                ret['acct_inp_oct'][j][i] = self.pck.get_data(U_TP_L)
                if not j in ret['acct_inp_giga']:ret['acct_inp_giga'][j] = dict()
                ret['acct_inp_giga'][j][i] = self.pck.get_data(U_TP_L)
                if not j in ret['acct_out_pack']:ret['acct_out_pack'][j] = dict()
                ret['acct_out_pack'][j][i] = self.pck.get_data(U_TP_L)
                if not j in ret['acct_out_oct']:ret['acct_out_oct'][j] = dict()
                ret['acct_out_oct'][j][i] = self.pck.get_data(U_TP_L)
                if not j in ret['acct_out_giga']:ret['acct_out_giga'][j] = dict()
                ret['acct_out_giga'][j][i] = self.pck.get_data(U_TP_L)
                if not j in ret['acct_sess_time']:ret['acct_sess_time'][j] = dict()
                ret['acct_sess_time'][j][i] = self.pck.get_data(U_TP_L)
                if not j in ret['acct_term_cause']:ret['acct_term_cause'][j] = dict()
                ret['acct_term_cause'][j][i] = self.pck.get_data(U_TP_I)
                if not j in ret['total_cost']:ret['total_cost'][j] = dict()
                ret['total_cost'][j][i] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_invoices_list_for_dealer(self, params):
        """ description
        @params: 
        :(s)  dealer_id :	(i)  - 
        :(s)  start_date :	(i)  - 
        :(s)  end_date :	(i)  - 
        @returns: 
        :(s)  count :	(i)  - 
        :(s)    invoice_id :	(i)  - 
        :(s)    ext_num :	(s)  - 
        :(s)    invoice_date :	(i)  - 
        :(s)    user_id :	(i)  - 
        :(s)    payment_transaction_id :	(i)  - 
        :(s)    expire_date :	(i)  - 
        :(s)    is_payed :	(i)  - 
        :(s)    is_printed :	(i)  - 
        :(s)    account_id :	(i)  - 
        :(s)    full_name :	(s)  - 
        :(s)    sum :	(d)  - 
        :(s)    tax :	(d)  - 
        :(s)    sum_with_tax :	(d)  - 
        """
        if not self.urfa_call(0x13026):
            raise Exception("Fail of urfa_call(0x13026) [rpcf_invoices_list_for_dealer]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['dealer_id'], U_TP_I)
        self.pck.add_data(params['start_date'], U_TP_I)
        self.pck.add_data(params['end_date'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['count']): 
            self.pck.recv(self.sck)
            ret['invoice_id'][i] = self.pck.get_data(U_TP_I)
            ret['ext_num'][i] = self.pck.get_data(U_TP_S)
            ret['invoice_date'][i] = self.pck.get_data(U_TP_I)
            ret['user_id'][i] = self.pck.get_data(U_TP_I)
            ret['payment_transaction_id'][i] = self.pck.get_data(U_TP_I)
            ret['expire_date'][i] = self.pck.get_data(U_TP_I)
            ret['is_payed'][i] = self.pck.get_data(U_TP_I)
            ret['is_printed'][i] = self.pck.get_data(U_TP_I)
            ret['account_id'][i] = self.pck.get_data(U_TP_I)
            ret['full_name'][i] = self.pck.get_data(U_TP_S)
            ret['sum'][i] = self.pck.get_data(U_TP_D)
            ret['tax'][i] = self.pck.get_data(U_TP_D)
            ret['sum_with_tax'][i] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_discount_periods(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  discount_periods_count :	(i)  - 
        :(s)    static_id :	(i)  - 
        :(s)    discount_period_id :	(i)  - 
        :(s)    start_date :	(i)  - 
        :(s)    end_date :	(i)  - 
        :(s)    periodic_type :	(i)  - 
        :(s)    custom_duration :	(i)  - 
        :(s)    next_discount_period_id :	(i)  - 
        :(s)    canonical_length :	(i)  - 
        """
        if not self.urfa_call(0x70000040):
            raise Exception("Fail of urfa_call(0x70000040) [rpcf_dealer_get_discount_periods]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['discount_periods_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['discount_periods_count']): 
            self.pck.recv(self.sck)
            ret['static_id'][i] = self.pck.get_data(U_TP_I)
            ret['discount_period_id'][i] = self.pck.get_data(U_TP_I)
            ret['start_date'][i] = self.pck.get_data(U_TP_I)
            ret['end_date'][i] = self.pck.get_data(U_TP_I)
            ret['periodic_type'][i] = self.pck.get_data(U_TP_I)
            ret['custom_duration'][i] = self.pck.get_data(U_TP_I)
            ret['next_discount_period_id'][i] = self.pck.get_data(U_TP_I)
            ret['canonical_length'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_core_time(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  time :	(i)  - 
        :(s)  tzname :	(s)  - 
        """
        if not self.urfa_call(0x70000046):
            raise Exception("Fail of urfa_call(0x70000046) [rpcf_dealer_get_core_time]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['time'] = self.pck.get_data(U_TP_I)
        ret['tzname'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_core_version(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  version_string :	(s)  - 
        """
        if not self.urfa_call(0x70000047):
            raise Exception("Fail of urfa_call(0x70000047) [rpcf_dealer_get_core_version]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['version_string'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_tariff_services_for_user(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  account_id :	(i)  - 
        :(s)  tplink_id :	(i)  - 
        @returns: 
        :(s)  services_array_size :	(i)  - 
        :(s)    service_id_array :	(i)  - 
        :(s)    service_name_array :	(s)  - 
        :(s)    service_type_array :	(i)  - 
        :(s)    service_comment_array :	(s)  - 
        :(s)    slink_id_array :	(i)  - 
        :(s)    is_linked_array :	(i)  - 
        """
        if not self.urfa_call(0x70000049):
            raise Exception("Fail of urfa_call(0x70000049) [rpcf_dealer_get_tariff_services_for_user]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['tplink_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['services_array_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['services_array_size']): 
            self.pck.recv(self.sck)
            ret['service_id_array'][i] = self.pck.get_data(U_TP_I)
            ret['service_name_array'][i] = self.pck.get_data(U_TP_S)
            ret['service_type_array'][i] = self.pck.get_data(U_TP_I)
            ret['service_comment_array'][i] = self.pck.get_data(U_TP_S)
            ret['slink_id_array'][i] = self.pck.get_data(U_TP_I)
            ret['is_linked_array'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_whoami(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  my_uid :	(i)  - 
        :(s)  login :	(s)  - 
        :(s)  user_ip :	(i)  - 
        :(s)  user_mask :	(i)  - 
        :(s)  system_group_size :	(i)  - 
        :(s)    system_group_id :	(i)  - 
        :(s)    system_group_name :	(s)  - 
        :(s)    system_group_info :	(s)  - 
        :(s)  allowed_fids_size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    name :	(s)  - 
        :(s)    module :	(s)  - 
        :(s)  not_allowed_fids_size :	(i)  - 
        :(s)    id_not_allowed :	(i)  - 
        :(s)    name_not_allowed :	(s)  - 
        :(s)    module_not_allowed :	(s)  - 
        :(s)  fullname :	(s)  - 
        :(s)  org_name :	(s)  - 
        """
        if not self.urfa_call(0x7000004a):
            raise Exception("Fail of urfa_call(0x7000004a) [rpcf_dealer_whoami]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['my_uid'] = self.pck.get_data(U_TP_I)
        ret['login'] = self.pck.get_data(U_TP_S)
        ret['user_ip'] = self.pck.get_data(U_TP_IP)
        ret['user_mask'] = self.pck.get_data(U_TP_IP)
        ret['system_group_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['system_group_size']): 
            self.pck.recv(self.sck)
            ret['system_group_id'][i] = self.pck.get_data(U_TP_I)
            ret['system_group_name'][i] = self.pck.get_data(U_TP_S)
            ret['system_group_info'][i] = self.pck.get_data(U_TP_S)
        self.pck.recv(self.sck)
        ret['allowed_fids_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['allowed_fids_size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['name'][i] = self.pck.get_data(U_TP_S)
            ret['module'][i] = self.pck.get_data(U_TP_S)
        self.pck.recv(self.sck)
        ret['not_allowed_fids_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['not_allowed_fids_size']): 
            self.pck.recv(self.sck)
            ret['id_not_allowed'][i] = self.pck.get_data(U_TP_I)
            ret['name_not_allowed'][i] = self.pck.get_data(U_TP_S)
            ret['module_not_allowed'][i] = self.pck.get_data(U_TP_S)
        self.pck.recv(self.sck)
        ret['fullname'] = self.pck.get_data(U_TP_S)
        ret['org_name'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_kbyte_size(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  kbyte_size :	(i)  - 
        """
        if not self.urfa_call(0x7000004b):
            raise Exception("Fail of urfa_call(0x7000004b) [rpcf_dealer_get_kbyte_size]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['kbyte_size'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_change_password_self(self, params):
        """ description
        @params: 
        :(s)  old_pass :	(s)  - 
        :(s)  new_pass :	(s)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x7000004f):
            raise Exception("Fail of urfa_call(0x7000004f) [rpcf_dealer_change_password_self]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['old_pass'], U_TP_S)
        self.pck.add_data(params['new_pass'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_entity_name_by_id(self, params):
        """ description
        @params: 
        :(s)  entity_type :	(i)  - 
        :(s)  entity_id :	(i)  - 
        @returns: 
        :(s)  entity_name :	(s)  - 
        """
        if not self.urfa_call(0x70000050):
            raise Exception("Fail of urfa_call(0x70000050) [rpcf_dealer_get_entity_name_by_id]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['entity_type'], U_TP_I)
        self.pck.add_data(params['entity_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['entity_name'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_switch_types_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    name :	(s)  - 
        :(s)    supp_volumes :	(s)  - 
        :(s)    tec_id_type :	(i)  - 
        :(s)    tec_id_len :	(i)  - 
        :(s)    tec_id_disp :	(i)  - 
        :(s)    tec_id_offset :	(i)  - 
        :(s)    port_id_type :	(i)  - 
        :(s)    port_id_len :	(i)  - 
        :(s)    port_id_disp :	(i)  - 
        :(s)    port_id_offset :	(i)  - 
        :(s)    vlan_id_type :	(i)  - 
        :(s)    vlan_id_len :	(i)  - 
        :(s)    vlan_id_disp :	(i)  - 
        :(s)    vlan_id_offset :	(i)  - 
        """
        if not self.urfa_call(0x7000006E):
            raise Exception("Fail of urfa_call(0x7000006E) [rpcf_dealer_get_switch_types_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['name'][i] = self.pck.get_data(U_TP_S)
            ret['supp_volumes'][i] = self.pck.get_data(U_TP_S)
            ret['tec_id_type'][i] = self.pck.get_data(U_TP_I)
            ret['tec_id_len'][i] = self.pck.get_data(U_TP_I)
            ret['tec_id_disp'][i] = self.pck.get_data(U_TP_I)
            ret['tec_id_offset'][i] = self.pck.get_data(U_TP_I)
            ret['port_id_type'][i] = self.pck.get_data(U_TP_I)
            ret['port_id_len'][i] = self.pck.get_data(U_TP_I)
            ret['port_id_disp'][i] = self.pck.get_data(U_TP_I)
            ret['port_id_offset'][i] = self.pck.get_data(U_TP_I)
            ret['vlan_id_type'][i] = self.pck.get_data(U_TP_I)
            ret['vlan_id_len'][i] = self.pck.get_data(U_TP_I)
            ret['vlan_id_disp'][i] = self.pck.get_data(U_TP_I)
            ret['vlan_id_offset'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_dhcp_pool_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    gateway :	(i)  - 
        :(s)    netmask :	(i)  - 
        :(s)    dns1_server :	(i)  - 
        :(s)    dns2_server :	(i)  - 
        :(s)    ntp_server :	(i)  - 
        :(s)    domain_name :	(s)  - 
        :(s)    block_action_type :	(i)  - 
        :(s)    lease_time :	(i)  - 
        :(s)    flags :	(i)  - 
        :(s)    ranges_size :	(i)  - 
        :(s)      range_last_addr :	(i)  - 
        :(s)      range_last_addr :	(i)  - 
        """
        if not self.urfa_call(0x7000006F):
            raise Exception("Fail of urfa_call(0x7000006F) [rpcf_dealer_get_dhcp_pool_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['gateway'][i] = self.pck.get_data(U_TP_IP)
            ret['netmask'][i] = self.pck.get_data(U_TP_IP)
            ret['dns1_server'][i] = self.pck.get_data(U_TP_IP)
            ret['dns2_server'][i] = self.pck.get_data(U_TP_IP)
            ret['ntp_server'][i] = self.pck.get_data(U_TP_IP)
            ret['domain_name'][i] = self.pck.get_data(U_TP_S)
            ret['block_action_type'][i] = self.pck.get_data(U_TP_I)
            ret['lease_time'][i] = self.pck.get_data(U_TP_I)
            ret['flags'][i] = self.pck.get_data(U_TP_I)
            ret['ranges_size'][i] = self.pck.get_data(U_TP_I)
            for ii in range(ret['ranges_size'][i]): 
                self.pck.recv(self.sck)
                if not i in ret['range_last_addr']:ret['range_last_addr'][i] = dict()
                ret['range_last_addr'][i][ii] = self.pck.get_data(U_TP_IP)
                if not i in ret['range_last_addr']:ret['range_last_addr'][i] = dict()
                ret['range_last_addr'][i][ii] = self.pck.get_data(U_TP_IP)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_switches_list(self, params):
        """ description
        @params: 
        :(s)  offset :	(i)  - 
        :(s)  count :	(i)  - 
        @returns: 
        :(s)  size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    name :	(s)  - 
        :(s)    location :	(s)  - 
        :(s)    type :	(i)  - 
        :(s)    ports_count :	(i)  - 
        :(s)    remote_id :	(s)  - 
        :(s)    address :	(i)  - 
        :(s)    login :	(s)  - 
        :(s)    password :	(s)  - 
        """
        if not self.urfa_call(0x70000070):
            raise Exception("Fail of urfa_call(0x70000070) [rpcf_dealer_get_switches_list]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['offset'], U_TP_I)
        self.pck.add_data(params['count'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['name'][i] = self.pck.get_data(U_TP_S)
            ret['location'][i] = self.pck.get_data(U_TP_S)
            ret['type'][i] = self.pck.get_data(U_TP_I)
            ret['ports_count'][i] = self.pck.get_data(U_TP_I)
            ret['remote_id'][i] = self.pck.get_data(U_TP_S)
            ret['address'][i] = self.pck.get_data(U_TP_IP)
            ret['login'][i] = self.pck.get_data(U_TP_S)
            ret['password'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_dealer_get_switch(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        @returns: 
        :(s)  id :	(i)  - 
        :(s)  name :	(s)  - 
        :(s)  location :	(s)  - 
        :(s)  type :	(i)  - 
        :(s)  ports_count :	(i)  - 
        :(s)  remote_id :	(s)  - 
        :(s)  address :	(i)  - 
        :(s)  login :	(s)  - 
        :(s)  password :	(s)  - 
        """
        if not self.urfa_call(0x70000071):
            raise Exception("Fail of urfa_call(0x70000071) [rpcf_dealer_get_switch]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['id'] = self.pck.get_data(U_TP_I)
        ret['name'] = self.pck.get_data(U_TP_S)
        ret['location'] = self.pck.get_data(U_TP_S)
        ret['type'] = self.pck.get_data(U_TP_I)
        ret['ports_count'] = self.pck.get_data(U_TP_I)
        ret['remote_id'] = self.pck.get_data(U_TP_S)
        ret['address'] = self.pck.get_data(U_TP_IP)
        ret['login'] = self.pck.get_data(U_TP_S)
        ret['password'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_shaping(self, params):
        """ description
        @params: 
        :(s)  service_id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        :(s)    flags :	(i)  - 
        :(s)    in_tclass_count :	(i)  - 
        :(s)      in_tclass_id_array :	(i)  - 
        :(s)    in_borders_count :	(i)  - 
        :(s)    in_timeranges_count :	(i)  - 
        :(s)      in_border_array :	(l)  - 
        :(s)        in_timerange_id_array :	(i)  - 
        :(s)        in_limits_array :	(i)  - 
        :(s)    out_tclass_count :	(i)  - 
        :(s)      out_tclass_id_array :	(i)  - 
        :(s)    out_borders_count :	(i)  - 
        :(s)    out_timeranges_count :	(i)  - 
        :(s)      out_border_array :	(l)  - 
        :(s)        out_timerange_id_array :	(i)  - 
        :(s)        out_limits_array :	(i)  - 
        :(s)    rad_count :	(i)  - 
        :(s)      rad_vendor :	(i)  - 
        :(s)      rad_attr :	(i)  - 
        :(s)      rad_type :	(i)  - 
        :(s)      rad_value :	(s)  - 
        :(s)    turbo_mode_service_id :	(i)  - 
        :(s)    turbo_mode_incoming_rate :	(i)  - 
        :(s)    turbo_mode_outgoing_rate :	(i)  - 
        :(s)    turbo_mode_duration :	(i)  - 
        :(s)    turbo_mode_acct_period_flag :	(i)  - 
        """
        if not self.urfa_call(0x1200a):
            raise Exception("Fail of urfa_call(0x1200a) [rpcf_get_shaping]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if ret['result']  ==  0:
            ret['flags'] = self.pck.get_data(U_TP_I)
            ret['in_tclass_count'] = self.pck.get_data(U_TP_I)
            for i in range(ret['in_tclass_count']): 
                self.pck.recv(self.sck)
                ret['in_tclass_id_array'][i] = self.pck.get_data(U_TP_I)
            self.pck.recv(self.sck)
            ret['in_borders_count'] = self.pck.get_data(U_TP_I)
            ret['in_timeranges_count'] = self.pck.get_data(U_TP_I)
            for i in range(ret['in_borders_count']): 
                self.pck.recv(self.sck)
                ret['in_border_array'][i] = self.pck.get_data(U_TP_L)
                for j in range(ret['in_timeranges_count']): 
                    self.pck.recv(self.sck)
                    ret['in_timerange_id_array'][j] = self.pck.get_data(U_TP_I)
                    if not i in ret['in_limits_array']:ret['in_limits_array'][i] = dict()
                    ret['in_limits_array'][i][j] = self.pck.get_data(U_TP_I)
            self.pck.recv(self.sck)
            ret['out_tclass_count'] = self.pck.get_data(U_TP_I)
            for i in range(ret['out_tclass_count']): 
                self.pck.recv(self.sck)
                ret['out_tclass_id_array'][i] = self.pck.get_data(U_TP_I)
            self.pck.recv(self.sck)
            ret['out_borders_count'] = self.pck.get_data(U_TP_I)
            ret['out_timeranges_count'] = self.pck.get_data(U_TP_I)
            for i in range(ret['out_borders_count']): 
                self.pck.recv(self.sck)
                ret['out_border_array'][i] = self.pck.get_data(U_TP_L)
                for j in range(ret['out_timeranges_count']): 
                    self.pck.recv(self.sck)
                    ret['out_timerange_id_array'][j] = self.pck.get_data(U_TP_I)
                    if not i in ret['out_limits_array']:ret['out_limits_array'][i] = dict()
                    ret['out_limits_array'][i][j] = self.pck.get_data(U_TP_I)
            self.pck.recv(self.sck)
            ret['rad_count'] = self.pck.get_data(U_TP_I)
            for i in range(ret['rad_count']): 
                self.pck.recv(self.sck)
                ret['rad_vendor'][i] = self.pck.get_data(U_TP_I)
                ret['rad_attr'][i] = self.pck.get_data(U_TP_I)
                ret['rad_type'][i] = self.pck.get_data(U_TP_I)
                ret['rad_value'][i] = self.pck.get_data(U_TP_S)
            self.pck.recv(self.sck)
            ret['turbo_mode_service_id'] = self.pck.get_data(U_TP_I)
            ret['turbo_mode_incoming_rate'] = self.pck.get_data(U_TP_I)
            ret['turbo_mode_outgoing_rate'] = self.pck.get_data(U_TP_I)
            ret['turbo_mode_duration'] = self.pck.get_data(U_TP_I)
            ret['turbo_mode_acct_period_flag'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_delete_shaping(self, params):
        """ description
        @params: 
        :(s)  service_id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x12005):
            raise Exception("Fail of urfa_call(0x12005) [rpcf_delete_shaping]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_shaped_services(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  svc_count :	(i)  - 
        :(s)    service_id_array :	(i)  - 
        :(s)    service_name_array :	(s)  - 
        :(s)    service_comment_array :	(s)  - 
        """
        if not self.urfa_call(0x12006):
            raise Exception("Fail of urfa_call(0x12006) [rpcf_get_shaped_services]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['svc_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['svc_count']): 
            self.pck.recv(self.sck)
            ret['service_id_array'][i] = self.pck.get_data(U_TP_I)
            ret['service_name_array'][i] = self.pck.get_data(U_TP_S)
            ret['service_comment_array'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_shaping(self, params):
        """ description
        @params: 
        :(s)  service_id :	(i)  - 
        :(s)  flags :	(i)  - 
        :(s)  in_tclass_count :	(i)  - 
        :(s)    in_tclass_id_array :	(i)  - 
        :(s)  in_borders_count :	(i)  - 
        :(s)  in_timeranges_count :	(i)  - 
        :(s)    in_border_array :	(l)  - 
        :(s)      in_timerange_id_array :	(i)  - 
        :(s)      in_limits_array :	(i)  - 
        :(s)  out_tclass_count :	(i)  - 
        :(s)    out_tclass_id_array :	(i)  - 
        :(s)  out_borders_count :	(i)  - 
        :(s)  out_timeranges_count :	(i)  - 
        :(s)    out_border_array :	(l)  - 
        :(s)      out_timerange_id_array :	(i)  - 
        :(s)      out_limits_array :	(i)  - 
        :(s)  rad_count :	(i)  - 
        :(s)    rad_vendor :	(i)  - 
        :(s)    rad_attr :	(i)  - 
        :(s)    rad_type :	(i)  - 
        :(s)    rad_value :	(s)  - 
        :(s)  turbo_mode_service_id :	(i)  - 
        :(s)  turbo_mode_incoming_rate :	(i)  - 
        :(s)  turbo_mode_outgoing_rate :	(i)  - 
        :(s)  turbo_mode_duration :	(i)  - 
        :(s)  turbo_mode_acct_period_flag :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x12007):
            raise Exception("Fail of urfa_call(0x12007) [rpcf_add_shaping]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.add_data(params['flags'], U_TP_I)
        self.pck.add_data(params['in_tclass_count'], U_TP_I)
        for i in range(params['in_tclass_count']):
            self.pck.add_data(params['in_tclass_id_array'][i], U_TP_I)
        self.pck.add_data(params['in_borders_count'], U_TP_I)
        self.pck.add_data(params['in_timeranges_count'], U_TP_I)
        for i in range(params['in_borders_count']):
            self.pck.add_data(params['in_border_array'][i], U_TP_L)
            for j in range(params['in_timeranges_count']):
                self.pck.add_data(params['in_timerange_id_array'][j], U_TP_I)
                self.pck.add_data(params['in_limits_array'][i][j], U_TP_I)
        self.pck.add_data(params['out_tclass_count'], U_TP_I)
        for i in range(params['out_tclass_count']):
            self.pck.add_data(params['out_tclass_id_array'][i], U_TP_I)
        self.pck.add_data(params['out_borders_count'], U_TP_I)
        self.pck.add_data(params['out_timeranges_count'], U_TP_I)
        for i in range(params['out_borders_count']):
            self.pck.add_data(params['out_border_array'][i], U_TP_L)
            for j in range(params['out_timeranges_count']):
                self.pck.add_data(params['out_timerange_id_array'][j], U_TP_I)
                self.pck.add_data(params['out_limits_array'][i][j], U_TP_I)
        self.pck.add_data(params['rad_count'], U_TP_I)
        for i in range(params['rad_count']):
            self.pck.add_data(params['rad_vendor'][i], U_TP_I)
            self.pck.add_data(params['rad_attr'][i], U_TP_I)
            self.pck.add_data(params['rad_type'][i], U_TP_I)
            self.pck.add_data(params['rad_value'][i], U_TP_S)
        self.pck.add_data(params['turbo_mode_service_id'], U_TP_I)
        self.pck.add_data(params['turbo_mode_incoming_rate'], U_TP_I)
        self.pck.add_data(params['turbo_mode_outgoing_rate'], U_TP_I)
        self.pck.add_data(params['turbo_mode_duration'], U_TP_I)
        self.pck.add_data(params['turbo_mode_acct_period_flag'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_shaping(self, params):
        """ description
        @params: 
        :(s)  service_id :	(i)  - 
        :(s)  flags :	(i)  - 
        :(s)  in_tclass_count :	(i)  - 
        :(s)    in_tclass_id_array :	(i)  - 
        :(s)  in_borders_count :	(i)  - 
        :(s)  in_timeranges_count :	(i)  - 
        :(s)    in_border_array :	(l)  - 
        :(s)      in_timerange_id_array :	(i)  - 
        :(s)      in_limits_array :	(i)  - 
        :(s)  out_tclass_count :	(i)  - 
        :(s)    out_tclass_id_array :	(i)  - 
        :(s)  out_borders_count :	(i)  - 
        :(s)  out_timeranges_count :	(i)  - 
        :(s)    out_border_array :	(l)  - 
        :(s)      out_timerange_id_array :	(i)  - 
        :(s)      out_limits_array :	(i)  - 
        :(s)  rad_count :	(i)  - 
        :(s)    rad_vendor :	(i)  - 
        :(s)    rad_attr :	(i)  - 
        :(s)    rad_type :	(i)  - 
        :(s)    rad_value :	(s)  - 
        :(s)  turbo_mode_service_id :	(i)  - 
        :(s)  turbo_mode_incoming_rate :	(i)  - 
        :(s)  turbo_mode_outgoing_rate :	(i)  - 
        :(s)  turbo_mode_duration :	(i)  - 
        :(s)  turbo_mode_acct_period_flag :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x12008):
            raise Exception("Fail of urfa_call(0x12008) [rpcf_edit_shaping]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.add_data(params['flags'], U_TP_I)
        self.pck.add_data(params['in_tclass_count'], U_TP_I)
        for i in range(params['in_tclass_count']):
            self.pck.add_data(params['in_tclass_id_array'][i], U_TP_I)
        self.pck.add_data(params['in_borders_count'], U_TP_I)
        self.pck.add_data(params['in_timeranges_count'], U_TP_I)
        for i in range(params['in_borders_count']):
            self.pck.add_data(params['in_border_array'][i], U_TP_L)
            for j in range(params['in_timeranges_count']):
                self.pck.add_data(params['in_timerange_id_array'][j], U_TP_I)
                self.pck.add_data(params['in_limits_array'][i][j], U_TP_I)
        self.pck.add_data(params['out_tclass_count'], U_TP_I)
        for i in range(params['out_tclass_count']):
            self.pck.add_data(params['out_tclass_id_array'][i], U_TP_I)
        self.pck.add_data(params['out_borders_count'], U_TP_I)
        self.pck.add_data(params['out_timeranges_count'], U_TP_I)
        for i in range(params['out_borders_count']):
            self.pck.add_data(params['out_border_array'][i], U_TP_L)
            for j in range(params['out_timeranges_count']):
                self.pck.add_data(params['out_timerange_id_array'][j], U_TP_I)
                self.pck.add_data(params['out_limits_array'][i][j], U_TP_I)
        self.pck.add_data(params['rad_count'], U_TP_I)
        for i in range(params['rad_count']):
            self.pck.add_data(params['rad_vendor'][i], U_TP_I)
            self.pck.add_data(params['rad_attr'][i], U_TP_I)
            self.pck.add_data(params['rad_type'][i], U_TP_I)
            self.pck.add_data(params['rad_value'][i], U_TP_S)
        self.pck.add_data(params['turbo_mode_service_id'], U_TP_I)
        self.pck.add_data(params['turbo_mode_incoming_rate'], U_TP_I)
        self.pck.add_data(params['turbo_mode_outgoing_rate'], U_TP_I)
        self.pck.add_data(params['turbo_mode_duration'], U_TP_I)
        self.pck.add_data(params['turbo_mode_acct_period_flag'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_slink_shaping(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i)  - 
        @returns: 
        :(s)  flags :	(i)  - 
        :(s)  incoming_rate :	(i)  - 
        :(s)  outgoing_rate :	(i)  - 
        :(s)  turbo_mode_start :	(i)  - 
        :(s)  turbo_mode_end :	(i)  - 
        """
        if not self.urfa_call(-0x12009):
            raise Exception("Fail of urfa_call(-0x12009) [rpcf_user5_get_slink_shaping]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['flags'] = self.pck.get_data(U_TP_I)
        ret['incoming_rate'] = self.pck.get_data(U_TP_I)
        ret['outgoing_rate'] = self.pck.get_data(U_TP_I)
        ret['turbo_mode_start'] = self.pck.get_data(U_TP_I)
        ret['turbo_mode_end'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_enable_turbo_mode(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(-0x1200a):
            raise Exception("Fail of urfa_call(-0x1200a) [rpcf_user5_enable_turbo_mode]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_turbo_mode_settings(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i)  - 
        @returns: 
        :(s)  incoming_rate :	(i)  - 
        :(s)  outgoing_rate :	(i)  - 
        :(s)  duration :	(i)  - 
        :(s)  cost :	(d)  - 
        """
        if not self.urfa_call(-0x1200b):
            raise Exception("Fail of urfa_call(-0x1200b) [rpcf_user5_get_turbo_mode_settings]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['incoming_rate'] = self.pck.get_data(U_TP_I)
        ret['outgoing_rate'] = self.pck.get_data(U_TP_I)
        ret['duration'] = self.pck.get_data(U_TP_I)
        ret['cost'] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_hotspot_sessions_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  sess_count :	(i)  - 
        :(s)    dhs_sess_id :	(i)  - 
        :(s)    nas_sess_id :	(s)  - 
        :(s)    web_sess_id :	(s)  - 
        :(s)    start_date :	(i)  - 
        :(s)    end_date :	(i)  - 
        :(s)    slink_id :	(i)  - 
        :(s)    ip :	(i)  - 
        :(s)    login :	(s)  - 
        :(s)    banalce :	(d)  - 
        """
        if not self.urfa_call(0x4308):
            raise Exception("Fail of urfa_call(0x4308) [rpcf_hotspot_sessions_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['sess_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['sess_count']): 
            self.pck.recv(self.sck)
            ret['dhs_sess_id'][i] = self.pck.get_data(U_TP_I)
            ret['nas_sess_id'][i] = self.pck.get_data(U_TP_S)
            ret['web_sess_id'][i] = self.pck.get_data(U_TP_S)
            ret['start_date'][i] = self.pck.get_data(U_TP_I)
            ret['end_date'][i] = self.pck.get_data(U_TP_I)
            ret['slink_id'][i] = self.pck.get_data(U_TP_I)
            ret['ip'][i] = self.pck.get_data(U_TP_I)
            ret['login'][i] = self.pck.get_data(U_TP_S)
            ret['banalce'][i] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_hotspot_networks(self, params):
        """ description
        @params: 
        :(s)  service_id :	(i)  - 
        @returns: 
        :(s)  cnt :	(i)  - 
        :(s)    ip :	(i)  - 
        :(s)    mask :	(i)  - 
        """
        if not self.urfa_call(0x10201):
            raise Exception("Fail of urfa_call(0x10201) [rpcf_get_hotspot_networks]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['cnt'] = self.pck.get_data(U_TP_I)
        for i in range(ret['cnt']): 
            self.pck.recv(self.sck)
            ret['ip'][i] = self.pck.get_data(U_TP_I)
            ret['mask'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_set_hotspot_networks(self, params):
        """ description
        @params: 
        :(s)  service_id :	(i)  - 
        :(s)  cnt :	(i)  - 
        :(s)    ip :	(i)  - 
        :(s)    mask :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x10202):
            raise Exception("Fail of urfa_call(0x10202) [rpcf_set_hotspot_networks]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.add_data(params['cnt'], U_TP_I)
        for i in range(params['cnt']):
            self.pck.add_data(params['ip'][i], U_TP_I)
            self.pck.add_data(params['mask'][i], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_fw_events(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  fw_events :	(l)  - 
        """
        if not self.urfa_call(0x0048):
            raise Exception("Fail of urfa_call(0x0048) [rpcf_get_fw_events]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['fw_events'] = self.pck.get_data(U_TP_L)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_fw_subst(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  subst_count :	(i)  - 
        :(s)    subst :	(s)  - 
        :(s)    events :	(l)  - 
        """
        if not self.urfa_call(0x0049):
            raise Exception("Fail of urfa_call(0x0049) [rpcf_get_fw_subst]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['subst_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['subst_count']): 
            self.pck.recv(self.sck)
            ret['subst'][i] = self.pck.get_data(U_TP_S)
            ret['events'][i] = self.pck.get_data(U_TP_L)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_edit_user(self, params):
        """ description
        @params: 
        :(s)  full_name :	(s)  - 
        :(s)  actual_address :	(s)  - 
        :(s)  juridical_address :	(s)  - 
        :(s)  work_telephone :	(s)  - 
        :(s)  home_telephone :	(s)  - 
        :(s)  mobile_telephone :	(s)  - 
        :(s)  web_page :	(s)  - 
        :(s)  icq_number :	(s)  - 
        :(s)  pasport :	(s)  - 
        :(s)  bank_id :	(i)  - 
        :(s)  bank_account :	(s)  - 
        :(s)  email :	(s)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(-0x4040):
            raise Exception("Fail of urfa_call(-0x4040) [rpcf_user5_edit_user]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['full_name'], U_TP_S)
        self.pck.add_data(params['actual_address'], U_TP_S)
        self.pck.add_data(params['juridical_address'], U_TP_S)
        self.pck.add_data(params['work_telephone'], U_TP_S)
        self.pck.add_data(params['home_telephone'], U_TP_S)
        self.pck.add_data(params['mobile_telephone'], U_TP_S)
        self.pck.add_data(params['web_page'], U_TP_S)
        self.pck.add_data(params['icq_number'], U_TP_S)
        self.pck.add_data(params['pasport'], U_TP_S)
        self.pck.add_data(params['bank_id'], U_TP_I)
        self.pck.add_data(params['bank_account'], U_TP_S)
        self.pck.add_data(params['email'], U_TP_S)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_user_info_new(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  user_id :	(i)  - 
        :(s)  login :	(s)  - 
        :(s)  basic_account :	(i)  - 
        :(s)  balance :	(d)  - 
        :(s)  credit :	(d)  - 
        :(s)  is_blocked :	(i)  - 
        :(s)  create_date :	(i)  - 
        :(s)  last_change_date :	(i)  - 
        :(s)  who_create :	(i)  - 
        :(s)  who_change :	(i)  - 
        :(s)  is_juridical :	(i)  - 
        :(s)  full_name :	(s)  - 
        :(s)  juridical_address :	(s)  - 
        :(s)  actual_address :	(s)  - 
        :(s)  work_telephone :	(s)  - 
        :(s)  home_telephone :	(s)  - 
        :(s)  mobile_telephone :	(s)  - 
        :(s)  web_page :	(s)  - 
        :(s)  icq_number :	(s)  - 
        :(s)  tax_number :	(s)  - 
        :(s)  kpp_number :	(s)  - 
        :(s)  bank_id :	(i)  - 
        :(s)  bank_account :	(s)  - 
        :(s)  int_status :	(i)  - 
        :(s)  vat_rate :	(d)  - 
        :(s)  pasport :	(s)  - 
        :(s)  locked_in_funds :	(d)  - 
        :(s)  email :	(s)  - 
        """
        if not self.urfa_call(-0x4052):
            raise Exception("Fail of urfa_call(-0x4052) [rpcf_user5_get_user_info_new]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['user_id'] = self.pck.get_data(U_TP_I)
        ret['login'] = self.pck.get_data(U_TP_S)
        ret['basic_account'] = self.pck.get_data(U_TP_I)
        ret['balance'] = self.pck.get_data(U_TP_D)
        ret['credit'] = self.pck.get_data(U_TP_D)
        ret['is_blocked'] = self.pck.get_data(U_TP_I)
        ret['create_date'] = self.pck.get_data(U_TP_I)
        ret['last_change_date'] = self.pck.get_data(U_TP_I)
        ret['who_create'] = self.pck.get_data(U_TP_I)
        ret['who_change'] = self.pck.get_data(U_TP_I)
        ret['is_juridical'] = self.pck.get_data(U_TP_I)
        ret['full_name'] = self.pck.get_data(U_TP_S)
        ret['juridical_address'] = self.pck.get_data(U_TP_S)
        ret['actual_address'] = self.pck.get_data(U_TP_S)
        ret['work_telephone'] = self.pck.get_data(U_TP_S)
        ret['home_telephone'] = self.pck.get_data(U_TP_S)
        ret['mobile_telephone'] = self.pck.get_data(U_TP_S)
        ret['web_page'] = self.pck.get_data(U_TP_S)
        ret['icq_number'] = self.pck.get_data(U_TP_S)
        ret['tax_number'] = self.pck.get_data(U_TP_S)
        ret['kpp_number'] = self.pck.get_data(U_TP_S)
        ret['bank_id'] = self.pck.get_data(U_TP_I)
        ret['bank_account'] = self.pck.get_data(U_TP_S)
        ret['int_status'] = self.pck.get_data(U_TP_I)
        ret['vat_rate'] = self.pck.get_data(U_TP_D)
        ret['pasport'] = self.pck.get_data(U_TP_S)
        ret['locked_in_funds'] = self.pck.get_data(U_TP_D)
        ret['email'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_invoice_data_new(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  full_name :	(s)  - 
        :(s)  actual_address :	(s)  - 
        :(s)  juridical_address :	(s)  - 
        :(s)  basic_account :	(i)  - 
        :(s)  payment_recv :	(s)  - 
        :(s)  inn :	(s)  - 
        :(s)  kpp :	(s)  - 
        :(s)  bank_account :	(s)  - 
        :(s)  bank_name :	(s)  - 
        :(s)  bank_city :	(s)  - 
        :(s)  bank_bic :	(s)  - 
        :(s)  bank_ks :	(s)  - 
        """
        if not self.urfa_call(-0x4041):
            raise Exception("Fail of urfa_call(-0x4041) [rpcf_user5_get_invoice_data_new]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['full_name'] = self.pck.get_data(U_TP_S)
        ret['actual_address'] = self.pck.get_data(U_TP_S)
        ret['juridical_address'] = self.pck.get_data(U_TP_S)
        ret['basic_account'] = self.pck.get_data(U_TP_I)
        ret['payment_recv'] = self.pck.get_data(U_TP_S)
        ret['inn'] = self.pck.get_data(U_TP_S)
        ret['kpp'] = self.pck.get_data(U_TP_S)
        ret['bank_account'] = self.pck.get_data(U_TP_S)
        ret['bank_name'] = self.pck.get_data(U_TP_S)
        ret['bank_city'] = self.pck.get_data(U_TP_S)
        ret['bank_bic'] = self.pck.get_data(U_TP_S)
        ret['bank_ks'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_set_ic_status(self, params):
        """ description
        @params: 
        :(s)  entity_type :	(i)  - 
        :(s)  entity_id :	(i)  - 
        :(s)  ic_status :	(i)  - 
        :(s)  ic_id :	(s)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x14006):
            raise Exception("Fail of urfa_call(0x14006) [rpcf_set_ic_status]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['entity_type'], U_TP_I)
        self.pck.add_data(params['entity_id'], U_TP_I)
        self.pck.add_data(params['ic_status'], U_TP_I)
        self.pck.add_data(params['ic_id'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_messages_list_new(self, params):
        """ description
        @params: 
        :(s)  time_start :	(l)  - 
        :(s)  time_end :	(l)  - 
        @returns: 
        :(s)  message_size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    send_date :	(i)  - 
        :(s)    sender_id :	(i)  - 
        :(s)    subject :	(s)  - 
        :(s)    mime :	(s)  - 
        :(s)    flag :	(i)  - 
        """
        if not self.urfa_call(0x500b):
            raise Exception("Fail of urfa_call(0x500b) [rpcf_get_messages_list_new]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['time_start'], U_TP_L)
        self.pck.add_data(params['time_end'], U_TP_L)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['message_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['message_size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['send_date'][i] = self.pck.get_data(U_TP_I)
            ret['sender_id'][i] = self.pck.get_data(U_TP_I)
            ret['subject'][i] = self.pck.get_data(U_TP_S)
            ret['mime'][i] = self.pck.get_data(U_TP_S)
            ret['flag'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_sent_messages_list(self, params):
        """ description
        @params: 
        :(s)  time_start :	(l)  - 
        :(s)  time_end :	(l)  - 
        @returns: 
        :(s)  message_size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    send_date :	(i)  - 
        :(s)    reciever_id :	(i)  - 
        :(s)    reciever_type :	(i)  - 
        :(s)    subject :	(s)  - 
        :(s)    mime :	(s)  - 
        :(s)    flag :	(i)  - 
        """
        if not self.urfa_call(0x500e):
            raise Exception("Fail of urfa_call(0x500e) [rpcf_get_sent_messages_list]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['time_start'], U_TP_L)
        self.pck.add_data(params['time_end'], U_TP_L)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['message_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['message_size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['send_date'][i] = self.pck.get_data(U_TP_I)
            ret['reciever_id'][i] = self.pck.get_data(U_TP_I)
            ret['reciever_type'][i] = self.pck.get_data(U_TP_I)
            ret['subject'][i] = self.pck.get_data(U_TP_S)
            ret['mime'][i] = self.pck.get_data(U_TP_S)
            ret['flag'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_sent_messages_list(self, params):
        """ description
        @params: 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i)  - 
        @returns: 
        :(s)  message_size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    send_date :	(i)  - 
        :(s)    subject :	(s)  - 
        """
        if not self.urfa_call(-0x4044):
            raise Exception("Fail of urfa_call(-0x4044) [rpcf_user5_get_sent_messages_list]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['time_start'], U_TP_I)
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['message_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['message_size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['send_date'][i] = self.pck.get_data(U_TP_I)
            ret['subject'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_message_new(self, params):
        """ description
        @params: 
        :(s)  receiver_id :	(i)  - 
        :(s)  receiver_type :	(i)  - 
        :(s)  subject :	(s)  - 
        :(s)  message :	(s)  - 
        :(s)  mime :	(s)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x500d):
            raise Exception("Fail of urfa_call(0x500d) [rpcf_add_message_new]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['receiver_id'], U_TP_I)
        self.pck.add_data(params['receiver_type'], U_TP_I)
        self.pck.add_data(params['subject'], U_TP_S)
        self.pck.add_data(params['message'], U_TP_S)
        self.pck.add_data(params['mime'], U_TP_S)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_message(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        @returns: 
        :(s)  subject :	(s)  - 
        :(s)  message :	(s)  - 
        :(s)  mime :	(s)  - 
        :(s)  send_date :	(i)  - 
        :(s)  sender_id :	(i)  - 
        :(s)  receiver_id :	(i)  - 
        :(s)  receiver_type :	(i)  - 
        """
        if not self.urfa_call(0x500c):
            raise Exception("Fail of urfa_call(0x500c) [rpcf_get_message]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['subject'] = self.pck.get_data(U_TP_S)
        ret['message'] = self.pck.get_data(U_TP_S)
        ret['mime'] = self.pck.get_data(U_TP_S)
        ret['send_date'] = self.pck.get_data(U_TP_I)
        ret['sender_id'] = self.pck.get_data(U_TP_I)
        ret['receiver_id'] = self.pck.get_data(U_TP_I)
        ret['receiver_type'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_messages_list(self, params):
        """ description
        @params: 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i)  - 
        @returns: 
        :(s)  messages_size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    send_date :	(i)  - 
        :(s)    sender_id :	(i)  - 
        :(s)    subject :	(s)  - 
        :(s)    mime :	(s)  - 
        :(s)    flag :	(i)  - 
        """
        if not self.urfa_call(-0x4043):
            raise Exception("Fail of urfa_call(-0x4043) [rpcf_user5_get_messages_list]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['time_start'], U_TP_I)
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['messages_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['messages_size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['send_date'][i] = self.pck.get_data(U_TP_I)
            ret['sender_id'][i] = self.pck.get_data(U_TP_I)
            ret['subject'][i] = self.pck.get_data(U_TP_S)
            ret['mime'][i] = self.pck.get_data(U_TP_S)
            ret['flag'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_new_messages_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  messages_size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    send_date :	(i)  - 
        :(s)    sender_id :	(i)  - 
        :(s)    subject :	(s)  - 
        :(s)    mime :	(s)  - 
        """
        if not self.urfa_call(-0x4046):
            raise Exception("Fail of urfa_call(-0x4046) [rpcf_user5_get_new_messages_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['messages_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['messages_size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['send_date'][i] = self.pck.get_data(U_TP_I)
            ret['sender_id'][i] = self.pck.get_data(U_TP_I)
            ret['subject'][i] = self.pck.get_data(U_TP_S)
            ret['mime'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_new_messages_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  messages_size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    send_date :	(i)  - 
        :(s)    sender_id :	(i)  - 
        :(s)    subject :	(s)  - 
        :(s)    mime :	(s)  - 
        :(s)    flag :	(i)  - 
        """
        if not self.urfa_call(0x500f):
            raise Exception("Fail of urfa_call(0x500f) [rpcf_get_new_messages_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['messages_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['messages_size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['send_date'][i] = self.pck.get_data(U_TP_I)
            ret['sender_id'][i] = self.pck.get_data(U_TP_I)
            ret['subject'][i] = self.pck.get_data(U_TP_S)
            ret['mime'][i] = self.pck.get_data(U_TP_S)
            ret['flag'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_message(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        @returns: 
        :(s)  subject :	(s)  - 
        :(s)  message :	(s)  - 
        :(s)  mime :	(s)  - 
        :(s)  send_date :	(i)  - 
        :(s)  sender_id :	(i)  - 
        """
        if not self.urfa_call(-0x4042):
            raise Exception("Fail of urfa_call(-0x4042) [rpcf_user5_get_message]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['subject'] = self.pck.get_data(U_TP_S)
        ret['message'] = self.pck.get_data(U_TP_S)
        ret['mime'] = self.pck.get_data(U_TP_S)
        ret['send_date'] = self.pck.get_data(U_TP_I)
        ret['sender_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_message_flag(self, params):
        """ description
        @params: 
        :(s)  message_id :	(i)  - 
        :(s)  flag :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x5030):
            raise Exception("Fail of urfa_call(0x5030) [rpcf_add_message_flag]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['message_id'], U_TP_I)
        self.pck.add_data(params['flag'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_remove_message_flag(self, params):
        """ description
        @params: 
        :(s)  message_id :	(i)  - 
        :(s)  flag :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x5031):
            raise Exception("Fail of urfa_call(0x5031) [rpcf_remove_message_flag]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['message_id'], U_TP_I)
        self.pck.add_data(params['flag'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_invoices_list(self, params):
        """ description
        @params: 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i)  - 
        @returns: 
        :(s)  currency_id :	(i)  - 
        :(s)  currency_name :	(s)  - 
        :(s)  accts_size :	(i)  - 
        :(s)    count_of_invoice :	(i)  - 
        :(s)      id :	(i)  - 
        :(s)      ext_num :	(s)  - 
        :(s)      invoice_date :	(i)  - 
        :(s)      is_payed :	(i)  - 
        :(s)      account_id :	(i)  - 
        :(s)      total_sum :	(d)  - 
        :(s)      total_tax :	(d)  - 
        :(s)      total_sum_plus_total_tax :	(d)  - 
        """
        if not self.urfa_call(-0x4047):
            raise Exception("Fail of urfa_call(-0x4047) [rpcf_user5_get_invoices_list]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['time_start'], U_TP_I)
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['currency_id'] = self.pck.get_data(U_TP_I)
        ret['currency_name'] = self.pck.get_data(U_TP_S)
        ret['accts_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['accts_size']): 
            self.pck.recv(self.sck)
            ret['count_of_invoice'] = self.pck.get_data(U_TP_I)
            ret['count_of_invoice_array'][i]=ret['count_of_invoice']
            for j in range(ret['count_of_invoice']): 
                self.pck.recv(self.sck)
                if not i in ret['id']:ret['id'][i] = dict()
                ret['id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['ext_num']:ret['ext_num'][i] = dict()
                ret['ext_num'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['invoice_date']:ret['invoice_date'][i] = dict()
                ret['invoice_date'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['is_payed']:ret['is_payed'][i] = dict()
                ret['is_payed'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['account_id']:ret['account_id'][i] = dict()
                ret['account_id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['total_sum']:ret['total_sum'][i] = dict()
                ret['total_sum'][i][j] = self.pck.get_data(U_TP_D)
                if not i in ret['total_tax']:ret['total_tax'][i] = dict()
                ret['total_tax'][i][j] = self.pck.get_data(U_TP_D)
                if not i in ret['total_sum_plus_total_tax']:ret['total_sum_plus_total_tax'][i] = dict()
                ret['total_sum_plus_total_tax'][i][j] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_traffic_aggregation_interval(self, params):
        """ description
        @params: 
        :(s)  service_id :	(i)  - 
        @returns: 
        :(s)  aggregation_interval :	(i)  - 
        """
        if not self.urfa_call(0x10203):
            raise Exception("Fail of urfa_call(0x10203) [rpcf_get_traffic_aggregation_interval]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['aggregation_interval'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_generate_doc(self, params):
        """ description
        @params: 
        :(s)  doc_type_id :	(i)  - 
        :(s)  base_id :	(i)  - 
        @returns: 
        :(s)  text_count :	(i)  - 
        :(s)    dynamic_text :	(s)  - 
        :(s)  landscape :	(i)  - 
        """
        if not self.urfa_call(-0x4048):
            raise Exception("Fail of urfa_call(-0x4048) [rpcf_user5_generate_doc]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['doc_type_id'], U_TP_I)
        self.pck.add_data(params['base_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['text_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['text_count']): 
            self.pck.recv(self.sck)
            ret['dynamic_text'][i] = self.pck.get_data(U_TP_S)
        self.pck.recv(self.sck)
        ret['landscape'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_set_traffic_aggregation_interval(self, params):
        """ description
        @params: 
        :(s)  service_id :	(i)  - 
        :(s)  aggregation_interval :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x10204):
            raise Exception("Fail of urfa_call(0x10204) [rpcf_set_traffic_aggregation_interval]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.add_data(params['aggregation_interval'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_change_int_status_for_account(self, params):
        """ description
        @params: 
        :(s)  account_id :	(i)  - 
        :(s)  int_status :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(-0x4049):
            raise Exception("Fail of urfa_call(-0x4049) [rpcf_user5_change_int_status_for_account]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['int_status'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_accounts_new(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  accounts_size :	(i)  - 
        :(s)    account_id :	(i)  - 
        :(s)    balance :	(d)  - 
        :(s)    credit :	(d)  - 
        :(s)    internet_status :	(i)  - 
        :(s)    block_status :	(i)  - 
        :(s)    vat_rate :	(d)  - 
        :(s)    locked_in_funds :	(d)  - 
        """
        if not self.urfa_call(-0x15028):
            raise Exception("Fail of urfa_call(-0x15028) [rpcf_user5_get_accounts_new]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['accounts_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['accounts_size']): 
            self.pck.recv(self.sck)
            ret['account_id'][i] = self.pck.get_data(U_TP_I)
            ret['balance'][i] = self.pck.get_data(U_TP_D)
            ret['credit'][i] = self.pck.get_data(U_TP_D)
            ret['internet_status'][i] = self.pck.get_data(U_TP_I)
            ret['block_status'][i] = self.pck.get_data(U_TP_I)
            ret['vat_rate'][i] = self.pck.get_data(U_TP_D)
            ret['locked_in_funds'][i] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_banks(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  banks_size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    bic :	(s)  - 
        :(s)    name :	(s)  - 
        :(s)    city :	(s)  - 
        :(s)    kschet :	(s)  - 
        """
        if not self.urfa_call(-0x4051):
            raise Exception("Fail of urfa_call(-0x4051) [rpcf_user5_get_banks]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['banks_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['banks_size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['bic'][i] = self.pck.get_data(U_TP_S)
            ret['name'][i] = self.pck.get_data(U_TP_S)
            ret['city'][i] = self.pck.get_data(U_TP_S)
            ret['kschet'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_generate_doc_for_user_new(self, params):
        """ description
        @params: 
        :(s)  doc_type_id :	(i)  - 
        :(s)  uid :	(i) = _def_  - 
        :(s)  base_id :	(i)  - 
        :(s)  doc_template_id :	(i) = _def_  - 
        @returns: 
        :(s)  doc_template_id :	(i)  - 
        :(s)  static_id :	(i)  - 
        :(s)    text_count :	(i)  - 
        :(s)      dynamic_text :	(s)  - 
        :(s)    dynamic_landscape :	(i)  - 
        :(s)    dynamic_id :	(i)  - 
        :(s)    text_count :	(i)  - 
        :(s)      static_text :	(s)  - 
        :(s)    static_landscape :	(i)  - 
        """
        if not self.urfa_call(0x7039):
            raise Exception("Fail of urfa_call(0x7039) [rpcf_generate_doc_for_user_new]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['doc_type_id'], U_TP_I)
        if 'uid' not in params: params['uid'] = 0
        self.pck.add_data(params['uid'], U_TP_I)
        self.pck.add_data(params['base_id'], U_TP_I)
        if 'doc_template_id' not in params: params['doc_template_id'] = 0
        self.pck.add_data(params['doc_template_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['doc_template_id'] = self.pck.get_data(U_TP_I)
        ret['static_id'] = self.pck.get_data(U_TP_I)
        if ret['static_id']  !=  0:
            ret['text_count'] = self.pck.get_data(U_TP_I)
            for i in range(ret['text_count']): 
                self.pck.recv(self.sck)
                ret['dynamic_text'][i] = self.pck.get_data(U_TP_S)
            self.pck.recv(self.sck)
            ret['dynamic_landscape'] = self.pck.get_data(U_TP_I)
        if ret['static_id']  ==  0:
            ret['dynamic_id'] = self.pck.get_data(U_TP_I)
            ret['text_count'] = self.pck.get_data(U_TP_I)
            for i in range(ret['text_count']): 
                self.pck.recv(self.sck)
                ret['static_text'][i] = self.pck.get_data(U_TP_S)
            self.pck.recv(self.sck)
            ret['static_landscape'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_doc_invoices_entries(self, params):
        """ description
        @params: 
        :(s)  invoice_id :	(i)  - 
        @returns: 
        :(s)  size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    invoice_id :	(i)  - 
        :(s)    accounting_period_id :	(i)  - 
        :(s)    slink_id :	(i)  - 
        :(s)    version :	(i)  - 
        :(s)    service_type :	(i)  - 
        :(s)    qnt :	(d)  - 
        :(s)    base_cost :	(d)  - 
        :(s)    sum_cost :	(d)  - 
        :(s)    tax_amount :	(d)  - 
        :(s)    name :	(s)  - 
        :(s)    det_size :	(i)  - 
        :(s)      type :	(i)  - 
        :(s)      value :	(i)  - 
        """
        if not self.urfa_call(0x7040):
            raise Exception("Fail of urfa_call(0x7040) [rpcf_get_doc_invoices_entries]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['invoice_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['invoice_id'][i] = self.pck.get_data(U_TP_I)
            ret['accounting_period_id'][i] = self.pck.get_data(U_TP_I)
            ret['slink_id'][i] = self.pck.get_data(U_TP_I)
            ret['version'][i] = self.pck.get_data(U_TP_I)
            ret['service_type'][i] = self.pck.get_data(U_TP_I)
            ret['qnt'][i] = self.pck.get_data(U_TP_D)
            ret['base_cost'][i] = self.pck.get_data(U_TP_D)
            ret['sum_cost'][i] = self.pck.get_data(U_TP_D)
            ret['tax_amount'][i] = self.pck.get_data(U_TP_D)
            ret['name'][i] = self.pck.get_data(U_TP_S)
            ret['det_size'][i] = self.pck.get_data(U_TP_I)
            for j in range(ret['det_size'][i]): 
                self.pck.recv(self.sck)
                if not i in ret['type']:ret['type'][i] = dict()
                ret['type'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['value']:ret['value'][i] = dict()
                ret['value'][i][j] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_reverse_invoice_entry(self, params):
        """ description
        @params: 
        :(s)  invoice_entry_id :	(i)  - 
        :(s)  new_summ :	(d)  - 
        :(s)  comment :	(s)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x7041):
            raise Exception("Fail of urfa_call(0x7041) [rpcf_reverse_invoice_entry]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['invoice_entry_id'], U_TP_I)
        self.pck.add_data(params['new_summ'], U_TP_D)
        self.pck.add_data(params['comment'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_delete_invoice(self, params):
        """ description
        @params: 
        :(s)  invoice_id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x7042):
            raise Exception("Fail of urfa_call(0x7042) [rpcf_delete_invoice]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['invoice_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_del_uaparam_new(self, params):
        """ description
        @params: 
        :(s)  uaparam_id :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x4411):
            raise Exception("Fail of urfa_call(0x4411) [rpcf_del_uaparam_new]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['uaparam_id'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_is_uaparam_in_use(self, params):
        """ description
        @params: 
        :(s)  uaparam_id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x4412):
            raise Exception("Fail of urfa_call(0x4412) [rpcf_is_uaparam_in_use]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['uaparam_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_user_contacts_new(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        @returns: 
        :(s)  size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    descr :	(s)  - 
        :(s)    reason :	(s)  - 
        :(s)    person :	(s)  - 
        :(s)    short_name :	(s)  - 
        :(s)    contact :	(s)  - 
        :(s)    email :	(s)  - 
        :(s)    id_exec_man :	(i)  - 
        """
        if not self.urfa_call(0x2040):
            raise Exception("Fail of urfa_call(0x2040) [rpcf_get_user_contacts_new]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['descr'][i] = self.pck.get_data(U_TP_S)
            ret['reason'][i] = self.pck.get_data(U_TP_S)
            ret['person'][i] = self.pck.get_data(U_TP_S)
            ret['short_name'][i] = self.pck.get_data(U_TP_S)
            ret['contact'][i] = self.pck.get_data(U_TP_S)
            ret['email'][i] = self.pck.get_data(U_TP_S)
            ret['id_exec_man'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_user_contact(self, params):
        """ description
        @params: 
        :(s)  cid :	(i)  - 
        @returns: 
        :(s)  descr :	(s)  - 
        :(s)  reason :	(s)  - 
        :(s)  person :	(s)  - 
        :(s)  short_name :	(s)  - 
        :(s)  contact :	(s)  - 
        :(s)  email :	(s)  - 
        :(s)  id_exec_man :	(i)  - 
        """
        if not self.urfa_call(0x2041):
            raise Exception("Fail of urfa_call(0x2041) [rpcf_get_user_contact]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['cid'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['descr'] = self.pck.get_data(U_TP_S)
        ret['reason'] = self.pck.get_data(U_TP_S)
        ret['person'] = self.pck.get_data(U_TP_S)
        ret['short_name'] = self.pck.get_data(U_TP_S)
        ret['contact'] = self.pck.get_data(U_TP_S)
        ret['email'] = self.pck.get_data(U_TP_S)
        ret['id_exec_man'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_user_contact(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  descr :	(s)  - 
        :(s)  reason :	(s)  - 
        :(s)  person :	(s)  - 
        :(s)  short_name :	(s)  - 
        :(s)  contact :	(s)  - 
        :(s)  email :	(s)  - 
        :(s)  id_exec_man :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x2042):
            raise Exception("Fail of urfa_call(0x2042) [rpcf_add_user_contact]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['descr'], U_TP_S)
        self.pck.add_data(params['reason'], U_TP_S)
        self.pck.add_data(params['person'], U_TP_S)
        self.pck.add_data(params['short_name'], U_TP_S)
        self.pck.add_data(params['contact'], U_TP_S)
        self.pck.add_data(params['email'], U_TP_S)
        self.pck.add_data(params['id_exec_man'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_user_contact(self, params):
        """ description
        @params: 
        :(s)  cid :	(i)  - 
        :(s)  descr :	(s)  - 
        :(s)  reason :	(s)  - 
        :(s)  person :	(s)  - 
        :(s)  short_name :	(s)  - 
        :(s)  contact :	(s)  - 
        :(s)  email :	(s)  - 
        :(s)  id_exec_man :	(i)  - 
        @returns: 
        :	True if success
        """
        if not self.urfa_call(0x2043):
            raise Exception("Fail of urfa_call(0x2043) [rpcf_edit_user_contact]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['cid'], U_TP_I)
        self.pck.add_data(params['descr'], U_TP_S)
        self.pck.add_data(params['reason'], U_TP_S)
        self.pck.add_data(params['person'], U_TP_S)
        self.pck.add_data(params['short_name'], U_TP_S)
        self.pck.add_data(params['contact'], U_TP_S)
        self.pck.add_data(params['email'], U_TP_S)
        self.pck.add_data(params['id_exec_man'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_generate_doc_new(self, params):
        """ description
        @params: 
        :(s)  doc_type_id :	(i)  - 
        :(s)  base_id :	(i)  - 
        @returns: 
        :(s)  text_count :	(i)  - 
        :(s)    dynamic_text :	(s)  - 
        :(s)  landscape :	(i)  - 
        """
        if not self.urfa_call(-0x4053):
            raise Exception("Fail of urfa_call(-0x4053) [rpcf_user5_generate_doc_new]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['doc_type_id'], U_TP_I)
        self.pck.add_data(params['base_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['text_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['text_count']): 
            self.pck.recv(self.sck)
            ret['dynamic_text'][i] = self.pck.get_data(U_TP_S)
        self.pck.recv(self.sck)
        ret['landscape'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_set_account_external_id(self, params):
        """ description
        @params: 
        :(s)  aid :	(i)  - 
        :(s)  external_id :	(s)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x2038):
            raise Exception("Fail of urfa_call(0x2038) [rpcf_set_account_external_id]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['aid'], U_TP_I)
        self.pck.add_data(params['external_id'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_account_external_id(self, params):
        """ description
        @params: 
        :(s)  aid :	(i)  - 
        @returns: 
        :(s)  external_id :	(s)  - 
        """
        if not self.urfa_call(0x2039):
            raise Exception("Fail of urfa_call(0x2039) [rpcf_get_account_external_id]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['aid'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['external_id'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_is_account_external_id_used(self, params):
        """ description
        @params: 
        :(s)  external_id :	(s)  - 
        @returns: 
        :(s)  aid :	(i)  - 
        """
        if not self.urfa_call(0x203a):
            raise Exception("Fail of urfa_call(0x203a) [rpcf_is_account_external_id_used]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['external_id'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['aid'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_change_account_balance(self, params):
        """ description
        @params: 
        :(s)  account_id :	(i)  - 
        :(s)  balance :	(d)  - 
        :(s)  comment :	(s)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x2045):
            raise Exception("Fail of urfa_call(0x2045) [rpcf_change_account_balance]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['balance'], U_TP_D)
        self.pck.add_data(params['comment'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_payments_report_new(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i) = _def_  - 
        :(s)  account_id :	(i)  - 
        :(s)  group_id :	(i) = _def_  - 
        :(s)  apid :	(i) = _def_  - 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i)  - 
        @returns: 
        :(s)  users_count :	(i)  - 
        :(s)    atr_size :	(i)  - 
        :(s)      id :	(i)  - 
        :(s)      account_id :	(i)  - 
        :(s)      login :	(s)  - 
        :(s)      actual_date :	(i)  - 
        :(s)      payment_enter_date :	(i)  - 
        :(s)      payment :	(d)  - 
        :(s)      payment_incurrency :	(d)  - 
        :(s)      currency_id :	(i)  - 
        :(s)      method :	(i)  - 
        :(s)      who_receved :	(i)  - 
        :(s)      admin_comment :	(s)  - 
        :(s)      payment_ext_number :	(s)  - 
        :(s)      full_name :	(s)  - 
        :(s)      acc_external_id :	(s)  - 
        :(s)      burnt_date :	(i)  - 
        """
        if not self.urfa_call(0x3030):
            raise Exception("Fail of urfa_call(0x3030) [rpcf_payments_report_new]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'user_id' not in params: params['user_id'] = 0
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['account_id'], U_TP_I)
        if 'group_id' not in params: params['group_id'] = 0
        self.pck.add_data(params['group_id'], U_TP_I)
        if 'apid' not in params: params['apid'] = 0
        self.pck.add_data(params['apid'], U_TP_I)
        self.pck.add_data(params['time_start'], U_TP_I)
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['users_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['users_count']): 
            self.pck.recv(self.sck)
            ret['atr_size'] = self.pck.get_data(U_TP_I)
            ret['atr_size_array'][i]=ret['atr_size']
            for j in range(ret['atr_size']): 
                self.pck.recv(self.sck)
                if not i in ret['id']:ret['id'][i] = dict()
                ret['id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['account_id']:ret['account_id'][i] = dict()
                ret['account_id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['login']:ret['login'][i] = dict()
                ret['login'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['actual_date']:ret['actual_date'][i] = dict()
                ret['actual_date'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['payment_enter_date']:ret['payment_enter_date'][i] = dict()
                ret['payment_enter_date'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['payment']:ret['payment'][i] = dict()
                ret['payment'][i][j] = self.pck.get_data(U_TP_D)
                if not i in ret['payment_incurrency']:ret['payment_incurrency'][i] = dict()
                ret['payment_incurrency'][i][j] = self.pck.get_data(U_TP_D)
                if not i in ret['currency_id']:ret['currency_id'][i] = dict()
                ret['currency_id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['method']:ret['method'][i] = dict()
                ret['method'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['who_receved']:ret['who_receved'][i] = dict()
                ret['who_receved'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['admin_comment']:ret['admin_comment'][i] = dict()
                ret['admin_comment'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['payment_ext_number']:ret['payment_ext_number'][i] = dict()
                ret['payment_ext_number'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['full_name']:ret['full_name'][i] = dict()
                ret['full_name'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['acc_external_id']:ret['acc_external_id'][i] = dict()
                ret['acc_external_id'][i][j] = self.pck.get_data(U_TP_S)
                if not i in ret['burnt_date']:ret['burnt_date'][i] = dict()
                ret['burnt_date'][i][j] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_switch_tariff_settings(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  count :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    group_id :	(i)  - 
        :(s)    priopity :	(i)  - 
        :(s)    is_enabled :	(i)  - 
        :(s)    instant_change :	(i)  - 
        :(s)    instant_change_count :	(i)  - 
        :(s)    tp_size :	(i)  - 
        :(s)      tp_id :	(i)  - 
        :(s)      min_balance :	(d)  - 
        :(s)      use_min_balance :	(i)  - 
        :(s)      free_balance :	(d)  - 
        :(s)      use_free_balance :	(i)  - 
        :(s)      service_id :	(i)  - 
        """
        if not self.urfa_call(0x15014):
            raise Exception("Fail of urfa_call(0x15014) [rpcf_get_switch_tariff_settings]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['count']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['group_id'][i] = self.pck.get_data(U_TP_I)
            ret['priopity'][i] = self.pck.get_data(U_TP_I)
            ret['is_enabled'][i] = self.pck.get_data(U_TP_I)
            ret['instant_change'][i] = self.pck.get_data(U_TP_I)
            ret['instant_change_count'][i] = self.pck.get_data(U_TP_I)
            ret['tp_size'] = self.pck.get_data(U_TP_I)
            ret['tp_size_array'][i]=ret['tp_size']
            for j in range(ret['tp_size']): 
                self.pck.recv(self.sck)
                if not i in ret['tp_id']:ret['tp_id'][i] = dict()
                ret['tp_id'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['min_balance']:ret['min_balance'][i] = dict()
                ret['min_balance'][i][j] = self.pck.get_data(U_TP_D)
                if not i in ret['use_min_balance']:ret['use_min_balance'][i] = dict()
                ret['use_min_balance'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['free_balance']:ret['free_balance'][i] = dict()
                ret['free_balance'][i][j] = self.pck.get_data(U_TP_D)
                if not i in ret['use_free_balance']:ret['use_free_balance'][i] = dict()
                ret['use_free_balance'][i][j] = self.pck.get_data(U_TP_I)
                if not i in ret['service_id']:ret['service_id'][i] = dict()
                ret['service_id'][i][j] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_switch_tariff_settings(self, params):
        """ description
        @params: 
        :(s)  group_id :	(i)  - 
        :(s)  priopity :	(i)  - 
        :(s)  is_enabled :	(i)  - 
        :(s)  instant_change :	(i)  - 
        :(s)  instant_change_count :	(i)  - 
        :(s)  tp_size :	(i)  - 
        :(s)    tp_id :	(i)  - 
        :(s)    min_balance :	(d)  - 
        :(s)    use_min_balance :	(i)  - 
        :(s)    free_balance :	(d)  - 
        :(s)    use_free_balance :	(i)  - 
        :(s)    service_id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x15015):
            raise Exception("Fail of urfa_call(0x15015) [rpcf_add_switch_tariff_settings]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['group_id'], U_TP_I)
        self.pck.add_data(params['priopity'], U_TP_I)
        self.pck.add_data(params['is_enabled'], U_TP_I)
        self.pck.add_data(params['instant_change'], U_TP_I)
        self.pck.add_data(params['instant_change_count'], U_TP_I)
        self.pck.add_data(params['tp_size'], U_TP_I)
        for i in range(params['tp_size']):
            self.pck.add_data(params['tp_id'][i], U_TP_I)
            self.pck.add_data(params['min_balance'][i], U_TP_D)
            self.pck.add_data(params['use_min_balance'][i], U_TP_I)
            self.pck.add_data(params['free_balance'][i], U_TP_D)
            self.pck.add_data(params['use_free_balance'][i], U_TP_I)
            self.pck.add_data(params['service_id'][i], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_switch_tariff_settings(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        :(s)  group_id :	(i)  - 
        :(s)  priopity :	(i)  - 
        :(s)  is_enabled :	(i)  - 
        :(s)  instant_change :	(i)  - 
        :(s)  instant_change_count :	(i)  - 
        :(s)  tp_size :	(i)  - 
        :(s)    tp_id :	(i)  - 
        :(s)    min_balance :	(d)  - 
        :(s)    use_min_balance :	(i)  - 
        :(s)    free_balance :	(d)  - 
        :(s)    use_free_balance :	(i)  - 
        :(s)    service_id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x15016):
            raise Exception("Fail of urfa_call(0x15016) [rpcf_edit_switch_tariff_settings]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['group_id'], U_TP_I)
        self.pck.add_data(params['priopity'], U_TP_I)
        self.pck.add_data(params['is_enabled'], U_TP_I)
        self.pck.add_data(params['instant_change'], U_TP_I)
        self.pck.add_data(params['instant_change_count'], U_TP_I)
        self.pck.add_data(params['tp_size'], U_TP_I)
        for i in range(params['tp_size']):
            self.pck.add_data(params['tp_id'][i], U_TP_I)
            self.pck.add_data(params['min_balance'][i], U_TP_D)
            self.pck.add_data(params['use_min_balance'][i], U_TP_I)
            self.pck.add_data(params['free_balance'][i], U_TP_D)
            self.pck.add_data(params['use_free_balance'][i], U_TP_I)
            self.pck.add_data(params['service_id'][i], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_delete_switch_tariff_settings(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x15003):
            raise Exception("Fail of urfa_call(0x15003) [rpcf_delete_switch_tariff_settings]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_voluntary_suspension_settings(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  count :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    group_id :	(i)  - 
        :(s)    priopity :	(i)  - 
        :(s)    is_enabled :	(i)  - 
        :(s)    min_duration :	(i)  - 
        :(s)    max_duration :	(i)  - 
        :(s)    interval_duration :	(i)  - 
        :(s)    block_type :	(i)  - 
        :(s)    self_unlock :	(i)  - 
        :(s)    min_balance :	(d)  - 
        :(s)    use_min_balance :	(i)  - 
        :(s)    free_balance :	(d)  - 
        :(s)    use_free_balance :	(i)  - 
        :(s)    service_id :	(i)  - 
        """
        if not self.urfa_call(0x15010):
            raise Exception("Fail of urfa_call(0x15010) [rpcf_get_voluntary_suspension_settings]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['count']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['group_id'][i] = self.pck.get_data(U_TP_I)
            ret['priopity'][i] = self.pck.get_data(U_TP_I)
            ret['is_enabled'][i] = self.pck.get_data(U_TP_I)
            ret['min_duration'][i] = self.pck.get_data(U_TP_I)
            ret['max_duration'][i] = self.pck.get_data(U_TP_I)
            ret['interval_duration'][i] = self.pck.get_data(U_TP_I)
            ret['block_type'][i] = self.pck.get_data(U_TP_I)
            ret['self_unlock'][i] = self.pck.get_data(U_TP_I)
            ret['min_balance'][i] = self.pck.get_data(U_TP_D)
            ret['use_min_balance'][i] = self.pck.get_data(U_TP_I)
            ret['free_balance'][i] = self.pck.get_data(U_TP_D)
            ret['use_free_balance'][i] = self.pck.get_data(U_TP_I)
            ret['service_id'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_voluntary_suspension_settings(self, params):
        """ description
        @params: 
        :(s)  group_id :	(i)  - 
        :(s)  priopity :	(i)  - 
        :(s)  is_enabled :	(i)  - 
        :(s)  min_duration :	(i)  - 
        :(s)  max_duration :	(i)  - 
        :(s)  interval_duration :	(i)  - 
        :(s)  block_type :	(i)  - 
        :(s)  self_unlock :	(i)  - 
        :(s)  min_balance :	(d)  - 
        :(s)  use_min_balance :	(i)  - 
        :(s)  free_balance :	(d)  - 
        :(s)  use_free_balance :	(i)  - 
        :(s)  service_id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x15011):
            raise Exception("Fail of urfa_call(0x15011) [rpcf_add_voluntary_suspension_settings]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['group_id'], U_TP_I)
        self.pck.add_data(params['priopity'], U_TP_I)
        self.pck.add_data(params['is_enabled'], U_TP_I)
        self.pck.add_data(params['min_duration'], U_TP_I)
        self.pck.add_data(params['max_duration'], U_TP_I)
        self.pck.add_data(params['interval_duration'], U_TP_I)
        self.pck.add_data(params['block_type'], U_TP_I)
        self.pck.add_data(params['self_unlock'], U_TP_I)
        self.pck.add_data(params['min_balance'], U_TP_D)
        self.pck.add_data(params['use_min_balance'], U_TP_I)
        self.pck.add_data(params['free_balance'], U_TP_D)
        self.pck.add_data(params['use_free_balance'], U_TP_I)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_voluntary_suspension_settings(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        :(s)  group_id :	(i)  - 
        :(s)  priopity :	(i)  - 
        :(s)  is_enabled :	(i)  - 
        :(s)  min_duration :	(i)  - 
        :(s)  max_duration :	(i)  - 
        :(s)  interval_duration :	(i)  - 
        :(s)  block_type :	(i)  - 
        :(s)  self_unlock :	(i)  - 
        :(s)  min_balance :	(d)  - 
        :(s)  use_min_balance :	(i)  - 
        :(s)  free_balance :	(d)  - 
        :(s)  use_free_balance :	(i)  - 
        :(s)  service_id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x15012):
            raise Exception("Fail of urfa_call(0x15012) [rpcf_edit_voluntary_suspension_settings]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['group_id'], U_TP_I)
        self.pck.add_data(params['priopity'], U_TP_I)
        self.pck.add_data(params['is_enabled'], U_TP_I)
        self.pck.add_data(params['min_duration'], U_TP_I)
        self.pck.add_data(params['max_duration'], U_TP_I)
        self.pck.add_data(params['interval_duration'], U_TP_I)
        self.pck.add_data(params['block_type'], U_TP_I)
        self.pck.add_data(params['self_unlock'], U_TP_I)
        self.pck.add_data(params['min_balance'], U_TP_D)
        self.pck.add_data(params['use_min_balance'], U_TP_I)
        self.pck.add_data(params['free_balance'], U_TP_D)
        self.pck.add_data(params['use_free_balance'], U_TP_I)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_delete_voluntary_suspension_settings(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x15013):
            raise Exception("Fail of urfa_call(0x15013) [rpcf_delete_voluntary_suspension_settings]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_promised_payment_settings(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  count :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    group_id :	(i)  - 
        :(s)    priopity :	(i)  - 
        :(s)    is_enabled :	(i)  - 
        :(s)    max_value :	(d)  - 
        :(s)    max_duration :	(i)  - 
        :(s)    interval_duration :	(i)  - 
        :(s)    min_balance :	(d)  - 
        :(s)    use_min_balance :	(i)  - 
        :(s)    free_balance :	(d)  - 
        :(s)    use_free_balance :	(i)  - 
        :(s)    service_id :	(i)  - 
        :(s)    flags :	(i)  - 
        """
        if not self.urfa_call(0x15034):
            raise Exception("Fail of urfa_call(0x15034) [rpcf_get_promised_payment_settings]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['count']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['group_id'][i] = self.pck.get_data(U_TP_I)
            ret['priopity'][i] = self.pck.get_data(U_TP_I)
            ret['is_enabled'][i] = self.pck.get_data(U_TP_I)
            ret['max_value'][i] = self.pck.get_data(U_TP_D)
            ret['max_duration'][i] = self.pck.get_data(U_TP_I)
            ret['interval_duration'][i] = self.pck.get_data(U_TP_I)
            ret['min_balance'][i] = self.pck.get_data(U_TP_D)
            ret['use_min_balance'][i] = self.pck.get_data(U_TP_I)
            ret['free_balance'][i] = self.pck.get_data(U_TP_D)
            ret['use_free_balance'][i] = self.pck.get_data(U_TP_I)
            ret['service_id'][i] = self.pck.get_data(U_TP_I)
            ret['flags'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_promised_payment_settings(self, params):
        """ description
        @params: 
        :(s)  group_id :	(i)  - 
        :(s)  priopity :	(i)  - 
        :(s)  is_enabled :	(i)  - 
        :(s)  max_value :	(d)  - 
        :(s)  max_duration :	(i)  - 
        :(s)  interval_duration :	(i)  - 
        :(s)  min_balance :	(d)  - 
        :(s)  use_min_balance :	(i)  - 
        :(s)  free_balance :	(d)  - 
        :(s)  use_free_balance :	(i)  - 
        :(s)  service_id :	(i)  - 
        :(s)  flags :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x15035):
            raise Exception("Fail of urfa_call(0x15035) [rpcf_add_promised_payment_settings]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['group_id'], U_TP_I)
        self.pck.add_data(params['priopity'], U_TP_I)
        self.pck.add_data(params['is_enabled'], U_TP_I)
        self.pck.add_data(params['max_value'], U_TP_D)
        self.pck.add_data(params['max_duration'], U_TP_I)
        self.pck.add_data(params['interval_duration'], U_TP_I)
        self.pck.add_data(params['min_balance'], U_TP_D)
        self.pck.add_data(params['use_min_balance'], U_TP_I)
        self.pck.add_data(params['free_balance'], U_TP_D)
        self.pck.add_data(params['use_free_balance'], U_TP_I)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.add_data(params['flags'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_promised_payment_settings(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        :(s)  group_id :	(i)  - 
        :(s)  priopity :	(i)  - 
        :(s)  is_enabled :	(i)  - 
        :(s)  max_value :	(d)  - 
        :(s)  max_duration :	(i)  - 
        :(s)  interval_duration :	(i)  - 
        :(s)  min_balance :	(d)  - 
        :(s)  use_min_balance :	(i)  - 
        :(s)  free_balance :	(d)  - 
        :(s)  use_free_balance :	(i)  - 
        :(s)  service_id :	(i)  - 
        :(s)  flags :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x15036):
            raise Exception("Fail of urfa_call(0x15036) [rpcf_edit_promised_payment_settings]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['group_id'], U_TP_I)
        self.pck.add_data(params['priopity'], U_TP_I)
        self.pck.add_data(params['is_enabled'], U_TP_I)
        self.pck.add_data(params['max_value'], U_TP_D)
        self.pck.add_data(params['max_duration'], U_TP_I)
        self.pck.add_data(params['interval_duration'], U_TP_I)
        self.pck.add_data(params['min_balance'], U_TP_D)
        self.pck.add_data(params['use_min_balance'], U_TP_I)
        self.pck.add_data(params['free_balance'], U_TP_D)
        self.pck.add_data(params['use_free_balance'], U_TP_I)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.add_data(params['flags'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_delete_promised_payment_settings(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x15023):
            raise Exception("Fail of urfa_call(0x15023) [rpcf_delete_promised_payment_settings]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_funds_flow_settings(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  count :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    group_id :	(i)  - 
        :(s)    priopity :	(i)  - 
        :(s)    is_enabled :	(i)  - 
        """
        if not self.urfa_call(0x15024):
            raise Exception("Fail of urfa_call(0x15024) [rpcf_get_funds_flow_settings]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['count']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['group_id'][i] = self.pck.get_data(U_TP_I)
            ret['priopity'][i] = self.pck.get_data(U_TP_I)
            ret['is_enabled'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_funds_flow_settings(self, params):
        """ description
        @params: 
        :(s)  group_id :	(i)  - 
        :(s)  priopity :	(i)  - 
        :(s)  is_enabled :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x15025):
            raise Exception("Fail of urfa_call(0x15025) [rpcf_add_funds_flow_settings]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['group_id'], U_TP_I)
        self.pck.add_data(params['priopity'], U_TP_I)
        self.pck.add_data(params['is_enabled'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_funds_flow_settings(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        :(s)  group_id :	(i)  - 
        :(s)  priopity :	(i)  - 
        :(s)  is_enabled :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x15026):
            raise Exception("Fail of urfa_call(0x15026) [rpcf_edit_funds_flow_settings]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['group_id'], U_TP_I)
        self.pck.add_data(params['priopity'], U_TP_I)
        self.pck.add_data(params['is_enabled'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_delete_funds_flow_settings(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x15027):
            raise Exception("Fail of urfa_call(0x15027) [rpcf_delete_funds_flow_settings]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_set_funds_flow(self, params):
        """ description
        @params: 
        :(s)  account_id_from :	(i)  - 
        :(s)  account_id_to :	(i)  - 
        :(s)  amount :	(d)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(-0x15007):
            raise Exception("Fail of urfa_call(-0x15007) [rpcf_user5_set_funds_flow]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['account_id_from'], U_TP_I)
        self.pck.add_data(params['account_id_to'], U_TP_I)
        self.pck.add_data(params['amount'], U_TP_D)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_funds_flow_report(self, params):
        """ description
        @params: 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i)  - 
        @returns: 
        :(s)  count :	(i)  - 
        :(s)    account_id_from :	(i)  - 
        :(s)    account_id_to :	(i)  - 
        :(s)    amount :	(d)  - 
        :(s)    date :	(i)  - 
        """
        if not self.urfa_call(-0x15009):
            raise Exception("Fail of urfa_call(-0x15009) [rpcf_user5_get_funds_flow_report]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['time_start'], U_TP_I)
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['count']): 
            self.pck.recv(self.sck)
            ret['account_id_from'][i] = self.pck.get_data(U_TP_I)
            ret['account_id_to'][i] = self.pck.get_data(U_TP_I)
            ret['amount'][i] = self.pck.get_data(U_TP_D)
            ret['date'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_funds_flow_report(self, params):
        """ description
        @params: 
        :(s)  time_start :	(i)  - 
        :(s)  time_end :	(i)  - 
        :(s)  uid :	(i)  - 
        @returns: 
        :(s)  count :	(i)  - 
        :(s)    account_id_from :	(i)  - 
        :(s)    account_id_to :	(i)  - 
        :(s)    amount :	(d)  - 
        :(s)    date :	(i)  - 
        :(s)    uid :	(i)  - 
        :(s)    login :	(s)  - 
        :(s)    full_name :	(s)  - 
        """
        if not self.urfa_call(0x501c):
            raise Exception("Fail of urfa_call(0x501c) [rpcf_get_funds_flow_report]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['time_start'], U_TP_I)
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.add_data(params['uid'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['count']): 
            self.pck.recv(self.sck)
            ret['account_id_from'][i] = self.pck.get_data(U_TP_I)
            ret['account_id_to'][i] = self.pck.get_data(U_TP_I)
            ret['amount'][i] = self.pck.get_data(U_TP_D)
            ret['date'][i] = self.pck.get_data(U_TP_I)
            ret['uid'][i] = self.pck.get_data(U_TP_I)
            ret['login'][i] = self.pck.get_data(U_TP_S)
            ret['full_name'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_tlink(self, params):
        """ description
        @params: 
        :(s)  account_id :	(i) = _def_  - 
        @returns: 
        :(s)  user_tariffs_size :	(i)  - 
        :(s)    tariff_link_id_array :	(i)  - 
        :(s)    tariff_current_array :	(i)  - 
        :(s)    tariff_current_name_array :	(s)  - 
        :(s)    tariff_current_comment_array :	(s)  - 
        :(s)    tariff_next_array :	(i)  - 
        :(s)    tariff_next_name_array :	(s)  - 
        :(s)    tariff_next_comment_array :	(s)  - 
        :(s)    discount_period_id_array :	(i)  - 
        :(s)    discount_period_start_array :	(i)  - 
        :(s)    discount_period_end_array :	(i)  - 
        """
        if not self.urfa_call(-0x15004):
            raise Exception("Fail of urfa_call(-0x15004) [rpcf_user5_get_tlink]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['user_tariffs_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['user_tariffs_size']): 
            self.pck.recv(self.sck)
            ret['tariff_link_id_array'][i] = self.pck.get_data(U_TP_I)
            ret['tariff_current_array'][i] = self.pck.get_data(U_TP_I)
            ret['tariff_current_name_array'][i] = self.pck.get_data(U_TP_S)
            ret['tariff_current_comment_array'][i] = self.pck.get_data(U_TP_S)
            ret['tariff_next_array'][i] = self.pck.get_data(U_TP_I)
            ret['tariff_next_name_array'][i] = self.pck.get_data(U_TP_S)
            ret['tariff_next_comment_array'][i] = self.pck.get_data(U_TP_S)
            ret['discount_period_id_array'][i] = self.pck.get_data(U_TP_I)
            ret['discount_period_start_array'][i] = self.pck.get_data(U_TP_I)
            ret['discount_period_end_array'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_next_tp(self, params):
        """ description
        @params: 
        :(s)  account_id :	(i) = _def_  - 
        :(s)  tp_link :	(i) = _def_  - 
        @returns: 
        :(s)  user_tariffs_size :	(i)  - 
        :(s)    tariff_id_array :	(i)  - 
        :(s)    tariff_name_array :	(s)  - 
        :(s)    tariff_comments_array :	(s)  - 
        :(s)    min_balance :	(d)  - 
        :(s)    use_min_balance :	(i)  - 
        :(s)    free_balance :	(d)  - 
        :(s)    use_free_balance :	(i)  - 
        :(s)    cost :	(d)  - 
        :(s)    can_change :	(i)  - 
        :(s)  balance :	(d)  - 
        """
        if not self.urfa_call(-0x15005):
            raise Exception("Fail of urfa_call(-0x15005) [rpcf_user5_get_next_tp]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        if 'tp_link' not in params: params['tp_link'] = 0
        self.pck.add_data(params['tp_link'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['user_tariffs_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['user_tariffs_size']): 
            self.pck.recv(self.sck)
            ret['tariff_id_array'][i] = self.pck.get_data(U_TP_I)
            ret['tariff_name_array'][i] = self.pck.get_data(U_TP_S)
            ret['tariff_comments_array'][i] = self.pck.get_data(U_TP_S)
            ret['min_balance'][i] = self.pck.get_data(U_TP_D)
            ret['use_min_balance'][i] = self.pck.get_data(U_TP_I)
            ret['free_balance'][i] = self.pck.get_data(U_TP_D)
            ret['use_free_balance'][i] = self.pck.get_data(U_TP_I)
            ret['cost'][i] = self.pck.get_data(U_TP_D)
            ret['can_change'][i] = self.pck.get_data(U_TP_I)
        self.pck.recv(self.sck)
        ret['balance'] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_set_next_tp(self, params):
        """ description
        @params: 
        :(s)  tp_link :	(i) = _def_  - 
        :(s)  tp_next :	(i) = _def_  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(-0x15006):
            raise Exception("Fail of urfa_call(-0x15006) [rpcf_user5_set_next_tp]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'tp_link' not in params: params['tp_link'] = 0
        self.pck.add_data(params['tp_link'], U_TP_I)
        if 'tp_next' not in params: params['tp_next'] = 0
        self.pck.add_data(params['tp_next'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_voluntary_blocking(self, params):
        """ description
        @params: 
        :(s)  account_id :	(i) = _def_  - 
        @returns: 
        :(s)  res :	(i)  - 
        :(s)    block_start :	(i)  - 
        :(s)    block_end :	(i)  - 
        :(s)    block_self_unlock :	(i)  - 
        :(s)    can_set :	(i)  - 
        :(s)    last_block_start :	(i)  - 
        :(s)    min_duration :	(i)  - 
        :(s)    max_duration :	(i)  - 
        :(s)    interval_duration :	(i)  - 
        :(s)    block_type :	(i)  - 
        :(s)    min_balance :	(d)  - 
        :(s)    use_min_balance :	(i)  - 
        :(s)    free_balance :	(d)  - 
        :(s)    use_free_balance :	(i)  - 
        :(s)    self_unlock :	(i)  - 
        :(s)    cost :	(d)  - 
        :(s)    balance :	(d)  - 
        """
        if not self.urfa_call(-0x15014):
            raise Exception("Fail of urfa_call(-0x15014) [rpcf_user5_get_voluntary_blocking]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['res'] = self.pck.get_data(U_TP_I)
        if ret['res']  ==  1:
            ret['block_start'] = self.pck.get_data(U_TP_I)
            ret['block_end'] = self.pck.get_data(U_TP_I)
            ret['block_self_unlock'] = self.pck.get_data(U_TP_I)
        if ret['res']  ==  0:
            ret['can_set'] = self.pck.get_data(U_TP_I)
            ret['last_block_start'] = self.pck.get_data(U_TP_I)
            ret['min_duration'] = self.pck.get_data(U_TP_I)
            ret['max_duration'] = self.pck.get_data(U_TP_I)
            ret['interval_duration'] = self.pck.get_data(U_TP_I)
            ret['block_type'] = self.pck.get_data(U_TP_I)
            ret['min_balance'] = self.pck.get_data(U_TP_D)
            ret['use_min_balance'] = self.pck.get_data(U_TP_I)
            ret['free_balance'] = self.pck.get_data(U_TP_D)
            ret['use_free_balance'] = self.pck.get_data(U_TP_I)
            ret['self_unlock'] = self.pck.get_data(U_TP_I)
            ret['cost'] = self.pck.get_data(U_TP_D)
            ret['balance'] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_set_voluntary_blocking(self, params):
        """ description
        @params: 
        :(s)  account_id :	(i) = _def_  - 
        :(s)  block_start :	(i)  - 
        :(s)  block_end :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(-0x15015):
            raise Exception("Fail of urfa_call(-0x15015) [rpcf_user5_set_voluntary_blocking]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['block_start'], U_TP_I)
        self.pck.add_data(params['block_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_delete_voluntary_blocking(self, params):
        """ description
        @params: 
        :(s)  account_id :	(i) = _def_  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(-0x15016):
            raise Exception("Fail of urfa_call(-0x15016) [rpcf_user5_delete_voluntary_blocking]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_promised_payment(self, params):
        """ description
        @params: 
        :(s)  account_id :	(i) = _def_  - 
        @returns: 
        :(s)  res :	(i)  - 
        :(s)    last_payment_date :	(i)  - 
        :(s)    amount :	(d)  - 
        :(s)    duration :	(i)  - 
        :(s)    interval_duration :	(i)  - 
        :(s)    cost :	(d)  - 
        :(s)    min_balance :	(d)  - 
        :(s)    use_min_balance :	(i)  - 
        :(s)    free_balance :	(d)  - 
        :(s)    use_free_balance :	(i)  - 
        :(s)    balance :	(d)  - 
        :(s)    flags :	(i)  - 
        """
        if not self.urfa_call(-0x15031):
            raise Exception("Fail of urfa_call(-0x15031) [rpcf_user5_get_promised_payment]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['res'] = self.pck.get_data(U_TP_I)
        if ret['res']  !=  -1:
            ret['last_payment_date'] = self.pck.get_data(U_TP_I)
            ret['amount'] = self.pck.get_data(U_TP_D)
            ret['duration'] = self.pck.get_data(U_TP_I)
            ret['interval_duration'] = self.pck.get_data(U_TP_I)
            ret['cost'] = self.pck.get_data(U_TP_D)
            ret['min_balance'] = self.pck.get_data(U_TP_D)
            ret['use_min_balance'] = self.pck.get_data(U_TP_I)
            ret['free_balance'] = self.pck.get_data(U_TP_D)
            ret['use_free_balance'] = self.pck.get_data(U_TP_I)
            ret['balance'] = self.pck.get_data(U_TP_D)
            ret['flags'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_set_promised_payment(self, params):
        """ description
        @params: 
        :(s)  account_id :	(i) = _def_  - 
        :(s)  value :	(d)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(-0x15025):
            raise Exception("Fail of urfa_call(-0x15025) [rpcf_user5_set_promised_payment]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['value'], U_TP_D)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_tariff_new(self, params):
        """ description
        @params: 
        :(s)  tariff_id :	(i)  - 
        @returns: 
        :(s)  tariff_name :	(s)  - 
        :(s)  tariff_create_date :	(i)  - 
        :(s)  who_create :	(i)  - 
        :(s)  who_create_login :	(s)  - 
        :(s)  tariff_change_date :	(i)  - 
        :(s)  who_change :	(i)  - 
        :(s)  who_change_login :	(s)  - 
        :(s)  tariff_balance_rollover :	(i)  - 
        :(s)  comments :	(s)  - 
        :(s)  services_count :	(i)  - 
        :(s)    service_id_array :	(i)  - 
        :(s)    service_type_array :	(i)  - 
        :(s)    service_name_array :	(s)  - 
        :(s)    comment_array :	(s)  - 
        :(s)    link_by_default_array :	(i)  - 
        :(s)    is_dynamic_array :	(i)  - 
        """
        if not self.urfa_call(0x3040):
            raise Exception("Fail of urfa_call(0x3040) [rpcf_get_tariff_new]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['tariff_name'] = self.pck.get_data(U_TP_S)
        ret['tariff_create_date'] = self.pck.get_data(U_TP_I)
        ret['who_create'] = self.pck.get_data(U_TP_I)
        ret['who_create_login'] = self.pck.get_data(U_TP_S)
        ret['tariff_change_date'] = self.pck.get_data(U_TP_I)
        ret['who_change'] = self.pck.get_data(U_TP_I)
        ret['who_change_login'] = self.pck.get_data(U_TP_S)
        ret['tariff_balance_rollover'] = self.pck.get_data(U_TP_I)
        ret['comments'] = self.pck.get_data(U_TP_S)
        ret['services_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['services_count']): 
            self.pck.recv(self.sck)
            ret['service_id_array'][i] = self.pck.get_data(U_TP_I)
            ret['service_type_array'][i] = self.pck.get_data(U_TP_I)
            ret['service_name_array'][i] = self.pck.get_data(U_TP_S)
            ret['comment_array'][i] = self.pck.get_data(U_TP_S)
            ret['link_by_default_array'][i] = self.pck.get_data(U_TP_I)
            ret['is_dynamic_array'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_tariff_new(self, params):
        """ description
        @params: 
        :(s)  name :	(s)  - 
        :(s)  balance_rollover :	(i)  - 
        :(s)  comments :	(s)  - 
        @returns: 
        :(s)  tp_id :	(i)  - 
        """
        if not self.urfa_call(0x3041):
            raise Exception("Fail of urfa_call(0x3041) [rpcf_add_tariff_new]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.add_data(params['balance_rollover'], U_TP_I)
        self.pck.add_data(params['comments'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['tp_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_tariff_new(self, params):
        """ description
        @params: 
        :(s)  tp_id :	(i)  - 
        :(s)  name :	(s)  - 
        :(s)  balance_rollover :	(i)  - 
        :(s)  comments :	(s)  - 
        @returns: 
        :(s)  tp_id :	(i)  - 
        """
        if not self.urfa_call(0x3042):
            raise Exception("Fail of urfa_call(0x3042) [rpcf_edit_tariff_new]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['tp_id'], U_TP_I)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.add_data(params['balance_rollover'], U_TP_I)
        self.pck.add_data(params['comments'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['tp_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_once_service_ex(self, params):
        """ description
        @params: 
        :(s)  parent_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  drop_from_group :	(i)  - 
        @returns: 
        :(s)  service_id :	(i)  - 
        """
        if not self.urfa_call(0x1300):
            raise Exception("Fail of urfa_call(0x1300) [rpcf_add_once_service_ex]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['parent_id'], U_TP_I)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.add_data(params['service_name'], U_TP_S)
        self.pck.add_data(params['comment'], U_TP_S)
        self.pck.add_data(params['link_by_default'], U_TP_I)
        self.pck.add_data(params['cost'], U_TP_D)
        self.pck.add_data(params['drop_from_group'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['service_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_once_service_ex(self, params):
        """ description
        @params: 
        :(s)  service_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  drop_from_group :	(i)  - 
        @returns: 
        :(s)  service_id :	(i)  - 
        """
        if not self.urfa_call(0x1301):
            raise Exception("Fail of urfa_call(0x1301) [rpcf_edit_once_service_ex]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.add_data(params['parent_id'], U_TP_I)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.add_data(params['service_name'], U_TP_S)
        self.pck.add_data(params['comment'], U_TP_S)
        self.pck.add_data(params['link_by_default'], U_TP_I)
        self.pck.add_data(params['cost'], U_TP_D)
        self.pck.add_data(params['drop_from_group'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['service_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_periodic_service_ex(self, params):
        """ description
        @params: 
        :(s)  parent_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  discount_method :	(i)  - 
        @returns: 
        :(s)  service_id :	(i)  - 
        """
        if not self.urfa_call(0x1302):
            raise Exception("Fail of urfa_call(0x1302) [rpcf_add_periodic_service_ex]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['parent_id'], U_TP_I)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.add_data(params['service_name'], U_TP_S)
        self.pck.add_data(params['comment'], U_TP_S)
        self.pck.add_data(params['link_by_default'], U_TP_I)
        self.pck.add_data(params['cost'], U_TP_D)
        self.pck.add_data(params['discount_method'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['service_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_periodic_service_ex(self, params):
        """ description
        @params: 
        :(s)  service_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  discount_method :	(i)  - 
        @returns: 
        :(s)  service_id :	(i)  - 
        """
        if not self.urfa_call(0x1303):
            raise Exception("Fail of urfa_call(0x1303) [rpcf_edit_periodic_service_ex]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.add_data(params['parent_id'], U_TP_I)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.add_data(params['service_name'], U_TP_S)
        self.pck.add_data(params['comment'], U_TP_S)
        self.pck.add_data(params['link_by_default'], U_TP_I)
        self.pck.add_data(params['cost'], U_TP_D)
        self.pck.add_data(params['discount_method'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['service_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_iptraffic_service_ex(self, params):
        """ description
        @params: 
        :(s)  parent_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  is_dynamic :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  discount_method :	(i)  - 
        :(s)  sessions_limit :	(i)  - 
        :(s)  null_service_prepaid :	(i)  - 
        :(s)  num_of_borders :	(i) = _def_  - 
        :(s)    tclass_b :	(i)  - 
        :(s)    size_b :	(l)  - 
        :(s)    cost_b :	(d)  - 
        :(s)  num_of_prepaid :	(i) = _def_  - 
        :(s)    tclass_p :	(i)  - 
        :(s)    size_p :	(l)  - 
        :(s)    size_max_p :	(l)  - 
        :(s)  num_of_groups :	(i) = _def_  - 
        :(s)    tcid :	(i)  - 
        :(s)    gid :	(i)  - 
        @returns: 
        :(s)  service_id :	(i)  - 
        """
        if not self.urfa_call(0x1310):
            raise Exception("Fail of urfa_call(0x1310) [rpcf_add_iptraffic_service_ex]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['parent_id'], U_TP_I)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.add_data(params['service_name'], U_TP_S)
        self.pck.add_data(params['comment'], U_TP_S)
        self.pck.add_data(params['link_by_default'], U_TP_I)
        self.pck.add_data(params['is_dynamic'], U_TP_I)
        self.pck.add_data(params['cost'], U_TP_D)
        self.pck.add_data(params['discount_method'], U_TP_I)
        self.pck.add_data(params['sessions_limit'], U_TP_I)
        self.pck.add_data(params['null_service_prepaid'], U_TP_I)
        if 'num_of_borders' not in params: params['num_of_borders'] = len(params['tclass_b'])
        self.pck.add_data(params['num_of_borders'], U_TP_I)
        for i in range(len(params['tclass_b'])):
            self.pck.add_data(params['tclass_b'][i], U_TP_I)
            self.pck.add_data(params['size_b'][i], U_TP_L)
            self.pck.add_data(params['cost_b'][i], U_TP_D)
        if 'num_of_prepaid' not in params: params['num_of_prepaid'] = len(params['tclass_p'])
        self.pck.add_data(params['num_of_prepaid'], U_TP_I)
        for i in range(len(params['tclass_p'])):
            self.pck.add_data(params['tclass_p'][i], U_TP_I)
            self.pck.add_data(params['size_p'][i], U_TP_L)
            self.pck.add_data(params['size_max_p'][i], U_TP_L)
        if 'num_of_groups' not in params: params['num_of_groups'] = len(params['tcid'])
        self.pck.add_data(params['num_of_groups'], U_TP_I)
        for i in range(len(params['tcid'])):
            self.pck.add_data(params['tcid'][i], U_TP_I)
            self.pck.add_data(params['gid'][i], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['service_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_iptraffic_service_ex(self, params):
        """ description
        @params: 
        :(s)  service_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  is_dynamic :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  discount_method_t :	(i)  - 
        :(s)  sessions_limit :	(i)  - 
        :(s)  null_service_prepaid :	(i)  - 
        :(s)  num_of_borders :	(i) = _def_  - 
        :(s)    tclass_b :	(i)  - 
        :(s)    size_b :	(l)  - 
        :(s)    cost_b :	(d)  - 
        :(s)  num_of_prepaid :	(i) = _def_  - 
        :(s)    tclass_p :	(i)  - 
        :(s)    size_p :	(l)  - 
        :(s)    size_max_p :	(l)  - 
        :(s)  num_of_groups :	(i) = _def_  - 
        :(s)    tcid :	(i)  - 
        :(s)    gid :	(i)  - 
        @returns: 
        :(s)  service_id :	(i)  - 
        """
        if not self.urfa_call(0x1311):
            raise Exception("Fail of urfa_call(0x1311) [rpcf_edit_iptraffic_service_ex]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.add_data(params['parent_id'], U_TP_I)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.add_data(params['service_name'], U_TP_S)
        self.pck.add_data(params['comment'], U_TP_S)
        self.pck.add_data(params['link_by_default'], U_TP_I)
        self.pck.add_data(params['is_dynamic'], U_TP_I)
        self.pck.add_data(params['cost'], U_TP_D)
        self.pck.add_data(params['discount_method_t'], U_TP_I)
        self.pck.add_data(params['sessions_limit'], U_TP_I)
        self.pck.add_data(params['null_service_prepaid'], U_TP_I)
        if 'num_of_borders' not in params: params['num_of_borders'] = len(params['tclass_b'])
        self.pck.add_data(params['num_of_borders'], U_TP_I)
        for i in range(len(params['tclass_b'])):
            self.pck.add_data(params['tclass_b'][i], U_TP_I)
            self.pck.add_data(params['size_b'][i], U_TP_L)
            self.pck.add_data(params['cost_b'][i], U_TP_D)
        if 'num_of_prepaid' not in params: params['num_of_prepaid'] = len(params['tclass_p'])
        self.pck.add_data(params['num_of_prepaid'], U_TP_I)
        for i in range(len(params['tclass_p'])):
            self.pck.add_data(params['tclass_p'][i], U_TP_I)
            self.pck.add_data(params['size_p'][i], U_TP_L)
            self.pck.add_data(params['size_max_p'][i], U_TP_L)
        if 'num_of_groups' not in params: params['num_of_groups'] = len(params['tcid'])
        self.pck.add_data(params['num_of_groups'], U_TP_I)
        for i in range(len(params['tcid'])):
            self.pck.add_data(params['tcid'][i], U_TP_I)
            self.pck.add_data(params['gid'][i], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['service_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_hotspot_service_ex(self, params):
        """ description
        @params: 
        :(s)  parent_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  is_dynamic :	(i)  - 
        :(s)  discount_method :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  radius_sessions_limit :	(i)  - 
        :(s)  recv_cost :	(d)  - 
        :(s)  rate_limit :	(s)  - 
        :(s)  allowed_net_size :	(i)  - 
        :(s)    allowed_net_ip :	(i)  - 
        :(s)    allowed_net_value :	(i)  - 
        :(s)  periodic_service_size :	(i)  - 
        :(s)    periodic_service_cost :	(d)  - 
        :(s)    periodic_service_id :	(i)  - 
        @returns: 
        :(s)  service_id :	(i)  - 
        """
        if not self.urfa_call(0x1306):
            raise Exception("Fail of urfa_call(0x1306) [rpcf_add_hotspot_service_ex]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['parent_id'], U_TP_I)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.add_data(params['service_name'], U_TP_S)
        self.pck.add_data(params['comment'], U_TP_S)
        self.pck.add_data(params['link_by_default'], U_TP_I)
        self.pck.add_data(params['is_dynamic'], U_TP_I)
        self.pck.add_data(params['discount_method'], U_TP_I)
        self.pck.add_data(params['cost'], U_TP_D)
        self.pck.add_data(params['radius_sessions_limit'], U_TP_I)
        self.pck.add_data(params['recv_cost'], U_TP_D)
        self.pck.add_data(params['rate_limit'], U_TP_S)
        self.pck.add_data(params['allowed_net_size'], U_TP_I)
        for i in range(params['allowed_net_size']):
            self.pck.add_data(params['allowed_net_ip'][i], U_TP_IP)
            self.pck.add_data(params['allowed_net_value'][i], U_TP_I)
        self.pck.add_data(params['periodic_service_size'], U_TP_I)
        for i in range(params['periodic_service_size']):
            self.pck.add_data(params['periodic_service_cost'][i], U_TP_D)
            self.pck.add_data(params['periodic_service_id'][i], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['service_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_hotspot_service_ex(self, params):
        """ description
        @params: 
        :(s)  service_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  is_dynamic :	(i)  - 
        :(s)  discount_method :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  radius_sessions_limit :	(i)  - 
        :(s)  recv_cost :	(d)  - 
        :(s)  rate_limit :	(s)  - 
        :(s)  allowed_net_size :	(i)  - 
        :(s)    allowed_net_ip :	(i)  - 
        :(s)    allowed_net_value :	(i)  - 
        :(s)  periodic_service_size :	(i)  - 
        :(s)    periodic_service_cost :	(d)  - 
        :(s)    periodic_service_id :	(i)  - 
        @returns: 
        :(s)  service_id :	(i)  - 
        """
        if not self.urfa_call(0x1307):
            raise Exception("Fail of urfa_call(0x1307) [rpcf_edit_hotspot_service_ex]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.add_data(params['parent_id'], U_TP_I)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.add_data(params['service_name'], U_TP_S)
        self.pck.add_data(params['comment'], U_TP_S)
        self.pck.add_data(params['link_by_default'], U_TP_I)
        self.pck.add_data(params['is_dynamic'], U_TP_I)
        self.pck.add_data(params['discount_method'], U_TP_I)
        self.pck.add_data(params['cost'], U_TP_D)
        self.pck.add_data(params['radius_sessions_limit'], U_TP_I)
        self.pck.add_data(params['recv_cost'], U_TP_D)
        self.pck.add_data(params['rate_limit'], U_TP_S)
        self.pck.add_data(params['allowed_net_size'], U_TP_I)
        for i in range(params['allowed_net_size']):
            self.pck.add_data(params['allowed_net_ip'][i], U_TP_IP)
            self.pck.add_data(params['allowed_net_value'][i], U_TP_I)
        self.pck.add_data(params['periodic_service_size'], U_TP_I)
        for i in range(params['periodic_service_size']):
            self.pck.add_data(params['periodic_service_cost'][i], U_TP_D)
            self.pck.add_data(params['periodic_service_id'][i], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['service_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_dialup_service_ex(self, params):
        """ description
        @params: 
        :(s)  parent_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  is_dynamic :	(i)  - 
        :(s)  discount_method :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  pool_name :	(s)  - 
        :(s)  max_timeout :	(i)  - 
        :(s)  radius_sessions_limit :	(i)  - 
        :(s)  login_prefix :	(s)  - 
        :(s)  cost_size :	(i) = _def_  - 
        :(s)    range_cost :	(d)  - 
        :(s)    range_id :	(i)  - 
        @returns: 
        :(s)  service_id :	(i)  - 
        """
        if not self.urfa_call(0x1308):
            raise Exception("Fail of urfa_call(0x1308) [rpcf_add_dialup_service_ex]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['parent_id'], U_TP_I)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.add_data(params['service_name'], U_TP_S)
        self.pck.add_data(params['comment'], U_TP_S)
        self.pck.add_data(params['link_by_default'], U_TP_I)
        self.pck.add_data(params['is_dynamic'], U_TP_I)
        self.pck.add_data(params['discount_method'], U_TP_I)
        self.pck.add_data(params['cost'], U_TP_D)
        self.pck.add_data(params['pool_name'], U_TP_S)
        self.pck.add_data(params['max_timeout'], U_TP_I)
        self.pck.add_data(params['radius_sessions_limit'], U_TP_I)
        self.pck.add_data(params['login_prefix'], U_TP_S)
        if 'cost_size' not in params: params['cost_size'] = len(params['range_id'])
        self.pck.add_data(params['cost_size'], U_TP_I)
        for i in range(len(params['range_id'])):
            self.pck.add_data(params['range_cost'][i], U_TP_D)
            self.pck.add_data(params['range_id'][i], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['service_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_dialup_service_ex(self, params):
        """ description
        @params: 
        :(s)  service_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  is_dynamic :	(i)  - 
        :(s)  discount_method :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  pool_name :	(s)  - 
        :(s)  max_timeout :	(i)  - 
        :(s)  radius_sessions_limit :	(i)  - 
        :(s)  login_prefix :	(s)  - 
        :(s)  cost_size :	(i) = _def_  - 
        :(s)    range_cost :	(d)  - 
        :(s)    range_id :	(i)  - 
        @returns: 
        :(s)  service_id :	(i)  - 
        """
        if not self.urfa_call(0x1309):
            raise Exception("Fail of urfa_call(0x1309) [rpcf_edit_dialup_service_ex]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.add_data(params['parent_id'], U_TP_I)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.add_data(params['service_name'], U_TP_S)
        self.pck.add_data(params['comment'], U_TP_S)
        self.pck.add_data(params['link_by_default'], U_TP_I)
        self.pck.add_data(params['is_dynamic'], U_TP_I)
        self.pck.add_data(params['discount_method'], U_TP_I)
        self.pck.add_data(params['cost'], U_TP_D)
        self.pck.add_data(params['pool_name'], U_TP_S)
        self.pck.add_data(params['max_timeout'], U_TP_I)
        self.pck.add_data(params['radius_sessions_limit'], U_TP_I)
        self.pck.add_data(params['login_prefix'], U_TP_S)
        if 'cost_size' not in params: params['cost_size'] = len(params['range_id'])
        self.pck.add_data(params['cost_size'], U_TP_I)
        for i in range(len(params['range_id'])):
            self.pck.add_data(params['range_cost'][i], U_TP_D)
            self.pck.add_data(params['range_id'][i], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['service_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_once_slink_ex(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  account_id :	(i)  - 
        :(s)  service_id :	(i)  - 
        :(s)  tariff_link_id :	(i) = _def_  - 
        :(s)  discount_date :	(i) = _def_  - 
        :(s)  cost_coef :	(d) = _def_  - 
        @returns: 
        :(s)  slink_id :	(i)  - 
        """
        if not self.urfa_call(0x2920):
            raise Exception("Fail of urfa_call(0x2920) [rpcf_add_once_slink_ex]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['service_id'], U_TP_I)
        if 'tariff_link_id' not in params: params['tariff_link_id'] = 0
        self.pck.add_data(params['tariff_link_id'], U_TP_I)
        if 'discount_date' not in params: params['discount_date'] = now()
        self.pck.add_data(params['discount_date'], U_TP_I)
        if 'cost_coef' not in params: params['cost_coef'] = 1.0
        self.pck.add_data(params['cost_coef'], U_TP_D)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['slink_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_once_slink_ex(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i) = _def_  - 
        :(s)  discount_date :	(i) = _def_  - 
        :(s)  cost_coef :	(d) = _def_  - 
        @returns: 
        :(s)  slink_id :	(i)  - 
        """
        if not self.urfa_call(0x2921):
            raise Exception("Fail of urfa_call(0x2921) [rpcf_edit_once_slink_ex]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'slink_id' not in params: params['slink_id'] = 0
        self.pck.add_data(params['slink_id'], U_TP_I)
        if 'discount_date' not in params: params['discount_date'] = now()
        self.pck.add_data(params['discount_date'], U_TP_I)
        if 'cost_coef' not in params: params['cost_coef'] = 1.0
        self.pck.add_data(params['cost_coef'], U_TP_D)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['slink_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_periodic_slink_ex(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  account_id :	(i)  - 
        :(s)  service_id :	(i)  - 
        :(s)  tariff_link_id :	(i) = _def_  - 
        :(s)  discount_period_id :	(i)  - 
        :(s)  start_date :	(i) = _def_  - 
        :(s)  expire_date :	(i) = _def_  - 
        :(s)  policy_id :	(i)  - 
        :(s)  unabon :	(i) = _def_  - 
        :(s)  cost_coef :	(d) = _def_  - 
        @returns: 
        :(s)  slink_id :	(i)  - 
        """
        if not self.urfa_call(0x2936):
            raise Exception("Fail of urfa_call(0x2936) [rpcf_add_periodic_slink_ex]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['service_id'], U_TP_I)
        if 'tariff_link_id' not in params: params['tariff_link_id'] = 0
        self.pck.add_data(params['tariff_link_id'], U_TP_I)
        self.pck.add_data(params['discount_period_id'], U_TP_I)
        if 'start_date' not in params: params['start_date'] = now()
        self.pck.add_data(params['start_date'], U_TP_I)
        if 'expire_date' not in params: params['expire_date'] = max_time()
        self.pck.add_data(params['expire_date'], U_TP_I)
        self.pck.add_data(params['policy_id'], U_TP_I)
        if 'unabon' not in params: params['unabon'] = 0
        self.pck.add_data(params['unabon'], U_TP_I)
        if 'cost_coef' not in params: params['cost_coef'] = 1
        self.pck.add_data(params['cost_coef'], U_TP_D)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['slink_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_periodic_slink_ex(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i) = _def_  - 
        :(s)  start_date :	(i) = _def_  - 
        :(s)  expire_date :	(i) = _def_  - 
        :(s)  policy_id :	(i)  - 
        :(s)  cost_coef :	(d)  - 
        @returns: 
        :(s)  slink_id :	(i)  - 
        """
        if not self.urfa_call(0x2937):
            raise Exception("Fail of urfa_call(0x2937) [rpcf_edit_periodic_slink_ex]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'slink_id' not in params: params['slink_id'] = 0
        self.pck.add_data(params['slink_id'], U_TP_I)
        if 'start_date' not in params: params['start_date'] = now()
        self.pck.add_data(params['start_date'], U_TP_I)
        if 'expire_date' not in params: params['expire_date'] = max_time()
        self.pck.add_data(params['expire_date'], U_TP_I)
        self.pck.add_data(params['policy_id'], U_TP_I)
        self.pck.add_data(params['cost_coef'], U_TP_D)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['slink_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_dialup_service_link_ex(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  account_id :	(i)  - 
        :(s)  service_id :	(i)  - 
        :(s)  tariff_link_id :	(i) = _def_  - 
        :(s)  discount_period_id :	(i)  - 
        :(s)  start_date :	(i) = _def_  - 
        :(s)  expire_date :	(i) = _def_  - 
        :(s)  policy_id :	(i)  - 
        :(s)  unabon :	(i) = _def_  - 
        :(s)  cost_coef :	(d) = _def_  - 
        :(s)  dialup_login :	(s)  - 
        :(s)  dialup_password :	(s)  - 
        :(s)  dialup_allowed_cid :	(s)  - 
        :(s)  dialup_allowed_csid :	(s)  - 
        :(s)  callback_enabled :	(i) = _def_  - 
        @returns: 
        :(s)  slink_id :	(i)  - 
        """
        if not self.urfa_call(0x2934):
            raise Exception("Fail of urfa_call(0x2934) [rpcf_add_dialup_service_link_ex]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['service_id'], U_TP_I)
        if 'tariff_link_id' not in params: params['tariff_link_id'] = 0
        self.pck.add_data(params['tariff_link_id'], U_TP_I)
        self.pck.add_data(params['discount_period_id'], U_TP_I)
        if 'start_date' not in params: params['start_date'] = now()
        self.pck.add_data(params['start_date'], U_TP_I)
        if 'expire_date' not in params: params['expire_date'] = max_time()
        self.pck.add_data(params['expire_date'], U_TP_I)
        self.pck.add_data(params['policy_id'], U_TP_I)
        if 'unabon' not in params: params['unabon'] = 0
        self.pck.add_data(params['unabon'], U_TP_I)
        if 'cost_coef' not in params: params['cost_coef'] = 1.0
        self.pck.add_data(params['cost_coef'], U_TP_D)
        self.pck.add_data(params['dialup_login'], U_TP_S)
        self.pck.add_data(params['dialup_password'], U_TP_S)
        self.pck.add_data(params['dialup_allowed_cid'], U_TP_S)
        self.pck.add_data(params['dialup_allowed_csid'], U_TP_S)
        if 'callback_enabled' not in params: params['callback_enabled'] = 0
        self.pck.add_data(params['callback_enabled'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['slink_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_dialup_slink_ex(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i) = _def_  - 
        :(s)  start_date :	(i) = _def_  - 
        :(s)  expire_date :	(i) = _def_  - 
        :(s)  policy_id :	(i)  - 
        :(s)  cost_coef :	(d)  - 
        :(s)  dialup_login :	(s)  - 
        :(s)  dialup_password :	(s)  - 
        :(s)  dialup_allowed_cid :	(s)  - 
        :(s)  dialup_allowed_csid :	(s)  - 
        :(s)  callback_enabled :	(i) = _def_  - 
        @returns: 
        :(s)  slink_id :	(i)  - 
        """
        if not self.urfa_call(0x2935):
            raise Exception("Fail of urfa_call(0x2935) [rpcf_edit_dialup_slink_ex]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'slink_id' not in params: params['slink_id'] = 0
        self.pck.add_data(params['slink_id'], U_TP_I)
        if 'start_date' not in params: params['start_date'] = now()
        self.pck.add_data(params['start_date'], U_TP_I)
        if 'expire_date' not in params: params['expire_date'] = max_time()
        self.pck.add_data(params['expire_date'], U_TP_I)
        self.pck.add_data(params['policy_id'], U_TP_I)
        self.pck.add_data(params['cost_coef'], U_TP_D)
        self.pck.add_data(params['dialup_login'], U_TP_S)
        self.pck.add_data(params['dialup_password'], U_TP_S)
        self.pck.add_data(params['dialup_allowed_cid'], U_TP_S)
        self.pck.add_data(params['dialup_allowed_csid'], U_TP_S)
        if 'callback_enabled' not in params: params['callback_enabled'] = 0
        self.pck.add_data(params['callback_enabled'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['slink_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_hotspot_slink_ex(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  account_id :	(i)  - 
        :(s)  service_id :	(i)  - 
        :(s)  tariff_link_id :	(i) = _def_  - 
        :(s)  discount_period_id :	(i)  - 
        :(s)  start_date :	(i) = _def_  - 
        :(s)  expire_date :	(i) = _def_  - 
        :(s)  policy_id :	(i)  - 
        :(s)  unabon :	(i) = _def_  - 
        :(s)  cost_coef :	(d) = _def_  - 
        :(s)  hotspot_login :	(s)  - 
        :(s)  hotspot_password :	(s)  - 
        @returns: 
        :(s)  slink_id :	(i)  - 
        """
        if not self.urfa_call(0x2933):
            raise Exception("Fail of urfa_call(0x2933) [rpcf_add_hotspot_slink_ex]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['service_id'], U_TP_I)
        if 'tariff_link_id' not in params: params['tariff_link_id'] = 0
        self.pck.add_data(params['tariff_link_id'], U_TP_I)
        self.pck.add_data(params['discount_period_id'], U_TP_I)
        if 'start_date' not in params: params['start_date'] = now()
        self.pck.add_data(params['start_date'], U_TP_I)
        if 'expire_date' not in params: params['expire_date'] = max_time()
        self.pck.add_data(params['expire_date'], U_TP_I)
        self.pck.add_data(params['policy_id'], U_TP_I)
        if 'unabon' not in params: params['unabon'] = 0
        self.pck.add_data(params['unabon'], U_TP_I)
        if 'cost_coef' not in params: params['cost_coef'] = 1.0
        self.pck.add_data(params['cost_coef'], U_TP_D)
        self.pck.add_data(params['hotspot_login'], U_TP_S)
        self.pck.add_data(params['hotspot_password'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['slink_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_hotspot_slink_ex(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i) = _def_  - 
        :(s)  start_date :	(i) = _def_  - 
        :(s)  expire_date :	(i) = _def_  - 
        :(s)  policy_id :	(i)  - 
        :(s)  cost_coef :	(d) = _def_  - 
        :(s)  hotspot_login :	(s)  - 
        :(s)  hotspot_password :	(s)  - 
        @returns: 
        :(s)  slink_id :	(i)  - 
        """
        if not self.urfa_call(0x2934):
            raise Exception("Fail of urfa_call(0x2934) [rpcf_edit_hotspot_slink_ex]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'slink_id' not in params: params['slink_id'] = 0
        self.pck.add_data(params['slink_id'], U_TP_I)
        if 'start_date' not in params: params['start_date'] = now()
        self.pck.add_data(params['start_date'], U_TP_I)
        if 'expire_date' not in params: params['expire_date'] = max_time()
        self.pck.add_data(params['expire_date'], U_TP_I)
        self.pck.add_data(params['policy_id'], U_TP_I)
        if 'cost_coef' not in params: params['cost_coef'] = 1.0
        self.pck.add_data(params['cost_coef'], U_TP_D)
        self.pck.add_data(params['hotspot_login'], U_TP_S)
        self.pck.add_data(params['hotspot_password'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['slink_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_ip_slink_ex(self, params):
        """ description
        @params: 
        :(s)  user_id :	(i)  - 
        :(s)  account_id :	(i) = _def_  - 
        :(s)  service_id :	(i)  - 
        :(s)  tariff_link_id :	(i) = _def_  - 
        :(s)  discount_period_id :	(i)  - 
        :(s)  start_date :	(i) = _def_  - 
        :(s)  expire_date :	(i) = _def_  - 
        :(s)  unabon :	(i) = _def_  - 
        :(s)  unprepay :	(i) = _def_  - 
        :(s)  ip_groups_count :	(i) = _def_  - 
        :(s)    ip_address :	(i)  - 
        :(s)    mask :	(i)  - 
        :(s)    mac :	(s)  - 
        :(s)    iptraffic_login :	(s)  - 
        :(s)    iptraffic_allowed_cid :	(s)  - 
        :(s)    iptraffic_password :	(s)  - 
        :(s)    ip_not_vpn :	(i) = _def_  - 
        :(s)    dont_use_fw :	(i) = _def_  - 
        :(s)    router_id :	(i) = _def_  - 
        :(s)  quotas_count :	(i) = _def_  - 
        :(s)    tclass_id :	(i)  - 
        :(s)    quota :	(l)  - 
        @returns: 
        :(s)  slink_id :	(i)  - 
        """
        if not self.urfa_call(0x2928):
            raise Exception("Fail of urfa_call(0x2928) [rpcf_add_ip_slink_ex]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 'basic_account'
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['service_id'], U_TP_I)
        if 'tariff_link_id' not in params: params['tariff_link_id'] = 0
        self.pck.add_data(params['tariff_link_id'], U_TP_I)
        self.pck.add_data(params['discount_period_id'], U_TP_I)
        if 'start_date' not in params: params['start_date'] = now()
        self.pck.add_data(params['start_date'], U_TP_I)
        if 'expire_date' not in params: params['expire_date'] = max_time()
        self.pck.add_data(params['expire_date'], U_TP_I)
        if 'unabon' not in params: params['unabon'] = 0
        self.pck.add_data(params['unabon'], U_TP_I)
        if 'unprepay' not in params: params['unprepay'] = 0
        self.pck.add_data(params['unprepay'], U_TP_I)
        if 'ip_groups_count' not in params: params['ip_groups_count'] = len(params['ip_address'])
        self.pck.add_data(params['ip_groups_count'], U_TP_I)
        for i in range(len(params['ip_address'])):
            self.pck.add_data(params['ip_address'][i], U_TP_I)
            self.pck.add_data(params['mask'][i], U_TP_I)
            self.pck.add_data(params['mac'][i], U_TP_S)
            self.pck.add_data(params['iptraffic_login'][i], U_TP_S)
            self.pck.add_data(params['iptraffic_allowed_cid'][i], U_TP_S)
            self.pck.add_data(params['iptraffic_password'][i], U_TP_S)
            if 'ip_not_vpn' not in params: params['ip_not_vpn'] = 0
            self.pck.add_data(params['ip_not_vpn'][i], U_TP_I)
            if 'dont_use_fw' not in params: params['dont_use_fw'] = 0
            self.pck.add_data(params['dont_use_fw'][i], U_TP_I)
            if 'router_id' not in params: params['router_id'] = 0
            self.pck.add_data(params['router_id'][i], U_TP_I)
        if 'quotas_count' not in params: params['quotas_count'] = len(params['quota'])
        self.pck.add_data(params['quotas_count'], U_TP_I)
        for i in range(len(params['quota'])):
            self.pck.add_data(params['tclass_id'][i], U_TP_I)
            self.pck.add_data(params['quota'][i], U_TP_L)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['slink_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_ip_slink_ex(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i) = _def_  - 
        :(s)  start_date :	(i) = _def_  - 
        :(s)  expire_date :	(i) = _def_  - 
        :(s)  ip_groups_count :	(i) = _def_  - 
        :(s)    ip_address :	(i)  - 
        :(s)    mask :	(i)  - 
        :(s)    mac :	(s)  - 
        :(s)    iptraffic_login :	(s)  - 
        :(s)    iptraffic_allowed_cid :	(s)  - 
        :(s)    iptraffic_password :	(s)  - 
        :(s)    ip_not_vpn :	(i) = _def_  - 
        :(s)    dont_use_fw :	(i) = _def_  - 
        :(s)    router_id :	(i) = _def_  - 
        :(s)  quotas_count :	(i) = _def_  - 
        :(s)    tclass_id :	(i)  - 
        :(s)    quota :	(l)  - 
        @returns: 
        :(s)  slink_id :	(i)  - 
        """
        if not self.urfa_call(0x2929):
            raise Exception("Fail of urfa_call(0x2929) [rpcf_edit_ip_slink_ex]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'slink_id' not in params: params['slink_id'] = 0
        self.pck.add_data(params['slink_id'], U_TP_I)
        if 'start_date' not in params: params['start_date'] = now()
        self.pck.add_data(params['start_date'], U_TP_I)
        if 'expire_date' not in params: params['expire_date'] = max_time()
        self.pck.add_data(params['expire_date'], U_TP_I)
        if 'ip_groups_count' not in params: params['ip_groups_count'] = len(params['ip_address'])
        self.pck.add_data(params['ip_groups_count'], U_TP_I)
        for i in range(len(params['ip_address'])):
            self.pck.add_data(params['ip_address'][i], U_TP_I)
            self.pck.add_data(params['mask'][i], U_TP_I)
            self.pck.add_data(params['mac'][i], U_TP_S)
            self.pck.add_data(params['iptraffic_login'][i], U_TP_S)
            self.pck.add_data(params['iptraffic_allowed_cid'][i], U_TP_S)
            self.pck.add_data(params['iptraffic_password'][i], U_TP_S)
            if 'ip_not_vpn' not in params: params['ip_not_vpn'] = 0
            self.pck.add_data(params['ip_not_vpn'][i], U_TP_I)
            if 'dont_use_fw' not in params: params['dont_use_fw'] = 0
            self.pck.add_data(params['dont_use_fw'][i], U_TP_I)
            if 'router_id' not in params: params['router_id'] = 0
            self.pck.add_data(params['router_id'][i], U_TP_I)
        if 'quotas_count' not in params: params['quotas_count'] = len(params['quota'])
        self.pck.add_data(params['quotas_count'], U_TP_I)
        for i in range(len(params['quota'])):
            self.pck.add_data(params['tclass_id'][i], U_TP_I)
            self.pck.add_data(params['quota'][i], U_TP_L)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['slink_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_iptraffic_service_link_ipv6(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i) = _def_  - 
        :(s)  start_date :	(i) = _def_  - 
        :(s)  expire_date :	(i) = _def_  - 
        :(s)  policy_id :	(i)  - 
        :(s)  cost_coef :	(d)  - 
        :(s)  ip_groups_count :	(i) = _def_  - 
        :(s)    ip_address :	(i)  - 
        :(s)    mask :	(i)  - 
        :(s)    mac :	(s)  - 
        :(s)    iptraffic_login :	(s)  - 
        :(s)    iptraffic_allowed_cid :	(s)  - 
        :(s)    iptraffic_password :	(s)  - 
        :(s)    pool_name :	(s)  - 
        :(s)    ip_not_vpn :	(i) = _def_  - 
        :(s)    dont_use_fw :	(i) = _def_  - 
        :(s)    router_id :	(i) = _def_  - 
        :(s)    switch_id :	(i) = _def_  - 
        :(s)    port_id :	(i) = _def_  - 
        :(s)    vlan_id :	(i) = _def_  - 
        :(s)    pool_id :	(i) = _def_  - 
        :(s)  quotas_count :	(i) = _def_  - 
        :(s)    tclass_id :	(i)  - 
        :(s)    quota :	(l)  - 
        @returns: 
        :(s)  slink_id :	(i)  - 
        """
        if not self.urfa_call(0x293b):
            raise Exception("Fail of urfa_call(0x293b) [rpcf_edit_iptraffic_service_link_ipv6]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        if 'slink_id' not in params: params['slink_id'] = 0
        self.pck.add_data(params['slink_id'], U_TP_I)
        if 'start_date' not in params: params['start_date'] = now()
        self.pck.add_data(params['start_date'], U_TP_I)
        if 'expire_date' not in params: params['expire_date'] = max_time()
        self.pck.add_data(params['expire_date'], U_TP_I)
        self.pck.add_data(params['policy_id'], U_TP_I)
        self.pck.add_data(params['cost_coef'], U_TP_D)
        if 'ip_groups_count' not in params: params['ip_groups_count'] = len(params['ip_address'])
        self.pck.add_data(params['ip_groups_count'], U_TP_I)
        for i in range(len(params['ip_address'])):
            self.pck.add_data(params['ip_address'][i], U_TP_IP)
            self.pck.add_data(params['mask'][i], U_TP_I)
            self.pck.add_data(params['mac'][i], U_TP_S)
            self.pck.add_data(params['iptraffic_login'][i], U_TP_S)
            self.pck.add_data(params['iptraffic_allowed_cid'][i], U_TP_S)
            self.pck.add_data(params['iptraffic_password'][i], U_TP_S)
            self.pck.add_data(params['pool_name'][i], U_TP_S)
            if 'ip_not_vpn' not in params: params['ip_not_vpn'] = 0
            self.pck.add_data(params['ip_not_vpn'][i], U_TP_I)
            if 'dont_use_fw' not in params: params['dont_use_fw'] = 0
            self.pck.add_data(params['dont_use_fw'][i], U_TP_I)
            if 'router_id' not in params: params['router_id'] = 0
            self.pck.add_data(params['router_id'][i], U_TP_I)
            if 'switch_id' not in params: params['switch_id'] = 0
            self.pck.add_data(params['switch_id'][i], U_TP_I)
            if 'port_id' not in params: params['port_id'] = 0
            self.pck.add_data(params['port_id'][i], U_TP_I)
            if 'vlan_id' not in params: params['vlan_id'] = 0
            self.pck.add_data(params['vlan_id'][i], U_TP_I)
            if 'pool_id' not in params: params['pool_id'] = 0
            self.pck.add_data(params['pool_id'][i], U_TP_I)
        if 'quotas_count' not in params: params['quotas_count'] = len(params['quota'])
        self.pck.add_data(params['quotas_count'], U_TP_I)
        for i in range(len(params['quota'])):
            self.pck.add_data(params['tclass_id'][i], U_TP_I)
            self.pck.add_data(params['quota'][i], U_TP_L)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['slink_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_tariff_history(self, params):
        """ description
        @params: 
        :(s)  account_id :	(i)  - 
        @returns: 
        :(s)  size :	(i)  - 
        :(s)    tariff_id :	(i)  - 
        :(s)    link_date :	(i)  - 
        :(s)    unlink_date :	(i)  - 
        :(s)    tariff_name :	(s)  - 
        """
        if not self.urfa_call(-0x15026):
            raise Exception("Fail of urfa_call(-0x15026) [rpcf_user5_get_tariff_history]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['size']): 
            self.pck.recv(self.sck)
            ret['tariff_id'][i] = self.pck.get_data(U_TP_I)
            ret['link_date'][i] = self.pck.get_data(U_TP_I)
            ret['unlink_date'][i] = self.pck.get_data(U_TP_I)
            ret['tariff_name'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_ui_settings(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  permissions :	(i)  - 
        """
        if not self.urfa_call(-0x403b):
            raise Exception("Fail of urfa_call(-0x403b) [rpcf_user5_get_ui_settings]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['permissions'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_user5_get_account_external_id(self, params):
        """ description
        @params: 
        :(s)  account_id :	(i)  - 
        @returns: 
        :(s)  external_id :	(s)  - 
        """
        if not self.urfa_call(-0x15030):
            raise Exception("Fail of urfa_call(-0x15030) [rpcf_user5_get_account_external_id]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['external_id'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_periodic_service_ex(self, params):
        """ description
        @params: 
        :(s)  sid :	(i)  - 
        @returns: 
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  deprecated :	(i)  - 
        :(s)  discount_method :	(i)  - 
        :(s)  param :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        """
        if not self.urfa_call(0x2130):
            raise Exception("Fail of urfa_call(0x2130) [rpcf_get_periodic_service_ex]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['sid'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['service_name'] = self.pck.get_data(U_TP_S)
        ret['comment'] = self.pck.get_data(U_TP_S)
        ret['link_by_default'] = self.pck.get_data(U_TP_I)
        ret['cost'] = self.pck.get_data(U_TP_D)
        ret['deprecated'] = self.pck.get_data(U_TP_I)
        ret['discount_method'] = self.pck.get_data(U_TP_I)
        ret['param'] = self.pck.get_data(U_TP_I)
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        ret['parent_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_dialup_service_ex(self, params):
        """ description
        @params: 
        :(s)  sid :	(i)  - 
        @returns: 
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  is_dynamic :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  deprecated :	(i)  - 
        :(s)  discount_method :	(i)  - 
        :(s)  pool_name :	(s)  - 
        :(s)  max_timeout :	(i)  - 
        :(s)  null_service_prepaid :	(i)  - 
        :(s)  radius_sessions_limit :	(i)  - 
        :(s)  login_prefix :	(s)  - 
        :(s)  cost_size :	(i)  - 
        :(s)    tr_time :	(s)  - 
        :(s)    param :	(d)  - 
        :(s)    id :	(i)  - 
        :(s)  is_parent_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        """
        if not self.urfa_call(0x2133):
            raise Exception("Fail of urfa_call(0x2133) [rpcf_get_dialup_service_ex]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['sid'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['service_name'] = self.pck.get_data(U_TP_S)
        ret['comment'] = self.pck.get_data(U_TP_S)
        ret['link_by_default'] = self.pck.get_data(U_TP_I)
        ret['is_dynamic'] = self.pck.get_data(U_TP_I)
        ret['cost'] = self.pck.get_data(U_TP_D)
        ret['deprecated'] = self.pck.get_data(U_TP_I)
        ret['discount_method'] = self.pck.get_data(U_TP_I)
        ret['pool_name'] = self.pck.get_data(U_TP_S)
        ret['max_timeout'] = self.pck.get_data(U_TP_I)
        ret['null_service_prepaid'] = self.pck.get_data(U_TP_I)
        ret['radius_sessions_limit'] = self.pck.get_data(U_TP_I)
        ret['login_prefix'] = self.pck.get_data(U_TP_S)
        ret['cost_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['cost_size']): 
            self.pck.recv(self.sck)
            ret['tr_time'][i] = self.pck.get_data(U_TP_S)
            ret['param'][i] = self.pck.get_data(U_TP_D)
            ret['id'][i] = self.pck.get_data(U_TP_I)
        self.pck.recv(self.sck)
        ret['is_parent_id'] = self.pck.get_data(U_TP_I)
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        ret['parent_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_hotspot_service_ex(self, params):
        """ description
        @params: 
        :(s)  sid :	(i)  - 
        @returns: 
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  is_dynamic :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  deprecated :	(i)  - 
        :(s)  discount_method :	(i)  - 
        :(s)  null_service_prepaid :	(i)  - 
        :(s)  radius_sessions_limit :	(i)  - 
        :(s)  recv_cost :	(d)  - 
        :(s)  rate_limit :	(s)  - 
        :(s)  hsd_allowed_net_size :	(i)  - 
        :(s)    allowed_net_id :	(i)  - 
        :(s)    allowed_net_value :	(i)  - 
        :(s)  cost_size :	(i)  - 
        :(s)    tr_time :	(s)  - 
        :(s)    param1 :	(d)  - 
        :(s)    param2 :	(i)  - 
        :(s)  service_data_parent_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        """
        if not self.urfa_call(0x2132):
            raise Exception("Fail of urfa_call(0x2132) [rpcf_get_hotspot_service_ex]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['sid'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['service_name'] = self.pck.get_data(U_TP_S)
        ret['comment'] = self.pck.get_data(U_TP_S)
        ret['link_by_default'] = self.pck.get_data(U_TP_I)
        ret['is_dynamic'] = self.pck.get_data(U_TP_I)
        ret['cost'] = self.pck.get_data(U_TP_D)
        ret['deprecated'] = self.pck.get_data(U_TP_I)
        ret['discount_method'] = self.pck.get_data(U_TP_I)
        ret['null_service_prepaid'] = self.pck.get_data(U_TP_I)
        ret['radius_sessions_limit'] = self.pck.get_data(U_TP_I)
        ret['recv_cost'] = self.pck.get_data(U_TP_D)
        ret['rate_limit'] = self.pck.get_data(U_TP_S)
        ret['hsd_allowed_net_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['hsd_allowed_net_size']): 
            self.pck.recv(self.sck)
            ret['allowed_net_id'][i] = self.pck.get_data(U_TP_I)
            ret['allowed_net_value'][i] = self.pck.get_data(U_TP_I)
        self.pck.recv(self.sck)
        ret['cost_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['cost_size']): 
            self.pck.recv(self.sck)
            ret['tr_time'][i] = self.pck.get_data(U_TP_S)
            ret['param1'][i] = self.pck.get_data(U_TP_D)
            ret['param2'][i] = self.pck.get_data(U_TP_I)
        self.pck.recv(self.sck)
        ret['service_data_parent_id'] = self.pck.get_data(U_TP_I)
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        ret['parent_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_iptraffic_service_ex(self, params):
        """ description
        @params: 
        :(s)  sid :	(i)  - 
        @returns: 
        :(s)  service_name :	(s)  - 
        :(s)  comment :	(s)  - 
        :(s)  link_by_default :	(i)  - 
        :(s)  is_dynamic :	(i)  - 
        :(s)  cost :	(d)  - 
        :(s)  deprecated :	(i)  - 
        :(s)  discount_method :	(i)  - 
        :(s)  sessions_limit :	(i)  - 
        :(s)  null_service_prepaid :	(i)  - 
        :(s)  borders_count :	(i)  - 
        :(s)    tclass :	(i)  - 
        :(s)      borders_size :	(l)  - 
        :(s)        border_id :	(l)  - 
        :(s)        border_cost :	(d)  - 
        :(s)  prepaid_count :	(i)  - 
        :(s)    tclass :	(i)  - 
        :(s)      prepaid_amount :	(l)  - 
        :(s)      prepaid_max :	(l)  - 
        :(s)  tclass_id2group_size :	(i)  - 
        :(s)    tclass_id :	(i)  - 
        :(s)    tclass_group_id :	(i)  - 
        :(s)  service_data_parent_id :	(i)  - 
        :(s)  tariff_id :	(i)  - 
        :(s)  parent_id :	(i)  - 
        """
        if not self.urfa_call(0x2134):
            raise Exception("Fail of urfa_call(0x2134) [rpcf_get_iptraffic_service_ex]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['sid'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['service_name'] = self.pck.get_data(U_TP_S)
        ret['comment'] = self.pck.get_data(U_TP_S)
        ret['link_by_default'] = self.pck.get_data(U_TP_I)
        ret['is_dynamic'] = self.pck.get_data(U_TP_I)
        ret['cost'] = self.pck.get_data(U_TP_D)
        ret['deprecated'] = self.pck.get_data(U_TP_I)
        ret['discount_method'] = self.pck.get_data(U_TP_I)
        ret['sessions_limit'] = self.pck.get_data(U_TP_I)
        ret['null_service_prepaid'] = self.pck.get_data(U_TP_I)
        ret['borders_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['borders_count']): 
            self.pck.recv(self.sck)
            ret['tclass'][i] = self.pck.get_data(U_TP_I)
            if ret['tclass'][i]  !=  -1:
                ret['borders_size'] = self.pck.get_data(U_TP_L)
                ret['borders_size_array'][i]=ret['borders_size']
                for j in range(ret['borders_size']): 
                    self.pck.recv(self.sck)
                    if not i in ret['border_id']:ret['border_id'][i] = dict()
                    ret['border_id'][i][j] = self.pck.get_data(U_TP_L)
                    if not i in ret['border_cost']:ret['border_cost'][i] = dict()
                    ret['border_cost'][i][j] = self.pck.get_data(U_TP_D)
        self.pck.recv(self.sck)
        ret['prepaid_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['prepaid_count']): 
            self.pck.recv(self.sck)
            ret['tclass'][i] = self.pck.get_data(U_TP_I)
            if ret['tclass'][i]  !=  -1:
                ret['prepaid_amount'][i] = self.pck.get_data(U_TP_L)
                ret['prepaid_max'][i] = self.pck.get_data(U_TP_L)
        self.pck.recv(self.sck)
        ret['tclass_id2group_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['tclass_id2group_size']): 
            self.pck.recv(self.sck)
            ret['tclass_id'][i] = self.pck.get_data(U_TP_I)
            ret['tclass_group_id'][i] = self.pck.get_data(U_TP_I)
        self.pck.recv(self.sck)
        ret['service_data_parent_id'] = self.pck.get_data(U_TP_I)
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        ret['parent_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_set_traffic_quota_on_link(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i)  - 
        :(s)  tclass_id :	(i)  - 
        :(s)  quota :	(l)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x5033):
            raise Exception("Fail of urfa_call(0x5033) [rpcf_set_traffic_quota_on_link]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.add_data(params['tclass_id'], U_TP_I)
        self.pck.add_data(params['quota'], U_TP_L)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_timezone(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  tzname :	(s)  - 
        """
        if not self.urfa_call(0x11113):
            raise Exception("Fail of urfa_call(0x11113) [rpcf_get_timezone]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['tzname'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_ic_get_users_list(self, params):
        """ description
        @params: 
        :(s)  from :	(i)  - 
        :(s)  to :	(i)  - 
        @returns: 
        :(s)  users_count :	(i)  - 
        :(s)    customer_id :	(i)  - 
        :(s)    login :	(s)  - 
        :(s)    full_name :	(s)  - 
        :(s)    status :	(i)  - 
        :(s)    last_sync_date :	(i)  - 
        :(s)    ic_id :	(s)  - 
        """
        if not self.urfa_call(0x14003):
            raise Exception("Fail of urfa_call(0x14003) [rpcf_ic_get_users_list]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['from'], U_TP_I)
        self.pck.add_data(params['to'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['users_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['users_count']): 
            self.pck.recv(self.sck)
            ret['customer_id'][i] = self.pck.get_data(U_TP_I)
            ret['login'][i] = self.pck.get_data(U_TP_S)
            ret['full_name'][i] = self.pck.get_data(U_TP_S)
            ret['status'][i] = self.pck.get_data(U_TP_I)
            ret['last_sync_date'][i] = self.pck.get_data(U_TP_I)
            ret['ic_id'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_is_tel_number_used(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i)  - 
        :(s)  login :	(s)  - 
        :(s)  incoming_trunk :	(s)  - 
        :(s)  outgoing_trunk :	(s)  - 
        :(s)  pbx_id :	(s)  - 
        :(s)  number :	(s)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x10311):
            raise Exception("Fail of urfa_call(0x10311) [rpcf_is_tel_number_used]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.add_data(params['login'], U_TP_S)
        self.pck.add_data(params['incoming_trunk'], U_TP_S)
        self.pck.add_data(params['outgoing_trunk'], U_TP_S)
        self.pck.add_data(params['pbx_id'], U_TP_S)
        self.pck.add_data(params['number'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_tel_emergency_calls(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  service_count :	(i)  - 
        :(s)    service_id :	(i)  - 
        :(s)    zone_count :	(i)  - 
        :(s)      zone_id_array :	(i)  - 
        """
        if not self.urfa_call(0x15032):
            raise Exception("Fail of urfa_call(0x15032) [rpcf_get_tel_emergency_calls]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['service_count'] = self.pck.get_data(U_TP_I)
        for i in range(ret['service_count']): 
            self.pck.recv(self.sck)
            ret['service_id'] = self.pck.get_data(U_TP_I)
            ret['zone_count'] = self.pck.get_data(U_TP_I)
            for j in range(ret['zone_count']): 
                self.pck.recv(self.sck)
                ret['zone_id_array'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_set_tel_emergency_calls(self, params):
        """ description
        @params: 
        :(s)  service_id :	(i)  - 
        :(s)  zone_count :	(i) = _def_  - 
        :(s)    zone_id_array :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x15033):
            raise Exception("Fail of urfa_call(0x15033) [rpcf_set_tel_emergency_calls]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        if 'zone_count' not in params: params['zone_count'] = len(params['zone_id_array'])
        self.pck.add_data(params['zone_count'], U_TP_I)
        for i in range(len(params['zone_id_array'])):
            self.pck.add_data(params['zone_id_array'][i], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_remove_dhcp_options(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        :(s)  type :	(i)  - 
        @returns: 
        :(s)  id :	(i)  - 
        """
        if not self.urfa_call(0x1102):
            raise Exception("Fail of urfa_call(0x1102) [rpcf_remove_dhcp_options]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['type'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_dhcp_options(self, params):
        """ description
        @params: 
        :(s)  owner_id :	(i)  - 
        :(s)  owner_type :	(i)  - 
        :(s)  size :	(i)  - 
        :(s)    option_id :	(i)  - 
        :(s)    data_type :	(i)  - 
        :(s)      attr_data_int :	(i)  - 
        :(s)      attr_data_string :	(s)  - 
        :(s)      attr_data_ip :	(i)  - 
        :(s)      attr_data_hex_bin :	(s)  - 
        :(s)      ip_array_size :	(i)  - 
        :(s)        attr_data_ip :	(i)  - 
        @returns: 
        :(s)  result :	(i)  - 
        """
        if not self.urfa_call(0x1107):
            raise Exception("Fail of urfa_call(0x1107) [rpcf_add_dhcp_options]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['owner_id'], U_TP_I)
        self.pck.add_data(params['owner_type'], U_TP_I)
        self.pck.add_data(params['size'], U_TP_I)
        for i in range(params['size']):
            self.pck.add_data(params['option_id'][i], U_TP_I)
            self.pck.add_data(params['data_type'][i], U_TP_I)
            if params['data_type'][i]  ==  1:
                self.pck.add_data(params['attr_data_int'][i], U_TP_I)
            if params['data_type'][i]  ==  2:
                self.pck.add_data(params['attr_data_string'][i], U_TP_S)
            if params['data_type'][i]  ==  3:
                self.pck.add_data(params['attr_data_ip'][i], U_TP_IP)
            if params['data_type'][i]  ==  4:
                self.pck.add_data(params['attr_data_hex_bin'][i], U_TP_S)
            if params['data_type'][i]  ==  5:
                self.pck.add_data(params['ip_array_size'], U_TP_I)
                for ii in range(params['ip_array_size']):
                    self.pck.add_data(params['attr_data_ip'][i][ii], U_TP_IP)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_dhcp_options_list(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        :(s)  type :	(i)  - 
        @returns: 
        :(s)  size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    option_id :	(i)  - 
        :(s)    owner_type :	(i)  - 
        :(s)    owner_id :	(i)  - 
        :(s)    data_type :	(i)  - 
        :(s)      attr_data_int :	(i)  - 
        :(s)      attr_data_string :	(s)  - 
        :(s)      attr_data_ip :	(i)  - 
        :(s)      attr_data_hex_bin :	(s)  - 
        :(s)      ip_array_size :	(i)  - 
        :(s)        attr_data_ip :	(i)  - 
        """
        if not self.urfa_call(0x1101):
            raise Exception("Fail of urfa_call(0x1101) [rpcf_get_dhcp_options_list]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['type'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['option_id'][i] = self.pck.get_data(U_TP_I)
            ret['owner_type'][i] = self.pck.get_data(U_TP_I)
            ret['owner_id'][i] = self.pck.get_data(U_TP_I)
            ret['data_type'][i] = self.pck.get_data(U_TP_I)
            if ret['data_type'][i]  ==  1:
                ret['attr_data_int'][i] = self.pck.get_data(U_TP_I)
            if ret['data_type'][i]  ==  2:
                ret['attr_data_string'][i] = self.pck.get_data(U_TP_S)
            if ret['data_type'][i]  ==  3:
                ret['attr_data_ip'][i] = self.pck.get_data(U_TP_IP)
            if ret['data_type'][i]  ==  4:
                ret['attr_data_hex_bin'][i] = self.pck.get_data(U_TP_S)
            if ret['data_type'][i]  ==  5:
                ret['ip_array_size'][i] = self.pck.get_data(U_TP_I)
                for ii in range(ret['ip_array_size'][i]): 
                    self.pck.recv(self.sck)
                    if not i in ret['attr_data_ip']:ret['attr_data_ip'][i] = dict()
                    ret['attr_data_ip'][i][ii] = self.pck.get_data(U_TP_IP)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_switch(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        @returns: 
        :(s)  id :	(i)  - 
        :(s)  name :	(s)  - 
        :(s)  location :	(s)  - 
        :(s)  type :	(i)  - 
        :(s)  ports_count :	(i)  - 
        :(s)  remote_id :	(s)  - 
        :(s)  address :	(i)  - 
        :(s)  login :	(s)  - 
        :(s)  password :	(s)  - 
        """
        if not self.urfa_call(0x1150):
            raise Exception("Fail of urfa_call(0x1150) [rpcf_get_switch]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['id'] = self.pck.get_data(U_TP_I)
        ret['name'] = self.pck.get_data(U_TP_S)
        ret['location'] = self.pck.get_data(U_TP_S)
        ret['type'] = self.pck.get_data(U_TP_I)
        ret['ports_count'] = self.pck.get_data(U_TP_I)
        ret['remote_id'] = self.pck.get_data(U_TP_S)
        ret['address'] = self.pck.get_data(U_TP_IP)
        ret['login'] = self.pck.get_data(U_TP_S)
        ret['password'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_switch(self, params):
        """ description
        @params: 
        :(s)  name :	(s)  - 
        :(s)  location :	(s)  - 
        :(s)  type :	(i)  - 
        :(s)  ports_count :	(i)  - 
        :(s)  remote_id :	(s)  - 
        :(s)  address :	(i)  - 
        :(s)  login :	(s)  - 
        :(s)  password :	(s)  - 
        @returns: 
        :(s)  id :	(i)  - 
        """
        if not self.urfa_call(0x1151):
            raise Exception("Fail of urfa_call(0x1151) [rpcf_add_switch]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.add_data(params['location'], U_TP_S)
        self.pck.add_data(params['type'], U_TP_I)
        self.pck.add_data(params['ports_count'], U_TP_I)
        self.pck.add_data(params['remote_id'], U_TP_S)
        self.pck.add_data(params['address'], U_TP_IP)
        self.pck.add_data(params['login'], U_TP_S)
        self.pck.add_data(params['password'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_remove_switch(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        @returns: 
        :(s)  id :	(i)  - 
        """
        if not self.urfa_call(0x1152):
            raise Exception("Fail of urfa_call(0x1152) [rpcf_remove_switch]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_switch(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        :(s)  name :	(s)  - 
        :(s)  location :	(s)  - 
        :(s)  type :	(i)  - 
        :(s)  ports_count :	(i)  - 
        :(s)  remote_id :	(s)  - 
        :(s)  address :	(i)  - 
        :(s)  login :	(s)  - 
        :(s)  password :	(s)  - 
        @returns: 
        :(s)  id :	(i)  - 
        """
        if not self.urfa_call(0x1153):
            raise Exception("Fail of urfa_call(0x1153) [rpcf_edit_switch]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.add_data(params['location'], U_TP_S)
        self.pck.add_data(params['type'], U_TP_I)
        self.pck.add_data(params['ports_count'], U_TP_I)
        self.pck.add_data(params['remote_id'], U_TP_S)
        self.pck.add_data(params['address'], U_TP_IP)
        self.pck.add_data(params['login'], U_TP_S)
        self.pck.add_data(params['password'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_switches_list(self, params):
        """ description
        @params: 
        :(s)  offset :	(i)  - 
        :(s)  count :	(i)  - 
        @returns: 
        :(s)  size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    name :	(s)  - 
        :(s)    location :	(s)  - 
        :(s)    type :	(i)  - 
        :(s)    ports_count :	(i)  - 
        :(s)    remote_id :	(s)  - 
        :(s)    address :	(i)  - 
        :(s)    login :	(s)  - 
        :(s)    password :	(s)  - 
        """
        if not self.urfa_call(0x1154):
            raise Exception("Fail of urfa_call(0x1154) [rpcf_get_switches_list]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['offset'], U_TP_I)
        self.pck.add_data(params['count'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['name'][i] = self.pck.get_data(U_TP_S)
            ret['location'][i] = self.pck.get_data(U_TP_S)
            ret['type'][i] = self.pck.get_data(U_TP_I)
            ret['ports_count'][i] = self.pck.get_data(U_TP_I)
            ret['remote_id'][i] = self.pck.get_data(U_TP_S)
            ret['address'][i] = self.pck.get_data(U_TP_IP)
            ret['login'][i] = self.pck.get_data(U_TP_S)
            ret['password'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_switches_count(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  count :	(i)  - 
        """
        if not self.urfa_call(0x1155):
            raise Exception("Fail of urfa_call(0x1155) [rpcf_get_switches_count]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['count'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_count_switches(self, params):
        """ description
        @params: 
        :(s)  field :	(i)  - 
        :(s)  value :	(s)  - 
        @returns: 
        :(s)  count :	(i)  - 
        """
        if not self.urfa_call(0x1157):
            raise Exception("Fail of urfa_call(0x1157) [rpcf_count_switches]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['field'], U_TP_I)
        self.pck.add_data(params['value'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['count'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_search_switches(self, params):
        """ description
        @params: 
        :(s)  status :	(i)  - 
        :(s)  params_cnt :	(i)  - 
        :(s)    field :	(i)  - 
        :(s)    criteria :	(i)  - 
        :(s)    value :	(s)  - 
        @returns: 
        :(s)  size :	(i)  - 
        :(s)            id :	(i)  - 
        :(s)            name :	(s)  - 
        :(s)            location :	(s)  - 
        :(s)            type :	(i)  - 
        :(s)            ports_count :	(i)  - 
        :(s)            remote_id :	(s)  - 
        :(s)            address :	(i)  - 
        :(s)            login :	(s)  - 
        :(s)            password :	(s)  - 
        """
        if not self.urfa_call(0x1156):
            raise Exception("Fail of urfa_call(0x1156) [rpcf_search_switches]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['status'], U_TP_I)
        self.pck.add_data(params['params_cnt'], U_TP_I)
        for i in range(params['params_cnt']):
            self.pck.add_data(params['field'][i], U_TP_I)
            self.pck.add_data(params['criteria'][i], U_TP_I)
            self.pck.add_data(params['value'][i], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['size'] = self.pck.get_data(U_TP_I)
        if ret['size']  !=  -1:
            if ret['size']  !=  -2:
                if ret['size']  !=  -3:
                    if ret['size']  !=  -4:
                        for i in range(ret['size']): 
                            self.pck.recv(self.sck)
                            ret['id'][i] = self.pck.get_data(U_TP_I)
                            ret['name'][i] = self.pck.get_data(U_TP_S)
                            ret['location'][i] = self.pck.get_data(U_TP_S)
                            ret['type'][i] = self.pck.get_data(U_TP_I)
                            ret['ports_count'][i] = self.pck.get_data(U_TP_I)
                            ret['remote_id'][i] = self.pck.get_data(U_TP_S)
                            ret['address'][i] = self.pck.get_data(U_TP_IP)
                            ret['login'][i] = self.pck.get_data(U_TP_S)
                            ret['password'][i] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_switch_ports_usage(self, params):
        """ description
        @params: 
        :(s)  switch_id :	(i)  - 
        @returns: 
        :(s)  ports_size :	(i)  - 
        :(s)    port_id :	(i)  - 
        :(s)    users_size :	(i)  - 
        :(s)      user_id :	(i)  - 
        :(s)      login :	(s)  - 
        """
        if not self.urfa_call(0x1158):
            raise Exception("Fail of urfa_call(0x1158) [rpcf_get_switch_ports_usage]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['switch_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['ports_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['ports_size']): 
            self.pck.recv(self.sck)
            ret['port_id'][i] = self.pck.get_data(U_TP_I)
            ret['users_size'][i] = self.pck.get_data(U_TP_I)
            for ii in range(ret['users_size'][i]): 
                self.pck.recv(self.sck)
                if not i in ret['user_id']:ret['user_id'][i] = dict()
                ret['user_id'][i][ii] = self.pck.get_data(U_TP_I)
                if not i in ret['login']:ret['login'][i] = dict()
                ret['login'][i][ii] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_switch_type(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        @returns: 
        :(s)  id :	(i)  - 
        :(s)  name :	(s)  - 
        :(s)  supp_volumes :	(s)  - 
        :(s)  port_start_offset :	(i)  - 
        :(s)  tec_id_type :	(i)  - 
        :(s)  tec_id_len :	(i)  - 
        :(s)  tec_id_disp :	(i)  - 
        :(s)  tec_id_offset :	(i)  - 
        :(s)  port_id_type :	(i)  - 
        :(s)  port_id_len :	(i)  - 
        :(s)  port_id_disp :	(i)  - 
        :(s)  port_id_offset :	(i)  - 
        :(s)  vlan_id_type :	(i)  - 
        :(s)  vlan_id_len :	(i)  - 
        :(s)  vlan_id_disp :	(i)  - 
        :(s)  vlan_id_offset :	(i)  - 
        """
        if not self.urfa_call(0x505):
            raise Exception("Fail of urfa_call(0x505) [rpcf_get_switch_type]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['id'] = self.pck.get_data(U_TP_I)
        ret['name'] = self.pck.get_data(U_TP_S)
        ret['supp_volumes'] = self.pck.get_data(U_TP_S)
        ret['port_start_offset'] = self.pck.get_data(U_TP_I)
        ret['tec_id_type'] = self.pck.get_data(U_TP_I)
        ret['tec_id_len'] = self.pck.get_data(U_TP_I)
        ret['tec_id_disp'] = self.pck.get_data(U_TP_I)
        ret['tec_id_offset'] = self.pck.get_data(U_TP_I)
        ret['port_id_type'] = self.pck.get_data(U_TP_I)
        ret['port_id_len'] = self.pck.get_data(U_TP_I)
        ret['port_id_disp'] = self.pck.get_data(U_TP_I)
        ret['port_id_offset'] = self.pck.get_data(U_TP_I)
        ret['vlan_id_type'] = self.pck.get_data(U_TP_I)
        ret['vlan_id_len'] = self.pck.get_data(U_TP_I)
        ret['vlan_id_disp'] = self.pck.get_data(U_TP_I)
        ret['vlan_id_offset'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_switch_type(self, params):
        """ description
        @params: 
        :(s)  name :	(s)  - 
        :(s)  supp_volumes :	(s)  - 
        :(s)  port_start_offset :	(i)  - 
        :(s)  tec_id_type :	(i)  - 
        :(s)  tec_id_len :	(i)  - 
        :(s)  tec_id_disp :	(i)  - 
        :(s)  tec_id_offset :	(i)  - 
        :(s)  port_id_type :	(i)  - 
        :(s)  port_id_len :	(i)  - 
        :(s)  port_id_disp :	(i)  - 
        :(s)  port_id_offset :	(i)  - 
        :(s)  vlan_id_type :	(i)  - 
        :(s)  vlan_id_len :	(i)  - 
        :(s)  vlan_id_disp :	(i)  - 
        :(s)  vlan_id_offset :	(i)  - 
        @returns: 
        :(s)  id :	(i)  - 
        """
        if not self.urfa_call(0x506):
            raise Exception("Fail of urfa_call(0x506) [rpcf_add_switch_type]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.add_data(params['supp_volumes'], U_TP_S)
        self.pck.add_data(params['port_start_offset'], U_TP_I)
        self.pck.add_data(params['tec_id_type'], U_TP_I)
        self.pck.add_data(params['tec_id_len'], U_TP_I)
        self.pck.add_data(params['tec_id_disp'], U_TP_I)
        self.pck.add_data(params['tec_id_offset'], U_TP_I)
        self.pck.add_data(params['port_id_type'], U_TP_I)
        self.pck.add_data(params['port_id_len'], U_TP_I)
        self.pck.add_data(params['port_id_disp'], U_TP_I)
        self.pck.add_data(params['port_id_offset'], U_TP_I)
        self.pck.add_data(params['vlan_id_type'], U_TP_I)
        self.pck.add_data(params['vlan_id_len'], U_TP_I)
        self.pck.add_data(params['vlan_id_disp'], U_TP_I)
        self.pck.add_data(params['vlan_id_offset'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_remove_switch_type(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        @returns: 
        :(s)  id :	(i)  - 
        """
        if not self.urfa_call(0x502):
            raise Exception("Fail of urfa_call(0x502) [rpcf_remove_switch_type]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_switch_type(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        :(s)  name :	(s)  - 
        :(s)  supp_volumes :	(s)  - 
        :(s)  port_start_offset :	(i)  - 
        :(s)  tec_id_type :	(i)  - 
        :(s)  tec_id_len :	(i)  - 
        :(s)  tec_id_disp :	(i)  - 
        :(s)  tec_id_offset :	(i)  - 
        :(s)  port_id_type :	(i)  - 
        :(s)  port_id_len :	(i)  - 
        :(s)  port_id_disp :	(i)  - 
        :(s)  port_id_offset :	(i)  - 
        :(s)  vlan_id_type :	(i)  - 
        :(s)  vlan_id_len :	(i)  - 
        :(s)  vlan_id_disp :	(i)  - 
        :(s)  vlan_id_offset :	(i)  - 
        @returns: 
        :(s)  id :	(i)  - 
        """
        if not self.urfa_call(0x507):
            raise Exception("Fail of urfa_call(0x507) [rpcf_edit_switch_type]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.add_data(params['supp_volumes'], U_TP_S)
        self.pck.add_data(params['port_start_offset'], U_TP_I)
        self.pck.add_data(params['tec_id_type'], U_TP_I)
        self.pck.add_data(params['tec_id_len'], U_TP_I)
        self.pck.add_data(params['tec_id_disp'], U_TP_I)
        self.pck.add_data(params['tec_id_offset'], U_TP_I)
        self.pck.add_data(params['port_id_type'], U_TP_I)
        self.pck.add_data(params['port_id_len'], U_TP_I)
        self.pck.add_data(params['port_id_disp'], U_TP_I)
        self.pck.add_data(params['port_id_offset'], U_TP_I)
        self.pck.add_data(params['vlan_id_type'], U_TP_I)
        self.pck.add_data(params['vlan_id_len'], U_TP_I)
        self.pck.add_data(params['vlan_id_disp'], U_TP_I)
        self.pck.add_data(params['vlan_id_offset'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_switch_types_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    name :	(s)  - 
        :(s)    supp_volumes :	(s)  - 
        :(s)    port_start_offset :	(i)  - 
        :(s)    tec_id_type :	(i)  - 
        :(s)    tec_id_len :	(i)  - 
        :(s)    tec_id_disp :	(i)  - 
        :(s)    tec_id_offset :	(i)  - 
        :(s)    port_id_type :	(i)  - 
        :(s)    port_id_len :	(i)  - 
        :(s)    port_id_disp :	(i)  - 
        :(s)    port_id_offset :	(i)  - 
        :(s)    vlan_id_type :	(i)  - 
        :(s)    vlan_id_len :	(i)  - 
        :(s)    vlan_id_disp :	(i)  - 
        :(s)    vlan_id_offset :	(i)  - 
        """
        if not self.urfa_call(0x508):
            raise Exception("Fail of urfa_call(0x508) [rpcf_get_switch_types_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['name'][i] = self.pck.get_data(U_TP_S)
            ret['supp_volumes'][i] = self.pck.get_data(U_TP_S)
            ret['port_start_offset'][i] = self.pck.get_data(U_TP_I)
            ret['tec_id_type'][i] = self.pck.get_data(U_TP_I)
            ret['tec_id_len'][i] = self.pck.get_data(U_TP_I)
            ret['tec_id_disp'][i] = self.pck.get_data(U_TP_I)
            ret['tec_id_offset'][i] = self.pck.get_data(U_TP_I)
            ret['port_id_type'][i] = self.pck.get_data(U_TP_I)
            ret['port_id_len'][i] = self.pck.get_data(U_TP_I)
            ret['port_id_disp'][i] = self.pck.get_data(U_TP_I)
            ret['port_id_offset'][i] = self.pck.get_data(U_TP_I)
            ret['vlan_id_type'][i] = self.pck.get_data(U_TP_I)
            ret['vlan_id_len'][i] = self.pck.get_data(U_TP_I)
            ret['vlan_id_disp'][i] = self.pck.get_data(U_TP_I)
            ret['vlan_id_offset'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_dhcp_pool(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        @returns: 
        :(s)  id :	(i)  - 
        :(s)  gateway :	(i)  - 
        :(s)  netmask :	(i)  - 
        :(s)  dns1_server :	(i)  - 
        :(s)  dns2_server :	(i)  - 
        :(s)  ntp_server :	(i)  - 
        :(s)  domain_name :	(s)  - 
        :(s)  block_action_type :	(i)  - 
        :(s)  lease_time :	(i)  - 
        :(s)  flags :	(i)  - 
        :(s)  ranges_size :	(i)  - 
        :(s)    range_first_addr :	(i)  - 
        :(s)    range_last_addr :	(i)  - 
        :(s)    range_flags :	(i)  - 
        """
        if not self.urfa_call(0x700):
            raise Exception("Fail of urfa_call(0x700) [rpcf_get_dhcp_pool]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['id'] = self.pck.get_data(U_TP_I)
        ret['gateway'] = self.pck.get_data(U_TP_IP)
        ret['netmask'] = self.pck.get_data(U_TP_IP)
        ret['dns1_server'] = self.pck.get_data(U_TP_IP)
        ret['dns2_server'] = self.pck.get_data(U_TP_IP)
        ret['ntp_server'] = self.pck.get_data(U_TP_IP)
        ret['domain_name'] = self.pck.get_data(U_TP_S)
        ret['block_action_type'] = self.pck.get_data(U_TP_I)
        ret['lease_time'] = self.pck.get_data(U_TP_I)
        ret['flags'] = self.pck.get_data(U_TP_I)
        ret['ranges_size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['ranges_size']): 
            self.pck.recv(self.sck)
            ret['range_first_addr'][i] = self.pck.get_data(U_TP_IP)
            ret['range_last_addr'][i] = self.pck.get_data(U_TP_IP)
            ret['range_flags'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_dhcp_pool(self, params):
        """ description
        @params: 
        :(s)  gateway :	(i)  - 
        :(s)  netmask :	(i)  - 
        :(s)  dns1_server :	(i)  - 
        :(s)  dns2_server :	(i)  - 
        :(s)  ntp_server :	(i)  - 
        :(s)  domain_name :	(s)  - 
        :(s)  block_pool_id :	(i)  - 
        :(s)  lease_time :	(i)  - 
        :(s)  flags :	(i)  - 
        :(s)  ranges_size :	(i)  - 
        :(s)    range_first_addr :	(i)  - 
        :(s)    range_last_addr :	(i)  - 
        :(s)    range_flags :	(i)  - 
        @returns: 
        :(s)  id :	(i)  - 
        """
        if not self.urfa_call(0x701):
            raise Exception("Fail of urfa_call(0x701) [rpcf_add_dhcp_pool]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['gateway'], U_TP_IP)
        self.pck.add_data(params['netmask'], U_TP_IP)
        self.pck.add_data(params['dns1_server'], U_TP_IP)
        self.pck.add_data(params['dns2_server'], U_TP_IP)
        self.pck.add_data(params['ntp_server'], U_TP_IP)
        self.pck.add_data(params['domain_name'], U_TP_S)
        self.pck.add_data(params['block_pool_id'], U_TP_I)
        self.pck.add_data(params['lease_time'], U_TP_I)
        self.pck.add_data(params['flags'], U_TP_I)
        self.pck.add_data(params['ranges_size'], U_TP_I)
        for i in range(params['ranges_size']):
            self.pck.add_data(params['range_first_addr'][i], U_TP_IP)
            self.pck.add_data(params['range_last_addr'][i], U_TP_IP)
            self.pck.add_data(params['range_flags'][i], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_remove_dhcp_pool(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        @returns: 
        :(s)  id :	(i)  - 
        """
        if not self.urfa_call(0x702):
            raise Exception("Fail of urfa_call(0x702) [rpcf_remove_dhcp_pool]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_edit_dhcp_pool(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        :(s)  gateway :	(i)  - 
        :(s)  netmask :	(i)  - 
        :(s)  dns1_server :	(i)  - 
        :(s)  dns2_server :	(i)  - 
        :(s)  ntp_server :	(i)  - 
        :(s)  domain_name :	(s)  - 
        :(s)  block_pool_id :	(i)  - 
        :(s)  lease_time :	(i)  - 
        :(s)  flags :	(i)  - 
        :(s)  ranges_size :	(i)  - 
        :(s)    range_first_addr :	(i)  - 
        :(s)    range_last_addr :	(i)  - 
        :(s)    range_flags :	(i)  - 
        @returns: 
        :(s)  id :	(i)  - 
        """
        if not self.urfa_call(0x703):
            raise Exception("Fail of urfa_call(0x703) [rpcf_edit_dhcp_pool]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['gateway'], U_TP_IP)
        self.pck.add_data(params['netmask'], U_TP_IP)
        self.pck.add_data(params['dns1_server'], U_TP_IP)
        self.pck.add_data(params['dns2_server'], U_TP_IP)
        self.pck.add_data(params['ntp_server'], U_TP_IP)
        self.pck.add_data(params['domain_name'], U_TP_S)
        self.pck.add_data(params['block_pool_id'], U_TP_I)
        self.pck.add_data(params['lease_time'], U_TP_I)
        self.pck.add_data(params['flags'], U_TP_I)
        self.pck.add_data(params['ranges_size'], U_TP_I)
        for i in range(params['ranges_size']):
            self.pck.add_data(params['range_first_addr'][i], U_TP_IP)
            self.pck.add_data(params['range_last_addr'][i], U_TP_IP)
            self.pck.add_data(params['range_flags'][i], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_dhcp_pool_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    gateway :	(i)  - 
        :(s)    netmask :	(i)  - 
        :(s)    dns1_server :	(i)  - 
        :(s)    dns2_server :	(i)  - 
        :(s)    ntp_server :	(i)  - 
        :(s)    domain_name :	(s)  - 
        :(s)    block_action_type :	(i)  - 
        :(s)    lease_time :	(i)  - 
        :(s)    flags :	(i)  - 
        :(s)    ranges_size :	(i)  - 
        :(s)      range_last_addr :	(i)  - 
        :(s)      range_last_addr :	(i)  - 
        """
        if not self.urfa_call(0x704):
            raise Exception("Fail of urfa_call(0x704) [rpcf_get_dhcp_pool_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['gateway'][i] = self.pck.get_data(U_TP_IP)
            ret['netmask'][i] = self.pck.get_data(U_TP_IP)
            ret['dns1_server'][i] = self.pck.get_data(U_TP_IP)
            ret['dns2_server'][i] = self.pck.get_data(U_TP_IP)
            ret['ntp_server'][i] = self.pck.get_data(U_TP_IP)
            ret['domain_name'][i] = self.pck.get_data(U_TP_S)
            ret['block_action_type'][i] = self.pck.get_data(U_TP_I)
            ret['lease_time'][i] = self.pck.get_data(U_TP_I)
            ret['flags'][i] = self.pck.get_data(U_TP_I)
            ret['ranges_size'][i] = self.pck.get_data(U_TP_I)
            for ii in range(ret['ranges_size'][i]): 
                self.pck.recv(self.sck)
                if not i in ret['range_last_addr']:ret['range_last_addr'][i] = dict()
                ret['range_last_addr'][i][ii] = self.pck.get_data(U_TP_IP)
                if not i in ret['range_last_addr']:ret['range_last_addr'][i] = dict()
                ret['range_last_addr'][i][ii] = self.pck.get_data(U_TP_IP)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_get_leases_list(self):
        """ description
        @params: 
        :	None
        @returns: 
        :(s)  size :	(i)  - 
        :(s)    id :	(i)  - 
        :(s)    ip :	(i)  - 
        :(s)    mac :	(s)  - 
        :(s)    server_id :	(s)  - 
        :(s)    client_id :	(s)  - 
        :(s)    expired :	(i)  - 
        :(s)    updated :	(i)  - 
        :(s)    ipgroup_item_id :	(i)  - 
        :(s)    flags :	(i)  - 
        """
        if not self.urfa_call(0x1350):
            raise Exception("Fail of urfa_call(0x1350) [rpcf_get_leases_list]")
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['size'] = self.pck.get_data(U_TP_I)
        for i in range(ret['size']): 
            self.pck.recv(self.sck)
            ret['id'][i] = self.pck.get_data(U_TP_I)
            ret['ip'][i] = self.pck.get_data(U_TP_IP)
            ret['mac'][i] = self.pck.get_data(U_TP_S)
            ret['server_id'][i] = self.pck.get_data(U_TP_S)
            ret['client_id'][i] = self.pck.get_data(U_TP_S)
            ret['expired'][i] = self.pck.get_data(U_TP_I)
            ret['updated'][i] = self.pck.get_data(U_TP_I)
            ret['ipgroup_item_id'][i] = self.pck.get_data(U_TP_I)
            ret['flags'][i] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_make_lease_overdue(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        @returns: 
        :(s)  ret_code :	(i)  - 
        """
        if not self.urfa_call(0x1351):
            raise Exception("Fail of urfa_call(0x1351) [rpcf_make_lease_overdue]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['ret_code'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_remove_lease(self, params):
        """ description
        @params: 
        :(s)  id :	(i)  - 
        @returns: 
        :(s)  ret_code :	(i)  - 
        """
        if not self.urfa_call(0x1352):
            raise Exception("Fail of urfa_call(0x1352) [rpcf_remove_lease]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['ret_code'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_add_ip_to_slink(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i)  - 
        :(s)  ip :	(i)  - 
        :(s)  mask :	(i)  - 
        :(s)  mac :	(s)  - 
        :(s)  login :	(s)  - 
        :(s)  allowed_cid :	(s)  - 
        :(s)  password :	(s)  - 
        :(s)  pool_name :	(s)  - 
        :(s)  is_skip_radius :	(i) = _def_  - 
        :(s)  is_skip_rfw :	(i) = _def_  - 
        :(s)  router_id :	(i) = _def_  - 
        :(s)  switch_id :	(i) = _def_  - 
        :(s)  port_id :	(i) = _def_  - 
        :(s)  vlan_id :	(i) = _def_  - 
        :(s)  pool_id :	(i) = _def_  - 
        @returns: 
        :(s)  result :	(i)  - 
        :(s)  err_desc :	(s)  - 
        """
        if not self.urfa_call(0x1510d):
            raise Exception("Fail of urfa_call(0x1510d) [rpcf_add_ip_to_slink]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.add_data(params['ip'], U_TP_IP)
        self.pck.add_data(params['mask'], U_TP_I)
        self.pck.add_data(params['mac'], U_TP_S)
        self.pck.add_data(params['login'], U_TP_S)
        self.pck.add_data(params['allowed_cid'], U_TP_S)
        self.pck.add_data(params['password'], U_TP_S)
        self.pck.add_data(params['pool_name'], U_TP_S)
        if 'is_skip_radius' not in params: params['is_skip_radius'] = 0
        self.pck.add_data(params['is_skip_radius'], U_TP_I)
        if 'is_skip_rfw' not in params: params['is_skip_rfw'] = 0
        self.pck.add_data(params['is_skip_rfw'], U_TP_I)
        if 'router_id' not in params: params['router_id'] = 0
        self.pck.add_data(params['router_id'], U_TP_I)
        if 'switch_id' not in params: params['switch_id'] = 0
        self.pck.add_data(params['switch_id'], U_TP_I)
        if 'port_id' not in params: params['port_id'] = 0
        self.pck.add_data(params['port_id'], U_TP_I)
        if 'vlan_id' not in params: params['vlan_id'] = 0
        self.pck.add_data(params['vlan_id'], U_TP_I)
        if 'pool_id' not in params: params['pool_id'] = 0
        self.pck.add_data(params['pool_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        ret['err_desc'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def rpcf_remove_ip_from_slink(self, params):
        """ description
        @params: 
        :(s)  slink_id :	(i)  - 
        :(s)  ip :	(i)  - 
        :(s)  mask :	(i)  - 
        :(s)  login :	(s)  - 
        :(s)  mac :	(s)  - 
        :(s)  switch_id :	(i) = _def_  - 
        :(s)  port_id :	(i) = _def_  - 
        :(s)  vlan_id :	(i) = _def_  - 
        @returns: 
        :(s)  result :	(i)  - 
        :(s)  err_desc :	(s)  - 
        """
        if not self.urfa_call(0x1510e):
            raise Exception("Fail of urfa_call(0x1510e) [rpcf_remove_ip_from_slink]")
        #--------- input
        self.pck.init(code = U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.add_data(params['ip'], U_TP_IP)
        self.pck.add_data(params['mask'], U_TP_I)
        self.pck.add_data(params['login'], U_TP_S)
        self.pck.add_data(params['mac'], U_TP_S)
        if 'switch_id' not in params: params['switch_id'] = 0
        self.pck.add_data(params['switch_id'], U_TP_I)
        if 'port_id' not in params: params['port_id'] = 0
        self.pck.add_data(params['port_id'], U_TP_I)
        if 'vlan_id' not in params: params['vlan_id'] = 0
        self.pck.add_data(params['vlan_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        ret = defaultdict(dict)
        self.pck.recv(self.sck)
        ret['result'] = self.pck.get_data(U_TP_I)
        ret['err_desc'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
    def report_payments(self, params=dict()):
        """ get report of payments
        @params:
        :(s)  user_id       :	(i) = 0
        :(s)  ???           :	(i) = 0     aid ???
        :(s)  group_id      :	(i) = 0
        :(s)  dp_id         :	(i) = 0
        :(s)  time_start    :	(i) = 0
        :(s)  time_end      :	(i) = max_time
        @returns:
        :(i)  payment_id : dict : -
        :(s)      account_id        :	(i)
        :(s)      login             :	(s)  - user login
        :(s)      full_name         :	(s)  - user full_name
        :(s)      actual_date       :	(i)
        :(s)      enter_date        :	(i)
        :(s)      sum               :	(d)
        :(s)      sum_incurrency    :	(d)
        :(s)      currency_id       :	(i)  - code of currency
        :(s)      method            :	(i)  - pay method code
        :(s)      who_receved       :	(i)  - sysuser_id who make the payment
        :(s)      admin_comment     :	(s)
        :(s)      payment_ext_id    :	(s)
        :(s)      account_ext_id    :	(s)
        :(s)      burnt_date        :	(i)  - date of burning the pay
        """
        if not self.urfa_call(0x3030):
            raise Exception("Fail of urfa_call(0x3030) [rpcf_payments_report_new]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        if 'user_id' not in params: params['user_id'] = 0
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        if 'group_id' not in params: params['group_id'] = 0
        self.pck.add_data(params['group_id'], U_TP_I)
        if 'dp_id' not in params: params['dp_id'] = 0
        self.pck.add_data(params['dp_id'], U_TP_I)
        if 'time_start' not in params: params['time_start'] = 0
        self.pck.add_data(params['time_start'], U_TP_I)
        if 'time_end' not in params: params['time_end'] = max_time
        self.pck.add_data(params['time_end'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        acc_cnt = self.pck.get_data(U_TP_I)
        while acc_cnt:
            if params['user_id'] or params['group_id'] or params['dp_id']:
                self.pck.recv(self.sck)
            atr_cnt = self.pck.get_data(U_TP_I)
            while atr_cnt:
                self.pck.recv(self.sck)
                payment_id = self.pck.get_data(U_TP_I)
                ret[payment_id] = {}
                ret[payment_id]['account_id'] = self.pck.get_data(U_TP_I)
                ret[payment_id]['login'] = self.pck.get_data(U_TP_S)
                ret[payment_id]['actual_date'] = self.pck.get_data(U_TP_I)
                ret[payment_id]['enter_date'] = self.pck.get_data(U_TP_I)
                ret[payment_id]['sum'] = self.pck.get_data(U_TP_D)
                ret[payment_id]['sum_incurrency'] = self.pck.get_data(U_TP_D)
                ret[payment_id]['currency_id'] = self.pck.get_data(U_TP_I)
                ret[payment_id]['method'] = self.pck.get_data(U_TP_I)
                ret[payment_id]['who_receved'] = self.pck.get_data(U_TP_I)
                ret[payment_id]['admin_comment'] = self.pck.get_data(U_TP_S)
                ret[payment_id]['payment_ext_number'] = self.pck.get_data(U_TP_S)
                ret[payment_id]['full_name'] = self.pck.get_data(U_TP_S)
                ret[payment_id]['acc_external_id'] = self.pck.get_data(U_TP_S)
                ret[payment_id]['burnt_date'] = self.pck.get_data(U_TP_I)
                atr_cnt -= 1
            acc_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
