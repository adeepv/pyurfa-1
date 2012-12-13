#coding=utf-8

""" main class of urfa-module """
from urfa_connection import *


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

    def password_gen(self, params=dict()):
        """ password generator
        @params:
        :(s)  passwd_len :	(i) = 8	 - length of generated password
        @returns:
        :(s)  error :	(s)	 - error message if it fail
        :(s)  passwd :	(s)	 - generated password
        """
        if not self.urfa_call(0x0060):
            raise Exception("Fail of urfa_call(0x0060) [rpcf_get_new_secret]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        if 'passwd_len' not in params: params['passwd_len'] = 8
        self.pck.add_data(params['passwd_len'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['error'] = self.pck.get_data(U_TP_S)
        ret['passwd'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def users_search_ligth(self, params):
        """ search first 5 users by liked fields
            smb. like:
                select id,login,email,name
                from users
                where (login like '') and (email like '') and (name like '')
        @params:
        :(s)  login :	(s)	 -  \
        :(s)  email :	(s)	 -  | search fields
        :(s)  fname :	(s)	 -  /
        @returns:
        :(s)  success :	(i)	 - ???
        :(s)  total :	(i)	 - count of finded users
        :(s)  result : dict:	 -  dict - result of search of:
        :(i)    id : dict:	     -  user id
        :(s)      login :	(s)	 -  user login
        :(s)      email :	(s)	 -  user email
        :(s)      name :	(s)	 -  user fullname
        """
        if not self.urfa_call(0x1202):
            raise Exception("Fail of urfa_call(0x1202) [rpcf_search_users_ligth]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['login'], U_TP_S)
        self.pck.add_data(params['email'], U_TP_S)
        self.pck.add_data(params['fname'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['success'] = self.pck.get_data(U_TP_I)
        ret['total'] = self.pck.get_data(U_TP_I)
        show_count = self.pck.get_data(U_TP_I)
        while show_count:
            self.pck.recv(self.sck)
            id = self.pck.get_data(U_TP_I)
            ret[id] = {}
            ret[id]['login'] = self.pck.get_data(U_TP_S)
            ret[id]['email'] = self.pck.get_data(U_TP_S)
            ret[id]['name'] = self.pck.get_data(U_TP_S)
            show_count -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def users_search(self, params):
        """ description
        @params:
        :(s)  add_ret_fields : list = () : (s)   -   list of add returnet field names
        :(s)  select_type :	(s) = 'and'	    - selection type name ('or'\'and')
        :(s)  patterns : list :             - list of dicts - field_criteria_pattern
        :                   dict:
        :(s)        field_name    :	(s)	 -  name of search-field
        :(s)        criteria      :	(s)	 -  criteria ('>','=='...)
        :(s)        pattern       :	(s)	 -  pattern for search
        @returns:
        :(i)  user_id : dict:	 -
        :(s)    login           :	(s)                                           \
        :(s)    basic_account   :	(i)                                           |
        :(s)    full_name       :	(s)                                           | basic returned fields
        :(s)    is_blocked      :	(i)                                           |
        :(s)    blocked_flags : list :                                            |
        :(s)      U_BL_SYS            - it's system block ?                       |
        :(s)      U_BL_SYS_REC_AB     - recalc abon when system block ?           |
        :(s)      U_BL_SYS_REC_PAY    - recalc prepaid traf when system block ?   |
        :(s)      U_BL_MAN            - it's manual block ?                       |
        :(s)      U_BL_MAN_REC_AB     - recalc abon when block ?                  |
        :(s)      U_BL_MAN_REC_PAY    - recalc prepaid traf when block ?          |
        :(s)    balance         :	(d)                                           |
        :(s)    ips : dict:	 - ip addresses dict of                              /
        :(s)      ip : dict:	 - ip address, contain:
        :(s)        grp     : (i)	 - ip group
        :(s)        mask    :	(s)	 - netmask
        :       ... - additional fields that was requested
        """
        if not self.urfa_call(0x1205):
            raise Exception("Fail of urfa_call(0x1205) [rpcf_search_users_new]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        if 'add_ret_fields' not in params: params['add_ret_fields'] = []
        self.pck.add_data(len(params['add_ret_fields']), U_TP_I)
        for ret_field in params['add_ret_fields']:
            self.pck.add_data(U_USRS_F.index(ret_field), U_TP_I)
        if 'select_type' not in params: params['select_type'] = 'and'
        self.pck.add_data(U_SEL_T.index(params['select_type']), U_TP_I)
        self.pck.add_data(len(params['patterns']), U_TP_I)
        for pattern in params['patterns']:
            self.pck.add_data(U_USRS_F.index(pattern['field_name']), U_TP_I)
            self.pck.add_data(U_CRITERIAS.index(pattern['criteria']), U_TP_I)
            if pattern['field_name'].count('_date'): field_type = U_TP_I
            else: field_type = U_TP_S
            self.pck.add_data(pattern['pattern'], field_type)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        users_cnt = self.pck.get_data(U_TP_I)
        while users_cnt:
            self.pck.recv(self.sck)
            user_id = self.pck.get_data(U_TP_I)
            ret[user_id] = {}
            ret[user_id]['login'] = self.pck.get_data(U_TP_S)
            ret[user_id]['basic_account'] = self.pck.get_data(U_TP_I)
            ret[user_id]['full_name'] = self.pck.get_data(U_TP_S)
            ret[user_id]['is_blocked'] = self.pck.get_data(U_TP_I)
            blocked2ret(ret[user_id]['is_blocked'], ret)
            ret[user_id]['balance'] = self.pck.get_data(U_TP_D)
            self.pck.recv(self.sck)
            ipaddr_cnt = self.pck.get_data(U_TP_I)
            while ipaddr_cnt:
                self.pck.recv(self.sck)
                ret[user_id]['ips'] = {}
                ipparams_cnt = self.pck.get_data(U_TP_I)
                while ipparams_cnt:
                    self.pck.recv(self.sck)
                    grp = self.pck.get_data(U_TP_I)
                    ip = self.pck.get_data(U_TP_IP)
                    mask = self.pck.get_data(U_TP_IP)
                    ret[user_id]['ips'][ip] = {}
                    ret[user_id]['ips'][ip]['mask'] = mask
                    ret[user_id]['ips'][ip]['grp'] = grp
                    ipparams_cnt -= 1
                ipaddr_cnt -= 1
            for ret_field in params['add_ret_fields']:
                self.pck.recv(self.sck)
                if ret_field == 'user_id': ret[user_id]['user_id'] = self.pck.get_data(U_TP_I)
                elif ret_field == 'create_date': ret[user_id]['create_date'] = self.pck.get_data(U_TP_I)
                elif ret_field == 'last_change_date': ret[user_id]['last_change_date'] = self.pck.get_data(U_TP_I)
                elif ret_field == 'who_create': ret[user_id]['who_create'] = self.pck.get_data(U_TP_I)
                elif ret_field == 'who_change': ret[user_id]['who_change'] = self.pck.get_data(U_TP_I)
                elif ret_field == 'is_jur_address': ret[user_id]['is_jur_address'] = self.pck.get_data(U_TP_I)
                elif ret_field == 'jur_address': ret[user_id]['jur_address'] = self.pck.get_data(U_TP_S)
                elif ret_field == 'actual_address': ret[user_id]['actual_address'] = self.pck.get_data(U_TP_S)
                elif ret_field == 'work_phone': ret[user_id]['work_phone'] = self.pck.get_data(U_TP_S)
                elif ret_field == 'home_phone': ret[user_id]['home_phone'] = self.pck.get_data(U_TP_S)
                elif ret_field == 'mobile_phone': ret[user_id]['mobile_phone'] = self.pck.get_data(U_TP_S)
                elif ret_field == 'web_page': ret[user_id]['web_page'] = self.pck.get_data(U_TP_S)
                elif ret_field == 'icq_uin': ret[user_id]['icq_uin'] = self.pck.get_data(U_TP_S)
                elif ret_field == 'tax_number': ret[user_id]['tax_number'] = self.pck.get_data(U_TP_S)
                elif ret_field == 'kpp_number': ret[user_id]['kpp_number'] = self.pck.get_data(U_TP_S)
                elif ret_field == 'house_id': ret[user_id]['house_id'] = self.pck.get_data(U_TP_I)
                elif ret_field == 'flat_number': ret[user_id]['flat_number'] = self.pck.get_data(U_TP_S)
                elif ret_field == 'entrance': ret[user_id]['entrance'] = self.pck.get_data(U_TP_S)
                elif ret_field == 'floor': ret[user_id]['floor'] = self.pck.get_data(U_TP_S)
                elif ret_field == 'email': ret[user_id]['email'] = self.pck.get_data(U_TP_S)
                elif ret_field == 'passport': ret[user_id]['passport'] = self.pck.get_data(U_TP_S)
                elif ret_field == 'district': ret[user_id]['district'] = self.pck.get_data(U_TP_S)
                elif ret_field == 'building': ret[user_id]['building'] = self.pck.get_data(U_TP_S)
                elif ret_field == 'external_id': ret[user_id]['external_id'] = self.pck.get_data(U_TP_S)
            users_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def users_list_get(self, params=dict(), keyfield=None):
        """ get list of users between p_from anf p_to position
        @params:
        :(s)  from  : (i) = 0	 - from position
        :(s)  to    : (i) = 9999	 - to position
        :(s)  card_user : (i) = 0  - it's card-user? (0/1)
        @returns:
        :(i)  user_id :	dict:	 -
        :(s)    login           :	(s)	 -  user login
        :(s)    basic_account   :	(i)	 -  user basic accaunt id
        :(s)    full_name       :	(s)	 -  user fullname
        :(s)    is_blocked      :	(i)
        :(s)    blocked_flags : list :
        :(s)      U_BL_SYS            - it's system block ?
        :(s)      U_BL_SYS_REC_AB     - recalc abon when system block ?
        :(s)      U_BL_SYS_REC_PAY    - recalc prepaid traf when system block ?
        :(s)      U_BL_MAN            - it's manual block ?
        :(s)      U_BL_MAN_REC_AB     - recalc abon when block ?
        :(s)      U_BL_MAN_REC_PAY    - recalc prepaid traf when block ?
        :(s)    balance         :	(d)	 -  current user balance
        :(s)    internet_status :	(i)	 -  internet status code
        :(s)    ips : dict:	 - ip addresses dict of
        :(s)      ip : dict:	 - ip address, contain:
        :(s)        grp     : (i)	 - ip group
        :(s)        mask    :	(s)	 - netmask

        """
        if not self.urfa_call(0x2001):
            raise Exception("Fail of urfa_call(0x2001) [rpcf_get_users_list]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        if 'from' not in params: params['from'] = 0
        self.pck.add_data(params['from'], U_TP_I)
        if 'to' not in params: params['to'] = 9999
        self.pck.add_data(params['to'], U_TP_I)
        if 'card_user' not in params: params['card_user'] = 0
        self.pck.add_data(params['card_user'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {} if keyfield else []
        cnt = self.pck.get_data(U_TP_I)
        while cnt:
            self.pck.recv(self.sck)
            userinfo = {}
            userinfo['uid'] = self.pck.get_data(U_TP_I)
            userinfo['login'] = self.pck.get_data(U_TP_S)
            userinfo['basic_aid'] = self.pck.get_data(U_TP_I)
            userinfo['full_name'] = self.pck.get_data(U_TP_S)
            userinfo['is_blocked'] = self.pck.get_data(U_TP_I)
            blocked2ret(userinfo['is_blocked'], userinfo)
            userinfo['balance'] = self.pck.get_data(U_TP_D)
            self.pck.recv(self.sck)
            ipaddr_cnt = self.pck.get_data(U_TP_I)
            while ipaddr_cnt:
                self.pck.recv(self.sck)
                userinfo['ips'] = {}
                ipparams_cnt = self.pck.get_data(U_TP_I)
                while ipparams_cnt:
                    self.pck.recv(self.sck)
                    ip = self.pck.get_data(U_TP_IP)
                    mask = self.pck.get_data(U_TP_IP)
                    grp = self.pck.get_data(U_TP_I)
                    userinfo['ips'][ip] = {}
                    userinfo['ips'][ip]['mask'] = mask
                    userinfo['ips'][ip]['grp'] = grp
                    ipparams_cnt -= 1
                ipaddr_cnt -= 1
            self.pck.recv(self.sck)
            userinfo['internet_status'] = self.pck.get_data(U_TP_I)
            if keyfield in userinfo:
                ret[userinfo[keyfield]] = userinfo
            else:
                ret.append(userinfo)
            cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def user_add(self, params):
        """ add new user & attach new account to created user
        @params:
        :(s)  login :	    (s)
        :(s)  password :	(s)
        :(s)  full_name :	(s) = ''
        :(s)  is_juridical :(i) = 0
        :(s)  jur_address :	(s) = ''
        :(s)  act_address :	(s) = ''
        :(s)  flat_number :	(s) = ''
        :(s)  entrance  :	(s) = ''
        :(s)  floor      :	(s) = ''
        :(s)  district :	(s) = ''
        :(s)  building :	(s) = ''
        :(s)  passport :	(s) = ''
        :(s)  house_id :	(i) = 0  - house id from houses dict
        :(s)  work_tel :	(s) = ''
        :(s)  home_tel :	(s) = ''
        :(s)  mob_tel   :	(s) = ''
        :(s)  web_page :	(s) = ''
        :(s)  icq_number :	(s) = ''
        :(s)  tax_number :	(s) = ''
        :(s)  kpp_number :	(s) = ''
        :(s)  email     :	(s) = ''
        :(s)  bank_id   :	(i) = 0  - bank id from banks dict
        :(s)  bank_account          :	(s) = ''
        :(s)  comments              :	(s) = ''
        :(s)  personal_manager      :	(s) = ''
        :(s)  connect_date          :	(i) = now()
        :(s)  is_send_invoice       :	(i) = 0  - send invoice ?
        :(s)  advance_payment       :	(i) = 0  - prepay (0/1)
        :(s)  switch_id             :	(i) = 0  - fw id
        :(s)  port_number           :	(i) = 0  - port on switch (fw)
        :(s)  binded_currency_id    :	(i) = 810  - ruble
        :(s)  addparams : dict: = {} -  dict of additional params
        :(s)    param_id : (s) param_value
        :(s)  groups : tuple: (i) group  - tuple of groups wich user is binded
        :(s)  is_blocked        :	(i) = 0  - blocking bit-mask
        :(s)  balance           :	(d) = 0.0
        :(s)  credit            :	(d) = 0.0
        :(s)  vat_rate          :	(d) = 0.0
        :(s)  sale_tax_rate     :	(d) = 0.0
        :(s)  int_status        :	(i) = 1
        @returns:
        :(s)  user_id :	(i)
        :   if not user_id:
        :(s)    error_code      :	(i)  - if user_id not returned then return error code...
        :(s)    error_msg       :	(s)  - .. and error message
        :   if user_id:
        :(s)    basic_account   :	(i)  - if user id is returnet then return basic account id
        """
        if not self.urfa_call(0x2125):
            raise Exception("Fail of urfa_call(0x2125) [rpcf_add_user_new]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['login'], U_TP_S)
        self.pck.add_data(params['password'], U_TP_S)
        if 'full_name' not in params: params['full_name'] = ''
        self.pck.add_data(params['full_name'], U_TP_S)
        if 'is_juridical' not in params: params['is_juridical'] = 0
        self.pck.add_data(params['is_juridical'], U_TP_I)
        if 'jur_address' not in params: params['jur_address'] = ''
        self.pck.add_data(params['jur_address'], U_TP_S)
        if 'act_address' not in params: params['act_address'] = ''
        self.pck.add_data(params['act_address'], U_TP_S)
        if 'flat_number' not in params: params['flat_number'] = ''
        self.pck.add_data(params['flat_number'], U_TP_S)
        if 'entrance' not in params: params['entrance'] = ''
        self.pck.add_data(params['entrance'], U_TP_S)
        if 'floor' not in params: params['floor'] = ''
        self.pck.add_data(params['floor'], U_TP_S)
        if 'district' not in params: params['district'] = ''
        self.pck.add_data(params['district'], U_TP_S)
        if 'building' not in params: params['building'] = ''
        self.pck.add_data(params['building'], U_TP_S)
        if 'passport' not in params: params['passport'] = ''
        self.pck.add_data(params['passport'], U_TP_S)
        if 'house_id' not in params: params['house_id'] = 0
        self.pck.add_data(params['house_id'], U_TP_I)
        if 'work_tel' not in params: params['work_tel'] = ''
        self.pck.add_data(params['work_tel'], U_TP_S)
        if 'home_tel' not in params: params['home_tel'] = ''
        self.pck.add_data(params['home_tel'], U_TP_S)
        if 'mob_tel' not in params: params['mob_tel'] = ''
        self.pck.add_data(params['mob_tel'], U_TP_S)
        if 'web_page' not in params: params['web_page'] = ''
        self.pck.add_data(params['web_page'], U_TP_S)
        if 'icq_number' not in params: params['icq_number'] = ''
        self.pck.add_data(params['icq_number'], U_TP_S)
        if 'tax_number' not in params: params['tax_number'] = ''
        self.pck.add_data(params['tax_number'], U_TP_S)
        if 'kpp_number' not in params: params['kpp_number'] = ''
        self.pck.add_data(params['kpp_number'], U_TP_S)
        if 'email' not in params: params['email'] = ''
        self.pck.add_data(params['email'], U_TP_S)
        if 'bank_id' not in params: params['bank_id'] = 0
        self.pck.add_data(params['bank_id'], U_TP_I)
        if 'bank_account' not in params: params['bank_account'] = ''
        self.pck.add_data(params['bank_account'], U_TP_S)
        if 'comments' not in params: params['comments'] = ''
        self.pck.add_data(params['comments'], U_TP_S)
        if 'personal_manager' not in params: params['personal_manager'] = ''
        self.pck.add_data(params['personal_manager'], U_TP_S)
        if 'connect_date' not in params: params['connect_date'] = now()
        self.pck.add_data(params['connect_date'], U_TP_I)
        if 'is_send_invoice' not in params: params['is_send_invoice'] = 0
        self.pck.add_data(params['is_send_invoice'], U_TP_I)
        if 'advance_payment' not in params: params['advance_payment'] = 0
        self.pck.add_data(params['advance_payment'], U_TP_I)
        if 'switch_id' not in params: params['switch_id'] = 0
        self.pck.add_data(params['switch_id'], U_TP_I)
        if 'port_number' not in params: params['port_number'] = 0
        self.pck.add_data(params['port_number'], U_TP_I)
        if 'binded_currency_id' not in params: params['binded_currency_id'] = 810 # ruble
        self.pck.add_data(params['binded_currency_id'], U_TP_I)
        if 'addparams' not in params: params['addparams'] = {}
        self.pck.add_data(len(params['addparams']), U_TP_I)
        for param_id, param_value in params['addparams'].iteritems():
            self.pck.add_data(param_id, U_TP_I)
            self.pck.add_data(param_value, U_TP_S)
        if 'groups' not in params: params['groups'] = ()
        self.pck.add_data(len(params['groups']), U_TP_I)
        for group_id in params['groups']:
            self.pck.add_data(group_id, U_TP_I)
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
        self.pck.recv(self.sck)
        ret = {}
        ret['user_id'] = self.pck.get_data(U_TP_I)
        if not ret['user_id']:
            ret['error_code'] = self.pck.get_data(U_TP_I)
            ret['error_msg'] = self.pck.get_data(U_TP_S)
        if ret['user_id']:
            ret['basic_account'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def user_edit(self, params):
        """ edit exist user profile by user_id ALL FIELDS ARE REQUARED
        @params:
        :(s)  user_id  :	(i)
        :(s)  login :	    (s)
        :(s)  password :	(s)
        :(s)  full_name :	(s)
        :(s)  is_juridical :(i)
        :(s)  jur_address :	(s)
        :(s)  act_address :	(s)
        :(s)  flat_number :	(s)
        :(s)  entrance  :	(s)
        :(s)  floor      :	(s)
        :(s)  district :	(s)
        :(s)  building :	(s)
        :(s)  passport :	(s)
        :(s)  house_id :	(i)
        :(s)  work_tel :	(s)
        :(s)  home_tel :	(s)
        :(s)  mob_tel   :	(s)
        :(s)  web_page :	(s)
        :(s)  icq_number :	(s)
        :(s)  tax_number :	(s)
        :(s)  kpp_number :	(s)
        :(s)  email     :	(s)
        :(s)  bank_id   :	(i)
        :(s)  bank_account          :	(s)
        :(s)  comments              :	(s)
        :(s)  personal_manager      :	(s)
        :(s)  connect_date          :	(i)
        :(s)  is_send_invoice       :	(i)
        :(s)  advance_payment       :	(i)
        :(s)  switch_id             :	(i)
        :(s)  port_number           :	(i)
        :(s)  binded_currency_id    :	(i)
        :(s)  addparams : dict:
        :(s)    param_id : (s) param_value
        @returns:
        :(s)  user_id :	(i)
        :   if not user_id:
        :(s)    error_code      :	(i)
        :(s)    error_msg       :	(s)
        """
        if not self.urfa_call(0x2126):
            raise Exception("Fail of urfa_call(0x2126) [rpcf_edit_user_new]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['login'], U_TP_S)
        self.pck.add_data(params['password'], U_TP_S)
        self.pck.add_data(params['full_name'], U_TP_S)
        self.pck.add_data(params['is_juridical'], U_TP_I)
        self.pck.add_data(params['jur_address'], U_TP_S)
        self.pck.add_data(params['act_address'], U_TP_S)
        self.pck.add_data(params['flat_number'], U_TP_S)
        self.pck.add_data(params['entrance'], U_TP_S)
        self.pck.add_data(params['floor'], U_TP_S)
        self.pck.add_data(params['district'], U_TP_S)
        self.pck.add_data(params['building'], U_TP_S)
        self.pck.add_data(params['passport'], U_TP_S)
        self.pck.add_data(params['house_id'], U_TP_I)
        self.pck.add_data(params['work_tel'], U_TP_S)
        self.pck.add_data(params['home_tel'], U_TP_S)
        self.pck.add_data(params['mob_tel'], U_TP_S)
        self.pck.add_data(params['web_page'], U_TP_S)
        self.pck.add_data(params['icq_number'], U_TP_S)
        self.pck.add_data(params['tax_number'], U_TP_S)
        self.pck.add_data(params['kpp_number'], U_TP_S)
        self.pck.add_data(params['email'], U_TP_S)
        self.pck.add_data(params['bank_id'], U_TP_I)
        self.pck.add_data(params['bank_account'], U_TP_S)
        self.pck.add_data(params['comments'], U_TP_S)
        self.pck.add_data(params['personal_manager'], U_TP_S)
        self.pck.add_data(params['connect_date'], U_TP_I)
        self.pck.add_data(params['is_send_invoice'], U_TP_I)
        self.pck.add_data(params['advance_payment'], U_TP_I)
        self.pck.add_data(params['switch_id'], U_TP_I)
        self.pck.add_data(params['port_number'], U_TP_I)
        self.pck.add_data(params['binded_currency_id'], U_TP_I)
        if 'addparams' not in params: params['addparams'] = {}
        self.pck.add_data(len(params['addparams']), U_TP_I)
        for param_id, param_value in params['addparams'].iteritems():
            self.pck.add_data(param_id, U_TP_I)
            self.pck.add_data(param_value, U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['user_id'] = self.pck.get_data(U_TP_I)
        if not ret['user_id']:
            ret['error_code'] = self.pck.get_data(U_TP_I)
            ret['error_msg'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def user_change_intstat(self, params):
        """ ON / OFF internet status for user
        @params:
        :(s)  user_id :	(i)
        :(s)  need_block :	(i)	- 1 to block, 0 not to block
        @returns:
        :	True if success
        """
        if not self.urfa_call(0x2003):
            raise Exception("Fail of urfa_call(0x2003) [rpcf_change_intstat_for_user]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['need_block'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")

    def user_del(self, params):
        """ remove user by id (need check existing before, not recive answer else)
        @params:
        :(s)  user_id :	(i)
        @returns:
        :(s)  result :	(i) - 0 - if 'Ok', error-msg - else
        """
        if not self.urfa_call(0x200e):
            raise Exception("Fail of urfa_call(0x200e) [rpcf_remove_user]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['result'] = self.pck.get_data(U_TP_I)
        if ret['result']:
            if ret['result'] == -22:
                ret['result'] = 'failed to delete user: Unlink all service links first'
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def user_contacts_get(self, params):
        """ get user add-contacts
        @params:
        :(s)  user_id :	(i)
        @returns:
        :(i)    cid : dict	(i)  dict of contacts by contact id's
        :(s)    descr       :	(s) -   description
        :(s)    reason      :	(s) -   reason
        :(s)    person      :	(s) -   person name
        :(s)    short_name  :	(s) -   person shortname
        :(s)    contact     :	(s) -   contact (phone, fax, etc)
        :(s)    email       :	(s) -   email
        :(s)    id_exec_man :	(s) is boss ? (None, 'CEO', 'BKR')
        """
        if not self.urfa_call(0x2040):
            raise Exception("Fail of urfa_call(0x2040) [rpcf_get_user_contacts_new]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        size = self.pck.get_data(U_TP_I)
        while size:
            self.pck.recv(self.sck)
            cid = self.pck.get_data(U_TP_I)
            ret[cid] = {}
            ret[cid]['descr'] = self.pck.get_data(U_TP_S)
            ret[cid]['reason'] = self.pck.get_data(U_TP_S)
            ret[cid]['person'] = self.pck.get_data(U_TP_S)
            ret[cid]['short_name'] = self.pck.get_data(U_TP_S)
            ret[cid]['contact'] = self.pck.get_data(U_TP_S)
            ret[cid]['email'] = self.pck.get_data(U_TP_S)
            ret[cid]['id_exec_man'] = U_CONTACT_BOSS[self.pck.get_data(U_TP_I)]
            size -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def user_contact_add(self, params):
        """ add for user add-contact
        @params:
        :(s)  user_id :	(i)
        :(s)  descr       :	(s) = '' -   description
        :(s)  reason      :	(s) = '' -   reason
        :(s)  person      :	(s) = '' -   person name
        :(s)  short_name  :	(s) = '' -   person shortname
        :(s)  contact     :	(s) = '' -   contact (phone, fax, etc)
        :(s)  email       :	(s) = '' -   email
        :(s)  id_exec_man :	(s) = 0  -   (s) is boss ? (None, 'CEO', 'BKR')
        @returns:
        :	True if success
        """
        if not self.urfa_call(0x2042):
            raise Exception("Fail of urfa_call(0x2042) [rpcf_add_user_contact]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'descr' not in params: params['descr'] = ''
        self.pck.add_data(params['descr'], U_TP_S)
        if 'reason' not in params: params['reason'] = ''
        self.pck.add_data(params['reason'], U_TP_S)
        if 'person' not in params: params['person'] = ''
        self.pck.add_data(params['person'], U_TP_S)
        if 'short_name' not in params: params['short_name'] = ''
        self.pck.add_data(params['short_name'], U_TP_S)
        if 'contact' not in params: params['contact'] = ''
        self.pck.add_data(params['contact'], U_TP_S)
        if 'email' not in params: params['email'] = ''
        self.pck.add_data(params['email'], U_TP_S)
        if 'id_exec_man' not in params: params['id_exec_man'] = 0
        self.pck.add_data(U_CONTACT_BOSS.index(params['id_exec_man']), U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")

    def user_contact_edit(self, params):
        """ edit add-contact of user by contact id
        @params:
        :(s)  cid :	(i) -   add-contact id
        :(s)  descr       :	(s)
        :(s)  reason      :	(s)
        :(s)  person      :	(s)
        :(s)  short_name  :	(s)
        :(s)  contact     :	(s)
        :(s)  email       :	(s)
        :(s)  id_exec_man :	(s)
        @returns:
        :	True if success
        """
        if not self.urfa_call(0x2043):
            raise Exception("Fail of urfa_call(0x2043) [rpcf_edit_user_contact]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
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

    def user_contact_del(self, params):
        """ delete add-contact from user profile
        @params:
        :(s)  cid :	(i)	 - contact global id
        @returns:
        :	True if success
        """
        if not self.urfa_call(0x2023):
            raise Exception("Fail of urfa_call(0x2023) [rpcf_del_user_contact]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['cid'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")

    def user_add_to_group(self, params):
        """ add user to group
        @params:
        :(s)  user_id   :	(i)
        :(s)  group_id  :	(i)
        @returns:
        :	True if success
        """
        if not self.urfa_call(0x2552):
            raise Exception("Fail of urfa_call(0x2552) [rpcf_add_group_to_user]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['group_id'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")

    def user_del_from_group(self, params):
        """ remove user by uid from group
        @params:
        :(s)  user_id   : (i)
        :(s)  group_id  : (i)
        @returns:
        :	True if success
        """
        if not self.urfa_call(0x2408):
            raise Exception("Fail of urfa_call(0x2408) [rpcf_remove_user_from_group]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['group_id'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")

    def user_get_info(self, params):
        """ get info about User
        @params:
        :(s)  user_id :	(i)
        @returns:
        :(s)  user_id           :	(i)	 -
        :(s)    error : dict:
        :(i)      code : (s) msg    -   if recived user id == 0 - return error dict {code:msg}
        :(s)  accounts : dict:	 -  dict of accounts owned by user
        :(i)    account_id  : (s) account_name
        :(s)  login             :	(s)	 - \
        :(s)  password          :	(s)	 - |
        :(s)  basic_account     :	(i)	 - |
        :(s)  full_name         :	(s)	 - |
        :(s)  create_date       :	(i)	 - |
        :(s)  last_change_date  :	(i)	 - |
        :(s)  who_create        :	(i)	 - |
        :(s)  who_change        :	(i)	 - |
        :(s)  is_juridical      :	(i)	 - |
        :(s)  jur_address       :	(s)	 - |
        :(s)  act_address       :	(s)	 - |
        :(s)  work_tel          :	(s)	 - |
        :(s)  home_tel          :	(s)	 - |
        :(s)  mob_tel           :	(s)	 - |
        :(s)  web_page          :	(s)	 - |
        :(s)  icq_number        :	(s)	 - | basic fields
        :(s)  tax_number        :	(s)	 - |
        :(s)  kpp_number        :	(s)	 - |
        :(s)  bank_id           :	(i)	 - |
        :(s)  bank_account      :	(s)	 - |
        :(s)  comments          :	(s)	 - |
        :(s)  personal_manager  :	(s)	 - |
        :(s)  connect_date      :	(i)	 - |
        :(s)  email             :	(s)	 - |
        :(s)  is_send_invoice   :	(i)	 - |
        :(s)  advance_payment   :	(i)	 - |
        :(s)  house_id          :	(i)	 - |
        :(s)  flat_number       :	(s)	 - |
        :(s)  entrance          :	(s)	 - |
        :(s)  floor             :	(s)	 - |
        :(s)  district          :	(s)	 - |
        :(s)  building          :	(s)	 - |
        :(s)  passport          :	(s)	 - /
        :(s)  addparams   :	dict :	 - dict of additional parameters {id:value}
        :(i)    paramid : (s) value
        """
        if not self.urfa_call(0x2006):
            raise Exception("Fail of urfa_call(0x2006) [rpcf_get_userinfo]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['user_id'] = self.pck.get_data(U_TP_I)
        if not ret['user_id']:
            ret['error'] = dict({10: "user not found"})
            return ret
        accounts_count = self.pck.get_data(U_TP_I)
        ret['accounts'] = {}
        while accounts_count:
            account_id = self.pck.get_data(U_TP_I)
            account_name = self.pck.get_data(U_TP_S)
            ret['accounts'][account_id] = account_name
            accounts_count -= 1
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
        addparams_cnt = self.pck.get_data(U_TP_I)
        ret['addparams'] = {}
        while addparams_cnt:
            paramid = self.pck.get_data(U_TP_I)
            value = self.pck.get_data(U_TP_S)
            ret['addparams'][paramid] = value
            addparams_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def user_get_log(self, params):
        """ get action-log, return
        : do SELECT user_id,date,who,what,comment
        :    FROM user_log
        :    WHERE 1=1 AND user_id=user_id AND what=act AND date>tstart AND date<tstop
        : not return first record where 'add user' - i donno why =\
        @params:
        :(s)  user_id   :	(i)
        :(s)  tstart    :	(i)	= 0     - time from
        :(s)  tstop     :	(i)	= now()   - time to
        :(s)  group_id  :	(i)	= 1     - id of system group (1 - admins)
        :(s)  act       :	(s)	= ''    - filter of action type
        @returns:
        :(i)  num: dict:	    -
        :(s)    user_id     :	(i)
        :(s)    user_login  :	(s)
        :(s)    who         :	(i)	 - action owner id
        :(s)    usd_login   :	(s)	 - action owner login
        :(s)    date        :	(i)	 - date of action
        :(s)    want        :	(s)	 - action
        :(s)    comment     :	(s)	 - comment to action
        """
        if not self.urfa_call(0x2025):
            raise Exception("Fail of urfa_call(0x2025) [rpcf_get_user_log]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'tstart' not in params: params['tstart'] = 0
        self.pck.add_data(params['tstart'], U_TP_I)
        if 'tstop' not in params: params['tstop'] = now()
        self.pck.add_data(params['tstop'], U_TP_I)
        if 'group_id' not in params: params['group_id'] = 1
        self.pck.add_data(params['group_id'], U_TP_I)
        if 'act' not in params: params['act'] = ''
        self.pck.add_data(params['act'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        size = self.pck.get_data(U_TP_I) - 1
        for cnt in range(size):
            self.pck.recv(self.sck)
            ret[cnt] = {}
            ret[cnt]['user_id'] = self.pck.get_data(U_TP_I)
            ret[cnt]['user_login'] = self.pck.get_data(U_TP_S)
            ret[cnt]['who'] = self.pck.get_data(U_TP_I)
            ret[cnt]['usd_login'] = self.pck.get_data(U_TP_S)
            ret[cnt]['date'] = self.pck.get_data(U_TP_I)
            ret[cnt]['want'] = self.pck.get_data(U_TP_S)
            ret[cnt]['comment'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def user_get_tplink(self, params):
        """ get tariff-link by user id
        @params:
        :(s)  user_id :	(i)
        @returns:
        :(i)  tplink_id  : dict:            - dict of tp-links
        :(s)    account_id          : (i)	- id of account owned this tplink
        :(s)    discount_period_id  : (i)   - discount period id linked to tplink
        """
        if not self.urfa_call(0x301e):
            raise Exception("Fail of urfa_call(0x301e) [rpcf_get_tplink_for_user] ")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        tplinks_cnt = self.pck.get_data(U_TP_I)
        self.pck.recv(self.sck)
        for cnt in range(tplinks_cnt):
            tplink_id = self.pck.get_data(U_TP_I)
            ret[tplink_id] = {}
            ret[tplink_id]['account_id'] = self.pck.get_data(U_TP_I)
        self.pck.recv(self.sck)
        for tplnk in ret:
            ret[tplnk]['discount_period_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def user_get_accounts(self, params):
        """ get accounts of user
        @params:
        :(s)  user_id :	(i)
        @returns:
        :(i) account_id : (s) account_name : (s) - dict of accounts: {id:'name'}
        """
        if not self.urfa_call(0x2033):
            raise Exception("Fail of urfa_call(0x2033) [rpcf_get_user_account_list]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        count = self.pck.get_data(U_TP_I)
        while count:
        #            self.pck.recv(self.sck)
            account_id = self.pck.get_data(U_TP_I)
            ret[account_id] = {}
            ret[account_id] = self.pck.get_data(U_TP_S)
            count -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def user_get_groups(self, params):
        """ get groups of user
        @params:
        :(s)  user_id :	(i)
        @returns:
        : (i) group_id : (s) group_name
        """
        if not self.urfa_call(0x2550):
            raise Exception("Fail of urfa_call(0x2550) [rpcf_get_groups_for_user]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        grp_cnt = self.pck.get_data(U_TP_I)
        while grp_cnt:
            group_id = self.pck.get_data(U_TP_I)
            ret[group_id] = self.pck.get_data(U_TP_S)
            grp_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def user_get_tariffs(self, params):
        """ get tariffs of user (and account if need)
        @params:
        :(s)  user_id       :	(i)
        :(s)  account_id    :	(i) = 0 - account id of user, if 0 - all acc's
        @returns:
        :(i)  tariff_link_id : dict: -  dict of tariffs
        :(s)    tariff_current      :	(i)  -  current tariff id
        :(s)    tariff_next         :	(i)  -  next tariff id
        :(s)    discount_period     :	(i)  -  discount period id
        """
        if not self.urfa_call(0x3017):
            raise Exception("Fail of urfa_call(0x3017) [rpcf_get_user_tariffs]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        tariffs_cnt = self.pck.get_data(U_TP_I)
        while tariffs_cnt:
            tp_id_current = self.pck.get_data(U_TP_I)
            tp_id_next = self.pck.get_data(U_TP_I)
            discount_period_id = self.pck.get_data(U_TP_I)
            tplink_id = self.pck.get_data(U_TP_I)
            ret[tplink_id] = {'tariff_current': tp_id_current,
                              'tariff_next': tp_id_next,
                              'discount_period': discount_period_id}
            tariffs_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def groups_list_get(self, params=dict()):
        """ get list of groups
        @params:
        :(s)  user_id :	(i) = 0 - user id (i donno why  - has no effect 0_o)
        @returns:
        :(i)    group_id : (s) group_name :	dict { group_id : group_name}
        """
        if not self.urfa_call(0x2400):
            raise Exception("Fail of urfa_call(0x2400) [rpcf_get_groups_list]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        if 'user_id' not in params: params['user_id'] = 0
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        grp_cnt = self.pck.get_data(U_TP_I)
        while grp_cnt:
            self.pck.recv(self.sck)
            grp_id = self.pck.get_data(U_TP_I)
            ret[grp_id] = self.pck.get_data(U_TP_S)
            grp_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def group_get_id_by_name(self, params):
        """ get group id by group name
        @params:
        :(s)  group_name :	(s)
        @returns:
        :(s)  group_id :	(i)
        """
        if not self.urfa_call(0x240c):
            raise Exception("Fail of urfa_call(0x240c) [rpcf_get_group_id_by_name]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['group_name'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['group_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def group_info_get(self, params):
        """ get info about group by id (name, included user_id's & user_login's)
        @params:
        :(s)  group_id :	(i)
        @returns:
        :(s)  group_name : dict:
        :(i)    user_id : (s) login
        """
        if not self.urfa_call(0x2409):
            raise Exception("Fail of urfa_call(0x2409) [rpcf_get_group_info]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['group_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        group_name = self.pck.get_data(U_TP_S)
        uids_cnt = self.pck.get_data(U_TP_I) - 1
        ret[group_name] = {}
        uid0 = self.pck.get_data(U_TP_I)
        login0 = self.pck.get_data(U_TP_S)
        ret[group_name][uid0] = login0
        while uids_cnt:
            self.pck.recv(self.sck)
            uid = self.pck.get_data(U_TP_I)
            ret[group_name][uid] = self.pck.get_data(U_TP_S)
            uids_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def group_add(self, params):
        """ add group
        @params:
        :(s)  group_id :	(i)
        :(s)  group_name :	(s) - cyrillic allow
        @returns:
        :	True if success
        """
        if not self.urfa_call(0x2401):
            raise Exception("Fail of urfa_call(0x2401) [rpcf_add_group]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['group_id'], U_TP_I)
        self.pck.add_data(params['group_name'], U_TP_S)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")

    def group_rename(self, params):
        """ edit name of group by id
        @params:
        :(s)  group_id :	(i)
        :(s)  group_name :	(s)  - cyrillic allow
        @returns:
        :	True if success
        """
        if not self.urfa_call(0x2402):
            raise Exception("Fail of urfa_call(0x2402) [rpcf_edit_group]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['group_id'], U_TP_I)
        self.pck.add_data(params['group_name'], U_TP_S)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")

    def group_users_add(self, params):
        """ add users by uid's to group
        @params:
        :(s) group_id : (i)
        :(s) user_ids : tuple of (i) user_ids
        @returns:
        :	True if success
        """
        if not self.urfa_call(0x2407):
            raise Exception("Fail of urfa_call(0x2407) [rpcf_add_users_to_group]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['group_id'], U_TP_I)
        self.pck.add_data(len(params['user_ids']), U_TP_I)
        for uid in params['user_ids']:
            self.pck.add_data(uid, U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")

    def group_del(self, params):
        """ delete group by id
        @params:
        :(s)  group_id :	(i)
        @returns:
        :	True if success
        """
        if not self.urfa_call(0x240b):
            raise Exception("Fail of urfa_call(0x240b) [rpcf_del_group]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['group_id'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")

    def account_add(self, params):
        """ add account to user
        @params:
        :(s)  user_id       :	(i)
        :(s)  is_basic      :	(i) = 1	    - it's basic account ? (0/1)
        :(s)  is_blocked    :	(i)	= 0     - do blocking ? (0/1) 1 = allways make full manual block (1739)
        :(s)  deprecated0   :	(s) = ' '
        :(s)  balance       :	(d)	= 0     - balance value
        :(s)  credit        :	(d)	= 0     - credit size
        :(s)  deprecated1   :	(i) = 0
        :(s)  deprecated2   :	(i) = 0
        :(s)  deprecated3   :	(d) = 0
        :(s)  deprecated4   :	(d) = 0
        :(s)  deprecated5   :	(i) = 0
        :(s)  vat_rate      :	(d) = 0     - VAT (NDS) in %
        :(s)  sale_tax_rate :	(d)	= 0     - ???
        :(s)  int_status    :	(i)	= 1     - internet status
        @returns:
        :(s)  account_id :	(i)
        :(s)    error : dict: - error if fail
        :(i)      code : (s) msg
        """
        if not self.urfa_call(0x2031):
            raise Exception("Fail of urfa_call(0x2031) [rpcf_add_account]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'is_basic' not in params: params['is_basic'] = 1
        self.pck.add_data(params['is_basic'], U_TP_I)
        if 'is_blocked' not in params: params['is_blocked'] = 0
        self.pck.add_data(params['is_blocked'], U_TP_I)
        if 'deprecated0' not in params: params['deprecated0'] = ' '
        self.pck.add_data(params['deprecated0'], U_TP_S)
        if 'balance' not in params: params['balance'] = 0.0
        self.pck.add_data(params['balance'], U_TP_D)
        if 'credit' not in params: params['credit'] = 0.0
        self.pck.add_data(params['credit'], U_TP_D)
        if 'deprecated1' not in params: params['deprecated1'] = 0
        self.pck.add_data(params['deprecated1'], U_TP_I)
        if 'deprecated2' not in params: params['deprecated2'] = 0
        self.pck.add_data(params['deprecated2'], U_TP_I)
        if 'deprecated3' not in params: params['deprecated3'] = 0.0
        self.pck.add_data(params['deprecated3'], U_TP_D)
        if 'deprecated4' not in params: params['deprecated4'] = 0.0
        self.pck.add_data(params['deprecated4'], U_TP_D)
        if 'deprecated5' not in params: params['deprecated5'] = 0
        self.pck.add_data(params['deprecated5'], U_TP_I)
        if 'vat_rate' not in params: params['vat_rate'] = 0.0
        self.pck.add_data(params['vat_rate'], U_TP_D)
        if 'sale_tax_rate' not in params: params['sale_tax_rate'] = 0.0
        self.pck.add_data(params['sale_tax_rate'], U_TP_D)
        if 'int_status' not in params: params['int_status'] = 1
        self.pck.add_data(params['int_status'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['account_id'] = self.pck.get_data(U_TP_I)
        if not ret['account_id']:
            ret['error'] = dict({11: "unable to add account"})
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def account_info_get(self, params):
        """ description
        @params:
        :(s)  account_id :	(i)
        @returns:
        :(s)  unused                    :	(i)	 - ???
        :(s)  is_blocked                :	(i)	 - blocking reason
        :(s)    blocked_flags : list :
        :(s)      U_BL_SYS            - it's system block ?
        :(s)      U_BL_SYS_REC_AB     - recalc abon when system block ?
        :(s)      U_BL_SYS_REC_PAY    - recalc prepaid traf when system block ?
        :(s)      U_BL_MAN            - it's manual block ?
        :(s)      U_BL_MAN_REC_AB     - recalc abon when block ?
        :(s)      U_BL_MAN_REC_PAY    - recalc prepaid traf when block ?
        :(s)  dealer_account_id         :	(i)	 - ???
        :(s)  is_dealer                 :	(i)	 - is dealer ?
        :(s)  vat_rate                  :	(d)	 - VAT (NDS) in %
        :(s)  sale_tax_rate             :	(d)	 - ???
        :(s)  comission_coefficient     :	(d)	 - ???
        :(s)  default_comission_value   :	(d)	 - ???
        :(s)  credit                    :	(d)	 - credit size
        :(s)  balance                   :	(d)	 - balance value
        :(s)  int_status                :	(i)	 - internet status
        :(s)  block_recalc_abon         :	(i)	 - recalc abon pay when sys block ?
        :(s)  block_recalc_prepaid      :	(i)	 - recalc prepaid when sys block ?
        :(s)  unlimited                 :	(i)	 - unlimited mode ?
        """
        if not self.urfa_call(0x2030):
            raise Exception("Fail of urfa_call(0x2030) [rpcf_get_accountinfo]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['unused'] = self.pck.get_data(U_TP_I)
        ret['is_blocked'] = self.pck.get_data(U_TP_I)
        blocked2ret(ret['is_blocked'], ret)
        ret['dealer_account_id'] = self.pck.get_data(U_TP_I)
        ret['is_dealer'] = self.pck.get_data(U_TP_I)
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

    def account_edit(self, params):
        """ edit account and save changes
        @params:
        :(s)  account_id            :	(i)
        :(s)  discount_period_id    :	(i) - id of discount period (from tarif-links)
        :(s)  credit                :	(d)
        :(s)  is_blocked            :	(i) - blocked reason code (bit-mask)
        :       if is_blocked:
        :(s)      block_start_date  :	(i)
        :(s)      block_end_date    :	(i)
        :(s)  dealer_account_id     :	(i) - ???
        :(s)  vat_rate              :	(d) - VAT (NDS) %
        :(s)  sale_tax_rate         :	(d) - ???
        :(s)  int_status            :	(i) - internet status (1/0)
        :(s)  sys_block_recalc_abon     :	(i) - recalc abon pay when sys block ? (1 - unchecked / 0 - checked)
        :(s)  sys_block_recalc_prepaid  :	(i) - recalc prepaid when sys block ? (1 - unchecked / 0 - checked)
        :(s)  unlimited             :	(i) - unimited mode ? (1/0)
        @returns:
        :	True if success
        """
        if not self.urfa_call(0x2032):
            raise Exception("Fail of urfa_call(0x2032) [rpcf_save_account]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['discount_period_id'], U_TP_I)
        self.pck.add_data(params['credit'], U_TP_D)
        self.pck.add_data(params['is_blocked'], U_TP_I)
        if params['is_blocked']:
            self.pck.add_data(params['block_start_date'], U_TP_I)
            self.pck.add_data(params['block_end_date'], U_TP_I)
        self.pck.add_data(params['dealer_account_id'], U_TP_I)
        self.pck.add_data(params['vat_rate'], U_TP_D)
        self.pck.add_data(params['sale_tax_rate'], U_TP_D)
        self.pck.add_data(params['int_status'], U_TP_I)
        self.pck.add_data(params['block_recalc_abon'], U_TP_I)
        self.pck.add_data(params['block_recalc_prepaid'], U_TP_I)
        self.pck.add_data(params['unlimited'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")

    def account_block(self, params):
        """ block account by id (not unblock with 0 - just block)
        @params:
        :(s)  account_id :	(i)
        :(s)  is_blocked :	(i)  - blocked reason (binmask is_blocked)
        @returns:
        :	True if success
        """
        if not self.urfa_call(0x2037):
            raise Exception("Fail of urfa_call(0x2037) [rpcf_block_account]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['is_blocked'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")

    def account_get_user(self, params):
        """ get user id by acc id
        @params:
        :(s)  account_id :	(i)
        @returns:
        :(s)  user_id :	(i)
        :(s)    error : dict: - error if failed
        :(i)      code : (s) msg
        """
        if not self.urfa_call(0x2026):
            raise Exception("Fail of urfa_call(0x2026) [rpcf_get_user_by_account]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['user_id'] = self.pck.get_data(U_TP_I)
        if not ret['user_id']:
            ret['error'] = dict({19: "No such account linked with user"})
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def account_services_get(self, params):
        """ get services in account
        @params:
        :(s)  account_id :	(i)
        @returns:
        :(i)    service_id : dict:
        :(s)      type              :	(i)  -  id of service type
        :(s)      name              :	(s)  -  name of service
        :(s)      tariff_name       :	(s)  -  name of tariff
        :(s)      cost              :	(d)  -  cost of service
        :(s)      slink_id          :	(i)  -  id of service-link
        :(s)      discount_period   :	(i)  -  id of discount period
        """
        if not self.urfa_call(0x2700):
            raise Exception("Fail of urfa_call(0x2700) [rpcf_get_all_services_for_user]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        slink_id_count = self.pck.get_data(U_TP_I)
        while slink_id_count:
            self.pck.recv(self.sck)
            service_id = self.pck.get_data(U_TP_I)
            ret[service_id] = {}
            if service_id != -1:
                ret[service_id]['type'] = self.pck.get_data(U_TP_I)
                ret[service_id]['name'] = self.pck.get_data(U_TP_S)
                ret[service_id]['tariff_name'] = self.pck.get_data(U_TP_S)
                ret[service_id]['cost'] = self.pck.get_data(U_TP_D)
                ret[service_id]['slink_id'] = self.pck.get_data(U_TP_I)
                ret[service_id]['discount_period'] = self.pck.get_data(U_TP_I)
            else:
                ret[service_id]['type'] = -1
                ret[service_id]['name'] = ''
                ret[service_id]['tariff_name'] = ''
                ret[service_id]['cost'] = -1
                ret[service_id]['slink_id'] = -1
                ret[service_id]['discount_period'] = -1
            slink_id_count -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def account_del(self, params):
        """ remove account by id
        @params:
        :(s)  account_id :	(i)
        @returns:
        :(s)  ret_code :	(i)
        """
        if not self.urfa_call(0x2034):
            raise Exception("Fail of urfa_call(0x2034) [rpcf_remove_account]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['ret_code'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def account_tplans_srv_and_slink_get(self, params):
        """ get service and service-link of user's tariff
        @params:
        :(s)  user_id           :	(i)
        :(s)  account_id        :	(i)
        :(s)  tariff_id         :	(i)
        :(s)  tariff_link_id    :	(i)
        :(s)  unused            :	(i)  - ???
        @returns:
        :(i)  slink_id : dict:
        :(s)    service_id      :	(i)
        :(s)    service_name    :	(s)
        :(s)    service_type    :	(i)
        :(s)    comment         :	(s)
        :(s)    value           :	(i)  - ???
        """
        if not self.urfa_call(0x301a):
            raise Exception("Fail of urfa_call(0x301a) [rpcf_get_tps_for_user]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.add_data(params['tariff_link_id'], U_TP_I)
        self.pck.add_data(params['unused'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        services_cnt = self.pck.get_data(U_TP_I)
        while services_cnt:
            self.pck.recv(self.sck)
            sid = self.pck.get_data(U_TP_I)
            service_name = self.pck.get_data(U_TP_S)
            service_type = self.pck.get_data(U_TP_I)
            comment = self.pck.get_data(U_TP_S)
            slink_id = self.pck.get_data(U_TP_I)
            value = self.pck.get_data(U_TP_I)
            ret[slink_id] = {
                'service_id': sid,
                'service_name': service_name,
                'service_type': service_type,
                'comment': comment,
                'value': value
            }
            services_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def account_tariffs_history_get(self, params, keyfield=None):
        """ get history of account changes (from old to new) except current
        @params:
        :(s)  account_id :	(i)
        @returns:
        :(i)  link_date : dict: - date of link to tariff
        :(s)    tariff_id       :	(i)
        :(s)    tariff_name     :	(s)
        :(s)    unlink_date     :	(i)
        """
        if not self.urfa_call(0x301c):
            raise Exception("Fail of urfa_call(0x301c) [rpcf_get_tariffs_history]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {} if keyfield else []
        th_count = self.pck.get_data(U_TP_I)
        while th_count:
            self.pck.recv(self.sck)
            tmp_dict = {}
            tmp_dict['tariff_id'] = self.pck.get_data(U_TP_I)
            tmp_dict['link_date'] = self.pck.get_data(U_TP_I)
            tmp_dict['unlink_date'] = self.pck.get_data(U_TP_I)
            tmp_dict['tariff_name'] = self.pck.get_data(U_TP_S)
            if keyfield in tmp_dict:
                ret[tmp_dict[keyfield]] = tmp_dict
            else:
                ret.append(tmp_dict)
            th_count -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def account_tp_link_add(self, params):
        """ make tariff link
        @params:
        :(s)  user_id               :	(i)
        :(s)  account_id            :	(i) = 0
        :(s)  tariff_id_current     :	(i)
        :(s)  tariff_id_next        :	(i) = tariff_id_current
        :(s)  discount_period_id    :	(i)
        :(s)  tariff_link_id        :	(i) = 0 - if not 0 then edit tariff link
        @returns:
        :(s)  tariff_link_id :	(i)  - id of created tariff_link if success
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        """
        if not self.urfa_call(0x3018):
            raise Exception("Fail of urfa_call(0x3018) [rpcf_link_user_tariff]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['tariff_id_current'], U_TP_I)
        if 'tariff_id_next' not in params: params['tariff_id_next'] = params['tariff_id_current']
        self.pck.add_data(params['tariff_id_next'], U_TP_I)
        self.pck.add_data(params['discount_period_id'], U_TP_I)
        if 'tariff_link_id' not in params: params['tariff_link_id'] = 0
        self.pck.add_data(params['tariff_link_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        tariff_link_id = self.pck.get_data(U_TP_I)
        if tariff_link_id:
            ret['tariff_link_id'] = tariff_link_id
        else:
            ret['error'] = dict({13: "unable to link user tariff"})
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def account_tp_link_del(self, params):
        """ unlink tariff from account (delete tariff_link)
        @params:
        :(s)  user_id           :	(i)
        :(s)  account_id        :	(i)
        :(s)  tariff_link_id    :	(i)
        @returns:
        :	True if success
        """
        if not self.urfa_call(0x3019):
            raise Exception("Fail of urfa_call(0x3019) [rpcf_unlink_user_tariff]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['tariff_link_id'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")

    def account_external_id_set(self, params):
        """ set external id to account
        @params:
        :(s)  aid           :	(i)  - account id
        :(s)  external_id   :	(s)  - ext id
        @returns:
        :(s)  result :	(i)  - result = account id
        """
        if not self.urfa_call(0x2038):
            raise Exception("Fail of urfa_call(0x2038) [rpcf_set_account_external_id]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['aid'], U_TP_I)
        self.pck.add_data(params['external_id'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def account_external_id_get(self, params):
        """ get external id from account
        @params:
        :(s)  aid :	(i)  - account id
        @returns:
        :(s)  external_id :	(s)  - ext id
        """
        if not self.urfa_call(0x2039):
            raise Exception("Fail of urfa_call(0x2039) [rpcf_get_account_external_id]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['aid'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['external_id'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def account_external_id_is_used(self, params):
        """ do exist owner of ext-id ?
        @params:
        :(s)  external_id :	(s)
        @returns:
        :(s)  aid :	(i)  - account id owner
        """
        if not self.urfa_call(0x203a):
            raise Exception("Fail of urfa_call(0x203a) [rpcf_is_account_external_id_used]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['external_id'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['aid'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def account_payment_add(self, params):
        """ do email-notify of payment for user
        @params:
        :(s)  account_id        :	(i)
        :(s)  param             :	(i) = 0     - ???
        :(s)  sum               :	(d) = 0     - sum of payment
        :(s)  currency_id       :	(i) = 810   - currency (810 = ruble)
        :(s)  payment_date      :	(i) = now()   - date of payment
        :(s)  burn_date         :	(i) = 0     - date of dead payment
        :(s)  payment_method    :	(i) = 1     - method of payent (1 = cash)
        :(s)  admin_comment     :	(s) = ''    - comment of admin
        :(s)  comment           :	(s) = ''    - comment for payment
        :(s)  payment_ext_number:	(s) = ''    - ext-number of payment
        :(s)  payment_to_invoice:	(i) = 0     - do add payment to invoice ?
        :(s)  turn_on_inet      :   (i) = 1     - do turn internet on ?
        :(s)  notify            :	(i) = 0     - do email-notify
        :(s)  hash              :	(s) = ''    - ???
        @returns:
        :(s)  payment_transaction :	(i)  - id of payment transaction
        """
        if not self.urfa_call(0x3113):
            raise Exception("Fail of urfa_call(0x3113) [rpcf_add_payment_for_account_notify]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['account_id'], U_TP_I)
        if 'param' not in params: params['param'] = 0
        self.pck.add_data(params['param'], U_TP_I)
        if 'sum' not in params: params['sum'] = 0.0
        self.pck.add_data(params['sum'], U_TP_D)
        if 'currency_id' not in params: params['currency_id'] = 810
        self.pck.add_data(params['currency_id'], U_TP_I)
        if 'payment_date' not in params: params['payment_date'] = now()
        self.pck.add_data(params['payment_date'], U_TP_I)
        if 'burn_date' not in params: params['burn_date'] = 0
        self.pck.add_data(params['burn_date'], U_TP_I)
        if 'payment_method' not in params: params['payment_method'] = 1
        self.pck.add_data(params['payment_method'], U_TP_I)
        if 'admin_comment' not in params: params['admin_comment'] = ''
        self.pck.add_data(params['admin_comment'], U_TP_S)
        if 'comment' not in params: params['comment'] = ''
        self.pck.add_data(params['comment'], U_TP_S)
        if 'payment_ext_number' not in params: params['payment_ext_number'] = ''
        self.pck.add_data(params['payment_ext_number'], U_TP_S)
        if 'payment_to_invoice' not in params: params['payment_to_invoice'] = 0
        self.pck.add_data(params['payment_to_invoice'], U_TP_I)
        if 'turn_on_inet' not in params: params['turn_on_inet'] = 1
        self.pck.add_data(params['turn_on_inet'], U_TP_I)
        if 'notify' not in params: params['notify'] = 0
        self.pck.add_data(params['notify'], U_TP_I)
        if 'hash' not in params: params['hash'] = ''
        self.pck.add_data(params['hash'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['payment_transaction'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def account_payment_rollback(self, params):
        """ do cancel of payment by transaction id (make a new payment with negative sum)
        @params:
        :(s)  payment_transaction :	(i)  - id of paymnet transaction
        :(s)  comment_for_user :	(s) = ''
        :(s)  comment_for_admin :	(s) = ''
        @returns:
        :	True if success
        """
        if not self.urfa_call(0x3111):
            raise Exception("Fail of urfa_call(0x3111) [rpcf_cancel_payment_for_account]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['payment_transaction'], U_TP_I)
        if 'comment_for_user' not in params: params['comment_for_user'] = ''
        self.pck.add_data(params['comment_for_user'], U_TP_S)
        if 'comment_for_admin' not in params: params['comment_for_admin'] = ''
        self.pck.add_data(params['comment_for_admin'], U_TP_S)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")

    def services_list_get(self, params=dict()):
        """ get list of services
        @params:
        :(s)  which_service :	(i) = -1  -
        @returns:
        :(i)  id : dict:  - service id
        :(s)    name        :	(s)
        :(s)    type        :	(i)
        :(s)    comment     :	(s)
        :(s)    status      :	(i)
        : if status == 2:
        :(s)    tariff_name :	(s)  - tariff name if service linked ti tariff
        """
        if not self.urfa_call(0x2101):
            raise Exception("Fail of urfa_call(0x2101) [rpcf_get_services_list]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        if 'which_service' not in params: params['which_service'] = -1
        self.pck.add_data(params['which_service'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        services_count = self.pck.get_data(U_TP_I)
        while services_count:
            self.pck.recv(self.sck)
            srvc_id = self.pck.get_data(U_TP_I)
            ret[srvc_id] = {}
            ret[srvc_id]['name'] = self.pck.get_data(U_TP_S)
            ret[srvc_id]['type'] = self.pck.get_data(U_TP_I)
            ret[srvc_id]['comment'] = self.pck.get_data(U_TP_S)
            ret[srvc_id]['status'] = self.pck.get_data(U_TP_I)
            if ret[srvc_id]['status'] == 2:
                ret[srvc_id]['tariff_name'] = self.pck.get_data(U_TP_S)
            services_count -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def services_templates_list_get(self):
        """ get list of services templates
        @params:
        :	None
        @returns:
        :(i)  id : dict:  - service template id
        :(s)    name        :	(s)
        :(s)    type        :	(i)
        :(s)    comment     :	(s)
        """
        if not self.urfa_call(0x2110):
            raise Exception("Fail of urfa_call(0x2110) [rpcf_get_fictive_services_list]")
            #--------- output
        self.pck.recv(self.sck)
        ret = {}
        services_count = self.pck.get_data(U_TP_I)
        while services_count:
            self.pck.recv(self.sck)
            srvc_id = self.pck.get_data(U_TP_I)
            if srvc_id != -1:
                ret[srvc_id] = {}
                ret[srvc_id]['name'] = self.pck.get_data(U_TP_S)
                ret[srvc_id]['type'] = self.pck.get_data(U_TP_I)
                ret[srvc_id]['comment'] = self.pck.get_data(U_TP_S)
            services_count -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def service_periodic_component_of_cost_get(self, params):
        """ get periodic component of cost of service
        @params:
        :(s)  service_id :	(i)
        @returns:
        :(s)  cost :	(d)
        """
        if not self.urfa_call(0x10000):
            raise Exception("Fail of urfa_call(0x10000) [rpcf_get_periodic_component_of_cost]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['cost'] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def service_get_links_count(self, params):
        """ get list of slink's of service (is service used?)
        @params:
        :(s)  service_id :	(i)
        @returns:
        :(s)  links_count :	(i)
        """
        if not self.urfa_call(0x10001):
            raise Exception("Fail of urfa_call(0x10001) [rpcf_is_service_used]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['links_count'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def slinks_get_by_uid(self, params):
        """ get slinks id and name by user_id (and account_id if need)
        @params:
        :(s)  user_id    :	(i)
        :(s)  account_id :	(i) = 0
        @returns:
        :(i) slink_id : (s) service_name
        """
        if not self.urfa_call(0x9003):
            raise Exception("Fail of urfa_call(0x9003) [rpcf_get_techparam_slink_by_uid]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        cnt = self.pck.get_data(U_TP_I)
        while cnt:
            self.pck.recv(self.sck)
            slink_id = self.pck.get_data(U_TP_I)
            ret[slink_id] = self.pck.get_data(U_TP_S)
            cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def slink_once_add(self, params):
        """ add once service to user
        @params:
        :(s)  user_id           :	(i)
        :(s)  account_id        :	(i)
        :(s)  service_id        :	(i)
        :(s)  tariff_link_id    :	(i) = 0
        :(s)  discount_date     :	(i) = now()
        @returns:
        :(s)  slink_id :	(i)  - return slink id, but slink is not exist o_0, don't use it
        """
        if not self.urfa_call(0x2920):
            raise Exception("Fail of urfa_call(0x2920) [rpcf_add_once_slink_ex]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['service_id'], U_TP_I)
        if 'tariff_link_id' not in params: params['tariff_link_id'] = 0
        self.pck.add_data(params['tariff_link_id'], U_TP_I)
        if 'discount_date' not in params: params['discount_date'] = now()
        self.pck.add_data(params['discount_date'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {'slink_id': self.pck.get_data(U_TP_I)}
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def slink_iptraffic_get(self, params):
        """ get iptraffic slink info
        @params:
        :(s)  slink_id :	(i)
        @returns:
        :(s)  tariff_link_id        :	(i)
        :(s)  is_blocked            :	(i)  - bit-mask of block
        :(s)  discount_period_id    :	(i)
        :(s)  start_date            :	(i)
        :(s)  expire_date           :	(i)
        :(s)  unabon                :	(i)  - recalc abon ?
        :(s)  unprepay              :	(i)  - recalc prepaids ?
        :(s)  tariff_id             :	(i)
        :(s)  parent_id             :	(i)  - id of service template - parent
        :(s)  ip_address: dict:  -  dict if ip_address groups
        :(s)    mask                    :	(i)
        :(s)    mac                     :	(s)
        :(s)    iptraffic_login         :	(s)
        :(s)    iptraffic_password      :	(s)
        :(s)    iptraffic_allowed_cid   :	(s)
        :(s)    ip_not_vpn              :	(i)  - (1 - checked, 0 - uncheked)
        :(s)    dont_use_fw             :	(i)
        :(s)    router_id               :	(i)
        :(s)  quotas :	dict:  -    dict of quotas if it is
        :(i)    tclass_id : dict :  - traffic class id
        :(s)    tclass_name     :	(s)    size :	(l)  - { tclass_name : size_of_quota } (in bytes)
        """
        if not self.urfa_call(0x2702):
            raise Exception("Fail of urfa_call(0x2702) [rpcf_get_iptraffic_service_link]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['tariff_link_id'] = self.pck.get_data(U_TP_I)
        ret['is_blocked'] = self.pck.get_data(U_TP_I)
        ret['discount_period_id'] = self.pck.get_data(U_TP_I)
        ret['start_date'] = self.pck.get_data(U_TP_I)
        ret['expire_date'] = self.pck.get_data(U_TP_I)
        ret['unabon'] = self.pck.get_data(U_TP_I)
        ret['unprepay'] = self.pck.get_data(U_TP_I)
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        ret['parent_id'] = self.pck.get_data(U_TP_I)
        ip_grp_cnt = self.pck.get_data(U_TP_I)
        while ip_grp_cnt:
            ipaddr = self.pck.get_data(U_TP_IP)
            ret[ipaddr] = {}
            ret[ipaddr]['mask'] = self.pck.get_data(U_TP_IP)
            ret[ipaddr]['mac'] = self.pck.get_data(U_TP_S)
            ret[ipaddr]['iptraffic_login'] = self.pck.get_data(U_TP_S)
            ret[ipaddr]['iptraffic_password'] = self.pck.get_data(U_TP_S)
            ret[ipaddr]['iptraffic_allowed_cid'] = self.pck.get_data(U_TP_S)
            ret[ipaddr]['ip_not_vpn'] = self.pck.get_data(U_TP_I)
            ret[ipaddr]['dont_use_fw'] = self.pck.get_data(U_TP_I)
            ret[ipaddr]['router_id'] = self.pck.get_data(U_TP_I)
            ip_grp_cnt -= 1
        qts_cnt = self.pck.get_data(U_TP_I)
        if qts_cnt: ret['quotas'] = {}
        while qts_cnt:
            tclass_id = self.pck.get_data(U_TP_I)
            tclass_name = self.pck.get_data(U_TP_S)
            quota = self.pck.get_data(U_TP_L)
            if quota: ret['quotas'][tclass_id] = {'tclass_name': tclass_name, 'size': quota}
            qts_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def slink_iptraffic_add(self, params):
        """ add iptraffic service to user
        @params:
        :(s)  user_id               :	(i)
        :(s)  account_id            :	(i)
        :(s)  service_id            :	(i)
        :(s)  tariff_link_id        :	(i) = 0
        :(s)  discount_period_id    :	(i)
        :(s)  start_date            :	(i) = now()
        :(s)  expire_date           :	(i) = max_time
        :(s)  unabon                :	(i) = 0  - recalc abon ?
        :(s)  unprepay              :	(i) = 0  - recalc prepaid ?
        :(s)  ips :	list:
        :(s)    ip                      : (s)  -
        :(s)    mask                    :	(s) = '255.255.255.255'
        :(s)    mac                     :	(s) = ''
        :(s)    iptraffic_login         :	(s) = ''
        :(s)    iptraffic_allowed_cid   :	(s) = ''
        :(s)    iptraffic_password      :	(s) = ''
        :(s)    ip_not_vpn              :	(i) = 1
        :(s)    dont_use_fw             :	(i) = 0
        :(s)    router_id               :	(i) = 0  - (fw id)
        :(s)  quotas : list: = []  - list of quotas (don't work)
        :(s)    tclass_id   : (i)
        :(s)    size        : (l) - size of quote in bytes
        @returns:
        :(s)  slink_id  :	(i)
        """
        if not self.urfa_call(0x2928):
            raise Exception("Fail of urfa_call(0x2928) [rpcf_add_ip_slink_ex]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.add_data(params['service_id'], U_TP_I)
        if 'tariff_link_id' not in params: params['tariff_link_id'] = 0
        self.pck.add_data(params['tariff_link_id'], U_TP_I)
        self.pck.add_data(params['discount_period_id'], U_TP_I)
        if 'start_date' not in params: params['start_date'] = now()
        self.pck.add_data(params['start_date'], U_TP_I)
        if 'expire_date' not in params: params['expire_date'] = max_time
        self.pck.add_data(params['expire_date'], U_TP_I)
        if 'unabon' not in params: params['unabon'] = 0
        self.pck.add_data(params['unabon'], U_TP_I)
        if 'unprepay' not in params: params['unprepay'] = 0
        self.pck.add_data(params['unprepay'], U_TP_I)
        self.pck.add_data(len(params['ips']), U_TP_I)
        for ipaddr in params['ips']:
            self.pck.add_data(ipaddr['ip'], U_TP_IP)
            if 'mask' not in ipaddr: ipaddr['mask'] = '255.255.255.255'
            self.pck.add_data(ipaddr['mask'], U_TP_IP)
            if 'mac' not in ipaddr: ipaddr['mac'] = ''
            self.pck.add_data(ipaddr['mac'], U_TP_S)
            if 'iptraffic_login' not in ipaddr: ipaddr['iptraffic_login'] = ''
            self.pck.add_data(ipaddr['iptraffic_login'], U_TP_S)
            if 'iptraffic_allowed_cid' not in ipaddr: ipaddr['iptraffic_allowed_cid'] = ''
            self.pck.add_data(ipaddr['iptraffic_allowed_cid'], U_TP_S)
            if 'iptraffic_password' not in ipaddr: ipaddr['iptraffic_password'] = ''
            self.pck.add_data(ipaddr['iptraffic_password'], U_TP_S)
            if 'ip_not_vpn' not in ipaddr: ipaddr['ip_not_vpn'] = 1
            self.pck.add_data(ipaddr['ip_not_vpn'], U_TP_I)
            if 'dont_use_fw' not in ipaddr: ipaddr['dont_use_fw'] = 0
            self.pck.add_data(ipaddr['dont_use_fw'], U_TP_I)
            if 'router_id' not in ipaddr: ipaddr['router_id'] = 0
            self.pck.add_data(ipaddr['router_id'], U_TP_I)
        if 'quotas' not in params: params['quotas'] = []
        self.pck.add_data(len(params['quotas']), U_TP_I)
        for quote in params['quotas']:
            self.pck.add_data(quote['tclass_id'], U_TP_L)
            self.pck.add_data(quote['size'], U_TP_L)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['slink_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def slink_iptraffic_edit(self, params):
        """ edit exist iptraffic service-link
        @params:
        :(s)  slink_id      :	(i)
        :(s)  start_date    :	(i)
        :(s)  expire_date   :	(i)
        :(s)  ips :	list:
        :(s)    ip                      : (s)
        :(s)    mask                    : (s)
        :(s)    mac                     : (s)
        :(s)    iptraffic_login         : (s)
        :(s)    iptraffic_allowed_cid   : (s)
        :(s)    iptraffic_password      : (s)
        :(s)    ip_not_vpn              : (i)
        :(s)    dont_use_fw             : (i)
        :(s)    router_id               : (i)
        :(s)  quotas : list: = []  - list of quotas (don't work)
        :(s)    tclass_id   : (i) - traffic class id
        :(s)    size        : (l) - size of quote in bytes
        @returns:
        :(s)  slink_id :	(i)
        """
        if not self.urfa_call(0x2929):
            raise Exception("Fail of urfa_call(0x2929) [rpcf_edit_ip_slink_ex]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.add_data(params['start_date'], U_TP_I)
        self.pck.add_data(params['expire_date'], U_TP_I)
        self.pck.add_data(len(params['ips']), U_TP_I)
        for ipaddr in params['ips']:
            self.pck.add_data(ipaddr['ip'], U_TP_IP)
            self.pck.add_data(ipaddr['mask'], U_TP_IP)
            self.pck.add_data(ipaddr['mac'], U_TP_S)
            self.pck.add_data(ipaddr['iptraffic_login'], U_TP_S)
            self.pck.add_data(ipaddr['iptraffic_allowed_cid'], U_TP_S)
            self.pck.add_data(ipaddr['iptraffic_password'], U_TP_S)
            self.pck.add_data(ipaddr['ip_not_vpn'], U_TP_I)
            self.pck.add_data(ipaddr['dont_use_fw'], U_TP_I)
            self.pck.add_data(ipaddr['router_id'], U_TP_I)
        if 'quotas' not in params: params['quotas'] = []
        self.pck.add_data(len(params['quotas']), U_TP_I)
        for quote in params['quotas']:
            self.pck.add_data(quote['tclass_id'], U_TP_L)
            self.pck.add_data(quote['size'], U_TP_L)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['slink_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def slink_del(self, params):
        """ delete service link by id
        @params:
        :(s)  slink_id :	(i)
        @returns:
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        """
        if not self.urfa_call(0x5100):
            raise Exception("Fail of urfa_call(0x5100) [rpcf_delete_slink]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        error_code = self.pck.get_data(U_TP_I)
        if error_code: ret['error'] = dict({13: "unable to delete service link"})
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def slink_get_datalogin(self, params):
        """ get service login by service link id
        @params:
        :(s)  slink_id :	(i)
        @returns:
        :(s)  user_data_full_login :	(i)
        """
        if not self.urfa_call(0x200d):
            raise Exception("Fail of urfa_call(0x200d) [rpcf_get_login_for_slink]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['datalogin'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def slink_del_from_ipgroup(self, params):
        """ description
        @params:
        :(s)  slink_id  :	(i)
        :(s)  ip_address:	(s)
        :(s)  mask      :	(i) = '255.255.255.255'  -
        @returns:
        :(s)  result :	(i)  -
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        """
        if not self.urfa_call(0x5101):
            raise Exception("Fail of urfa_call(0x5101) [rpcf_delete_from_ipgroup]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.add_data(params['ip_address'], U_TP_IP)
        if 'mask' not in params: params['mask'] = '255.255.255.255'
        self.pck.add_data(params['mask'], U_TP_IP)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        result = self.pck.get_data(U_TP_I)
        if not result:
            ret['error'] = dict({16: "unable to delete IP-address from ipgroup"})
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def slink_prepaid_units_get(self, params):
        """ get prepaids from slink
        @params:
        :(s)  slink_id :	(i)
        @returns:
        :(s)  bytes_in_mbyte :	(i)
        :(s)  prepaids : dict:  - dict of prepaids
        :(i)    tclass: dict:   - dict of prepaid values (key = traffic_class_id)
        :(s)      old_value :	(l)  - prev. value of prepaid units
        :(s)      cur_value :	(l)  - next. value of prepaid units
        """
        if not self.urfa_call(0x5500):
            raise Exception("Fail of urfa_call(0x5500) [rpcf_get_prepaid_units]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {'bytes_in_mbyte': 0, 'prepaids': {}}
        ret['bytes_in_mbyte'] = self.pck.get_data(U_TP_I)
        self.pck.recv(self.sck)
        pp_cnt = self.pck.get_data(U_TP_I)
        while pp_cnt:
            self.pck.recv(self.sck)
            tclass_id = self.pck.get_data(U_TP_I)
            ret['prepaids'][tclass_id] = {}
            ret['prepaids'][tclass_id]['old_value'] = self.pck.get_data(U_TP_L)
            ret['prepaids'][tclass_id]['cur_value'] = self.pck.get_data(U_TP_L)
            pp_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def _slink_prepaid_units_put(self, params):
        """ edit prepaid
        @params:
        :(s)  slink_id      :	(i)
        :(s)  tclass_id     :	(i)
        :(s)  prepaid_units :	(l) in Mb
        @returns:
        :	True if success
        """
        if not self.urfa_call(0x5501):
            raise Exception("Fail of urfa_call(0x5501) [rpcf_put_prepaid_units]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.add_data(params['tclass_id'], U_TP_I)
        self.pck.add_data(params['prepaid_units'], U_TP_L)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")

    def _put_unif_iptr(self, params):
        """ ???
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
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(len(params['logins']), U_TP_I)
        for login_idx in params['logins']:
            self.pck.add_data(login_idx['login'], U_TP_S)
            self.pck.add_data(login_idx['ipid'], U_TP_I)
            self.pck.add_data(login_idx['tclass'], U_TP_I)
            self.pck.add_data(login_idx['d_oct'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")

    def traffic_aggregation_interval_get(self, params):
        """ get traffic aggregation interval of service
        @params:
        :(s)  service_id :	(i)
        @returns:
        :(s)  aggregation_interval :	(i)
        """
        if not self.urfa_call(0x10203):
            raise Exception("Fail of urfa_call(0x10203) [rpcf_get_traffic_aggregation_interval]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['aggregation_interval'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def time_ranges_get(self):
        """ get time ranges with diapasons
        @params:
        :	None
        @returns:
        :(i)  time_range_id : dict:  -  dict of time ranges
        :(s)    time_range_name :	(s)  - name of
        :(i)      time_range_diap_id : dict:  - id of time diapason
        :(s)      start_sec     :	(i)
        :(s)      start_min     :	(i)
        :(s)      start_hour    :	(i)
        :(s)      start_wday    :	(i)
        :(s)      stop_sec      :	(i)
        :(s)      stop_min      :	(i)
        :(s)      stop_hour     :	(i)
        :(s)      stop_wday     :	(i)
        :(i)  day_of_month_id :	dict  - dict of month-days
        :(s)    day_of_month    :	(i)  - day of each moth
        :(s)    month           :	(i)  - each month
        """
        if not self.urfa_call(0x2200):
            raise Exception("Fail of urfa_call(0x2200) [rpcf_get_time_ranges]")
            #--------- output
        self.pck.recv(self.sck)
        ret = {}
        tr_cnt = self.pck.get_data(U_TP_I)
        while tr_cnt:
            self.pck.recv(self.sck)
            tr_id = self.pck.get_data(U_TP_I)
            ret[tr_id] = {}
            ret[tr_id]['time_range_name'] = self.pck.get_data(U_TP_S)
            tr_diap_cnt = self.pck.get_data(U_TP_I)
            while tr_diap_cnt:
                self.pck.recv(self.sck)
                tr_diap_id = self.pck.get_data(U_TP_I)
                ret[tr_id][tr_diap_id] = {}
                ret[tr_id][tr_diap_id]['start_sec'] = self.pck.get_data(U_TP_I)
                ret[tr_id][tr_diap_id]['stop_sec'] = self.pck.get_data(U_TP_I)
                ret[tr_id][tr_diap_id]['start_min'] = self.pck.get_data(U_TP_I)
                ret[tr_id][tr_diap_id]['stop_min'] = self.pck.get_data(U_TP_I)
                ret[tr_id][tr_diap_id]['start_hour'] = self.pck.get_data(U_TP_I)
                ret[tr_id][tr_diap_id]['stop_hour'] = self.pck.get_data(U_TP_I)
                ret[tr_id][tr_diap_id]['start_wday'] = self.pck.get_data(U_TP_I)
                ret[tr_id][tr_diap_id]['stop_wday'] = self.pck.get_data(U_TP_I)
                tr_diap_cnt -= 1
            self.pck.recv(self.sck)
            days_cnt = self.pck.get_data(U_TP_I)
            while days_cnt:
                self.pck.recv(self.sck)
                internal_id = self.pck.get_data(U_TP_I)
                ret[tr_id][internal_id] = {}
                ret[tr_id][internal_id]['day_of_month'] = self.pck.get_data(U_TP_I)
                ret[tr_id][internal_id]['month'] = self.pck.get_data(U_TP_I)
                days_cnt -= 1
            tr_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def tclasses_list_get(self):
        """ get list of tariff classes
        @params:
        :	None
        @returns:
        :(i)  tclass_id : dict: - dict of tariff classes (id is key)
        :(s)    tclass_name : (s) - name of tariff class
        :(s)    graph_color : (i) - color of tclass on graphs
        :(s)    is_display  : (i) - show tclass on graphs ? (1/0)
        :(s)    is_fill     : (i) - to fill tclass on graphs ? (1/0)
        """
        if not self.urfa_call(0x2300):
            raise Exception("Fail of urfa_call(0x2300) [rpcf_get_tclasses]")
            #--------- output
        self.pck.recv(self.sck)
        ret = {}
        tclasses_cnt = self.pck.get_data(U_TP_I)
        while tclasses_cnt:
            self.pck.recv(self.sck)
            tclass_id = self.pck.get_data(U_TP_I)
            ret[tclass_id] = {}
            ret[tclass_id]['tclass_name'] = self.pck.get_data(U_TP_S)
            ret[tclass_id]['graph_color'] = self.pck.get_data(U_TP_I)
            ret[tclass_id]['is_display'] = self.pck.get_data(U_TP_I)
            ret[tclass_id]['is_fill'] = self.pck.get_data(U_TP_I)
            tclasses_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def tclass_get(self, params):
        """ get tariff-class info by id
        @params:
        :(s)  tclass_id :	(i)
        @returns:
        :(s)  tclass_name : (s) - name of tariff class
        :(s)  graph_color : (i) - color of tclass on graphs
        :(s)  is_display  : (i) - show tclass on graphs ? (1/0)
        :(s)  is_fill     : (i) - to fill tclass on graphs ? (1/0)
        :(s)  time_range_id :	(i)  - id of time range
        :(s)  dont_save :	(i)  - 'don't save' checkbox (1/0)
        :(s)  local_traf_policy :	(i)  - policy for traffic classes (0 - to reciever, 1 - to sender, 2 - both)
        :(s)  tsubclasses: list:	- list of traffic subclasses
        :(s)    saddr           :	(s)  - source ip addr
        :(s)    saddr_mask      :	(s)  - source mask
        :(s)    sport           :	(i)  - source port
        :(s)    input           :	(i)  - incoming interface
        :(s)    src_as          :	(s)  - AS of source
        :(s)    daddr           :	(s)  - dest ip addr
        :(s)    daddr_mask      :	(s)  - dest mask
        :(s)    dport           :	(i)  - dest port
        :(s)    output          :	(i)  - outcoming interface
        :(s)    dst_as          :	(s)  - AS of dest
        :(s)    proto           :	(i)  - protocol
        :(s)    tos             :	(i)  - type of service (ToS)
        :(s)    nexthop         :	(i)  - next hop (router, fw, etc)
        :(s)    tcp_flags       :	(i)  - TCP flags
        :(s)    ip_from         :	(i)  - prev hop ip addr (router, fw, etc)
        :(s)    skip            :	(i)  - skip ? (1/0)
        :(s)    use: dict:           \
        :(s)      sport       :	(i)   \
        :(s)      input       :	(i)   |
        :(s)      src_as      :	(i)   |
        :(s)      dport       :	(i)   |
        :(s)      output      :	(i)   | ???
        :(s)      dst_as      :	(i)   |
        :(s)      proto       :	(i)   |
        :(s)      tos         :	(i)   |
        :(s)      nexthop     :	(i)   |
        :(s)      tcp_flags   :	(i)  /
        """
        if not self.urfa_call(0x2302):
            raise Exception("Fail of urfa_call(0x2302) [rpcf_get_tclass]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['tclass_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['tclass_name'] = self.pck.get_data(U_TP_S)
        ret['graph_color'] = self.pck.get_data(U_TP_I)
        ret['is_display'] = self.pck.get_data(U_TP_I)
        ret['is_fill'] = self.pck.get_data(U_TP_I)
        ret['time_range_id'] = self.pck.get_data(U_TP_I)
        ret['dont_save'] = self.pck.get_data(U_TP_I)
        ret['local_traf_policy'] = self.pck.get_data(U_TP_I)
        tclass_count = self.pck.get_data(U_TP_I)
        if tclass_count: ret['tsubclasses'] = []
        while tclass_count:
            self.pck.recv(self.sck)
            subclass = {}
            subclass['saddr'] = self.pck.get_data(U_TP_IP)
            subclass['saddr_mask'] = self.pck.get_data(U_TP_IP)
            subclass['sport'] = self.pck.get_data(U_TP_I)
            subclass['input'] = self.pck.get_data(U_TP_I)
            subclass['src_as'] = self.pck.get_data(U_TP_IP)
            subclass['daddr'] = self.pck.get_data(U_TP_IP)
            subclass['daddr_mask'] = self.pck.get_data(U_TP_IP)
            subclass['dport'] = self.pck.get_data(U_TP_I)
            subclass['output'] = self.pck.get_data(U_TP_I)
            subclass['dst_as'] = self.pck.get_data(U_TP_IP)
            subclass['proto'] = self.pck.get_data(U_TP_I)
            subclass['tos'] = self.pck.get_data(U_TP_I)
            subclass['nexthop'] = self.pck.get_data(U_TP_I)
            subclass['tcp_flags'] = self.pck.get_data(U_TP_I)
            subclass['ip_from'] = self.pck.get_data(U_TP_IP)
            subclass['use'] = {}
            subclass['use']['sport'] = self.pck.get_data(U_TP_I)
            subclass['use']['input'] = self.pck.get_data(U_TP_I)
            subclass['use']['src_as'] = self.pck.get_data(U_TP_I)
            subclass['use']['dport'] = self.pck.get_data(U_TP_I)
            subclass['use']['output'] = self.pck.get_data(U_TP_I)
            subclass['use']['dst_as'] = self.pck.get_data(U_TP_I)
            subclass['use']['proto'] = self.pck.get_data(U_TP_I)
            subclass['use']['tos'] = self.pck.get_data(U_TP_I)
            subclass['use']['nexthop'] = self.pck.get_data(U_TP_I)
            subclass['use']['tcp_flags'] = self.pck.get_data(U_TP_I)
            subclass['skip'] = self.pck.get_data(U_TP_I)
            ret['tsubclasses'].append(subclass)
            tclass_count -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def discount_periods_list_get_all(self):
        """ get list of all (incl. customs & hiden) discount periods
        @params:
        :	None
        @returns:
        :(i)  static_id : dict:
        :(s)    serial_id               :	(i)
        :(s)    start_date              :	(i)
        :(s)    end_date                :	(i)
        :(s)    periodic_type           :	(i)  - type of period (day, week, etc... custom)
        :(s)    custom_duration         :	(i)  - duration (in sec) of period if not preset, else == 1
        :(s)    next_discount_period_id :	(i)  - ???
        :(s)    canonical_length        :	(i)  - classic leangth of period (in sec)
        """
        if not self.urfa_call(0x2607):
            raise Exception("Fail of urfa_call(0x2607) [rpcf_get_all_discount_periods]")
            #--------- output
        self.pck.recv(self.sck)
        ret = {}
        dp_cnt = self.pck.get_data(U_TP_I)
        while dp_cnt:
            self.pck.recv(self.sck)
            static_id = self.pck.get_data(U_TP_I)
            ret[static_id] = {}
            ret[static_id]['serial_id'] = self.pck.get_data(U_TP_I)
            ret[static_id]['start_date'] = self.pck.get_data(U_TP_I)
            ret[static_id]['end_date'] = self.pck.get_data(U_TP_I)
            ret[static_id]['periodic_type'] = self.pck.get_data(U_TP_I)
            ret[static_id]['custom_duration'] = self.pck.get_data(U_TP_I)
            ret[static_id]['next_discount_period_id'] = self.pck.get_data(U_TP_I)
            ret[static_id]['canonical_length'] = self.pck.get_data(U_TP_I)
            dp_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def discount_periods_list_get(self):
        """ get list of discount periods (excluded customs & hiden)
        @params:
        :	None
        @returns:
        :(i)  static_id : dict:
        :(s)    serial_id               :	(i)
        :(s)    start_date              :	(i)
        :(s)    end_date                :	(i)
        :(s)    periodic_type           :	(i)  - type of period (day, week, etc... custom)
        :(s)    custom_duration         :	(i)  - duration (in sec) of period if not preset, else == 1
        :(s)    next_discount_period_id :	(i)  - ???
        :(s)    canonical_length        :	(i)  - classic leangth of period (in sec)
        """
        if not self.urfa_call(0x2600):
            raise Exception("Fail of urfa_call(0x2600) [rpcf_get_discount_periods]")
            #--------- output
        self.pck.recv(self.sck)
        ret = {}
        dp_cnt = self.pck.get_data(U_TP_I)
        while dp_cnt:
            self.pck.recv(self.sck)
            static_id = self.pck.get_data(U_TP_I)
            ret[static_id] = {}
            ret[static_id]['serial_id'] = self.pck.get_data(U_TP_I)
            ret[static_id]['start_date'] = self.pck.get_data(U_TP_I)
            ret[static_id]['end_date'] = self.pck.get_data(U_TP_I)
            ret[static_id]['periodic_type'] = self.pck.get_data(U_TP_I)
            ret[static_id]['custom_duration'] = self.pck.get_data(U_TP_I)
            ret[static_id]['next_discount_period_id'] = self.pck.get_data(U_TP_I)
            ret[static_id]['canonical_length'] = self.pck.get_data(U_TP_I)
            dp_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def discount_period_first_get_id(self):
        """ get id of first discount period  ( o_0 why!? )
        @params:
        :	None
        @returns:
        :(s)  id :	(i)
        """
        if not self.urfa_call(0x2601):
            raise Exception("Fail of urfa_call(0x2601) [rpcf_get_first_discount_period_id]")
            #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def discount_period_get(self, params):
        """ get discount period info by id
        @params:
        :(s)  dp_serial_id :	(i)
        @returns:
        :(s)  start_date                :	(i)
        :(s)  end_date                  :	(i)
        :(s)  periodic_type             :	(i)  - type of period (day, week, etc... custom)
        :(s)  custom_duration           :	(i)  - duration (in sec) (if preset then == 1)
        :(s)  discounts_per_week        :	(i)  - count of discounts per one week
        :(s)  next_discount_period_id   :	(i)  - ???
        """
        if not self.urfa_call(0x2602):
            raise Exception("Fail of urfa_call(0x2602) [rpcf_get_discount_period]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['dp_serial_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['start_date'] = self.pck.get_data(U_TP_I)
        ret['end_date'] = self.pck.get_data(U_TP_I)
        ret['periodic_type'] = self.pck.get_data(U_TP_I)
        ret['custom_duration'] = self.pck.get_data(U_TP_I)
        ret['discounts_per_week'] = self.pck.get_data(U_TP_I)
        ret['next_discount_period_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def discount_period_add(self, params=dict()):
        """ add discount period
        @params:
        :(s)  dp_serial_id          :	(i) = 0  - next if 0
        :(s)  start_date            :	(i) = now()
        :(s)  expire_date           :	(i) = 0  - auto (period type depend) if 0
        :(s)  periodic_type         :	(i) = 3  - monthly is default
        :(s)  custom_duration       :	(i) = 1 - duration (in sec) default == 1 - period type depend
        :(s)  discounts_per_week    :	(i) = 1 - count of discounts per one week
        @returns:
        :(s)  discount_period_id :	(i)
        """
        if not self.urfa_call(0x2605):
            raise Exception("Fail of urfa_call(0x2605) [rpcf_add_discount_period_return]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        if 'dp_serial_id' not in params: params['static_id'] = 0
        self.pck.add_data(params['static_id'], U_TP_I)
        if 'start_date' not in params: params['start_date'] = now()
        self.pck.add_data(params['start_date'], U_TP_I)
        if 'expire_date' not in params: params['expire_date'] = 0
        self.pck.add_data(params['expire_date'], U_TP_I)
        if 'periodic_type' not in params: params['periodic_type'] = 3
        self.pck.add_data(params['periodic_type'], U_TP_I)
        if 'custom_duration' not in params: params['custom_duration'] = 1
        self.pck.add_data(params['custom_duration'], U_TP_I)
        if 'discount_interval' not in params: params['discount_interval'] = 1
        self.pck.add_data(params['discount_interval'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['discount_period_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def discount_period_expire(self, params):
        """ to expire of discount period by id
        @params:
        :(s)  dp_id :	(i)  -
        @returns:
        :	True if success
        """
        if not self.urfa_call(0x2606):
            raise Exception("Fail of urfa_call(0x2606) [rpcf_expire_discount_period]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['dp_id'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")

    def ipzones_list_get(self):
        """ get list of ip-zones
        @params:
        :	None
        @returns:
        :(i) zone_id : (s) zone_name    - dict like {id:name} of ip-zones
        """
        if not self.urfa_call(0x2800):
            raise Exception("Fail of urfa_call(0x2800) [rpcf_get_ipzones_list]")
            #--------- output
        self.pck.recv(self.sck)
        ret = {}
        zones_count = self.pck.get_data(U_TP_I)
        while zones_count:
            self.pck.recv(self.sck)
            zone_id = self.pck.get_data(U_TP_I)
            ret[zone_id] = self.pck.get_data(U_TP_S)
            zones_count -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def ipzone_add(self, params=dict()):
        """ add ip-zone
        @params:
        :(s)  id    :	(i) = 0  - next if 0
        :(s)  name  :	(s)      - name of ip-zone
        :(s)  subnets : list: = []   - list of dicts of subnets
        :                dict:
        :(s)    net     :	(s) -   subnet ip
        :(s)    mask    :	(s) -   subnet mask
        :(s)    gw      :	(s) -   subnet gateway
        @returns:
        :(s)  ipzone_id :	(i)
        """
        if not self.urfa_call(0x2801):
            raise Exception("Fail of urfa_call(0x2801) [rpcf_add_ipzone]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        if 'id' not in params: params['id'] = 0
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['name'], U_TP_S)
        if 'subnets' not in params: params['subnets'] = []
        self.pck.add_data(len(params['subnets']), U_TP_I)
        for subnet in params['subnets']:
            if 'net' not in params: params['net'] = '0.0.0.0'
            self.pck.add_data(subnet['net'], U_TP_IP)
            if 'mask' not in params: params['mask'] = '255.255.255.255'
            self.pck.add_data(subnet['mask'], U_TP_IP)
            if 'gw' not in params: params['gw'] = '0.0.0.0'
            self.pck.add_data(subnet['gw'], U_TP_IP)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {'ipzone_id': self.pck.get_data(U_TP_I)}
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def ipzone_get(self, params):
        """ get ip-zone info by id
        @params:
        :(s)  ipzone_id :	(i)
        @returns:
        :(s)  name :	(s)  - name of ipzone
        :(s)  subnet_ip :dict:	 -  dict of subnets
        :(s)    subnet_mask :	(s)
        :(s)    subnet_gw   :	(s)
        """
        if not self.urfa_call(0x2802):
            raise Exception("Fail of urfa_call(0x2802) [rpcf_get_ipzone]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['ipzone_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['name'] = self.pck.get_data(U_TP_S)
        ipz_cnt = self.pck.get_data(U_TP_I)
        while ipz_cnt:
            self.pck.recv(self.sck)
            subnet_ip = self.pck.get_data(U_TP_IP)
            ret[subnet_ip] = {}
            ret[subnet_ip]['mask'] = self.pck.get_data(U_TP_IP)
            ret[subnet_ip]['gateaway'] = self.pck.get_data(U_TP_IP)
            ipz_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def ipgroups_list_get(self):
        """ get ip-groups list
        @params:
        :	None
        @returns:
        :(i)  ipgroup_id : dict:
        :(s)    ip      :	(s)  - ip address
        :(s)    mask    :	(s)  - netmask of ipaddr
        :(s)    mac     :	(s)  - binded MAC
        :(s)    login   :	(s)  - login for iptraffic service
        :(s)    allowed_cid :	(s)  - ???
        """
        if not self.urfa_call(0x2900):
            raise Exception("Fail of urfa_call(0x2900) [rpcf_get_ipgroups_list]")
            #--------- output
        self.pck.recv(self.sck)
        ret = {}
        grp_cnt = self.pck.get_data(U_TP_I)
        while grp_cnt:
            self.pck.recv(self.sck)
            ips_cnt = self.pck.get_data(U_TP_I)
            while ips_cnt:
                self.pck.recv(self.sck)
                id = self.pck.get_data(U_TP_I)
                ret[id] = {}
                ret[id]['ip'] = self.pck.get_data(U_TP_IP)
                ret[id]['mask'] = self.pck.get_data(U_TP_IP)
                ret[id]['mac'] = self.pck.get_data(U_TP_S)
                ret[id]['login'] = self.pck.get_data(U_TP_S)
                ret[id]['allowed_cid'] = self.pck.get_data(U_TP_S)
                ips_cnt -= 1
            grp_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def ipgroup_del_ip(self, params):
        """ delete ip from ipgroup (if ipgroup becomes empty then remove it too)
        @params:
        :(s)  ipgroup_id   :	(i)
        :(s)  ip_address    :	(s)
        :(s)  mask          :	(s) = '255.255.255.255'
        @returns:
        :(s)  result :	(i)  -
        :(s)    error : dict:
        :(i)      code : (s) msg - error code:msg if fail
        """
        if not self.urfa_call(0x5102):
            raise Exception("Fail of urfa_call(0x5102) [rpcf_delete_from_ipgroup_by_ipgroup]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['ipgroup_id'], U_TP_I)
        self.pck.add_data(params['ip_address'], U_TP_IP)
        if 'mask' not in params: params['mask'] = '255.255.255.255'
        self.pck.add_data(params['mask'], U_TP_IP)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['result'] = self.pck.get_data(U_TP_I)
        if not ret['result']:
            ret['error'] = dict({16: "unable to delete IP-address from ipgroup"})
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def houses_list_get(self):
        """ get list of houses
        @params:
        :	None
        @returns:
        :(i)  house_id : dict:
        :(s)    ip_zone_id      :	(i)
        :(s)    connect_date    :	(i)
        :(s)    post_code       :	(s)
        :(s)    country         :	(s)
        :(s)    region          :	(s)
        :(s)    city            :	(s)
        :(s)    street          :	(s)
        :(s)    number          :	(s)
        :(s)    building        :	(s)
        """
        if not self.urfa_call(0x2810):
            raise Exception("Fail of urfa_call(0x2810) [rpcf_get_houses_list]")
            #--------- output
        self.pck.recv(self.sck)
        ret = {}
        hs_cnt = self.pck.get_data(U_TP_I)
        while hs_cnt:
            self.pck.recv(self.sck)
            house_id = self.pck.get_data(U_TP_I)
            ret[house_id] = {}
            ret[house_id]['ip_zone_id'] = self.pck.get_data(U_TP_I)
            ret[house_id]['connect_date'] = self.pck.get_data(U_TP_I)
            ret[house_id]['post_code'] = self.pck.get_data(U_TP_S)
            ret[house_id]['country'] = self.pck.get_data(U_TP_S)
            ret[house_id]['region'] = self.pck.get_data(U_TP_S)
            ret[house_id]['city'] = self.pck.get_data(U_TP_S)
            ret[house_id]['street'] = self.pck.get_data(U_TP_S)
            ret[house_id]['number'] = self.pck.get_data(U_TP_S)
            ret[house_id]['building'] = self.pck.get_data(U_TP_S)
            hs_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def house_get(self, params):
        """ get house info by id
        @params:
        :(s)  house_id :	(i)
        @returns:
        :(s)  house_id      :	(i)
        :(s)  connect_date  :	(i)
        :(s)  post_code     :	(s)
        :(s)  country       :	(s)
        :(s)  region        :	(s)
        :(s)  city          :	(s)
        :(s)  street        :	(s)
        :(s)  number        :	(s)
        :(s)  building      :	(s)
        :(s)  ipzones :	dict:  -
        :(i)    ipzone_id :	(s) ipzone_name
        """
        if not self.urfa_call(0x2812):
            raise Exception("Fail of urfa_call(0x2812) [rpcf_get_house]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['house_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['house_id'] = self.pck.get_data(U_TP_I)
        ret['connect_date'] = self.pck.get_data(U_TP_I)
        ret['post_code'] = self.pck.get_data(U_TP_S)
        ret['country'] = self.pck.get_data(U_TP_S)
        ret['region'] = self.pck.get_data(U_TP_S)
        ret['city'] = self.pck.get_data(U_TP_S)
        ret['street'] = self.pck.get_data(U_TP_S)
        ret['number'] = self.pck.get_data(U_TP_S)
        ret['building'] = self.pck.get_data(U_TP_S)
        ipz_cnt = self.pck.get_data(U_TP_I)
        if ipz_cnt: ret['ipzones'] = {}
        while ipz_cnt:
            ipzone_id = self.pck.get_data(U_TP_I)
            ret['ipzones'][ipzone_id] = self.pck.get_data(U_TP_S)
            ipz_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def house_add(self, params=dict()):
        """ add house
        @params:
        :(s)  house_id      :	(i) = 0     - next if 0
        :(s)  connect_date  :	(i) = now() - date of connect house
        :(s)  post_code     :	(s) = ''    - ZIP
        :(s)  country       :	(s) = ''    - country title
        :(s)  region        :	(s) = ''    - region title
        :(s)  city          :	(s) = ''    - city title
        :(s)  street        :	(s) = ''    - street name
        :(s)  number        :	(s) = ''    - house number
        :(s)  building      :	(s) = ''    - building litera (or corp. number)
        :(s)  ipzones :	list  - list of binded ipzones
        :(i)    ipzone_id   - REQUARED !!!
        @returns:
        :	True if success
        """
        if not self.urfa_call(0x2811):
            raise Exception("Fail of urfa_call(0x2811) [rpcf_add_house]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        if 'house_id' not in params: params['house_id'] = 0
        self.pck.add_data(params['house_id'], U_TP_I)
        if 'connect_date' not in params: params['connect_date'] = now()
        self.pck.add_data(params['connect_date'], U_TP_I)
        if 'post_code' not in params: params['post_code'] = ''
        self.pck.add_data(params['post_code'], U_TP_S)
        if 'country' not in params: params['country'] = ''
        self.pck.add_data(params['country'], U_TP_S)
        if 'region' not in params: params['region'] = ''
        self.pck.add_data(params['region'], U_TP_S)
        if 'city' not in params: params['city'] = ''
        self.pck.add_data(params['city'], U_TP_S)
        if 'street' not in params: params['street'] = ''
        self.pck.add_data(params['street'], U_TP_S)
        if 'number' not in params: params['number'] = ''
        self.pck.add_data(params['number'], U_TP_S)
        if 'building' not in params: params['building'] = ''
        self.pck.add_data(params['building'], U_TP_S)
        if 'house_id' not in params: params['house_id'] = ''
        self.pck.add_data(len(params['ipzones']), U_TP_I)
        for ipz_id in params['ipzones']:
            self.pck.add_data(ipz_id, U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")

    def house_get_free_ips(self, params):
        """ get unused ip adressess (and ipzone name) for house
        @params:
        :(s)  house_id :	(i)
        @returns:
        :(s)  ips_ip : (s)  zone_name - next free ip address and ipzone name
        :(s)  error :	(s)  - error message if fail
        """
        if not self.urfa_call(0x2813):
            raise Exception("Fail of urfa_call(0x2813) [rpcf_get_free_ips_for_house]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['house_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ips_cnt = self.pck.get_data(U_TP_I)
        while ips_cnt:
            ips_ip = self.pck.get_data(U_TP_IP)
            ret[ips_ip] = self.pck.get_data(U_TP_S)
            ips_cnt -= 1
        error_msg = self.pck.get_data(U_TP_S)
        if error_msg: ret['error'] = error_msg
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def report_blocks(self, params=dict()):
        """ get report of blocks
        @params:
        :(s)  user_id       :	(i) = 0
        :(s)  account_id    :	(i) = 0
        :(s)  group_id      :	(i) = 0
        :(s)  dp_id         :	(i) = 0
        :(s)  time_start    :	(i) = 0
        :(s)  time_end      :	(i) = max_time
        :(s)  show_all      :	(i) = 1 (0 - show only not deleted blocks type = 2 (admin), else - show all)
        @returns:
        :(i)  block_id : dict:
        :(s)    account_id      :	(i)
        :(s)    login           :	(s)  - user login
        :(s)    time_start      :	(i)  - block start time
        :(s)    time_end        :	(i)  - block end time
        :(s)    block_type      :	(i)  - type of block (1 - system, 2 - admin)
        :(s)    unabon          :	(i)  - recalc abon ? (1/0)
        :(s)    unprepay        :	(i)  - recalc prepaid ? (1/0)
        :(s)    is_deleted      :	(i)  - is deleted block ? (1/0)
        """
        if not self.urfa_call(0x300b):
            raise Exception("Fail of urfa_call(0x300b) [rpcf_blocks_report_ex]")
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
        if 'show_all' not in params: params['show_all'] = 1
        self.pck.add_data(params['show_all'], U_TP_I)
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
                account_id = self.pck.get_data(U_TP_I)
                login = self.pck.get_data(U_TP_S)
                time_start = self.pck.get_data(U_TP_I)
                time_end = self.pck.get_data(U_TP_I)
                block_type = self.pck.get_data(U_TP_I)
                id = self.pck.get_data(U_TP_I)
                unabon = self.pck.get_data(U_TP_I)
                unprepay = self.pck.get_data(U_TP_I)
                is_deleted = self.pck.get_data(U_TP_I)
                ret[id] = {
                    'account_id': account_id,
                    'login': login,
                    'time_start': time_start,
                    'time_end': time_end,
                    'block_type': block_type,
                    'unabon': unabon,
                    'unprepay': unprepay,
                    'is_deleted': is_deleted
                }
                atr_cnt -= 1
            acc_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def report_other_charges(self, params=dict()):
        """ get report of other charges
        @params:
        :(s)  user_id       :	(i) = 0
        :(s)  ???           :	(i) = 0
        :(s)  group_id      :	(i) = 0
        :(s)  dp_id         :	(i) = 0
        :(s)  time_start    :	(i) = 0
        :(s)  time_end      :	(i) = max_time
        @returns:
        :(i)  items_count : dict:
        :(s)    account_id      :	(i)
        :(s)    login           :	(s)
        :(s)    full_name       :	(s)
        :(s)    discount_date   :	(i)
        :(s)    discount_sum    :	(d)
        :(s)    charge_type     :	(i)
        """
        if not self.urfa_call(0x3023):
            raise Exception("Fail of urfa_call(0x3023) [rpcf_other_charges_report]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        if 'user_id' not in params: params['user_id'] = 0
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(0, U_TP_I)                                    # ??? aid ???
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
                ret[atr_cnt] = {}
                ret[atr_cnt]['account_id'] = self.pck.get_data(U_TP_I)
                ret[atr_cnt]['login'] = self.pck.get_data(U_TP_S)
                ret[atr_cnt]['full_name'] = self.pck.get_data(U_TP_S)
                ret[atr_cnt]['discount_date'] = self.pck.get_data(U_TP_I)
                ret[atr_cnt]['discount_sum'] = self.pck.get_data(U_TP_D)
                ret[atr_cnt]['charge_type'] = self.pck.get_data(U_TP_I)
                atr_cnt -= 1
            acc_cnt -= 1
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

    def report_traffic(self, params=dict()):
        """ get report of traffic discounts
        @params:
        :(s)  type          :	(i) = 0  - type of result grouping (0-none, 1-by_hours, ...etc)
        :(s)  user_id       :	(i) = 0
        :(s)  account_id    :	(i) = 0
        :(s)  group_id      :	(i) = 0
        :(s)  dp_id         :	(i) = 0
        :(s)  time_start    :	(i) = 0
        :(s)  time_end      :	(i) = max_time
        @returns:
        :(s)  bytes_in_kbyte :	(d)  - system setting for convert bytes to k-M-G-bytes
        :(s)  discounts: list:      - list of dicts of discounts
        :                   dicts:
        :(s)      account_id    :	(i)
        :(s)      login         :	(s)
        :(s)      tclass        :	(i)  - traffic class code
        :(s)      base_cost     :	(d)  - price
        :(s)      bytes         :	(l)  - traffic size
        :(s)      discount_sum  :	(d)
        :   if type <> 0 then:
        :(s)        add_param   :	(i,s)  - param for result grouping (unixtime or ip)
        """
        if not self.urfa_call(0x3009):
            raise Exception("Fail of urfa_call(0x3009) [rpcf_traffic_report_ex]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        if 'type' not in params: params['type'] = 0
        self.pck.add_data(params['type'], U_TP_I)
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
        ret = {'bytes_in_kbyte': self.pck.get_data(U_TP_D)}  # bytes_in_kbyte   why!? it's 1024
        ret['discounts'] = []
        acc_cnt = self.pck.get_data(U_TP_I)
        while acc_cnt:
            self.pck.recv(self.sck)
            atr_cnt = self.pck.get_data(U_TP_I)
            while atr_cnt:
                self.pck.recv(self.sck)
                tmp = {}
                tmp['account_id'] = self.pck.get_data(U_TP_I)
                tmp['login'] = self.pck.get_data(U_TP_S)
                if params['type']:
                    if params['type'] == 4:
                        tmp['add_param'] = self.pck.get_data(U_TP_IP)
                    else:
                        tmp['add_param'] = self.pck.get_data(U_TP_I)
                tmp['tclass'] = self.pck.get_data(U_TP_I)
                tmp['base_cost'] = self.pck.get_data(U_TP_D)
                tmp['bytes'] = self.pck.get_data(U_TP_L)
                tmp['discount_sum'] = self.pck.get_data(U_TP_D)
                ret['discounts'].append(tmp)
                atr_cnt -= 1
            acc_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def tariffs_list_get(self):
        """ get list of tariffs
        @params:
        :	None
        @returns:
        :(i)  id :	dict:
        :(s)    name                :	(s)
        :(s)    create_date         :	(i)
        :(s)    who_create_id       :	(i)
        :(s)    who_create_login    :	(s)  -
        :(s)    change_create       :	(i)  -
        :(s)    who_change_id       :	(i)  -
        :(s)    who_change_login    :	(s)  -
        :(s)    expire_date         :	(i)  -
        :(s)    is_blocked          :	(i)  -
        :(s)    balance_rollover    :	(i)  - reset balance at end of discount period? (1/0)
        """
        if not self.urfa_call(0x3010):
            raise Exception("Fail of urfa_call(0x3010) [rpcf_get_tariffs_list]")
            #--------- output
        self.pck.recv(self.sck)
        ret = {}
        tar_cnt = self.pck.get_data(U_TP_I)
        while tar_cnt:
            self.pck.recv(self.sck)
            tar_id = self.pck.get_data(U_TP_I)
            ret[tar_id] = {}
            ret[tar_id]['name'] = self.pck.get_data(U_TP_S)
            ret[tar_id]['create_date'] = self.pck.get_data(U_TP_I)
            ret[tar_id]['who_create_id'] = self.pck.get_data(U_TP_I)
            ret[tar_id]['who_create_login'] = self.pck.get_data(U_TP_S)
            ret[tar_id]['change_create'] = self.pck.get_data(U_TP_I)
            ret[tar_id]['who_change_id'] = self.pck.get_data(U_TP_I)
            ret[tar_id]['who_change_login'] = self.pck.get_data(U_TP_S)
            ret[tar_id]['expire_date'] = self.pck.get_data(U_TP_I)
            ret[tar_id]['is_blocked'] = self.pck.get_data(U_TP_I)
            ret[tar_id]['balance_rollover'] = self.pck.get_data(U_TP_I)
            tar_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def tariff_get(self, params):
        """ get tariff info by id
        @params:
        :(s)  tariff_id :	(i)
        @returns:
        :(s)  tariff_name               :	(s)
        :(s)  tariff_create_date        :	(i)
        :(s)  who_create_id             :	(i)
        :(s)  who_create_login          :	(s)
        :(s)  tariff_change_date        :	(i)
        :(s)  who_change_id             :	(i)
        :(s)  who_change_login          :	(s)
        :(s)  tariff_balance_rollover   :	(i)
        :(s)  comments                  :	(s)
        :(s)  services: dict:
        :(i)    service_id : dict:
        :(s)      service_type      :	(i)
        :(s)      service_name      :	(s)
        :(s)      service_comment   :	(s)
        :(s)      link_by_default   :	(i)
        :(s)      is_dynamic        :	(i)
        """
        if not self.urfa_call(0x3040):
            raise Exception("Fail of urfa_call(0x3040) [rpcf_get_tariff_new]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['tariff_name'] = self.pck.get_data(U_TP_S)
        ret['tariff_create_date'] = self.pck.get_data(U_TP_I)
        ret['who_create_id'] = self.pck.get_data(U_TP_I)
        ret['who_create_login'] = self.pck.get_data(U_TP_S)
        ret['tariff_change_date'] = self.pck.get_data(U_TP_I)
        ret['who_change_id'] = self.pck.get_data(U_TP_I)
        ret['who_change_login'] = self.pck.get_data(U_TP_S)
        ret['tariff_balance_rollover'] = self.pck.get_data(U_TP_I)
        ret['comments'] = self.pck.get_data(U_TP_S)
        srvc_cnt = self.pck.get_data(U_TP_I)
        while srvc_cnt:
            self.pck.recv(self.sck)
            service_id = self.pck.get_data(U_TP_I)
            ret[service_id] = {}
            ret[service_id]['service_type'] = self.pck.get_data(U_TP_I)
            ret[service_id]['service_name'] = self.pck.get_data(U_TP_S)
            ret[service_id]['service_comment'] = self.pck.get_data(U_TP_S)
            ret[service_id]['link_by_default'] = self.pck.get_data(U_TP_I)
            ret[service_id]['is_dynamic'] = self.pck.get_data(U_TP_I)
            srvc_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def tariff_get_id_by_name(self, params):
        """ get tariff id by name
        @params:
        :(s)  name :	(s)
        @returns:
        :(s)  tid :	(i)
        """
        if not self.urfa_call(0x301d):
            raise Exception("Fail of urfa_call(0x301d) [rpcf_get_tariff_id_by_name]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def tariff_add(self, params):
        """ add new tariff
        @params:
        :(s)  name              :	(s)
        :(s)  balance_rollover  :	(i)
        :(s)  comments          :	(s)
        @returns:
        :(s)  tariff_id :	(i)
        """
        if not self.urfa_call(0x3041):
            raise Exception("Fail of urfa_call(0x3041) [rpcf_add_tariff_new]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['name'], U_TP_S)
        if 'balance_rollover' not in params: params['balance_rollover'] = 0
        self.pck.add_data(params['balance_rollover'], U_TP_I)
        if 'comments' not in params: params['comments'] = ''
        self.pck.add_data(params['comments'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['tariff_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def tariff_edit(self, params):
        """ edit tariff by id
        @params:
        :(s)  tp_id             :	(i)
        :(s)  name              :	(s)
        :(s)  balance_rollover  :	(i)
        :(s)  comments          :	(s)
        @returns:
        :(s)  res :	(i)
        """
        if not self.urfa_call(0x3042):
            raise Exception("Fail of urfa_call(0x3042) [rpcf_edit_tariff_new]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['tp_id'], U_TP_I)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.add_data(params['balance_rollover'], U_TP_I)
        self.pck.add_data(params['comments'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['res'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def tariff_add_service(self, params):
        """ add service to tariff (truncated version)
        @params:
        :(s)  tariff_id :	(i)
        :(s)  service_parent_id     :	(i)
        :(s)  service_name          :	(s)
        :(s)  service_type          :	(i)
        :(s)  service_comment       :	(s) = ''
        :(s)  link_by_default       :	(i) = 1 - attach service as default ? (1/0)
        :(s)  is_dynamic            :	(i) = 0 - it's dynamic service ? (1/0)
        :   if service_type is 'once':
        :(s)  cost                  :	(d)
        :   if service_type is 'periodic':
        :(s)  cost                  :	(d)
        :(s)  periodic_type         :	(i) = 3 - discount period type (3 - monthly)
        :(s)  discount_method       :	(i) = 1 - charge method (1 - at start period)
        :(s)  start_date            :	(i) = now
        :(s)  expire_date           :	(i) = max_time
        :   if service_type is 'iptraffic':
        :(s)  cost                  :	(d)
        :(s)  periodic_type         :	(i) = 3 - discount period type (3 - monthly)
        :(s)  discount_method       :	(i) = 1 - charge method (1 - at start period)
        :(s)  start_date            :	(i) = now
        :(s)  expire_date           :	(i) = max_time
        :(s)  null_service_prepaid  :	(i) = 1 - reset prepaids ? (1/0)
        :(s)  borders: list     : = []      - borders of traffic by classess
        :(s)    tclass  : (i) - traffic class id
        :(s)    size    : (l) - border value (in bytes)
        :(s)    cost    : (d) - cost per Mbyte
        :(s)  prepaids : list   : = []      - prepaids by traffic classess
        :(s)   tclass   : (i)
        :(s)   size     : (l) - prepayed Mbytes
        :(s)  groups :	list    : = []      - ???
        :(s)   tclass   : (i)
        :(s)   group_id : (i) - prepayed Mbytes
        :   ... cut cuz not used
        @returns:
        :	True if success
        """
        if not self.urfa_call(0x3014):
            raise Exception("Fail of urfa_call(0x3014) [rpcf_add_service_to_tariff]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.add_data(params['service_parent_id'], U_TP_I)
        self.pck.add_data(params['service_name'], U_TP_S)
        self.pck.add_data(params['service_type'], U_TP_I)
        if 'comment' not in params: params['comment'] = ''
        self.pck.add_data(params['comment'], U_TP_S)
        if 'link_by_default' not in params: params['link_by_default'] = 1
        self.pck.add_data(params['link_by_default'], U_TP_I)
        if 'is_dynamic' not in params: params['is_dynamic'] = 0
        self.pck.add_data(params['is_dynamic'], U_TP_I)
        if params['service_type'] == 1:                                               # once
            self.pck.add_data(params['cost'], U_TP_D)
        elif params['service_type'] == 2:                                               # periodic
            self.pck.add_data(params['cost'], U_TP_D)
            if 'periodic_type' not in params: params['periodic_type'] = 3
            self.pck.add_data(params['periodic_type'], U_TP_I)
            if 'discount_method' not in params: params['discount_method'] = 1
            self.pck.add_data(params['discount_method'], U_TP_I)
            if 'start_date' not in params: params['start_date'] = now()
            self.pck.add_data(params['start_date'], U_TP_I)
            if 'expire_date' not in params: params['expire_date'] = max_time
            self.pck.add_data(params['expire_date'], U_TP_I)
        elif params['service_type'] == 3:                                               # iptraffic
            self.pck.add_data(params['cost'], U_TP_D)
            if 'periodic_type' not in params: params['periodic_type'] = 3
            self.pck.add_data(params['periodic_type'], U_TP_I)
            if 'discount_method' not in params: params['discount_method'] = 1
            self.pck.add_data(params['discount_method'], U_TP_I)
            if 'start_date' not in params: params['start_date'] = now()
            self.pck.add_data(params['start_date'], U_TP_I)
            if 'expire_date' not in params: params['expire_date'] = max_time
            self.pck.add_data(params['expire_date'], U_TP_I)
            if 'null_service_prepaid' not in params: params['null_service_prepaid'] = 1
            self.pck.add_data(params['null_service_prepaid'], U_TP_I)
            if 'borders' not in params: params['borders'] = []
            self.pck.add_data(len(params['borders']), U_TP_I)
            for border in params['borders']:
                self.pck.add_data(border['tclass'], U_TP_I)
                self.pck.add_data(border['size'], U_TP_L)
                self.pck.add_data(border['cost'], U_TP_D)
            if 'prepaids' not in params: params['prepaids'] = []
            self.pck.add_data(len(params['prepaids']), U_TP_I)
            for prepay in params['prepaids']:
                self.pck.add_data(prepay['tclass'], U_TP_I)
                self.pck.add_data(prepay['size'], U_TP_L)
            if 'groups' not in params: params['groups'] = []
            self.pck.add_data(len(params['groups']), U_TP_I)
            for group in params['groups']:
                self.pck.add_data(group['tclass'], U_TP_I)
                self.pck.add_data(group['group_id'], U_TP_I)
                # cut hotspot, dialup and voice service-types cuz not used
        self.pck.show()
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")

    def tariff_del_service(self, params):
        """ delete service by id from tariff by id
        @params:
        :(s)  tariff_id :	(i)
        :(s)  service_id :	(i)
        @returns:
        :(s)  result :	(i)
        """
        if not self.urfa_call(0x3015):
            raise Exception("Fail of urfa_call(0x3015) [rpcf_del_service_from_tariff]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def tariff_del(self, params):
        """ delete tariff-plan (all tariff_links with him must by unlinked)
        @params:
        :(s)  tariff_id :	(i)
        @returns:
        :(s)  result    :	(i)
        """
        if not self.urfa_call(0x301b):
            raise Exception("Fail of urfa_call(0x301b) [rpcf_remove_tariff]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['tariff_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def payment_methods_list_get(self):
        """ get list of payment methods
        @params:
        :	None
        @returns:
        :(i)    pm_id :	(s) name
        """
        if not self.urfa_call(0x3100):
            raise Exception("Fail of urfa_call(0x3100) [rpcf_get_payment_methods_list]")
            #--------- output
        self.pck.recv(self.sck)
        ret = {}
        pm_cnt = self.pck.get_data(U_TP_I)
        while pm_cnt:
            pm_id = self.pck.get_data(U_TP_I)
            ret[pm_id] = self.pck.get_data(U_TP_S)
            pm_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def sys_settings_list_get(self):
        """ description
        @params:
        :	None
        @returns:
        :(i)  pm_id : dict:  -
        :(s)    name :	(s)  -
        :(s)    value :	(s)  -
        """
        if not self.urfa_call(0x4400):
            raise Exception("Fail of urfa_call(0x4400) [rpcf_get_settings_list]")
            #--------- output
        self.pck.recv(self.sck)
        ret = {}
        val_cnt = self.pck.get_data(U_TP_I)
        while val_cnt:
            self.pck.recv(self.sck)
            val_id = self.pck.get_data(U_TP_I)
            ret[val_id] = {}
            ret[val_id]['name'] = self.pck.get_data(U_TP_S)
            ret[val_id]['value'] = self.pck.get_data(U_TP_S)
            val_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def sys_setting_get(self, params):
        """ get values of system variable by name
        @params:
        :(s)  var_name :	(s)
        @returns:
        :(s)  var_name : list:  - list of values
        :(s)    value
        """
        if not self.urfa_call(0x4404):
            raise Exception("Fail of urfa_call(0x4404) [rpcf_get_setting]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['var_name'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret[params['var_name']] = []
        val_cnt = self.pck.get_data(U_TP_I)
        while val_cnt:
            ret[params['var_name']].append(self.pck.get_data(U_TP_S))
            val_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def sys_core_time_get(self):
        """ get system core time with tz-name
        @params:
        :	None
        @returns:
        :(s)  time :	(i)  -
        :(s)  tzname :	(s)  -
        """
        if not self.urfa_call(0x11112):
            raise Exception("Fail of urfa_call(0x11112) [rpcf_get_core_time]")
            #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['time'] = self.pck.get_data(U_TP_I)
        ret['tzname'] = self.pck.get_data(U_TP_S)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def sys_defaults_recal_vat_get(self):
        """ get block recalc's and VAT (NDS) % system defaults
        @params:
        :	None
        @returns:
        :(s)  block_recalc_abon     :	(i)
        :(s)  block_recalc_prepaid  :	(i)
        :(s)  default_vat_rate      :	(d)
        """
        if not self.urfa_call(0x2035):
            raise Exception("Fail of urfa_call(0x2035) [rpcf_get_sys_settings]")
            #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['block_recalc_abon'] = self.pck.get_data(U_TP_I)
        ret['block_recalc_prepaid'] = self.pck.get_data(U_TP_I)
        ret['default_vat_rate'] = self.pck.get_data(U_TP_D)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def sys_default_currency_get(self):
        """ current system currency code
        @params:
        :	None
        @returns:
        :(s)  currency_id :	(i)	 - code of currency (810 - ruble)
        """
        if not self.urfa_call(0x0101):
            raise Exception("Fail of urfa_call(0x0101) [rpcf_get_system_currency]")
            #--------- output
        self.pck.recv(self.sck)
        ret = {'currency_id': self.pck.get_data(U_TP_I)}
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def uaparam_list_get(self):
        """ get list of user additional params
        @params:
        :	None
        @returns:
        :(i)  uap_id : dict:
        :(s)    name            :	(s)
        :(s)    display_name    :	(s)
        :(s)    visible         :	(i)  - show in interface ? (1/0)
        """
        if not self.urfa_call(0x440b):
            raise Exception("Fail of urfa_call(0x440b) [rpcf_get_uaparam_list]")
            #--------- output
        self.pck.recv(self.sck)
        ret = {}
        uaparam_cnt = self.pck.get_data(U_TP_I)
        while uaparam_cnt:
            self.pck.recv(self.sck)
            uap_id = self.pck.get_data(U_TP_I)
            ret[uap_id] = {}
            ret[uap_id]['name'] = self.pck.get_data(U_TP_S)
            ret[uap_id]['display_name'] = self.pck.get_data(U_TP_S)
            ret[uap_id]['visible'] = self.pck.get_data(U_TP_I)
            uaparam_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def uaparam_add(self, params):
        """ add user additional parameter
        @params:
        :(s)  uap_id        :	(i) - does nothing if already exist
        :(s)  name          :	(s)
        :(s)  display_name  :	(s)
        :(s)  visible       :	(i) = 0 - show in interface ? (1/0)
        @returns:
        :	True if success
        """
        if not self.urfa_call(0x440c):
            raise Exception("Fail of urfa_call(0x440c) [rpcf_add_uaparam]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['uap_id'], U_TP_I)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.add_data(params['display_name'], U_TP_S)
        if 'visible' not in params: params['visible'] = 1
        self.pck.add_data(params['visible'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")

    def uaparam_edit(self, params):
        """ edit user additional parametr by id
        @params:
        :(s)  uap_id        :	(i)
        :(s)  name          :	(s)
        :(s)  display_name  :	(s)
        :(s)  visible       :	(i)  - show in interface ? (1/0)
        @returns:
        :	True if success
        """
        if not self.urfa_call(0x440e):
            raise Exception("Fail of urfa_call(0x440e) [rpcf_edit_uaparam]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['uap_id'], U_TP_I)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.add_data(params['display_name'], U_TP_S)
        self.pck.add_data(params['visible'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")

    def uaparam_del(self, params):
        """ delete user additional parametr by id
        @params:
        :(s)  uap_id :	(i)
        @returns:
        :	True if success
        """
        if not self.urfa_call(0x4411):
            raise Exception("Fail of urfa_call(0x4411) [rpcf_del_uaparam_new]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['uap_id'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")

    def uaparam_is_in_use(self, params):
        """ check the using of parameter
        @params:
        :(s)  uap_id :	(i)
        @returns:
        :(s)  result :	(i) - (1 - is used, 0 - isn't used)
        """
        if not self.urfa_call(0x4412):
            raise Exception("Fail of urfa_call(0x4412) [rpcf_is_uaparam_in_use]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['uap_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {'result': self.pck.get_data(U_TP_I)}
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def routers_list_get(self):
        """ get routers (fw) list
        @params:
        :	None
        @returns:
        :(i)  r_id : dict:
        :(s)    r_type      :	(i)  - (0 - local, 2 - cisco rsh)
        :(s)    r_name      :	(s)
        :(s)    r_login     :	(s)
        :(s)    r_password  :	(s)
        :(s)    r_comments  :	(s)
        :(s)    r_ip        :	(s)
        """
        if not self.urfa_call(0x5002):
            raise Exception("Fail of urfa_call(0x5002) [rpcf_get_routers_list]")
            #--------- output
        self.pck.recv(self.sck)
        ret = {}
        rcnt = self.pck.get_data(U_TP_I)
        while rcnt:
            self.pck.recv(self.sck)
            r_id = self.pck.get_data(U_TP_I)
            ret[r_id] = {}
            ret[r_id]['r_type'] = self.pck.get_data(U_TP_I)
            ret[r_id]['r_name'] = self.pck.get_data(U_TP_S)
            ret[r_id]['r_login'] = self.pck.get_data(U_TP_S)
            ret[r_id]['r_password'] = self.pck.get_data(U_TP_S)
            ret[r_id]['r_comments'] = self.pck.get_data(U_TP_S)
            ret[r_id]['r_ip'] = self.pck.get_data(U_TP_IP)
            rcnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def router_put(self, params):
        """ add/edit router (fw)
        @params:
        :(s)  r_id          :	(i) = 0 - next if zero, edit if already exist
        :(s)  r_type        :	(i) = 0 - (0 - local, 2 - cisco rsh)
        :(s)  r_name        :	(s)
        :(s)  r_login       :	(s) = ''
        :(s)  r_password    :	(s) = ''
        :(s)  r_comments    :	(s) = ''
        :(s)  r_ip          :	(s) = '0.0.0.0'
        @returns:
        :	True if success
        """
        if not self.urfa_call(0x5003):
            raise Exception("Fail of urfa_call(0x5003) [rpcf_put_router]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        if 'r_id' not in params: params['r_id'] = 0
        self.pck.add_data(params['r_id'], U_TP_I)
        if 'r_type' not in params: params['r_type'] = 0
        self.pck.add_data(params['r_type'], U_TP_I)
        self.pck.add_data(params['r_name'], U_TP_S)
        if 'r_login' not in params: params['r_login'] = ''
        self.pck.add_data(params['r_login'], U_TP_S)
        if 'r_password' not in params: params['r_password'] = ''
        self.pck.add_data(params['r_password'], U_TP_S)
        if 'r_comments' not in params: params['r_comments'] = ''
        self.pck.add_data(params['r_comments'], U_TP_S)
        if 'r_ip' not in params: params['r_ip'] = '0.0.0.0'
        self.pck.add_data(params['r_ip'], U_TP_IP)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")

    def router_del(self, params):
        """ delete router (fw) by id
        @params:
        :(s)  r_id :	(i)
        @returns:
        :	True if success
        """
        if not self.urfa_call(0x5007):
            raise Exception("Fail of urfa_call(0x5007) [rpcf_del_router]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['r_id'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")

    def messages_list_get(self, params=dict()):
        """ get messages list
        @params:
        :(s)  time_start :	(l) = 0
        :(s)  time_end :	(l) = max_time
        @returns:
        :(i)  msg_id : dict:
        :(s)    send_date   :	(i)
        :(s)    sender_id   :	(i)
        :(s)    subject     :	(s)
        :(s)    mime        :	(s)
        :(s)    flag        :	(i) -  bitmask (U_MSG_FLGS)
        """
        if not self.urfa_call(0x500b):
            raise Exception("Fail of urfa_call(0x500b) [rpcf_get_messages_list_new]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        if 'time_start' not in params: params['time_start'] = 0
        self.pck.add_data(params['time_start'], U_TP_L)
        if 'time_end' not in params: params['time_end'] = max_time
        self.pck.add_data(params['time_end'], U_TP_L)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        msg_cnt = self.pck.get_data(U_TP_I) - 1
        # first message
        if msg_cnt:
            msg_id = self.pck.get_data(U_TP_I)
            ret[msg_id] = {}
            ret[msg_id]['send_date'] = self.pck.get_data(U_TP_I)
            ret[msg_id]['sender_id'] = self.pck.get_data(U_TP_I)
            ret[msg_id]['subject'] = self.pck.get_data(U_TP_S)
            ret[msg_id]['mime'] = self.pck.get_data(U_TP_S)
            ret[msg_id]['flag'] = self.pck.get_data(U_TP_I)
        while msg_cnt:
            self.pck.recv(self.sck)
            msg_id = self.pck.get_data(U_TP_I)
            ret[msg_id] = {}
            ret[msg_id]['send_date'] = self.pck.get_data(U_TP_I)
            ret[msg_id]['sender_id'] = self.pck.get_data(U_TP_I)
            ret[msg_id]['subject'] = self.pck.get_data(U_TP_S)
            ret[msg_id]['mime'] = self.pck.get_data(U_TP_S)
            ret[msg_id]['flag'] = self.pck.get_data(U_TP_I)
            msg_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def messages_sent_list_get(self, params=dict()):
        """ get sent message list
        @params:
        :(s)  time_start :	(l) = 0
        :(s)  time_end :	(l) = max_time
        @returns:
        :(i)  msg_id : dict:
        :(s)    send_date       :	(i)
        :(s)    reciever_id     :	(i)
        :(s)    reciever_type   :	(i)  - code of reciever type (U_RCVR_T)
        :(s)    subject         :	(s)
        :(s)    mime            :	(s)
        :(s)    flag            :	(i) -  bitmask (U_MSG_FLGS)
        """
        if not self.urfa_call(0x500e):
            raise Exception("Fail of urfa_call(0x500e) [rpcf_get_sent_messages_list]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        if 'time_start' not in params: params['time_start'] = 0
        self.pck.add_data(params['time_start'], U_TP_L)
        if 'time_end' not in params: params['time_end'] = max_time
        self.pck.add_data(params['time_end'], U_TP_L)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        msg_cnt = self.pck.get_data(U_TP_I) - 1
        # first message
        if msg_cnt:
            msg_id = self.pck.get_data(U_TP_I)
            ret[msg_id] = {}
            ret[msg_id]['send_date'] = self.pck.get_data(U_TP_I)
            ret[msg_id]['reciever_id'] = self.pck.get_data(U_TP_I)
            ret[msg_id]['reciever_type'] = self.pck.get_data(U_TP_I)
            ret[msg_id]['subject'] = self.pck.get_data(U_TP_S)
            ret[msg_id]['mime'] = self.pck.get_data(U_TP_S)
            ret[msg_id]['flag'] = self.pck.get_data(U_TP_I)
        while msg_cnt:
            self.pck.recv(self.sck)
            msg_id = self.pck.get_data(U_TP_I)
            ret[msg_id] = {}
            ret[msg_id]['send_date'] = self.pck.get_data(U_TP_I)
            ret[msg_id]['reciever_id'] = self.pck.get_data(U_TP_I)
            ret[msg_id]['reciever_type'] = self.pck.get_data(U_TP_I)
            ret[msg_id]['subject'] = self.pck.get_data(U_TP_S)
            ret[msg_id]['mime'] = self.pck.get_data(U_TP_S)
            ret[msg_id]['flag'] = self.pck.get_data(U_TP_I)
            msg_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def message_get(self, params):
        """ get message
        @params:
        :(s)  msg_id :	(i)
        @returns:
        :(s)  subject       :	(s)
        :(s)  msg_body      :	(s)
        :(s)  mime          :	(s)
        :(s)  send_date     :	(i)
        :(s)  sender_id     :	(i)
        :(s)  receiver_id   :	(i)
        :(s)  receiver_type :	(i) - code of reciever type (U_RCVR_T)
        """
        if not self.urfa_call(0x500c):
            raise Exception("Fail of urfa_call(0x500c) [rpcf_get_message]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['msg_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['subject'] = self.pck.get_data(U_TP_S)
        ret['msg_body'] = self.pck.get_data(U_TP_S)
        ret['mime'] = self.pck.get_data(U_TP_S)
        ret['send_date'] = self.pck.get_data(U_TP_I)
        ret['sender_id'] = self.pck.get_data(U_TP_I)
        ret['receiver_id'] = self.pck.get_data(U_TP_I)
        ret['receiver_type'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def message_add(self, params=dict()):
        """ create message
        @params:
        :(s)  receiver_id   :	(i) = 0 - if receiver_type = _all_ then receiver_id = 0
        :(s)  receiver_type :	(i) = 4 - code of reciever type (U_RCVR_T), default - all
        :(s)  subject       :	(s)
        :(s)  msg_body      :	(s)
        :(s)  mime          :	(s) = 'text/plain' - (text/plain or text/html)
        @returns:
        :	True if success
        """
        if not self.urfa_call(0x500d):
            raise Exception("Fail of urfa_call(0x500d) [rpcf_add_message_new]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        if 'receiver_id' not in params: params['receiver_id'] = 0
        self.pck.add_data(params['receiver_id'], U_TP_I)
        if 'receiver_type' not in params: params['receiver_type'] = 4
        self.pck.add_data(params['receiver_type'], U_TP_I)
        self.pck.add_data(params['subject'], U_TP_S)
        self.pck.add_data(params['msg_body'], U_TP_S)
        if 'mime' not in params: params['mime'] = 'text/plain'
        self.pck.add_data(params['mime'], U_TP_S)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")

    def message_flag_add(self, params):
        """ check on the flags of message
        @params:
        :(s)  msg_id :	(i)
        :(s)  flag :	(i)  -  bitmask (U_MSG_FLGS)
        @returns:
        :	True if success
        """
        if not self.urfa_call(0x5030):
            raise Exception("Fail of urfa_call(0x5030) [rpcf_add_message_flag]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['msg_id'], U_TP_I)
        self.pck.add_data(params['flag'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")

    def message_flag_del(self, params):
        """ uncheck the flags of mesage
        @params:
        :(s)  msg_id :	(i)
        :(s)  flag :	(i)  - bitmask (U_MSG_FLGS)
        @returns:
        :	True if success
        """
        if not self.urfa_call(0x5031):
            raise Exception("Fail of urfa_call(0x5031) [rpcf_remove_message_flag]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['msg_id'], U_TP_I)
        self.pck.add_data(params['flag'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")

    def message_state_update(self, params):
        """ ???
        @params:
        :(s)  msg_id :	(i)
        :(s)  state :	(i)  - ???
        @returns:
        :	True if success
        """
        if not self.urfa_call(0x5029):
            raise Exception("Fail of urfa_call(0x5029) [rpcf_update_message_state]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['msg_id'], U_TP_I)
        self.pck.add_data(params['state'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")

    def banks_get(self):
        """ get banks info
        @params:
        :	None
        @returns:
        :(i)  bnk_id : dict:
        :(s)    bic     :	(s)
        :(s)    name    :	(s)
        :(s)    city    :	(s)
        :(s)    cor_acc :	(s)
        """
        if not self.urfa_call(0x6002):
            raise Exception("Fail of urfa_call(0x6002) [rpcf_get_banks]")
            #--------- output
        self.pck.recv(self.sck)
        ret = {}
        bnk_cnt = self.pck.get_data(U_TP_I)
        while bnk_cnt:
            self.pck.recv(self.sck)
            bnk_id = self.pck.get_data(U_TP_I)
            ret[bnk_id] = {}
            ret[bnk_id]['bic'] = self.pck.get_data(U_TP_S)
            ret[bnk_id]['name'] = self.pck.get_data(U_TP_S)
            ret[bnk_id]['city'] = self.pck.get_data(U_TP_S)
            ret[bnk_id]['cor_acc'] = self.pck.get_data(U_TP_S)
            bnk_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def banks_put(self, params):
        """ add/edit bank info by BIC
        @params:
        :(s)  bic : dict:  -  if already exist then edit, else add new
        :(s)    name    :	(s)
        :(s)    city    :	(s)
        :(s)    cor_acc :	(s)  - (Corresp. account)
        @returns:
        :(s)  result :	(i)  - bank_id if make new, 0 if edit exist
        """
        if not self.urfa_call(0x6001):
            raise Exception("Fail of urfa_call(0x6001) [rpcf_put_banks]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(len(params), U_TP_I)
        for bic, pm in params.iteritems():
            self.pck.add_data(bic, U_TP_S)
            self.pck.add_data(pm['name'], U_TP_S)
            self.pck.add_data(pm['city'], U_TP_S)
            self.pck.add_data(pm['cor_acc'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def bank_del(self, params):
        """ delete bank by id and BIC
        @params:
        :(s)  bank_id   :	(i)
        :(s)  bic       :	(s)
        @returns:
        :	True if success
        """
        if not self.urfa_call(0x6003):
            raise Exception("Fail of urfa_call(0x6003) [rpcf_del_bank]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['bank_id'], U_TP_I)
        self.pck.add_data(params['bic'], U_TP_S)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")

    def sup_get(self):
        """ get suppliers info
        @params:
        :	None
        @returns:
        :(i)  sup_id : dict:
        :(s)    title           :	(s)
        :(s)    title_sh        :	(s)
        :(s)    fio_seo         :	(s)
        :(s)    fio_seo_sh      :	(s)
        :(s)    fio_booker      :	(s)
        :(s)    fio_booker_sh   :	(s)
        :(s)    adress_jur      :	(s)
        :(s)    adress_act      :	(s)
        :(s)    inn             :	(s)
        :(s)    kpp             :	(s)
        :(s)    bank_id         :	(i)
        :(s)    bank_account    :	(s)
        :(s)    bank_bic        :	(s)
        :(s)    bank_name       :	(s)
        :(s)    bank_city       :	(s)
        :(s)    bank_cor_acc    :	(s)
        """
        if not self.urfa_call(0x8011):
            raise Exception("Fail of urfa_call(0x8011) [rpcf_get_sup]")
            #--------- output
        self.pck.recv(self.sck)
        ret = {}
        sup_cnt = self.pck.get_data(U_TP_I)
        while sup_cnt:
            self.pck.recv(self.sck)
            sup_id = self.pck.get_data(U_TP_I)
            ret[sup_id] = {}
            ret[sup_id]['title'] = self.pck.get_data(U_TP_S)
            ret[sup_id]['adress_jur'] = self.pck.get_data(U_TP_S)
            ret[sup_id]['adress_act'] = self.pck.get_data(U_TP_S)
            ret[sup_id]['inn'] = self.pck.get_data(U_TP_S)
            ret[sup_id]['kpp'] = self.pck.get_data(U_TP_S)
            ret[sup_id]['bank_id'] = self.pck.get_data(U_TP_I)
            ret[sup_id]['bank_account'] = self.pck.get_data(U_TP_S)
            ret[sup_id]['fio_seo'] = self.pck.get_data(U_TP_S)
            ret[sup_id]['fio_booker'] = self.pck.get_data(U_TP_S)
            ret[sup_id]['fio_seo_sh'] = self.pck.get_data(U_TP_S)
            ret[sup_id]['fio_booker_sh'] = self.pck.get_data(U_TP_S)
            ret[sup_id]['title_sh'] = self.pck.get_data(U_TP_S)
            ret[sup_id]['bank_bic'] = self.pck.get_data(U_TP_S)
            ret[sup_id]['bank_name'] = self.pck.get_data(U_TP_S)
            ret[sup_id]['bank_city'] = self.pck.get_data(U_TP_S)
            ret[sup_id]['bank_cor_acc'] = self.pck.get_data(U_TP_S)
            sup_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def sup_edit(self, params):
        """ edit supplier
        @params:
        :(s)  sup_id        :	(i)  - supplier id
        :(s)  title         :	(s)  - title
        :(s)  title_sh      :	(s)  - short title
        :(s)  fio_seo       :	(s)  - SEO full name
        :(s)  fio_seo_sh    :	(s)  - SEO short name
        :(s)  fio_booker    :	(s)  - chief booker full name
        :(s)  fio_booker_sh :	(s)  - chief booker short name
        :(s)  adress_jur     :	(s)  - juridical address
        :(s)  adress_act    :	(s)  - actual address
        :(s)  inn           :	(s)  - TaxID
        :(s)  kpp           :	(s)  - RCR
        :(s)  bank_id       :	(i)
        :(s)  bank_account  :	(s)
        @returns:
        :	True if success
        """
        if not self.urfa_call(0x8012):
            raise Exception("Fail of urfa_call(0x8012) [rpcf_save_sup]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['id'], U_TP_I)
        self.pck.add_data(params['name'], U_TP_S)
        self.pck.add_data(params['jur_adress'], U_TP_S)
        self.pck.add_data(params['act_adress'], U_TP_S)
        self.pck.add_data(params['inn'], U_TP_S)
        self.pck.add_data(params['kpp'], U_TP_S)
        self.pck.add_data(params['bank_id'], U_TP_I)
        self.pck.add_data(params['account'], U_TP_S)
        self.pck.add_data(params['fio_headman'], U_TP_S)
        self.pck.add_data(params['fio_bookeeper'], U_TP_S)
        self.pck.add_data(params['fio_headman_sh'], U_TP_S)
        self.pck.add_data(params['fio_bookeeper_sh'], U_TP_S)
        self.pck.add_data(params['name_sh'], U_TP_S)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")

    def tech_param_get(self, params):
        """ get tech params by user_id (and account_id if need)
        @params:
        :(s)  user_id       :	(i)
        :(s)  account_id    :	(i) = 0
        @returns:
        :(i)  tparam_id : dict:
        :(s)    type_id         :	(i)  - id of type
        :(s)    type_name       :	(s)  - name of type
        :(s)    value           :	(s)  - value
        :(s)    reg_date        :	(i)  - date of reg. param.
        :(s)    slink_id        :	(i)
        :(s)    service_name    :	(s)
        :(s)    password        :	(s)
        """
        if not self.urfa_call(0x9000):
            raise Exception("Fail of urfa_call(0x9000) [rpcf_get_tech_param_by_uid]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        if 'account_id' not in params: params['account_id'] = 0
        self.pck.add_data(params['account_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        tparam_cnt = self.pck.get_data(U_TP_I)
        while tparam_cnt:
            self.pck.recv(self.sck)
            tparam_vec_ltp = self.pck.get_data(U_TP_I)
            while tparam_vec_ltp:
                self.pck.recv(self.sck)
                tparam_id = self.pck.get_data(U_TP_I)
                ret[tparam_id] = {}
                ret[tparam_id]['type_id'] = self.pck.get_data(U_TP_I)
                ret[tparam_id]['type_name'] = self.pck.get_data(U_TP_S)
                ret[tparam_id]['value'] = self.pck.get_data(U_TP_S)
                ret[tparam_id]['reg_date'] = self.pck.get_data(U_TP_I)
                ret[tparam_id]['slink_id'] = self.pck.get_data(U_TP_I)
                ret[tparam_id]['service_name'] = self.pck.get_data(U_TP_S)
                ret[tparam_id]['password'] = self.pck.get_data(U_TP_S)
                tparam_vec_ltp -= 1
            tparam_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def tech_param_get_types(self):
        """ get tech params types
        @params:
        :	None
        @returns:
        :(i) type_id : (s) type_name
        """
        if not self.urfa_call(0x9002):
            raise Exception("Fail of urfa_call(0x9002) [rpcf_get_tech_param_type]")
            #--------- output
        self.pck.recv(self.sck)
        ret = {}
        cnt = self.pck.get_data(U_TP_I)
        while cnt:
            self.pck.recv(self.sck)
            type_id = self.pck.get_data(U_TP_I)
            ret[type_id] = self.pck.get_data(U_TP_S)
            cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def tech_param_add(self, params):
        """ add tech param to slink
        @params:
        :(s)  type_id   :	(i) = 1
        :(s)  slink_id  :	(i)
        :(s)  value     :	(s) = ''
        :(s)  reg_date  :	(i) = now()
        :(s)  password  :	(s) = ''
        @returns:
        :(s)  result    :	(i)
        """
        if not self.urfa_call(0x9004):
            raise Exception("Fail of urfa_call(0x9004) [rpcf_add_tech_param]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        if 'type_id' not in params: params['type_id'] = 1
        self.pck.add_data(params['type_id'], U_TP_I)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.add_data(params['value'], U_TP_S)
        if 'reg_date' not in params: params['reg_date'] = now()
        self.pck.add_data(params['reg_date'], U_TP_I)
        if 'password' not in params: params['password'] = ''
        self.pck.add_data(params['password'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def tech_param_edit(self, params):
        """ edit tech param by slink_id and tparam_id
        @params:
        :(s)  slink_id  :	(i) - unchangeable (just for id)
        :(s)  tparam_id :	(i) - unchangeable (just for id)
        :(s)  reg_date  :	(i) = now()
        :(s)  value     :	(s)
        :(s)  password  :	(s)
        @returns:
        :(s)  result :	(i) - 0 if not errors
        """
        if not self.urfa_call(0x9005):
            raise Exception("Fail of urfa_call(0x9005) [rpcf_save_tech_param]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        if 'type_id' not in params: params['type_id'] = 1
        self.pck.add_data(params['type_id'], U_TP_I)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.add_data(params['tparam_id'], U_TP_I)
        self.pck.add_data(params['value'], U_TP_S)
        if 'reg_date' not in params: params['reg_date'] = now()
        self.pck.add_data(params['reg_date'], U_TP_I)
        self.pck.add_data(params['password'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def tech_param_del(self, params):
        """ delete tech param
        @params:
        :(s)  tparam_id :	(i)
        :(s)  slink_id  :	(i)
        @returns:
        :	True if success
        """
        if not self.urfa_call(0x9001):
            raise Exception("Fail of urfa_call(0x9001) [rpcf_del_tech_param]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['tparam_id'], U_TP_I)
        self.pck.add_data(params['slink_id'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")

    def user_othersets_get(self, params):
        """ get "other" sets of user
        @params:
        :(s)  user_id :	(i)
        @returns:
        : if set_type == 1 (switch) then
        :(s)  switch_id :	(i)  - id of binded switch
        :(s)  port      :	(i)  - port on switch
        : else if set_type == 3 (currency) then
        :(s)  currency_id   :	(i)  - currency id
        :(s)  currency_name :	(s)  - currency name
        """
        if not self.urfa_call(0x9021):
            raise Exception("Fail of urfa_call(0x9021) [rpcf_get_user_othersets]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        sets_cnt = self.pck.get_data(U_TP_I)
        while sets_cnt:
            set_type = self.pck.get_data(U_TP_I)
            if set_type == 1:                    # switch id and port number
                ret['switch_id'] = self.pck.get_data(U_TP_I)
                ret['port'] = self.pck.get_data(U_TP_I)
            elif set_type == 3:                    # currency id & name
                ret['currency_id'] = self.pck.get_data(U_TP_I)
                ret['currency_name'] = self.pck.get_data(U_TP_S)
            sets_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def user_othersets_edit(self, params):
        """ edit "other" sets of user
        @params:
        :(s)  user_id :	(i)
        :(i)  type : dict:  - type of set (1 - switch, 3 - currency)
        : if set_type == 1 (switch) then
        :(s)    switch_id   :	(i)  - id of binded switch, 0 - any
        :(s)    port        :	(i)  - port on switch, not use if switch_id == 0
        : else if set_type == 3 (currency) then
        :(s)    currency_id :	(i)  currency id
        @returns:
        :	True if success
        """
        if not self.urfa_call(0x9022):
            raise Exception("Fail of urfa_call(0x9022) [rpcf_save_user_othersets]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(len(params['osets']), U_TP_I)
        for oset in params['osets']:
            self.pck.add_data(oset['type'], U_TP_I)
            if oset['type'] == 1:
                self.pck.add_data(oset['switch_id'], U_TP_I)
                self.pck.add_data(oset['port'], U_TP_I)
            elif oset['type'] == 3:
                self.pck.add_data(oset['currency_id'], U_TP_I)
        self.pck.send(self.sck)
        if self.pck.recv(self.sck): return True
        else: raise Exception("Fail recive answer from server")

    def fw_subst_get(self):
        """ get available substring (variables) of fw rule text, depended of events bitmask
        @params:
        :	None
        @returns:
        :(s)  subst : events :	(l)  -
        """
        if not self.urfa_call(0x0049):
            raise Exception("Fail of urfa_call(0x0049) [rpcf_get_fw_subst]")
            #--------- output
        self.pck.recv(self.sck)
        ret = {}
        subst_cnt = self.pck.get_data(U_TP_I)
        while subst_cnt:
            self.pck.recv(self.sck)
            subs = self.pck.get_data(U_TP_S)
            ret[subs] = self.pck.get_data(U_TP_L)
            subst_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def fwrules_list_get(self):
        """ get list of fw_rules
        @params:
        :	None
        @returns:
        :(i)  rule_id : dict:
        :(s)    flags       :	(i)  - 'execute for...' flags: 0 - None, 1 - all users, 2 - all params match (id's)
        :(s)    events      :	(l)  - bitmask of 'events when' (U_EVENTS_T)
        :(s)    router_id   :	(i)
        :(s)    tariff_id   :	(i)
        :(s)    group_id    :	(i)
        :(s)    user_id     :	(i)
        :(s)    rule        :	(s)  - rule text
        :(s)    comment     :	(s)
        """
        if not self.urfa_call(0x5020):
            raise Exception("Fail of urfa_call(0x5020) [rpcf_get_fwrules_list_new]")
            #--------- output
        self.pck.recv(self.sck)
        ret = {}
        rules_cnt = self.pck.get_data(U_TP_I)
        while rules_cnt:
            self.pck.recv(self.sck)
            rule_id = self.pck.get_data(U_TP_I)
            ret[rule_id] = {}
            ret[rule_id]['flags'] = self.pck.get_data(U_TP_I)
            ret[rule_id]['events'] = hex(self.pck.get_data(U_TP_L))
            ret[rule_id]['router_id'] = self.pck.get_data(U_TP_I)
            ret[rule_id]['tariff_id'] = self.pck.get_data(U_TP_I)
            ret[rule_id]['group_id'] = self.pck.get_data(U_TP_I)
            ret[rule_id]['user_id'] = self.pck.get_data(U_TP_I)
            ret[rule_id]['rule'] = self.pck.get_data(U_TP_S)
            ret[rule_id]['comment'] = self.pck.get_data(U_TP_S)
            rules_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def fwrule_add(self, params):
        """ add fw rule
        @params:
        :(s)  flags         :	(i) = 0 - 'execute for...' flags: 0 - None, 1 - all users, 2 - all params match (id's)
        :(s)  events        :	(l)     - bitmask of 'events when' (U_EVENTS_T)
        :(s)  router_id     :	(i) = 0 - 0 = any
        :(s)  tariff_id     :	(i) = 0 - 0 = any
        :(s)  group_id      :	(i) = 0 - 0 = any
        :(s)  user_id       :	(i) = 0 - must by non-zero if tariff_id & group_id == 0
        :(s)  rule          :	(s)     - rule text
        :(s)  comment       :	(s) = ''
        @returns:
        :(s)  rule_id :	(i)  -
        """
        if not self.urfa_call(0x5021):
            raise Exception("Fail of urfa_call(0x5021) [rpcf_add_fwrule_new]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        if 'flags' not in params: params['flags'] = 0
        self.pck.add_data(params['flags'], U_TP_I)
        self.pck.add_data(params['events'], U_TP_L)
        if 'router_id' not in params: params['router_id'] = 0
        self.pck.add_data(params['router_id'], U_TP_I)
        if 'tariff_id' not in params: params['tariff_id'] = 0
        self.pck.add_data(params['tariff_id'], U_TP_I)
        if 'group_id' not in params: params['group_id'] = 0
        self.pck.add_data(params['group_id'], U_TP_I)
        if 'user_id' not in params: params['user_id'] = 0
        self.pck.add_data(params['user_id'], U_TP_I)
        self.pck.add_data(params['rule'], U_TP_S)
        if 'comment' not in params: params['comment'] = ''
        self.pck.add_data(params['comment'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['rule_id'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def fwrule_edit(self, params):
        """ edit fw rule by id
        @params:
        :(s)  rule_id   :	(i)
        :(s)  flags     :	(i)
        :(s)  events    :	(l)
        :(s)  router_id :	(i)
        :(s)  tariff_id :	(i)
        :(s)  group_id  :	(i)
        :(s)  user_id   :	(i)
        :(s)  rule      :	(s)
        :(s)  comment   :	(s)
        @returns:
        :(s)  result    :	(i)
        """
        if not self.urfa_call(0x5022):
            raise Exception("Fail of urfa_call(0x5022) [rpcf_edit_fwrule_new]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
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
        self.pck.recv(self.sck)
        ret = {}
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def fwrule_del(self, params):
        """ delete fw rule by id
        @params:
        :(s)  rule_id :	(i)
        @returns:
        :(s)  result :	(i)
        """
        if not self.urfa_call(0x5023):
            raise Exception("Fail of urfa_call(0x5023) [rpcf_del_fwrule_new]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['rule_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def shaped_services_list_get(self):
        """ get list of shaped services
        @params:
        :	None
        @returns:
        :(i)  srvc_id :	dict:  -
        :(s)    srvc_name :	(s)  -
        :(s)    srvc_comment :	(s)  -
        """
        if not self.urfa_call(0x12006):
            raise Exception("Fail of urfa_call(0x12006) [rpcf_get_shaped_services]")
            #--------- output
        self.pck.recv(self.sck)
        ret = {}
        srvc_cnt = self.pck.get_data(U_TP_I)
        while srvc_cnt:
            self.pck.recv(self.sck)
            srvc_id = self.pck.get_data(U_TP_I)
            ret[srvc_id] = {}
            ret[srvc_id]['srvc_name'] = self.pck.get_data(U_TP_S)
            ret[srvc_id]['srvc_comment'] = self.pck.get_data(U_TP_S)
            srvc_cnt -= 1
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def shaping_get(self, params):
        """ get dynam-shaping rule by id of shaped service
        @params:
        :(s)  service_id :	(i)
        @returns:
        :(s) flags: (i)                 - 'applay to...' (VPN/nonVPN) checkbox (U_DSH_APPLY)
        :(s) incoming: dict:            - dict of rules for incoming traffic
        :(s)   tclasses : list:         - list of traffic classes id's that are used in dshape rule
        :(i)     tclass_id
        :(s)   borders : list:          - dict of traffic bordes and time ranges with limits on them
        :(l)     border_value :	dict:    - value of border when rule is On (in bytes)
        :(i)       tr_id : (i) tr_limit - dict of time ranges like { tr_id : tr_limit }, tr_limit set in Kbps
        :(s) outcoming: dict:           - dict of rules for outcoming traffic
        :(s)   tclasses : list:         - list of traffic classes id's that are used in dshape rule
        :(i)     tclass_id
        :(s)   borders : list:          - dict of traffic bordes and time ranges with limits on them
        :(l)     border_value :	dict:    - value of border when rule is On (in bytes)
        :(i)       tr_id : (i) tr_limit - dict of time ranges like { tr_id : tr_limit }, tr_limit set in Kbps
        :(s)    radius_attr : list      - list of RADIUS attributes
        :               :dict:
        :(s)      rad_vendor:	(i)
        :(s)      rad_attr  :	(i)
        :(s)      rad_type  :	(i)     - 1 - 'string', 2 - 'number'
        :(s)      rad_value :	(s)
        :(s)  result :	(i)  - not 0 if errors
        """
        if not self.urfa_call(0x12004):
            raise Exception("Fail of urfa_call(0x12004) [rpcf_get_shaping]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        res = self.pck.get_data(U_TP_I)
        if not res:
            ret = {'incoming': {'tclasses': [], 'borders': {}},
                   'outcoming': {'tclasses': [], 'borders': {}},
                   'radius_attr': []}
            ret['flags'] = self.pck.get_data(U_TP_I)
            for trtype in ('incoming', 'outcoming'):
                tclasses_cnt = self.pck.get_data(U_TP_I)
                while tclasses_cnt:
                    self.pck.recv(self.sck)
                    ret[trtype]['tclasses'].append(self.pck.get_data(U_TP_I))
                    tclasses_cnt -= 1
                self.pck.recv(self.sck)
                borders_cnt = self.pck.get_data(U_TP_I)
                timeranges_cnt = self.pck.get_data(U_TP_I)
                while borders_cnt:
                    self.pck.recv(self.sck)
                    border_value = self.pck.get_data(U_TP_L)
                    if timeranges_cnt:
                        time_ranges = {}
                        while timeranges_cnt:
                            self.pck.recv(self.sck)
                            timerange_id = self.pck.get_data(U_TP_I)
                            time_ranges[timerange_id] = self.pck.get_data(U_TP_I)
                            timeranges_cnt -= 1
                        ret[trtype]['borders'][border_value] = time_ranges
                    borders_cnt -= 1
                self.pck.recv(self.sck)
                ## ------------ RADIUS params
            radius_attr_cnt = self.pck.get_data(U_TP_I)
            if radius_attr_cnt:
                ret['radius_attr'] = []
                while radius_attr_cnt:
                    self.pck.recv(self.sck)
                    rad_attr = {}
                    rad_attr['rad_vendor'] = self.pck.get_data(U_TP_I)
                    rad_attr['rad_attr'] = self.pck.get_data(U_TP_I)
                    rad_attr['rad_type'] = self.pck.get_data(U_TP_I)
                    rad_attr['rad_value'] = self.pck.get_data(U_TP_S)
                    ret['radius_attr'].append(rad_attr)
                    radius_attr_cnt -= 1
        else: ret['result'] = res
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def shaping_add(self, params):
        """ add dynam-shape rule
        @params:
        :(s) service_id    :	(i)     - MUST BY EXISTING SERVICE_ID!!! else dynamshape module crashed
        :(s) flags: (i)                 - 'applay to...' (VPN/nonVPN) checkbox (U_DSH_APPLY)
        :(s) incoming: dict:            - dict of rules for incoming traffic
        :(s)   tclasses : list:         - list of traffic classes id's that are used in dshape rule
        :(i)     tclass_id
        :(s)   borders : dict:          - dict of traffic bordes and time ranges with limits on them
        :(l)     border_value :	dict:   - value of border when rule is On (in bytes)
        :(i)       tr_id : (i) tr_limit - dict of time ranges like { tr_id : tr_limit }, tr_limit set in Kbps
        :(s) outcoming: dict:           - dict of rules for outcoming traffic
        :(s)   tclasses : list:         - list of traffic classes id's that are used in dshape rule
        :(i)     tclass_id
        :(s)   borders : list:          - dict of traffic bordes and time ranges with limits on them
        :(l)     border_value :	dict:   - value of border when rule is On (in bytes)
        :(i)       tr_id : (i) tr_limit - dict of time ranges like { tr_id : tr_limit }, tr_limit set in Kbps
        :(s)    radius_attr : list:     - list of RADIUS attributes
        :              :dict:
        :(s)      rad_vendor:	(i)
        :(s)      rad_attr  :	(i)
        :(s)      rad_type  :	(i)     - 1 - 'string', 2 - 'number'
        :(s)      rad_value :	(s)
        @returns:
        :(s)  result :	(i)
        """
        if not self.urfa_call(0x12002):
            raise Exception("Fail of urfa_call(0x12002) [rpcf_add_shaping]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.add_data(params['flags'], U_TP_I)
        for trtype in ['incoming', 'outcoming']:
            if not trtype in params: params[trtype] = {}
            if not 'tclasses' in params[trtype]: params[trtype]['tclasses'] = ()
            self.pck.add_data(len(params[trtype]['tclasses']), U_TP_I)
            for tclasses in params[trtype]['tclasses']:
                self.pck.add_data(tclasses, U_TP_I)
            if not 'borders' in params[trtype]: params[trtype]['borders'] = {}
            self.pck.add_data(len(params[trtype]['borders']), U_TP_I)
            if len(params[trtype]['borders']):
                tr_cnt = len(dict(params[trtype]['borders']).values()[0])
            else:
                tr_cnt = 0
            self.pck.add_data(tr_cnt, U_TP_I)
            for brd_val, tr_limits in params[trtype]['borders'].iteritems():
                self.pck.add_data(brd_val, U_TP_L)
                for lim_tr, lim_val in tr_limits.iteritems():
                    self.pck.add_data(lim_tr, U_TP_I)
                    self.pck.add_data(lim_val, U_TP_I)
            # ====== RADIUS
        if not 'radius_attr' in params: params['radius_attr'] = ()
        self.pck.add_data(len(params['radius_attr']), U_TP_I)
        for ra in params['radius_attr']:
            self.pck.add_data(ra['rad_vendor'], U_TP_I)
            self.pck.add_data(ra['rad_attr'], U_TP_I)
            self.pck.add_data(ra['rad_type'], U_TP_I)
            self.pck.add_data(ra['rad_value'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def shaping_edit(self, params):
        """ edit dynam-shape rule by service_id, !!!unspecified parameters will be reset to zero!!!
        @params:
        :(s) service_id    :	(i)     - MUST BY EXISTING SERVICE_ID!!! else dynamshape module crashed
        :(s) flags: (i)                 - 'applay to...' (VPN/nonVPN) checkbox (U_DSH_APPLY)
        :(s) incoming: dict:            - dict of rules for incoming traffic
        :(s)   tclasses : list:         - list of traffic classes id's that are used in dshape rule
        :(i)     tclass_id
        :(s)   borders : dict:          - dict of traffic bordes and time ranges with limits on them
        :(l)     border_value :	dict:   - value of border when rule is On (in bytes)
        :(i)       tr_id : (i) tr_limit - dict of time ranges like { tr_id : tr_limit }, tr_limit set in Kbps
        :(s) outcoming: dict:           - dict of rules for outcoming traffic
        :(s)   tclasses : list:         - list of traffic classes id's that are used in dshape rule
        :(i)     tclass_id
        :(s)   borders : list:          - dict of traffic bordes and time ranges with limits on them
        :(l)     border_value :	dict:   - value of border when rule is On (in bytes)
        :(i)       tr_id : (i) tr_limit - dict of time ranges like { tr_id : tr_limit }, tr_limit set in Kbps
        :(s)    radius_attr : list:     - list of RADIUS attributes
        :              :dict:
        :(s)      rad_vendor:	(i)
        :(s)      rad_attr  :	(i)
        :(s)      rad_type  :	(i)     - 1 - 'string', 2 - 'number'
        :(s)      rad_value :	(s)
        @returns:
        :(s)  result :	(i)
        """
        if not self.urfa_call(0x12003):
            raise Exception("Fail of urfa_call(0x12003) [rpcf_edit_shaping]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.add_data(params['flags'], U_TP_I)
        for trtype in ['incoming', 'outcoming']:
            if not trtype in params: params[trtype] = {}
            if not 'tclasses' in params[trtype]: params[trtype]['tclasses'] = ()
            self.pck.add_data(len(params[trtype]['tclasses']), U_TP_I)
            for tclasses in params[trtype]['tclasses']:
                self.pck.add_data(tclasses, U_TP_I)
            if not 'borders' in params[trtype]: params[trtype]['borders'] = {}
            self.pck.add_data(len(params[trtype]['borders']), U_TP_I)
            if len(params[trtype]['borders']):
                tr_cnt = len(dict(params[trtype]['borders']).values()[0])
            else:
                tr_cnt = 0
            self.pck.add_data(tr_cnt, U_TP_I)
            for brd_val, tr_limits in params[trtype]['borders'].iteritems():
                self.pck.add_data(brd_val, U_TP_L)
                for lim_tr, lim_val in tr_limits.iteritems():
                    self.pck.add_data(lim_tr, U_TP_I)
                    self.pck.add_data(lim_val, U_TP_I)
            # ====== RADIUS
        if not 'radius_attr' in params: params['radius_attr'] = ()
        self.pck.add_data(len(params['radius_attr']), U_TP_I)
        for ra in params['radius_attr']:
            self.pck.add_data(ra['rad_vendor'], U_TP_I)
            self.pck.add_data(ra['rad_attr'], U_TP_I)
            self.pck.add_data(ra['rad_type'], U_TP_I)
            self.pck.add_data(ra['rad_value'], U_TP_S)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")

    def shaping_del(self, params):
        """ delete dynam-shaping rule by service id
        @params:
        :(s)  service_id :	(i)
        @returns:
        :(s)  result :	(i)
        """
        if not self.urfa_call(0x12005):
            raise Exception("Fail of urfa_call(0x12005) [rpcf_delete_shaping]")
            #--------- input
        self.pck.init(code=U_PKT_DATA)
        self.pck.add_data(params['service_id'], U_TP_I)
        self.pck.send(self.sck)
        #--------- output
        self.pck.recv(self.sck)
        ret = {}
        ret['result'] = self.pck.get_data(U_TP_I)
        if self.pck.recv(self.sck): return ret
        else: raise Exception("Fail recive answer from server")
