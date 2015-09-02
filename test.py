from urfa import urfa_client
import os,sys

def resource_path(relative):
    return os.path.join(getattr(sys, '_MEIPASS', os.path.abspath(".")),relative)
uid = 5
aid = 5
bonusServiceId = 188
bonus = 1.0
bill = urfa_client('bill.nester.ru', 11758, 'init', 'init02Nit87',admin=True,crt_file=resource_path('admin.crt'))
ret = bill.rpcf_add_once_slink_ex({'user_id':uid,'account_id':aid,'service_id':bonusServiceId,'cost_coef':-bonus})
print ret