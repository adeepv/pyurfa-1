from urfa import urfa_client
import os,sys

def resource_path(relative):
    return os.path.join(getattr(sys, '_MEIPASS', os.path.abspath(".")),relative)

bill = urfa_client('bill.nester.ru', 11758, 'init', 'init02Nit87',admin=True,crt_file=resource_path('admin.crt'))
r = bill.rpcf_radius_get_attributes_list()
print r