#!/usr/bin/env python
#coding=utf-8

"""
    api.xml to python functions converter
"""

from lxml import etree
import re


def size2len(d):
    p = re.findall(r'size[(](\w+)[,]?[)]?', d)
    if p:
        return "len(" + p[0].split(',')[0] + ")"

isin = lambda key, iter: key in iter and iter[key]

glob_idnt_symb_cnt = 4
glob_idnt_symb = ' '
glob_idnt_cnt = 1
glob_idnt = glob_idnt_symb * glob_idnt_symb_cnt * glob_idnt_cnt
functions = []


def pars_params(io, io_type, codelist, docslist, code_idt_cnt=glob_idnt_cnt + 1, doc_idt_cnt=1):
    for prm in io:
        idt = glob_idnt * code_idt_cnt

        if prm.tag in ('string', 'integer', 'long', 'double', 'ip_address'):
            type = ''
            if prm.tag == 'string':
                type = 'U_TP_S'
            elif prm.tag == 'integer':
                type = 'U_TP_I'
            elif prm.tag == 'long':
                type = 'U_TP_L'
            elif prm.tag == 'double':
                type = 'U_TP_D'
            elif prm.tag == 'ip_address':
                type = 'U_TP_IP'
            curcode = ''
            default = 0
            def_flag = ' '
            if isin('array_index',prm.attrib):
                idx = "[{}]".format(prm.attrib['array_index'])
            else: idx = ''
            if isin('default', prm.attrib):
                default = prm.attrib['default']
                if default == '':
                    default = "''"
                if default.count('size('):
                    default = size2len(default)
                codelist.append(idt + "if '{0}' not in params: params['{0}'] = {1}".format(
                    prm.attrib['name'], default))
            if io_type == 'input':
                curcode = "self.pck.add_data(params['{}'], {})"
            elif io_type == 'output':
                curcode = "ret['{}']{} = self.pck.get_data({})"
            codelist.append(idt + curcode.format(prm.attrib['name'], idx, type))
            if default:
                def_flag = ' = _def_ '
            docslist.append(":(s){type_idt}{prm_name} :\t({type_symb}){defs} - ".format(
                type_symb=str(prm.tag[:1]),
                type_idt='  ' * doc_idt_cnt,
                prm_name=prm.attrib['name'],
                defs=def_flag))

        elif prm.tag == 'if':
            condit = ''
            if prm.attrib['condition'] == 'eq':
                condit = ' == '
            elif prm.attrib['condition'] == 'ne':
                condit = ' != '
            pm_arr_if = ''
            if io_type == 'input':
                pm_arr_if = "params"
            elif io_type == 'output':
                pm_arr_if = "ret"
            codelist.append(idt + "if {arr_name}['{var_name}'] {exp_condit} {value}:".format(
                arr_name=pm_arr_if,
                var_name=prm.attrib['variable'],
                exp_condit=condit,
                value=prm.attrib['value']
            )
            )
            pars_params(prm, io_type, codelist, docslist, code_idt_cnt + 1, doc_idt_cnt + 1)

        elif prm.tag == 'for':
            count = prm.attrib['count']
            idx = prm.attrib['name']
            if count.count('size('):
                count = size2len(count)
            if io_type == 'input':
#                codelist.append(idt + "for {} in params['{}']:".format(count + '_idx', count))
                codelist.append(idt + "for {} in range({}):".format(idx, count))
                pars_params(prm, io_type, codelist, docslist, code_idt_cnt + 1, doc_idt_cnt + 1)
            elif io_type == 'output':
                codelist.append(idt + "{0} = ret['{0}']".format(count))
                codelist.append(idt + "for {} in range({}): ".format(idx,count))
                codelist.append(idt + glob_idnt + 'self.pck.recv(self.sck)')
                #                codelist.append(idt + glob_idnt + '{} = dict() '.format(''))
                pars_params(prm, io_type, codelist, docslist, code_idt_cnt + 1, doc_idt_cnt + 1)
#                codelist.append(idt + glob_idnt + "{}_idx -= 1".format(prm.attrib['count']))

        elif prm.tag == 'break':
            codelist.append(idt + prm.tag)

        elif prm.tag == 'error':
            codelist.append(idt + "ret['error'] = dict({{{}:\"{}\"}})".format(
                prm.attrib['code'], prm.attrib['comment']))
            docslist.append(":(s){}error : dict:".format('  ' * doc_idt_cnt))
            docslist.append(":(i){}code : (s) msg - error code:msg if fail".format('  ' * (doc_idt_cnt + 1)))


def building():
    xml_filename = 'api.xml'
    tree = etree.parse(xml_filename)
    root = tree.getroot()
    if root.tag != 'urfa':
        raise Exception(xml_filename + ' is not from URFA')

    for funct in root:
        if funct.tag == 'function':
            functions.append(dict({
                'definit': dict({
                    'name': funct.attrib['name'],
                    'id': funct.attrib['id'],
                    'params': ''
                }),
                'docstrings': dict({
                    'descript': '""" description',
                    'params': [],
                    'returns': []
                }),
                'code': dict({
                    'input': [],
                    'output': []
                })
            })
            )
            for io in funct:
                if io.tag == 'input' and len(io):
                    functions[-1]['definit']['params'] = ', params'
                    pars_params(io, io.tag, functions[-1]['code']['input'], functions[-1]['docstrings']['params'])
                if io.tag == 'output' and len(io):
                    pars_params(io, io.tag, functions[-1]['code']['output'], functions[-1]['docstrings']['returns'])


def printing():
    code = []
    fn_cur_num = 0
    for fn in functions:
        fn_cur_num += 1
        #        code.append('{} {}'.format('#'*80, fn_cur_num))
        code.append(glob_idnt + 'def {}(self{}):'.format(fn['definit']['name'], fn['definit']['params']))
        code.append(glob_idnt * 2 + fn['docstrings']['descript'])
        code.append(glob_idnt * 2 + '@params: ')
        if len(fn['docstrings']['params']):
            for pm in fn['docstrings']['params']:
                code.append(glob_idnt * 2 + pm)
        else:
            code.append(glob_idnt * 2 + ':\tNone')
        code.append(glob_idnt * 2 + '@returns: ')
        if len(fn['docstrings']['returns']):
            for rt in fn['docstrings']['returns']:
                code.append(glob_idnt * 2 + rt)
        else:
            code.append(glob_idnt * 2 + ':\tTrue if success')
        code.append(glob_idnt * 2 + '"""')
        code.append(glob_idnt * 2 + 'if not self.urfa_call({}):'.format(fn['definit']['id']))
        code.append(glob_idnt * 3 + 'raise Exception("Fail of urfa_call({}) [{}]")'.format(
            fn['definit']['id'], fn['definit']['name']))
        if len(fn['code']['input']):
            code.append(glob_idnt * 2 + '#--------- input')
            code.append(glob_idnt * 2 + 'self.pck.init(code = U_PKT_DATA)')
            for prm_in in fn['code']['input']:
                code.append(prm_in)
            code.append(glob_idnt * 2 + 'self.pck.send(self.sck)')
        fn_ret = 'True'
        if len(fn['code']['output']):
            fn_ret = 'ret'
            code.append(glob_idnt * 2 + '#--------- output')
            code.append(glob_idnt * 2 + 'self.pck.recv(self.sck)')
            code.append(glob_idnt * 2 + 'ret = defaultdict(dict)')
            for prm_out in fn['code']['output']:
                code.append(prm_out)
        code.append(glob_idnt * 2 + 'if self.pck.recv(self.sck): return ' + fn_ret)
        code.append(glob_idnt * 2 + 'else: raise Exception("Fail recive answer from server")')
    for line in code:
        print line

if __name__ == "__main__":
    building()
    printing()