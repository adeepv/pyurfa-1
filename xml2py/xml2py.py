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
def resolv_names(ref,io_type,names):
    """

    :type names: dict()
    """
    if io_type == 'output' and ref in names['input']: return names['input'][ref]
    if ref in names[io_type]:
        return names[io_type][ref]
    return ref

def pars_params(io, io_type, codelist, docslist, code_idt_cnt=glob_idnt_cnt + 1, doc_idt_cnt=1, names={}):
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
            default = 0
            def_flag = ' '
            idx = ''
            if isin('array_index',prm.attrib):
                for i in prm.attrib['array_index'].split(','):
                    idx += "[{}]".format(i)
            if isin('default', prm.attrib):
                default = prm.attrib['default']
                if default == '':
                    default = "''"
                p = re.findall(r'size[(](\w+)[)]', default)
                if p:
                    names['input'][p[0]] = "params['{}']".format(p[0])
                    default = "len({})".format(names['input'][p[0]])

                codelist.append(idt + "if '{0}' not in params: params['{0}'] = {1}".format(
                    prm.attrib['name'], default))
            if io_type == 'input':
                ref = "params['%s']%s" % (prm.attrib['name'],idx)
                codelist.append(idt + "self.pck.add_data({}, {})".format(ref, type))
            elif io_type == 'output':
                if isin('array_index',prm.attrib):
                    idxs = prm.attrib['array_index'].split(',')
                    if len(idxs) > 1:
                        base = "ret['%s']" % prm.attrib['name']
                        for i in idxs[:-1]:
                            s = 'if not {i} in {b}:{b}[{i}] = dict()'.format(i=i,b=base)
                            base = '{b}[{i}]'.format(b=base,i=i)
                            codelist.append(idt + s)
                ref = "ret['%s']%s" % (prm.attrib['name'],idx)
                codelist.append(idt + "{} = self.pck.get_data({})".format(ref, type))
            if not prm.attrib['name'] in names[io_type]:
                names[io_type][prm.attrib['name']] = ref
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
            codelist.append(idt + "if {ref} {exp_condit} {value}:".format(
                ref= resolv_names(prm.attrib['variable'], io_type, names),
                exp_condit=condit,
                value=prm.attrib['value']
            )
            )
            pars_params(prm, io_type, codelist, docslist, code_idt_cnt + 1, doc_idt_cnt + 1, names)

        elif prm.tag == 'for':
            count = prm.attrib['count']
            idx = prm.attrib['name']
            p = re.findall(r'size[(](\w+)[)]', count)
            if p:
                if io_type == 'input': names['input'][p[0]] = "params['{}']".format(p[0])
                count = "len({})".format(names['input'][p[0]])
            else:
                count = resolv_names(count,io_type,names)
            if io_type == 'input':
#                codelist.append(idt + "for {} in params['{}']:".format(count + '_idx', count))
                codelist.append(idt + "for {} in range({}):".format(idx, count))
                pars_params(prm, io_type, codelist, docslist, code_idt_cnt + 1, doc_idt_cnt + 1, names)
            elif io_type == 'output':
                # codelist.append(idt + "{0} = ret['{0}']".format(count))
                codelist.append(idt + "for {} in range({}): ".format(idx,count))
                codelist.append(idt + glob_idnt + 'self.pck.recv(self.sck)')
                #                codelist.append(idt + glob_idnt + '{} = dict() '.format(''))
                pars_params(prm, io_type, codelist, docslist, code_idt_cnt + 1, doc_idt_cnt + 1, names)
#                codelist.append(idt + glob_idnt + "{}_idx -= 1".format(prm.attrib['count']))

        elif prm.tag == 'set':
            if io_type == 'output':
                di = ''
                si = ''
                if isin('dst_index',prm.attrib):
                    for i in prm.attrib['dst_index'].split(','):  di += "[{}]".format(i)
                dref = "ret['{}']{}".format(prm.attrib['dst'],di)
                names[io_type][prm.attrib['dst']] = dref
                if isin('src',prm.attrib):
                    if isin('src_index',prm.attrib):
                        for i in prm.attrib['src_index'].split(','):  si += "[{}]".format(i)
                    sref = resolv_names(prm.attrib['src'],io_type,names)
                elif 'value' in prm.attrib:
                    sref = prm.attrib['value']
                    if isinstance(sref,str): sref = '"{0}"'.format(sref)
                codelist.append(idt + '{}={}{}'.format(dref, sref, si))
            else:
                pass

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
            names = {'input':{},'output':{}}
            for io in funct:
                if io.tag == 'input' and len(io):
                    functions[-1]['definit']['params'] = ', params'
                    pars_params(io, io.tag, functions[-1]['code']['input'], functions[-1]['docstrings']['params'],names = names)
                if io.tag == 'output' and len(io):
                    pars_params(io, io.tag, functions[-1]['code']['output'], functions[-1]['docstrings']['returns'],names = names)


def printing():
    code = [glob_idnt + 'from collections import defaultdict']
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