#!/usr/bin/python
# coding: utf-8
__author__ = 'sn355_000'
import re
import datetime
import smtplib
import os
import sys
from email.mime.text import MIMEText

import MySQLdb

from urfa import urfa_client

bonusServiceId = 188

dbuser = "NCX4IS"
dbpass = "NCX4IS"
dbname = "UTM5"
dbhost = "bill.nester.ru"

fromAddr = ''
reportAddr = ''
#reportAddr = 'snkhokh@gmail.com'

def lindex2percent(lind):
    if lind >= 3:
        if lind < 6: return 0.03
        elif lind < 9: return 0.05
        elif lind < 12: return 0.07
        else: return 0.09
    else: return 0

def resource_path(relative):
    return os.path.join(getattr(sys, '_MEIPASS', os.path.abspath(".")),relative)

def main():
    bill = urfa_client('bill.nester.ru', 11758, 'init', 'init02Nit87',admin=True,crt_file=resource_path('admin.crt'))
    db = MySQLdb.connect(db = dbname,passwd = dbpass,host = dbhost, user = dbuser, charset='utf8')
    c = db.cursor()
    #Выборка платежей за предыдущие сутки
    sql = "SELECT  UNIX_TIMESTAMP(date_sub(curdate( ), INTERVAL 1 DAY)),UNIX_TIMESTAMP(curdate( ))"
    c.execute(sql)
    (stime,ftime) = c.fetchall()[0]

    sql = """
SELECT u.id,
  a.id,
  u.full_name,
  u.mobile_telephone,
  (to_days(curdate()) - if(to_days(ifnull(from_unixtime(max(bi.start_date)),uap.d1)) > to_days(uap.d1),
                        to_days(ifnull(from_unixtime(max(bi.start_date)),uap.d1)),
                        to_days(uap.d1))) div 30 as lindex
FROM users as u,
  users_accounts as ua,
  accounts as a LEFT JOIN blocks_info AS bi ON bi.account_id = a.id,
  (
    SELECT str_to_date(value,'%d/%m/%Y') as d1, userid
    FROM user_additional_params
    WHERE paramid = (SELECT paramid FROM uaddparams_desc WHERE name LIKE 'loyalty_start')
      AND  value REGEXP '^[0-9]{1,2}/[0-9]{1,2}/[0-9]{4}$'
  ) AS uap
WHERE u.id = ua.uid
    AND ua.account_id = a.id
    AND not ua.is_deleted
    AND (uap.userid = u.id  AND uap.d1)
    AND (isnull(bi.block_type) or bi.block_type = 1)
    AND NOT a.unlimited
    AND LENGTH(TRIM(u.mobile_telephone))
GROUP BY u.id
"""
    c.execute(sql)
    report = u''
    s = smtplib.SMTP('localhost')
    for (uid, aid, uname, tel, lind) in c.fetchall():
        print u"%s (uid:%s) индекс лояльности - %s" % (uname, uid, lind)
        pbonus = lindex2percent(lind)
        if not pbonus:
            continue
        m = re.match(r'^(?:8|\+7)?([0-9]{10})',re.sub('-','',tel))
        bonus = 0
        pm = bill.report_payments({'user_id': uid, 'time_start': stime, 'time_end': ftime})
        for i in pm:
            bonus += pm[i]['sum']
        bonus *=pbonus
        if bonus:
            report += u"Идентификатор абонента: %s, Лицевой счет: %s Полное имя: %s , Бонус: %s\n" % (uid, aid, uname, bonus)
#            ret = bill.rpcf_add_once_slink_ex({'user_id':uid,'account_id':aid,'service_id':bonusServiceId,'cost_coef':-bonus})
            if m:
                toAddr = "8%s@sms.beeline.amega-inform.ru" % m.group(1)
                msg = MIMEText('Ув. абонент! За участие в бонусной программе, Вам начислен бонус в размере %s %% от суммы пополнения - %s рублей.'
                           % (pbonus*100,bonus),'plain','utf-8')
                msg['Subject'] = 'Short message service'
                msg['From'] = fromAddr
                msg['To'] = toAddr
                # s.sendmail(fromAddr, [toAddr], msg.as_string())




if __name__ == '__main__': main()

