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
smtphost = 'mail.nester.ru'

fromAddr = 'ZAO_Nester@nester.ru'
reportAddr = 'ilona84@mail.ru'
reportAddr = 'sn@nester.ru'

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
    runtime = datetime.datetime.now()
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
    report = u'Обработка учетных записей абонентов, участников программы лояльности:\n'
    s = smtplib.SMTP(smtphost)
    for (uid, aid, uname, tel, lind) in c.fetchall():
        report += u"Идентификатор абонента: %s, Лицевой счет: %s Полное имя: %s, индекс лояльности: %s\n" \
                  % (uid, aid, uname, lind)
        pbonus = lindex2percent(lind)
        if not pbonus:
            continue
        pSum = 0
        pm = bill.report_payments({'user_id': uid, 'time_start': stime, 'time_end': ftime})
        for i in pm:
            pSum += pm[i]['sum']
        bonus = pbonus * pSum
        if bonus:
            report += u"Суточный платеж:%s коэфициент:%s Начислен бонус:%s" % (pSum, pbonus, bonus)
            ret = bill.rpcf_add_once_slink_ex({'user_id':uid,'account_id':aid,'service_id':bonusServiceId,'cost_coef':-bonus})
            if ret:
                report += u" ИдСервСвязки:%s \n" % (ret,)
                m = re.match(r'^(?:8|\+7)?([0-9]{10})',re.sub('-','',tel))
                if m:
                    toAddr = "8%s@sms.beeline.amega-inform.ru" % m.group(1)
                    msg = MIMEText('Ув. абонент! За участие в бонусной программе, Вам начислен бонус в размере %s %% от суммы пополнения - %s рублей.'
                                   % (pbonus*100,bonus),'plain','utf-8')
                    msg['Subject'] = 'Short message service'
                    msg['From'] = fromAddr
                    msg['To'] = toAddr
                    s.sendmail(fromAddr, [toAddr], msg.as_string())
                else:
                    report += u'ВНИМАНИЕ! ОШИБОЧНЫЙ НОМЕР МОБ. ТЕЛЕФОНА АБОНЕНТА! (%s) ОТСЫЛКА ОПОВЕЩЕНИЯ НЕВОЗМОЖНО!\n' % (tel,)
            else:
                report += u" НЕИЗВЕСТНЫЙ РЕЗУЛЬТАТ НАЧИСЛЕНИЯ БОНУСА!\n"
    msg = MIMEText(report,'plain','utf-8')
    msg['Subject'] = u'Отчет программы лояльности за %s' % (runtime.strftime('%d-%m-%Y'),)
    msg['From'] = fromAddr
    msg['To'] = reportAddr
    s.sendmail(fromAddr, [reportAddr], msg.as_string())
    s.quit()
if __name__ == '__main__': main()

