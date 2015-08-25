#!/usr/bin/python
# coding: utf-8
__author__ = 'sn355_000'
import MySQLdb,re,datetime,smtplib
from email.mime.text import MIMEText

minBalanse = 30
sendPeriod = datetime.timedelta(days=1)
maxSendCnt = 3
restPeriod = datetime.timedelta(days=10)

dbuser = "NCX4IS"
dbpass = "NCX4IS"
dbname = "UTM5"
dbhost = "bill.nester.ru"

fromAddr = ''
reportAddr = ''
#reportAddr = 'snkhokh@gmail.com'

def main():
  runTime = datetime.datetime.now()
  newLastSend = runTime.strftime('%Y-%m-%d %H:%M:%S')

  db = MySQLdb.connect(db = dbname,passwd = dbpass,host = dbhost, user = dbuser, charset='utf8')
  c = db.cursor()
  sql = """SELECT users.id,users_accounts.id,users.full_name,balance,users.mobile_telephone,additional_params.lastSend,additional_params.sendOff
        FROM accounts LEFT JOIN blocks_info ON accounts.block_id = blocks_info.id,
        users_accounts,
        users LEFT JOIN (SELECT userid AS uid,(SELECT CONCAT(id,';',value) FROM user_additional_params
            WHERE userid = uid AND paramid = (SELECT paramid FROM uaddparams_desc WHERE name = 'sms_sended')) AS lastSend,
            (SELECT value FROM user_additional_params WHERE userid = uid AND paramid = (SELECT paramid FROM uaddparams_desc WHERE name = 'sms_off')) AS sendOff
            FROM user_additional_params GROUP BY uid)
             AS additional_params ON additional_params.uid = users.id
        WHERE users_accounts.uid = users.id
        AND users_accounts.account_id = accounts.id
        AND NOT accounts.is_deleted
        AND NOT unlimited
        AND LENGTH(TRIM(mobile_telephone))
        AND (blocks_info.is_deleted IS NULL OR blocks_info.is_deleted)
        AND balance < %s"""
  c.execute(sql,(minBalanse,))

  sent = u''
  for (uid,aid,uname,balance,tel,lastSend,sendOff) in c.fetchall():
    if sendOff: continue
    m = re.match(r'^(?:8|\+7)?([0-9]{10})',re.sub('-','',tel))
    if m:
      toAddr = "8%s@sms.beeline.amega-inform.ru" % m.group(1)
      needSend = True
      sendCnt = 0
      lastSendId = None
      if lastSend:
        m = re.match(r'(\d+);(?:(\d+):)?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}){0,1}',lastSend)
        if m:
          lastSendId = int(m.group(1))
          if m.group(2):
            sendCnt = int(m.group(2))
            lastSendDT = datetime.datetime.strptime(m.group(3),'%Y-%m-%d %H:%M:%S')
            if (lastSendDT + restPeriod) < runTime: sendCnt = 0
            if not (sendCnt < maxSendCnt) or ((lastSendDT + sendPeriod) > runTime): needSend = False
      if needSend:
#       msg = MIMEText('Ув. абонент! Баланс Вашего л/счета №%s приближается к порогу отключения.' % aid,'plain','utf-8')
#        print(fromAddr, [toAddr], msg.as_string())
        sendCnt = sendCnt+1
        sent = sent + u"Идентификатор абонента: %s, Лицевой счет: %s Полное имя: %s , Баланс: %s\n" % (uid,aid,uname,balance)
        # if lastSendId:
        #   # c.execute("UPDATE user_additional_params SET value = CONCAT(%s,':',%s) WHERE id = %s",(sendCnt,newLastSend,lastSendId))
        # else:
        #    # c.execute("INSERT INTO user_additional_params (paramid,userid,value) VALUES "
        #    #           "((SELECT paramid FROM uaddparams_desc WHERE name = 'sms_sended'),%s,CONCAT(%s,':',%s))",
        #    #  (uid,sendCnt,newLastSend))
        db.commit()


if __name__ == '__main__': main()
