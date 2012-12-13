#coding=utf-8
"""
    urfa constants and helpful functions
"""
import time
import simplejson

now = lambda: int(time.time())
pp = lambda obj: simplejson.dumps(obj, indent=2, ensure_ascii=False)
unixtime = lambda date, fmt='%Y-%m-%d %H:%M:%S': int(time.mktime(time.strptime(date, fmt)))
humantime = lambda timestamp, fmt='%Y-%m-%d %H:%M:%S': time.strftime(fmt, time.localtime(int(timestamp)))

# 2033-05-18 03:33:20 GMT
max_time = 2000000000

# URFA constants
U_PORT          = 11758
U_VER           = 35
U_PCK_INIT      = 192
U_PKT_REQ       = 193
U_PKT_ACCEPT    = 194
U_PKT_REJECT    = 195
U_PKT_DATA      = 200
U_PKT_CALL      = 201
U_PKT_TERM      = 203
U_H_LEN         = 4
U_CODE_DATA         = 5
U_CODE_ATTR_SID     = 6
U_CODE_ATTR_LGN     = 2
U_CODE_ATTR_LGN_T   = 1
U_CODE_ATTR_DGS     = 8
U_CODE_ATTR_HSH     = 9
U_CODE_ATTR_SSL     = 10
U_CODE_ATTR_FN      = 3
U_CODE_ATTR_EOF     = 4
U_ERR_ILLG_FN       = 3
U_ERR_NOT_PERM      = 7
U_LGN_USR   = 0
U_LGN_SYS   = 1
U_LGN_CRD   = 2
U_SSLT_NONE     = 0
U_SSLT_TLS1     = 1
U_SSLT_SSL3     = 2
U_SSLT_CRT      = 3
U_SSLT_RSACRT   = 4
U_TP_S      = 'string'
U_TP_I      = 'integer'
U_LEN_I     = 8
U_TP_D      = 'double'
U_LEN_D     = 12
U_TP_L      = 'long'
U_LEN_L     = 12
U_TP_IP     = 'ip_address'
U_LEN_IP    = 8

# is_blocked flags
#Below are the possible blocking types: Type Meaning
#0 Account is not blocked
#16 System blocking
#48      \
#80      |  System blocking (deprecated flags)
#112    /
#256 Administrative blocking
#768     \
#1280    | Administrative blocking (deprecated flags)
#1792    /
#4112 System blocking on quota
#4144   \
#4176    | System blocking (deprecated flags)
#4208    /
U_BL_NONE           = 0x0
U_BL_SYS            = 0x10
U_BL_SYS_REC_AB     = 0x20
U_BL_SYS_REC_PAY    = 0x40

U_BL_MAN            = 0x100
U_BL_MAN_REC_AB     = 0x200
U_BL_MAN_REC_PAY    = 0x400

U_CRITERIAS = (
    None,       # 0
    'like',     # 1
    None,       # 2
    '=',        # 3
    '<>',       # 4
    None,       # 5
    None,       # 6
    '>',        # 7
    '<',        # 8
    '>=',       # 9
    '<=',       # 10
    'not like'  # 11
)

U_SEL_T = (
    'and',  # 0
    'or'    # 1
)

#"field_name"
U_USRS_F = (
    None,                   #   0
    'user_id',              #   1
    'user_login',           #   2
    'user_account',         #   3
    'acc_period_id',        #   4   *
    'fullname',             #   5
    'create_date',          #   6   *
    'last_change_date',     #   7   *
    'who_create',           #   8   *
    'who_change',           #   9   *
    'is_jur_address',       #   10  *
    'jur_address',          #   11  *
    'actual_address',       #   12  *
    'work_phone',           #   13  *
    'home_phone',           #   14  *
    'mobile_phone',         #   15  *
    'web_page',             #   16  *
    'icq_uin',              #   17  *
    'tax_number',           #   18  *
    'kpp_number',           #   19  *
    None,                   #   20
    'house_id',             #   21  *
    'flat_number',          #   22  *
    'entrance',             #   23  *
    'floor',                #   24  *
    'email',                #   25  *
    'passport',             #   26  *
    None,                   #   27
    'ip',                   #   28
    None,                   #   29
    'group_id',             #   30
    'balance',              #   31
    'personal_manager',     #   32
    'connect_date',         #   33
    'comments',             #   34
    'internet_status',      #   35
    'tariff_id',            #   36
    'service_id',           #   37
    'slink_id',             #   38
    'tplink_id',            #   39
    'district',             #   40  *
    'building',             #   41  *
    'mac',                  #   42
    'slink_login',          #   43
    'external_id'           #   44  *
)

U_CONTACT_BOSS = (
    None,   # 0
    'CEO',  # 1
    'BKR',  # 2
)

U_SRVC_T = (
    None,           # 0
    'once',         # 1
    'periodic',     # 2
    'iptraffic',    # 3
    'hotspot',      # 4
    'dialup',       # 5
    'voice'         # 6
)

U_TRAF_LOC_POLICY = (
    'to_reciever',  # 0
    'to_sender',    # 1
    'both',         # 2
)

U_DP_PERIOD_T = (
    None,           # 0
    'daily',        # 1
    'weekly',       # 2
    'monthly',      # 3
    'quarterly',    # 4
    'yearly'        # 5
)
U_DP_CUSTOM_PERIOD = 0x100000

U_REP_TRAF_TPS = (
    None,           # 0
    'by_hours',     # 1
    'by_days',      # 2
    'by_months',    # 3
    'by_ip'         # 4
)

U_CHRG_M = (
    None,               # 0
    'at_period_start',  # 1
    'at_period_end',    # 2
    'flow'              # 3
)

U_RCVR_T = (
    'user',             # 0
    'user_group',       # 1
    'sys_user',         # 2
    'sys_user_group',   # 3
    'all'               # 4
)

U_MSG_FLGS = {
    'unreaded'  : 0b00001,
    'answered'  : 0b00010,
    'forwarded' : 0b00100,
    'important' : 0b01000,
    'deleted'   : 0b10000
}

U_EVENTS_T = {
    'None'                  : 0x00000000,
    'internet_on'           : 0x00000001,
    'internet_off'          : 0x00000002,
    'block_type_changed'    : 0x00000020,
    'user_added'            : 0x00000040,
    'user_modifed'          : 0x00000080,
    'user_deleted'          : 0x00000100,
    'tparam_added'          : 0x00000200,
    'tparam_modifed'        : 0x00000400,
    'tparam_deleted'        : 0x00000800,
    'tplink_added'          : 0x00001000,
    'tplink_modifed'        : 0x00002000,
    'tplink_deleted'        : 0x00004000,
    'raw_traf_file_closed'  : 0x00008000,
    'log_file_closed'       : 0x00010000,
    'hotspot_enabled '      : 0x00020000,
    'hotspot_disabled'      : 0x00040000,
    'session_opened'        : 0x00080000,
    'session_closed'        : 0x00100000,
    'set_bw_limit_in'       : 0x00200000,
    'edit_bw_limit_in'      : 0x00400000,
    'del_bw_limit_in'       : 0x00800000,
    'set_bw_limit_out'      : 0x01000000,
    'edit_bw_limit_out'     : 0x02000000,
    'del_bw_limit_out'      : 0x04000000,
    'balance_notif_sent'    : 0x40000000
}

U_DSH_APPLY = (
    'None',     # 0
    'VPN',      # 1
    'non-VPN',  # 2
    'both'      # 3
)