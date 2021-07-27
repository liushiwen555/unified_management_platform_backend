# -*- coding: utf-8 -*-
# @Author: JanKin Cai
# @Date:   2018-06-27 16:59:55
# @Last Modified by:   caizhengxin16@163.com
# @Last Modified time: 2018-07-02 18:28:23

# 登录
from django.conf import settings

PREFIX = 'api'
SERVER_PORT = '443'

LOGIN_URL_PATH = 'checkUser'

# 基础防火墙
NEW_FIRE_RULE_PATH = 'NewFiveTupleRule'
CHECK_FIRE_RULE_PATH = 'CheckFiveTupleRuleIDValid'
ENABLE_FIRE_RULE_PATH = 'EnableOneFiveTupleRule'
DISABLE_FIRE_RULE_PATH = 'DisableOneFiveTupleByID'
DEL_FIRE_RULE_PATH = 'DelOneFiveTupleByID'
ENABLE_FIRE_RULES_PATH = 'EnableSomeFiveTupleRules'
DISABLE_FIRE_RULES_PATH = 'DisableSomeFiveTupleRules'
CHECK_FIRE_RULES_DISABLED_PATH = 'CheckFiveTupleRulesDisabled'
DEL_FIRE_RULES_PATH = 'DelSomeFiveTupleRules'
GET_FIRE_RULE_DETAIL_PATH = 'GetOneFiveTupleRuleDetail'
GET_FIRE_RULES_PATH = 'FindFiveTupleRules'


# 白名单
NEW_WHITE_LIST_RULE_PATH = 'NewWhiteListRule'
CHECK_WHITE_LIST_RULE_PATH = 'CheckWhiteListRuleIDValid'
ENABLE_WHITE_LIST_RULES_PATH = 'EnableWhiteListRules'
DISABLE_WHITE_LIST_RULES_PATH = 'DisableSomeWhiteListRules'
DEL_WHITE_LIST_RULES_PATH = 'DelSomeWhiteListRules'
CHECK_WHITE_LIST_RULES_DISABLE_PATH = 'CheckWhiteListRulesDisabled'
GET_ALL_DISABLED_RULES_PATH = 'GetAllDisabledRules'
GET_ALL_ENABLED_RULES_PATH = 'GetAllEnabledRules'
FIND_ALL_RULES_PATH = 'FindWhiteListRules'
DISABLED_ALL_RULES_PATH = 'DisableAllRules'
GET_ALL_ENABLED_COUNT = 'GetEnableRulesCount'

# 连接管理
CHECK_SESSION_RULE_PATH = 'CheckSessionPolicyValid'
NEW_SESSION_RULE_PATH = 'NewSessionPolicy'
FIND_SESSION_RULES_PATH = 'FindSessionPolicies'
DEL_SESSION_RULES_PATH = 'DelSomeSessionPolicies'

# 策略日志
GET_STRA_LOG_PATH = 'straLogRes'
FILTER_STRA_LOG_PATH = 'straLogSearch'
DEL_STRA_LOG_PATH = 'straLogDelete'
EXPORT_STRA_LOG_PATH = 'straLogExportData'
CLEAR_STRA_LOG_PATH = 'straLogClear'

# 策略配置

GET_RUN_MODEL_PATH = 'GetRunMode'
GET_DEFAULT_STATUS_PATH = 'GetPacketFilterDefaultAction'
GET_DPI_STATUS_PATH = 'GetDefaultToDPI'
SET_RUN_MODEL_PATH = 'SetRunMode'
SET_DEFAULT_STATUS_PATH = 'SetPacketFilterDefaultAction'
SET_DPI_STATUS_PATH = 'SetDefaultToDPI'

# 协议默认策略配置

GET_OPC_STATUS_PATH = 'GetOpcDefaultAction'
GET_MODBUS_STATUS_PATH = 'GetModbusDefaultAction'
SET_OPC_STATUS_PATH = 'SetOpcDefaultAction'
SET_MODBUS_STATUS_PATH = 'SetModbusDefaultAction'

# 协议自定义策略配置

GET_OPC_DA_WR_PATH = 'getOpcda'
SET_OPC_DA_WR_PATH = 'setOpcda'

CHECK_MODBUS_RULE = 'ModbusCheckRuleIDExist'
ADD_MODBUS_RULE = 'ModbusAddNewRule'
GET_MODBUS_RULES = 'ModbusGetAllRules'
GET_DISABLE_MODBUS_RULES = 'ModbusGetAllDisableRules'
GET_ENABLE_MODBUS_RULES = 'ModbusGetAllEnableRules'

ENABLE_MODBUS_RULES = 'ModbusEnableSomeRules'
DISABLE_MODBUS_RULES = 'ModbusDisableSomeRules'

DISABLE_ALL_MODBUS_RULES = 'ModbusDisableAllRules'

CHECK_MODSUB_RULES = 'ModbusCheckRulesDisabled'
DEL_MODBUS_RULES = 'ModbusDelSomeRules'


GET_S7_ALL_RULES = 'S7GetAllRules'
ENABLE_S7_RULES = 'S7EnableSomeRules'
DISABLE_S7_RULES = 'S7DisableSomeRules'

DISABLE_ALL_S7_RULES = 'S7DisableAllRules'

DEL_S7_RULES = 'S7DelSomeRules'



# 批量操作策略相关api

GET_ALL_FIVE_TUPLE_RULE_IDS = 'GetAllFivetupleRulesIDs'
ADD_SOME_FIVE_TUPLE_RULES = 'AddSomeFiveTupleRules'

GET_ALL_WHITELIST_RULE_IDS = 'GetAllUserDefWhitelistRulesIDs'
ADD_SOME_WHITELIST_RULES = 'AddSomeWhiteListRules'


LEARNED_WHITELIST_START_LEARN = 'whiteliststartstudy'
LEARNED_WHITELIST_STOP_LEARN = 'whiteliststopstudy'
LEARNED_WHITELIST_ACTIVATION_OR_DELETE = 'whitelistDeploy'
LEARNED_WHITELIST_ACTION = 'whitelistUpdate'
LEARNED_WHITELIST_ALL_ACTION = 'whitelistSetAll'
LEARNED_WHITELIST_BATCH_ACTION = 'whitelistBatchAction'


GET_ALL_BLACKLIST_IDS = 'getAllBlacklist'
BLACKLIST_SET_ALL_ACTION = 'blacklistSetAll'
BLACKLIST_SET_ACTION = 'blacklistUpdate'
BLACKLIST_SET_BATCH_ACTION = 'blacklistBatchAction'
BLACKLIST_CLEAR = 'blacklistClear'
ACTIVATE_SOME_BLACKLIST = 'startSomeBlacklist'

GET_ALL_IP_MAC_IDS = 'getAllIPMACList'
ADD_SOME_IP_MAC = 'AddSomeIPMACRules'
ADD_IP_MAC = 'addIpMac'
IP_MAC_EXTRA_AREA_IP = 'IPMACExtraAreaIp'
START_SOME_IP_MAC = 'startSomeIpMac'
DELETE_SOME_IP_MAC = 'deleteIpMac'
GET_IP_MAC_ID_FROM_IP = 'getIdfromIP'
CLEAR_ALL_IP_MAC = 'clearAllIpMac'

GET_ALL_MODBUS_IDS = 'GetAllModbusRulesIDs'
ADD_SOME_MODBUS_RULES = 'AddSomeModbusRules'
GET_ALL_S7_IDS = 'GetAllS7RulesIDs'
ADD_SOME_S7_RULES = 'AddSomeS7Rules'

UN_REGISTER = 'platform/unregister'
REBOOT = 'rebootDpi'
HEART_BEAT = 'keepalive'


def get_full_url(ip, url):
    return '{}://{}:{}/{}/{}'.format(settings.FIREWALL_SCHEME, ip, settings.FIREWALL_PORT, PREFIX, url)
