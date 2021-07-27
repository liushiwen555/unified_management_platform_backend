import json as json_util

import requests
from django.conf import settings
from django.shortcuts import get_object_or_404
from requests.exceptions import RequestException
from rest_framework import status

from base_app.models import Device
from firewall import api_path_constants
from firewall.api_path_constants import get_full_url
from firewall.models import BaseFirewallStrategy, STATUS_ENABLE, FirewallWhiteListStrategy, \
    IndustryProtocolDefaultConfStrategy, ConfStrategy, IndustryProtocolOPCStrategy, IndustryProtocolModbusStrategy, \
    IndustryProtocolS7Strategy, FirewallIPMACBondStrategy, FirewallLearnedWhiteListStrategy, \
    FirewallIPMACUnknownDeviceActionStrategy, FirewallBlackListStrategy
from firewall.serializers import BaseFirewallStrategyApplySerializer, FirewallWhiteListStrategyApplySerializer, \
    IndustryProtocolModbusStrategyApplySerializer, IndustryProtocolS7StrategyApplySerializer, \
    FirewallIPMACBondStrategyApplySerializer, ConfStrategySerializer, IndustryProtocolDefaultConfStrategySerializer, \
    IndustryProtocolOPCStrategySerializer
from utils.core.exceptions import CustomError, FirewallError
from utils.helper import get_int_choices_range

STATUS = 'status'
NO_CHECK = 0
STATUS_CHECK = 1
RANGE_CHECK = 2
SUCCESS_CHECK = 3
FIREWALL_WHITELIST_LEARNING_ERROR_STATUS = 2
FIREWALL_WHITELIST_DELETING_ACTIVE_ITEM_ERROR_STATUS = 3


class FirewallRequests:

    def __init__(self, firewall, verify=False):

        self.firewall = firewall
        self.verify = verify
        self.session = requests.session()
        self._login()

    def post(self, url, data=None, json=None, valid_status=0, check=STATUS_CHECK, **kwargs):
        if kwargs.get('verify', None) is None:
            kwargs.update({'verify': self.verify})
        resp = self.session.post(get_full_url(self.firewall.ip, url), data, json, **kwargs)
        self._check_status(resp, valid_status, check, **kwargs)
        resp_json = json_util.loads(resp.json()) if isinstance(resp.json(), str) else resp.json()
        return resp_json

    def get(self, url, valid_status=0, check=STATUS_CHECK, **kwargs):
        if kwargs.get('verify', None) is None:
            kwargs.update({'verify': self.verify})
        resp = self.session.get(get_full_url(self.firewall.ip, url), **kwargs)
        self._check_status(resp, valid_status, check, **kwargs)
        resp_json = json_util.loads(resp.json()) if isinstance(resp.json(), str) else resp.json()
        return resp_json

    def set_run_mode(self, running_mode, **kwargs):
        payload = {'runningMode': str(running_mode)}
        self.post(api_path_constants.SET_RUN_MODEL_PATH, json=payload, check=RANGE_CHECK, **kwargs)

    def set_packet_filter_default_action(self, action, **kwargs):
        payload = {'action': action}
        self.post(api_path_constants.SET_DEFAULT_STATUS_PATH, json=payload, check=RANGE_CHECK, **kwargs)

    def set_default_to_dpi(self, action, **kwargs):
        payload = {'action': action}
        self.post(api_path_constants.SET_DPI_STATUS_PATH, json=payload, check=RANGE_CHECK, **kwargs)

    # 获取策略设置的三个接口
    def get_run_mode(self, **kwargs):
        return self.get(api_path_constants.GET_RUN_MODEL_PATH, check=NO_CHECK, **kwargs)

    def get_packet_filter_default_action(self, **kwargs):
        return self.get(api_path_constants.GET_DEFAULT_STATUS_PATH, check=NO_CHECK, **kwargs)

    def get_default_to_dpi(self, **kwargs):
        return self.get(api_path_constants.GET_DPI_STATUS_PATH, check=NO_CHECK, **kwargs)

    def get_all_base_firewall_rule_ids(self, **kwargs):
        return self.get(api_path_constants.GET_ALL_FIVE_TUPLE_RULE_IDS, check=False, **kwargs)

    def get_all_base_firewall_rules(self, **kwargs):
        return self.get(api_path_constants.GET_FIRE_RULES_PATH, check=NO_CHECK, **kwargs)

    def disable_some_base_firewall_rules(self, rule_ids, **kwargs):
        payload = {'ruleIDs': rule_ids}
        return self.post(api_path_constants.DISABLE_FIRE_RULES_PATH, json=payload, **kwargs)

    def enable_some_base_firewall_rules(self, rule_ids, **kwargs):
        payload = {'ruleIDs': rule_ids}
        return self.post(api_path_constants.ENABLE_FIRE_RULES_PATH, json=payload, **kwargs)

    def del_some_base_firewall_rules(self, rule_ids, **kwargs):
        payload = {'ruleIDs': rule_ids}
        return self.post(api_path_constants.DEL_FIRE_RULES_PATH, json=payload, **kwargs)

    def add_some_base_firewall_rules(self, rules_list, **kwargs):
        payload = {'rules_list': rules_list}
        return self.post(api_path_constants.ADD_SOME_FIVE_TUPLE_RULES, check=RANGE_CHECK, json=payload, **kwargs)

    def get_all_whitelist_rule_ids(self, **kwargs):
        return self.get(api_path_constants.GET_ALL_WHITELIST_RULE_IDS, check=NO_CHECK, **kwargs)

    def get_all_whitelist_rules(self, **kwargs):
        return self.get(api_path_constants.FIND_ALL_RULES_PATH, check=NO_CHECK, **kwargs)

    def disable_some_whitelist_rules(self, rule_ids, **kwargs):
        payload = {'ruleIDs': rule_ids}
        return self.post(api_path_constants.DISABLE_WHITE_LIST_RULES_PATH, json=payload, **kwargs)

    def enable_some_whitelist_rules(self, rule_ids, **kwargs):
        if len(rule_ids) == 0:
            return
        payload = {'ruleIDs': rule_ids}
        return self.post(api_path_constants.ENABLE_WHITE_LIST_RULES_PATH, json=payload, **kwargs)

    def del_some_whitelist_rules(self, rule_ids, **kwargs):
        payload = {'ruleIDs': rule_ids}
        return self.post(api_path_constants.DEL_WHITE_LIST_RULES_PATH, json=payload, **kwargs)

    def add_some_whitelist_rules(self, rules_list, **kwargs):
        payload = {'rules_list': rules_list}
        return self.post(api_path_constants.ADD_SOME_WHITELIST_RULES, json=payload, check=RANGE_CHECK, **kwargs)

    def learned_whitelist_start_learn(self, payload, **kwargs):
        return self.post(api_path_constants.LEARNED_WHITELIST_START_LEARN, json=payload, valid_status=1, **kwargs)

    def learned_whitelist_stop_learn(self, **kwargs):
        return self.get(api_path_constants.LEARNED_WHITELIST_STOP_LEARN, valid_status=1, **kwargs)

    def learned_whitelist_action(self, sid, action, **kwargs):
        payload = {'sid': sid, 'action': action}
        return self.get(api_path_constants.LEARNED_WHITELIST_ACTION, params=payload, valid_status=1, **kwargs)

    def learned_whitelist_all_action(self, action, **kwargs):
        payload = {'action': action}
        return self.get(api_path_constants.LEARNED_WHITELIST_ALL_ACTION, params=payload, valid_status=1, **kwargs)

    def learned_whitelist_batch_action(self, action, sid_list, **kwargs):
        payload = {'action': action, 'sids': ','.join(list(map(str, sid_list)))}
        return self.post(api_path_constants.LEARNED_WHITELIST_BATCH_ACTION, json=payload, valid_status=1, **kwargs)

    def learned_whitelist_deploy_or_clear(self, _status, sid_list, **kwargs):
        # status 1 means deploy or clear deploy, deploy needs sids, clear deploy does not need sids, it clears all
        # status 0 means delete items, needs sids
        payload = {'status': _status, 'sids': ','.join(list(map(str, sid_list)))}
        return self.post(api_path_constants.LEARNED_WHITELIST_ACTIVATION_OR_DELETE, json=payload, valid_status=1,
                         **kwargs)

    def learned_whitelist_deploy(self, sid_list, **kwargs):
        return self.learned_whitelist_deploy_or_clear(1, sid_list, **kwargs)

    def learned_whitelist_un_deploy(self, **kwargs):
        return self.learned_whitelist_deploy_or_clear(1, [], **kwargs)

    def learned_whitelist_delete(self, sid_list, **kwargs):
        return self.learned_whitelist_deploy_or_clear(0, sid_list, **kwargs)

    def set_opc_status(self, action, **kwargs):
        payload = {'action': str(action)}
        return self.post(api_path_constants.SET_OPC_STATUS_PATH, json=payload, check=RANGE_CHECK, **kwargs)

    # get opc 与 modbus 的状态
    def get_opc_status(self, **kwargs):
        return self.get(api_path_constants.GET_OPC_STATUS_PATH, check=NO_CHECK, **kwargs)

    def set_modbus_status(self, action, **kwargs):
        payload = {'action': str(action)}
        return self.post(api_path_constants.SET_MODBUS_STATUS_PATH, json=payload, check=RANGE_CHECK, **kwargs)

    def get_modbus_status(self, action, **kwargs):
        return self.get(api_path_constants.GET_MODBUS_STATUS_PATH, check=NO_CHECK, **kwargs)

    def set_opcda_wr(self, is_read_open, read_action, is_write_open, write_action, **kwargs):
        payload = {
            'read': {
                'action': read_action,
                'isOpen': is_read_open
            },
            'write': {
                'action': write_action,
                'isOpen': is_write_open
            }
        }
        return self.post(api_path_constants.SET_OPC_DA_WR_PATH, json=payload, valid_status=1, **kwargs)

    def get_opcda_wr(self, **kwargs):
        return self.get(api_path_constants.GET_OPC_DA_WR_PATH, check=NO_CHECK, **kwargs)

    def get_all_modbus_rule_ids(self, **kwargs):
        return self.get(api_path_constants.GET_ALL_MODBUS_IDS, check=NO_CHECK, **kwargs)

    def get_all_modbus_rules(self, **kwargs):
        return self.get(api_path_constants.GET_MODBUS_RULES, check=NO_CHECK, **kwargs)

    def disable_some_modbus_rules(self, rule_ids, **kwargs):
        payload = {'ruleids': rule_ids}
        return self.post(api_path_constants.DISABLE_MODBUS_RULES, json=payload, **kwargs)

    def disable_all_modbus_rules(self, **kwargs):
        return self.post(api_path_constants.DISABLE_ALL_MODBUS_RULES, **kwargs)

    def enable_some_modbus_rules(self, rule_ids, **kwargs):
        if len(rule_ids) == 0:
            return
        payload = {'ruleids': rule_ids}
        return self.post(api_path_constants.ENABLE_MODBUS_RULES, json=payload, **kwargs)

    def del_some_modbus_rules(self, rule_ids, **kwargs):
        payload = {'ruleids': rule_ids}
        return self.post(api_path_constants.DEL_MODBUS_RULES, json=payload, **kwargs)

    def add_some_modbus_rules(self, rules_list, **kwargs):
        payload = {'rules_list': rules_list}
        return self.post(api_path_constants.ADD_SOME_MODBUS_RULES, json=payload, check=RANGE_CHECK, **kwargs)

    def get_all_s7_rule_ids(self, **kwargs):
        return self.get(api_path_constants.GET_ALL_S7_IDS, check=NO_CHECK, **kwargs)

    def get_all_s7_rules(self, **kwargs):
        return self.get(api_path_constants.GET_S7_ALL_RULES, check=NO_CHECK, **kwargs)

    def disable_some_s7_rules(self, rule_ids, **kwargs):
        payload = {'ruleids': rule_ids}
        return self.post(api_path_constants.DISABLE_S7_RULES, json=payload, **kwargs)

    def disable_all_s7_rules(self, **kwargs):
        return self.post(api_path_constants.DISABLE_ALL_S7_RULES, **kwargs)

    def enable_some_s7_rules(self, rule_ids, **kwargs):
        if len(rule_ids) == 0:
            return
        payload = {'ruleids': rule_ids}
        return self.post(api_path_constants.ENABLE_S7_RULES, json=payload, **kwargs)

    def del_some_s7_rules(self, rule_ids, **kwargs):
        payload = {'ruleids': rule_ids}
        return self.post(api_path_constants.DEL_S7_RULES, json=payload, **kwargs)

    def add_some_s7_rules(self, rules_list, **kwargs):
        payload = {'rules_list': rules_list}
        return self.post(api_path_constants.ADD_SOME_S7_RULES, json=payload, check=RANGE_CHECK, **kwargs)

    def get_all_ip_mac_rule_ids(self, **kwargs):
        return self.get(api_path_constants.GET_ALL_IP_MAC_IDS, check=NO_CHECK, **kwargs)['ipmaclist']

    def deploy_or_clear_some_ip_mac(self, id_list, rule_status, action, **kwargs):

        # status 1 means deploy, 0 means clear all rules
        ids = ','.join(list(map(str, id_list)))
        payload = {'ids': ids, 'status': rule_status, 'action': action}
        return self.get(api_path_constants.START_SOME_IP_MAC, params=payload, valid_status=1, **kwargs)

    def deploy_some_ip_mac(self, id_list, action, **kwargs):

        # status 1 means deploy, 0 means clear all rules
        return self.deploy_or_clear_some_ip_mac(id_list, 1, action, **kwargs)

    def clear_ip_mac(self, action, **kwargs):

        # status 1 means deploy, 0 means clear all rules
        return self.deploy_or_clear_some_ip_mac([], 0, action, **kwargs)

    def del_some_ip_mac(self, id_list, **kwargs):
        payload = {'ids': ','.join(list(map(str, id_list)))}
        return self.get(api_path_constants.DELETE_SOME_IP_MAC, params=payload, valid_status=1, **kwargs)

    def get_ip_mac_id_list_from_ip(self, ip_list, **kwargs):
        payload = {'ip_list': ip_list}
        return self.post(api_path_constants.GET_IP_MAC_ID_FROM_IP, check=NO_CHECK, json=payload, **kwargs)

    def add_some_ip_mac(self, rules_list, **kwargs):
        payload = {'rules_list': rules_list}
        return self.post(api_path_constants.ADD_SOME_IP_MAC, json=payload, **kwargs)

    def clear_all_ip_mac(self, **kwargs):
        return self.get(api_path_constants.CLEAR_ALL_IP_MAC, valid_status=1, **kwargs)

    def unknown_device_ip_mac_action(self, action, **kwargs):
        payload = {'action': action}
        return self.get(api_path_constants.IP_MAC_EXTRA_AREA_IP, params=payload, valid_status=1, **kwargs)

    def get_all_blacklist_ids(self, **kwargs):
        return self.get(api_path_constants.GET_ALL_BLACKLIST_IDS, check=NO_CHECK, **kwargs)['blacklist']

    def blacklist_all_action(self, action, **kwargs):
        payload = {'action': action}
        return self.get(api_path_constants.BLACKLIST_SET_ALL_ACTION, params=payload, valid_status=1, **kwargs)

    def blacklist_action(self, sid, action, **kwargs):
        payload = {'sid': sid, 'action': action}
        return self.post(api_path_constants.BLACKLIST_SET_ACTION, json=payload, valid_status=1, **kwargs)

    def blacklist_batch_action(self, action, sid_list, **kwargs):
        payload = {'action': action, 'sids': ','.join(list(map(str, sid_list)))}
        return self.post(api_path_constants.BLACKLIST_SET_BATCH_ACTION, json=payload, valid_status=1, **kwargs)

    def clear_all_blacklist(self, **kwargs):
        return self.get(api_path_constants.BLACKLIST_CLEAR, valid_status=1, **kwargs)

    def blacklist_batch_enable(self, sid_list, **kwargs):
        payload = {'sids': ','.join(list(map(str, sid_list)))}
        return self.post(api_path_constants.ACTIVATE_SOME_BLACKLIST, json=payload, valid_status=1, **kwargs)

    def reboot(self, **kwargs):
        return self.get(api_path_constants.REBOOT, valid_status=1, **kwargs)

    def un_register(self, **kwargs):
        return self.get(api_path_constants.UN_REGISTER, check=SUCCESS_CHECK, **kwargs)

    def heart_beat(self, **kwargs):
        return self.get(api_path_constants.HEART_BEAT, valid_status=1, **kwargs)

    def _login(self, **kwargs):
        self.post(api_path_constants.LOGIN_URL_PATH,
                  data={'username': settings.FIREWALL_INLAY_USER, 'pw': settings.FIREWALL_INLAY_USER_PW},
                  valid_status=2,
                  **kwargs)

    def _check_status(self, resp, valid_status=0, check=STATUS_CHECK, **kwargs):
        """
        :param resp: HTTP response
        :param valid_status: a valid response status
        :param check: NO_CHECK does not check the status,  STATUS_CHECK check if the status == valid_status,
         RANGE_CHECK check if status < 0, SUCCESS_CHECK check if the success in response == True
        :param kwargs: 
        :return: 
        """
        # print(resp)
        # print(resp.text)
        # first,check http status
        if not status.is_success(resp.status_code):
            raise CustomError({'error': CustomError.FIREWALL_API_FAIL})
        if check == NO_CHECK:
            return
        resp_json = json_util.loads(resp.json()) if isinstance(resp.json(), str) else resp.json()
        if check == STATUS_CHECK:
            if resp_json.get(STATUS) != valid_status:
                raise FirewallError('firewall api error', resp_json.get(STATUS))
        elif check == RANGE_CHECK:
            if resp_json.get(STATUS) < 0:
                raise FirewallError('firewall api error', resp_json.get(STATUS))
        elif check == SUCCESS_CHECK:
            if not resp_json.get('success'):
                raise FirewallError('firewall api error', resp_json.get(STATUS))


def reboot(serializer):
    firewalls = Device.objects.filter(id__in=serializer.data['dev_ids'], status=Device.ONLINE)
    failed_ids = []
    for firewall in firewalls:
        try:
            request = FirewallRequests(firewall)
            request.reboot()
        except (RequestException, CustomError):
            failed_ids.append(firewall.id)
    if failed_ids:
        raise CustomError({'error': CustomError.BATCH_OPERATION_PART_FAIL, 'failed_ids': failed_ids})


def un_register(serializer):
    firewalls = Device.objects.filter(id__in=serializer.data['dev_ids'], status=Device.ONLINE)
    failed_ids = []
    for firewall in firewalls:
        try:
            request = FirewallRequests(firewall)
            request.un_register()
            firewall.status = Device.NOT_REGISTERED
            firewall.save()
        except (RequestException, CustomError):
            failed_ids.append(firewall.id)
    if failed_ids:
        raise CustomError({'error': CustomError.BATCH_OPERATION_PART_FAIL, 'failed_ids': failed_ids})


def firewall_apply_strategies(firewall: Device):
    request = FirewallRequests(firewall)
    _apply_base_firewall_strategies(request)
    _apply_whitelist_strategies(request)
    _apply_learned_whitelist_strategies(request)
    _apply_conf_strategy(request)
    _apply_default_conf_strategy(request)
    _apply_opc_wr_strategy(request)
    _apply_ip_mac_strategies(request)
    _apply_modbus_strategies(request)
    _apply_s7_strategies(request)
    _apply_blacklist_strategies(request)


def firewall_sync_strategies(firewall: Device):
    # todo 防火墙数据同步到综管函数

    request = FirewallRequests(firewall)
    _sync_base_firewall_strategies(request)
    _sync_whitelist_strategies(request)
    # _sync_learned_whitelist_strategies(request)
    _sync_conf_strategy(request)
    _sync_default_conf_strategy(request)
    _sync_opc_wr_strategy(request)
    # _sync_ip_mac_strategies(request)
    _sync_modbus_strategies(request)
    _sync_s7_strategies(request)
    # _sync_blacklist_strategies(request)



# def change_all_learned_whitelists_activation(device_id, serializer):
#     device = Device.objects.get(id=device_id)
#
#     try:
#         request = FirewallRequests(device)
#         request.learned_whitelist_deploy_or_clear(serializer.data['status'], serializer.data['sids'])
#     except RequestException:
#         raise CustomError({'error': CustomError.LEARNED_WHITELIST_ACTIVATION_FAIL})
#     except FirewallError as e:
#         if e.status == FIREWALL_WHITELIST_LEARNING_ERROR_STATUS:
#             raise CustomError({'error': CustomError.LEARNED_WHITELIST_OPERATION_WHILE_LEARNING})
#         elif e.status == FIREWALL_WHITELIST_DELETING_ACTIVE_ITEM_ERROR_STATUS:
#             raise CustomError({'error': CustomError.LEARNED_WHITELIST_DELETING_ACTIVE_ITEM})


def change_learned_whitelist_action(learned_whitelist, action):
    device = learned_whitelist.device
    try:
        request = FirewallRequests(device)
        request.learned_whitelist_action(learned_whitelist.sid, action)
    except (RequestException, FirewallError):
        raise CustomError({'error': CustomError.FIREWALL_API_FAIL})


def change_all_learned_whitelists_action(device_id, action):
    device = Device.objects.get(id=device_id)
    try:
        request = FirewallRequests(device)
        request.learned_whitelist_all_action(action)
    except (RequestException, FirewallError):
        raise CustomError({'error': CustomError.FIREWALL_API_FAIL})


def whitelist_learn(device_id, serializer):
    device = Device.objects.get(id=device_id)
    try:
        request = FirewallRequests(device)
        request.learned_whitelist_start_learn(serializer.data)
    except RequestException:
        raise CustomError({'error': CustomError.FIREWALL_API_FAIL})


def whitelist_stop_learn(device_id):
    device = Device.objects.get(id=device_id)

    try:
        request = FirewallRequests(device)
        request.learned_whitelist_stop_learn()
    except RequestException:
        raise CustomError({'error': CustomError.FIREWALL_API_FAIL})


def del_all_learned_whitelist(device_id):
    device = Device.objects.get(id=device_id)

    whitelists = FirewallLearnedWhiteListStrategy.objects.filter(device_id=device_id)
    whitelist_sids = [whitelist.sid for whitelist in whitelists]
    if len(whitelist_sids) > 0:
        try:
            request = FirewallRequests(device)
            request.learned_whitelist_un_deploy()
            request.learned_whitelist_delete(whitelist_sids)
        except RequestException:
            raise CustomError({'error': CustomError.FIREWALL_API_FAIL})


def _apply_base_firewall_strategies(request: FirewallRequests):
    """
    disable all rules, then we can delete them, add new ones
    after add new ones, we have to enable them
    :param request: FirewallRequests class
    :return:
    """

    all_firewall_ids_list = request.get_all_base_firewall_rule_ids()
    if len(all_firewall_ids_list) != 0:
        request.disable_some_base_firewall_rules(all_firewall_ids_list)
        request.del_some_base_firewall_rules(all_firewall_ids_list)
    strategies = BaseFirewallStrategy.objects.filter(device_id=request.firewall.id)
    strategy_serializers = BaseFirewallStrategyApplySerializer(strategies, many=True)
    request.add_some_base_firewall_rules(strategy_serializers.data)
    # enabled_rule_ids = _get_rule_attr_list_by_attr_key_value(strategies)
    enabled_rule_ids = [strategy.rule_id for strategy in strategies if strategy.status == STATUS_ENABLE]
    request.enable_some_base_firewall_rules(enabled_rule_ids)


def get_ori_to_normal_dict(name_of_api_dict):
    r = {}

    base_firewall_normal_dict = dict(
        _ruleID='rule_id',
        _ruleName='rule_name',
        _srcIP='src_ip',
        _dstIP='dst_ip',
        _srcPort='src_port',
        _dstPort='dst_port',
        _proto='protocol',
        _action='action',
        _status='status',
        _logging='logging',
    )

    modbus_strategies_normal_dict = dict(
        _action='action',
        _funcCode='func_code',
        _length='length',
        _logging='logging',
        _regEnd='reg_end',
        _regStart='reg_start',
        _regValue='reg_value',
        _ruleID='rule_id',
        _ruleName='rule_name',
        _status='status',
    )

    s7_strategies_normal_dict = dict(
        _action='action',
        _funcType='func_type',
        _pduType='pdu_type',
        _ruleID='rule_id',
        _ruleName='rule_name',
        _status='status',
    )

    whitelist_normal_dict = base_firewall_normal_dict

    r['base_firewall_normal_dict'] = base_firewall_normal_dict
    r['whitelist_normal_dict'] = whitelist_normal_dict
    r['modbus_strategies_normal_dict'] = modbus_strategies_normal_dict
    r['s7_strategies_normal_dict'] = s7_strategies_normal_dict

    ori_to_normal_dict = r.get(name_of_api_dict)

    return ori_to_normal_dict


def transfer_lists(ori_lists, name_of_api):
    r = []
    for ori_dict in ori_lists:
        i_ = transfer_key(ori_dict, name_of_api)
        r.append(i_)
    return r


def transfer_key(ori_dict, name_of_api):

    ori_normal_dict = get_ori_to_normal_dict(name_of_api)

    r = {}
    for k, v in ori_dict.items():
        for k1, v1 in ori_normal_dict.items():
            if k == k1:
                r[v1] = v
    return r


def _sync_base_firewall_strategies(request: FirewallRequests):
    # todo 获取 base_firewall_strategies 策略
    # 需要添加 base_firewall_stratigies 的 device_id 是防火墙 id 的内容
    all_base_firewall_rules = request.get_all_base_firewall_rules()['matchList'] # 这里其实是个列表
    all_base_firewall_rules_unified = transfer_lists(all_base_firewall_rules, 'base_firewall_normal_dict')
    BaseFirewallStrategy.objects.filter(device=request.firewall).delete()

    rs = [BaseFirewallStrategy(**item, device=request.firewall) for item in all_base_firewall_rules_unified]
    BaseFirewallStrategy.objects.bulk_create(rs)
    # serializer = BaseFirewallStrategySerializer(data=all_base_firewall_rules_unified, many=True)
    # serializer.is_valid(raise_exception=True)
    # serializer.save()


def _sync_whitelist_strategies(request: FirewallRequests):
    # todo 获取 whitelist 策略
    # 需要添加 whitelist 的 device_id 是防火墙 id 的内容

    all_whitelist_rules = request.get_all_whitelist_rules()['matchList']
    all_whitelist_rules_unified = transfer_lists(all_whitelist_rules, 'whitelist_normal_dict')
    FirewallWhiteListStrategy.objects.filter(device=request.firewall).delete()

    rs = [FirewallWhiteListStrategy(**item, device=request.firewall) for item in all_whitelist_rules_unified]
    FirewallWhiteListStrategy.objects.bulk_create(rs)


    # serializer = FirewallWhiteListStrategy(data=all_base_firewall_rules_unified)
    # serializer.is_valid(raise_exception=True)
    # serializer.save()


def _sync_conf_strategy(request: FirewallRequests):
    # todo 获取 策略配置的内容

    firewall_run_mode = request.get_run_mode()
    firewall_packet_filter_default_action = request.get_packet_filter_default_action()
    firewall_get_default_to_dpi = request.get_default_to_dpi()

    data = dict(
        run_mode=firewall_run_mode.get('status'),
        default_filter=firewall_packet_filter_default_action.get('status'),
        DPI=firewall_get_default_to_dpi.get('status'),
        device_id=request.firewall.id,
    )

    ConfStrategy.objects.filter(device=request.firewall).delete()

    serializer = ConfStrategySerializer(data=data)
    serializer.is_valid(raise_exception=True)
    serializer.save()
    pass


def _sync_default_conf_strategy(request: FirewallRequests):
    OPC_default_action = request.get_opc_status().get('status')
    modbus_default_action = request.get_modbus_status().get('status')

    data = dict(
        OPC_default_action=OPC_default_action,
        modbus_default_action=modbus_default_action,
        device_id=request.firewall.id,
    )
    IndustryProtocolDefaultConfStrategy.objects.filter(device=request.firewall).delete()

    serializer = IndustryProtocolDefaultConfStrategySerializer(data=data)
    serializer.is_valid(raise_exception=True)
    serializer.save()


def _sync_opc_wr_strategy(request: FirewallRequests):
    res = request.get_opcda_wr()

    is_read_open = res.get('read').get('isOpen')
    read_action = res.get('read').get('action')
    is_write_open = res.get('write').get('isOpen')
    write_action = res.get('write').get('action')

    data = dict(
        is_read_open=is_read_open,
        read_action=read_action,
        is_write_open=is_write_open,
        write_action=write_action,
        device_id=request.firewall.id,
    )

    IndustryProtocolOPCStrategy.objects.filter(device=request.firewall).delete()
    serializer = IndustryProtocolOPCStrategySerializer(data=data)
    serializer.is_valid(raise_exception=True)
    serializer.save()


def _sync_modbus_strategies(request: FirewallRequests):

    # todo 获取 _all_modbus_strategies 策略
    # 需要添加 all_modbus_strategies 的 device_id 是防火墙 id 的内容
    all_modbus_strategies = request.get_all_modbus_rules()['matchList'] # 这里其实是个列表
    all_modbus_strategies_unified = transfer_lists(all_modbus_strategies, 'modbus_strategies_normal_dict')
    IndustryProtocolModbusStrategy.objects.filter(device=request.firewall).delete()

    rs = [IndustryProtocolModbusStrategy(**item, device=request.firewall) for item in all_modbus_strategies_unified]
    IndustryProtocolModbusStrategy.objects.bulk_create(rs)

    # serializer = IndustryProtocolModbusStrategySerializer(data=all_modbus_strategies_unified)
    # serializer.is_valid(raise_exception=True)
    # serializer.save()


def _sync_s7_strategies(request: FirewallRequests):

    # todo 获取 all_s7_strategies 策略
    # 需要添加 all_s7_strategies 的 device_id 是防火墙 id 的内容
    all_s7_strategies = request.get_all_s7_rules()['matchList'] # 这里其实是个列表
    all_s7_strategies_unified = transfer_lists(all_s7_strategies, 's7_strategies_normal_dict')
    IndustryProtocolS7Strategy.objects.filter(device=request.firewall).delete()

    rs = [IndustryProtocolS7Strategy(**item, device=request.firewall) for item in all_s7_strategies_unified]
    IndustryProtocolS7Strategy.objects.bulk_create(rs)

    # serializer = IndustryProtocolS7StrategySerializer(data=all_s7_strategies_unified)
    # serializer.is_valid(raise_exception=True)
    # serializer.save()


def _apply_whitelist_strategies(request: FirewallRequests):
    """
    disable all rules, then we can delete them, add new ones
    after add new ones, we have to enable them
    :param request: FirewallRequests class
    :return:
    """
    all_whitelist_ids_list = request.get_all_whitelist_rule_ids()
    if len(all_whitelist_ids_list) != 0:
        request.disable_some_whitelist_rules(all_whitelist_ids_list)
        request.del_some_whitelist_rules(all_whitelist_ids_list)
    strategies = FirewallWhiteListStrategy.objects.filter(device_id=request.firewall.id)
    strategy_serializers = FirewallWhiteListStrategyApplySerializer(strategies, many=True)
    request.add_some_whitelist_rules(strategy_serializers.data)
    # enabled_rule_ids = _get_rule_attr_list_by_attr_key_value(strategies)
    enabled_rule_ids = [strategy.rule_id for strategy in strategies if strategy.status == STATUS_ENABLE]
    request.enable_some_whitelist_rules(enabled_rule_ids)


def _apply_learned_whitelist_strategies(request: FirewallRequests):
    whitelists = FirewallLearnedWhiteListStrategy.objects.filter(device_id=request.firewall.id)
    low, high = get_int_choices_range(FirewallLearnedWhiteListStrategy.LEARNED_WHITELIST_ACTION_CHOICES)
    for action in range(low, high + 1):
        sid_list = [whitelist.sid for whitelist in whitelists if whitelist.action == action]
        request.learned_whitelist_batch_action(action, sid_list)
    whitelist_sids = [whitelist.sid for whitelist in whitelists if whitelist.status == STATUS_ENABLE]
    request.learned_whitelist_deploy(whitelist_sids)


def _apply_conf_strategy(request: FirewallRequests):
    conf_strategy = get_object_or_404(ConfStrategy, device_id=request.firewall.id)
    request.set_run_mode(conf_strategy.run_mode)
    request.set_packet_filter_default_action(conf_strategy.default_filter)
    request.set_default_to_dpi(conf_strategy.DPI)


def _apply_default_conf_strategy(request: FirewallRequests):
    default_conf = get_object_or_404(IndustryProtocolDefaultConfStrategy, device_id=request.firewall.id)
    request.set_opc_status(default_conf.OPC_default_action)
    request.set_modbus_status(default_conf.modbus_default_action)


def _apply_opc_wr_strategy(request: FirewallRequests):
    opc = get_object_or_404(IndustryProtocolOPCStrategy, device_id=request.firewall.id)
    request.set_opcda_wr(opc.is_read_open, opc.read_action, opc.is_write_open, opc.write_action)


def _apply_modbus_strategies(request: FirewallRequests):
    """
        disable all rules, then we can delete them, add new ones
        after add new ones, we have to enable them
        :param request: FirewallRequests class
        :return:
        """
    all_modbus_ids_list = request.get_all_modbus_rule_ids()
    if len(all_modbus_ids_list) != 0:
        request.disable_some_modbus_rules(all_modbus_ids_list)
        request.del_some_modbus_rules(all_modbus_ids_list)
    strategies = IndustryProtocolModbusStrategy.objects.filter(device_id=request.firewall.id)
    strategy_serializers = IndustryProtocolModbusStrategyApplySerializer(strategies, many=True)
    request.add_some_modbus_rules(strategy_serializers.data)
    enabled_rule_ids = [strategy.rule_id for strategy in strategies if strategy.status == STATUS_ENABLE]
    request.enable_some_modbus_rules(enabled_rule_ids)


def _apply_s7_strategies(request: FirewallRequests):
    """
        disable all rules, then we can delete them, add new ones
        after add new ones, we have to enable them
        :param request: FirewallRequests class
        :return:
        """
    all_s7_ids_list = request.get_all_s7_rule_ids()
    if len(all_s7_ids_list) != 0:
        request.disable_some_s7_rules(all_s7_ids_list)
        request.del_some_s7_rules(all_s7_ids_list)
    strategies = IndustryProtocolS7Strategy.objects.filter(device_id=request.firewall.id)
    strategy_serializers = IndustryProtocolS7StrategyApplySerializer(strategies, many=True)
    request.add_some_s7_rules(strategy_serializers.data)
    enabled_rule_ids = [strategy.rule_id for strategy in strategies if strategy.status == STATUS_ENABLE]
    request.enable_some_s7_rules(enabled_rule_ids)


def _apply_ip_mac_strategies(request: FirewallRequests):
    """
        disable all rules, then we can delete them, add new ones
        after add new ones, we have to enable them
        :param request: FirewallRequests class
        :return:
        """
    all_ip_mac_ids_list = request.get_all_ip_mac_rule_ids()
    if len(all_ip_mac_ids_list) != 0:
        request.clear_ip_mac(FirewallIPMACBondStrategy.ACTION_PASS)
        request.del_some_ip_mac(all_ip_mac_ids_list)
    # request.clear_all_ip_mac()
    strategies = FirewallIPMACBondStrategy.objects.filter(device_id=request.firewall.id)
    if len(strategies) != 0:
        strategy_serializers = FirewallIPMACBondStrategyApplySerializer(strategies, many=True)
        request.add_some_ip_mac(strategy_serializers.data)
        enabled_rule_ip_list = [strategy.ip for strategy in strategies if strategy.status == STATUS_ENABLE]
        if len(enabled_rule_ip_list) != 0:
            ip_mac_id_map_list = request.get_ip_mac_id_list_from_ip(enabled_rule_ip_list)
            ip_mac_id_list = [item['ipmac_id'] for item in ip_mac_id_map_list]
            request.deploy_some_ip_mac(ip_mac_id_list, strategies[0].action)

    unknown_action = FirewallIPMACUnknownDeviceActionStrategy.objects.get(device_id=request.firewall.id)
    request.unknown_device_ip_mac_action(unknown_action.action)


def _apply_blacklist_strategies(request: FirewallRequests):
    """
        change action, then enable them
        :param request: FirewallRequests class
        :return:
        """

    low, high = get_int_choices_range(FirewallBlackListStrategy.EVENT_PROCESS_CHOICES)
    strategies = FirewallBlackListStrategy.objects.filter(device_id=request.firewall.id)
    for action in range(low, high+1):
        sid_list = [strategy.feature_code for strategy in strategies if strategy.action == action]
        request.blacklist_batch_action(action, sid_list)
    enabled_sid_list = [strategy.feature_code for strategy in strategies if strategy.status == STATUS_ENABLE]
    request.blacklist_batch_enable(enabled_sid_list)
