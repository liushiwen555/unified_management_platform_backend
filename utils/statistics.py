from django.db.models import Sum, Count
# from device.models import Device


# def stat_traffic_by_device(queryset):
#     traffic_in = list(queryset.values('dst_ip', 'dst_mac').annotate(traffic=Sum('length')).order_by())
#     # if there exist two item, they have same mac, but one has ip and the other has not. we have to combine them.
#     temp_in = deepcopy(traffic_in)
#
#     for i, x in enumerate(temp_in):
#         # x only need to compare the items behind it.
#         for j, y in enumerate(temp_in[i + 1:]):
#             if x['dst_mac'] == y['dst_mac']:
#                 if x['dst_ip']:
#                     traffic_in[i]['traffic'] = x['traffic'] + y['traffic']
#                     del traffic_in[i + j + 1]
#                 else:
#                     traffic_in[i + j + 1]['traffic'] = x['traffic'] + y['traffic']
#                     del traffic_in[i]
#
#     traffic_out = list(queryset.values('src_ip', 'src_mac').annotate(traffic=Sum('length')).order_by())
#     # if there exist two item, they have same mac, but one has ip and the other has not. we have to combine them.
#     temp_out = deepcopy(traffic_out)
#     for i, x in enumerate(temp_out):
#         # x only need to compare the items behind it.
#         for j, y in enumerate(temp_out[i + 1:]):
#             if x['src_mac'] == y['src_mac']:
#                 if x['src_ip'] and not y['src_ip']:
#                     traffic_out[i]['traffic'] = x['traffic'] + y['traffic']
#                     del traffic_out[i + j + 1]
#                 if y['src_ip'] and not x['src_ip']:
#                     traffic_out[i + j + 1]['traffic'] = x['traffic'] + y['traffic']
#                     del traffic_out[i]
#
#     devices = Device.objects.values('name', 'ip', 'mac')
#     temp_out = deepcopy(traffic_out)
#     results = []
#     # combine traffic-in and traffic-out, and add device name.
#     for i, x in enumerate(deepcopy(traffic_in)):
#         result = {'id': i + 1, 'name': None, 'ip': x['dst_ip'], 'mac': x['dst_mac'],
#                   'traffic_in': x['traffic'], 'traffic_out': 0}
#         # add device name, and update ip.
#         for dev in devices:
#             # if mac matches or ip matches.
#             if result['mac'] == dev['mac'] or (not dev['mac'] and result['ip'] == dev['ip']):
#                 result['name'] = dev['name']
#                 # in case there is no ip information in traffic.
#                 if not result['ip']:
#                     result['ip'] = dev['ip']
#                 break
#         # add traffic-out, and update ip.
#         for j, y in enumerate(temp_out):
#             if result['mac'] == y['src_mac'] and (not result['ip'] or not y['src_ip'] or result['ip'] == y['src_ip']):
#                 result['traffic_out'] = y['traffic']
#                 if not result['ip'] and y['src_ip']:
#                     result['ip'] = y['src_ip']
#                 del traffic_out[j]
#                 break
#         results.append(result)
#     for i, x in enumerate(traffic_out):
#         result = {'id': len(results) + i + 1, 'name': None, 'ip': x['src_ip'], 'mac': x['src_mac'],
#                   'traffic_in': 0, 'traffic_out': x['traffic']}
#         for dev in devices:
#             # if mac matches or ip matches.
#             if result['mac'] == dev['mac'] or (not dev['mac'] and result['ip'] == dev['ip']):
#                 result['name'] = dev['name']
#                 # in case there is no ip information in traffic.
#                 if not result['ip']:
#                     result['ip'] = dev['ip']
#                 break
#         results.append(result)
#
#     return results


# def stat_traffic_by_device(queryset):
#
#     traffic_in = list(queryset.values('dst_ip', 'dst_mac').annotate(traffic=Sum('length')).order_by())
#     traffic_out = list(queryset.values('src_ip', 'src_mac').annotate(traffic=Sum('length')).order_by())
#     devices = Device.objects.values('name', 'ip', 'mac')
#     results = []
#     # combine traffic-in and traffic-out, and add device name.
#     for i, x in enumerate(traffic_in):
#         result = {'id': i + 1, 'name': None, 'ip': x['dst_ip'], 'mac': x['dst_mac'],
#                   'traffic_in': x['traffic'], 'traffic_out': 0}
#         # add device name.
#         for dev in devices:
#             # if mac matches or ip matches.
#             if result['ip'] == dev['ip'] or (dev['mac'] and result['mac'] == dev['mac']):
#                 result['name'] = dev['name']
#                 break
#         # add traffic-out, and update ip.
#         temp_out = deepcopy(traffic_out)
#         for j, y in enumerate(temp_out):
#             if result['mac'] == y['src_mac'] and result['ip'] == y['src_ip']:
#                 result['traffic_out'] = y['traffic']
#                 del traffic_out[j]
#                 break
#         results.append(result)
#     for i, x in enumerate(traffic_out):
#         result = {'id': len(results) + i + 1, 'name': None, 'ip': x['src_ip'], 'mac': x['src_mac'],
#                   'traffic_in': 0, 'traffic_out': x['traffic']}
#         for dev in devices:
#             # if mac matches or ip matches.
#             if result['ip'] == dev['ip'] or (dev['mac'] and result['mac'] == dev['mac']):
#                 result['name'] = dev['name']
#                 break
#         results.append(result)
#
#     return results


def stat_traffic_by_device(queryset):
    # Statistic traffic group by IP and MAC.
    traffic_in = queryset.values('dst_ip', 'dst_mac').annotate(traffic=Sum('length')).order_by()
    traffic_out = queryset.values('src_ip', 'src_mac').annotate(traffic=Sum('length')).order_by()
    # Device information contain name, ip and mac.
    devices = Device.objects.values('name', 'ip', 'mac')
    ip_name = {}
    mac_name = {}
    for device in devices:
        # Device information dict whose key is IP and value is name.
        ip_name[device['ip']] = device['name']
        if device['mac']:
            # Device information dict whose key is MAC and value is name.
            ip_name[device['mac']] = device['name']

    # Generate dict whose key is MAC and value is {'ip':ip, 'traffic': traffic}
    traffic_in_dict = {}
    for item in traffic_in:
        # If record with the same mac already exists, combine them and update ip.
        if item['dst_mac'] in traffic_in_dict:
            v = traffic_in_dict[item['dst_mac']]
            v.update(
                ip=v['ip'] or item['dst_ip'],
                traffic=v['traffic']+item['traffic']
            )
        else:
            traffic_in_dict[item['dst_mac']] = {
                'ip': item['dst_ip'],
                'traffic': item['traffic']
            }

    # Generate dict whose key is MAC and value is {'ip':ip, 'traffic': traffic}
    traffic_out_dict = {}
    for item in traffic_out:
        # If record with the same mac already exists, combine them and update ip.
        if item['src_mac'] in traffic_out_dict:
            v = traffic_out_dict[item['src_mac']]
            v.update(
                ip=v['ip'] or item['src_ip'],
                traffic=v['traffic']+item['traffic']
            )
        else:
            traffic_out_dict[item['src_mac']] = {
                'ip': item['src_ip'],
                'traffic': item['traffic']
            }

    results = []
    for mac in traffic_in_dict:
        # MAC is in traffic_in and traffic_out at the same time.
        if mac in traffic_out_dict:
            # IP may be in traffic_in or traffic_out.
            result = {
                'ip': traffic_in_dict[mac]['ip'] or traffic_out_dict[mac]['ip'],
                'mac': mac,
                'traffic_in': traffic_in_dict[mac]['traffic'],
                'traffic_out': traffic_out_dict[mac]['traffic']
            }
            # Delete the record in traffic_out.
            del traffic_out_dict[mac]
        # MAC is only in traffic_in.
        else:
            result = {
                'ip': traffic_in_dict[mac]['ip'],
                'mac': mac,
                'traffic_in': traffic_in_dict[mac]['traffic'],
                'traffic_out': 0
            }
        results.append(result)

    # The rest MAC is only in traffic_out.
    for mac in traffic_out_dict:
        result = {
            'ip': traffic_out_dict[mac]['ip'],
            'mac': mac,
            'traffic_in': 0,
            'traffic_out': traffic_out_dict[mac]['traffic']
        }
        results.append(result)

    # Add id and device name to the results.
    for i_d, result in enumerate(results, 1):
        result.update(
            id=i_d,
            name=ip_name.get(result['ip']) or mac_name.get(result['mac'])
        )

    return results


def gen_time_list(start_time, end_time, interval):
    """
    :param start_time:  开始时间 datetime
    :param end_time:    结束时间 datetime
    :param interval:    周期 datetime.timedelta

    :return: [time, ...]  时间列表 datetime
    """
    time_list = []
    if start_time > end_time:
        return time_list
    time = start_time
    while time < end_time:
        time_list.append(time)
        time += interval
    time_list.append(end_time)
    return time_list


def stat_count(queryset, time_field, time_list, value_field='id'):
    """
    :param queryset:    用于统计的Django Queryset对象
    :param time_field:  用于分组的字段
    :param time_list:   用于分组的字段值组成的列表，正序
    :param value_field: 用于计数的字段，默认为id

    :return: [{}, ...] 字典列表，字典包含字段
        time:   起始时间 iso 格式
        value:  时间段内的统计值
    """

    stat_results = []
    if len(time_list) < 2:
        return stat_results
    for i in range(len(time_list) - 1):
        kwargs = {time_field + '__gte': time_list[i], time_field + '__lt': time_list[i + 1]}
        qs = queryset.filter(**kwargs)
        count = qs.aggregate(count=Count(value_field))['count'] or 0
        stat_results.append({'time': time_list[i].isoformat(), 'count': count})
    return stat_results


def stat_sum(queryset, time_field, time_list, value_field):
    """
    :param queryset:    用于统计的Django Queryset对象
    :param time_field:  用于分组的字段
    :param time_list:   用于分组的字段值组成的列表，正序
    :param value_field: 用于统计的字段

    :return: [{}, ...] 字典列表，字典包含字段
        time:   起始时间 iso 格式
        value:  时间段内的统计值
    """
    stat_results = []
    if len(time_list) < 2:
        return stat_results
    for i in range(len(time_list)-1):
        kwargs = {time_field+'__gte': time_list[i], time_field+'__lt': time_list[i+1]}
        qs = queryset.filter(**kwargs)
        value = qs.aggregate(value=Sum(value_field))['value'] or 0
        stat_results.append({'time': time_list[i].isoformat(), 'value': value})
    return stat_results
