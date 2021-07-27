import os
import re
import subprocess
from ipaddress import ip_interface
from shutil import copyfile

from django.conf import settings

from gen_cert.gen_cert import gen


def reboot():
    subprocess.run('sudo reboot', shell=True, check=True)


def parse_ip(interface):
    pattern1 = r'auto {0}\niface {0} inet static\naddress (.*?)\nnetmask (.*?)\ngateway (.*?)\n'.format(interface)
    pattern2 = r'auto {0}\niface {0} inet static\naddress (.*?)\nnetmask (.*?)\n'.format(interface)
    with open(os.path.join(settings.IFACE_FILE_DIR, interface)) as iface_file:
        iface_str = iface_file.read()
        m1 = re.search(pattern1, iface_str)
        if m1:
            return m1.group(1, 2, 3)
        m2 = re.search(pattern2, iface_str)
        if m2:
            return m2.group(1), m2.group(2), ''
    return '', '', ''


def set_ip(interface, address, net_mask, gateway=''):
    """
    set ip information by writing the /etc/network/interface file directly.
    :param interface:  the interface name.
    :param address:    ip address, IPv4 or IPv6.
    :param net_mask:    netmask
    :param gateway:    gateway.
    :return:
    """
    cidr_address = ip_interface('{}/{}'.format(address, net_mask)).with_prefixlen

    if '.' in gateway:
        gateway = 'gateway4: ' + gateway
    elif ':' in gateway:
        gateway = 'gateway6: ' + gateway
    else:
        gateway = ''

    # Put the gen_cert project in Django project base dir, cert file will be in dir 'gen_cert/gen_key/'.
    src_crt_path = os.path.join(settings.BASE_DIR, 'gen_cert/gen_key/server.crt')
    src_key_path = os.path.join(settings.BASE_DIR, 'gen_cert/gen_key/server.key')
    # Cert dir where nginx get cert is set in 'local_setting.py' as 'CERTIFICATE_DIR'.
    dst_crt_path = os.path.join(settings.CERTIFICATE_DIR, 'server.crt')
    # Backup file name of old cert file.
    dst_crt_bak_path = dst_crt_path + '.bak'
    dst_key_path = os.path.join(settings.CERTIFICATE_DIR, 'server.key')
    dst_key_bak_path = dst_key_path + '.bak'

    # Interface conf file name.
    iface_file_path = os.path.join(settings.IFACE_FILE_DIR, settings.MGMT+'.yaml')
    iface_file_bak_path = iface_file_path + '.bak'
    # nginx_file_path = settings.NGINX_FILE_PATH
    # nginx_file_bak_path = nginx_file_path + '.bak'
    # Django IP conf file name.
    django_file_path = settings.DJANGO_IP_PATH
    django_file_bak_path = django_file_path + '.bak'

    # Generate cert file by new IP.
    gen(address)
    try:
        # Backup old crt file.
        if os.path.exists(dst_crt_path):
            copyfile(dst_crt_path, dst_crt_bak_path)
        # Backup old key file.
        if os.path.exists(dst_key_path):
            copyfile(dst_key_path, dst_key_bak_path)
        # Overwrite cert file.
        copyfile(src_crt_path, dst_crt_path)
        copyfile(src_key_path, dst_key_path)

        # Backup old interface conf file before rewrite.
        if os.path.exists(iface_file_path):
            copyfile(iface_file_path, iface_file_bak_path)
        iface_config = settings.IFACE_TEMPLATE.format(interface, cidr_address, gateway)
        with open(iface_file_path, mode='w') as iface_file:
            iface_file.write(iface_config)

        # copyfile(settings.NGINX_FILE_PATH, nginx_file_bak_path)
        # nginx_config = nginx_template % address
        # with open(nginx_file_path, mode='w') as nginx_file:
        #     nginx_file.write(nginx_config)

        # Backup old Django IP conf file before rewrite.
        if os.path.exists(django_file_path):
            copyfile(django_file_path, django_file_bak_path)
        with open(settings.DJANGO_IP_PATH, mode='w') as django_file:
            django_file.write('IP = "{}"'.format(address))
    except Exception as e:
        # If exception occurred, recover old conf file.
        if os.path.exists(dst_crt_bak_path):
            copyfile(dst_crt_bak_path, dst_crt_path)
        if os.path.exists(dst_key_bak_path):
            copyfile(dst_key_bak_path, dst_key_path)
        if os.path.exists(iface_file_bak_path):
            copyfile(iface_file_bak_path, iface_file_path)
        # if os.path.exists(nginx_file_bak_path):
        #     copyfile(nginx_file_bak_path, nginx_file_path)
        if os.path.exists(django_file_bak_path):
            copyfile(django_file_bak_path, django_file_path)
        raise e
    finally:
        # Always delete backup file.
        if os.path.exists(dst_crt_bak_path):
            os.remove(dst_crt_bak_path)
        if os.path.exists(dst_key_bak_path):
            os.remove(dst_key_bak_path)
        if os.path.exists(iface_file_bak_path):
            os.remove(iface_file_bak_path)
        # if os.path.exists(nginx_file_bak_path):
        #     os.remove(nginx_file_bak_path)
        if os.path.exists(django_file_bak_path):
            os.remove(django_file_bak_path)

    reboot()


def set_time(time):
    """
    set time by execute shell command.
    :param time:    python datetime object.
    :return:
    """
    strftime = time.strftime('%Y-%m-%d %H:%M:%S')
    subprocess.run('sudo timedatectl set-time "{0}"'.format(strftime), shell=True, check=True)


def set_rule(queryset):
    # write rule file.
    with open(settings.SURICATA_RULE_PATH, 'w') as rule_file:
        for i in queryset.filter(is_active=True):
            rule_file.write(i.rule)

    # reload suricata configuration file.
    subprocess.run('kill -USR2 $(cat {})'.format(settings.SURICATA_PID_FILE_PATH), shell=True, check=True)
