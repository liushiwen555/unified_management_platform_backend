from log.log_content.alarm_log import alarm_config
from log.log_content.assets_log import assets_config
from log.log_content.auth_log import auth_config
from log.log_content.log_generator import log_config, additional_before_delete
from log.log_content.login_logout_log import login_logout_config
from log.log_content.security_log import security_config
from log.log_content.system_log import system_config
from log.log_content.snmp_log import snmp_config
from log.log_content.unified_log import unified_log_config

__all__ = ['log_config', 'additional_before_delete']
