from django.core.validators import RegexValidator

from utils.core.field_error import AssetsField

MAC_VALIDATOR = RegexValidator(
    regex=r'^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$',
    message=AssetsField.MAC_VALIDATOR_ERROR)

IPV4_VALIDATOR = RegexValidator(
    regex=r'(?:^|\b(?<!\.))(?:1?\d?\d|2[0-4]\d|25[0-5])(?:\.(?:1?\d?\d|2[0-4]\d'
          r'|25[0-5])){3}(?=$|[^\w.])',
    message=AssetsField.IP_VALIDATOR_ERROR)

