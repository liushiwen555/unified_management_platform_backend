from django.db.models.signals import post_save, post_delete, pre_save
from django.dispatch import receiver
from django.forms import model_to_dict

from auditor.models import AuditorBlackList, AuditBlackListStrategy
from base_app.models import BaseStrategy, Device, StrategyTemplate
from firewall.models import ConfStrategy, IndustryProtocolDefaultConfStrategy, STATUS_DISABLE, \
    IndustryProtocolOPCStrategy, FirewallIPMACUnknownDeviceActionStrategy, FirewallBlackList, FirewallBlackListStrategy
from utils.core.exceptions import CustomError
from utils.helper import get_subclasses


def receiver_subclasses(signal, sender, dispatch_uid_prefix, **kwargs):
    """
    A decorator for connecting receivers and all receiver's subclasses to signals. Used by passing in the
    signal and keyword arguments to connect::

        @receiver_subclasses(post_save, sender=MyModel)
        def signal_receiver(sender, **kwargs):
            ...
    """
    def _decorator(func):
        all_senders = get_subclasses(sender)
        for snd in all_senders:
            signal.connect(func, sender=snd, dispatch_uid=dispatch_uid_prefix+'_'+snd.__name__, **kwargs)
        return func
    return _decorator


@receiver_subclasses(pre_save, BaseStrategy, "strategy_pre_save")
def strategy_pre_save(sender, instance, **kwargs):
    try:
        device = Device.objects.get(id=instance.device_id)
        if device.strategy_apply_status == Device.STRATEGY_APPLY_STATUS_APPLYING:
            raise CustomError({'error': CustomError.EDIT_STRATEGY_WHILE_APPLYING})
    except Device.DoesNotExist:
        pass


@receiver_subclasses(post_save, BaseStrategy, "strategy_post_save")
def strategy_post_save(sender, instance, **kwargs):
    try:
        device = Device.objects.get(id=instance.device_id)
        device.strategy_apply_status = Device.STRATEGY_APPLY_STATUS_UN_APPLIED
        device.save(update_fields=['strategy_apply_status'])
    except Device.DoesNotExist:
        pass


@receiver_subclasses(post_delete, BaseStrategy, "strategy_post_delete")
def strategy_post_delete(sender, instance, **kwargs):
    try:
        device = Device.objects.get(id=instance.device_id)
        device.strategy_apply_status = Device.STRATEGY_APPLY_STATUS_UN_APPLIED
        device.save(update_fields=['strategy_apply_status'])
    except Device.DoesNotExist:
        pass


@receiver(post_save, sender=Device)
def device_post_save(sender, instance, created, **kwargs):
    if not created:
        return
    if instance.type == Device.FIRE_WALL:
        ConfStrategy.objects.create(device_id=instance.id,
                                    run_mode=ConfStrategy.RUN_MODE_TEST,
                                    default_filter=ConfStrategy.DEFAULT_FILTER_OFF,
                                    DPI=ConfStrategy.DPI_OFF)
        IndustryProtocolDefaultConfStrategy.objects.create(device_id=instance.id,
                                                           OPC_default_action=STATUS_DISABLE,
                                                           modbus_default_action=STATUS_DISABLE)
        IndustryProtocolOPCStrategy.objects.create(device_id=instance.id)
        FirewallIPMACUnknownDeviceActionStrategy.objects.create(device_id=instance.id)

        blacklists = FirewallBlackList.objects.all()
        result = [FirewallBlackListStrategy(**model_to_dict(item, exclude=['id']), device_id=instance.id)
                  for item in blacklists]
        FirewallBlackListStrategy.objects.bulk_create(result)

    if instance.type == Device.AUDITOR:
        blacklists = AuditorBlackList.objects.all()
        result = [AuditBlackListStrategy(**model_to_dict(item, exclude=['id']), device_id=instance.id)
                  for item in blacklists]
        AuditBlackListStrategy.objects.bulk_create(result)


@receiver(post_save, sender=StrategyTemplate)
def template_post_save(sender, instance, created, **kwargs):
    if not created:
        return
    if instance.type == Device.FIRE_WALL:
        ConfStrategy.objects.create(template_id=instance.id,
                                    run_mode=ConfStrategy.RUN_MODE_TEST,
                                    default_filter=ConfStrategy.DEFAULT_FILTER_OFF,
                                    DPI=ConfStrategy.DPI_OFF)
        IndustryProtocolDefaultConfStrategy.objects.create(template_id=instance.id,
                                                           OPC_default_action=STATUS_DISABLE,
                                                           modbus_default_action=STATUS_DISABLE)
        IndustryProtocolOPCStrategy.objects.create(template_id=instance.id)
        FirewallIPMACUnknownDeviceActionStrategy.objects.create(template_id=instance.id)

        blacklists = FirewallBlackList.objects.all()
        result = [FirewallBlackListStrategy(**model_to_dict(item, exclude=['id']), template_id=instance.id)
                  for item in blacklists]
        FirewallBlackListStrategy.objects.bulk_create(result)

    if instance.type == Device.AUDITOR:
        blacklists = AuditorBlackList.objects.all()
        result = [AuditBlackListStrategy(**model_to_dict(item, exclude=['id']), template_id=instance.id)
                  for item in blacklists]
        AuditBlackListStrategy.objects.bulk_create(result)
