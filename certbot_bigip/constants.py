"""F5 BIG-IP plugin constants."""

CLI_DEFAULTS = dict(
    bigip_list=None,
    bigip_username=None,
    bigip_password=None,
    bigip_partition='Common',
    bigip_iapp=None,
    bigip_clientssl_parent='/Common/clientssl',
    bigip_device_group='sync-failover',
    virtual_server_list=None,
    bigip_apm=False,
    bigip_verify_ssl=False
)
