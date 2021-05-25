# certbot-bigip

## Requirements

see certbot rquirements: <https://certbot.eff.org/docs/install.html#system-requirements>

* F5
  * The LetsEncrypt Chain needs to be at /Common/chain_Letsencrypt and in every other partition that uses this plugin. ( f.e.: /Partition/chain_Letsencrypt)
      At the moment, the plugin checks if a corresponding certificate/chain is located in the same partition/folder as the clientssl profile that uses it.
  * clientssl profile needs to be attached to the virtual server manually(DOMAIN_clientssl). At the moment, the plugin only updates the client profile but does not attach it to the virtual server.

## Install

## Supported Features

* verifies the domain via HTTP01 (challenge verification implemented through an iRule)
* Partitions and iApps
* Standalone and HA setups (Active/Standby, Active/Active)
* Creates the clientssl profile and attaches the certificate, key and chain
  * Does not modify the clientssl profile if it already exists
* Supports APM enabled virtual servers

## Usage

```bash
Parameters:
  --certbot-bigip:bigip-list                CSV list of BIG-IP system  hostnames or addresses, all have to be in the same cluster
  --certbot-bigip:bigip-username            BIG-IP username (common to all listed BIG-IP systems)
  --certbot-bigip:bigip-password            BIG-IP password (common to all listed BIG-IP systems)
  --certbot-bigip:bigip-partition           BIG-IP partition (common to all listed BIG-IP systems)
  --certbot-bigip:bigip-clientssl-parent    Client SSL parent profile to inherit default values from
  --certbot-bigip:bigip-vs-list             CSV list of BIG-IP virtual server names, optionally including partition
  --certbot-bigip:bigip-device-group        Device Group to syncronise configuration
  --certbot-bigip:bigip-iapp                BIG-IP iApp (common to all listed BIG-IP systems)
  --certbot-bigip:bigip-apm                 Is the VS APM enabled or not
```

Example:

```bash
certbot --non-interactive --expand --email 'admin@example.com' --agree-tos \
  -a certbot-bigip:bigip -i certbot-bigip:bigip \
  -d 'example.com' \
  --certbot-bigip:bigip-list 'example-f5.local,example-f5-ha.local' \
  --certbot-bigip:bigip-username 'user' \
  --certbot-bigip:bigip-password 'secret' \
  --certbot-bigip:bigip-partition 'internal' \
  --certbot-bigip:bigip-clientssl-parent '/Common/parent_clientssl' \
  --certbot-bigip:bigip-vs-list '/internal/example.com.app/example.com_vs' \
  --certbot-bigip:bigip-device-group 'fail-sync' \
  --certbot-bigip:bigip-iapp '/internal/example.com.app/example.com'
```

This plugin currently does not support the ```certbot renew``` function, it will only do the challenge and renew the certificate but it will not uploade the certificate to the F5 as the renew does not call the deploy function. To overcome this you can use it like this:

```bash
certbot certonly --non-interactive --expand --email 'admin@example.com' --agree-tos \
  -a certbot-bigip:bigip -i certbot-bigip:bigip \
  -d 'example.com' \
  --certbot-bigip:bigip-list 'example-f5.local,example-f5-ha.local' \
  --certbot-bigip:bigip-username 'user' \
  --certbot-bigip:bigip-password 'secret' \
  --certbot-bigip:bigip-partition 'internal' \
  --certbot-bigip:bigip-clientssl-parent '/Common/parent_clientssl' \
  --certbot-bigip:bigip-vs-list '/internal/example.com.app/example.com_vs' \
  --certbot-bigip:bigip-device-group 'fail-sync' \
  --certbot-bigip:bigip-iapp '/internal/example.com.app/example.com_vs'

if ! /usr/local/bin/cert-test.sh --quiet example.com
then
  echo $(date)
  echo "installing example.com"
  certbot --non-interactive --expand --email 'admin@example.com' --agree-tos \
    -a certbot-bigip:bigip -i certbot-bigip:bigip \
    -d 'example.com' \
    --certbot-bigip:bigip-list 'example-f5.local,example-f5-ha.local' \
    --certbot-bigip:bigip-username 'user' \
    --certbot-bigip:bigip-password 'secret' \
    --certbot-bigip:bigip-partition 'internal' \
    --certbot-bigip:bigip-clientssl-parent '/Common/parent_clientssl' \
    --certbot-bigip:bigip-vs-list '/internal/example.com.app/example.com_vs' \
    --certbot-bigip:bigip-device-group 'fail-sync' \
    --certbot-bigip:bigip-iapp '/internal/example.com.app/example.com_vs'
else
  echo $(date)
  echo "not installing greensight.on.at"
fi
```

The first call only validates and renews the certificate through ```certonly``` and the ```cert-test.sh``` compares the local certificate to the certificate delivered by the F5. If these don't match the second certbot call will skip the validation (as the certificate got already renewed) and install the certificate onto the F5.

## Testing
> :warning: Currently only integration tests are supported. Therefore a bigip is needed. to run integrations tests with other plugins for example the bluecat plugin you also need a bluecat in place.

### Prerequisites

1. Connection to the bigip under test from the machine running the tests
2. clientssl profile needs to be attached to the virtual server manually(DOMAIN_clientssl). At the moment, the plugin only updates the client profile but does not attach it to the virtual server.
3.  Configure the tests using the following environment variables:

| ENV                    | default   | Example                                                      |
| ---------------------- | --------- | ------------------------------------------------------------ |
| BIGIP_EMAIL            |           | test@test.test                                               |
| BIGIP_USERNAME         |           | user                                                         |
| BIGIP_PASSWORD         |           | secret                                                       |
| BIGIP_LIST             |           | example-f5.local,example-f5-ha.local                         |
| BIGIP_PARTITION        |           | internal                                                     |
| BIGIP_CLIENTSSL_PARENT |           | /Common/parent_clientssl                                     |
| BIGIP_VS_LIST          |           | /internal/example.com.app/example.com_vs                     |
| BIGIP_DEVICE_GROUP     | fail-sync | fail-sync                                                    |
| BIGIP_IAPP             |           | /internal/example.com.app/example.com                        |
| BIGIP_CUSTOM_PARTITION | Common    | Common                                                       |
| BIGIP_CUSTOM_VS_LIST   |           | /Common/example.com.app/example1.com_vs, /Common/example.com.app/example2.com_vs |
### running the tests

`python setup.py test`

## Contributing

If you find errors please open a new issue.

Open a pull request if you have made changes you want to add. we will take a look at it and try our best to merge it. Your help is very welcomed. 
