# certbot-bigip

## PROJECT IS ARCHIVED

This project is not maintained anymore. A fork can be found [here](https://gitlab.com/emalzer/certbot-f5bigip) which is under active development.

## Requirements

see certbot rquirements: <https://certbot.eff.org/docs/install.html#system-requirements>

*   F5
    *   The LetsEncrypt Chain needs to be at /Common/chain_Letsencrypt and in every other partition that uses this plugin (f.e.: /Partition/chain_Letsencrypt). At the moment, the plugin checks if a corresponding certificate/chain is located in the same partition/folder as the clientssl profile that uses it.
    *   clientssl profile needs to be attached to the virtual server manually(DOMAIN_clientssl). At the moment, the plugin only updates the client profile but does not attach it to the virtual server.
    *   F5 SW version 14.x and higher

## Install

`pip install certbot-bigip`

by installing the plugin you will also install all missing dependencies including certbot.

## Supported Features

*   verifies the domain via HTTP01 (challenge verification implemented through an iRule)
*   Partitions and iApps
*   Standalone and HA setups (Active/Standby, Active/Active)
*   Creates the clientssl profile and attaches the certificate, key and chain
    *   Does not modify the clientssl profile if it already exists
*   Supports APM enabled virtual servers

## Usage

```bash
Parameters:
  --bigip-list                CSV list of BIG-IP system  hostnames or addresses, all have to be in the same cluster
  --bigip-username            BIG-IP username (common to all listed BIG-IP systems)
  --bigip-password            BIG-IP password (common to all listed BIG-IP systems)
  --bigip-partition           BIG-IP partition (common to all listed BIG-IP systems)
  --bigip-clientssl-parent    Client SSL parent profile to inherit default values from
  --bigip-vs-list             CSV list of BIG-IP virtual server names, optionally including partition
  --bigip-device-group        Device Group to syncronise configuration
  --bigip-iapp                BIG-IP iApp (common to all listed BIG-IP systems)
  --bigip-apm                 Is the VS APM enabled or not
```

Example:

```bash
certbot --non-interactive --expand --email 'admin@example.com' --agree-tos \
  -a bigip -i bigip \
  -d 'example.com' \
  --bigip-list 'example-f5.local,example-f5-ha.local' \
  --bigip-username 'user' \
  --bigip-password 'secret' \
  --bigip-partition 'internal' \
  --bigip-clientssl-parent '/Common/parent_clientssl' \
  --bigip-vs-list '/internal/example.com.app/example.com_vs' \
  --bigip-device-group 'fail-sync' \
  --bigip-iapp '/internal/example.com.app/example.com'
```

If the installation of a certificate during a `certbot renew` command somehow fails, certbot will not try to install the new certificate on a later run.
You can implement a check if the local certificate matches the remote certificate and if not issue a `certbot install --cert-name example.com` command.

```bash
certbot renew 

if ! /usr/local/bin/cert-test.sh --quiet example.com
then
  echo $(date)
  echo "installing example.com"
  certbot install --cert-name'example.com' 
fi
```

Alternatevly you can split the commands and not use the renew functionality like this:

```bash
certbot certonly --non-interactive --expand --email 'admin@example.com' --agree-tos \
  -a bigip -i bigip \
  -d 'example.com' \
  --bigip-list 'example-f5.local,example-f5-ha.local' \
  --bigip-username 'user' \
  --bigip-password 'secret' \
  --bigip-partition 'internal' \
  --bigip-clientssl-parent '/Common/parent_clientssl' \
  --bigip-vs-list '/internal/example.com.app/example.com_vs' \
  --bigip-device-group 'fail-sync' \
  --bigip-iapp '/internal/example.com.app/example.com_vs'

if ! /usr/local/bin/cert-test.sh --quiet example.com
then
  echo $(date)
  echo "installing example.com"
  certbot --non-interactive --expand --email 'admin@example.com' --agree-tos \
    -a bigip -i bigip \
    -d 'example.com' \
    --bigip-list 'example-f5.local,example-f5-ha.local' \
    --bigip-username 'user' \
    --bigip-password 'secret' \
    --bigip-partition 'internal' \
    --bigip-clientssl-parent '/Common/parent_clientssl' \
    --bigip-vs-list '/internal/example.com.app/example.com_vs' \
    --bigip-device-group 'fail-sync' \
    --bigip-iapp '/internal/example.com.app/example.com_vs'
else
  echo $(date)
  echo "not installing example.com"
fi
```

The first call only validates and renews the certificate through `certonly` parameter and the `cert-test.sh` compares the local certificate to the certificate delivered by the F5. If these don't match the second certbot call will skip the validation (as the certificate got already renewed) and install the certificate onto the F5.

## Testing

> **_WARNING_** Currently only integration tests are supported. Therefore a bigip is needed. To run integrations tests with other plugins for example the bluecat plugin you also need a bluecat in place.

### Prerequisites

1. Connection to the bigip under test from the machine running the tests
2. clientssl profile needs to be attached to the virtual server manually(DOMAIN_clientssl). At the moment, the plugin only updates the client profile but does not attach it to the virtual server.
3. Configure the tests using the following environment variables:

| ENV                    | default   | Example                                                      |
| ---------------------- | --------- | ------------------------------------------------------------ |
| BIGIP_EMAIL            |           | <test@test.test>                                             |
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
