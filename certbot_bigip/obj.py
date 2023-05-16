'''Module contains classes used by the F5 BIG-IP Configurator.'''

import logging
import os
import requests
from urllib3.exceptions import InsecureRequestWarning

from certbot import errors

from f5.bigip import ManagementRoot
from f5.bigip.contexts import TransactionContextManager
from f5.multi_device.device_group import DeviceGroup


logger = logging.getLogger(__name__)


class Bigip(object):
    '''Object representing access to F5 BIG-IP system(s)

    :param object: [description]
    :type object: [type]
    '''

    def __init__(
        self,
        bigips,
        username,
        password,
        vs_list,
        device_group,
        partition,
        clientssl_parent,
        verify_ssl,
    ):
        '''Initialize a BIG-IP.

        :param hosts: CSV list of BIG-IP system hostnames or addresses, all have to be in the same cluster
        :type hosts: string
        :param username: BIG-IP username
        :type username: string
        :param password: BIG-IP password
        :type password: string
        :param device_group: Device Group to syncronise configuration
        :type device_group: string
        :param partition: BIG-IP partition, defaults to 'Common'
        :type partition: str, optional
        :param clientssl_parent: Client SSL parent profile to inherit default values from,
                                 defaults to '/Common/clientssl'
        :type clientssl_parent: str, optional
        :param verify_ssl: enable or disable SSL verification of the BIG-IP management API, defaults to False
        :type verify_ssl: bool, optional
        :raises errors.AuthorizationError: Connection to the BIG-IP failed
        '''

        self.bigips = bigips
        self.bigip_map = {}
        self.username = username
        self.__password = password
        self.token = True
        self.partition = partition
        self.vs_list = vs_list
        self.device_group = device_group
        self.clientssl_parent = clientssl_parent
        self.standalone = False
        self.verify_ssl = verify_ssl

        if not self.verify_ssl:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        self.bigip_map = self._get_bigip_map()
        logger.debug(f'bigip map: {self.bigip_map}')
        self.active_device = self._get_active_bigip()
        logger.debug(f'active device: {self.active_device}')
        if self.active_device:
            try:
                self.mgmt = ManagementRoot(
                    self.active_device,
                    self.username,
                    self.__password,
                    token=True,
                    verify=self.verify_ssl,
                )
            except Exception as e:
                msg = (
                    f'Connection to F5 BIG-IP iControl REST API on {self.active_device} failed.{os.linesep}'
                    f'Error raised was {os.linesep}{e}{os.linesep}'
                    '(You most probably need to ensure the username and'
                    'password is correct. Make sure you use the --bigip-username'
                    'and --bigip-password options)'
                )
                raise errors.AuthorizationError(msg)
        else:
            msg = (
                f'No active device found which is responsible for all '
                'provided virtual servers or auto-sync is disabled. If you run an active/active setup '
                f'please ensure that all virtual servers are in the same traffic group or auto-sync is enabled{os.linesep}'
            )
            raise errors.PluginError(msg)
        self.standalone = self._get_cluster_state()
        logger.debug(f'standalone: {self.standalone}')

    def _split_fullpath(self, fullpath):
        '''Return partition, subpath and name from object.

        :return: splits object into its parts like: /partition/path/object -> ['partition', 'path', 'object']
        :rtype: list
        '''
        try:
            if len(fullpath.split('/')) == 4:
                subpath = fullpath.split('/')[2]
                partition = fullpath.split('/')[1]
                name = fullpath.split('/')[3]
            elif len(fullpath.split('/')) == 3:
                subpath = ''
                partition = fullpath.split('/')[1]
                name = fullpath.split('/')[2]
            elif len(fullpath.split('/')) == 2:
                subpath = ''
                partition = 'Common'
                name = fullpath.split('/')[2]

            return [partition, subpath, name]
        except Exception as e:
            msg = (
                f'Failure with {fullpath}.{os.linesep}'
                f'Error raised was {os.linesep}{e}{os.linesep}'
            )
            raise errors.PluginError(msg)

    def get_version(self):
        '''Returns the BIG-IPs SW version, currently not implemented.

        :return: running software version
        :rtype: string
        '''
        return 'N/A'

    def _get_bigip_map(self):
        '''Map bigips from user input with true bigip hostnamess.

        :raises errors.AuthorizationError: Connection to the BIG-IP failed
        :return: Dict with mapping of given bigip from user cli to actual hostname
        :rtype: dict
        '''
        bigip_map = {}
        for bigip in self.bigips:
            try:
                mgmt = ManagementRoot(
                    bigip,
                    self.username,
                    self.__password,
                    token=True,
                    verify=self.verify_ssl,
                )
                device = mgmt.tm.sys.global_settings.load()
                bigip_map[bigip] = device.raw['hostname']
            except Exception as e:
                msg = (
                    f'Connection to F5 BIG-IP iControl REST API on {bigip} failed.{os.linesep}'
                    f'Error raised was {os.linesep}{e}{os.linesep}'
                    '(You most probably need to ensure the username and '
                    'password is correct. Make sure you use the --bigip-username '
                    'and --bigip-password options)'
                )
                raise errors.AuthorizationError(msg)
        return bigip_map

    def _get_active_bigip(self):
        '''sets the active bigip if one is the active unit for all given virtual servers.
        sets the first bigip if cluster is active/active and auto-sync is turned on.
        returns false if no bigip is active for all virtual servers (active/active without auto-sync)

        :raises errors.AuthorizationError: Connection to the BIG-IP failed
        :raises errors.PluginError: Connection to the BIG-IP failed
        :return: name of the active bigip
        :rtype: string
        '''
        try:
            mgmt = ManagementRoot(
                self.bigips[0],
                self.username,
                self.__password,
                token=True,
                verify=self.verify_ssl,
            )
        except Exception as e:
            msg = (
                f'Connection to F5 BIG-IP iControl REST API on {self.bigips[0]} failed.{os.linesep}'
                f'Error raised was {os.linesep}{e}{os.linesep}'
                '(You most probably need to ensure the username and '
                'password is correct. Make sure you use the --bigip-username '
                'and --bigip-password options)'
            )
            raise errors.AuthorizationError(msg)
        try:
            # first check for failover status
            active_device = ''
            active_devices = []
            devices = mgmt.tm.cm.devices.get_collection()
            for device in devices:
                if device.raw['failoverState'] == 'active':
                    active_devices.append(device.raw['hostname'])
            if len(active_devices) == 0:
                logger.debug('No active device found')
                return False
            if len(active_devices) == 1:
                active_device = active_devices[0]
                logger.debug(f'Active device found in A/S cluster: {active_device}')
            else:
                # active/active cluster, checking if auto-sync is enabled
                device_groups = mgmt.tm.cm.device_groups.get_collection()
                for dg in device_groups:
                    if (
                        dg.raw['type'] == 'sync-failover'
                        and dg.raw['autoSync'] == 'enabled'
                    ):
                        logger.debug(
                            'sync-failover with autoSync enabled, returning first device from list.'
                        )
                        active_devices.append(self.bigips[0])
                # active/active cluster, need to find active device for specified virtual servers
                destinations = []
                for vs in self.vs_list:
                    # get destination from vs
                    # extract IP from destination
                    # get virtual address with address=destination
                    # get tg from va
                    # check active device for tgs
                    r = self._split_fullpath(vs)
                    virtual = mgmt.tm.ltm.virtuals.virtual.load(
                        partition=r[0], subPath=r[1], name=r[2]
                    )
                    dst = virtual.raw['destination']
                    dst = dst[dst.rfind('/') + 1 :]
                    if dst.count('.') == 3:
                        # IPv4 address
                        dst = dst.split(':')[0]
                    else:
                        # IPv6 address
                        dst = dst.split('.')[0]
                    if dst not in destinations:
                        destinations.append(dst)

                tgs = []
                virtual_addresses = mgmt.tm.ltm.virtual_address_s.get_collection()
                for va in virtual_addresses:
                    for dst in destinations:
                        if va.raw['address'] == dst:
                            if va.raw['trafficGroup'] not in tgs:
                                tgs.append(va.raw['trafficGroup'])

                active_devices = []
                for tg in tgs:
                    traffic_group = mgmt.tm.cm.traffic_groups.traffic_group.load(
                        partition=tg.split('/')[1], name=tg.split('/')[2]
                    )
                    traffic_group_stats = traffic_group.stats.load()
                    for item in traffic_group_stats.entries:
                        if (
                            traffic_group_stats.entries[item]['nestedStats']['entries'][
                                'failoverState'
                            ]['description']
                            == 'active'
                        ):
                            if (
                                traffic_group_stats.entries[item]['nestedStats'][
                                    'entries'
                                ]['deviceName']['description']
                                not in active_devices
                            ):
                                active_devices.append(
                                    traffic_group_stats.entries[item]['nestedStats'][
                                        'entries'
                                    ]['deviceName']['description']
                                )
                if len(active_devices) == 0:
                    logger.debug('No active device found')
                    return False
                if len(active_devices) == 1:
                    active_device = active_devices[0].split('/')[2]
                    logger.debug(
                        f'Active device found in A/A cluster: {active_devices[0]}'
                    )
                else:
                    logger.debug('No active device found')
                    return False

            for device in self.bigip_map:
                if self.bigip_map[device] == active_device:
                    logger.debug(f'Active device {active_device} mapped to {device}')
                    return device

        except Exception as e:
            msg = (
                f'Connection to F5 BIG-IP iControl REST API failed.{os.linesep}'
                f'Error raised was {os.linesep}{e}{os.linesep}'
            )
            raise errors.PluginError(msg)

    def _get_cluster_state(self):
        '''gets current cluster state

        :return: True for cluster, False for Standalone
        :rtype: bool
        '''
        ss = self.mgmt.tm.cm.sync_status.load()
        if (
            ss.raw['entries']['https://localhost/mgmt/tm/cm/sync-status/0'][
                'nestedStats'
            ]['entries']['mode']['description']
            == 'standalone'
        ):
            return True
        else:
            return False

    def save(self):
        '''Saves the running configuration.

        :raises errors.PluginError: something went wrong connecting to the BIG-IP
        '''
        try:
            self.mgmt.tm.sys.config.exec_cmd('save')
            if not self.standalone:
                list_of_bigips = []
                for bigip in self.bigips:
                    list_of_bigips.append(
                        ManagementRoot(bigip, self.username, self.__password)
                    )

                device_group = DeviceGroup(
                    devices=list_of_bigips,
                    device_group_name=self.device_group,
                    device_group_type='sync-failover',
                    device_group_partition='Common',
                )
                device_group.ensure_all_devices_in_sync()

        except Exception as e:
            msg = (
                f'Connection to F5 BIG-IP iControl REST API on {self.active_device} failed.{os.linesep}'
                f'Error raised was {os.linesep}{e}{os.linesep}'
            )
            raise errors.PluginError(msg)

    def save_ucs(self, ucs_name):
        '''Generate UCS backup file, currently not used. Might be relevant for checkpoint implementation.

        :param ucs_name: name of the UCS file
        :type ucs_name: string
        :raises errors.PluginError: something went wrong connecting to the BIG-IP
        :return: return True if UCS generation is successfull
        :rtype: bool
        '''
        try:
            self.mgmt.tm.sys.ucs.exec_cmd('save', name=ucs_name)
            return True

        except Exception as e:
            msg = (
                f'Connection to F5 BIG-IP iControl REST API on {self.active_device} failed.{os.linesep}'
                f'Error raised was {os.linesep}{e}{os.linesep}'
            )
            raise errors.PluginError(msg)

    def upload_file(self, local_file_name):
        '''Upload a file.

        :param local_file_name: local file name
        :type local_file_name: string
        :raises errors.CertStorageError: something went wrong saving the file to the BIG-IP
        :return: return True if file upload is successfull
        :rtype: bool
        '''
        try:
            self.mgmt.shared.file_transfer.uploads.upload_file(local_file_name)
            return True

        except Exception as e:
            msg = (
                f'Connection to F5 BIG-IP iControl REST API on {self.active_device} failed.{os.linesep}'
                f'Error raised was {os.linesep}{e}{os.linesep}'
            )
            raise errors.CertStorageError(msg)

    def exists_crypto_cert(self, certificate):
        '''check if certificate already exists

        :param certificate: name of the certificate
        :type certificate: string
        :raises errors.CertStorageError: something went wrong accessing the file to the BIG-IP
        :return: return true or false certificate exists or not
        :rtype: bool
        '''
        try:
            return self.mgmt.tm.sys.file.ssl_certs.ssl_cert.exists(
                name=f'{certificate}_Letsencrypt', partition=self.partition
            )

        except Exception as e:
            msg = (
                f'Connection to F5 BIG-IP iControl REST API on {self.active_device} failed.{os.linesep}'
                f'Error raised was {os.linesep}{e}{os.linesep}'
            )
            raise errors.CertStorageError(msg)

    def exists_crypto_key(self, key):
        '''check if key already exists

        :param key: name of the key
        :type key: string
        :raises errors.CertStorageError: something went wrong accessing the file to the BIG-IP
        :return: return true or false certificate exists or not
        :rtype: bool
        '''
        try:
            return self.mgmt.tm.sys.file.ssl_keys.ssl_key.exists(
                name=f'{key}_Letsencrypt', partition=self.partition
            )

        except Exception as e:
            raise BigIpCertStorageError(self.active_device, e)

    def update_crypto(self, name, cert, key, chain, cert_chain_name):
        '''updated certificate and key

        :param name: domain name
        :type name: string
        :param cert: certificate filename
        :type cert: string
        :param key: key filename
        :type key: string
        :param chain: chain filename
        :type chain: string
        :param cert_chain_name: chain name
        :type cert_chain_name: string
        :raises BigIpCertStorageError: something went wrong accessing the file to the BIG-IP
        '''
        # Because they exist, we will modify them in a transaction
        try:
            tx = self.mgmt.tm.transactions.transaction
            with TransactionContextManager(tx) as api:

                self._update_crypto_key(api, key, name)
                self._update_crypto_cert(api, cert, name)

            self._update_crypto_cert(api, chain, cert_chain_name)

        except Exception as e:
            raise BigIpCertStorageError(self.active_device, e)

    def _update_crypto_cert(self, api, cert, name):
        '''upload certificate

        :param api: transaction object
        :type api: TransactionContextManager
        :param cert: certificate filename
        :type cert: string
        :param name: domain name
        :type name: string
        '''
        if self.exists_crypto_cert(name):
            logger.debug(f'updating cert for {name}')
            modcert = api.tm.sys.file.ssl_certs.ssl_cert.load(
                name=f'{name}_Letsencrypt', partition=self.partition
            )
            modcert.sourcePath = (
                f'file:/var/config/rest/downloads/{os.path.basename(cert)}'
            )
            modcert.update()

        else:
            logger.debug(f'creating cert for {name}')
            modcert = self.mgmt.tm.sys.file.ssl_certs.ssl_cert.create(
                name=f'{name}_Letsencrypt',
                partition=self.partition,
                sourcePath=f'file:/var/config/rest/downloads/{os.path.basename(cert)}',
            )

    def _update_crypto_key(self, api, key, name):
        '''upload key

        :param api: transaction object
        :type api: TransactionContextManager
        :param key: key filename
        :type key: string
        :param name: domain name
        :type name: string
        '''
        if self.exists_crypto_key(name):
            logger.debug(f'updating key for {name}')
            modkey = api.tm.sys.file.ssl_keys.ssl_key.load(
                name=f'{name}_Letsencrypt', partition=self.partition
            )
            modkey.sourcePath = f'file:/var/config/rest/downloads/{os.path.basename(key)}'
            modkey.update()
        else:
            logger.debug(f'creating key for {name}')
            modkey = self.mgmt.tm.sys.file.ssl_keys.ssl_key.create(
                name=f'{name}_Letsencrypt',
                partition=self.partition,
                sourcePath=f'file:/var/config/rest/downloads/{os.path.basename(key)}',
            )

    def exists_clientssl_profile(self, domain, virtual_name, iapp):
        '''check if clientssl profile already exists

        :param domain: domain name
        :type domain: [string
        :param virtual_name: virtual server name
        :type virtual_name: string
        :param iapp: iapp name
        :type iapp: string
        :raises errors.CertStorageError: something went wrong accessing the file to the BIG-IP
        :return: true if exists, false if not exists
        :rtype: bool
        '''
        try:
            r = self._split_fullpath(virtual_name)
            name = f'{domain}_clientssl'
            if iapp != '':
                return self.mgmt.tm.ltm.profile.client_ssls.client_ssl.exists(
                    name=name, partition=self.partition, subPath=r[1]
                )
            else:
                return self.mgmt.tm.ltm.profile.client_ssls.client_ssl.exists(
                    name=name, partition=self.partition
                )

        except Exception as e:
            msg = (
                f'Connection to F5 BIG-IP iControl REST API on {self.active_device} failed.{os.linesep}'
                f'Error raised was {os.linesep}{e}{os.linesep}'
            )
            raise errors.CertStorageError(msg)

    def update_clientssl_profile(self, domain, virtual_name, iapp):
        '''update client ssl profile

        :param domain: domain name
        :type domain: string
        :param virtual_name: virtual server name
        :type virtual_name: string
        :param iapp: iapp name
        :type iapp: string
        '''
        if 'wildcard' not in domain:
            wildcard = False
        else:
            wildcard = True
        if not self.exists_clientssl_profile(domain, virtual_name, iapp):
            self.create_clientssl_profile(domain, virtual_name, iapp, wildcard)
        else:
            logger.debug('Nothing left to do')

    def create_clientssl_profile(self, domain, virtual_name, iapp, wildcard):
        '''create new clientssl profile

        :param domain: domain name
        :type domain: string
        :param virtual_name: virtual server name
        :type virtual_name: string
        :param iapp: iapp name
        :type iapp: string
        :param wildcard: if it's a wildcard of not
        :type wildcard: bool
        :raises errors.CertStorageError: something went wrong creating the profile to the BIG-IP
        :return: return true if it worked
        :rtype: bool
        '''

        # if it's a wildcard, we use it as default profile for SNI
        sni_default = wildcard

        try:
            r = self._split_fullpath(virtual_name)
            if iapp != '':
                name = f'/{self.partition}/{r[1]}/{domain}_clientssl'
            else:
                name = f'/{self.partition}/{domain}_clientssl'
            cssl_profile = {
                'name': name,
                'cert-key-chain':{
                    'default': {
                        'cert': f'/{self.partition}/{domain}_Letsencrypt',
                        'key': f'/{self.partition}/{domain}_Letsencrypt',
                        'chain': f'/{self.partition}/chain_Letsencrypt',
                    }
                },
                'defaultsFrom': self.clientssl_parent,
                'app-service': iapp,
                'sniDefault': sni_default,
            }
            self.mgmt.tm.ltm.profile.client_ssls.client_ssl.create(**cssl_profile)
            return True

        except Exception as e:
            msg = (
                f'Certificate creation on F5 Failed. Connection to F5 BIG-IP iControl REST API on {self.active_device} failed.{os.linesep}'
                f'Error raised was {os.linesep}{e}{os.linesep}'
            )
            raise errors.CertStorageError(msg)

    def exists_irule(self, irule_name):
        '''check if iRule already exists

        :param irule_name: iRule name
        :type irule_name: string
        :raises errors.ConfigurationError: check failed
        :return: True or False if iRule exists or not
        :rtype: bool
        '''
        try:
            return self.mgmt.tm.ltm.rules.rule.exists(
                partition=self.partition, name=irule_name
            )

        except Exception as e:
            msg = f'iRule creation on {self.active_device} failed. {os.linesep}{e}{os.linesep}'
            raise errors.ConfigurationError(msg)

    def create_irule_HTTP01(self, token, http_response_content, apm):
        '''create iRule for verification

        :param token: challenge token
        :type token: string
        :param http_response_content: challenge response value
        :type http_response_content: string
        :param apm: Flag if APM is enabled on this virtual server
        :type apm: bool
        :raises errors.ConfigurationError: creation failed
        :return: True iRule creation succeeded
        :rtype: bool
        '''
        try:
            irule_name = f'Certbot-Letsencrypt-{token}'
            if apm is True:
                irule_text = f'when CLIENT_ACCEPTED {{\n  catch {{\n    ACCESS::restrict_irule_events disable\n  }}\n}}\nwhen HTTP_REQUEST priority 100 {{\n  if {{[HTTP::has_responded]}}{{return}}\n  if {{[HTTP::uri] equals "/.well-known/acme-challenge/{token}"}} {{\n    HTTP::respond 200 -version auto content "{http_response_content}" noserver \n  event disable\n  }}\n}}'
            else:
                irule_text = f'when HTTP_REQUEST priority 100 {{\n  if {{[HTTP::has_responded]}}{{return}}\n  if {{[HTTP::uri] equals "/.well-known/acme-challenge/{token}"}} {{\n    HTTP::respond 200 -version auto content "{http_response_content}" noserver \n  event disable\n  }}\n}}'

            self.mgmt.tm.ltm.rules.rule.create(
                name=irule_name, partition=self.partition, apiAnonymous=irule_text
            )
            return True

        except Exception as e:
            msg = f'iRule creation on {self.active_device} failed. {os.linesep}{e}{os.linesep}'
            raise errors.ConfigurationError(msg)

    def delete_irule(self, token):
        '''delete iRule

        :param token: challenge token
        :type token: string
        :raises errors.ConfigurationError: deletion failed
        :return: True if deletion succeeded
        :rtype: bool
        '''
        try:
            irule_name = f'Certbot-Letsencrypt-{token}'

            rule = self.mgmt.tm.ltm.rules.rule.load(
                name=irule_name, partition=self.partition
            )
            rule.delete()
            return True

        except Exception as e:
            msg = f'iRule deletion from {self.active_device} failed. {os.linesep}{e}{os.linesep}'
            raise errors.ConfigurationError(msg)

    def exists_virtual(self, virtual_name):
        '''check if virtual server exists

        :param virtual_name: name of virtual server
        :type virtual_name: string
        :raises errors.ConfigurationError: check failed
        :return: True or False if VS exists or not
        :rtype: bool
        '''
        try:
            r = self._split_fullpath(virtual_name)
            return self.mgmt.tm.ltm.virtuals.virtual.exists(
                partition=r[0], subPath=r[1], name=r[2]
            )

        except Exception as e:
            msg = f'Virtual server {virtual_name} check on {self.active_device} failed. {os.linesep}{e}{os.linesep}'
            raise errors.ConfigurationError(msg)

    def profile_on_virtual(self, virtual_name, profile_type):
        '''check for profiles which are attached to the virtual server

        :param virtual_name: virtual server name
        :type virtual_name: string
        :param profile_type: type of profile to look for
        :type profile_type: string
        :raises errors.ConfigurationError: check failed
        :return: True or False if profile of specified type exists
        :rtype: bool
        '''
        try:
            r = self._split_fullpath(virtual_name)
            virtual = self.mgmt.tm.ltm.virtuals.virtual.load(
                partition=r[0], subPath=r[1], name=r[2]
            )

            if virtual != '':
                for profile in virtual.profiles_s.get_collection():
                    r = self._split_fullpath(profile.fullPath)
                    try:
                        getattr(
                            getattr(
                                getattr(self.mgmt.tm.ltm.profile, f'{profile_type}s'),
                                f'{profile_type}',
                            ),
                            'load',
                        )(partition=r[0], subPath=r[1], name=r[2])
                        return True
                    except Exception:
                        pass
                return False
            else:
                return False

        except Exception as e:
            msg = f'Test for HTTP profile on virtual server on {self.active_device} failed. {os.linesep}{e}{os.linesep}'
            raise errors.ConfigurationError(msg)

    def http_virtual(self, virtual_name):
        '''checks for http profile on virtual server

        :param virtual_name: virtual server name
        :type virtual_name: string
        :return: True or False
        :rtype: bool
        '''
        return self.profile_on_virtual(virtual_name, 'http')

    def client_ssl_virtual(self, virtual_name):
        '''checks for clientssl profile on virtual server

        :param virtual_name: virtual server name
        :type virtual_name: string
        :return: True or False
        :rtype: bool
        '''
        return self.profile_on_virtual(virtual_name, 'client_ssl')

    def irules_on_virtual(self, virtual_name):
        '''[summary]

        :param virtual_name: virtual server name
        :type virtual_name: string
        :raises errors.ConfigurationError: check failed
        :return: Dictionary with keys result and list of attached iRules
        :rtype: dict
        '''
        try:
            r = self._split_fullpath(virtual_name)
            virtual = self.mgmt.tm.ltm.virtuals.virtual.load(
                partition=r[0], subPath=r[1], name=r[2]
            )

            if virtual != '' and 'rules' in virtual.raw:
                return {'result': True, 'rules': virtual.rules}
            else:
                return {'result': False, 'rules': []}

        except Exception as e:
            msg = f'Retrieval of iRules for virtual server on {self.active_device} failed. {os.linesep}{e}{os.linesep}'
            raise errors.ConfigurationError(msg)

    def associate_irule_virtual(self, token, virtual_name):
        '''attach iRule to virtual server

        :param token: challenge token
        :type token: string
        :param virtual_name: virtual server name
        :type virtual_name: string
        :raises errors.ConfigurationError: attach failed
        :return: True if successfull
        :rtype: bool
        '''
        try:
            r = self._split_fullpath(virtual_name)
            irules = self.irules_on_virtual(virtual_name)
            virtual = self.mgmt.tm.ltm.virtuals.virtual.load(
                partition=r[0], subPath=r[1], name=r[2]
            )
            if irules['result'] is True:
                virtual.rules.append(f'/{self.partition}/Certbot-Letsencrypt-{token}')
            else:
                virtual.rules = [f'/{self.partition}/Certbot-Letsencrypt-{token}']
            virtual.update()
            return True

        except Exception as e:
            msg = f'iRule association to virtual server on {self.active_device} failed. {os.linesep}{e}{os.linesep}'
            raise errors.ConfigurationError(msg)

    def remove_irule_virtual(self, token, virtual_name):
        '''remove iRule from virtual server

        :param token: challenge token
        :type token: string
        :param virtual_name: virtual server name
        :type virtual_name: string
        :raises errors.ConfigurationError: removal failed
        :return: True if successfull
        :rtype: bool
        '''
        try:
            r = self._split_fullpath(virtual_name)
            irules = self.irules_on_virtual(virtual_name)
            if irules['result'] is True:
                virtual = self.mgmt.tm.ltm.virtuals.virtual.load(
                    partition=r[0], subPath=r[1], name=r[2]
                )
                if f'/{self.partition}/Certbot-Letsencrypt-{token}' in virtual.rules:
                    virtual.rules.remove(f'/{self.partition}/Certbot-Letsencrypt-{token}')
                    virtual.update()
            return True

        except Exception as e:
            msg = f'iRule removal from virtual server on {self.active_device} failed. {os.linesep}{e}{os.linesep}'
            raise errors.ConfigurationError(msg)


class BigIpCertStorageError(errors.CertStorageError):
    def __init__(self, host: str, e: Exception):
        self.msg = (
            f'Connection to F5 BIG-IP iControl REST API on {host} failed.{os.linesep}'
            f'Error raised was {os.linesep}{e}{os.linesep}'
        )
