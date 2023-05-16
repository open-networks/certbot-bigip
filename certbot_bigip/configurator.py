'''Certbot Bigip plugin.'''
import logging
import os
import sys
import time
from collections import defaultdict

from acme import challenges

from certbot import errors
from certbot import interfaces
from certbot.plugins import common

from . import constants
from . import obj

# create a logging format
formatter = logging.Formatter('[%(asctime)s] [%(levelname)8s] [%(name)30s] %(message)s')

streamhandler = logging.StreamHandler()
streamhandler.setLevel(logging.DEBUG)

logging.getLogger('certbot_bigip').addHandler(streamhandler)
logger = logging.getLogger(__name__)


class BigipConfigurator(common.Configurator):
    '''Configurator for BigIP. Deploys certificates to ssl profiles in BigIp.'''

    description = 'F5 BIG-IP - beta!'

    @classmethod
    def add_parser_arguments(cls, add):
        '''Defines Commandline Arguments for the plugin.
        beware that the full name of the argument will be `--certbot-bigip:bigip-<ARGUMENT-NAME>`
        ie. `username` is set with `--certbot-bigip:bigip-username`
        '''
        add(
            'list',
            metavar='bigip1,bigip2',
            default=constants.CLI_DEFAULTS['bigip_list'],
            help='CSV list of BIG-IP system hostnames or addresses, all have to be in the same cluster',
        )
        add(
            'username',
            metavar='USERNAME',
            default=constants.CLI_DEFAULTS['bigip_username'],
            help='BIG-IP username (common to all listed BIG-IP systems)',
        )
        add(
            'password',
            metavar='PASSWORD',
            default=constants.CLI_DEFAULTS['bigip_password'],
            help='BIG-IP password (common to all listed BIG-IP systems)',
        )
        add(
            'partition',
            metavar='PartitionName',
            default=constants.CLI_DEFAULTS['bigip_partition'],
            help='BIG-IP partition (common to all listed BIG-IP systems)',
        )
        add(
            'iapp',
            metavar='Application Service Name',
            default=constants.CLI_DEFAULTS['bigip_iapp'],
            help='BIG-IP partition (common to all listed BIG-IP systems)',
        )
        add(
            'vs-list',
            metavar='vs1,vs2,vs3',
            default=constants.CLI_DEFAULTS['virtual_server_list'],
            help='CSV list of BIG-IP virtual server names, optionally including partition',
        )
        add(
            'clientssl-parent',
            metavar='/Partition/Profile',
            default=constants.CLI_DEFAULTS['bigip_clientssl_parent'],
            help='Client SSL parent profile to inherit default values from',
        )
        add(
            'device-group',
            metavar='sync-failover',
            default=constants.CLI_DEFAULTS['bigip_device_group'],
            help='Device Group to syncronise configuration',
        )
        add(
            'apm',
            metavar='apm',
            default=constants.CLI_DEFAULTS['bigip_apm'],
            help='Is the VS APM enabled or not',
        )
        add(
            'verify-ssl',
            metavar='verify-ssl',
            default=constants.CLI_DEFAULTS['bigip_verify_ssl'],
            help='enable or disable SSL verification of the BIG-IP management API',
        )

    def __init__(self, *args, **kwargs):
        '''Membervariables are initialiyed as empty objects of the coressponding type.
        The only exception is the version parameter which can be parsed.
        '''

        version = kwargs.pop('version', None)
        super(BigipConfigurator, self).__init__(*args, **kwargs)

        # Add name_server association dict
        self.assoc = dict()
        # Outstanding challenges
        self._chall_out = set()
        # Maps enhancements to vhosts we've enabled the enhancement for
        self._enhanced_vhosts = defaultdict(set)

        self.bigip_list = []
        self.bigip_vs_list = []
        self.apm = False

        self.version = version
        self.vservers = None
        self._enhance_func = {}

        self._domain = None
        self.cert_chain_name = None

    def prepare(self):
        '''Prepare the authenticator/installer'''

        if self.conf('username') == '':
            msg = 'No username specified, please use --bigip-username'
            raise errors.MissingCommandlineFlag(msg)

        if self.conf('password') == '':
            msg = 'No password specified, please use --bigip-password'
            raise errors.MissingCommandlineFlag(msg)

        if self.conf('vs_list') != '' and self.conf('vs_list') is not None:
            self.bigip_vs_list = self.conf('vs_list').split(',')
            for vs in self.bigip_vs_list:
                logger.debug(f'Virtual server: {vs}')
        else:
            msg = '--bigip-vs-list is required when using the F5 BIG-IP plugin'
            raise errors.MissingCommandlineFlag(msg)

        self.iapp = ''
        if self.conf('iapp') != '' and self.conf('iapp') is not None:
            self.iapp = self.conf('iapp')

        if self.conf('list') != '':
            self.bigip_host_list = self.conf('list').split(',')
        else:
            msg = '--bigip-list is required when using the F5 BIG-IP plugin'
            raise errors.MissingCommandlineFlag(msg)

        if '--staging' in sys.argv or '--test-cert' in sys.argv:
            self.cert_chain_name = 'staging_chain'
            logger.debug('certbot was called in staging mode')
        else:
            self.cert_chain_name = 'chain'

        if self.conf('apm'):
            self.apm = True

        try:
            self.bigip = obj.Bigip(
                self.bigip_host_list,
                self.conf('username'),
                self.conf('password'),
                self.bigip_vs_list,
                self.conf('device-group'),
                self.conf('partition'),
                self.conf('clientssl-parent'),
                self.conf('verify-ssl'),
            )
        except Exception as e:
            msg = (
                f'Connection to F5 BIG-IP iControl REST API failed.{os.linesep}'
                f'Error raised was {os.linesep}{e}{os.linesep}'
                '(You most probably need to ensure the username and '
                'password is correct. Make sure you use the --bigip-username '
                'and --bigip-password options)'
            )
            raise errors.AuthorizationError(msg)

    def config_test(self):
        '''Does nothing in context of F5 BIG-IP, but must be defined.
        Mandatory member function of parent class.
        '''

        logger.debug('in config_test()')

        return

    def more_info(self):
        '''Human-readable string to help understand the module.
        Mandatory member function of parent class.
        '''

        return (
            'Configures F5 BIG-IP to authenticate and configure X.509'
            'certificate/key use. Only one F5 Cluster addressable.'
        )

    def get_chall_pref(self, domain):
        '''Return list of challenge preferences.
        Currently only HTTP01 is supported.
        Mandatory member function of parent class.
        '''

        return [
            challenges.HTTP01
        ]  # support only HTTP01, DNS01 can be done with DNS module, not implemented now

    def perform(self, achalls):
        '''Perform the configuration related challenge.
        This function currently assumes all challenges will be fulfilled.
        If this turns out not to be the case in the future. Cleanup and
        outstanding challenges will have to be designed better.

        '''

        responses = [None] * len(achalls)

        for count, achall in enumerate(achalls):
            if isinstance(achall.chall, challenges.HTTP01):
                response, validation = achall.response_and_validation()
                token = achall.chall.encode('token')
                responses[count] = response

                bigip = self.bigip
                if not bigip.exists_irule(f'Certbot-Letsencrypt-{token}'):
                    bigip.create_irule_HTTP01(token, validation, self.apm)

                logger.debug(f'DEBUG: VS-List: {self.bigip_vs_list}')
                for virtual_server in self.bigip_vs_list:
                    logger.debug(f'DEBUG: VS: {virtual_server}')
                    try:
                        if bigip.exists_virtual(virtual_server) and bigip.http_virtual(
                            virtual_server
                        ):
                            # virtual server exists and has a HTTP profile attached to it
                            # associate the iRule to it which will respond for HTTP01 validations
                            logger.debug(f'Associating irule with {virtual_server}')
                            bigip.associate_irule_virtual(token, virtual_server)
                            time.sleep(10)
                        else:
                            logger.debug(
                                f'VS {virtual_server} does not exist or has no HTTP profile attached.'
                            )
                            logger.debug('Skipping challenge on this VS')
                            logger.debug(
                                f'exists_virtual: {bigip.exists_virtual(virtual_server)}'
                            )
                            logger.debug(
                                f'http_virtual: {bigip.http_virtual(virtual_server)}'
                            )
                    except Exception as e:
                        msg = (
                            f'Connection to F5 BIG-IP iControl REST API on {self.bigip_host_list[0]} failed.'
                            f'{os.linesep}Error raised was {os.linesep}{e}{os.linesep}'
                        )
                        raise errors.PluginError(msg)

        return responses

    def cleanup(self, achalls):
        '''Revert all challenges.

        :param achalls: challanges
        :type achalls: [type]
        :raises errors.PluginError:
        '''

        for achall in achalls:
            if isinstance(achall.chall, challenges.HTTP01):
                token = achall.chall.encode('token')
                for virtual_server in self.bigip_vs_list:
                    if self.bigip.exists_virtual(virtual_server):
                        if (
                            self.bigip.remove_irule_virtual(token, virtual_server)
                            is not True
                        ):
                            logger.error(
                                f'iRule could not be removed from virtual server {virtual_server} you may need to do this manually'
                            )
                    else:
                        logger.error(
                            f'The virtual server {virtual_server} does not appear to exist on this BIG-IP'
                        )
                try:
                    self.bigip.delete_irule(token)
                except Exception as e:
                    msg = (
                        f'Connection to F5 BIG-IP iControl REST API on {self.bigip_host_list[0]} failed.{os.linesep}'
                        f'Error raised was {os.linesep}{e}{os.linesep}'
                    )
                    raise errors.PluginError(msg)
            elif isinstance(achall.chall, challenges.DNS01):
                pass

        return

    def get_all_names(self):
        '''Cannot currently work for F5 BIG-IP due to the way in which Cerbot validates
        returned strings as conforming to host/domain name format. e.g. F5 BIG-IP virtual
        server names are not always in pure host/domain name.

        :raises errors.PluginError: Always

        '''

        msg = (
            'Certbot can\'t be used to select domain names based on F5 '
            f'BIG-IP Virtual Server names.{os.linesep}{os.linesep}Please use CLI arguments, '
            'example: --bigip-vs-list virtual_name1,virtual_name2 --domain '
            'domain.name'
        )

        raise errors.PluginError(msg)

    def deploy_cert(
        self, domain, cert_path, key_path, chain_path=None, fullchain_path=None
    ):
        '''Deploys certificate and key to specified F5 BIG-IP, creates or updates
        client SSL profiles, and ensures they are associated with the specified
        virtual server.

        NOTE: This gets run for EVERY primary certificate name and every subjectAltName
              in a certificate. Need to improve efficiency within F5 BIG-IP config by
              not creating lots of duplicates of certs/keys.

        :raises errors.PluginError: When unable to deploy certificate due to
            a lack of directives
        '''

        logger.debug('Deploying on bigip')
        bigip = self.bigip

        logger.debug('Uploading certificates to bigip')
        bigip.upload_file(cert_path)
        bigip.upload_file(key_path)
        bigip.upload_file(chain_path)

        logger.debug('deploying certs and keys on bigip')
        bigip.update_crypto(
            domain.replace('.', '_').replace('*', 'wildcard'),
            cert_path,
            key_path,
            chain_path,
            self.cert_chain_name,
        )
        logger.debug('Deployed Succesfully')

        logger.debug('Updating Client SSL Profile')

        bigip.update_clientssl_profile(
            domain.replace('.', '_').replace('*', 'wildcard'),
            self.bigip_vs_list[0],
            self.iapp,
        )
        logger.debug('Successfully Updated Client SSL Profile')

        return True

    def renew_deploy(self, lineage, *args, **kwargs): # pylint: disable=missing-docstring,no-self-use
        '''
        Renew certificates when calling `certbot renew`
        '''

        # Run deploy_cert with the lineage params
        self.deploy_cert(lineage.names()[0], lineage.cert_path, lineage.key_path, lineage.chain_path, lineage.fullchain_path)

        return


    def enhance(self, domain, enhancement, options=None):
        '''Enhance configuration.

        :param str domain: domain to enhance
        :param str enhancement: enhancement type defined in
            :const:`~certbot.constants.ENHANCEMENTS`
        :param options: options for the enhancement
            See :const:`~certbot.constants.ENHANCEMENTS`
            documentation for appropriate parameter.

        :raises .errors.PluginError: If Enhancement is not supported, or if
            there is any other problem with the enhancement.

        '''

        logger.debug(
            f'DEBUG: enhance(domain={domain}, enhancement={enhancement}, options={options})'
        )

        return

    def supported_enhancements(self):  # pylint: disable=no-self-use
        '''Returns currently supported enhancements.
        Mandatory member function of parent class.
        '''

        # return ['ensure-http-header', 'redirect', 'staple-ocsp']
        return []

    def get_all_certs_keys(self):
        '''Does nothing in context of F5 BIG-IP, but must be defined.
        Mandatory member function of parent class.
        '''
        logger.debug('DEBUG: in get_all_certs_keys()')
        return []

    def save(self, title=None, temporary=False):
        '''Saves all changes to all F5 BIG-IP's, e.g. tmsh /sys save config.

        This function first checks for save errors, if none are found,
        all configuration changes made will be saved. According to the
        function parameters. If an exception is raised, a new checkpoint
        was not created.

        :param str title: The title of the save. If a title is given, a UCS
            archive will be created.

        :param bool temporary: Indicates whether the changes made will
            be quickly reversed in the future (ie. challenges)

        :raises .errors.PluginError: If there was an error in Augeas, in
            an attempt to save the configuration, or an error creating a
            checkpoint
        '''
        bigip = self.bigip

        if temporary is False:
            bigip.save()

        return

    def revert_challenge_config(self):
        '''Does nothing in context of F5 BIG-IP, but must be defined.
        Mandatory member function of parent class.
        '''
        logger.debug('DEBUG: in revert_challenge_config()')
        return

    def rollback_checkpoints(self, rollback=1):
        '''Does nothing in context of F5 BIG-IP, but must be defined.
        Mandatory member function of parent class.
        '''
        logger.debug('DEBUG: in rollback_checkpoints()')
        return

    def recovery_routine(self):
        '''Does nothing in context of F5 BIG-IP, but must be defined.
        Mandatory member function of parent class.
        '''
        logger.debug('DEBUG: in recovery_routine()')
        return

    def view_config_changes(self):
        '''Does nothing in context of F5 BIG-IP, but must be defined.
        Mandatory member function of parent class.
        '''
        logger.debug('DEBUG: in view_config_changes()')
        return

    def restart(self):
        '''Does nothing in context of F5 BIG-IP, but must be defined.
        Mandatory member function of parent class.
        '''
        return

interfaces.RenewDeployer.register(BigipConfigurator)