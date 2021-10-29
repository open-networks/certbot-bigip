import logging
import os

from certbot_bigip.configurator import BigipConfigurator

logging.basicConfig(level=logging.DEBUG)
mylogger = logging.getLogger(__name__)

email = os.getenv("BIGIP_EMAIL", "test@test.test")
user = os.getenv("BIGIP_USERNAME")
password = os.getenv("BIGIP_PASSWORD")
bigip_list = os.getenv("BIGIP_LIST")
partition = os.getenv("BIGIP_PARTITION", "Intern")
clientssl_parent = os.getenv("BIGIP_CLIENTSSL_PARENT")
vs_list = os.getenv("BIGIP_VS_LIST")
device_group = os.getenv("BIGIP_DEVICE_GROUP", "fail-sync")
iapp = os.getenv("BIGIP_IAPP")
custom_partition = os.getenv("BIGIP_CUSTOM_PARTITION", "Common")
custom_vs_list = os.getenv("BIGIP_CUSTOM_VS_LIST")

from OpenSSL import crypto, SSL


def cert_gen(
    emailAddress="emailAddress",
    commonName="commonName",
    countryName="NT",
    localityName="localityName",
    stateOrProvinceName="stateOrProvinceName",
    organizationName="organizationName",
    organizationUnitName="organizationUnitName",
    serialNumber=0,
    validityStartInSeconds=0,
    validityEndInSeconds=10 * 365 * 24 * 60 * 60,
    KEY_FILE="private.key",
    CERT_FILE="selfsigned.crt",
):
    # can look at generated file using openssl:
    # openssl x509 -inform pem -in selfsigned.crt -noout -text
    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)
    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = countryName
    cert.get_subject().ST = stateOrProvinceName
    cert.get_subject().L = localityName
    cert.get_subject().O = organizationName
    cert.get_subject().OU = organizationUnitName
    cert.get_subject().CN = commonName
    cert.get_subject().emailAddress = emailAddress
    cert.set_serial_number(serialNumber)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(validityEndInSeconds)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, "sha512")
    with open(CERT_FILE, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    with open(KEY_FILE, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))


#########################################################
# Instanciating an object without using the certbot-CLI #
#########################################################


class Config(object):
    def __init__(self):
        self.certbot_bigip_list = bigip_list
        self.certbot_bigip_username = user
        self.certbot_bigip_password = password
        self.certbot_bigip_partition = partition
        self.certbot_bigip_iapp = iapp
        self.certbot_bigip_clientssl_parent = clientssl_parent
        self.certbot_bigip_vs_list = vs_list
        self.certbot_bigip_device_group = device_group
        self.certbot_bigip_apm = False
        self.certbot_bigip_verify_ssl = False
        self.backup_dir = "/tests/backup"
        self.strict_permissions = False
        self.temp_checkpoint_dir = "/tests/backup"
        self.in_progress_dir = "/tests/backup"


def test_upload_cert_to_bigip():
    config = Config()

    configurator = BigipConfigurator(config, "certbot_bigip")
    configurator.prepare()
    configurator.cert_chain_name = "test_chain"

    domain = "test01.certbot.on.at"

    from pathlib import Path

    Path("tests/test_certificates").mkdir(parents=True, exist_ok=True)

    cert_path = "tests/test_certificates/test_certbot_ong_at.pem"
    key_path = "tests/test_certificates/test_certbot_ong_at_key.pem"
    chain_path = "tests/test_certificates/test_chain.pem"

    cert_gen(CERT_FILE=cert_path, KEY_FILE=key_path)

    if configurator.deploy_cert(
        domain,
        cert_path,
        key_path,
        cert_path,
    ):
        assert True
