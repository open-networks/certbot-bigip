"""
This test the deployment of several integration test
"""

import subprocess
import re
import logging
import ssl
import socket
import os
import pytest

logging.basicConfig(level=logging.DEBUG)
mylogger = logging.getLogger(__name__)

email = os.getenv("BIGIP_EMAIL", "test@test.test")
user = os.getenv("BIGIP_USERNAME")
password = os.getenv("BIGIP_PASSWORD")
bigip_list = os.getenv("BIGIP_LIST")
partition = os.getenv("BIGIP_PARTITION")
clientssl_parent = os.getenv("BIGIP_CLIENTSSL_PARENT")
vs_list = os.getenv("BIGIP_VS_LIST")
device_group = os.getenv("BIGIP_DEVICE_GROUP", "fail-sync")
iapp = os.getenv("BIGIP_IAPP")
custom_partition = os.getenv("BIGIP_CUSTOM_PARTITION", "Common")
custom_vs_list = os.getenv("BIGIP_CUSTOM_VS_LIST")


def validate_certbot_certificate_delivery(stdout: str, stderr: str):
    # from https://www.regextester.com/96683
    regex_date = r"([12]\d{3}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01]))"
    regex_cert_expire_indicator = "(?<=certificate expires on )"
    regex_check_result = regex_cert_expire_indicator + regex_date
    match = re.search(regex_check_result, stdout)
    if match is not None:
        mylogger.info("New Certificate was created. Expiration Date: " + match.group(1))
        return True
    else:
        mylogger.error(
            "Certificate aquirement failed: \n stdout:\n"
            + stdout
            + "\n sterr:\n"
            + stderr
        )
        return False


def validate_certbot_certificate_delivery_renew(stdout: str, stderr: str):
    # from https://www.regextester.com/96683
    regex_check_result = "(?<=Congratulations, all renewals succeeded)"
    match = re.search(regex_check_result, stdout)
    if match is not None:
        mylogger.info("Renewal succeded")
        return True
    else:
        mylogger.error(
            "Certificate aquirement failed: \n stdout:\n"
            + stdout
            + "\n sterr:\n"
            + stderr
        )
        return False

def get_certbot_certificate(domain: str):
    file_path = f"/etc/letsencrypt/live/{domain}/cert.pem"

    with open(file_path, "r") as cert_file:
        return cert_file.read()


def is_delivered_cert_equal_deployed_cert(domain):
    # check if certificate has been deployed
    delivered_cert = get_certbot_certificate(domain)
    socket.setdefaulttimeout(
        5
    )  # set the timeout low to fail quickly if no certificate is served by the server

    # use sni in ssl communication
    port = 443
    conn = ssl.create_connection((domain, port))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    sock = context.wrap_socket(conn, server_hostname=domain)
    deployed_cert = ssl.DER_cert_to_PEM_cert(sock.getpeercert(True))
    mylogger.debug(f"delivered_cert: \n {delivered_cert}")
    mylogger.debug(f"deployed_cert: \n {deployed_cert}")
    return delivered_cert == deployed_cert


def test_response_evaluation():
    stdout_sample = 'Successfully received certificate.\nCertificate is saved at: /etc/letsencrypt/live/example.on.at/fullchain.pem\nKey is saved at:         /etc/letsencrypt/live/example.on.at/privkey.pem\nThis certificate expires on 2023-04-25.\nThese files will be updated when the certificate renews.'
    stderr_sample = ""
    validate_certbot_certificate_delivery(stdout_sample, stderr_sample)


def test_certbot_bigip_server_cert():
    domain = "test01.certbot.on.at"
    response = subprocess.run(
        (
            f"certbot --non-interactive --expand --email '{email}' --agree-tos"
            " -a bigip -i bigip"
            f" --bigip-list '{bigip_list}'"
            f" --bigip-username '{user}'"
            f" --bigip-password '{password}'"
            f" --bigip-partition '{partition}'"
            f" --bigip-clientssl-parent '{clientssl_parent}'"
            f" --bigip-vs-list '{vs_list}'"
            f" --bigip-device-group '{device_group}'"
            f" --bigip-iapp '{iapp}'"
            f" -d {domain}"
            " -v --staging --debug --force-renewal"
        ),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
    )

    mylogger.debug(response.stdout.decode("utf-8"))

    # check if new certificate was created
    if not validate_certbot_certificate_delivery(
        response.stdout.decode("utf-8"), response.stderr.decode("utf-8")
    ):
        assert False
    # check if process has finished correctly
    response.check_returncode()

    # check if certificate has been deployed
    assert is_delivered_cert_equal_deployed_cert(
        domain
    ), "did you assign the ssl profile to the virtualserver? this step is not automated."


def test_certbot_bigip_server_cert_renew():
    domain = "test01.certbot.on.at"
    response = subprocess.run(
        (
            f"certbot renew --force-renewal"
        ),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
    )

    mylogger.debug(response.stdout.decode("utf-8"))

    # check if new certificate was created
    if not validate_certbot_certificate_delivery_renew(
        response.stdout.decode("utf-8"), response.stderr.decode("utf-8")
    ):
        assert False
    # check if process has finished correctly
    response.check_returncode()

    # check if certificate has been deployed
    assert is_delivered_cert_equal_deployed_cert(
        domain
    ), "did you assign the ssl profile to the virtualserver? this step is not automated."


def test_certbot_bigip_deployment_in_custompartition_and_folders():
    domain = "test02.certbot.on.at"
    response = subprocess.run(
        (
            f"certbot --non-interactive --expand --email '{email}' --agree-tos"
            " -a bigip -i bigip"
            f" --bigip-list '{bigip_list}'"
            f" --bigip-username '{user}'"
            f" --bigip-password '{password}'"
            f" --bigip-partition '{custom_partition}'"
            f" --bigip-clientssl-parent '{clientssl_parent}'"
            f" --bigip-vs-list '{custom_vs_list}'"
            f" --bigip-device-group '{device_group}'"
            f" -d {domain}"
            " -v --staging --debug --force-renewal"
        ),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
    )

    # check if new certificate was created
    if not validate_certbot_certificate_delivery(
        response.stdout.decode("utf-8"), response.stderr.decode("utf-8")
    ):
        assert False

    # check if process has finished correctly
    response.check_returncode()

    # check if certificate has been deployed
    assert is_delivered_cert_equal_deployed_cert(
        domain
    ), "did you assign the ssl profile to the virtualserver? this step is not automated."


@pytest.mark.skip(reason="no way of currently testing this")
def test_wildcard_deployment_with_bluecat_validation():
    domain = "*.certbot.on.at"
    response = subprocess.run(
        (
            "certbot"
            " --non-interactive"
            f" -d {domain}"
            " --staging"
            " --expand"
            f" --email '{email}'"
            " --agree-tos"
            " --no-eff-email"
            " -v"
            " --debug"
            " --force-renewal"
            # authentication
            " -a bluecat"
            " -i bigip"
            f" --bigip-list '{bigip_list}'"
            f" --bigip-username '{user}'"
            f" --bigip-password '{password}'"
            f" --bigip-partition '{partition}'"
            f" --bigip-clientssl-parent '{clientssl_parent}'"
            f" --bigip-vs-list '{vs_list}'"
            f" --bigip-device-group '{device_group}'"
            f" --bigip-iapp '{iapp}'"
        ),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
    )

    # check if new certificate was created
    if not validate_certbot_certificate_delivery(
        response.stdout.decode("utf-8"), response.stderr.decode("utf-8")
    ):
        assert False

    # check if process has finished correctly
    response.check_returncode()

    # check if certificate has been deployed
    assert is_delivered_cert_equal_deployed_cert(
        domain.strip("*.")
    ), "did you assign the ssl profile to the virtualserver? this step is not automated."
