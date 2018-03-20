# Copyright (c) 2018 StackHPC Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import os
import unittest

import mock

from ironic_python_agent import errors
from ironic_python_agent import hardware

from stackhpc_ipa_hardware_managers import system_nic

EXPECTED_VERSION = "12.20.1010"

TEST_DIR = os.path.dirname(os.path.abspath(__file__))


def get_dummy_node_info(version=EXPECTED_VERSION, disable='false'):
    return {
        'extra': {
            system_nic._FIRMWARE_CHECK_DISABLE_KEY: disable,
            'nic_firmware': [
                {
                    'vendor_id': '15B3',
                    'device_id': '1013',
                    'firmware_version': version
                }
            ]
        }
    }


def get_lspci_output_multi():
    with open(os.path.join(TEST_DIR, "data/lspci.output"), "r") as f:
        return f.read()


def get_lspci_output_no_match():
    return ""


def get_lspci_output_one_match():
    return \
        'Slot:\t0000:03:00.0\nClass:\t0200\nVendor:\t10ec\nDevice:\t8168\n"' \
        '"SVendor:\t1458\nSDevice:\te000\nRev:\t06\n\n'


def get_ethtool_output():
    with open(os.path.join(TEST_DIR, "data/ethtool.output"), "r") as f:
        return f.read()


class TestSystemNIC(unittest.TestCase):

    def test_get_base_in_relative_path(self):
        result = system_nic._get_base_in_relative_path("one/two/three")
        self.assertEqual("one", result)

    def test_parse_lspci_multi(self):
        lspci_output = get_lspci_output_multi()
        devices = system_nic._parse_lspci_output(lspci_output)
        self.assertGreater(len(devices), 1)

    def test_parse_lspci_no_match(self):
        lspci_output = get_lspci_output_no_match()
        devices = system_nic._parse_lspci_output(lspci_output)
        self.assertEqual(len(devices), 0)

    def test_parse_lspci_one_match(self):
        lspci_output = get_lspci_output_one_match()
        devices = system_nic._parse_lspci_output(lspci_output)
        self.assertEqual(len(devices), 1)

    def test_test_uevent_line_good(self):
        input = "PCI_SLOT_NAME=0000:00:19.0"
        result = system_nic._is_matching_uevent_line(input, "0000:00:19.0")
        self.assertTrue(result)

    def test_test_uevent_line_non_matching_addr(self):
        input = "PCI_SLOT_NAME=0000:00:19.0"
        result = system_nic._is_matching_uevent_line(input, "0000:00:18.0")
        self.assertFalse(result)

    def test_test_uevent_line_wrong_field_name(self):
        input = "GARBAGE=0000:00:19.0"
        result = system_nic._is_matching_uevent_line(input, "0000:00:19.0")
        self.assertFalse(result)

    def test_test_uevent_line_garbage(self):
        input = "GARBAGE STRING"
        result = system_nic._is_matching_uevent_line(input, "0000:00:19.0")
        self.assertFalse(result)

    def test_get_NIC_name(self):
        input = "/sys/class/net/enp3s0/device/uevent"
        result = system_nic._get_NIC_name(input)
        self.assertEqual("enp3s0", result)

    def test_get_ethtool_field(self):
        input = get_ethtool_output()
        result = system_nic._get_ethtool_field(input, "firmware-version")
        self.assertEqual("12.20.1010", result)


class SystemNICHardwareManagerMock(system_nic.SystemNICHardwareManager):

    def get_firmware_mappings(self, vendor_id, device_id):
        return {"enp3s0": "12.20.1010"}


class TestSystemNICManager(unittest.TestCase):

    def setUp(self):
        self.manager = SystemNICHardwareManagerMock()

    def test_evaluate_hardware_support(self):
        actual = self.manager.evaluate_hardware_support()
        self.assertEqual(hardware.HardwareSupport.SERVICE_PROVIDER, actual)

    def test_verify_nic_firmware_disabled(self):
        for value in (True, "true", "on", "y", "yes"):
            self._verify_nic_firmware_disabled(value)

    def test_verify_nic_firmware_explicity_enabled(self):
        for value in (False, "false", "off", "n", "no"):
            node = get_dummy_node_info(disable=value)
            self._verify_nic_firmware(node)

    def test_verify_nic_firmware_enabled(self):
        node = get_dummy_node_info()
        del node['extra'][system_nic._FIRMWARE_CHECK_DISABLE_KEY]
        self._verify_nic_firmware(node)

    def _verify_nic_firmware_disabled(self, value):
        node = get_dummy_node_info(disable=value)
        self.assertFalse(self.manager.verify_nic_firmware(node, None))

    def _verify_nic_firmware(self, node):
        self.assertTrue(
            self.manager.verify_nic_firmware(
                get_dummy_node_info(), None))

    def test_nic_firmware_mismatch(self):
        spoof_version = "will_not_match"
        # clearly different
        self._verify_nic_firmware_mismatch(spoof_version, EXPECTED_VERSION)

    def test_nic_firmware_substrings(self):
        spoof_version = "will_not_match"
        self._verify_nic_firmware_mismatch(
            spoof_version,
            spoof_version[1:]
        )
        self._verify_nic_firmware_mismatch(
            spoof_version,
            spoof_version[:-1]
        )

    def test_nic_firmware_appendix(self):
        spoof_version = "will_not_match"
        self._verify_nic_firmware_mismatch(
            spoof_version,
            spoof_version + "ADDITIONAL"
        )
        self._verify_nic_firmware_mismatch(
            spoof_version + "ADDITIONAL",
            spoof_version
        )
    def test_verify_missing_vendor(self):
        node = get_dummy_node_info()
        del node["extra"]["nic_firmware"][0]["vendor_id"]
        self.assertRaisesRegexp(
            errors.CleaningError,
            "vendor_id",
            self.manager.verify_nic_firmware,
            node,
            None
        )

    def test_verify_missing_device_id(self):
        node = get_dummy_node_info()
        del node["extra"]["nic_firmware"][0]["device_id"]
        self.assertRaisesRegexp(
            errors.CleaningError,
            "device_id",
            self.manager.verify_nic_firmware,
            node,
            None
        )

    def test_verify_missing_firmware_version(self):
        node = get_dummy_node_info()
        del node["extra"]["nic_firmware"][0]["firmware_version"]
        self.assertRaisesRegexp(
            errors.CleaningError,
            "firmware_version",
            self.manager.verify_nic_firmware,
            node,
            None
        );

    @mock.patch.object(SystemNICHardwareManagerMock, 'get_firmware_mappings')
    def _verify_nic_firmware_mismatch(self, expected_version, spoof_version,
                                      mock):
        mock.return_value = {"enp3s0": spoof_version}
        node = get_dummy_node_info(version=expected_version)
        expected_regex = "^(.*\\b{expected}\\b)(.*\\b{actual}\\b).*$" \
            .format(actual=spoof_version, expected=expected_version)
        self.assertRaisesRegexp(
            errors.CleaningError,
            expected_regex,
            self.manager.verify_nic_firmware,
            node,
            None
        )
