# Copyright 2015 Rackspace, Inc.
# Copyright 2018 StackHPC Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import glob
import os
from collections import namedtuple

from ironic_python_agent import errors
from ironic_python_agent import hardware
from ironic_python_agent import utils

from oslo_concurrency import processutils
from oslo_log import log
from oslo_utils import strutils

_FIRMWARE_CHECK_DISABLE_KEY = 'disable_nic_firmware_check'
_HELP_MSG_EXAMPLE = (
    "For cleaning to proceed, you must set the property "
    "'nic_firmware' in the node's extra field, for example:\n"
    "$ openstack baremetal node set $NODE_ID --extra "
    """nic_firmware='[{"vendor_id": "15B3","device_id": " "1013","""
    """firmware_version": "12.20.1019"}]'"""
)

_UEVENT_PCI_SLOT_NAME_PREFIX = "PCI_SLOT_NAME="

LOG = log.getLogger()


def _get_lspci_output(vendor_id=None, device_id=None, **kwargs):
    device_filter_arg = ""
    if vendor_id or device_id:
        device_filter_arg = "-d " + _get_device_filter_string(vendor_id,
                                                              device_id)
    kwargs["shell"] = True
    try:
        lspci_output, _e = utils.execute(
            "lspci -vmmnD {filter}".format(filter=device_filter_arg), **kwargs)
    except (processutils.ProcessExecutionError, OSError) as e:
        raise errors.CleaningError(
            "The command: lspci failed to execute when performing NIC "
            "firmware check. {}".format(e)
        )
    return lspci_output


def _parse_lspci_output(lspci_output):
    """Converts raw output of *lspci* into a dictionary of fields to values

    The lspci_output must be in the verbose machine readable format i.e you
    must use the -vmm flags. This is so the output remains stable between
    versions. An example input would be::

        Slot:	0000:00:00.0
        Class:	0600
        Vendor:	8086
        Device:	6f00
        SVendor:	8086
        SDevice:	0000
        Rev:	01
        NUMANode:	0


    Please see the *lspci* man page for more details.

    :param lspci_output: machine readable output of lspci
    :return: dictionary of fields to values
    """
    all_records = lspci_output.split("\n\n")
    devices = []
    for record_str in all_records:
        if record_str == "":
            continue
        fields_raw = record_str.splitlines()
        fields = map((lambda x: x.split(":\t")), fields_raw)
        devices.append(dict(list(map(tuple, fields))))
    return devices


def _get_device_filter_string(vendor_id, device_id):
    device_id_str = ""
    device_id_str += vendor_id or ""
    device_id_str += ":"
    device_id_str += device_id or ""
    return device_id_str


def _get_base_in_relative_path(path):
    # given relative path, returns the base element, e.g one/two/three,
    # returns one
    if os.path.isabs(path):
        raise ValueError("path must be relative")
    return path.split(os.sep)[0]


def _pci_addr_to_net_interface(pci_addr):
    # The pci slot name of all network cards can be determined by reading
    # /sys/class/net/*/device/uevent, and looking at the line beginning with
    # PCI_SLOT_NAME.
    for uevent_file in glob.glob("/sys/class/net/*/device/uevent"):
        with open(uevent_file, "r") as f:
            for line in f.readlines():
                if _is_matching_uevent_line(line, pci_addr):
                    return _get_NIC_name(uevent_file)


def _is_matching_uevent_line(line, pci_addr):
    # example good input : "PCI_SLOT_NAME=0000:00:19.0\n"
    if line.startswith(_UEVENT_PCI_SLOT_NAME_PREFIX):
        slot_name = line.lstrip(_UEVENT_PCI_SLOT_NAME_PREFIX).strip()
        if slot_name == pci_addr:
            return True
    return False


def _get_NIC_name(uevent_file):
    # network card name appears in wildcard position of the
    # /sys/class/net/*/device/uevent glob
    relative_path = os.path.relpath(uevent_file, "/sys/class/net/")
    return _get_base_in_relative_path(relative_path)


def _get_ethtool_output(dev, **kwargs):
    kwargs["shell"] = True
    try:
        ethtool_output, _e = utils.execute(
            "ethtool -i {device}".format(device=dev),
            **kwargs)
    except (processutils.ProcessExecutionError, OSError) as e:
        raise errors.CleaningError(
            "The command: ethtool failed to execute when performing NIC "
            "firmware check. {}".format(e)
        )
    return ethtool_output


def _get_ethtool_field(ethtool_output, field):
    # given the example ethtool_output:
    #
    #   driver: mlx5_core
    #   version: 3.0-1 (January 2015)
    #   firmware-version: 12.20.1010
    #   expansion-rom-version:
    #   bus-info: 0000:03:00.1
    #   supports-statistics: yes
    #   supports-test: yes
    #   supports-eeprom-access: no
    #   supports-register-dump: no
    #   supports-priv-flags: yes
    #
    # the available fields are driver, version, firmware-version, etc.
    for line in ethtool_output.splitlines():
        (candidate_field, value) = tuple(line.split(": "))
        if candidate_field == field:
            return value


def _get_expected_field(firmware_matcher, field):
    try:
        value = firmware_matcher[field]
    except KeyError:
        raise errors.CleaningError(
            "Expected field '{0}' not found. You should make sure all items"
            " in the nic_firmware list contain the field: {0}".format(field))
    return value


def _is_nic_verification_disabled(node):
    disable_check = node['extra'].get(_FIRMWARE_CHECK_DISABLE_KEY)
    return strutils.bool_from_string(
        disable_check) if disable_check is not None else False


NICFirmwareVerifyResult = namedtuple(
    'NICFirmwareVerifyResult',
    'actual_version expected_version '
    'matcher')


class SystemNICHardwareManager(hardware.HardwareManager):
    """Checks firmware version for a given network card"""

    HARDWARE_MANAGER_VERSION = "1.0"

    def evaluate_hardware_support(self):
        """Declare whether the system is supported by this manager.

        :returns: HardwareSupport level for this manager.
        """
        # This should work for anything which supports ethtool, lspci
        return hardware.HardwareSupport.SERVICE_PROVIDER

    def get_clean_steps(self, node, ports):
        """Get a list of clean steps with priority.

        :param node: The node object as provided by Ironic.
        :param ports: Port objects as provided by Ironic.
        :returns: A list of cleaning steps, as a list of dicts.
        """
        return [{'step': 'verify_nic_firmware',
                 'priority': 90,
                 'interface': 'deploy',
                 'reboot_requested': False,
                 'abortable': True}]

    def get_firmware_mappings(self, vendor_id, device_id):
        """Get a dictionary of interface names to firmware version

        :param vendor_id: string containing numeric representation of
                          pci vendor id
        :param device_id: string containing numeric representation of
                          pci device id
        :return: a dictionary mapping the interface name to the firmware
                 version for all interfaces matching vendor_id and device_id
        """
        # there might be multiple identical cards, we must check them all
        devices = _parse_lspci_output(
            _get_lspci_output(vendor_id, device_id))
        interfaces = []
        for device in devices:
            interface_name = _pci_addr_to_net_interface(device['Slot'])
            if interface_name is None:
                raise errors.CleaningError(
                    "Could not network determine interface name. The pci_id "
                    "was: {vendor_id}:{device_id}. Does this correspond to a "
                    "network card?"
                    .format(vendor_id=vendor_id, device_id=device_id))
            interfaces.append(interface_name)
        return dict(map(lambda x: (x, _get_ethtool_field(
            _get_ethtool_output(x), "firmware-version")), interfaces))

    def verify_nic_firmware(self, node, ports):
        """
        Verify all firmware versions specified by the nic_firmware property.

        The nic_firmware property should take the form of a json list of
        firmware matching criteria. The firmware matching criteria should
        be a dictionary containing the following required fields:

        - vendor_id : numeric pci vendor id
        - device_id : numeric pci device id
        - firmware_version : expected firmware version

        the values of all fields should be strings. An example is given below::

            [
                { "vendor_id": "15B3", "device_id": "1013",
                  "firmware_version": "12.20.1010" }
            ]

        The nic_firmware property can be manually set on a given node, as shown
        in this example::

              openstack baremetal node set $NODE_ID --extra \\
              nic_firmware='[{"vendor_id": "15B3", "device_id": "1013", \\
              "firmware_version": "12.20.1010"}]'

        Each network card is checked against each of the items in the matching
        criteria list. If the device and vendor ids match, the firmware version
        is checked against the expected version specified in the
        nic_firmware property's firmware_version field.

        """

        if _is_nic_verification_disabled(node):
            LOG.warning('NIC firmware version verification has been disabled.')
            return False

        if "extra" not in node or "nic_firmware" not in node["extra"]:
            raise errors.CleaningError(
                "Expected property 'nic_firmware' not found. " +
                _HELP_MSG_EXAMPLE)

        firmware_matchers = node["extra"]["nic_firmware"]

        if not isinstance(firmware_matchers, list):
            raise errors.CleaningError(
                "The property 'nic_firmware' should be a list. " +
                _HELP_MSG_EXAMPLE
            )

        successes = {}
        failures = {}
        for firmware_matcher in firmware_matchers:
            result = self.process_firmware_matcher(firmware_matcher)
            successes.update(result[0])
            failures.update(result[1])

        error_msgs = []
        for interface, result in failures.iteritems():
                msg = (
                    "Firmware version mismatch for card: {interface}. The "
                    "expected version was: {expected_version}, "
                    "but the actual version was {actual_version}. "
                    "The matcher that failed was {matcher}"
                    ).format(
                    interface=interface,
                    expected_version=result.expected_version,
                    actual_version=result.actual_version,
                    matcher=result.matcher)
                error_msgs.append(msg)

        if failures:
            raise errors.CleaningError(
                "Found {} firmware version mismatches "
                "when verifying NIC firmware. The errors were: \n"
                .format(len(error_msgs)) +
                 "\n".join(error_msgs)
            )

        return successes

    def process_firmware_matcher(self, matcher):
        """Processes all interfaces matching the given criteria

        The matcher dictionary should contain the following strings:

        * vendor_id : a numeric pci vendor id
        * device_id: a numeric pci device id
        * firmware_version: expected firmware version

        :param matcher: dictionary of matching criteria
        :return: tuple with the structure (successes, failures) where,
                 *successes* and *failures* are dictionaries mapping the
                 interface name to a NICFirmwareVerifyResult
        """
        device_id = _get_expected_field(matcher, "device_id")
        vendor_id = _get_expected_field(matcher, "vendor_id")
        expected_version = _get_expected_field(matcher, "firmware_version")
        interface_to_version_map = self.get_firmware_mappings(vendor_id,
                                                              device_id)
        successes = {}
        failures = {}
        for interface_name, actual_version in interface_to_version_map.items():
            if actual_version == expected_version:
                LOG.debug("firmware version matches for interface: {}".format(
                    interface_name))
                successes[interface_name] = NICFirmwareVerifyResult(
                    actual_version,
                    expected_version,
                    matcher
                )
            else:
                failures[interface_name] = NICFirmwareVerifyResult(
                    actual_version,
                    expected_version,
                    matcher
                )
        return (successes, failures)
