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

from ironic_python_agent import errors
from ironic_python_agent import hardware
from ironic_python_agent import utils

from oslo_concurrency import processutils
from oslo_log import log

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
    except (processutils.ProcessExecutionError, OSError):
        raise errors.CleaningError("Unable to run lspci")
    return lspci_output


def _parse_lspci_output(lspci_output):
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
    dirname = os.path.dirname(path)
    if dirname == "":
        return path
    else:
        return _get_base_in_relative_path(dirname)


def _pci_addr_to_net_interface(pci_addr):
    for uevent_file in glob.glob("/sys/class/net/*/device/uevent"):
        with open(uevent_file, "r") as f:
            for line in f.readlines():
                if _is_matching_uevent_line(line, pci_addr):
                    return _get_NIC_name(uevent_file)


def _is_matching_uevent_line(line, pci_addr):
    if line.startswith(_UEVENT_PCI_SLOT_NAME_PREFIX):
        # example : "PCI_SLOT_NAME=0000:00:19.0\n"
        slot_name = line.lstrip(_UEVENT_PCI_SLOT_NAME_PREFIX).strip()
        if slot_name == pci_addr:
            return True
    return False


def _get_NIC_name(uevent_file):
    relative_path = os.path.relpath(uevent_file, "/sys/class/net/")
    return _get_base_in_relative_path(relative_path)


def _get_ethtool_output(dev, **kwargs):
    kwargs["shell"] = True
    try:
        ethtool_output, _e = utils.execute(
            "ethtool -i {device}".format(device=dev),
            **kwargs)
    except (processutils.ProcessExecutionError, OSError):
        raise errors.CleaningError("Unable to run ethtool")
    return ethtool_output


def _get_ethtool_field(ethtool_output, field):
    for line in ethtool_output.splitlines():
        (candidate_field, value) = tuple(line.split(": "))
        if candidate_field == field:
            return value


def _get_expected_property(node, node_property):
    try:
        expected_property = node[node_property]
    except KeyError:
        raise errors.CleaningError(
            "Expected property '{0}' not found. You should make sure all items"
            " in the nic_firmware list contain {0}".format(node_property))
    return expected_property


def _get_nic_firmware_versions(vendor_id, device_id):
    # there might be multiple identical cards, we must check them all
    devices = _parse_lspci_output(_get_lspci_output(vendor_id, device_id))
    interfaces = []
    for device in devices:
        interface_name = _pci_addr_to_net_interface(device['Slot'])
        if interface_name is None:
            raise errors.CleaningError(
                "Could not determine network interface name. The pci_id was: "
                "{vendor_id}:{device_id}. Does this correspond to a network "
                "card?".format(vendor_id=vendor_id, device_id=device_id))
        interfaces.append(interface_name)
    return dict(map(lambda x: (
        x, _get_ethtool_field(_get_ethtool_output(x), "firmware-version")),
        interfaces))


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
        """

        # dirty hack to get node structure
        raise errors.CleaningError(repr(node))

        if "extra" not in node or "nic_firmware" not in node["extra"]:
            LOG.warning(
                "NIC firmware property has not been set. No firmware will be "
                "verified")
            return True

        firmwares = node["extra"]["nic_firmware"]

        for firmware in firmwares:
            self.process_firmware_descriptor(firmware)

    def process_firmware_descriptor(self, firmware):
        device_id = _get_expected_property(firmware, "device_id")
        vendor_id = _get_expected_property(firmware, "vendor_id")
        expected_version = _get_expected_property(firmware, "firmware_version")
        interface_to_version_map = self.get_firmware_mappings(vendor_id,
                                                              device_id)
        for interface_name, actual_version in interface_to_version_map.items():
            if actual_version == expected_version:
                LOG.debug("firmware version matches for interface: {}".format(
                    interface_name))
            else:
                raise errors.CleaningError(
                    "Firmware version mismatch for card: {interface}. The "
                    "expected version was: {expected_version}, "
                    "but the actual version was {actual_version}".format(
                        interface=interface_name,
                        expected_version=expected_version,
                        actual_version=actual_version))

# if __name__ == "__main__":
# Access to some parts of the PCI configuration space is restricted to
# root on many operating systems, so the features of lspci available to
# normal users are limited

# print(_get_lspci_output(None,None,run_as_root=True, root_helper="sudo"))
# print repr(_get_ethtool_output("enp3s0"))
# print repr(_get_lspci_output("10ec", None))
# print _get_nic_firmware_versions("10EC", "8168")
