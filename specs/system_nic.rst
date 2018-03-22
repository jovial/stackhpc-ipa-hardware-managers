..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

============================================
Automated Network Interface Firmware Checker
============================================

This document proposes an extension to the stackhpc-ipa-hardware-managers
disk image builder element to facilitate automated checking of network
interface firmware.

Problem description
===================

It is difficult to manually verify that all network interface cards in a
cluster are running the same firmware version. This can lead to hard to debug
issues if a firmware bug is present and only a subset of nodes are running
that version.

Use Cases
---------

It is intended to allow baremetal openstack cloud providers to ensure that
the hardware is in a consistent state with regards to the firmware version of
the network cards.

Proposed change
===============

A new python module, called `system_nic`, will be added to the
`stackhpc-ipa-hardware-managers` disk image builder (DIB) element. The
module should provide a hardware manager that adds a network card firmware
verification cleaning step. The step will be called `verify_nic_firmware` and
will be described in detail below.

The module should discriminate network cards based on their pci-id. The pci-id
consists of a unique `(vendor_id, device_id)` pair. It is proposed that, in
order to negate operational differences, all of the devices should run the same
version of the firmware. To ensure that this condition is enforced, the
hardware manager must be given an expected firmware version; this will be
compared against the version detected during cleaning. The expected version
will provided to the manager together with the unique pci id to form a
so called matching rule.

If a network card is present, and a matching rule exists with the same pci-id,
that card will be required to be running the version of the firmware specified
by the matching rule. The following scenarios should be considered cleaning
errors:

* a device is present and it's firmware version doesn't match the version
  specified in the corresponding matching rule

* a firmware matching rule exists, but no card exists with the pci-id from
  that rule. This helps prevent configuration errors where a mistake is made
  in the matching criteria. The responsibility to ensure that the correct
  number of devices are present is beyond the scope of the module and would
  be better handled by another hardware manager running with higher priority

* the manager is provided with an invalid matching rule (specified below)

The following scenarios should pass cleaning:

* a card exists, but no matching rule with the corresponding pci-id is found.
  This allows you to only check a subset of the network cards, and skip for
  example unused interfaces

* a flag is set to disable verification, and a normal failure condition is
  triggered (see below)

Matching rules will be provided to the hardware manager by setting a property
on the ironic node. It should be possible to specify more than one device to
check. The property should be of the form:

.. code-block::

  "extra": {
    "nic_firmware": [
      {
        "vendor_id": "<vendor_id>",
        "device_id": "<device_id>",
        "firmware_version": "<firmware_version>"
      }
    ]
  }

To minimise dependencies the list of network devices can be obtained from
sysfs. A listing of all cards is located in `/sys/class/net/`. It is possible
to parse `sys/class/net/*/device/uevent` to obtain the pci-id for a network
card in the wildcard position. `ethtool` can then be used to obtain the
firmware version.

In a heterogeneous cluster, it may be desirable to disable checking for a
subset of the node. In order to allow this, the `disable_nic_firmware_check`
flag can be set in the ironic node info. This will stop checking entirely and
cleaing should always pass.


Alternatives
------------

* It is possible to carry on manually checking firmware versions
* It is possible to use the json output of `lshw` instead of `ethtool`


References
==========

* `Reference implementation pull request`__.

.. __: https://github.com/stackhpc/stackhpc-ipa-hardware-managers/pull/5