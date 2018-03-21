==============================
stackhpc-ipa-hardware-managers
==============================

.. image:: https://travis-ci.org/stackhpc/stackhpc-ipa-hardware-managers.svg?branch=master
    :target: https://travis-ci.org/stackhpc/stackhpc-ipa-hardware-managers

A collection of hardware managers for the Ironic Python Agent.

system_bios
-----------

A simple hardware manager for checking the system BIOS version against
a version specified in the Ironic node info. The following node info
is expected to be set:

.. code-block::

    'extra': {
        'system_vendor': {
            'product_name': 'PowerEdge R630',
            'bios_version': '2.3.4'
        }
    }

The following examples may be used to set the node info.

* To set multiple fields at once:

    .. code-block::

        openstack baremetal node set $NODE_ID --extra system_vendor='{"product_name": "PowerEdge R630", "bios_version": "2.6.0"}'

* To set a single field:

    .. code-block::

        openstack baremetal node set $NODE_ID --extra system_vendor/bios_version=1.0

The hardware manager should be supported by any system which supports
returning the product name and BIOS version via dmidecode.

In the case that you wish to disable the hardware manager for specific nodes,
you can set the following property in the nodes extra info:

.. code-block::

    openstack baremetal node set $NODE_ID --extra disable_bios_version_check=True

If you wish to re-enable the hardware manager, you can either unset the property, or
set it to `False`. For example:

.. code-block::

    openstack baremetal node set $NODE_ID --extra disable_bios_version_check=False

or:

.. code-block::

    openstack baremetal node unset $NODE_ID --extra disable_bios_version_check

system_nic
-----------

Provides a hardware manager to verify the firmware version of network interface
cards against a list of expected versions in the Ironic node info. The following
node info is expected to be set:

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

Below is an example of how to set the node info:

.. code-block::

   openstack baremetal node set $NODE_ID --extra nic_firmware='[{"vendor_id": "15B3", "device_id": "1013", "firmware_version": "12.20.1010"}]'

The hardware manager should work with any network card that supports returning
the firmware-version with `ethtool`.

In the case that you wish to disable the hardware manager for specific nodes,
you can set the following property in the nodes extra info:

.. code-block::

    openstack baremetal node set $NODE_ID --extra disable_nic_firmware_check=True

If you wish to re-enable the hardware manager, you can either unset the property, or
set it to `False`. For example:

.. code-block::

    openstack baremetal node unset $NODE_ID --extra disable_nic_firmware_check


Credits
-------

Based on the example hardware manager project by Jay Faulkner:

https://github.com/openstack/ipa-example-hardware-managers
