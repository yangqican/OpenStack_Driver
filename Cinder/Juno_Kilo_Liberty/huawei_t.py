# Copyright (c) 2013 Huawei Technologies Co., Ltd.
# Copyright (c) 2012 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
"""
Volume Drivers for Huawei OceanStor T series storage arrays.
"""

try:
    from oslo_config import cfg
    from oslo_log import log as logging
    from oslo_utils import excutils
except ImportError:
    from cinder.openstack.common import log as logging
    from oslo.config import cfg
    from oslo.utils import excutils

from cinder import exception
from cinder.i18n import _
from cinder.i18n import _LE
from cinder.i18n import _LW
from cinder.volume import driver
from cinder.volume.drivers.huawei import huawei_utils
from cinder.volume.drivers.huawei import ssh_client


LOG = logging.getLogger(__name__)


huawei_opt = [
    cfg.StrOpt('cinder_huawei_conf_file',
               default='/etc/cinder/cinder_huawei_conf.xml',
               help='The configuration file for the Cinder Huawei driver.')]

CONF = cfg.CONF
CONF.register_opts(huawei_opt)


class HuaweiTISCSIDriver(driver.ISCSIDriver):
    """ISCSI driver for Huawei OceanStor T series storage arrays."""

    VERSION = '1.1.0'

    def __init__(self, *args, **kwargs):
        super(HuaweiTISCSIDriver, self).__init__(*args, **kwargs)
        self.configuration = kwargs.get('configuration', None)
        if not self.configuration:
            msg = (_('_instantiate_driver: configuration not found.'))
            raise exception.InvalidInput(reason=msg)

        self.configuration.append_config_values(huawei_opt)

    def do_setup(self, context):
        """Instantiate common class."""
        self.sshclient = ssh_client.TseriesClient(configuration=
                                                  self.configuration)
        self.sshclient.do_setup(context)

    def check_for_setup_error(self):
        """Check something while starting."""
        self.sshclient.check_for_setup_error()

    def create_volume(self, volume):
        """Create a new volume."""
        volume_id = self.sshclient.create_volume(volume)
        return {'provider_location': volume_id}

    def create_volume_from_snapshot(self, volume, snapshot):
        """Create a volume from a snapshot."""
        volume_id = (
            self.sshclient.create_volume_from_snapshot(volume, snapshot))
        return {'provider_location': volume_id}

    def create_cloned_volume(self, volume, src_vref):
        """Create a clone of the specified volume."""
        volume_id = self.sshclient.create_cloned_volume(volume, src_vref)
        return {'provider_location': volume_id}

    def extend_volume(self, volume, new_size):
        """Extend a volume."""
        self.sshclient.extend_volume(volume, new_size)

    def delete_volume(self, volume):
        """Delete a volume."""
        self.sshclient.delete_volume(volume)

    def create_export(self, context, volume, connector=None):
        """Export the volume."""
        pass

    def ensure_export(self, context, volume):
        """Synchronously recreate an export for a volume."""
        pass

    def remove_export(self, context, volume):
        """Remove an export for a volume."""
        pass

    def create_snapshot(self, snapshot):
        """Create a snapshot."""
        snapshot_id = self.sshclient.create_snapshot(snapshot)
        return {'provider_location': snapshot_id}

    def delete_snapshot(self, snapshot):
        """Delete a snapshot."""
        self.sshclient.delete_snapshot(snapshot)

    def initialize_connection(self, volume, connector):
        """Map a volume to a host and return target iSCSI information."""
        LOG.debug('initialize_connection: volume name: %(vol)s, '
                  'host: %(host)s, initiator: %(ini)s'
                  % {'vol': volume['name'],
                     'host': connector['host'],
                     'ini': connector['initiator']})

        self.sshclient.update_login_info()
        (iscsi_iqn, target_ip, port_ctr) = (
            self._get_iscsi_params(connector['initiator']))

        # First, add a host if not added before.
        host_id = self.sshclient.add_host(connector['host'], connector['ip'],
                                          connector['initiator'])

        # Then, add the iSCSI port to the host.
        self.sshclient.add_iscsi_port_to_host(host_id, connector)

        # Finally, map the volume to the host.
        volume_id = volume['provider_location']
        try:
            hostlun_id = self.sshclient.map_volume(host_id, volume_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                # Remove the iSCSI port from the host if the map failed.
                self._remove_iscsi_port(host_id, connector)

        properties = {}
        properties['target_discovered'] = False
        properties['target_portal'] = ('%s:%s' % (target_ip, '3260'))
        properties['target_iqn'] = iscsi_iqn
        properties['target_lun'] = int(hostlun_id)
        properties['volume_id'] = volume['id']
        auth = volume['provider_auth']
        if auth:
            (auth_method, auth_username, auth_secret) = auth.split()

            properties['auth_method'] = auth_method
            properties['auth_username'] = auth_username
            properties['auth_password'] = auth_secret

        return {'driver_volume_type': 'iscsi', 'data': properties}

    def _get_iscsi_params(self, initiator):
        """Get target iSCSI params, including iqn and IP."""
        configuration = self.sshclient.configuration
        iscsi_conf = self._get_iscsi_conf(configuration)
        target_ip = None
        for ini in iscsi_conf['Initiator']:
            if ini['Name'] == initiator:
                target_ip = ini['TargetIP']
                break
        # If didn't specify target IP for some initiator, use default IP.
        if not target_ip:
            if iscsi_conf['DefaultTargetIP']:
                target_ip = iscsi_conf['DefaultTargetIP']

            else:
                msg = (_('_get_iscsi_params: Failed to get target IP '
                         'for initiator %(ini)s, please check config file.')
                       % {'ini': initiator})
                LOG.error(msg)
                raise exception.InvalidInput(reason=msg)

        (target_iqn, port_ctr) = self.sshclient.get_tgt_iqn(target_ip)
        return (target_iqn, target_ip, port_ctr)

    def _get_iscsi_conf(self, configuration):
        """Get iSCSI info from config file.

        This function returns a dict:
        {'DefaultTargetIP': '11.11.11.11',
         'Initiator': [{'Name': 'iqn.xxxxxx.1', 'TargetIP': '11.11.11.12'},
                       {'Name': 'iqn.xxxxxx.2', 'TargetIP': '11.11.11.13'}
                      ]
        }

        """

        iscsiinfo = {}
        root = (
            huawei_utils.parse_xml_file(configuration.cinder_huawei_conf_file))

        default_ip = root.findtext('iSCSI/DefaultTargetIP')
        if default_ip:
            iscsiinfo['DefaultTargetIP'] = default_ip.strip()
        else:
            iscsiinfo['DefaultTargetIP'] = None
        initiator_list = []
        tmp_dic = {}
        for dic in root.findall('iSCSI/Initiator'):
            # Strip the values of dict.
            for k, v in dic.items():
                tmp_dic[k] = v.strip()
            initiator_list.append(tmp_dic)
        iscsiinfo['Initiator'] = initiator_list
        return iscsiinfo

    def terminate_connection(self, volume, connector, **kwargs):
        """Terminate the map."""
        LOG.debug('terminate_connection: volume: %(vol)s, host: %(host)s, '
                  'connector: %(initiator)s'
                  % {'vol': volume['name'],
                     'host': connector['host'],
                     'initiator': connector['initiator']})

        self.sshclient.update_login_info()
        host_id = self.sshclient.remove_map(volume['provider_location'],
                                            connector['host'],
                                            connector['initiator'])
        if host_id and not self.sshclient.get_host_map_info(host_id):
            self._remove_iscsi_port(host_id, connector)

    def _remove_iscsi_port(self, hostid, connector):
        """Remove iSCSI ports and delete host."""
        initiator = connector['initiator']
        # Delete the host initiator if no LUN mapped to it.
        port_num = 0
        port_info = self.sshclient.get_host_port_info(hostid)
        if port_info:
            port_num = len(port_info)
            for port in port_info:
                if port[2] == initiator:
                    self.sshclient.delete_hostport(port[0])
                    port_num -= 1
                    break
        else:
            LOG.warning(_LW('_remove_iscsi_port: iSCSI port was not found '
                            'on host %(hostid)s.'), {'hostid': hostid})

        # Delete host if no initiator added to it.
        if port_num == 0:
            self.sshclient.delete_host(hostid)

    def get_volume_stats(self, refresh=False):
        """Get volume stats."""
        self._stats = self.sshclient.get_volume_stats(refresh)
        self._stats['storage_protocol'] = 'iSCSI'
        self._stats['driver_version'] = self.VERSION
        backend_name = self.configuration.safe_get('volume_backend_name')
        self._stats['volume_backend_name'] = (backend_name or
                                              self.__class__.__name__)
        return self._stats


class HuaweiTFCDriver(driver.FibreChannelDriver):
    """FC driver for Huawei OceanStor T series storage arrays."""

    VERSION = '1.0.0'

    def __init__(self, *args, **kwargs):
        super(HuaweiTFCDriver, self).__init__(*args, **kwargs)
        self.configuration = kwargs.get('configuration', None)
        if not self.configuration:
            msg = (_('_instantiate_driver: configuration not found.'))
            raise exception.InvalidInput(reason=msg)

        self.configuration.append_config_values(huawei_opt)

    def do_setup(self, context):
        """Instantiate common class."""
        self.sshclient = ssh_client.TseriesClient(configuration=
                                                  self.configuration)
        self.sshclient.do_setup(context)

    def check_for_setup_error(self):
        """Check something while starting."""
        self.sshclient.check_for_setup_error()

    def create_volume(self, volume):
        """Create a new volume."""
        volume_id = self.sshclient.create_volume(volume)
        return {'provider_location': volume_id}

    def create_volume_from_snapshot(self, volume, snapshot):
        """Create a volume from a snapshot."""
        volume_id = (
            self.sshclient.create_volume_from_snapshot(volume, snapshot))
        return {'provider_location': volume_id}

    def create_cloned_volume(self, volume, src_vref):
        """Create a clone of the specified volume."""
        volume_id = self.sshclient.create_cloned_volume(volume, src_vref)
        return {'provider_location': volume_id}

    def extend_volume(self, volume, new_size):
        """Extend a volume."""
        self.sshclient.extend_volume(volume, new_size)

    def delete_volume(self, volume):
        """Delete a volume."""
        self.sshclient.delete_volume(volume)

    def create_export(self, context, volume, connector=None):
        """Export the volume."""
        pass

    def ensure_export(self, context, volume):
        """Synchronously recreate an export for a volume."""
        pass

    def remove_export(self, context, volume):
        """Remove an export for a volume."""
        pass

    def create_snapshot(self, snapshot):
        """Create a snapshot."""
        snapshot_id = self.sshclient.create_snapshot(snapshot)
        return {'provider_location': snapshot_id}

    def delete_snapshot(self, snapshot):
        """Delete a snapshot."""
        self.sshclient.delete_snapshot(snapshot)

    def validate_connector(self, connector):
        """Check for wwpns in connector."""
        if 'wwpns' not in connector:
            err_msg = (_LE('validate_connector: The FC driver requires the'
                           ' wwpns in the connector.'))
            LOG.error(err_msg)
            raise exception.InvalidConnectorException(missing='wwpns')

    def initialize_connection(self, volume, connector):
        """Create FC connection between a volume and a host."""
        LOG.debug('initialize_connection: volume name: %(vol)s, '
                  'host: %(host)s, initiator: %(wwn)s'
                  % {'vol': volume['name'],
                     'host': connector['host'],
                     'wwn': connector['wwpns']})

        self.sshclient.update_login_info()
        # First, add a host if it is not added before.
        host_id = self.sshclient.add_host(connector['host'], connector['ip'])
        # Then, add free FC ports to the host.
        ini_wwns = connector['wwpns']
        free_wwns = self.sshclient.get_connected_free_wwns()
        for wwn in free_wwns:
            if wwn in ini_wwns:
                self.sshclient.add_fc_port_to_host(host_id, wwn)
        fc_port_details = self.sshclient.get_host_port_details(host_id)
        tgt_wwns = self._get_tgt_fc_port_wwns(fc_port_details)

        LOG.debug('initialize_connection: Target FC ports WWNS: %s'
                  % tgt_wwns)

        # Finally, map the volume to the host.
        volume_id = volume['provider_location']
        try:
            hostlun_id = self.sshclient.map_volume(host_id, volume_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                # Remove the FC port from the host if the map failed.
                self._remove_fc_ports(host_id, connector)

        properties = {}
        properties['target_discovered'] = False
        properties['target_wwn'] = tgt_wwns
        properties['target_lun'] = int(hostlun_id)
        properties['volume_id'] = volume['id']

        return {'driver_volume_type': 'fibre_channel',
                'data': properties}

    def _get_tgt_fc_port_wwns(self, port_details):
        wwns = []
        for port in port_details:
            wwns.append(port['TargetWWN'])
        return wwns

    def _get_fc_port_ctr(self, port_details):
        return port_details['ControllerID']

    def terminate_connection(self, volume, connector, **kwargs):
        """Terminate the map."""
        LOG.debug('terminate_connection: volume: %(vol)s, host: %(host)s, '
                  'connector: %(initiator)s'
                  % {'vol': volume['name'],
                     'host': connector['host'],
                     'initiator': connector['initiator']})

        self.sshclient.update_login_info()
        host_id = self.sshclient.remove_map(volume['provider_location'],
                                            connector['host'])

        # Remove all FC ports and delete the host if
        # no volume mapping to it.
        if host_id and not self.sshclient.get_host_map_info(host_id):
            self._remove_fc_ports(host_id, connector)

    def _remove_fc_ports(self, hostid, connector):
        """Remove FC ports and delete host."""
        wwns = connector['wwpns']
        port_num = 0
        port_info = self.sshclient.get_host_port_info(hostid)
        if port_info:
            port_num = len(port_info)
            for port in port_info:
                if port[2] in wwns:
                    self.sshclient.delete_hostport(port[0])
                    port_num -= 1
        else:
            LOG.warning(_LW('_remove_fc_ports: FC port was not found '
                            'on host %(hostid)s.'), {'hostid': hostid})

        if port_num == 0:
            self.sshclient.delete_host(hostid)

    def get_volume_stats(self, refresh=False):
        """Get volume stats."""
        self._stats = self.sshclient.get_volume_stats(refresh)
        self._stats['storage_protocol'] = 'FC'
        self._stats['driver_version'] = self.VERSION
        backend_name = self.configuration.safe_get('volume_backend_name')
        self._stats['volume_backend_name'] = (backend_name or
                                              self.__class__.__name__)
        return self._stats
