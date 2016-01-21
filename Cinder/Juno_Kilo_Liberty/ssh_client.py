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
Common classes for Huawei OceanStor T series storage arrays.

The common classes provide the drivers command line operation using SSH.
"""

try:
    from oslo_log import log as logging
    from oslo_utils import excutils
except ImportError:
    from cinder.openstack.common import log as logging
    from oslo.utils import excutils

import base64
import re
import six
import socket
import threading
import time
from xml.etree import ElementTree as ET

from cinder import context
from cinder import exception
from cinder.i18n import _
from cinder.i18n import _LE
from cinder.i18n import _LI
from cinder.i18n import _LW
from cinder import ssh_utils
from cinder import utils
from cinder.volume.drivers.huawei import constants
from cinder.volume.drivers.huawei import huawei_utils
from cinder.volume import utils as volume_utils
from cinder.volume import volume_types


LOG = logging.getLogger(__name__)

HOST_GROUP_NAME = 'HostGroup_OpenStack'
HOST_NAME_PREFIX = 'Host_'
VOL_AND_SNAP_NAME_PREFIX = 'OpenStack_'
HOST_PORT_PREFIX = 'HostPort_'
HOST_LUN_ERR_MSG = 'host LUN is mapped or does not exist'


def ssh_read(user, channel, cmd, timeout):
    """Get results of CLI commands."""
    result = ''
    output = None
    channel.settimeout(timeout)
    while True:
        try:
            output = channel.recv(8192)
            result = result + output
        except socket.timeout as err:
            msg = _('ssh_read: Read SSH timeout. %s') % err
            LOG.error(msg)
            raise err
        else:
            # CLI returns welcome information when first log in. So need to
            # deal differently.
            if not re.search('Welcome', result):
                # Complete CLI response starts with CLI cmd and
                # ends with "username:/>".
                if result.startswith(cmd) and result.endswith(user + ':/>'):
                    break
                # Some commands need to send 'y'.
                elif re.search('(y/n)|y or n', result):
                    break
                # Reach maximum limit of SSH connection.
                elif re.search('No response message', result):
                    msg = _('No response message. Please check system status.')
                    LOG.error(msg)
                    raise exception.CinderException(msg)
                elif re.search('relogin', result):
                    msg = _('The client is reject by the storate server ')
                    LOG.error(msg)
                    raise exception.CinderException(msg)
            elif (re.search(user + ':/>' + cmd, result) and
                  result.endswith(user + ':/>')):
                break
            if not output:
                LOG.error(_LE('Output is empty.'))
                break

    # Filter the last line: username:/> .
    result = '\r\n'.join(result.split('\r\n')[:-1])
    # Filter welcome information.
    index = result.find(user + ':/>')

    return (result[index:] if index > -1 else result)


class TseriesClient(object):
    """Common class for Huawei T series storage arrays."""

    def __init__(self, configuration=None):
        self.configuration = configuration
        self.xml_file_path = configuration.cinder_huawei_conf_file
        self.login_info = {}
        self.lun_distribution = [0, 0]
        self.hostgroup_id = None
        self.ssh_pool = None
        self.lock_ip = threading.Lock()
        self.luncopy_list = []  # to store LUNCopy name

    def do_setup(self, context):
        """Check config file."""
        LOG.debug('do_setup')

        self._check_conf_file()
        self.login_info = self._get_login_info()
        exist_luns = self._get_all_luns_info()
        self.lun_distribution = self._get_lun_distribution_info(exist_luns)
        self.luncopy_list = self._get_all_luncopy_name()
        self.hostgroup_id = self._get_hostgroup_id(HOST_GROUP_NAME)

    def _check_conf_file(self):
        """Check config file, make sure essential items are set."""
        root = huawei_utils.parse_xml_file(self.xml_file_path)
        check_list = ['Storage/ControllerIP0', 'Storage/ControllerIP1',
                      'Storage/UserName', 'Storage/UserPassword']
        for item in check_list:
            if not huawei_utils.is_xml_item_exist(root, item):
                err_msg = (_('_check_conf_file: Config file invalid. '
                             '%s must be set.') % item)
                LOG.error(err_msg)
                raise exception.InvalidInput(reason=err_msg)

        # Make sure storage pool is set.
        if not huawei_utils.is_xml_item_exist(root, 'LUN/StoragePool', 'Name'):
            err_msg = _('_check_conf_file: Config file invalid. '
                        'StoragePool must be set.')
            LOG.error(err_msg)
            raise exception.InvalidInput(reason=err_msg)

        # If setting os type, make sure it valid.
        if huawei_utils.is_xml_item_exist(root, 'Host', 'OSType'):
            os_list = constants.OS_TYPE.keys()
            if not huawei_utils.is_xml_item_valid(root, 'Host', os_list,
                                                  'OSType'):
                err_msg = (_('_check_conf_file: Config file invalid. '
                             'Host OSType is invalid.\n'
                             'The valid values are: %(os_list)s')
                           % {'os_list': os_list})
                LOG.error(err_msg)
                raise exception.InvalidInput(reason=err_msg)

    def _get_login_info(self):
        """Get login IP, username and password from config file."""
        logininfo = {}
        filename = self.configuration.cinder_huawei_conf_file
        tree = ET.parse(filename)
        root = tree.getroot()
        logininfo['ControllerIP0'] = (
            root.findtext('Storage/ControllerIP0').strip())
        logininfo['ControllerIP1'] = (
            root.findtext('Storage/ControllerIP1').strip())

        need_encode = False
        for key in ['UserName', 'UserPassword']:
            node = root.find('Storage/%s' % key)
            node_text = node.text.strip()
            # Prefix !$$$ means encoded already.
            if node_text.find('!$$$') > -1:
                logininfo[key] = base64.b64decode(node_text[4:])
            else:
                logininfo[key] = node_text
                node.text = '!$$$' + base64.b64encode(node_text)
                need_encode = True
        if need_encode:
            self._change_file_mode(filename)
            try:
                tree.write(filename, 'UTF-8')
            except Exception as err:
                LOG.info(_LI('_get_login_info: %s'), err)

        return logininfo

    def _change_file_mode(self, filepath):
        utils.execute('chmod', '640', filepath, run_as_root=True)

    def _get_lun_distribution_info(self, luns):
        """Get LUN distribution information.

        For we have two controllers for each array, we want to make all
        LUNs(just for Thick LUN) distributed evenly. The driver uses the
        LUN distribution info to determine in which controller to create
        a new LUN.

        """

        ctr_info = [0, 0]
        for lun in luns:
            if (lun[6].startswith(VOL_AND_SNAP_NAME_PREFIX) and
                    lun[8] == 'THICK'):
                if lun[4] == 'A':
                    ctr_info[0] += 1
                else:
                    ctr_info[1] += 1
        return ctr_info

    def check_for_setup_error(self):
        pass

    def _get_all_luncopy_name(self):
        cli_cmd = 'showluncopy'
        out = self._execute_cli(cli_cmd)
        luncopy_ids = []
        if re.search('LUN Copy Information', out):
            for line in out.split('\r\n')[6:-2]:
                tmp_line = line.split()
                if tmp_line[0].startswith(VOL_AND_SNAP_NAME_PREFIX):
                    luncopy_ids.append(tmp_line[0])
        return luncopy_ids

    def _get_extended_lun(self, luns):
        extended_dict = {}
        for lun in luns:
            if lun[6].startswith('ext'):
                vol_name = lun[6].split('_')[1]
                add_ids = extended_dict.get(vol_name, [])
                add_ids.append(lun[0])
                extended_dict[vol_name] = add_ids
        return extended_dict

    @utils.synchronized('huawei', external=False)
    def create_volume(self, volume):
        """Create a new volume."""
        volume_name = self._name_translate(volume['name'])

        LOG.debug('create_volume: volume name: %s' % volume_name)

        self.update_login_info()
        if int(volume['size']) == 0:
            volume_size = '100M'
        else:
            volume_size = '%sG' % volume['size']
        parameters = self._parse_volume_type(volume)
        volume_id = self._create_volume(volume_name, volume_size, parameters)
        return volume_id

    def _name_translate(self, name):
        """Form new names for volume and snapshot.

        Form new names for volume and snapshot because of
        32-character limit on names.
        """
        newname = VOL_AND_SNAP_NAME_PREFIX + six.text_type(hash(name))

        LOG.debug('_name_translate: Name in cinder: %(old)s, new name in '
                  'storage system: %(new)s' % {'old': name, 'new': newname})

        return newname

    def update_login_info(self):
        """Update user name and password."""
        self.login_info = self._get_login_info()

    def _get_opts_from_specs(self, opts_capabilite, specs):
        opts = {}
        for key, value in specs.items():
            # Get the scope, if using scope format
            scope = None
            key_split = key.split(':')
            if len(key_split) > 2 and key_split[0] != "capabilities":
                    continue

            if len(key_split) == 1:
                key = key_split[0]
            else:
                scope = key_split[0]
                key = key_split[1]

            if scope:
                scope = scope.lower()
            if key:
                key = key.lower()

            # We generally do not look at capabilities in the driver, but
            # replication is a special case where the user asks for
            # a volume to be replicated, and we want both the scheduler and
            # the driver to act on the value.
            if ((not scope or scope == 'capabilities') and
               key in opts_capabilite):
                words = value.split()

                if (words and len(words) == 2 and words[0] == '<is>'):
                    del words[0]
                    value = words[0]
                    opts[key] = value.lower()
                else:
                    LOG.error(_LE('Capabilities must be specified as '
                                  '\'<is> True\' or \'<is> False\'.'))

        return opts

    def _set_volume_type_by_specs(self, specs, params):
        '''Support LUN type configuration in SmartX.'''

        thin_key = 'thin_provisioning_support'
        thick_key = 'thick_provisioning_support'
        opts_capabilite = {thin_key: False,
                           thick_key: True}

        opts = self._get_opts_from_specs(opts_capabilite, specs)
        if (thin_key not in opts and thick_key not in opts):
            return
        if (thin_key in opts and thick_key in opts
           and opts[thin_key] == 'true' and opts[thick_key] == 'true'):
            raise exception.InvalidInput(
                reason=_('Illegal value specified for thin: '
                         'Can not set thin and thick at the same time.'))
        elif (thin_key in opts and opts[thin_key] == 'true'):
            params['LUNType'] = 'Thin'
        elif (thick_key in opts
              and opts[thick_key] == 'true'):
            params['LUNType'] = 'Thick'

    def _parse_volume_type(self, volume):
        """Parse volume type form extra_specs by type id.

        The keys in extra_specs must be consistent with the element in config
        file. And the keys can starts with "drivers" to make them distinguished
        from capabilities keys, if you like.

        """

        params = self._get_lun_params(volume)
        typeid = volume['volume_type_id']
        if typeid is not None:
            ctxt = context.get_admin_context()
            volume_type = volume_types.get_volume_type(ctxt, typeid)
            specs = volume_type.get('extra_specs')
            self._set_volume_type_by_specs(specs, params)
            for key, value in specs.items():
                key_split = key.split(':')
                if len(key_split) > 1:
                    if key_split[0] == 'drivers':
                        key = key_split[1]
                    else:
                        continue
                else:
                    key = key_split[0]

                if key in params.keys():
                    params[key] = value.strip()
                else:
                    conf = self.configuration.cinder_huawei_conf_file
                    LOG.warning(_LW('_parse_volume_type: Unacceptable '
                                    'parameter %(key)s. Please check this key'
                                    ' in extra_specs and make '
                                    'it consistent with the element in '
                                    'configuration file %(conf)s.'),
                                {'key': key,
                                 'conf': conf})

        return params

    def _create_volume(self, name, size, params):
        """Create a new volume with the given name and size."""
        cli_cmd = ('createlun -n %(name)s -lunsize %(size)s '
                   '-wrtype %(wrtype)s ' % {'name': name,
                                            'size': size,
                                            'wrtype': params['WriteType']})

        # If write type is "write through", no need to set mirror switch.
        if params['WriteType'] != '2':
            cli_cmd = cli_cmd + ('-mirrorsw %(mirrorsw)s '
                                 % {'mirrorsw': params['MirrorSwitch']})

        # Differences exist between "Thin" and "thick" LUN in CLI commands.
        luntype = params['LUNType']
        ctr = None
        if luntype == 'Thin':
            cli_cmd = cli_cmd + ('-pool %(pool)s '
                                 % {'pool': params['StoragePool']})
        else:
            # Make LUN distributed to A/B controllers evenly,
            # just for Thick LUN.
            ctr = self._calculate_lun_ctr()
            cli_cmd = cli_cmd + ('-rg %(raidgroup)s -susize %(susize)s '
                                 '-c %(ctr)s '
                                 % {'raidgroup': params['StoragePool'],
                                    'susize': params['StripUnitSize'],
                                    'ctr': ctr})

        prefetch_value_or_times = ''
        pretype = '-pretype %s ' % params['PrefetchType']
        # If constant prefetch, we should specify prefetch value.
        if params['PrefetchType'] == '1':
            prefetch_value_or_times = '-value %s' % params['PrefetchValue']
        # If variable prefetch, we should specify prefetch multiple.
        elif params['PrefetchType'] == '2':
            prefetch_value_or_times = '-times %s' % params['PrefetchTimes']

        cli_cmd = cli_cmd + pretype + prefetch_value_or_times
        out = self._execute_cli(cli_cmd)

        self._assert_cli_operate_out('_create_volume',
                                     'Failed to create volume %s' % name,
                                     cli_cmd, out)
        if ctr:
            self._update_lun_distribution(ctr)

        return self._get_lun_id(name)

    def _calculate_lun_ctr(self):
        return ('a' if self.lun_distribution[0] <= self.lun_distribution[1]
                else 'b')

    def _update_lun_distribution(self, ctr):
        index = (0 if ctr == 'a' else 1)
        self.lun_distribution[index] += 1

    def _get_lun_params(self, volume):
        params_conf = self._parse_conf_lun_params()
        pool_name = volume_utils.extract_host(volume['host'], level='pool')

        thick_pools = self._get_dev_pool_info('Thick')
        thick_infos = {}
        for pool in thick_pools:
            thick_infos[pool[5]] = pool[0]

        if pool_name in thick_infos:
            params_conf['LUNType'] = 'Thick'
            params_conf['StoragePool'] = thick_infos[pool_name]
            return params_conf

        thin_pools = self._get_dev_pool_info('Thin')
        thin_infos = {}
        for pool in thin_pools:
            thin_infos[pool[1]] = pool[0]
        if pool_name in thin_infos:
            params_conf['LUNType'] = 'Thin'
            params_conf['StoragePool'] = thin_infos[pool_name]
            return params_conf

        msg = _("Pool does not exist. Pool name: %s.") % pool_name
        LOG.error(msg)
        raise exception.VolumeBackendAPIException(data=msg)

    def _parse_conf_lun_params(self):
        """Get parameters from config file for creating LUN."""
        # Default LUN parameters.
        conf_params = {'LUNType': 'Thin',
                       'StripUnitSize': '64',
                       'WriteType': '1',
                       'MirrorSwitch': '1',
                       'PrefetchType': '3',
                       'PrefetchValue': '0',
                       'PrefetchTimes': '0',
                       'StoragePool': []}

        root = huawei_utils.parse_xml_file(self.xml_file_path)

        stripunitsize = root.findtext('LUN/StripUnitSize')
        if stripunitsize:
            conf_params['StripUnitSize'] = stripunitsize.strip()
        writetype = root.findtext('LUN/WriteType')
        if writetype:
            conf_params['WriteType'] = writetype.strip()
        mirrorswitch = root.findtext('LUN/MirrorSwitch')
        if mirrorswitch:
            conf_params['MirrorSwitch'] = mirrorswitch.strip()
        prefetch = root.find('LUN/Prefetch')
        if prefetch is not None and prefetch.attrib['Type']:
            conf_params['PrefetchType'] = prefetch.attrib['Type'].strip()
            if conf_params['PrefetchType'] == '1':
                conf_params['PrefetchValue'] = prefetch.attrib['Value'].strip()
            elif conf_params['PrefetchType'] == '2':
                conf_params['PrefetchTimes'] = prefetch.attrib['Value'].strip()
        else:
            LOG.debug('_parse_conf_lun_params: Use default prefetch type. '
                      'Prefetch type: Intelligent')

        pools_conf = root.findall('LUN/StoragePool')
        for pool in pools_conf:
            conf_params['StoragePool'].append(pool.attrib['Name'].strip())

        return conf_params

    @utils.synchronized('huawei-cli', external=False)
    def _execute_cli(self, cmd):
        """Build SSH connection and execute CLI commands.

        If the connection to first controller timeout,
        try to connect to the other controller.

        """

        LOG.debug('CLI command: %s' % cmd)
        old_cmd = cmd
        connect_times = 1
        ip0 = self.login_info['ControllerIP0']
        ip1 = self.login_info['ControllerIP1']
        user = self.login_info['UserName']
        pwd = self.login_info['UserPassword']
        if not self.ssh_pool:
            self.ssh_pool = ssh_utils.SSHPool(ip0, 22, 30, user, pwd,
                                              max_size=20)
        ssh_client = None
        while True:
            try:
                if connect_times == 2:
                    # Switch to the other controller.
                    with self.lock_ip:
                        if ssh_client:
                            if ssh_client.server_ip == self.ssh_pool.ip:
                                self.ssh_pool.ip = (ip1
                                                    if self.ssh_pool.ip == ip0
                                                    else ip0)
                            old_ip = ssh_client.server_ip
                            # Create a new client to replace the old one.
                            if getattr(ssh_client, 'chan', None):
                                ssh_client.chan.close()
                                ssh_client.close()
                                ssh_client = self.ssh_pool.create()
                                self._reset_transport_timeout(ssh_client, 0.1)
                        else:
                            self.ssh_pool.ip = ip1
                            old_ip = ip0

                    LOG.info(_LI('_execute_cli: Can not connect to IP '
                                 '%(old)s, try to connect to the other '
                                 'IP %(new)s.'),
                             {'old': old_ip, 'new': self.ssh_pool.ip})

                if not ssh_client:
                    # Get an SSH client from SSH pool.
                    ssh_client = self.ssh_pool.get()
                    self._reset_transport_timeout(ssh_client, 0.1)
                # "server_ip" shows the IP of SSH server.
                if not getattr(ssh_client, 'server_ip', None):
                    with self.lock_ip:
                        setattr(ssh_client, 'server_ip', self.ssh_pool.ip)
                # An SSH client owns one "chan".
                if not getattr(ssh_client, 'chan', None):
                    setattr(ssh_client, 'chan',
                            utils.create_channel(ssh_client, 600, 800))

                busyRetryTime = 5
                while True:
                    if 0 == ssh_client.chan.send(cmd + '\n'):
                        ssh_client.chan.close()
                        setattr(ssh_client, 'chan',
                                utils.create_channel(ssh_client, 600, 800))
                        ssh_client.chan.send(cmd + '\n')
                    out = ssh_read(user, ssh_client.chan, cmd, 200)
                    if out.find('(y/n)') > -1 or out.find('y or n') > -1:
                        cmd = 'y'
                    elif (out.find('The system is busy') > -1
                          and busyRetryTime > 0):
                        busyRetryTime = busyRetryTime - 1
                        LOG.info(_LI("System is busy, retry after sleep 10s."))
                        time.sleep(10)
                    elif re.search('Login failed.', out):
                        err_msg = (_('Login failed when running command:'
                                     ' %(cmd)s, CLI out: %(out)s')
                                   % {'cmd': cmd,
                                      'out': out})
                        LOG.error(err_msg)
                        raise exception.VolumeBackendAPIException(data=err_msg)
                    else:
                        # Put SSH client back into SSH pool.
                        if (old_cmd == 'showrg') or (old_cmd == 'showpool'):
                            ssh_client.chan.close()
                            self.ssh_pool.remove(ssh_client)
                        else:
                            self.ssh_pool.put(ssh_client)
                        return out

            except Exception as err:
                if connect_times < 2:
                    connect_times += 1
                    continue
                else:
                    if self.ssh_pool and ssh_client:
                        self.ssh_pool.remove(ssh_client)
                    # Set ssh_pool as None when connect error,or the next
                    # command connect will also error.
                    self.ssh_pool = None
                    LOG.error(_LE('_execute_cli: %s'), err)
                    raise err

    def _reset_transport_timeout(self, ssh, time):
        transport = ssh.get_transport()
        transport.sock.settimeout(time)

    @utils.synchronized('huawei', external=False)
    def delete_volume(self, volume):
        volume_name = self._name_translate(volume['name'])

        LOG.debug('delete_volume: volume name: %s' % volume_name)

        self.update_login_info()
        volume_id = volume.get('provider_location', None)
        if volume_id is None or not self._check_volume_created(volume_id):
            err_msg = (_('delete_volume: Volume %(name)s does not exist.')
                       % {'name': volume['name']})
            LOG.warning(err_msg)
            return

        map_info = self._get_host_map_info_by_lunid(volume_id)
        if map_info and len(map_info) is 1:
            self._delete_map(map_info[0][0])

        added_vol_ids = self._get_extended_lun_member(volume_id)
        if added_vol_ids:
            self._del_lun_from_extended_lun(volume_id, added_vol_ids)
        self._delete_volume(volume_id)

    def _check_volume_created(self, volume_id):
        if volume_id is None:
            return False
        cli_cmd = 'showlun -lun %s' % volume_id
        out = self._execute_cli(cli_cmd)
        return (True if re.search('LUN Information', out) else False)

    def _get_extended_lun_member(self, lun_id):
        cli_cmd = 'showextlunmember -ext %s' % lun_id
        out = self._execute_cli(cli_cmd)

        members = []
        if re.search('Extending LUN Member Information', out):
            try:
                for line in out.split('\r\n')[6:-2]:
                    tmp_line = line.split()
                    if len(tmp_line) < 3:
                        continue
                    if tmp_line[2] != 'Master':
                        members.append(tmp_line[0])
            except Exception:
                err_msg = (_('CLI out is not normal. CLI out: %s') % out)
                LOG.error(err_msg)
                raise exception.VolumeBackendAPIException(data=err_msg)

        return members

    def _del_lun_from_extended_lun(self, extended_id, added_ids):
        cli_cmd = 'rmlunfromextlun -ext %s' % extended_id
        out = self._execute_cli(cli_cmd)

        self._assert_cli_operate_out('_del_lun_from_extended_lun',
                                     ('Failed to remove LUN from extended '
                                      'LUN: %s' % extended_id),
                                     cli_cmd, out)
        for id in added_ids:
            cli_cmd = 'dellun -lun %s' % id
            out = self._execute_cli(cli_cmd)

            self._assert_cli_operate_out('_del_lun_from_extended_lun',
                                         'Failed to delete LUN: %s' % id,
                                         cli_cmd, out)

    def _delete_volume(self, volumeid):
        """Run CLI command to delete volume."""
        cli_cmd = 'dellun -force -lun %s' % volumeid
        out = self._execute_cli(cli_cmd)

        self._assert_cli_operate_out('_delete_volume',
                                     ('Failed to delete volume. volume id: %s'
                                      % volumeid),
                                     cli_cmd, out)

    @utils.synchronized('huawei', external=False)
    def create_volume_from_snapshot(self, volume, snapshot):
        """Create a volume from a snapshot.

        We use LUNcopy to copy a new volume from snapshot.
        The time needed increases as volume size does.

        """

        snapshot_name = self._name_translate(snapshot['name'])
        volume_name = self._name_translate(volume['name'])

        LOG.debug('create_volume_from_snapshot: snapshot '
                  'name: %(snapshot)s, volume name: %(volume)s'
                  % {'snapshot': snapshot_name,
                     'volume': volume_name})

        self.update_login_info()
        snapshot_id = snapshot.get('provider_location', None)
        if not snapshot_id:
            snapshot_id = self._get_snapshot_id(snapshot_name)
            if snapshot_id is None:
                err_msg = (_('create_volume_from_snapshot: Snapshot %(name)s '
                             'does not exist.')
                           % {'name': snapshot_name})
                LOG.error(err_msg)
                raise exception.VolumeBackendAPIException(data=err_msg)

        # Create a target LUN.
        if int(volume['size']) == 0:
            volume_size = '%sG' % snapshot['volume_size']
        else:
            volume_size = '%sG' % volume['size']
        parameters = self._parse_volume_type(volume)
        tgt_vol_id = self._create_volume(volume_name, volume_size, parameters)
        self._copy_volume(snapshot_id, tgt_vol_id)

        return tgt_vol_id

    def _copy_volume(self, src_vol_id, tgt_vol_id):
        """Copy a volume or snapshot to target volume."""
        luncopy_name = VOL_AND_SNAP_NAME_PREFIX + src_vol_id + '_' + tgt_vol_id
        self._create_luncopy(luncopy_name, src_vol_id, tgt_vol_id)
        self.luncopy_list.append(luncopy_name)
        luncopy_id = self._get_luncopy_info(luncopy_name)[1]
        try:
            self._start_luncopy(luncopy_id)
            self._wait_for_luncopy(luncopy_name)
        # Delete the target volume if LUNcopy failed.
        except Exception:
            with excutils.save_and_reraise_exception():
                # Need to remove the LUNcopy of the volume first.
                self._delete_luncopy(luncopy_id)
                self.luncopy_list.remove(luncopy_name)
                self._delete_volume(tgt_vol_id)
        # Need to delete LUNcopy finally.
        self._delete_luncopy(luncopy_id)
        self.luncopy_list.remove(luncopy_name)

    def _create_luncopy(self, luncopyname, srclunid, tgtlunid):
        """Run CLI command to create LUNcopy."""
        cli_cmd = ('createluncopy -n %(name)s -l 4 -slun %(srclunid)s '
                   '-tlun %(tgtlunid)s' % {'name': luncopyname,
                                           'srclunid': srclunid,
                                           'tgtlunid': tgtlunid})
        out = self._execute_cli(cli_cmd)

        self._assert_cli_operate_out('_create_luncopy',
                                     ('Failed to create LUNcopy %s'
                                      % luncopyname),
                                     cli_cmd, out)

    def _start_luncopy(self, luncopyid):
        """Run CLI command to start LUNcopy."""
        cli_cmd = ('chgluncopystatus -luncopy %(luncopyid)s -start'
                   % {'luncopyid': luncopyid})
        out = self._execute_cli(cli_cmd)

        self._assert_cli_operate_out('_start_luncopy',
                                     'Failed to start LUNcopy %s' % luncopyid,
                                     cli_cmd, out)

    def _wait_for_luncopy(self, luncopyname):
        """Wait for LUNcopy to complete."""
        while True:
            luncopy_info = self._get_luncopy_info(luncopyname)
            # If state is complete
            if luncopy_info[3] == 'Complete':
                break
            # If status is not normal
            elif luncopy_info[4] != 'Normal':
                err_msg = (_('_wait_for_luncopy: LUNcopy %(luncopyname)s '
                             'status is %(status)s.')
                           % {'luncopyname': luncopyname,
                              'status': luncopy_info[4]})
                LOG.error(err_msg)
                raise exception.VolumeBackendAPIException(data=err_msg)

            time.sleep(10)

    def _get_luncopy_info(self, luncopyname):
        """Return a LUNcopy information list."""
        cli_cmd = 'showluncopy'
        out = self._execute_cli(cli_cmd)

        self._assert_cli_out(re.search('LUN Copy Information', out),
                             '_get_luncopy_info',
                             'No LUNcopy information was found.',
                             cli_cmd, out)

        for line in out.split('\r\n')[6:-2]:
            tmp_line = line.split()
            if tmp_line[0] == luncopyname:
                return tmp_line
        return None

    def _delete_luncopy(self, luncopyid):
        """Run CLI command to delete LUNcopy."""
        cli_cmd = 'delluncopy -luncopy %(id)s' % {'id': luncopyid}
        out = self._execute_cli(cli_cmd)

        self._assert_cli_operate_out('_delete_luncopy',
                                     'Failed to delete LUNcopy %s' % luncopyid,
                                     cli_cmd, out)

    def create_cloned_volume(self, tgt_volume, src_volume):
        src_vol_name = self._name_translate(src_volume['name'])
        tgt_vol_name = self._name_translate(tgt_volume['name'])

        LOG.debug('create_cloned_volume: src volume: %(src)s, '
                  'tgt volume: %(tgt)s' % {'src': src_vol_name,
                                           'tgt': tgt_vol_name})

        self.update_login_info()
        src_vol_id = src_volume.get('provider_location', None)
        if not src_vol_id:
            src_vol_id = self._get_lun_id(src_vol_name)
            if src_vol_id is None:
                LOG.error(_LE('Source volume %(name)s does not exist.'),
                          {'name': src_vol_name})
                raise exception.VolumeNotFound(volume_id=src_vol_name)

        # Create a target volume.
        if int(tgt_volume['size']) == 0:
            tgt_vol_size = '%sG' % src_vol_name['size']
        else:
            tgt_vol_size = '%sG' % tgt_volume['size']
        params = self._parse_volume_type(tgt_volume)
        tgt_vol_id = self._create_volume(tgt_vol_name, tgt_vol_size, params)
        self._copy_volume(src_vol_id, tgt_vol_id)

        return tgt_vol_id

    def _get_all_luns_info(self):
        cli_cmd = 'showlun'
        out = self._execute_cli(cli_cmd)
        luns = []
        if re.search('LUN Information', out):
            for line in out.split('\r\n')[6:-2]:
                new_line = line.replace('Not format', 'Notformat').split()
                if len(new_line) < 7:
                    err_msg = (_('CLI out is not normal. CLI out: %s') % out)
                    LOG.error(err_msg)
                    raise exception.VolumeBackendAPIException(data=err_msg)
                luns.append(new_line)
        return luns

    def _get_lun_id(self, lun_name):
        luns = self._get_all_luns_info()
        if luns:
            for lun in luns:
                if lun[6] == lun_name:
                    return lun[0]
        return None

    def _get_lun_status(self, lun_id):
        status = None
        cli_cmd = ('showlun -lun %s' % lun_id)
        out = self._execute_cli(cli_cmd)
        if re.search('LUN Information', out):
            try:
                line = out.split('\r\n')[7]
                status = line.split()[2]
            except Exception:
                err_msg = (_('CLI out is not normal. CLI out: %s') % out)
                LOG.error(err_msg)
                raise exception.VolumeBackendAPIException(data=err_msg)
        return status

    def _wait_for_lun_status(self, lun_id, expected_status):
        """Wait for LUN to be the expected status."""
        while True:
            status = self._get_lun_status(lun_id)
            if status in expected_status:
                break
            elif status == 'Fault':
                err_msg = (_('_wait_for_lun_status: LUN %(lun_id)s '
                             'status is %(status)s.')
                           % {'lun_id': lun_id,
                              'status': status})
                LOG.error(err_msg)
                raise exception.VolumeBackendAPIException(data=err_msg)
            LOG.info(_LI('LUN %s is not ready, waiting 2s...'), lun_id)
            time.sleep(2)

    def extend_volume(self, volume, new_size):
        lun_id = volume.get('provider_location', None)
        extended_vol_name = self._name_translate(volume['name'])
        if lun_id is None:
            err_msg = (_('extend_volume: volume %s does not exist.')
                       % extended_vol_name)
            LOG.error(err_msg)
            raise exception.VolumeNotFound(volume_id=extended_vol_name)
        added_vol_ids = self._get_extended_lun_member(lun_id)
        added_vol_name = ('ext_' + extended_vol_name.split('_')[1] + '_' +
                          six.text_type(len(added_vol_ids)))
        added_vol_size = (
            six.text_type(int(new_size) - int(volume['size'])) + 'G')

        LOG.debug('extend_volume: extended volume name: %(extended_name)s '
                  'new added volume name: %(added_name)s '
                  'new added volume size: %(added_size)s'
                  % {'extended_name': extended_vol_name,
                     'added_name': added_vol_name,
                     'added_size': added_vol_size})

        parameters = self._parse_volume_type(volume)
        if ('LUNType' in parameters and parameters['LUNType'] == 'Thin'):
            err_msg = _("extend_volume: Thin LUN can't be extended.")
            LOG.error(err_msg)
            raise exception.VolumeBackendAPIException(data=err_msg)
        added_vol_id = self._create_volume(added_vol_name, added_vol_size,
                                           parameters)
        try:
            # Source LUN must be 'Normal' to extend.
            self._wait_for_lun_status(lun_id, ('Normal'))

            # Added LUN must be 'Formatting' or 'Normal'.
            self._wait_for_lun_status(added_vol_id, ('Formatting', 'Normal'))
            self._extend_volume(lun_id, added_vol_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                self._delete_volume(added_vol_id)

        added_vol_ids.append(added_vol_id)

    def _extend_volume(self, extended_vol_id, added_vol_id):
        cli_cmd = ('addluntoextlun -extlun %(extended_vol)s '
                   '-lun %(added_vol)s' % {'extended_vol': extended_vol_id,
                                           'added_vol': added_vol_id})
        out = self._execute_cli(cli_cmd)
        self._assert_cli_operate_out('_extend_volume',
                                     ('Failed to extend volume %s'
                                      % extended_vol_id),
                                     cli_cmd, out)

    @utils.synchronized('huawei', external=False)
    def create_snapshot(self, snapshot):
        snapshot_name = self._name_translate(snapshot['name'])
        volume_name = self._name_translate(snapshot['volume_name'])

        LOG.debug('create_snapshot: snapshot name: %(snapshot)s, '
                  'volume name: %(volume)s'
                  % {'snapshot': snapshot_name,
                     'volume': volume_name})

        if self._resource_pool_enough() is False:
            err_msg = (_('create_snapshot: '
                         'Resource pool needs 1GB valid size at least.'))
            LOG.error(err_msg)
            raise exception.VolumeBackendAPIException(data=err_msg)

        volume = snapshot['volume']
        lun_id = volume.get('provider_location', None)
        if lun_id is None:
            lun_id = self._get_lun_id(volume_name)
        if lun_id is None:
            LOG.error(_LE('create_snapshot: Volume %(name)s does not exist.'),
                      {'name': volume_name})
            raise exception.VolumeNotFound(volume_id=volume_name)

        self._create_snapshot(snapshot_name, lun_id)
        snapshot_id = self._get_snapshot_id(snapshot_name)
        try:
            self._active_snapshot(snapshot_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                self._delete_snapshot(snapshot_id)

        return snapshot_id

    def _resource_pool_enough(self):
        """Check whether resource pools' valid size is more than 1GB."""
        cli_cmd = 'showrespool'
        out = self._execute_cli(cli_cmd)
        try:
            for line in out.split('\r\n')[6:-2]:
                tmp_line = line.split()
                if len(tmp_line) < 4:
                    continue
                if float(tmp_line[3]) < 1024.0:
                    return False
        except Exception:
            err_msg = (_('CLI out is not normal. CLI out: %s') % out)
            LOG.error(err_msg)
            raise exception.VolumeBackendAPIException(data=err_msg)

        return True

    def _create_snapshot(self, snapshotname, srclunid):
        """Create a snapshot with snapshot name and source LUN ID."""
        cli_cmd = ('createsnapshot -lun %(lunid)s -n %(snapname)s'
                   % {'lunid': srclunid,
                      'snapname': snapshotname})
        out = self._execute_cli(cli_cmd)

        self._assert_cli_operate_out('_create_snapshot',
                                     ('Failed to create snapshot %s'
                                      % snapshotname),
                                     cli_cmd, out)

    def _get_snapshot_id(self, snapshotname):
        cli_cmd = 'showsnapshot'
        out = self._execute_cli(cli_cmd)
        if re.search('Snapshot Information', out):
            try:
                for line in out.split('\r\n')[6:-2]:
                    emp_line = line.split()
                    if len(emp_line) < 2:
                        continue
                    if emp_line[0] == snapshotname:
                        return emp_line[1]
            except Exception:
                err_msg = (_('CLI out is not normal. CLI out: %s') % out)
                LOG.error(err_msg)
                raise exception.VolumeBackendAPIException(data=err_msg)
        return None

    def _active_snapshot(self, snapshotid):
        """Run CLI command to active snapshot."""
        cli_cmd = ('actvsnapshot -snapshot %(snapshotid)s'
                   % {'snapshotid': snapshotid})
        out = self._execute_cli(cli_cmd)

        self._assert_cli_operate_out('_active_snapshot',
                                     ('Failed to active snapshot %s'
                                      % snapshotid),
                                     cli_cmd, out)

    def delete_snapshot(self, snapshot):
        snapshot_name = self._name_translate(snapshot['name'])
        volume_name = self._name_translate(snapshot['volume_name'])

        LOG.debug('delete_snapshot: snapshot name: %(snapshot)s, '
                  'volume name: %(volume)s' % {'snapshot': snapshot_name,
                                               'volume': volume_name})

        self.update_login_info()
        snapshot_id = snapshot.get('provider_location', None)
        if ((snapshot_id is not None) and
                self._check_snapshot_created(snapshot_id)):
            # Not allow to delete snapshot if it is copying.
            if self._snapshot_in_luncopy(snapshot_id):
                err_msg = (_('delete_snapshot: Can not delete snapshot %s '
                             'for it is a source LUN of LUNCopy.')
                           % snapshot_name)
                LOG.error(err_msg)
                raise exception.VolumeBackendAPIException(data=err_msg)

            self._delete_snapshot(snapshot_id)
        else:
            err_msg = (_('delete_snapshot: Snapshot %(snap)s does not exist.')
                       % {'snap': snapshot_name})
            LOG.warning(err_msg)

    def _check_snapshot_created(self, snapshot_id):
        cli_cmd = 'showsnapshot -snapshot %(snap)s' % {'snap': snapshot_id}
        out = self._execute_cli(cli_cmd)
        return (True if re.search('Snapshot Information', out) else False)

    def _snapshot_in_luncopy(self, snapshot_id):
        for name in self.luncopy_list:
            if name.startswith(VOL_AND_SNAP_NAME_PREFIX + snapshot_id):
                return True
        return False

    def _delete_snapshot(self, snapshotid):
        """Send CLI command to delete snapshot.

        Firstly, disable the snapshot, then delete it.

        """

        cli_cmd = ('disablesnapshot -snapshot %(snapshotid)s'
                   % {'snapshotid': snapshotid})
        out = self._execute_cli(cli_cmd)

        self._assert_cli_operate_out('_delete_snapshot',
                                     ('Failed to disable snapshot %s'
                                      % snapshotid),
                                     cli_cmd, out)

        cli_cmd = ('delsnapshot -snapshot %(snapshotid)s'
                   % {'snapshotid': snapshotid})
        out = self._execute_cli(cli_cmd)

        self._assert_cli_operate_out('_delete_snapshot',
                                     ('Failed to delete snapshot %s'
                                      % snapshotid),
                                     cli_cmd, out)

    def _assert_cli_out(self, condition, func, msg, cmd, cliout):
        """Assertion for CLI query out."""
        if not condition:
            err_msg = (_('%(func)s: %(msg)s\nCLI command: %(cmd)s\n'
                         'CLI out: %(out)s') % {'func': func,
                                                'msg': msg,
                                                'cmd': cmd,
                                                'out': cliout})
            LOG.error(err_msg)
            raise exception.VolumeBackendAPIException(data=err_msg)

    def _assert_cli_operate_out(self, func, msg, cmd, cliout):
        """Assertion for CLI out string: command operates successfully."""
        condition = (re.search('command operates successfully', cliout)
                     or re.search('The name exists already', cliout))
        self._assert_cli_out(condition, func, msg, cmd, cliout)

    def _is_lun_normal(self, volume_id):
        """Check whether the LUN is normal."""
        cli_cmd = ('showlun -lun %s' % volume_id)
        out = self._execute_cli(cli_cmd)
        if re.search('LUN Information', out):
            try:
                line = out.split('\r\n')[7]
                line = line.replace('Not format', 'Notformat')
                status = line.split()[2]
            except Exception:
                err_msg = (_('CLI out is not normal. CLI out: %s') % out)
                LOG.error(err_msg)
                raise exception.VolumeBackendAPIException(data=err_msg)

            LOG.debug('LUN: %(volume_id)s, current status: %(status)s'
                      % {'volume_id': volume_id,
                         'status': status})
            if (status == 'Normal') or (status == 'Formatting'):
                return True

        return False

    def map_volume(self, host_id, volume_id):
        """Map a volume to a host."""
        # Map a LUN to a host if not mapped.
        if not self._check_volume_created(volume_id):
            LOG.error(_LE('map_volume: Volume %s was not found.'), volume_id)
            raise exception.VolumeNotFound(volume_id=volume_id)

        hostlun_id = None
        map_info = self.get_host_map_info(host_id)
        # Make sure the host LUN ID starts from 1.
        new_hostlun_id = 1
        new_hostlunid_found = False
        if map_info:
            for maping in map_info:
                if maping[2] == volume_id:
                    hostlun_id = maping[4]
                    break
                elif not new_hostlunid_found:
                    if new_hostlun_id < int(maping[4]):
                        new_hostlunid_found = True
                    else:
                        new_hostlun_id = int(maping[4]) + 1

        if not hostlun_id:
            count = 0
            max_wait_time = 5
            while self._is_lun_normal(volume_id) is False:
                if count >= max_wait_time:
                    err_msg = (_('LUN %(volume_id)s is still not normal after'
                                 ' %(max_wait_time)s seconds wait.')
                               % {'volume_id': volume_id,
                                  'max_wait_time': max_wait_time})
                    LOG.error(err_msg)
                    raise exception.VolumeBackendAPIException(data=err_msg)
                else:
                    LOG.debug('LUN %s is not normal, sleep 1s to wait.',
                              volume_id)
                    time.sleep(1)
                    count = count + 1
            cli_cmd = ('addhostmap -host %(host_id)s -devlun %(lunid)s '
                       '-hostlun %(hostlunid)s'
                       % {'host_id': host_id,
                          'lunid': volume_id,
                          'hostlunid': new_hostlun_id})
            out = self._execute_cli(cli_cmd)
            # Check whether the hostlunid has already been assigned.
            condition = re.search(HOST_LUN_ERR_MSG, out)
            while condition:
                new_hostlun_id = new_hostlun_id + 1
                cli_cmd = ('addhostmap -host %(host_id)s -devlun %(lunid)s '
                           '-hostlun %(hostlunid)s'
                           % {'host_id': host_id,
                              'lunid': volume_id,
                              'hostlunid': new_hostlun_id})
                out = self._execute_cli(cli_cmd)
                condition = re.search(HOST_LUN_ERR_MSG, out)

            msg = ('Failed to map LUN %s to host %s. host LUN ID: %s'
                   % (volume_id, host_id, new_hostlun_id))
            self._assert_cli_operate_out('map_volume', msg, cli_cmd, out)

            hostlun_id = new_hostlun_id

        return hostlun_id

    def add_host(self, host_name, host_ip, initiator=None):
        """Create a host and add it to hostgroup."""
        # Create an OpenStack hostgroup if not created before.
        hostgroup_name = HOST_GROUP_NAME
        self.hostgroup_id = self._get_hostgroup_id(hostgroup_name)
        if self.hostgroup_id is None:
            try:
                self._create_hostgroup(hostgroup_name)
                self.hostgroup_id = self._get_hostgroup_id(hostgroup_name)
            except Exception:
                self.hostgroup_id = self._get_hostgroup_id(hostgroup_name)
                if self.hostgroup_id is None:
                    err_msg = (_('error to create hostgroup: %s')
                               % hostgroup_name)
                    LOG.error(err_msg)
                    raise exception.VolumeBackendAPIException(data=err_msg)

        # Create a host and add it to the hostgroup.
        # Check the old host name to support the upgrade from grizzly to
        # higher versions.
        if initiator:
            old_host_name = HOST_NAME_PREFIX + six.text_type(hash(initiator))
            old_host_id = self._get_host_id(old_host_name, self.hostgroup_id)
            if old_host_id is not None:
                return old_host_id

        if host_name and (len(host_name) > 26):
            host_name = six.text_type(hash(host_name))
        host_name = HOST_NAME_PREFIX + host_name
        host_id = self._get_host_id(host_name, self.hostgroup_id)
        if host_id is None:
            os_type = huawei_utils.get_conf_host_os_type(host_ip,
                                                         self.configuration)
            try:
                self._create_host(host_name, self.hostgroup_id, os_type)
                host_id = self._get_host_id(host_name, self.hostgroup_id)
            except Exception:
                host_id = self._get_host_id(host_name, self.hostgroup_id)
                if host_id is None:
                    err_msg = (_('error to create host: %s') % host_name)
                    LOG.error(err_msg)
                    raise exception.VolumeBackendAPIException(data=err_msg)

        return host_id

    def _get_hostgroup_id(self, groupname):
        """Get the given hostgroup ID.

        If the hostgroup not found, return None.

        """

        cli_cmd = 'showhostgroup'
        out = self._execute_cli(cli_cmd)
        if re.search('Host Group Information', out):
            try:
                for line in out.split('\r\n')[6:-2]:
                    tmp_line = line.split()
                    if len(tmp_line) < 2:
                        continue
                    if tmp_line[1] == groupname:
                        return tmp_line[0]
            except Exception:
                err_msg = (_('CLI out is not normal. CLI out: %s') % out)
                LOG.error(err_msg)
                raise exception.VolumeBackendAPIException(data=err_msg)
        return None

    def _create_hostgroup(self, hostgroupname):
        """Run CLI command to create host group."""
        cli_cmd = 'createhostgroup -n %(name)s' % {'name': hostgroupname}
        out = self._execute_cli(cli_cmd)

        self._assert_cli_operate_out('_create_hostgroup',
                                     ('Failed to Create hostgroup %s.'
                                      % hostgroupname),
                                     cli_cmd, out)

    def _get_host_id(self, hostname, hostgroupid):
        """Get the given host ID."""
        cli_cmd = 'showhost -group %(groupid)s' % {'groupid': hostgroupid}
        out = self._execute_cli(cli_cmd)
        if re.search('Host Information', out):
            try:
                for line in out.split('\r\n')[6:-2]:
                    tmp_line = line.split()
                    if len(tmp_line) < 2:
                        continue
                    if tmp_line[1] == hostname:
                        return tmp_line[0]
            except Exception:
                err_msg = (_('CLI out is not normal. CLI out: %s') % out)
                LOG.error(err_msg)
                raise exception.VolumeBackendAPIException(data=err_msg)
        return None

    def _create_host(self, hostname, hostgroupid, type):
        """Run CLI command to add host."""
        cli_cmd = ('addhost -group %(groupid)s -n %(hostname)s -t %(type)s'
                   % {'groupid': hostgroupid,
                      'hostname': hostname,
                      'type': type})
        out = self._execute_cli(cli_cmd)

        self._assert_cli_operate_out('_create_host',
                                     'Failed to create host %s' % hostname,
                                     cli_cmd, out)

    def get_host_port_info(self, hostid):
        """Run CLI command to get host port information."""
        cli_cmd = ('showhostport -host %(hostid)s' % {'hostid': hostid})
        out = self._execute_cli(cli_cmd)
        if re.search('Host Port Information', out):
            return [line.split() for line in out.split('\r\n')[6:-2]]
        else:
            return None

    def get_host_map_info(self, hostid):
        """Get map information of the given host."""

        cli_cmd = 'showhostmap -host %(hostid)s' % {'hostid': hostid}
        out = self._execute_cli(cli_cmd)
        if re.search('Map Information', out):
            mapinfo = []
            try:
                for line in out.split('\r\n')[6:-2]:
                    new_line = line.split()
                    if len(new_line) < 5:
                        continue
                    mapinfo.append(new_line)
            except Exception:
                err_msg = (_('CLI out is not normal. CLI out: %s') % out)
                LOG.error(err_msg)
                raise exception.VolumeBackendAPIException(data=err_msg)
            # Sorted by host LUN ID.
            return sorted(mapinfo, key=lambda x: int(x[4]))
        else:
            return None

    def _get_host_map_info_by_lunid(self, lunid):
        """Get map information of the given host."""

        cli_cmd = 'showhostmap -lun %(lunid)s' % {'lunid': lunid}
        out = self._execute_cli(cli_cmd)
        if re.search('Map Information', out):
            mapinfo = []
            try:
                for line in out.split('\r\n')[6:-2]:
                    new_line = line.split()
                    if len(new_line) < 5:
                        continue
                    mapinfo.append(new_line)
            except Exception:
                err_msg = (_('CLI out is not normal. CLI out: %s') % out)
                LOG.error(err_msg)
                raise exception.VolumeBackendAPIException(data=err_msg)

            return mapinfo
        else:
            return None

    def get_lun_details(self, lun_id):
        cli_cmd = 'showlun -lun %s' % lun_id
        out = self._execute_cli(cli_cmd)
        lun_details = {}
        if re.search('LUN Information', out):
            try:
                for line in out.split('\r\n')[4:-2]:
                    line = line.split('|')
                    key = ''.join(line[0].strip().split())
                    if len(line) < 2:
                        continue
                    val = line[1].strip()
                    lun_details[key] = val
            except Exception:
                err_msg = (_('CLI out is not normal. CLI out: %s') % out)
                LOG.error(err_msg)
                raise exception.VolumeBackendAPIException(data=err_msg)
        return lun_details

    def change_lun_ctr(self, lun_id, ctr):
        LOG.debug('change_lun_ctr: Changing LUN %(lun)s ctr to %(ctr)s.'
                  % {'lun': lun_id, 'ctr': ctr})

        cli_cmd = 'chglun -lun %s -c %s' % (lun_id, ctr)
        out = self._execute_cli(cli_cmd)

        self._assert_cli_operate_out('change_lun_ctr',
                                     'Failed to change owning controller for '
                                     'LUN %s' % lun_id,
                                     cli_cmd, out)

    def remove_map(self, volume_id, host_name, initiator=None):
        """Remove host map."""
        # Check the old host name to support the upgrade from grizzly to
        # higher versions.
        host_id = None
        if self.hostgroup_id is None:
            self.hostgroup_id = self._get_hostgroup_id(HOST_GROUP_NAME)
            if self.hostgroup_id is None:
                return None
        if initiator:
            old_host_name = HOST_NAME_PREFIX + six.text_type(hash(initiator))
            host_id = self._get_host_id(old_host_name, self.hostgroup_id)
        if host_id is None:
            if host_name and (len(host_name) > 26):
                host_name = six.text_type(hash(host_name))
            host_name = HOST_NAME_PREFIX + host_name
            host_id = self._get_host_id(host_name, self.hostgroup_id)
            if host_id is None:
                LOG.debug('remove_map: Host %s does not exist.', host_name)
                return None

        if not self._check_volume_created(volume_id):
            LOG.error(_LE('remove_map: Volume %s does not exist.'), volume_id)

        map_id = None
        map_info = self.get_host_map_info(host_id)
        if map_info:
            for maping in map_info:
                if maping[2] == volume_id:
                    map_id = maping[0]
                    break
        if map_id is not None:
            try:
                self._delete_map(map_id)
            except Exception:
                map_info = self.get_host_map_info(host_id)
                if map_info and filter(lambda x: x[2] == volume_id, map_info):
                    err_msg = (_('remove_map: Failed to delete host map to '
                                 'volume %s.') % volume_id)
                    LOG.error(err_msg)
                    raise exception.VolumeBackendAPIException(data=err_msg)
        else:
            LOG.warning(_LW('remove_map: No map between host %(host)s and '
                            'volume %(volume)s.'), {'host': host_name,
                                                    'volume': volume_id})
        return host_id

    def _delete_map(self, mapid, attempts=5):
        """Run CLI command to remove map."""
        cli_cmd = 'delhostmap -force -map %(mapid)s' % {'mapid': mapid}
        while True:
            out = self._execute_cli(cli_cmd)

            # We retry to delete host map 10s later if there are
            # IOs accessing the system.
            if re.search('command operates successfully', out):
                break
            else:
                if (re.search('there are IOs accessing the system', out) and
                        (attempts > 0)):

                    LOG.debug('_delete_map: There are IOs accessing '
                              'the system. Retry to delete host map '
                              '%(mapid)s 10s later.' % {'mapid': mapid})

                    time.sleep(10)
                    attempts -= 1
                    continue
                else:
                    err_msg = (_('_delete_map: Failed to delete host map '
                                 '%(mapid)s.\nCLI out: %(out)s')
                               % {'mapid': mapid,
                                  'times': attempts,
                                  'out': out})
                    LOG.error(err_msg)
                    raise exception.VolumeBackendAPIException(data=err_msg)

    def delete_hostport(self, portid, attempts=5):
        """Run CLI command to delete host port."""
        cli_cmd = ('delhostport -force -p %(portid)s' % {'portid': portid})
        while True:
            out = self._execute_cli(cli_cmd)
            # We retry to delete host 10s later if there are
            # IOs accessing the system.
            if (re.search('the initiator has requests to be performed', out)
               and (attempts > 0)):
                LOG.debug('delhostport: There are IOs accessing '
                          'the system. Retry to delete host port '
                          '%(portid)s 10s later.', {'portid': portid})

                time.sleep(10)
                attempts -= 1
                continue
            else:
                self._assert_cli_operate_out(
                    'delete_hostport',
                    'Failed to delete host port %s.' % portid,
                    cli_cmd, out)
                break

    def delete_host(self, hostid):
        """Run CLI command to delete host."""
        cli_cmd = ('delhost -force -host %(hostid)s' % {'hostid': hostid})
        out = self._execute_cli(cli_cmd)

        self._assert_cli_operate_out('delete_host',
                                     'Failed to delete host. %s.' % hostid,
                                     cli_cmd, out)

    def get_volume_stats(self, refresh=False):
        """Get volume stats.

        If 'refresh' is True, run update the stats first.
        """
        if refresh:
            self._update_volume_stats()

        return self._stats

    def _update_pool_info(self, pool_name, pool_type, pool_dev, disk_info):
        pool_info = {}
        pool_info['pool_name'] = pool_name
        pool_info['QoS_support'] = False
        pool_info['reserved_percentage'] = 0
        pool_info['total_capacity_gb'] = 0.0
        pool_info['free_capacity_gb'] = 0.0
        key = 'TotalCapacity(MB)'

        pool_details = self.get_pool_details(pool_type, pool_dev[0])
        if 'Thin' == pool_type:
            pool_info['free_capacity_gb'] = (float(pool_dev[4]) / 1024)
            pool_info['total_capacity_gb'] = (float(pool_details[key]) / 1024)
            pool_info['thin_provisioning_support'] = True
        elif 'Thick' == pool_type:
            pool_info['free_capacity_gb'] = (float(pool_dev[3]) / 1024)
            pool_info['total_capacity_gb'] = (float(pool_details[key]) / 1024)
            pool_info['thick_provisioning_support'] = True

        if not self._is_pool_normal(pool_details, disk_info):
            pool_info['free_capacity_gb'] = 0.0
            pool_info['total_capacity_gb'] = 0.0

        return pool_info

    def _update_volume_stats(self):
        """Retrieve stats info from volume group."""

        LOG.debug("_update_volume_stats: Updating volume stats.")
        self.update_login_info()
        params_conf = self._parse_conf_lun_params()
        pools_conf = params_conf['StoragePool']

        data = {}
        data['vendor_name'] = 'Huawei'
        data['pools'] = []
        thick_pools = self._get_dev_pool_info('Thick')
        thin_pools = self._get_dev_pool_info('Thin')
        disk_info = self._get_disk_info()

        for pool_conf in pools_conf:
            is_find = False
            for pool_dev in thick_pools:
                if pool_dev[5] == pool_conf:
                    pool_info = self._update_pool_info(pool_conf,
                                                       'Thick',
                                                       pool_dev,
                                                       disk_info)
                    data['pools'].append(pool_info)
                    is_find = True

            for pool_dev in thin_pools:
                if pool_dev[1] == pool_conf:
                    pool_info = self._update_pool_info(pool_conf,
                                                       'Thin',
                                                       pool_dev,
                                                       disk_info)
                    data['pools'].append(pool_info)
                    is_find = True

            if is_find is not True:
                pool_info = self._update_pool_info(pool_conf, '',
                                                   pool_dev, disk_info)

        self._stats = data

    def _get_dev_pool_info(self, pooltype):
        """Get pools information created in storage device.

        Return a list whose elements are also list.

        """

        cli_cmd = ('showpool' if pooltype == 'Thin' else 'showrg')
        out = self._execute_cli(cli_cmd)

        test = (re.search('Pool Information', out) or
                re.search('RAID Group Information', out))
        if test:
            pool = out.split('\r\n')[6:-2]
            return [line.split() for line in pool]

        return []

    def get_pool_details(self, pooltype, pool_id):
        cli_cmd = ('showpool -pool ' if pooltype == 'Thin' else 'showrg -rg ')
        cli_cmd += '%s' % pool_id
        out = self._execute_cli(cli_cmd)

        test = (re.search('Pool Information', out) or
                re.search('RAID Group Information', out))
        self._assert_cli_out(test, 'get_pool_details',
                             'No pool details found.', cli_cmd, out)

        lun_details = {}
        try:
            for line in out.split('\r\n')[4:-2]:
                line = line.split('|')
                key = ''.join(line[0].strip().split())
                if len(line) < 2:
                    continue
                val = line[1].strip()
                lun_details[key] = val
        except Exception:
            err_msg = (_('CLI out is not normal. CLI out: %s') % out)
            LOG.error(err_msg)
            raise exception.VolumeBackendAPIException(data=err_msg)
        return lun_details

    def _is_pool_normal(self, pool_details, disk_info):
        if pool_details['Status'] != 'Normal':
            LOG.warning(_LW('%s status is not normal'), pool_details['Name'])
            return False

        disk_list = pool_details['MemberDiskList'].split(';')
        for disk in disk_list:
            if (disk and not self._is_disk_available(disk, disk_info)):
                LOG.warning(_LW('disk %(disk)s in pool %(pool)s'
                                ' is not available'),
                            {'disk': disk, 'pool': pool_details['Name']})
                return False

        return True

    def _get_disk_info(self, info_type='logic'):
        cli_cmd = 'showdisk -' + info_type
        out = self._execute_cli(cli_cmd)

        test = re.search('Disk Information', out)
        self._assert_cli_out(test, '_get_disk_info',
                             'No disk information found.', cli_cmd, out)
        return out

    def _is_disk_available(self, disk_name, disk_info):
        pattern = r"\(%s\)\s+(Normal|Reconstructed)" % disk_name
        if re.search(pattern, disk_info):
            return True

        LOG.warning(_LW('disk (%s) status is unavailable'), disk_name)
        return False

    def get_tgt_iqn(self, port_ip):
        """Run CLI command to get target iSCSI iqn.

        The iqn is formed with three parts:
        iSCSI target name + iSCSI port info + iSCSI IP

        """

        LOG.debug('get_tgt_iqn: iSCSI IP is %s.' % port_ip)

        cli_cmd = 'showiscsitgtname'
        out = self._execute_cli(cli_cmd)

        self._assert_cli_out(re.search('ISCSI Name', out),
                             'get_tgt_iqn',
                             'Failed to get iSCSI target %s iqn.' % port_ip,
                             cli_cmd, out)

        lines = out.split('\r\n')
        try:
            index = lines[4].index('iqn')
            iqn_prefix = lines[4][index:].strip()
        except Exception:
            err_msg = (_('CLI out is not normal. CLI out: %s') % out)
            LOG.error(err_msg)
            raise exception.VolumeBackendAPIException(data=err_msg)
        # Here we make sure port_info won't be None.
        port_info = self._get_iscsi_tgt_port_info(port_ip)
        ctr = ('0' if port_info[0] == 'A' else '1')
        interface = '0' + port_info[1]
        port = '0' + port_info[2][1:]
        iqn_suffix = ctr + '02' + interface + port
        # iqn_suffix should not start with 0
        while(True):
            if iqn_suffix.startswith('0'):
                iqn_suffix = iqn_suffix[1:]
            else:
                break

        iqn = iqn_prefix + ':' + iqn_suffix + ':' + port_info[3]

        LOG.debug('get_tgt_iqn: iSCSI target iqn is %s.' % iqn)

        return (iqn, port_info[0])

    def _get_iscsi_tgt_port_info(self, port_ip):
        """Get iSCSI Port information of storage device."""
        cli_cmd = 'showiscsiip'
        out = self._execute_cli(cli_cmd)
        if re.search('iSCSI IP Information', out):
            for line in out.split('\r\n')[6:-2]:
                tmp_line = line.split()
                if len(tmp_line) < 4:
                    continue
                if tmp_line[3] == port_ip:
                    return tmp_line

        err_msg = _('_get_iscsi_tgt_port_info: Failed to get iSCSI port '
                    'info. Please make sure the iSCSI port IP %s is '
                    'configured in array.') % port_ip
        LOG.error(err_msg)
        raise exception.VolumeBackendAPIException(data=err_msg)

    def add_iscsi_port_to_host(self, hostid, connector, multipathtype=0):
        """Add an iSCSI port to the given host.

        First, add an initiator if needed, the initiator is equivalent to
        an iSCSI port. Then, add the initiator to host if not added before.

        """

        initiator = connector['initiator']
        # Add an iSCSI initiator.
        if not self._initiator_added(initiator):
            self._add_initiator(initiator)
        # Add the initiator to host if not added before.
        port_name = HOST_PORT_PREFIX + six.text_type(hash(initiator))
        portadded = False
        hostport_info = self.get_host_port_info(hostid)
        if hostport_info:
            for hostport in hostport_info:
                if hostport[2] == initiator:
                    portadded = True
                    break
        if not portadded:
            cli_cmd = ('addhostport -host %(id)s -type 5 '
                       '-info %(info)s -n %(name)s -mtype %(multype)s'
                       % {'id': hostid,
                          'info': initiator,
                          'name': port_name,
                          'multype': multipathtype})
            out = self._execute_cli(cli_cmd)

            msg = ('Failed to add iSCSI port %(port)s to host %(host)s'
                   % {'port': port_name,
                      'host': hostid})
            self._assert_cli_operate_out('add_iscsi_port_to_host',
                                         msg, cli_cmd, out)

    def _initiator_added(self, ininame):
        """Check whether the initiator is already added."""
        cli_cmd = 'showiscsiini -ini %(name)s' % {'name': ininame}
        out = self._execute_cli(cli_cmd)
        return (True if re.search('Initiator Information', out) else False)

    def _add_initiator(self, ininame):
        """Add a new initiator to storage device."""
        cli_cmd = 'addiscsiini -n %(name)s' % {'name': ininame}
        out = self._execute_cli(cli_cmd)

        self._assert_cli_operate_out('_add_iscsi_host_port',
                                     'Failed to add initiator %s' % ininame,
                                     cli_cmd, out)

    def get_connected_free_wwns(self):
        """Get free connected FC port WWNs.

        If no new ports connected, return an empty list.

        """

        cli_cmd = 'showfreeport'
        out = self._execute_cli(cli_cmd)
        wwns = []
        if re.search('Host Free Port Information', out):
            for line in out.split('\r\n')[6:-2]:
                tmp_line = line.split()
                if len(tmp_line) < 5:
                    continue
                if (tmp_line[1] == 'FC') and (tmp_line[4] == 'Connected'):
                    wwns.append(tmp_line[0])

        return list(set(wwns))

    def add_fc_port_to_host(self, hostid, wwn, multipathtype=0):
        """Add a FC port to host."""
        portname = HOST_PORT_PREFIX + wwn
        cli_cmd = ('addhostport -host %(id)s -type 1 '
                   '-wwn %(wwn)s -n %(name)s -mtype %(multype)s'
                   % {'id': hostid,
                      'wwn': wwn,
                      'name': portname,
                      'multype': multipathtype})
        out = self._execute_cli(cli_cmd)

        msg = ('Failed to add FC port %(port)s to host %(host)s.'
               % {'port': portname, 'host': hostid})
        self._assert_cli_operate_out('add_fc_port_to_host', msg, cli_cmd, out)

    def get_host_port_details(self, host_id):
        cli_cmd = 'showhostpath -host %s' % host_id
        out = self._execute_cli(cli_cmd)

        self._assert_cli_out(re.search('Multi Path Information', out),
                             'get_host_port_details',
                             'Failed to get host port details.',
                             cli_cmd, out)

        port_details = []
        tmp_details = {}
        for line in out.split('\r\n')[4:-2]:
            line = line.split('|')
            # Cut-point of multipal details, usually is "-------".
            if len(line) == 1:
                port_details.append(tmp_details)
                continue
            key = ''.join(line[0].strip().split())
            val = line[1].strip()
            tmp_details[key] = val
        port_details.append(tmp_details)
        return port_details
