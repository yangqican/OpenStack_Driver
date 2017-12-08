# Copyright (c) 2016 Huawei Technologies Co., Ltd.
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

from oslo_log import log as logging

from cinder import exception
from cinder.i18n import _
from cinder.volume.drivers.huawei import constants


LOG = logging.getLogger(__name__)


class FCZoneHelper(object):
    """FC zone helper for Huawei driver."""

    def __init__(self, fcsan_lookup_service, client):
        self.fcsan = fcsan_lookup_service
        self.client = client

    def _get_fc_ports_info(self):
        ports_info = {}
        contr_map = {}

        fc_ports = self.client.get_fc_ports()
        for port in fc_ports:
            if port['RUNNINGSTATUS'] == constants.FC_PORT_CONNECTED:
                location = port['PARENTID'].split('.')
                port_info = {'id': port['ID'],
                             'bandwidth': port['RUNSPEED'],
                             'contr': location[0],
                             'wwn': port['WWN']}
                ports_info[port['WWN']] = port_info

                if location[0] not in contr_map:
                    contr_map[location[0]] = [port['WWN']]
                else:
                    contr_map[location[0]].append(port['WWN'])

        return ports_info, contr_map

    def _count_port_weight(self, port, ports_info):
        LOG.debug("Count weight for port: %s.", port)
        portgs = self.client.get_portgs_by_portid(ports_info[port]['id'])
        LOG.debug("Port %(port)s belongs to PortGroup %(portgs)s.",
                  {"port": port, "portgs": portgs})
        weight = 0
        for portg in portgs:
            views = self.client.get_views_by_portg(portg)
            if not views:
                LOG.debug("PortGroup %s doesn't belong to any view.", portg)
                continue

            LOG.debug("PortGroup %(portg)s belongs to view %(views)s.",
                      {"portg": portg, "views": views[0]})
            # In fact, there is just one view for one port group.
            lungroup = self.client.get_lungroup_by_view(views[0])
            lun_num = self.client.get_obj_count_from_lungroup(lungroup)
            ports_in_portg = self.client.get_ports_by_portg(portg)
            LOG.debug("PortGroup %(portg)s contains ports: %(ports)s.",
                      {"portg": portg, "ports": ports_in_portg})
            total_bandwidth = 0
            for port_pg in ports_in_portg:
                if port_pg in ports_info:
                    total_bandwidth += int(ports_info[port_pg]['bandwidth'])

            LOG.debug("Total bandwidth for PortGroup %(portg)s is %(bindw)s.",
                      {"portg": portg, "bindw": total_bandwidth})

            if total_bandwidth:
                weight += float(lun_num) / float(total_bandwidth)

        bandwidth = float(ports_info[port]['bandwidth'])
        return (weight, 10000 / bandwidth)

    def _get_weighted_ports_per_contr(self, ports, ports_info):
        port_weight_map = {}
        for port in ports:
            port_weight_map[port] = self._count_port_weight(port, ports_info)

        LOG.debug("port_weight_map: %s", port_weight_map)
        sorted_ports = sorted(port_weight_map.items(), key=lambda d: d[1])
        weighted_ports = []
        count = 0
        for port in sorted_ports:
            if count >= constants.PORT_NUM_PER_CONTR:
                break
            weighted_ports.append(port[0])
            count += 1
        return weighted_ports

    def _get_weighted_ports(self, fabric_contrs, ports_info):
        LOG.debug("select ports from controllers: %s", fabric_contrs)
        weighted_ports = []
        for k in fabric_contrs:
            if len(fabric_contrs[k]) <= 2:
                weighted_ports.extend(fabric_contrs[k])
            else:
                select_ports = self._get_weighted_ports_per_contr(
                    fabric_contrs[k], ports_info)
                weighted_ports.extend(select_ports)
        return weighted_ports

    def _filter_by_fabric(self, wwns, ports):
        """Filter FC ports and initiators connected to fabrics."""
        ini_tgt_map = self.fcsan.get_device_mapping_from_network(wwns, ports)

        def _get_fabric_connection(fabric_name, fabric):
            ini_port_wwn_list = fabric.get('initiator_port_wwn_list')
            tgt_port_wwn_list = fabric.get('target_port_wwn_list')

            if not ini_port_wwn_list or not tgt_port_wwn_list:
                LOG.warning("Fabric %(fabric_name)s doesn't really "
                            "connect host and array: %(fabric)s.",
                            {'fabric_name': fabric_name,
                             'fabric': fabric})
                return None

            return ini_port_wwn_list, tgt_port_wwn_list

        fabric_connected = []
        for fabric in ini_tgt_map:
            ini_tgt_tuple = _get_fabric_connection(
                fabric, ini_tgt_map[fabric])

            if ini_tgt_tuple:
                fabric_connected.append(ini_tgt_tuple)

        if not fabric_connected:
            msg = _("No valid fabric connection from: %s.") % ini_tgt_map
            LOG.error(msg)
            raise exception.VolumeBackendAPIException(data=msg)

        LOG.info("Fabric connected: %s.", fabric_connected)
        return fabric_connected

    def build_ini_targ_map(self, wwns, host_id, lun_id):
        ports_info, contr_map = self._get_fc_ports_info()

        # Check if there is already a port group in the view.
        view_name = constants.MAPPING_VIEW_PREFIX + host_id
        portg_name = constants.PORTGROUP_PREFIX + host_id

        view_id = self.client.find_mapping_view(view_name)
        portg_id = None
        if view_id:
            portg_id = self.client.get_portgroup_by_view(view_id)
        if not portg_id:
            portg_id = self.client.get_tgt_port_group(portg_name)

        exist_tgt_ports = []
        if portg_id:
            portg_ports = self.client.get_fc_ports_by_portgroup(portg_id)
            exist_tgt_ports = list(portg_ports.keys())

        # Filter initiators and ports that connected to fabrics.
        fabric_connected = self._filter_by_fabric(wwns, list(ports_info.keys()))

        def _select_fabric_tgt_ports(fabric_tgt_ports):
            new_ports = set(fabric_tgt_ports) - set(exist_tgt_ports)
            fabric_contrs = {}
            for k in contr_map:
                fabric_contrs[k] = [port for port in contr_map[k]
                                    if port in new_ports]
            return self._get_weighted_ports(fabric_contrs, ports_info)

        init_targ_map = {}
        select_tgt_ports = []
        for fabric in fabric_connected:
            select_ports = _select_fabric_tgt_ports(fabric[1])
            select_tgt_ports += select_ports
            for ini in fabric[0]:
                init_targ_map[ini] = select_ports

        if not portg_id:
            portg_id = self.client.create_portg(portg_name)

        for port in select_tgt_ports:
            self.client.add_port_to_portg(portg_id, ports_info[port]['id'])

        total_tgt_wwns = select_tgt_ports + exist_tgt_ports
        LOG.debug("build_ini_targ_map: Port group name: %(portg_name)s, "
                  "init_targ_map: %(map)s, target_wwns: %(wwns)s.",
                  {"portg_name": portg_name,
                   "map": init_targ_map,
                   "wwns": total_tgt_wwns})
        return total_tgt_wwns, portg_id, init_targ_map

    def get_init_targ_map(self, wwns, host_id):
        error_ret = ([], None, {})
        if not host_id:
            return error_ret

        view_name = constants.MAPPING_VIEW_PREFIX + host_id
        view_id = self.client.find_mapping_view(view_name)
        if not view_id:
            return error_ret
        portg_id = self.client.get_portgroup_by_view(view_id)

        ports = {}
        if portg_id:
            ports = self.client.get_fc_ports_by_portgroup(portg_id)

        for port_id in ports.values():
            self.client.remove_port_from_portgroup(portg_id, port_id)
        init_targ_map = {}
        for wwn in wwns:
            init_targ_map[wwn] = list(ports.keys())
        return list(ports.keys()), portg_id, init_targ_map
