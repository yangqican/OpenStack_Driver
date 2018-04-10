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

STATUS_HEALTH = '1'
STATUS_ACTIVE = '43'
STATUS_RUNNING = '10'
STATUS_VOLUME_READY = '27'
STATUS_LUNCOPY_READY = '40'
STATUS_QOS_ACTIVE = '2'
STATUS_QOS_INACTIVATED = '45'
STATUS_SNAPSHOT_INACTIVE = '45'
LUN_TYPE = '11'
SNAPSHOT_TYPE = '27'

BLOCK_STORAGE_POOL_TYPE = '1'
FILE_SYSTEM_POOL_TYPE = '2'

HOSTGROUP_PREFIX = 'OpenStack_HostGroup_'
LUNGROUP_PREFIX = 'OpenStack_LunGroup_'
MAPPING_VIEW_PREFIX = 'OpenStack_Mapping_View_'
PORTGROUP_PREFIX = 'OpenStack_PortGroup_'
QOS_NAME_PREFIX = 'OpenStack_'
PORTGROUP_DESCRIP_PREFIX = "Please do NOT modify this. Engine ID: "
FC_PORT_CONNECTED = '10'
FC_INIT_ONLINE = '27'
FC_PORT_MODE_FABRIC = '0'
CAPACITY_UNIT = 1024.0 * 1024.0 * 2
DEFAULT_WAIT_TIMEOUT = 3600 * 24 * 30
DEFAULT_WAIT_INTERVAL = 5

MIGRATION_WAIT_INTERVAL = 5
MIGRATION_FAULT = '74'
MIGRATION_COMPLETE = '76'

ERROR_CONNECT_TO_SERVER = -403
ERROR_UNAUTHORIZED_TO_SERVER = -401
HTTP_ERROR_NOT_FOUND = 404
SOCKET_TIMEOUT = 52
ERROR_VOLUME_ALREADY_EXIST = 1077948993
LOGIN_SOCKET_TIMEOUT = 32
ERROR_VOLUME_NOT_EXIST = 1077939726
ERROR_LUN_NOT_EXIST = 1077936859
ERROR_SNAPSHOT_NOT_EXIST = 1077937880
FC_INITIATOR_NOT_EXIST = 1077948996
HYPERMETROPAIR_NOT_EXIST = 1077674242
REPLICATIONPAIR_NOT_EXIST = 1077937923
REPLICG_IS_EMPTY = 1077937960

RELOGIN_ERROR_PASS = [ERROR_VOLUME_NOT_EXIST]
RUNNING_NORMAL = '1'
RUNNING_SYNC = '23'
RUNNING_STOP = '41'
HEALTH_NORMAL = '1'

NO_SPLITMIRROR_LICENSE = 1077950233
NO_MIGRATION_LICENSE = 1073806606

THICK_LUNTYPE = 0
THIN_LUNTYPE = 1
MAX_NAME_LENGTH = 31
MAX_VOL_DESCRIPTION = 170
PORT_NUM_PER_CONTR = 2
MAX_QUERY_COUNT = 100

OS_TYPE = {'Linux': '0',
           'Windows': '1',
           'Solaris': '2',
           'HP-UX': '3',
           'AIX': '4',
           'XenServer': '5',
           'Mac OS X': '6',
           'VMware ESX': '7'}

LOWER_LIMIT_KEYS = ['MINIOPS', 'LATENCY', 'MINBANDWIDTH']
UPPER_LIMIT_KEYS = ['MAXIOPS', 'MAXBANDWIDTH']
PWD_EXPIRED_OR_INITIAL = (3, 4)

DEFAULT_REPLICA_WAIT_INTERVAL = 1
DEFAULT_REPLICA_WAIT_TIMEOUT = 20

REPLICA_SYNC_MODEL = '1'
REPLICA_ASYNC_MODEL = '2'
REPLICA_SPEED = '2'
REPLICA_PERIOD = '3600'
REPLICA_SECOND_RO = '2'
REPLICA_SECOND_RW = '3'
REPLICG_PERIOD = '60'

REPLICA_RUNNING_STATUS_KEY = 'RUNNINGSTATUS'
REPLICA_RUNNING_STATUS_INITIAL_SYNC = '21'
REPLICA_RUNNING_STATUS_SYNC = '23'
REPLICA_RUNNING_STATUS_SYNCED = '24'
REPLICA_RUNNING_STATUS_NORMAL = '1'
REPLICA_RUNNING_STATUS_SPLIT = '26'
REPLICA_RUNNING_STATUS_ERRUPTED = '34'
REPLICA_RUNNING_STATUS_INVALID = '35'

REPLICA_HEALTH_STATUS_KEY = 'HEALTHSTATUS'
REPLICA_HEALTH_STATUS_NORMAL = '1'

REPLICA_LOCAL_DATA_STATUS_KEY = 'PRIRESDATASTATUS'
REPLICA_REMOTE_DATA_STATUS_KEY = 'SECRESDATASTATUS'
REPLICA_DATA_SYNC_KEY = 'ISDATASYNC'
REPLICA_DATA_STATUS_SYNCED = '1'
REPLICA_DATA_STATUS_COMPLETE = '2'
REPLICA_DATA_STATUS_INCOMPLETE = '3'

SNAPSHOT_NOT_EXISTS_WARN = 'warning'
SNAPSHOT_NOT_EXISTS_RAISE = 'raise'

LUN_TYPE_MAP = {'Thick': THICK_LUNTYPE,
                'Thin': THIN_LUNTYPE}

VALID_PRODUCT = ['T', 'TV2', 'V3', 'V5', '18000', 'Dorado']
VALID_PROTOCOL = ['FC', 'iSCSI']
VALID_WRITE_TYPE = ['1', '2']
VOLUME_NOT_EXISTS_WARN = 'warning'
VOLUME_NOT_EXISTS_RAISE = 'raise'

LUN_COPY_SPEED_TYPES = (
    LUN_COPY_SPEED_LOW,
    LUN_COPY_SPEED_MEDIUM,
    LUN_COPY_SPEED_HIGH,
    LUN_COPY_SPEED_HIGHEST
) = ('1', '2', '3', '4')

REPLICG_STATUS_NORMAL = '1'
REPLICG_STATUS_SYNCING = '23'
REPLICG_STATUS_TO_BE_RECOVERD = '33'
REPLICG_STATUS_INTERRUPTED = '34'
REPLICG_STATUS_SPLITED = '26'
REPLICG_STATUS_INVALID = '35'
REPLICG_HEALTH_NORMAL = '1'

OPTIMAL_MULTIPATH_NUM = 16
