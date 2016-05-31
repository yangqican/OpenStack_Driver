# Copyright (c) 2013 - 2014 Huawei Technologies Co., Ltd.
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

import base64
import codecs
import os

from xml.dom.minidom import Document
from xml.etree import ElementTree as ET


def Indent(dom, node, indent = 0):
    children = node.childNodes[:]
    if indent:
        text = dom.createTextNode('\n' + '\t' * indent)
        node.parentNode.insertBefore(text, node)
    if children:
        if children[-1].nodeType == node.ELEMENT_NODE:
            text = dom.createTextNode('\n' + '\t' * indent)
            node.appendChild(text)
        for n in children:
            if n.nodeType == node.ELEMENT_NODE:
                Indent(dom, n, indent + 1)


class create_cinder_conf_file():
    def __init__(self):
        self.conf_file_name = '/etc/cinder/cinder_huawei_conf.xml'
        self.message = "\nConfig Successfully!"
        self.welcome = ("================================"
                        "============================= \n"
                        "You are configing the huawei storage "
                        "driver for OpenStack, this \n"
                        "would create a  cinder_huawei_conf.xml  "
                        "in /etc/cinder/. For    \n"
                        "advanced configuration, please edit "
                        "the config file directly.   \n"
                        "-------------------------------"
                        "-------------------------------")
        self.conf_file_exit = False
        self.SVP_IP = ''
        self.ControllerIPs = []
        self.ControllerIP_Num = 0

    def check_xmlfile(self):
        is_file_exit = os.path.isfile(self.conf_file_name)
        if is_file_exit is False:
            self.conf_file_exit = False
            return
        self.conf_file_exit = True
        tree = ET.parse(self.conf_file_name)
        root = tree.getroot()
        self.Product = root.findtext('Storage/Product').strip()
        self.Protocol = root.findtext('Storage/Protocol').strip()

        if self.Product == 'T':
            while True:
                text = ("Storage/ControllerIP%s" % (self.ControllerIP_Num))
                node = root.find(text)
                if node is None:
                    break
                else:
                    controllerIP_Tmp = root.findtext(text).strip()
                    self.ControllerIPs.append(controllerIP_Tmp)
                    self.ControllerIP_Num = self.ControllerIP_Num + 1
        self.RestURL = root.findtext('Storage/RestURL').strip()
        if self.RestURL:
            self.SVP_IP = self.RestURL[8:]
            self.SVP_IP = self.SVP_IP[:-20]

        self.LUNType = root.findtext('LUN/LUNType').strip()
        StoragePool = root.find('LUN/StoragePool')
        self.StoragePool = StoragePool.get('Name')
        self.DefaultTargetIP = root.findtext('iSCSI/DefaultTargetIP').strip()
        host = root.find('Host')
        self.HostIP = host.get('HostIP')
        self.OSType = host.get('OSType')

    def create_xmlfile(self):
        print(self.welcome)
        self.check_xmlfile()
        doc = Document()
        config = doc.createElement('config')
        doc.appendChild(config)
        storage = doc.createElement('Storage')
        config.appendChild(storage)
        if self.conf_file_exit:
            text_Product = ("Product:[%s]" % (self.Product))
            text_Protocol = ("Protocol:[%s]" % (self.Protocol))
            text_LUNType = ("LUNType:[%s]" % (self.LUNType))
            text_StoragePool = ("StoragePool:[%s]" % (self.StoragePool))
            text_HostIP = ("HostIP:[%s]" % (self.HostIP))
            text_OSType = ("OSType:[%s]" % (self.OSType))
            if self.Product == 'T':
                text_ControllerIP_Num = ("The number of Control ip "
                                         "you want to cinfig:[%d]"
                                         % (self.ControllerIP_Num))
            else:
                text_ControllerIP_Num = ("The number of Control ip "
                                         "you want to cinfig:")
            if self.Protocol == 'FC':
                text_DefaultTargetIP = ("DefaultTargetIP:")
            else:
                text_DefaultTargetIP = ("DefaultTargetIP:[%s]"
                                        % (self.DefaultTargetIP))

        else:
            text_Product = ("Product:")
            text_Protocol = ("Protocol:")
            text_LUNType = ("LUNType:")
            text_StoragePool = ("StoragePool:")
            text_DefaultTargetIP = ("DefaultTargetIP:")
            text_HostIP = ("HostIP:")
            text_OSType = ("OSType:")
            text_ControllerIP_Num = ("The number of Control ip "
                                     "you want to cinfig:")

        if self.SVP_IP:
            text_SVP_IP = ("SVP IP:[%s]" % (self.SVP_IP))
        else:
            text_SVP_IP = ("SVP IP:")

        v_Product = raw_input(text_Product)
        if not v_Product:
            v_Product = self.Product
        Product = doc.createElement('Product')
        Product_text = doc.createTextNode(v_Product)
        Product.appendChild(Product_text)
        storage.appendChild(Product)
        v_Protocol = raw_input(text_Protocol)
        if not v_Protocol:
            v_Protocol = self.Protocol
        Protocol = doc.createElement('Protocol')
        Protocol_text = doc.createTextNode(v_Protocol)
        Protocol.appendChild(Protocol_text)
        storage.appendChild(Protocol)

        if v_Product == 'T':
            ControllerIP_Num_str = raw_input(text_ControllerIP_Num)
            if (not ControllerIP_Num_str) and (self.ControllerIP_Num):
                ControllerIP_Num_int = self.ControllerIP_Num
            else:
                ControllerIP_Num_int = int(ControllerIP_Num_str)
            controllerIPs = []
            for i in range(1, ControllerIP_Num_int + 1):
                if ((self.ControllerIP_Num >= ControllerIP_Num_int)
                   and self.ControllerIPs[i - 1]):
                    text = ("ControllerIP%s:[%s]"
                            % ((i - 1), (self.ControllerIPs[i - 1])))
                else:
                    text = ("ControllerIP%s:" % (i - 1))
                controllerIP_Tmp = raw_input(text)
                if (not controllerIP_Tmp) and (self.ControllerIPs[i - 1]):
                    controllerIPs.append(self.ControllerIPs[i - 1])
                else:
                    controllerIPs.append(controllerIP_Tmp)

            for i in range(1, ControllerIP_Num_int + 1):
                text = ("ControllerIP%s" % (i - 1))
                controllerip = doc.createElement(text)
                controllerip_text = doc.createTextNode(controllerIPs[i - 1])
                controllerip.appendChild(controllerip_text)
                storage.appendChild(controllerip)
        else:
            controllerip = doc.createElement('ControllerIP0')
            controllerip_text = doc.createTextNode('')
            controllerip.appendChild(controllerip_text)
            storage.appendChild(controllerip)

        if v_Product == '18000':
            v_SVP_IP = raw_input(text_SVP_IP)
            if (not v_SVP_IP) and (self.SVP_IP):
                v_SVP_IP = self.SVP_IP
            V_RestURL = 'https://' + v_SVP_IP + '/deviceManager/rest/'
        else:
            V_RestURL = ''
        RestURL = doc.createElement('RestURL')
        RestURL_text = doc.createTextNode(V_RestURL)
        RestURL.appendChild(RestURL_text)
        storage.appendChild(RestURL)

        v_UserName = raw_input("UserName:")
        v_UserName = '!$$$' + base64.b64encode(v_UserName)
        username = doc.createElement('UserName')
        username_text = doc.createTextNode(v_UserName)
        username.appendChild(username_text)
        storage.appendChild(username)
        v_UserPassword = raw_input("UserPassword:")
        v_UserPassword = '!$$$' + base64.b64encode(v_UserPassword)
        userpassword = doc.createElement('UserPassword')
        userpassword_text = doc.createTextNode(v_UserPassword)
        userpassword.appendChild(userpassword_text)
        storage.appendChild(userpassword)
        lun = doc.createElement('LUN')
        config.appendChild(lun)
        v_LUNType = raw_input(text_LUNType)
        if (not v_LUNType) and (self.LUNType):
            v_LUNType = self.LUNType
        LUNType = doc.createElement('LUNType')
        LUNType_text = doc.createTextNode(v_LUNType)
        LUNType.appendChild(LUNType_text)
        lun.appendChild(LUNType)
        '''
        v_StripUnitSize = raw_input("StripUnitSize:[64]")
        if not v_StripUnitSize:
            v_StripUnitSize = '64'
        '''
        StripUnitSize = doc.createElement('StripUnitSize')
        StripUnitSize_text = doc.createTextNode('64')
        StripUnitSize.appendChild(StripUnitSize_text)
        lun.appendChild(StripUnitSize)
        '''
        v_WriteType = raw_input("WriteType:[1]")
        if not v_WriteType:
            v_WriteType = '1'
        '''
        WriteType = doc.createElement('WriteType')
        WriteType_text = doc.createTextNode('1')
        WriteType.appendChild(WriteType_text)
        lun.appendChild(WriteType)
        '''
        v_MirrorSwitch = raw_input("MirrorSwitch:[1]")
        if not v_MirrorSwitch:
            v_MirrorSwitch = '1'
        '''
        MirrorSwitch = doc.createElement('MirrorSwitch')
        MirrorSwitch_text = doc.createTextNode('1')
        MirrorSwitch.appendChild(MirrorSwitch_text)
        lun.appendChild(MirrorSwitch)
        '''
        v_Prefetch_Type = raw_input("Prefetch Type:[0]")
        v_Prefetch_Value = raw_input("Prefetch Value:[0]")
        if not v_Prefetch_Type:
            v_Prefetch_Type = '0'
        if not v_Prefetch_Value:
            v_Prefetch_Value = '0'
        '''
        prefetch = doc.createElement('Prefetch')
        prefetch.setAttribute('Type', '0')
        prefetch.setAttribute('Value', '0')
        lun.appendChild(prefetch)

        v_StoragePool = raw_input(text_StoragePool)
        if (not v_StoragePool) and (self.StoragePool):
            v_StoragePool = self.StoragePool
        StoragePool = doc.createElement('StoragePool')
        StoragePool.setAttribute('Name', v_StoragePool)
        lun.appendChild(StoragePool)

        if v_Protocol == 'iSCSI':
            iscsi = doc.createElement('iSCSI')
            config.appendChild(iscsi)
            v_DefaultTargetIP = raw_input(text_DefaultTargetIP)
            if (not v_DefaultTargetIP) and (self.DefaultTargetIP):
                v_DefaultTargetIP = self.DefaultTargetIP
            defaulttargetip = doc.createElement('DefaultTargetIP')
            defaulttargetip_text = doc.createTextNode(v_DefaultTargetIP)
            defaulttargetip.appendChild(defaulttargetip_text)
            iscsi.appendChild(defaulttargetip)

            initiator = doc.createElement('Initiator')
            initiator.setAttribute('Name', 'xxxxxx')
            initiator.setAttribute('TargetIP', '192.168.100.2')
            iscsi.appendChild(initiator)

            initiator = doc.createElement('Initiator')
            initiator.setAttribute('Name', 'xxxxxx')
            initiator.setAttribute('TargetIP', 'x.x.x.x')
            iscsi.appendChild(initiator)
        else:
            iscsi = doc.createElement('iSCSI')
            config.appendChild(iscsi)
            defaulttargetip = doc.createElement('DefaultTargetIP')
            defaulttargetip_text = doc.createTextNode('')
            defaulttargetip.appendChild(defaulttargetip_text)
            iscsi.appendChild(defaulttargetip)

        v_HostIP = raw_input(text_HostIP)
        if (not v_HostIP) and (self.HostIP):
            v_HostIP = self.HostIP
        v_Host_OSType = raw_input(text_OSType)
        if (not v_Host_OSType) and (self.OSType):
            v_Host_OSType = self.OSType
        Host = doc.createElement('Host')
        Host.setAttribute('HostIP', v_HostIP)
        Host.setAttribute('OSType', v_Host_OSType)
        config.appendChild(Host)

        doccopy = doc.cloneNode(True)
        Indent(doccopy, doccopy.documentElement)
        cinder_conf_file = open(self.conf_file_name, 'w')
        writer = codecs.lookup('utf-8')[3](cinder_conf_file)
        doccopy.writexml(writer, encoding = 'utf-8')
        cinder_conf_file.close()
        doccopy.unlink()

        cinder_conf_file = open(self.conf_file_name, 'r')
        file_content = cinder_conf_file.read()
        cinder_conf_file.close()

        pos = file_content.find('<config>')
        file_content = file_content[:pos] + '\n' + file_content[pos:]
        cinder_conf_file = open(self.conf_file_name, 'w')
        cinder_conf_file.write(file_content)
        cinder_conf_file.close()

        print(self.message)

ConfFile = create_cinder_conf_file()
ConfFile.create_xmlfile()
