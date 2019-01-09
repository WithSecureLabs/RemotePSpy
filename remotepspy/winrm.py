import sys
import os
import logging
import traceback
import ctypes
import binascii
import base64
import struct
import xml.etree.ElementTree as ET
import threading

from remotepspy.psrp import PSRPDefragmenter
from remotepspy.psrp import PSRPParser
from remotepspy.simple_command_tracer import SimpleCommandTracer


class WSManPS:
    """Accepts complete WS-Man SOAP documents (such as those output by SoapDefragmenter), identifies those relating to
    PowerShell Remote Protocol (PSRP), and extracts raw PSRP data ready to be processed by the next layer.
    Non-PSRP related WS-Man messages are simply ignored.
    """

    LOGGER_NAME = 'RemotePSpy.WSManPS'

    NAMESPACES = {
        'w': 'http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd',
        'ps': 'http://schemas.microsoft.com/powershell',
        'rsp': 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell',
        'f': 'http://schemas.microsoft.com/wbem/wsman/1/wsmanfault',
        'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
        's': 'http://www.w3.org/2003/05/soap-envelope',
        'a': 'http://schemas.xmlsoap.org/ws/2004/08/addressing',
        'p': 'http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd',
        'x': 'http://schemas.xmlsoap.org/ws/2004/09/transfer'
    }

    PS_RESOURCE_URI = 'http://schemas.microsoft.com/powershell/Microsoft.PowerShell'

    ADDRESS_ANON = 'http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous'

    CMD_STATE_DONE = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done'

    WIMLIB_COMPRESSION_TYPE_XPRESS = 1

    def __init__(self):
        self.logger = logging.getLogger(WSManPS.LOGGER_NAME)
        simple_cmd_logger = SimpleCommandTracer()
        psrp_parser = PSRPParser(simple_cmd_logger.message)
        self.psrp_defrag = PSRPDefragmenter(psrp_parser.new_psrp_message)
        # Tracks the MessageID of Receive requests known to be PowerShell related, to allow matching the ReceiveResponse
        # and to link it to a ShellID.
        self.receive_msgs = {}
        # Tracks the MessageID of Command requests known to be PowerShell related, to allow matching to the
        # CommandResponse which will contain the CommandId so we can move tracking into self.commands.
        # Also links it to a ShellID.
        self.command_msgs = {}
        # Tracks the MessageID of Delete requests known to be PowerShell relates, to allow matching to the
        # DeleteResponse. Also links it to a ShellID.
        self.delete_msgs = {}
        # Tracks the MessageID of Create requests. These create Shells, and the response will contain the MessageID in
        # the RelatesTo field, and a ShellId we will end up tracking via the PSRPDefragmenter.
        self.create_msgs = []
        # Tracks CommandId's known to relate to PowerShell
        self.commands = {}
        # Actions known to relate to PowerShell, and pointers to handler functions
        self.ps_actions = {
            'http://schemas.xmlsoap.org/ws/2004/09/transfer/CreateResponse': self._action_create_response,
            'http://schemas.xmlsoap.org/ws/2004/09/transfer/DeleteResponse': self._action_delete_response,
            'http://schemas.xmlsoap.org/ws/2004/09/transfer/Create': self._action_create,
            'http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete': self._action_delete,
            'http://schemas.dmtf.org/wbem/wsman/1/wsman/fault': self._action_fault,
            'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandResponse': self._action_command_response,
            'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/ReceiveResponse': self._action_receive_response,
            'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command': self._action_command,
            'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive': self._action_receive,
            'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal': self._action_signal,
        }
        # Load and instantiate a libwim xpress decompressor, for decompression of data in PSRP streams.
        try:
            if 'AMD64' in sys.version:
                dll = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'libwim_bin', '64', 'libwim-15.dll')
            else:
                dll = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'libwim_bin', '32', 'libwim-15.dll')
            self.libwim = ctypes.CDLL(dll)
            # Set to 64k, but I'm not sure the xpress decompressor even uses this value!
            max_block_size = 65536
            self.xpress_decompressor = ctypes.c_void_p()
            # Normally we would need to free this after use, but as we expect it to live the lifetime of the program, we
            # don't bother.
            ret = self.libwim.wimlib_create_decompressor(WSManPS.WIMLIB_COMPRESSION_TYPE_XPRESS, max_block_size,
                                                         ctypes.byref(self.xpress_decompressor))
            if ret != 0:
                self.libwim = None
                self.xpress_decompressor = None
                self.logger.error('Failed to create libwim decompressor. We will proceed and hope we are lucky enough '
                                  'to not encounter compression.')
        except (NameError, OSError):
            self.libwim = None
            self.xpress_decompressor = None
            self.logger.error('Failed to load libwim-15.dll and instantiate an xpress decompressor. We will proceed '
                              'and hope we are lucky enough to not encounter compression.')

    def new_soap(self, activity_id, pid, tid, soap):
        try:
            doc = ET.fromstring(soap)
            header = doc.find('s:Header', WSManPS.NAMESPACES)
            if header is None:
                self.logger.error('Could not find header in WS-Man SOAP (activity_id: {}, pid: {}, tid: {}): {}'
                                  ''.format(activity_id, pid, tid, soap))
                return
            action = header.find('a:Action', WSManPS.NAMESPACES)
            if action is not None:
                action = action.text
            if action is None:
                self.logger.error('Could not find action in WS-Man SOAP header (activity_id: {}, pid: {}, tid: {}): {}'
                                  ''.format(activity_id, pid, tid, soap))
                return
            if action not in self.ps_actions:
                self.logger.debug('WS-Man did not look related to PowerShell so ignored due to unrecognised action '
                                  '(action: {}, activity_id: {}, pid: {}, tid: {}): {}'
                                  ''.format(action, activity_id, pid, tid, soap))
                return
            resource_uri = header.find('w:ResourceURI', WSManPS.NAMESPACES)
            if resource_uri is not None:
                resource_uri = resource_uri.text
            if resource_uri is not None and resource_uri != WSManPS.PS_RESOURCE_URI:
                self.logger.debug('WS-Man did not look related to PowerShell so ignored due to unrecognised '
                                  'ResourceURI (ResourceURI: {}, action: {}, activity_id: {}, pid: {}, tid: {}): {}'
                                  ''.format(resource_uri, action, activity_id, pid, tid, soap))
                return
            to = header.find('a:To', WSManPS.NAMESPACES)
            if to is not None:
                to = to.text
            message_id = header.find('a:MessageID', WSManPS.NAMESPACES)
            if message_id is not None:
                message_id = message_id.text
            # Call appropriate handler
            self.ps_actions[action](activity_id, pid, tid, doc, header, action, to, message_id,
                                    resource_uri=resource_uri)
        except Exception:
            tb = traceback.format_exc()
            self.logger.error('Error parsing SOAP XML (activity_id: {}, pid: {}, tid: {}): {} | Exception info: {}'
                              ''.format(activity_id, pid, tid, soap, tb))

    def _action_create_response(self, activity_id, pid, tid, doc, header, action, to, message_id, resource_uri=None):
        # See if there is a match in create_msgs
        relates_to = header.find('a:RelatesTo', WSManPS.NAMESPACES)
        if relates_to is not None:
            relates_to = relates_to.text
        pending_match = False
        if relates_to is not None:
            if relates_to in self.create_msgs:
                pending_match = True
                self.create_msgs.remove(relates_to)  # Stop tracking
        # Extract some other important values
        resource_created = doc.find('s:Body/x:ResourceCreated', WSManPS.NAMESPACES)
        if resource_created is None:
            self.logger.error('Could not find s:Body/x:ResourceCreated in CreateResponse (action: {}, activity_id: {}, '
                              'pid: {}, tid: {}): {}'.format(action, activity_id, pid, tid,
                                                             ET.tostring(doc, encoding='unicode')))
            return

        # TODO not using address yet - maybe use in combination with <a:To>?
        address = resource_created.find('a:Address', WSManPS.NAMESPACES)
        if address is not None:
            address = address.text

        res_params = resource_created.find('a:ReferenceParameters', WSManPS.NAMESPACES)
        if res_params is None:
            self.logger.error('Could not find s:Body/x:ResourceCreated/a:ReferenceParameters in CreateResponse '
                              '(action: {}, activity_id: {}, pid: {}, tid: {}): {}'
                              ''.format(action, activity_id, pid, tid, ET.tostring(doc, encoding='unicode')))
            return
        body_resource_uri = res_params.find('w:ResourceURI', WSManPS.NAMESPACES)
        if body_resource_uri is not None:
            body_resource_uri = body_resource_uri.text
        # Check whether to continue processing based on body_resource_uri and pending_match
        if not pending_match and body_resource_uri != WSManPS.PS_RESOURCE_URI:
            self.logger.debug('WS-Man CreateResponse did not look related to PowerShell so ignored due to unrecognised '
                              'ResourceURI in the Body and no previous matching Microsoft.PowerShell request '
                              '(Body-ResourceId: {}, action: {}, activity_id: {}, pid: {}, tid: {}): {}'
                              ''.format(body_resource_uri, action, activity_id, pid, tid,
                                        ET.tostring(doc, encoding='unicode')))
            return
        elif pending_match and body_resource_uri != WSManPS.PS_RESOURCE_URI:
            self.logger.warning('The ResourceURI in the body of the CreateResponse did not look like PowerShell, but '
                                'RelatesTo matches an MessageID for a PowerShell Shell Create request, so we will '
                                'continue processing it anyway. (Body-ResourceId: {}, ResourceURI: {}, action: {}, '
                                'activity_id: {}, pid: {}, tid: {}): {}'
                                ''.format(body_resource_uri, resource_uri, action, activity_id, pid, tid,
                                          ET.tostring(doc, encoding='unicode')))
        elif not pending_match and body_resource_uri == WSManPS.PS_RESOURCE_URI:
            self.logger.warning('Found a CreateRespose with a PowerShell ResourceURI for which we have no previous '
                                'matching request. (RelatesTo: {}, Body-ResourceId: {}, ResourceURI: {}, action: {}, '
                                'activity_id: {}, pid: {}, tid: {})'.format(relates_to, body_resource_uri, resource_uri,
                                                                            action, activity_id, pid, tid))
        selectors = res_params.findall('w:SelectorSet/w:Selector', WSManPS.NAMESPACES)
        shell_id = None
        for selector in selectors:
            name = selector.get('Name')
            if name == 'ShellId':
                shell_id = selector.text
                break
        if shell_id is None:
            self.logger.warning('No ShellId found in CreateResponse (ResourceURI: {}, action: {}, activity_id: {}, '
                                'pid: {}, tid: {}): {}'.format(resource_uri, action, activity_id, pid, tid,
                                                               ET.tostring(doc, encoding='unicode')))
            return
        self.logger.info('Received ShellID {} for pending Shell being tracked with MessageID {}.'.format(shell_id,
                                                                                                         message_id))
        self.psrp_defrag.set_pending_shell_id(relates_to, shell_id)

    def _action_delete_response(self, activity_id, pid, tid, doc, header, action, to, message_id, resource_uri=None):
        # Look for a a matching Delete request in self.delete_msgs to obtain the ShellID context
        relates_to = header.find('a:RelatesTo', WSManPS.NAMESPACES)
        if relates_to is not None:
            relates_to = relates_to.text
        if relates_to is None or relates_to not in self.delete_msgs:
            self.logger.debug('WS-Man DeleteResponse did not look related to PowerShell so ignored due to '
                              'unrecognised RelatedTo (action: {}, activity_id: {}, pid: {}, tid: {}): {}'
                              ''.format(action, activity_id, pid, tid, ET.tostring(doc, encoding='unicode')))
            return
        shell_id = self.delete_msgs.pop(relates_to)
        # Remove shell from tracking in the PSRPDefragmenter
        if self.psrp_defrag.has_shell(shell_id):
            self.psrp_defrag.delete_shell(shell_id)
            self.logger.info('Shell {} has been deleted (activity_id: {}, pid: {}, tid: {})'
                             ''.format(shell_id, activity_id, pid, tid))

    def _action_create(self, activity_id, pid, tid, doc, header, action, to, message_id, resource_uri=None):
        if resource_uri != WSManPS.PS_RESOURCE_URI:
            self.logger.debug('WS-Man did not look related to PowerShell so ignored due to unrecognised combination of '
                              'action and ResourceURI (action: {}, activity_id: {}, pid: {}, tid: {}): {}'
                              ''.format(action, activity_id, pid, tid, ET.tostring(doc, encoding='unicode')))
            return
        shell = doc.find('s:Body/rsp:Shell', WSManPS.NAMESPACES)
        if shell is None:
            self.logger.warning('Could not find Shell element in Create Microsoft.PowerShell request.')
            return
        # Record the Activity ID to track the CreateResponse and get the ShellId for the Shell being created here
        self._track_create(message_id)

        # Stream names do not really matter to us as it happens
        # input_streams = shell.find('rsp:InputStreams', WSManPS.NAMESPACES)
        # if input_streams is not None:
        #     input_streams = input_streams.text
        # output_streams = shell.find('rsp:OutputStreams', WSManPS.NAMESPACES)
        # if output_streams is not None:
        #     output_streams = output_streams.text

        creation_xml = shell.find('ps:creationXml', WSManPS.NAMESPACES)
        if creation_xml is not None:
            creation_xml = creation_xml.text
        # Base64 decode the contents of creation_xml and pass up to next PSRP layer
        try:
            creation_xml = base64.b64decode(creation_xml.encode('utf-8'))
            # Pass on to defragmenter
            self.logger.info('New Shell create pending. Tracking pending Shell with MessageID: {}'.format(message_id))
            self.psrp_defrag.new_pending_shell(message_id)
            self.psrp_defrag.new_fragment_data_pending_shell(message_id, creation_xml)
        except (ValueError, binascii.Error):
            tb = traceback.format_exc()
            self.logger.error('Error decoding creationXml (activity_id: {}, pid: {}, tid: {}): {} | '
                              'Exception info: '.format(activity_id, pid, tid, tb))

    def _action_delete(self, activity_id, pid, tid, doc, header, action, to, message_id, resource_uri=None):
        if not self._known_shell_id_or_resource_uri(header, resource_uri, action):
            self.logger.debug('WS-Man Delete was not associated with a known PowerShell Shell or ResourceURI, so it '
                              'will be ignored (resource_uri: {}, activity_id: {}, pid: {}, tid: {}): {}'
                              ''.format(resource_uri, activity_id, pid, tid, ET.tostring(doc, encoding='unicode')))
            return
        # Track by MessageID to match corresponding DeleteResponse and keep track of what Shell we are in
        self._track_delete(message_id, header)

    def _action_fault(self, activity_id, pid, tid, doc, header, action, to, message_id, resource_uri=None):
        pass  # TODO

    def _action_command_response(self, activity_id, pid, tid, doc, header, action, to, message_id, resource_uri=None):
        relates_to = header.find('a:RelatesTo', WSManPS.NAMESPACES)
        if relates_to is not None:
            relates_to = relates_to.text
        if relates_to is None or relates_to not in self.command_msgs:
            self.logger.debug('WS-Man CommandResponse did not look related to PowerShell so ignored due to '
                              'unrecognised RelatedTo (relates_to: {}, action: {}, activity_id: {}, pid: {}, tid: {}): '
                              '{}'.format(relates_to, action, activity_id, pid, tid,
                                          ET.tostring(doc, encoding='unicode')))
            return
        # Get the command ID
        command_id = doc.find('s:Body/rsp:CommandResponse/rsp:CommandId', WSManPS.NAMESPACES)
        if command_id is not None:
            command_id = command_id.text
        if command_id is None:
            self.logger.warning('Could not find a CommandId in CommandResponse despite it appearing to be related to a '
                                'prior PowerShell Command request based on RelatesTo/MessageID match '
                                '(action: {}, activity_id: {}, pid: {}, tid: {}): {}'
                                ''.format(action, activity_id, pid, tid, ET.tostring(doc, encoding='unicode')))
            return
        # Grab the shell_id tracked against the initial Command request, removing it from tracking there as we now track
        # it by command_id instead
        shell_id = self.command_msgs.pop(relates_to)
        self._track_command_by_id(command_id, shell_id)

    def _action_receive_response(self, activity_id, pid, tid, doc, header, action, to, message_id, resource_uri=None):
        relates_to = header.find('a:RelatesTo', WSManPS.NAMESPACES)
        if relates_to is not None:
            relates_to = relates_to.text
        if relates_to is None or relates_to not in self.receive_msgs:
            self.logger.debug('WS-Man ReceiveResponse was not associated with a known PowerShell Receive request, so '
                              'it will be ignored (relates_to: {}, activity_id: {}, pid: {}, tid: {}): {}'
                              ''.format(relates_to, activity_id, pid, tid, ET.tostring(doc, encoding='unicode')))
            return
        # Remove from receive tracking, capturing shell_id at the same time
        shell_id = self.receive_msgs.pop(relates_to)
        # Identify any commands which are finished executing
        commands_finished = {}
        command_states = doc.findall('s:Body/rsp:ReceiveResponse/rsp:CommandState', WSManPS.NAMESPACES)
        for cs_elem in command_states:
            command_id = cs_elem.get('CommandId')
            exit_code = cs_elem.find('rsp:ExitCode', WSManPS.NAMESPACES)
            if exit_code is not None:
                exit_code = exit_code.text  # Note, this will be a string, not an int. Could parse it, but real need.
            state = cs_elem.get('State')
            if command_id is not None and (state == WSManPS.CMD_STATE_DONE or exit_code is not None):
                commands_finished[command_id] = exit_code
                self.logger.info('Command {} finished with ExitCode: {}'.format(command_id, exit_code))
        # Parse out streams and pass to PSRP defragmenter
        streams = doc.findall('s:Body/rsp:ReceiveResponse/rsp:Stream', WSManPS.NAMESPACES)
        for stream_element in streams:
            name = stream_element.get('Name')
            if name is None:
                name = '<UNKNOWN_STREAM>'
            # There may not be a CommandId
            command_id = stream_element.get('CommandId')
            stream_blob = None
            try:
                stream_blob = base64.b64decode(stream_element.text.encode('utf-8'))
                if command_id is not None:
                    self.logger.debug('ReceiveResponse for CommandId {}, stream {}'.format(command_id, name))
                else:
                    self.logger.debug('ReceiveResponse, stream {}'.format(name))
            except (ValueError, binascii.Error):
                tb = traceback.format_exc()
                if command_id is None:
                    self.logger.error('Error decoding stream {}: {}'.format(name, tb))
                else:
                    self.logger.error('Error decoding stream {} for CommandId {}: {}'.format(name, command_id, tb))
            if stream_blob is not None:
                # Decompress the stream data as necessary
                decompressed_data = self._decompress_stream_data(stream_blob)
                self.psrp_defrag.new_fragment_data(shell_id, decompressed_data, command_id=command_id)
        # Remove tracking for finished commands
        for command_id, exit_code in commands_finished.items():
            self.commands.pop(command_id)

    def _action_command(self, activity_id, pid, tid, doc, header, action, to, message_id, resource_uri=None):
        # We get shell_id before calling _known_shell_id_or_resource_uri, as we need to capture and use it later
        shell_id = WSManPS._get_shell_id(header)
        if not self._known_shell_id_or_resource_uri(header, resource_uri, action, shell_id=shell_id):
            self.logger.debug('WS-Man Command was not associated with a known PowerShell Shell or ResourceURI, so it '
                              'will be ignored (resource_uri: {}, activity_id: {}, pid: {}, tid: {}): {}'
                              ''.format(resource_uri, activity_id, pid, tid, ET.tostring(doc, encoding='unicode')))
            return
        # Pull out and parse the command details from the Arguments tag
        arguments = doc.find('s:Body/rsp:CommandLine/rsp:Arguments', WSManPS.NAMESPACES)
        if arguments is not None:
            arguments = arguments.text
        if arguments is None:
            self.logger.error('Could not find s:Body/rsp:CommandLine/rsp:Arguments in Command request despite it '
                              'appearing to relate to PowerShell based on ShellId/ResourceURI '
                              '(resource_uri: {}, activity_id: {}, pid: {}, tid: {}): {}'
                              ''.format(resource_uri, activity_id, pid, tid, ET.tostring(doc, encoding='unicode')))
            return
        cmd_blob = None
        try:
            cmd_blob = base64.b64decode(arguments.encode('utf-8'))
        except (ValueError, binascii.Error):
            tb = traceback.format_exc()
            self.logger.error('Error decoding command arguments (activity_id: {}, pid: {}, tid: {}): {} | '
                              'Exception info: '.format(activity_id, pid, tid, tb))
        if cmd_blob is not None:
            self.psrp_defrag.new_fragment_data(shell_id, cmd_blob)
        # Track by MessageID to match corresponding CommandResponse and keep track of what Shell we are in
        self._track_command(message_id, header)

    def _action_receive(self, activity_id, pid, tid, doc, header, action, to, message_id, resource_uri=None):
        # We get shell_id before calling _known_shell_id_or_resource_uri, as we need to capture and use it later
        shell_id = WSManPS._get_shell_id(header)
        if not self._known_shell_id_or_resource_uri(header, resource_uri, action, shell_id=shell_id):
            self.logger.debug('WS-Man Receive was not associated with a known PowerShell Shell or ResourceURI, so it '
                              'will be ignored (resource_uri: {}, activity_id: {}, pid: {}, tid: {}): {}'
                              ''.format(resource_uri, activity_id, pid, tid, ET.tostring(doc, encoding='unicode')))
            return
        # Track by MessageID to match corresponding ReceiveResponse and keep track of what Shell we are in
        self._track_receive(message_id, header)
        # Find any CommandIds in the request. We do not care about what streams are being requested at this stage, but
        # we grab any CommandIds here in case we missed the previous CommandResponse where we usually first see the
        # CommandId. This gives us a second chance to identify PowerShell related CommandIds, so we can connect commands
        # to their stream outputs.
        desired_streams = doc.findall('s:Body/rsp:Receive/rsp:DesiredStream', WSManPS.NAMESPACES)
        for desired_stream in desired_streams:
            command_id = desired_stream.get('CommandId')
            if command_id is not None and command_id not in self.commands:
                self.logger.info('New PowerShell related CommandId ({}) found in a Receive request. This means we '
                                 'will have missed the Command request and so will only see the Command result, '
                                 'without knowing what command was executed.'.format(command_id))
                self._track_command_by_id(command_id, shell_id)

    def _action_signal(self, activity_id, pid, tid, doc, header, action, to, message_id, resource_uri=None):
        # TODO not sure if we really need to process these. It can signal a "terminate" on a command in a shell, but we
        #  will already have seen its State move to "done" and have gotten an ExitCode in the last ReceiveResponse
        #  anyway.
        pass

    @staticmethod
    def _get_shell_id(header):
        selectors = header.findall('w:SelectorSet/w:Selector', WSManPS.NAMESPACES)
        shell_id = None
        for selector in selectors:
            name = selector.get('Name')
            if name == 'ShellId':
                shell_id = selector.text
                break
        return shell_id

    def _known_shell_id_or_resource_uri(self, header, resource_uri, action, shell_id=None):
        if shell_id is None:
            shell_id = WSManPS._get_shell_id(header)
        if self.psrp_defrag.has_shell(shell_id):
            # TODO here we may want to check if we already have a <a:To> or <a:Address> value associated with the Shell and to add it if not
            return True
        else:
            if resource_uri == WSManPS.PS_RESOURCE_URI:
                if shell_id is not None:
                    self.logger.info('{} request with unknown ShellId {}, but with a PowerShell ResourceURI. Will now '
                                     'start tracking this ShellId.'.format(action, shell_id))
                    # TODO we may want to add a <a:To> or <a:Address> value to the Shell here if we are able
                    self.psrp_defrag.new_shell(shell_id)
                return True
            else:
                return False

    # This abstracts out the common work performed by many specific tracking cases. The SOAP header is passed to extract
    # a shell_id from, the key is what is used to index the tracking dict (usually message_id), tracking_dist is the
    # actual tracking variable (such as self.receive_msgs), and track_name is used only for more readable log messages
    # (e.g. for tracking Receive requests 'Receive' could be passed).
    def _track_shell_id(self, header, key, tracking_dict, track_name):
        # Pull out the shell_id and track against key in tracking_dict
        selectors = header.findall('w:SelectorSet/w:Selector', WSManPS.NAMESPACES)
        for selector in selectors:
            name = selector.get('Name')
            if name == 'ShellId':
                shell_id = selector.text
                if shell_id is not None and shell_id != '':
                    # Save this key to tracking_dict, recording the associated shell_id
                    if key in tracking_dict:
                        self.logger.warning('Replacing an existing {} tracking entry with key: {}, shell_id will now '
                                            'be {} (was {})'.format(track_name, key, shell_id, tracking_dict[key]))
                    tracking_dict[key] = shell_id

    def _track_receive(self, message_id, header):
        self._track_shell_id(header, message_id, self.receive_msgs, 'Receive')

    def _track_delete(self, message_id, header):
        self._track_shell_id(header, message_id, self.delete_msgs, 'Delete')

    def _track_command(self, message_id, header):
        self._track_shell_id(header, message_id, self.command_msgs, 'Command')

    def _track_command_by_id(self, command_id, shell_id):
        if shell_id is not None and shell_id != '':
            if shell_id in self.commands:
                self.logger.warning('Replacing an existing command_id tracking entry. The command_id {} will now be '
                                    'associated with shell_id {} (was {})'.format(command_id, shell_id,
                                                                                  self.commands[command_id]))
            self.commands[command_id] = shell_id

    def _track_create(self, message_id):
        if message_id not in self.create_msgs:
            self.create_msgs.append(message_id)

    def _decompress_stream_data(self, stream_blob):
        if self.libwim is None:
            raise Exception('Cannot decompress as libwim not initialized. Do you have the libwim-15.dll?')
        # Will contain the fully decompressed data
        fully_decompressed = bytearray()
        # Iterate through each compression block in the stream_blob
        while stream_blob != b'':
            # Decode the compression header
            uncompressed_size, compressed_size = struct.unpack('<HH', stream_blob[:4])
            # Correct for the out-by-one (a known problem in the original Microsoft protocol spec)
            uncompressed_size += 1
            compressed_size += 1
            # Strip the compression header from the buffer
            stream_blob = stream_blob[4:]
            # Grab the block data for this compression block
            compressed_block = stream_blob[:compressed_size]
            # See if the data was actually compressed or not
            if uncompressed_size != compressed_size:
                # Block is compressed, so decompress it
                uncompressed_data_type = ctypes.c_char * uncompressed_size
                uncompressed_data = uncompressed_data_type()
                ret = self.libwim.wimlib_decompress(compressed_block, compressed_size, uncompressed_data,
                                                    uncompressed_size, self.xpress_decompressor)
                if ret != 0:
                    self.logger.error('Wimlib xpress decompression failed with return value: {}. Data will be appended '
                                      'to the stream buffer anyway just in case we can proceed, but other errors may '
                                      'occur as a result.'.format(ret))
                final_block_data = uncompressed_data.raw
            else:
                # No compression actually took place for this block
                final_block_data = compressed_block
            # Append data and advance to next compression block
            fully_decompressed.extend(final_block_data)
            stream_blob = stream_blob[compressed_size:]
        return bytes(fully_decompressed)


class SoapDefragmenterException(Exception):
    pass


class SoapDefragmenter:
    """This defragments SOAP received from ETW, also providing thread synchronisation.
    (Note this is not the same as defragmentation of PSRP messages).
    We assume SOAP chunks will arrive in order, for a given ActivityID+PID+TID combination.
    """

    LOGGER_NAME = 'RemotePSpy.soap'

    def __init__(self, completed_soap_callback):
        self.logger = logging.getLogger(SoapDefragmenter.LOGGER_NAME)
        self.lock = threading.Lock()
        self.partial_messages = {}
        self.completed_soap_callback = completed_soap_callback

    # Accepts a new Microsoft-Windows-WinRM SOAP event and handles defragmentation. Once a full SOAP message is
    # available, it will be passed on to self.completed_soap_callback().
    def new_event(self, event_tuple):
        event_id, event = event_tuple
        mkey = None
        with self.lock:
            try:
                if 'ActivityId' not in event['EventHeader']:
                    activity_id = -1  # Fall back ActivityId in an attempt to handle cases where there isn't one
                else:
                    activity_id = event['EventHeader']['ActivityId']
                pid = event['EventHeader']['ProcessId']
                tid = event['EventHeader']['ThreadId']
                # Make a key for partial_messages combining activity_id, pid and tid
                mkey = '{}_{}_{}'.format(activity_id, pid, tid)
                # Add a new partial_messages record if not seen before
                if mkey not in self.partial_messages:
                    self.partial_messages[mkey] = {'total_chunks': int(event['totalChunks']), 'last_chunk': 0,
                                                   'pid': pid, 'tid': tid, 'soap': ''}
                # Check the chunk index is what we expect
                chunk_index = int(event['index'])
                if chunk_index != self.partial_messages[mkey]['last_chunk'] + 1:
                    raise SoapDefragmenterException('out of order chunk, got index {}, expected {}'
                                                    ''.format(chunk_index,
                                                              self.partial_messages[mkey]['last_chunk'] + 1))
                else:
                    self.logger.debug('Processing WS-Man SOAP chunk from ETW: ActivityId: {}, PID: {}, TID: {}, '
                                      'chunk: {} of {}'.format(activity_id, pid, tid, chunk_index,
                                                               self.partial_messages[mkey]['total_chunks']))
                    self.partial_messages[mkey]['last_chunk'] += 1
                    # String concatenation is expensive in Python, but usually only ~1-6 chunks, so not too many
                    self.partial_messages[mkey]['soap'] += event['SoapDocument']
                    # Check if we have the last chunk
                    if chunk_index == self.partial_messages[mkey]['total_chunks']:
                        self.logger.info('WS-Man SOAP (Activity ID: {}, PID: {}, TID: {}): '
                                         '{}'.format(activity_id, pid, tid, self.partial_messages[mkey]['soap']))
                        self.completed_soap_callback(activity_id, pid, tid, self.partial_messages[mkey]['soap'])
                        self.partial_messages.pop(mkey)
            except Exception:
                tb = traceback.format_exc()
                self.logger.error('SoapDefragmener error: soap message will be abandoned. self.partial_messages: {} | '
                                  'event: {} | Exception info: {}'
                                  ''.format(self.partial_messages, event, tb))
                # Drop any data for this SOAP message
                if mkey and mkey in self.partial_messages:
                    self.partial_messages.pop(mkey)
