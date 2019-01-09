import logging
import struct
from uuid import UUID
import html
import re


class PSRPParser:
    LOGGER_NAME = 'RemotePSpy.psrpparse'

    MSG_TYPES = {
        0x00010002: 'SESSION_CAPABILITY',
        0x00010004: 'INIT_RUNSPACEPOOL',
        0x00010005: 'PUBLIC_KEY',
        0x00010006: 'ENCRYPTED_SESSION_KEY',
        0x00010007: 'PUBLIC_KEY_REQUEST',
        0x00021002: 'SET_MAX_RUNSPACES',
        0x00021003: 'SET_MIN_RUNSPACES',
        0x00021004: 'RUNSPACE_AVAILABILITY',
        0x00021005: 'RUNSPACEPOOL_STATE',
        0x00021006: 'CREATE_PIPELINE',
        0x00021007: 'GET_AVAILABLE_RUNSPACES',
        0x00021008: 'USER_EVENT',
        0x00021009: 'APPLICATION_PRIVATE_DATA',
        0x0002100A: 'GET_COMMAND_METADATA',
        0x00021100: 'RUNSPACEPOOL_HOST_CALL',
        0x00021101: 'RUNSPACEPOOL_HOST_RESPONSE',
        0x00041002: 'PIPELINE_INPUT',
        0x00041003: 'END_OF_PIPELINE_INPUT',
        0x00041004: 'PIPELINE_OUTPUT',
        0x00041005: 'ERROR_RECORD',
        0x00041006: 'PIPELINE_STATE',
        0x00041007: 'DEBUG_RECORD',
        0x00041008: 'VERBOSE_RECORD',
        0x00041009: 'WARNING_RECORD',
        0x00041010: 'PROGRESS_RECORD',
        0x00041011: 'INFORMATION_RECORD',
        0x00041100: 'PIPELINE_HOST_CALL',
        0x00041101: 'PIPELINE_HOST_RESPONSE',
        0x00010008: 'CONNECT_RUNSPACEPOOL',
        0x0002100B: 'RUNSPACEPOOL_INIT_DATA',
        0x0002100C: 'RESET_RUNSPACE_STATE'
    }

    def __init__(self, callback):
        self.logger = logging.getLogger(PSRPParser.LOGGER_NAME)
        self.callback = callback

    def new_psrp_message(self, shell_id, object_id, message, command_id):
        # Decode message
        destination, message_type = struct.unpack('<II', message[:8])
        rpid = UUID(bytes_le=bytes(message[8:24]))
        # While the spec defines pipeline_id as "PID", we call it pipeline_id to avoid confusion with Process ID
        pipeline_id = UUID(bytes_le=bytes(message[24:40]))
        data = message[40:].decode('utf-8-sig')
        # Log full message to debug log
        self.logger.debug('New PSRP message for ShellID: {}, ObjectID: {}, Destination: {}, MessageType: {}, '
                          'RPID: {}, PipelineID: {}, Data: {}'
                          ''.format(shell_id, object_id, destination, PSRPParser._msg_type_name(message_type), rpid,
                                    pipeline_id, data))
        self.callback(destination, message_type, rpid, pipeline_id, data)

    # If 'unknown' is not specified, throws KeyError on unknown type; otherwise, returns the value of 'unknown' (which
    # cannot itself be None).
    @staticmethod
    def _msg_type_name(msg_type, unknown=None):
        try:
            return PSRPParser.MSG_TYPES[msg_type]
        except KeyError:
            if unknown is None:
                raise
            else:
                return unknown

    @staticmethod
    def deserialize_string(serialized, htmldecode=False):
        """Utility method to decode Clixml Strings that contain characters encoded according to [MS-PSRP] 2.2.5.3.
        These are characters that look like _xHHHH_ where H is a hex digit of a UTF-16 character code
        (e.g. _x000A_ for a newline).
        If htmldecode is True, also decode HTML characters (e.g. '&gt;' becomes '>').
        """
        def re_replacer(match):
            match = match.group(1)
            return bytes.fromhex(match).decode('utf-16be')
        deserialized = re.sub(r'_x([0-9A-Fa-f]{4})_', re_replacer, serialized)
        if htmldecode:
            deserialized = html.unescape(deserialized)
        return deserialized


class PSRPDefragmenter:
    LOGGER_NAME = 'RemotePSpy.psrpfrag'
    FRAG_HEADER_LEN = 21
    END_MASK = 2
    START_MASK = 1

    def __init__(self, completed_psrp_callback):
        self.logger = logging.getLogger(PSRPDefragmenter.LOGGER_NAME)
        self.completed_psrp_callback = completed_psrp_callback
        # Stores object buffers per Shell, by Shell ID.
        # The object buffers will use a fragment's ObjectID to track an individual PSRP message's fragments.
        # E.g.: {shell_id: {obj_id: {'last_fragment_id': id, 'buffer': appended_fragment_bytes,
        #                            'command_id': optional_command_id}}}
        self.shell_bufs = {}
        # As above, but for pending shells, using message_id instead of shell_id
        self.pending_shell_bufs = {}
        # Stashes completed messages for pending shells until the shell_id is obtained so they can be passed on
        self.pending_shell_completed_messages = {}

    # Process a new PSRP fragment which has already had its header parsed into individual variables.
    def new_fragment(self, shell_id, object_id, fragment_id, s_flag, e_flag, frag_len, frag_data):
        self._append_frag_data(object_id, fragment_id, s_flag, e_flag, frag_data, shell_id, self.has_shell,
                               self.new_shell, self.shell_bufs, self.completed_psrp_callback)

    # Process new PSRP fragment data (a 'bytes') for a known shell. There may be more than one fragment.
    # (pending shells should use new_fragment_data_pending_shell() and use message_id instead of shell_id)
    def new_fragment_data(self, shell_id, fragment_data, command_id=None):
        self._new_fragment_data(shell_id, self.has_shell, self.new_shell, self.shell_bufs, self.completed_psrp_callback,
                                fragment_data, command_id=command_id)

    # Process new PSRP fragment data (a 'bytes') for a pending shell (for which we do not yet have the shell_id).
    # There may be more than one fragment.
    # (fully initialised shells with a known shell_id should instead use new_fragment_data())
    def new_fragment_data_pending_shell(self, message_id, fragment_data, command_id=None):
        self._new_fragment_data(message_id, self.has_pending_shell, self.new_pending_shell, self.pending_shell_bufs,
                                self.pending_shell_message_callback, fragment_data, command_id=command_id)

    def _new_fragment_data(self, identifier, has_identifier_func, new_ident_func, bufs, message_complete_callback,
                           fragment_data, command_id=None):
        # Loop through all the fragments in the data provided
        frag_offset = 0
        while frag_offset < len(fragment_data):
            # Decode fragment header
            frag_header_end = frag_offset + PSRPDefragmenter.FRAG_HEADER_LEN
            object_id, fragment_id, e_s, frag_len = struct.unpack('>qqbI', fragment_data[frag_offset:frag_header_end])
            # Grab the fragment payload (partial PSRP data)
            data_start = frag_offset + PSRPDefragmenter.FRAG_HEADER_LEN
            data_end = frag_offset + PSRPDefragmenter.FRAG_HEADER_LEN + frag_len
            frag_data = fragment_data[data_start:data_end]
            s_flag = PSRPDefragmenter._start_bit_set(e_s)
            e_flag = PSRPDefragmenter._end_bit_set(e_s)
            # Store the fragment to the appropriate buffer
            self._append_frag_data(object_id, fragment_id, s_flag, e_flag, frag_data, identifier, has_identifier_func,
                                   new_ident_func, bufs, message_complete_callback, command_id=command_id)
            # Advance to next fragment
            frag_offset += PSRPDefragmenter.FRAG_HEADER_LEN + frag_len

    def _append_frag_data(self, object_id, fragment_id, s_flag, e_flag, frag_data, identifier, has_identifier_func,
                          new_ident_func, bufs, message_complete_callback, command_id=None):
        # Check we are tracking the shell_id
        if not has_identifier_func(identifier):
            self.logger.info('Adding tracking for a Shell {} we were not tracking before, but have received '
                             'fragment data for.')
            new_ident_func(identifier)
        # Check we have a buffer for the object_id
        if object_id not in bufs[identifier]:
            bufs[identifier][object_id] = {'last_fragment_id': -1, 'buffer': bytearray()}
        bufs[identifier][object_id]['command_id'] = command_id
        # Check the fragment is the one we were expecting next
        expected_frag_id = bufs[identifier][object_id]['last_fragment_id'] + 1
        if expected_frag_id != fragment_id:
            self.logger.error('Unexpected or out-of-order fragment for Shell ID: {}, Object ID: {}. Expected '
                              'Fragment ID {}, got {}.'.format(identifier, object_id, expected_frag_id, fragment_id))
            return
        self.logger.debug('New fragment for ShellID: {}, ObjectID {}: {}'.format(identifier, object_id, frag_data))
        # Append to appropriate buffer
        bufs[identifier][object_id]['buffer'].extend(frag_data)
        # Check E (end fragment) bit in e_s to see if this is the last fragment. If so, pass on completed PSRP
        # message to the callback.
        if e_flag:
            self.logger.info('End fragment found for ShellID: {}, ObjectID: {}'.format(identifier, object_id))
            message_complete_callback(identifier, object_id, bufs[identifier][object_id]['buffer'],
                                      bufs[identifier][object_id]['command_id'])
            # Remove ref to completed buffer
            bufs[identifier].pop(object_id)

    # Instead of using the standard message callback, pending shells use this internal one which just stash the
    # completed message until a shell_id is received for the shell, at which point the messages are propogated on via
    # the normal callback to the next layer.
    def pending_shell_message_callback(self, message_id, object_id, message, command_id):
        if message_id not in self.pending_shell_completed_messages:
            self.pending_shell_completed_messages[message_id] = []
        self.pending_shell_completed_messages[message_id].append((object_id, message, command_id))

    def has_shell(self, shell_id):
        return shell_id in self.shell_bufs

    def has_pending_shell(self, shell_id):
        return shell_id in self.pending_shell_bufs

    # Track a new shell_id immediately. This should only be used if a new shell_id is encountered part way through use.
    # For new shells created with a Create/CreateResponse pair, new_pending_shell() and subsequently
    # set_pending_shell_id() should be used to allow messages to be defragmented and propogated to the shell from the
    # Create (before we have the shell_id).
    def new_shell(self, shell_id):
        if shell_id is None:
            self.logger.error('new_shell() called with a shell_id of None')
            return
        if shell_id in self.shell_bufs:
            self.logger.warning('Request to create a new Shell ID {}, but this ID already existed.'.format(shell_id))
        else:
            self.shell_bufs[shell_id] = {}

    def new_pending_shell(self, message_id):
        if message_id is None:
            self.logger.error('new_pending_shell() called with a message_id of None')
            return
        if message_id in self.pending_shell_bufs:
            self.logger.warning('Request to create a new pending shell with MessageID {}, but this ID already existed.'
                                ''.format(message_id))
        else:
            self.pending_shell_bufs[message_id] = {}

    def set_pending_shell_id(self, message_id, shell_id):
        if message_id not in self.pending_shell_bufs:
            # Pending shell not found, track the shell_id anyway now we know it's PowerShell related.
            self.new_shell(shell_id)
            self.logger.warning('Attempt to set a shell_id for a pending shell tracked by message_id {}, but no such '
                                'pending shell was found. The shell_id has been added to tracking, but any messages '
                                'that were associated with the pending shell will be lost.'.format(message_id))
            return
        # Move message buffers over
        bufs = self.pending_shell_bufs.pop(message_id)
        if shell_id in self.shell_bufs:
            pass  ### TODO if already there, merge the message buffers together and log warning?
        else:
            self.shell_bufs[shell_id] = bufs
        # Send on any completed messages
        if message_id in self.pending_shell_completed_messages:
            for object_id, message, command_id in self.pending_shell_completed_messages[message_id]:
                self.completed_psrp_callback(shell_id, object_id, message, command_id)
        # Remove messages from stash
        self.pending_shell_completed_messages.pop(message_id)

    # A WS-Man Shell instance has been deleted, so discard any buffers relating to it we may still have
    def delete_shell(self, shell_id):
        if shell_id in self.shell_bufs:
            self.logger.debug('Discarding buffers for deleted Shell ID {}'.format(shell_id))
            self.shell_bufs.pop(shell_id)

    @staticmethod
    def _end_bit_set(e_s):
        return e_s & PSRPDefragmenter.END_MASK > 0

    @staticmethod
    def _start_bit_set(e_s):
        return e_s & PSRPDefragmenter.START_MASK > 0
