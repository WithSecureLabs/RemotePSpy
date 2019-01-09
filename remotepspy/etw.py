import logging
import threading
import traceback

import etw


class PowerShellETWParser:
    """Parses PowerShell ETW events to identify Shell context and PSRP fragments. Also provides thread synchronisation.
    """

    LOGGER_NAME = 'RemotePSpy.PowerShellETWParser'

    def __init__(self, completed_callback):
        self.logger = logging.getLogger(PowerShellETWParser.LOGGER_NAME)
        self.lock = threading.Lock()
        self.completed_callback = completed_callback
        self.shells = []
        self.activity_shell_contexts = {}

    # Accepts a new Microsoft-Windows-PowerShell event and readies it for being passed to the PSRPDefragmenter via
    # completed_callback
    def new_event(self, event_tuple):
        event_id, event = event_tuple
        with self.lock:
            try:
                if (event['EventHeader']['EventDescriptor']['Keyword'] == 0x4000000000000008
                        and event['EventHeader']['EventDescriptor']['Level'] == 5):
                    # Skip events from keyword 0x4000000000000008 which are not level 5. The non-level 5 events do not
                    # contain PSRP fragments.
                    self._psrp_frag_event(event)
                elif event['EventHeader']['EventDescriptor']['Keyword'] == 0x4000000000000100:
                    self._shell_context_event(event)
            except Exception:
                tb = traceback.format_exc()
                self.logger.error('PowerShellETWParser error: event: {} | Exception info: {}'.format(event, tb))

    def _psrp_frag_event(self, event):
        # Get some useful header details
        activity_id = None
        if 'ActivityId' in event['EventHeader']:
            activity_id = event['EventHeader']['ActivityId']
        pid = event['EventHeader']['ProcessId']
        tid = event['EventHeader']['ThreadId']
        # Get relevant payload data
        object_id = event['ObjectId']
        fragment_id = int(event['FragmentId'])
        s_flag = event['sFlag']
        e_flag = event['eFlag']
        frag_len = event['FragmentLength']
        frag_data = event['FragmentPayload']  # Is in the form of a long hex string like '0x0102....'
        frag_data = bytes.fromhex(frag_data[2:])
        # Identify the Shell context of this PSRP fragment
        if activity_id not in self.activity_shell_contexts:
            self.logger.error('Unable to identify Shell context for PSRP fragment: {}'.format(event))
            return
        shell_id = self.activity_shell_contexts[activity_id]
        self.completed_callback(shell_id, object_id, fragment_id, s_flag, e_flag, frag_len, frag_data)

    # NOTE: it would be possible to also get Command IDs from here, as they get associated with request IDs, but we
    # probably don't need CommandID after all.
    def _shell_context_event(self, event):
        if 'ActivityId' not in event['EventHeader']:
            return  # Cannot add shell context if there is no ActivityID to go on
        activity_id = event['EventHeader']['ActivityId']
        # A new shell context has been created
        if 'Request %1. Creating a server remote session.' in event['Description']:
            # Context for a newly created shell
            shell_id = event['param1']
            username = event['param2']  # TODO add user context to the tracked shell
            self.logger.debug('Tracking new shell {} against ActivityID: {}'.format(shell_id, activity_id))
            if shell_id not in self.shells:
                self.shells.append(shell_id)
            self.activity_shell_contexts[activity_id] = shell_id
        # Identify shell context for an existing shell
        elif 'Shell Context %1. Request Id %2' in event['Description']:
            shell_id = event['param1']
            if shell_id not in self.shells:
                self.logger.debug('Tracking new shell {} for which we missed the shell creation event.'
                                  ''.format(shell_id))
                self.shells.append(shell_id)
            if activity_id not in self.activity_shell_contexts:
                self.logger.debug('Tracking shell {} against ActivityID: {}'.format(shell_id, activity_id))
                self.activity_shell_contexts[activity_id] = shell_id
        # A shell may have closed
        elif 'Reporting operation complete for request: %1' in event['Description']:
            request_id = event['param1']
            # error_code = event['param2']
            # error_message = event['param3']  # May be blank
            # stack_trace = event['param4']  # May be blank
            if request_id in self.shells:
                # This request ID is being tracked as a shell context. As it is not closed, remove all tracking.
                self.logger.debug('Shell {} closed, removing tracking data.'.format(request_id))
                self.shells = [v for v in self.shells if v != request_id]
                self.activity_shell_contexts = {k: v for k, v in self.activity_shell_contexts.items() if
                                                v != request_id}


class ETWRemotePSBase(etw.ETW):
    LOGGER_NAME = 'RemotePSpy.etw'

    def __init__(self, event_callback, providers, session_name='PSRP_monitor', include_pids=None):
        self.logger = logging.getLogger(ETWWinRM.LOGGER_NAME)
        self.real_event_callback = event_callback
        self.session_name = session_name
        if include_pids is None:
            self.include_pids = []
        else:
            self.include_pids = include_pids
        super().__init__(session_name=session_name, providers=providers, event_callback=self.event_callback_hook)

    # Adds logging to the callback
    def event_callback_hook(self, event_tuple):
        event_id, event = event_tuple
        include = False
        try:
            pid = event['EventHeader']['ProcessId']
            if pid not in self.include_pids:
                include = True
        except KeyError:
            include = False
        if include:
            self.logger.debug('New ETW event: {}'.format(event))
            self.real_event_callback(event_tuple)

    def start(self):
        self.logger.info('ETW capture starting session: {}'.format(self.session_name))
        super().start()

    def stop(self):
        self.logger.info('ETW capture stopping session: {}'.format(self.session_name))
        super().stop()


class ETWWinRM(ETWRemotePSBase):
    def __init__(self, event_callback, session_name='PSRP_monitor', include_pids=None):
        providers = [etw.ProviderInfo('Microsoft-Windows-WinRM',
                                      etw.GUID('{A7975C8F-AC13-49F1-87DA-5A984A4AB417}'), level=4,
                                      all_keywords=0x2000000000000005)]
        super().__init__(event_callback, providers, session_name=session_name, include_pids=include_pids)


class ETWPowerShell(ETWRemotePSBase):
    def __init__(self, event_callback, session_name='PSRP_monitor', include_pids=None):
        providers = [etw.ProviderInfo('Microsoft-Windows-PowerShell',
                                      etw.GUID('{A0C1853B-5C40-4B15-8766-3CF1C58F985A}'), level=5,
                                      any_keywords=0x4000000000000008 | 0x4000000000000100)]
        super().__init__(event_callback, providers, session_name=session_name, include_pids=include_pids)
