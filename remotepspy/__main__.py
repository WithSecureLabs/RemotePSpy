import sys
import logging

import psutil

from remotepspy.etw import PowerShellETWParser
from remotepspy.etw import ETWWinRM
from remotepspy.etw import ETWPowerShell

from remotepspy.winrm import WSManPS
from remotepspy.winrm import SoapDefragmenter

from remotepspy.psrp import PSRPDefragmenter
from remotepspy.psrp import PSRPParser

from remotepspy.simple_command_tracer import SimpleCommandTracer


def get_svchost_pids():
    svchost_procs = []
    for proc in psutil.process_iter():
        try:
            pinfo = proc.as_dict(attrs=['pid', 'name'])
        except psutil.NoSuchProcess:
            pass
        else:
            if pinfo['name'] == 'svchost.exe':
                svchost_procs.append(pinfo['pid'])
    return svchost_procs


def init_logging():
    # TODO configure logs from command line args or a config file
    rh = logging.getLogger()
    rh.setLevel(logging.CRITICAL)
    if len(rh.handlers) > 0:
        rh.handlers[0].setLevel(logging.CRITICAL)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler = logging.StreamHandler(stream=sys.stdout)
    f_handler = logging.FileHandler('RemotePSpy.log')
    f_handler.setFormatter(formatter)
    handler.setFormatter(formatter)
    soap_logger = logging.getLogger(SoapDefragmenter.LOGGER_NAME)
    soap_logger.setLevel(logging.WARNING)
    soap_logger.addHandler(handler)
    etw_logger = logging.getLogger(ETWWinRM.LOGGER_NAME)
    etw_logger.setLevel(logging.WARNING)
    etw_logger.addHandler(handler)
    wsmanps_logger = logging.getLogger(WSManPS.LOGGER_NAME)
    wsmanps_logger.setLevel(logging.ERROR)
    wsmanps_logger.addHandler(handler)
    psrpdefrag_logger = logging.getLogger(PSRPDefragmenter.LOGGER_NAME)
    psrpdefrag_logger.setLevel(logging.ERROR)
    psrpdefrag_logger.addHandler(handler)
    psrpparse_logger = logging.getLogger(PSRPParser.LOGGER_NAME)
    psrpparse_logger.setLevel(logging.WARNING)
    psrpparse_logger.addHandler(handler)
    psetwparse_logger = logging.getLogger(PowerShellETWParser.LOGGER_NAME)
    psetwparse_logger.setLevel(logging.WARNING)
    psetwparse_logger.addHandler(handler)
    simplecmd_logger = logging.getLogger(SimpleCommandTracer.LOGGER_NAME)
    simplecmd_logger.setLevel(logging.DEBUG)
    simplecmd_logger.addHandler(f_handler)


def run_winrm_etw():
    init_logging()
    svchost_pids = get_svchost_pids()

    # Setup tracing using WinRM ETW data
    psrp_disect = WSManPS()
    soap_defrag = SoapDefragmenter(psrp_disect.new_soap)
    etw_job = ETWWinRM(session_name='PSRP_monitor', event_callback=soap_defrag.new_event, include_pids=svchost_pids)

    try:
        etw_job.start()
        print('\nPress ENTER or CTRL+C to stop trace\n')
        input()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        if etw_job.running:
            etw_job.stop()


def run_powershell_etw():
    init_logging()
    svchost_pids = get_svchost_pids()

    # Setup tracing using PowerShell ETW data
    simple_cmd_logger = SimpleCommandTracer()
    psrp_parser = PSRPParser(simple_cmd_logger.message)
    psrp_defrag = PSRPDefragmenter(psrp_parser.new_psrp_message)
    psetwparse = PowerShellETWParser(psrp_defrag.new_fragment)
    etw_job = ETWPowerShell(session_name='PSRP_monitor', event_callback=psetwparse.new_event, include_pids=svchost_pids)

    try:
        etw_job.start()
        print('\nPress ENTER or CTRL+C to stop trace\n')
        input()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        if etw_job.running:
            etw_job.stop()


def main():
    # Default to WinRM provider
    run_winrm_etw()


if __name__ == '__main__':
    main()
