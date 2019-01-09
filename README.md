# RemotePSpy

RemotePSpy provides live monitoring of remote PowerShell sessions, which is particularly useful for older (pre-5.0)
versions of PowerShell which do not have comprehensive logging facilities built in.

It uses Event Tracing for Windows (ETW) to obtain message data from the WinRM protocol that is used as a transport for
remote PowerShell, and decodes the various protocol layers to provide a trace of the script commands executed and their
input/output.

This is currently an early research prototype and so does not support every aspect of the PowerShell Remote Protocol
(PSRP). It can still provide useful insights as to what is happening in a remote PowerShell session.

## Installation

The easiest way to install is using pip:

```
pip install remotepspy
```

### Dependencies

Dependencies should be installed automatically when installing via pip, but in case you wish to install from source they
are listed here:

* Python 3.7
* pywintrace (https://github.com/fireeye/pywintrace or https://pypi.org/project/pywintrace/)
* psutils (https://pypi.org/project/pywintrace/)
* libwim-15.dll from https://wimlib.net/ (bundled in the RemotePSpy package for convenience)

The libwim-15.dll is only required if using the (recommended, and default) Microsoft-Windows-WinRM ETW provider as a
data source. It is used to decompress certain stream objects in the WinRM/WSMan protocol which contain PSRP message
fragments. Just put it in the same directory as the main Python script.

## Usage

Simply execute `RemotePSpy` to start monitoring and logging, and press Return when you are finished. The log will be
written to the current working directory, named `RemotePSpy.log`.

The tool will also print an approximate replica of what the user of remote PowerShell would see on their screen to
stdout alongside the more verbose information in the log file. More complex logging is available, see "Logging" below.

If you installed Python to be in your PATH, the RemotePSpy executable scripts will also be in your PATH. Otherwise you
may need to look for then in your Python site-packages directory.

### PowerShell ETW Provider Version

The default `RemotePSpy` uses the (recommended) WinRM ETW provider as a data source. If you wish to use the PowerShell
ETW provider instead, you can execute `RemotePSpy_powershell_prov`.

This version may produce some unecessary warnings due to the added complexity of tracking certain state based on how the
data is provided in this particular ETW provider.

## Internals

The code consists of a number of fairly modular classes which can accept input at different layers in the protocol
stack. This allows them to be plugged together in slightly different ways depending on where the data is obtained from
and in what form. Most classes accept a callback function which they use to pass on the result they produce to the next
layer in the stack.

A description of the main classes used is given below, followed by some processing flows which show which class feeds
into which in different scenarios.

* ETWWinRM – Obtains ETW events from the WinRM provider.

* ETWPowerShell – Obtains ETW events from the PowerShell provider.

* PowerShellETWParser – Identifies Shell context for PowerShell ETW events, passing on the fragment data to
PSRPDefragmenter. Also provides thread synchronization.

* SoapDefragmenter – Re-assembles full WSMan SOAP messages from WinRM ETW events, passing the complete SOAP on to
WSManPS.

* WSManPS – Filters out non-PowerShell related WinRM, tracks Shell context, parses out PSRP fragment data from the WSMan
SOAP, and passes on the fragment data to PSRPDefragmenter.

* PSRPDefragmenter – Re-assembles PSRP fragments into full PRSP messages. Fragments are assembled by ObjectID, and
uniqueness of ObjectID is ensured by taking Shell context into account. Passes final PSRP messages on to PSRPParser.

* PSRPParser – Decodes the raw binary PSRP message, extracting header details like RPID, Pipeline ID, and MessageType.
Passes decoded messages on to SimpleCommandTracer.

* SimpleCommandTracer – Interprets PSRP messages using MessageType, and extracts and prints/logs commands, arguments,
and their output. Includes partial decoding of serialized PowerShell objects. Not a complete implementation of every
possible feature, but attempts to cover most common cases to allow for execution trace.

Processing flow when using Microsoft-Windows-WinRM ETW provider:

_ETWWinRM -> SoapDefragmenter -> WSManPS -> PSRPDefragmenter -> PSRPParser -> SimpleCommandTracer_

Processing flow when using Microsoft-Windows-PowerShell ETW provider:

_ETWPowerShell -> PowerShellETWParser -> PSRPDefragmenter -> PSRPParser -> SimpleCommandTracer_


## Logging

There is comprehensive logging at each layer in the protocol stack. This allows debugging at various levels, and was
especially helpful during development. Hopefully it can also be useful to anyone wanting to investigate remote
PowerShell in action, as it is possible to get a full trace of the protocol at all the key layers.

Currently, the source code at the end of the script where loggers are configured must be edited to change logging.
Future releases should hopefully provide a better method for such configuration.

Each logger name is defined by a constant, LOGGER_NAME, in the class that uses it. Every logger is defined as a child of
"RemotePSpy" (e.g. RemotePSpy.etw). Programmatically, loggers can be configured by using logging.getLogger() with the
appropriate log name.

For quick reference, the following loggers and levels will provide you with protocol traces at different layers in the
protocol:

| Key Log Data                     | Logger Name Constant            | Level |
| -------------------------------- | ------------------------------- | ----- |
| Command Trace                    | SimpleCommandTracer.LOGGER_NAME | INFO  |
| Full ETW event trace             | ETWWinRM.LOGGER_NAME            | DEBUG |
| Full WSMan SOAP message trace    | SoapDefragmenter.LOGGER_NAME    | INFO  |
| Full trace of each PSRP fragment | PSRPDefragmenter.LOGGER_NAME    | DEBUG |
| Full PSRP message trace          | PSRPParser.LOGGER_NAME          | DEBUG |

Note that SimpleCommandTracer outputs a trace on stdout as well, and this attempts to somewhat replicate the display as
the remote PowerShell user would see it. This is different to the command trace log which logs each command, pipeline
method call, and pipeline output in a more precise way, including additional context such as RPID and Pipeline ID.

A fuller summary of what appears in each log at which level is given below:

#### SimpleCommandTracer.LOGGER_NAME
**ERROR:** 
* Parsing errors

**WARNING:** 
* Unsupported type or pipeline method encountered

**INFO:** 
* The actual command trace

**DEBUG:**
* Pipeline method called with no arguments

#### PSRPParser.LOGGER_NAME
**DEBUG:** 
* Full PSRP message trace

#### PSRPDefragmenter.LOGGER_NAME
**ERROR:** 
* Out-of-order fragment received

**WARNING:** 
* Non-fatal Shell tracking anomalies

**INFO:** 
* End fragment found
* Tracking Shell ID found in fragment data that was not explicitly tracked before

**DEBUG:** 
* Full trace of each PSRP fragment

#### WSManPS.LOGGER_NAME
**ERROR:** 
* Serious parsing errors

**WARNING:** 
* Less serious parsing errors
* Overwriting of existing shell/command tracking contexts

**INFO:** 
* Shell and command tracking info

**DEBUG:** 
* Full trace of WSMan messages that are ignored due to not being related to PowerShell

#### SoapDefragmenter.LOGGER_NAME
**INFO:** 
* Full WSMan SOAP message trace

**DEBUG:** 
* SOAP chunk processed

#### PowerShellETWParser.LOGGER_NAME
**DEBUG:** 
* Shell tracking info

**ERROR:** 
* Shell context identification errors
* Catch-all exceptions from lower layers

#### ETWWinRM.LOGGER_NAME
**DEBUG:** 
* Full ETW event trace

**INFO:** 
* ETW session start/stop
