import logging
import xml.etree.ElementTree as ET
import base64

from remotepspy.psrp import PSRPParser


class SimpleCommandTracer:
    """A simple PowerShell tracer that attempts to print (and log, if enabled) commands and their output. Does not
    support every possible use case fully, but attempts to cover most common, interesting activity.
    """

    LOGGER_NAME = 'RemotePSpy.simple_cmd'

    def __init__(self):
        self.logger = logging.getLogger(SimpleCommandTracer.LOGGER_NAME)
        self.prompt_incoming = False

    def message(self, destination, message_type, rpid, pipeline_id, data):
        if message_type not in PSRPParser.MSG_TYPES:
            self.logger.error('Unrecognised MessageType: {}'.format(message_type))
            return
        if PSRPParser.MSG_TYPES[message_type] == 'CREATE_PIPELINE':
            self.msg_create_pipeline(data, rpid, pipeline_id, destination)
        elif PSRPParser.MSG_TYPES[message_type] == 'PIPELINE_HOST_CALL':
            self.msg_pipeline_host_call(data, rpid, pipeline_id, destination)
        elif PSRPParser.MSG_TYPES[message_type] == 'PIPELINE_OUTPUT':
            self.msg_pipeline_output(data, rpid, pipeline_id, destination)

    def msg_create_pipeline(self, data, rpid, pipeline_id, destination):
        if data == '':
            self.logger.warning('Empty message data in CREATE_PIPELINE message. Runspace: {}, Pipeline: {}, '
                                'Destination: {}'.format(rpid, pipeline_id, destination))
            return
        doc = ET.fromstring(data)
        # Find Cmds list
        lst = doc.find("MS/Obj[@N='PowerShell']/MS/Obj[@N='Cmds']/LST")
        if lst is None:
            return
        cmds = list(lst)
        # Iterate over each command
        parsed_cmds = []
        for cmd_obj in cmds:
            # Everything is under an <MS> in the <Obj>
            ms = cmd_obj.find('MS')
            if ms is None:
                continue
            # Find and decode the command
            cmd = ms.find("S[@N='Cmd']")
            if cmd is None:
                continue
            cmd = cmd.text
            if cmd is None:
                continue
            # TODO also add handling for any other special commands here, maybe like Out-Default
            # If the command is 'prompt', it simply indicates an incoming prompt string value on the pipeline
            if cmd == 'prompt':
                self.prompt_incoming = True
                return
            cmd = PSRPParser.deserialize_string(cmd)
            final_cmd_str = [cmd]  # Will be joined together with space separator
            # Find any args
            # NOTE: this does not currently support all complex type arguments, only strings and arrays of strings
            args = ms.find("Obj[@N='Args']")
            args_lst = args.find('LST')
            if args_lst is not None:
                self.get_cmd_args(args_lst, final_cmd_str)
            # Join an individual command and its arguments together
            parsed_cmds.append(' '.join(final_cmd_str))
        # Join commands together
        full_cmd_str = ' | '.join(parsed_cmds)
        # Output the final result
        print(full_cmd_str)
        self.logger.info('Runspace: {}, Pipeline: {}, Destination: {}, Command: {}'.format(rpid, pipeline_id,
                                                                                          destination, full_cmd_str))

    def msg_pipeline_host_call(self, data, rpid, pipeline_id, destination):
        if data == '':
            self.logger.warning('Empty message data in PIPELINE_HOST_CALL message. Runspace: {}, Pipeline: {}, '
                                'Destination: {}'.format(rpid, pipeline_id, destination))
            return
        doc = ET.fromstring(data)
        method = doc.find("MS/Obj[@N='mi']/ToString")
        if method is None:
            self.logger.error('Could not find method identifier in PIPELINE_HOST_CALL. Runspace: {}, Pipeline: {}, '
                              'Destination: {}, Data: {}'.format(rpid, pipeline_id, destination, data))
            return
        method = method.text
        # TODO we can support more functions later, the full list is at [MS-PSRP] 2.2.3.17
        # (https://msdn.microsoft.com/en-us/library/dd306624.aspx)
        if method == 'WriteLine2':
            self._pipeline_method_WriteLine2(doc, rpid, pipeline_id, destination)
        elif method == 'Write2':
            self._pipeline_method_Write2(doc, rpid, pipeline_id, destination)
        elif method == 'WriteLine3':
            self._pipeline_method_WriteLine3(doc, rpid, pipeline_id, destination)
        elif method == 'SetShouldExit':
            pass  # Nothing really needed to be done
        else:
            print('[Unsupported PIPELINE_HOST_CALL method: {}]'.format(method))
            self.logger.warning('Unsupported PIPELINE_HOST_CALL method: {}. Runspace: {}, Pipeline: {}, Destination:{}'
                                ''.format(method, rpid, pipeline_id, destination))

    def msg_pipeline_output(self, data, rpid, pipeline_id, destination):
        if data == '':
            self.logger.info('Empty message data in PIPELINE_OUTPUT message. Runspace: {}, Pipeline: {}, '
                             'Destination: {}'.format(rpid, pipeline_id, destination))
            return
        doc = ET.fromstring(data)
        # If we're expecting an incoming prompt value to display, do so now
        if self.prompt_incoming:
            if doc.tag != 'S':
                self.logger.warning('Unsupported type received for prompt: {}'.format(data))
                print('[UNSUPPORTED TYPE RECEIVED FOR PROMPT]:\n{}'.format(data))
                return
            prompt = doc.text
            if prompt is None:
                return
            prompt = PSRPParser.deserialize_string(prompt, htmldecode=True)
            print(prompt, end='', flush=True)
            self.logger.info('Runspace: {}, Pipeline: {}, Destination: {}, Prompt: {}'.format(rpid, pipeline_id,
                                                                                             destination, prompt))
            self.prompt_incoming = False
        else:
            # NOTE: most complex types are not yet supported and will be output as raw CLIXML.
            tn = doc.find('TN')
            if tn is not None:
                tns = list(tn)
                if len(tns) > 0:
                    if tns[0].text == 'Selected.Microsoft.PowerShell.Commands.GenericMeasureInfo':
                        pass  # Not believed to be relevant for a simple command trace
                    elif tns[0].text == 'Selected.System.Management.Automation.CmdletInfo':
                        pass  # Not believed to be relevant for a simple command trace
                    elif tns[0].text == 'Selected.System.Management.ManagementObject':
                        self.output_management_object(doc, rpid, pipeline_id, destination)
                    else:
                        self.logger.warning('Unsupported type in PIPELINE_OUTPUT: {}'.format(data))
                        print('[UNSUPPORTED TYPE RECEIVED]:\n{}'.format(data))
            else:
                # Output any basic types we support. Primitive types are defined in [MS-PSRP] 2.2.5.1.
                output = SimpleCommandTracer.deseiralize_element(doc)
                if output is not None:
                    print(output)
                    self.logger.info('Runspace: {}, Pipeline: {}, Destination: {}, <{}> output: {}'
                                     ''.format(rpid, pipeline_id, destination, doc.tag, output))

    # Note: Only basic types supported, and not yet fully.
    @staticmethod
    def deseiralize_element(elem):
        output = None
        if elem.tag == 'Nil':
            output = None  # Just ignore
        elif elem.tag == 'S' or elem.tag == 'SBK' or elem.tag == 'Version' or elem.tag == 'URI':
            if elem.text is None:
                output = ''
            else:
                output = PSRPParser.deserialize_string(elem.text)
        elif elem.tag == 'XD':
            if elem.text is None:
                output = ''
            else:
                output = PSRPParser.deserialize_string(elem.text, htmldecode=True)
        elif elem.tag == 'GUID':
            # Wrap output in curly brackets
            output = '{{{}}}'.format(elem.text)
        elif elem.tag == 'SecureString':
            output = '[SecureString]{}'.format(elem.text)
        elif (elem.tag == 'D' or elem.tag == 'Dd' or elem.tag == 'Sg' or elem.tag == 'I64'
              or elem.tag == 'U64' or elem.tag == 'I32' or elem.tag == 'U32' or elem.tag == 'I16'
              or elem.tag == 'U16' or elem.tag == 'DT' or elem.tag == 'B'):
            if elem.text is None:
                output = ''
            else:
                output = elem.text
        elif elem.tag == 'C':
            output = '[char_code]{}'.format(elem.text)
        elif elem.tag == 'BA':
            if elem.text is None:
                output = "b''"
            else:
                byte_array = base64.b64decode(elem.text)
                output = '{}'.format(byte_array)
        elif elem.tag == 'SB':
            output = '[signed_byte]{}'.format(elem.text)
        elif elem.tag == 'By':
            output = '[unsigned_byte]{}'.format(elem.text)
        else:
            # Types not yet supported fall into here
            output = '[unsupported-{}-type]{}'.format(elem.tag, ET.tostring(elem).decode('utf-8'))
        return output

    def _pipeline_method_WriteLine2(self, doc, rpid, pipeline_id, destination):
        output_lst = doc.find("MS/Obj[@N='mp']/LST")
        if output_lst is None:
            self.logger.debug('Runspace: {}, Pipeline: {}, Destination: {}, WriteLine2() called with no arguments'
                              ''.format(rpid, pipeline_id, destination))
            return
        for elem in list(output_lst):
            output = SimpleCommandTracer.deseiralize_element(elem)
            if output is not None:
                print(output)
                self.logger.info('Runspace: {}, Pipeline: {}, Destination: {}, WriteLine2({})'
                                 ''.format(rpid, pipeline_id, destination, output.encode('utf-8')))

    def _pipeline_method_Write2(self, doc, rpid, pipeline_id, destination):
        self._pipeline_write_with_colours(doc, rpid, pipeline_id, destination, False, 'Write2')

    def _pipeline_method_WriteLine3(self, doc, rpid, pipeline_id, destination):
        self._pipeline_write_with_colours(doc, rpid, pipeline_id, destination, True, 'WriteLine3')

    # Supports the workings of Write2 and WriteLine3, which operate the same except for whether a newline is output.
    def _pipeline_write_with_colours(self, doc, rpid, pipeline_id, destination, newline_flag, method_name):
        method_args = doc.find("MS/Obj[@N='mp']/LST")
        if method_args is None:
            self.logger.debug('Runspace: {}, Pipeline: {}, Destination: {}, {}() called with no arguments'
                              ''.format(rpid, pipeline_id, destination, method_name))
            return
        method_args = list(method_args)
        if len(method_args) < 3:
            self.logger.error('Runspace: {}, Pipeline: {}, Destination: {}, {}() called with unexpected number of '
                              'arguments. Expected 3, got {}.'.format(rpid, pipeline_id, destination, method_name,
                                                                      len(method_args)))
            return
        # The first 2 args are background and foreground colour, which we do not support here
        elem = method_args[2]
        output = SimpleCommandTracer.deseiralize_element(elem)
        if output is not None:
            if newline_flag:
                print(output)
            else:
                print(output, end='', flush=True)
            self.logger.info('Runspace: {}, Pipeline: {}, Destination: {}, {}({})'
                             ''.format(rpid, pipeline_id, destination, method_name, output.encode('utf-8')))

    def get_cmd_args(self, args_lst, final_cmd_str):
        arg_objs = list(args_lst)
        for arg_obj in arg_objs:
            arg_obj_ms = arg_obj.find('MS')
            if arg_obj_ms is None:
                continue
            for elem in arg_obj_ms:
                if elem.tag == 'Nil':
                    pass  # Can just ignore
                elif elem.tag == 'S':
                    # This is just a simple string arg
                    arg_str = elem.text
                    if arg_str is not None:
                        arg_str = PSRPParser.deserialize_string(arg_str)
                        if ' ' in arg_str.strip():
                            final_cmd_str.append('"' + arg_str + '"')
                        else:
                            final_cmd_str.append(arg_str)
                elif elem.tag == 'Obj':
                    # We may have an array of strings as the argument value
                    inner_lst = elem.find('LST')
                    if inner_lst is not None:
                        values = []
                        for item in list(inner_lst):
                            if item.tag == 'S':
                                item_val = item.text
                                if item_val is not None:
                                    values.append(PSRPParser.deserialize_string(item_val))
                        if len(values) > 0:
                            # Join the argument array values together separated by comma
                            final_values = ','.join(values)
                            if ' ' in final_values.strip():
                                final_cmd_str.append('"' + final_values + '"')
                            final_cmd_str.append(final_values)
                else:
                    self.logger.warning('Unsupported type in args list of a cmd in CREATE_PIPELINE message: {}'
                                        ''.format(ET.tostring(elem).decode('utf-8')))
                    print('[UNSUPPORTED ARG TYPE RECEIVED]: {}'.format(ET.tostring(elem).decode('utf-8')))

    def output_management_object(self, serialized_element, rpid, pipeline_id, destination):
        # Output a set of Strings as property_name:value pairs
        ms = serialized_element.find('MS')
        if ms is None:
            return
        for item in list(ms):
            if item.tag != 'S':
                self.logger.warning('Unsupported type in PIPELINE_OUTPUT, in the <MS> element of a '
                                    'Selected.System.Management.ManagementObject: {}'
                                    ''.format(ET.tostring(item).decode('utf-8')))
                print('[UNSUPPORTED TYPE RECEIVED]: {}'.format(ET.tostring(item).decode('utf-8')))
                continue
            value = item.text
            prop_name = SimpleCommandTracer.get_property_name(item)
            if prop_name is not None:
                print('{}: {}'.format(prop_name, value))
                self.logger.info("Runspace: {}, Pipeline: {}, Destination: {}, Output: '{}:{}'"
                                 "".format(rpid, pipeline_id, destination, prop_name, value))
            else:
                print(value)
                self.logger.info(
                    'Runspace: {}, Pipeline: {}, Destination: {}, Output: {}'.format(rpid, pipeline_id, destination,
                                                                                     value))

    # Return any property name from the 'N' attribute of an Element.
    @staticmethod
    def get_property_name(elem):
        if 'N' not in elem.keys():
            return None
        prop_name = elem.get('N')
        return PSRPParser.deserialize_string(prop_name)
