# -*- coding: utf-8 -*-
"""

"""
import csv
import datetime
import io
import json
import logging
import os
import re
import signal
import sys
import time
import traceback
import types

from intelmq import (DEFAULT_LOGGING_PATH, DEFAULTS_CONF_FILE,
                     HARMONIZATION_CONF_FILE, PIPELINE_CONF_FILE,
                     RUNTIME_CONF_FILE, __version__)
from intelmq.lib import exceptions, utils
import intelmq.lib.message as libmessage
from intelmq.lib.pipeline import PipelineFactory
from intelmq.lib.utils import RewindableFileHandle
from typing import Any, Optional, List

__all__ = ['Bot', 'CollectorBot', 'ParserBot']


class Bot(object):

    """ Not to be reset when initialized again on reload. """
    __current_message = None
    __message_counter = 0
    __message_counter_start = None
    # Bot is capable of SIGHUP delaying
    sighup_delay = True

    def __init__(self, bot_id: str):
        self.__log_buffer = []
        self.parameters = Parameters()

        self.__error_retries_counter = 0
        self.__source_pipeline = None
        self.__destination_pipeline = None
        self.logger = None

        try:
            version_info = sys.version.splitlines()[0].strip()
            self.__log_buffer.append(('info',
                                      '{bot} initialized with id {id} and intelmq {intelmq}'
                                      ' and python {python} as process {pid}.'
                                      ''.format(bot=self.__class__.__name__,
                                                id=bot_id, python=version_info,
                                                pid=os.getpid(), intelmq=__version__)))
            self.__log_buffer.append(('debug', 'Library path: %r.' % __file__))

            self.__load_defaults_configuration()

            self.__check_bot_id(bot_id)
            self.__bot_id = bot_id

            self.__init_logger()
        except Exception:
            self.__log_buffer.append(('critical', traceback.format_exc()))
            self.stop()
        else:
            for line in self.__log_buffer:
                getattr(self.logger, line[0])(line[1])

        try:
            self.logger.info('Bot is starting.')
            self.__load_runtime_configuration()
            self.__load_pipeline_configuration()
            self.__load_harmonization_configuration()

            self.init()

            self.__sighup = False
            signal.signal(signal.SIGHUP, self.__handle_sighup_signal)
            # system calls should not be interrupted, but restarted
            signal.siginterrupt(signal.SIGHUP, False)
            signal.signal(signal.SIGTERM, self.__handle_sigterm_signal)
        except Exception as exc:
            if self.parameters.error_log_exception:
                self.logger.exception('Bot initialization failed.')
            else:
                self.logger.error(utils.error_message_from_exc(exc))
                self.logger.error('Bot initialization failed.')

            self.stop()
            raise

    def __handle_sigterm_signal(self, signum: int, stack: Optional[object]):
        """
        Calles when a SIGTERM is received. Stops the bot.
        """
        self.logger.info("Received SIGTERM.")
        self.stop(exitcode=0)
        del self

    def __handle_sighup_signal(self, signum: int, stack: Optional[object]):
        """
        Called when signal is received and postpone.
        """
        self.__sighup = True
        self.logger.info('Received SIGHUP, initializing again later.')
        if not self.sighup_delay:
            self.__handle_sighup()

    def __handle_sighup(self):
        """
        Handle SIGHUP.
        """
        if not self.__sighup:
            return False
        self.logger.info('Handling SIGHUP, initializing again now.')
        self.__disconnect_pipelines()
        self.shutdown()  # disconnects, stops threads etc
        self.logger.handlers = []  # remove all existing handlers
        self.__init__(self.__bot_id)
        self.__connect_pipelines()

    def init(self):
        pass

    def shutdown(self):
        pass

    def start(self, starting: bool=True, error_on_pipeline: bool=True,
              error_on_message: bool=False, source_pipeline: Optional[str]=None,
              destination_pipeline: Optional[str]=None):

        self.__source_pipeline = source_pipeline
        self.__destination_pipeline = destination_pipeline

        while True:
            try:
                if not starting and (error_on_pipeline or error_on_message):
                    self.logger.info('Bot will continue in %s seconds.',
                                     self.parameters.error_retry_delay)
                    time.sleep(self.parameters.error_retry_delay)

                if error_on_message:
                    error_on_message = False

                if error_on_pipeline:
                    self.__connect_pipelines()
                    error_on_pipeline = False

                if starting:
                    starting = False

                self.__handle_sighup()
                self.process()
                self.__error_retries_counter = 0  # reset counter

                if self.parameters.rate_limit and self.run_mode != 'scheduled':
                    self.__sleep()

            except exceptions.PipelineError as exc:
                error_on_pipeline = True

                if self.parameters.error_log_exception:
                    self.logger.exception('Pipeline failed.')
                else:
                    self.logger.error(utils.error_message_from_exc(exc))
                    self.logger.error('Pipeline failed.')
                self.__disconnect_pipelines()

            except Exception as exc:
                # in case of serious system issues, exit immediately
                if isinstance(exc, MemoryError):
                    self.logger.exception('Out of memory. Exit immediately.')
                    self.stop()
                elif isinstance(exc, (IOError, OSError)) and exc.errno == 28:
                    self.logger.exception('Out of disk space. Exit immediately.')
                    self.stop()

                error_on_message = sys.exc_info()

                if self.parameters.error_log_exception:
                    self.logger.exception("Bot has found a problem.")
                else:
                    self.logger.error(utils.error_message_from_exc(exc))
                    self.logger.error("Bot has found a problem.")

                if self.parameters.error_log_message:
                    # Dump full message if explicitly requested by config
                    self.logger.info("Current Message(event): %r.",
                                     self.__current_message)

                # In case of permanent failures, stop now
                if isinstance(exc, exceptions.ConfigurationError):
                    self.stop()

            except KeyboardInterrupt:
                self.logger.info("Received KeyboardInterrupt.")
                self.stop(exitcode=0)
                del self
                break

            finally:
                if getattr(self.parameters, 'testing', False):
                    self.stop()
                    break

                if error_on_message or error_on_pipeline:
                    self.__error_retries_counter += 1

                    # reached the maximum number of retries
                    if (self.__error_retries_counter >
                            self.parameters.error_max_retries):

                        if error_on_message:

                            if self.parameters.error_dump_message:
                                error_traceback = traceback.format_exception(*error_on_message)
                                self._dump_message(error_traceback,
                                                   message=self.__current_message)
                                self.__current_message = None

                            # remove message from pipeline
                            self.acknowledge_message()

                            # when bot acknowledge the message,
                            # don't need to wait again
                            error_on_message = False

                        # run_mode: scheduled
                        if self.run_mode == 'scheduled':
                            self.logger.info('Shutting down scheduled bot.')
                            self.stop()

                        # error_procedure: stop
                        elif self.parameters.error_procedure == "stop":
                            self.stop()

                        # error_procedure: pass
                        else:
                            self.__error_retries_counter = 0  # reset counter

                # no errors, check for run mode: scheduled
                elif self.run_mode == 'scheduled':
                    self.logger.info('Shutting down scheduled bot.')
                    self.stop()

            self.__handle_sighup()

    def __sleep(self):
        """
        Sleep handles interrupts and changed rate_limit-parameter.

        time.sleep is stopped by signals such as SIGHUP. As rate_limit could
        have been changed, we initialize again and continue to sleep, if
        necessary at all.
        """
        starttime = time.time()
        remaining = self.parameters.rate_limit
        while remaining > 0:
            self.logger.info("Idling for {:.1f}s now.".format(remaining))
            time.sleep(remaining)
            self.__handle_sighup()
            remaining = self.parameters.rate_limit - (time.time() - starttime)

    def stop(self, exitcode: int=1):
        try:
            self.shutdown()
        except BaseException:
            pass

        if self.__message_counter:
            self.logger.info("Processed %d messages since last logging.", self.__message_counter)

        self.__disconnect_pipelines()

        if self.logger:
            self.logger.info("Bot stopped.")
            logging.shutdown()
        else:
            self.__log_buffer.append(('info', 'Bot stopped.'))
            self.__print_log_buffer()

        if not getattr(self.parameters, 'testing', False):
            del self
            exit(exitcode)

    def __print_log_buffer(self):
        for level, message in self.__log_buffer:
            if self.logger:
                getattr(self.logger, level)(message)
            if level in ['WARNING', 'ERROR', 'critical']:
                print(level.upper(), '-', message, file=sys.stderr)
            else:
                print(level.upper(), '-', message)
        self.__log_buffer = []

    def __check_bot_id(self, name: str):
        res = re.search('[^0-9a-zA-Z\-]+', name)
        if res:
            self.__log_buffer.append(('error',
                                      "Invalid bot id, must match '"
                                      "[^0-9a-zA-Z\-]+'."))
            self.stop()

    def __connect_pipelines(self):
        self.logger.debug("Loading source pipeline and queue %r.", self.__source_queues)
        self.__source_pipeline = PipelineFactory.create(self.parameters)
        self.__source_pipeline.set_queues(self.__source_queues, "source")
        self.__source_pipeline.connect()
        self.logger.debug("Connected to source queue.")

        if self.__destination_queues:
            self.logger.debug("Loading destination pipeline and queues %r.",
                              self.__destination_queues)
            self.__destination_pipeline = PipelineFactory.create(self.parameters)
            self.__destination_pipeline.set_queues(self.__destination_queues,
                                                   "destination")
            self.__destination_pipeline.connect()
            self.logger.debug("Connected to destination queues.")
        else:
            self.logger.debug("No destination queues to load.")

        self.logger.info("Pipeline ready.")

    def __disconnect_pipelines(self):
        """ Disconnecting pipelines. """
        if self.__source_pipeline:
            self.__source_pipeline.disconnect()
            self.__source_pipeline = None
            self.logger.debug("Disconnected from source pipeline.")
        if self.__destination_pipeline:
            self.__destination_pipeline.disconnect()
            self.__destination_pipeline = None
            self.logger.debug("Disconnected from destination pipeline.")

    def send_message(self, *messages):
        for message in messages:
            if not message:
                self.logger.warning("Ignoring empty message at sending. Possible bug in bot.")
                continue
            if not self.__destination_pipeline:
                raise exceptions.ConfigurationError('pipeline', 'No destination pipeline given, '
                                                    'but needed')
                self.stop()

            self.logger.debug("Sending message.")
            self.__message_counter += 1
            if not self.__message_counter_start:
                self.__message_counter_start = datetime.datetime.now()
            if self.__message_counter % self.parameters.log_processed_messages_count == 0 or \
               datetime.datetime.now() - self.__message_counter_start > self.parameters.log_processed_messages_seconds:
                self.logger.info("Processed %d messages since last logging.", self.__message_counter)
                self.__message_counter = 0
                self.__message_counter_start = datetime.datetime.now()

            raw_message = libmessage.MessageFactory.serialize(message)
            self.__destination_pipeline.send(raw_message)

    def receive_message(self):
        self.logger.debug('Waiting for incoming message.')
        message = None
        while not message:
            message = self.__source_pipeline.receive()
            if not message:
                self.logger.warning('Empty message received. Some previous bot sent invalid data.')
                continue

        # handle a sighup which happened during blocking read
        self.__handle_sighup()

        try:
            self.__current_message = libmessage.MessageFactory.unserialize(message,
                                                                           harmonization=self.harmonization)
        except exceptions.InvalidKey as exc:
            # In case a incoming message is malformed an does not conform with the currently
            # loaded harmonization, stop now as this will happen repeatedly without any change
            raise exceptions.ConfigurationError('harmonization', exc.args[0])

        if 'raw' in self.__current_message and len(self.__current_message['raw']) > 400:
            tmp_msg = self.__current_message.to_dict(hierarchical=False)
            tmp_msg['raw'] = tmp_msg['raw'][:397] + '...'
        else:
            tmp_msg = self.__current_message
        self.logger.debug('Received message %r.', tmp_msg)

        return self.__current_message

    def acknowledge_message(self):
        self.__source_pipeline.acknowledge()

    def _dump_message(self, error_traceback, message: dict):
        if message is None:
            return

        self.logger.info('Dumping message from pipeline to dump file.')
        timestamp = datetime.datetime.utcnow()
        timestamp = timestamp.isoformat()

        dump_file = os.path.join(self.parameters.logging_path, self.__bot_id + ".dump")

        new_dump_data = dict()
        new_dump_data[timestamp] = dict()
        new_dump_data[timestamp]["bot_id"] = self.__bot_id
        new_dump_data[timestamp]["source_queue"] = self.__source_queues
        new_dump_data[timestamp]["traceback"] = error_traceback

        new_dump_data[timestamp]["message"] = message.serialize()

        try:
            with open(dump_file, 'r') as fp:
                dump_data = json.load(fp)
                dump_data.update(new_dump_data)
        except (ValueError, FileNotFoundError):
            dump_data = new_dump_data

        with open(dump_file, 'w') as fp:
            json.dump(dump_data, fp, indent=4, sort_keys=True)

        self.logger.debug('Message dumped.')

    def __load_defaults_configuration(self):
        self.__log_buffer.append(('debug', "Loading defaults configuration from %r."
                                  "" % DEFAULTS_CONF_FILE))
        config = utils.load_configuration(DEFAULTS_CONF_FILE)

        setattr(self.parameters, 'logging_path', DEFAULT_LOGGING_PATH)

        for option, value in config.items():
            setattr(self.parameters, option, value)
            self.__log_configuration_parameter("defaults", option, value)

        self.parameters.log_processed_messages_seconds = datetime.timedelta(seconds=self.parameters.log_processed_messages_seconds)

    def __load_runtime_configuration(self):
        self.logger.debug("Loading runtime configuration from %r.", RUNTIME_CONF_FILE)
        config = utils.load_configuration(RUNTIME_CONF_FILE)
        reinitialize_logging = False

        if self.__bot_id in list(config.keys()):
            params = config[self.__bot_id]
            self.run_mode = params.get('run_mode', 'stream')
            for option, value in params['parameters'].items():
                setattr(self.parameters, option, value)
                self.__log_configuration_parameter("runtime", option, value)
                if option.startswith('logging_'):
                    reinitialize_logging = True

        if reinitialize_logging:
            self.logger.handlers = []  # remove all existing handlers
            self.__init_logger()

    def __init_logger(self):
        """
        Initialize the logger.
        """
        if self.parameters.logging_handler == 'syslog':
            syslog = self.parameters.logging_syslog
        else:
            syslog = False
        self.logger = utils.log(self.__bot_id, syslog=syslog,
                                log_path=self.parameters.logging_path,
                                log_level=self.parameters.logging_level)

    def __load_pipeline_configuration(self):
        self.logger.debug("Loading pipeline configuration from %r.", PIPELINE_CONF_FILE)
        config = utils.load_configuration(PIPELINE_CONF_FILE)

        self.__source_queues = None
        self.__destination_queues = None

        if self.__bot_id in list(config.keys()):

            if 'source-queue' in config[self.__bot_id].keys():
                self.__source_queues = config[self.__bot_id]['source-queue']

            if 'destination-queues' in config[self.__bot_id].keys():

                self.__destination_queues = config[
                    self.__bot_id]['destination-queues']

        else:
            raise exceptions.ConfigurationError('pipeline', "no key "
                                                "{!r}.".format(self.__bot_id))

    def __log_configuration_parameter(self, config_name: str, option: str, value: Any):
        if "password" in option or "token" in option:
            value = "HIDDEN"

        message = "{} configuration: parameter {!r} loaded with value {!r}."\
            .format(config_name.title(), option, value)

        if self.logger:
            self.logger.debug(message)
        else:
            self.__log_buffer.append(("debug", message))

    def __load_harmonization_configuration(self):
        self.logger.debug("Loading Harmonization configuration from %r.", HARMONIZATION_CONF_FILE)
        self.harmonization = utils.load_configuration(HARMONIZATION_CONF_FILE)

    def new_event(self, *args, **kwargs):
        return libmessage.Event(*args, harmonization=self.harmonization, **kwargs)

    @classmethod
    def run(cls):
        if len(sys.argv) < 2:
            exit('No bot ID given.')
        instance = cls(sys.argv[1])
        instance.start()

    def set_request_parameters(self):
        self.http_header = getattr(self.parameters, 'http_header', {})
        self.http_verify_cert = getattr(self.parameters, 'http_verify_cert',
                                        True)
        self.ssl_client_cert = getattr(self.parameters,
                                       'ssl_client_certificate', None)

        if (hasattr(self.parameters, 'http_username') and
            hasattr(self.parameters, 'http_password') and
                self.parameters.http_username):
            self.auth = (self.parameters.http_username,
                         self.parameters.http_password)
        else:
            self.auth = None

        if self.parameters.http_proxy and self.parameters.https_proxy:
            self.proxy = {'http': self.parameters.http_proxy,
                          'https': self.parameters.https_proxy}
        elif self.parameters.http_proxy or self.parameters.https_proxy:
            self.logger.warning('Only %s_proxy seems to be set.'
                                'Both http and https proxies must be set.',
                                'http' if self.parameters.http_proxy else 'https')
            self.proxy = None
        else:
            self.proxy = None

        self.http_timeout_sec = getattr(self.parameters, 'http_timeout_sec', None)
        self.http_timeout_max_tries = getattr(self.parameters, 'http_timeout_max_tries', 1)
        # Be sure this is always at least 1
        self.http_timeout_max_tries = self.http_timeout_max_tries if self.http_timeout_max_tries >= 1 else 1

        self.http_header['User-agent'] = self.parameters.http_user_agent

    @staticmethod
    def check(parameters: dict) -> Optional[List[List[str]]]:
        """
        The bot's own check function can perform individual checks on it's
        parameters.
        `init()` is *not* called before, this is a staticmethod which does not
        require class initialization.

        Parameters:
            parameters: Bot's parameters, defaults and runtime merged together

        Returns:
            output: None or a list of [log_level, log_message] pairs, both
                strings. log_level must be a valid log level.
        """
        pass


class ParserBot(Bot):
    csv_params = {}
    ignore_lines_starting = []
    handle = None
    current_line = None

    def __init__(self, bot_id):
        super(ParserBot, self).__init__(bot_id=bot_id)
        if self.__class__.__name__ == 'ParserBot':
            self.logger.error('ParserBot can\'t be started itself. '
                              'Possible Misconfiguration.')
            self.stop()

    def parse_csv(self, report: dict):
        """
        A basic CSV parser.
        """
        raw_report = utils.base64_decode(report.get("raw")).strip()
        if self.ignore_lines_starting:
            raw_report = '\n'.join([line for line in raw_report.splitlines()
                                    if not any([line.startswith(prefix) for prefix
                                                in self.ignore_lines_starting])])
        self.handle = RewindableFileHandle(io.StringIO(raw_report))
        for line in csv.reader(self.handle):
            self.current_line = self.handle.current_line
            yield line

    def parse_csv_dict(self, report: dict):
        """
        A basic CSV Dictionary parser.
        """
        raw_report = utils.base64_decode(report.get("raw")).strip()
        if self.ignore_lines_starting:
            raw_report = '\n'.join([line for line in raw_report.splitlines()
                                    if not any([line.startswith(prefix) for prefix
                                                in self.ignore_lines_starting])])
        self.handle = RewindableFileHandle(io.StringIO(raw_report))
        for line in csv.DictReader(self.handle):
            self.current_line = self.handle.current_line
            yield line

    def parse_json(self, report: dict):
        """
        A basic JSON parser
        """
        raw_report = utils.base64_decode(report.get("raw"))
        for line in json.loads(raw_report):
            yield line

    def parse(self, report: dict):
        """
        A generator yielding the single elements of the data.

        Comments, headers etc. can be processed here. Data needed by
        `self.parse_line` can be saved in `self.tempdata` (list).

        Default parser yields stripped lines.
        Override for your use or use an existing parser, e.g.::

            parse = ParserBot.parse_csv

        You should do that for recovering lines too.
            recover_line = ParserBot.recover_line_csv

        """
        for line in utils.base64_decode(report.get("raw")).splitlines():
            line = line.strip()
            if not any([line.startswith(prefix) for prefix in self.ignore_lines_starting]):
                yield line

    def parse_line(self, line, report):
        """
        A generator which can yield one or more messages contained in line.

        Report has the full message, thus you can access some metadata.
        Override for your use.
        """
        raise NotImplementedError

    def process(self):
        self.tempdata = []  # temporary data for parse, parse_line and recover_line
        self.__failed = []
        report = self.receive_message()

        if 'raw' not in report:
            self.logger.warning('Report without raw field received. Possible '
                                'bug or misconfiguration in previous bots.')
            self.acknowledge_message()
            return

        for line in self.parse(report):
            if not line:
                continue
            try:
                value = self.parse_line(line, report)
                if value is None:
                    continue
                elif type(value) is list or isinstance(value, types.GeneratorType):
                    # filter out None
                    events = list(filter(bool, value))
                else:
                    events = [value]
            except Exception:
                self.logger.exception('Failed to parse line.')
                self.__failed.append((traceback.format_exc(), line))
            else:
                self.send_message(*events)

        for exc, line in self.__failed:
            report_dump = report.copy()
            report_dump.change('raw', self.recover_line(line))
            self._dump_message(exc, report_dump)

        self.acknowledge_message()

    def recover_line(self, line: str):
        """
        Reverse of parse for single lines.

        Recovers a fully functional report with only the problematic line.
        """
        if self.handle and self.handle.first_line and not self.tempdata:
            tempdata = [self.handle.first_line.strip()]
        else:
            tempdata = self.tempdata
        if self.current_line:
            line = self.current_line
        return '\n'.join(tempdata + [line])

    def recover_line_csv(self, line: str):
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(line)
        return out.getvalue()

    def recover_line_csv_dict(self, line: str):
        """
        Converts dictionaries to csv. self.csv_fieldnames must be list of fields.
        """
        out = io.StringIO()
        writer = csv.DictWriter(out, self.csv_fieldnames, **self.csv_params)
        writer.writeheader()
        writer.writerow(line)
        return out.getvalue()

    def recover_line_json(self, line: dict):
        """
        Reverse of parse for JSON pulses.

        Recovers a fully functional report with only the problematic pulse.
        """
        return json.dumps(line)


class CollectorBot(Bot):
    """
    Base class for collectors.

    Does some sanity checks on message sending.
    """
    def __init__(self, bot_id: str):
        super(CollectorBot, self).__init__(bot_id=bot_id)
        if self.__class__.__name__ == 'CollectorBot':
            self.logger.error('CollectorBot can\'t be started itself. '
                              'Possible Misconfiguration.')
            self.stop()

    def __filter_empty_report(self, message: dict):
        if 'raw' not in message:
            self.logger.warning('Ignoring report without raw field. '
                                'Possible bug or misconfiguration of this bot.')
            return False
        return True

    def __add_report_fields(self, report: dict):
        report.add("feed.name", self.parameters.feed)
        if hasattr(self.parameters, 'code'):
            report.add("feed.code", self.parameters.code)
        if hasattr(self.parameters, 'documentation'):
            report.add("feed.documentation", self.parameters.documentation)
        if hasattr(self.parameters, 'provider'):
            report.add("feed.provider", self.parameters.provider)
        report.add("feed.accuracy", self.parameters.accuracy)
        return report

    def send_message(self, *messages):
        messages = filter(self.__filter_empty_report, messages)
        messages = map(self.__add_report_fields, messages)
        super(CollectorBot, self).send_message(*messages)

    def new_report(self):
        return libmessage.Report()


class Parameters(object):
    pass
