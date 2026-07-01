import import_declare_test  # noqa: F401

import json
import sys
import solnlib.utils
import splunklib.client
import time
import datetime

from solnlib import log
from splunklib import modularinput as smi
from croniter import croniter

from splunktaucclib.modinput_wrapper.base_modinput import BaseModInput

from crowdstrike_handler import CrowdStrikeHandler

ADDON_NAME = "TA-crowdstrike_falcon_discover"
CHECK_POINT_KEY = "crowdstrike_falcon_discover_cs_applications_checkpointer"
SCHEDULER_KEY = "crowdstrike_falcon_discover_scheduler"


class CrowdStrikeApplicationInput(BaseModInput):

    def __init__(self):
        super(CrowdStrikeApplicationInput, self).__init__(
            "ta_crowdstrike_falcon_discover", "input_cs_applications", False
        )
        self.global_checkbox_fields = None

    def get_scheme(self):
        scheme = super(CrowdStrikeApplicationInput, self).get_scheme()
        scheme.title = "CrowdStrike Discover Application Input"
        scheme.description = "CrowdStrike Discover Application Input"
        scheme.use_external_validation = True
        scheme.streaming_mode_xml = True
        scheme.use_single_instance = False

        scheme.add_argument(
            smi.Argument(
                "name", title="Name", description="Name", required_on_create=True
            )
        )

        scheme.add_argument(
            smi.Argument(
                "cron_schedule",
                required_on_create=True,
            )
        )

        scheme.add_argument(
            smi.Argument(
                "cs_account",
                required_on_create=True,
            )
        )

        scheme.add_argument(
            smi.Argument(
                "fql_filter_devices",
                required_on_create=False,
            )
        )

        scheme.add_argument(
            smi.Argument(
                "fql_filter_devices_help",
                required_on_create=False,
            )
        )

        scheme.add_argument(
            smi.Argument(
                "fql_filter_applications",
                required_on_create=False,
            )
        )

        scheme.add_argument(
            smi.Argument(
                "fql_filter_applications_help",
                required_on_create=False,
            )
        )

        scheme.add_argument(
            smi.Argument(
                "index_host_info",
                required_on_create=True,
            )
        )

        scheme.add_argument(
            smi.Argument(
                "excluded_fields",
                required_on_create=False,
            )
        )

        scheme.add_argument(
            smi.Argument(
                "num_worker_threads",
                required_on_create=True,
            )
        )

        scheme.add_argument(
            smi.Argument(
                "verify",
                required_on_create=True,
            )
        )

        return scheme

    def get_app_name(self):
        return "TA-crowdstrike_falcon_discover"

    def get_account_fields(self):
        return ["cs_account"]

    def get_checkbox_fields(self):
        return ["index_host_info", "verify"]

    def validate_input(self, definition: smi.ValidationDefinition):
        return

    def collect_events(self, event_writer: smi.EventWriter):
        """
        This function fetches applications from CrowdStrike Falcon Discover
        and streams them into Splunk.
        """
        # set up logging
        log_level = self.get_log_level()
        self.set_log_level(log_level)
        normalized_input_name = (
            f"{self.get_input_type()}://{self.get_input_stanza_names()}"
        )
        log.modular_input_start(self.logger, normalized_input_name)

        try:
            # fetch and save input configuration
            index = self.get_arg("index")
            cron_schedule = self.get_arg("cron_schedule")
            api_account = self.get_arg("cs_account")
            fql_filter_devices = self.get_arg("fql_filter_devices")
            fql_filter_applications = self.get_arg("fql_filter_applications")
            excluded_fields = self.get_arg("excluded_fields")
            index_host_info = self.get_arg("index_host_info")
            num_worker_threads = self.get_arg("num_worker_threads")
            verify = self.get_arg("verify")

            # save account configuration
            client_id = api_account["client_id"]
            client_secret = api_account["client_secret"]
            member_cid = (
                api_account["member_cid"] if "member_cid" in api_account else None
            )

            if (
                not index
                or not cron_schedule
                or not api_account
                or index_host_info is None
                or num_worker_threads is None
            ):
                self.log_critical(
                    f"Stopping input because of invalid input configuration: name={normalized_input_name}, schedule={cron_schedule}, account={api_account['name']}, index={index}, fql_filter_devices={fql_filter_devices}, fql_filter_applications={fql_filter_applications}, index_host_info={index_host_info}, excluded_fields={excluded_fields}, num_worker_threads={num_worker_threads}, verify={verify}"
                )
                sys.exit(1)

            # set defaults for optional arguments
            fql_filter_devices = fql_filter_devices if fql_filter_devices else ""
            fql_filter_applications = (
                fql_filter_applications if fql_filter_applications else ""
            )
            excluded_fields = excluded_fields if excluded_fields else ""
            verify = verify if verify is not None else True

            self.log_info(
                f"Starting input with configuration: name={normalized_input_name}, cron_schedule={cron_schedule}, account={api_account['name']}, index={index}, fql_filter_devices={fql_filter_devices}, fql_filter_applications={fql_filter_applications}, index_host_info={index_host_info}, excluded_fields={excluded_fields}, num_worker_threads={num_worker_threads}, verify={verify}"
            )

            # initialize splunklib client
            dscheme, dhost, dport = solnlib.utils.extract_http_scheme_host_port(
                self.context_meta["server_uri"]
            )
            splunklib_client = splunklib.client.connect(
                host=dhost,
                port=dport,
                scheme=dscheme,
                app=ADDON_NAME,
                token=self.context_meta["session_key"],
            )

            # fetch and save proxy configuration
            proxy = self.get_proxy()

            # initialize CrowdStrike handler
            cs_handler = CrowdStrikeHandler(
                self,
                client_id,
                client_secret,
                num_worker_threads,
                log_level,
                member_cid,
                verify,
                proxy,
            )

            # fetch AIDs from check point
            try:
                kv_checkpoint: splunklib.client.KVStoreCollection = (
                    splunklib_client.kvstore[CHECK_POINT_KEY]
                )
                aids_to_query = [c["_key"] for c in kv_checkpoint.data.query()]
            except Exception as ex:
                self.log_info(
                    f"Unable to fetch checkpoint from KV Store! Stopping now. Exception: {ex}"
                )
                sys.exit(1)

            # check if there are remaining AIDs in check point
            # -> if yes, continue where left off
            # -> if not, check if input should run depending on schedule settings
            if aids_to_query:
                self.log_info(
                    f"There are {len(aids_to_query)} AIDs in the check point. Running application input for these AIDs instead of fetching AIDs from the devices API ..."
                )
            else:
                schedule_reached = False

                while schedule_reached is False:
                    # refetch cron_schedule setting in case it has changed
                    cron_schedule = self.get_arg("cron_schedule")

                    # fetch scheduler data from KV store collection
                    self.log_debug(
                        "Checking scheduler data if next execution time has been reached ..."
                    )
                    try:
                        kv_scheduler: splunklib.client.KVStoreCollection = (
                            splunklib_client.kvstore[SCHEDULER_KEY]
                        )
                        scheduler_data = kv_scheduler.data.query_by_id(
                            normalized_input_name
                        )
                    except Exception:
                        # first run, no scheduler data
                        scheduler_data = None

                    if scheduler_data:
                        now = datetime.datetime.now().astimezone()
                        scheduler_expression = scheduler_data["schedule"]
                        scheduler_next_run = datetime.datetime.fromtimestamp(
                            timestamp=scheduler_data["next_run"],
                            tz=datetime.timezone.utc,
                        )

                        self.log_debug(
                            f"Scheduler data: schedule={cron_schedule}, scheduler_expression={scheduler_expression} now={now}, next run={scheduler_next_run}"
                        )

                        # run input if next run has been reached or schedule settings have changed
                        if scheduler_expression != cron_schedule:
                            self.log_info(
                                f"Cron expression changed (was={scheduler_expression}, now={cron_schedule}). Starting input ..."
                            )
                            schedule_reached = True
                        elif now > scheduler_next_run:
                            self.log_info(
                                f"Schedule has been reached (now={now}, next_run={scheduler_next_run}). Starting input ..."
                            )
                            schedule_reached = True
                        else:
                            # sleep for 1 minute and then check again
                            self.log_info(
                                f"Input schedule has not yet been reached (input={normalized_input_name}, now={now}, next run={scheduler_next_run}). Sleeping for 1 minute ..."
                            )
                            time.sleep(60)
                    else:
                        self.log_info(
                            "No scheduler data has been found in KV store (first run?). Starting input ..."
                        )
                        schedule_reached = True

                # schedule has been reached - running input ...
                self.log_info(
                    f'Fetching devices from CrowdStrike Hosts API with FQL filter "{fql_filter_devices}" ...'
                )
                aids_to_query = cs_handler.fetch_device_aids(fql_filter_devices)

                if not aids_to_query:
                    self.log_error(
                        "The input was not able to index application data, because CrowdStrike devices could not be fetched :/ Please check the TA logs for more details why this happened."
                    )
                    log.modular_input_end(self.logger, normalized_input_name)
                    sys.exit(1)

                # save AIDs in checkpoint
                self.log_info(f"Saving {len(aids_to_query)} AID(s) in checkpoint ...")
                try:
                    for chunk_start in range(0, len(aids_to_query), 100):
                        chunk_end = (
                            chunk_start + 100
                            if chunk_start + 100 < len(aids_to_query)
                            else len(aids_to_query)
                        )
                        chunk = [
                            {"_key": aid}
                            for aid in aids_to_query[chunk_start:chunk_end]
                        ]

                        # the batch_save(...) function has a bug (hide the pain)
                        kv_checkpoint.data._post(
                            "batch_save",
                            headers=splunklib.client.KVStoreCollectionData.JSON_HEADER,
                            body=json.dumps(chunk),
                        )

                    self.log_info(
                        f"Successfully saved {len(aids_to_query)} AID(s) in checkpoint!"
                    )
                except Exception as ex:
                    self.log_critical(f"Unable to save AIDs in checkpoint: {ex}")
                    sys.exit(1)

            self.log_info(
                f'Fetching applications from CrowdStrike Discover API for {len(aids_to_query)} device(s) with FQL filter "{fql_filter_applications}" ...'
            )
            num_total_indexed = cs_handler.fetch_applications_and_index_all(
                event_writer,
                kv_checkpoint,
                index,
                aids_to_query,
                fql_filter_applications,
                index_host_info,
                excluded_fields,
            )

            if num_total_indexed:
                log.events_ingested(
                    self.logger,
                    normalized_input_name,
                    "crowdstrike:discover:application",
                    num_total_indexed,
                    index,
                )
            else:
                self.log_error(
                    "The input was not able to index application data :/ Please check the TA logs for more details."
                )

            # Always update the scheduler after a completed run — even when zero events
            # were indexed — so the input does not immediately re-fire on the next restart.
            iteration = croniter(
                expr_format=cron_schedule,
                start_time=datetime.datetime.now().astimezone(),
            )
            next_run = iteration.get_next(datetime.datetime)
            self.log_info(
                f"Updating scheduler data: input={normalized_input_name}, schedule={cron_schedule}, next_run={next_run}"
            )

            try:
                kv_scheduler: splunklib.client.KVStoreCollection = (
                    splunklib_client.kvstore[SCHEDULER_KEY]
                )
                # batch_save is an atomic upsert — no separate insert/update needed
                kv_scheduler.data._post(
                    "batch_save",
                    headers=splunklib.client.KVStoreCollectionData.JSON_HEADER,
                    body=json.dumps([{
                        "_key": normalized_input_name,
                        "schedule": cron_schedule,
                        "next_run": int(next_run.timestamp()),
                    }]),
                )
                self.log_info("Successfully updated scheduler data!")
            except Exception as ex:
                self.log_error(
                    f"Unable to update scheduler data in KV Store: {ex}. Input may run again sooner than scheduled."
                )

            log.modular_input_end(self.logger, normalized_input_name)

        except Exception as e:
            log.log_exception(
                self.logger,
                e,
                msg_before="Exception raised while ingesting data for demo_input: ",
            )


if __name__ == "__main__":
    exit_code = CrowdStrikeApplicationInput().run(sys.argv)
    sys.exit(exit_code)
