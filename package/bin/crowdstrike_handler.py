import json
import time
import asyncio

from falconpy import Hosts
from falconpy import Discover
from splunklib import modularinput as smi
from splunklib.client import KVStoreCollection
from splunktaucclib.modinput_wrapper.base_modinput import BaseModInput


"""
CrowdStrike API Handler Class

Notes:
- Not handling exceptions in Python because pythonic is disabled by default.
- falconpy uses requests in the background, so it's blocking.
"""


class CrowdStrikeHandler:
    def __init__(
        self,
        helper: BaseModInput,
        client_id,
        client_secret,
        num_worker_threads,
        log_level="INFO",
        member_cid=None,
        verify=True,
        proxy=None,
    ):
        """
        Initialize CrowdStrike Falcon API Handler
        """
        self.helper = helper

        optional_arguments = {}
        if member_cid:
            optional_arguments["member_cid"] = member_cid

        if proxy:
            optional_arguments["proxy"] = proxy

        debug = True if log_level == "DEBUG" else False

        if not verify:
            self.helper.log_info("Disabling certificate validation for requests to CrowdStrike API!")

        # limit number of concurrent
        self.semaphore = asyncio.BoundedSemaphore(10)
        self.helper.log_debug(f"Number of concurrent requests: {num_worker_threads}")

        self.discover_client = Discover(
            client_id=client_id,
            client_secret=client_secret,
            verify=verify,
            debug=debug,
            **optional_arguments,
        )
        self.hosts_client = Hosts(
            client_id=client_id,
            client_secret=client_secret,
            verify=verify,
            debug=debug,
            **optional_arguments,
        )

    def fetch_device_aids(self, fql_filter=""):
        """
        This function fetches all devices matching your FQL filter
        and returns a list of AIDs
        """
        aids = []

        position = None
        total = 1
        limit = 1000

        while len(aids) < total:
            self.helper.log_info(f"Querying devices: filter={fql_filter}, position={position}, total={total}, progress={round(len(aids)/total * 100, 2)}%")
            query_response = self.hosts_client.query_devices_by_filter_scroll(limit=limit, filter=fql_filter, offset=position)

            if query_response["status_code"] != 200:
                # handle query API error
                for error_result in query_response["body"]["errors"]:
                    self.helper.log_critical(f"Received API error when querying devices: {error_result['message']}")
                    return None

            # parse response and update position/total values
            query_response_data = query_response["body"]
            page = query_response_data["meta"]["pagination"]
            total = page["total"]
            position = page["offset"]

            self.helper.log_debug(f"Successfully fetched {len(query_response_data['resources'])} AID(s) from Hosts API - continuing with next page ...")
            aids.extend(query_response_data["resources"])

        # remove duplicates
        aids = list(set(aids))
        self.helper.log_info(f"Successfully fetched {len(aids)} AID(s) in total!")
        self.helper.log_debug(f"Matching AIDs: {aids}")

        return aids

    async def query_application_ids_for_aid(self, aid, fql_filter_application=""):
        offset = 0
        total = 1
        limit = 100
        application_ids = []

        # put together FQL with AID and application filter
        curr_fql_filter = f"host.aid:'{aid}'"
        if fql_filter_application:
            curr_fql_filter = f"{curr_fql_filter}+{fql_filter_application}"

        self.helper.log_info(f'Querying applications for AID {aid} with FQL filter "{curr_fql_filter}" ...')

        # query applications from API and collect application IDs
        while offset < total:
            self.helper.log_debug(f'Query status for AID {aid}: offset={offset}, total={total}, progress={round(offset/total*100, 2)}%, filter="{curr_fql_filter}"')
            query_response = self.discover_client.query_applications(offset=offset, limit=limit, filter=curr_fql_filter)

            if query_response["status_code"] != 200:
                # handle query API error
                for error_result in query_response["body"]["errors"]:
                    self.helper.log_critical(f"Received API error when querying applications: {error_result['message']}")
                    return None

            # parse response and update offset/total values
            query_response_data = query_response["body"]
            offset = offset + limit
            total = query_response_data["meta"]["pagination"]["total"]

            if len(query_response_data["resources"]) == 0:
                self.helper.log_info(f"CrowdStrike does not have any application data for AID {aid}!")

            application_ids.extend(query_response_data["resources"])

        return application_ids

    async def single_fetch_application_and_index(
        self,
        aid,
        event_writer: smi.EventWriter,
        kv_checkpoint: KVStoreCollection,
        index,
        fql_filter_application="",
        index_host_info=False,
        excluded_fields="",
    ):
        async with self.semaphore:
            # fetch application IDs for AID
            application_ids_for_aid = await self.query_application_ids_for_aid(aid, fql_filter_application)
            num_indexed = 0

            if application_ids_for_aid is None:
                self.helper.log_warning(f"Unable to query application IDs for AID {aid}! See TA logs for more details. Will retry it during the next run :/")
                return 0

            if len(application_ids_for_aid) == 0:
                self.helper.log_info(f"Skipping application detail requests because no application IDs have been returned for AID {aid}")
            else:
                self.helper.log_info(f"Fetched {len(application_ids_for_aid)} application ID(s) for AID {aid}! Requesting application details for them next.")

                # iterate over application IDs and fetch details for them (100 at a time = max)
                for lower_boundary in range(0, len(application_ids_for_aid), 100):
                    upper_boundary = lower_boundary + 100 if lower_boundary + 100 < len(application_ids_for_aid) else len(application_ids_for_aid)
                    application_id_range = application_ids_for_aid[lower_boundary:upper_boundary]

                    self.helper.log_debug(f"Requesting application details {lower_boundary}-{upper_boundary} for AID {aid} ...")

                    # fetch application details
                    get_applications_response = self.discover_client.get_applications(application_id_range)

                    if get_applications_response["status_code"] != 200:
                        # handle details API error
                        for error_result in get_applications_response["body"]["errors"]:
                            self.helper.log_critical(f"Received API error when fetching application details: {error_result['message']}")
                            return None

                    # parse details and index
                    self.helper.log_debug(f"Sending events {lower_boundary}-{upper_boundary} to index {index} ...")
                    for app in get_applications_response["body"]["resources"]:
                        # check if host information should be removed
                        if not index_host_info:
                            try:
                                del app["host"]
                            except KeyError as ex:
                                self.helper.log_warning(f"Unable to delete host information from application: {ex}")

                            # adding AID to event
                            app["host"] = {"aid": aid}

                        # remove excluded fields
                        for field_to_remove in excluded_fields.split(","):
                            normalized_field_to_remove = field_to_remove.strip()

                            try:
                                # I know this is kinda ugly, but application data only has two-layers, so this is
                                # more performant than iterations with isinstance(...)
                                if "." in normalized_field_to_remove:
                                    key_parts = normalized_field_to_remove.split(".")
                                    parent_key = key_parts[0].strip()
                                    child_key = key_parts[1].strip()

                                    del app[parent_key][child_key]
                                else:
                                    del app[normalized_field_to_remove]
                            except KeyError as ex:
                                self.helper.log_debug(f"Unable to remove excluded field {normalized_field_to_remove} from application: {ex}")

                        event = smi.Event(
                            data=json.dumps(app, ensure_ascii=False),
                            index=index,
                            sourcetype="crowdstrike:discover:application",
                            source="TA-crowdstrike_falcon_discover",
                            time=time.time(),
                        )
                        try:
                            event_writer.write_event(event)
                        except Exception as ex:
                            self.helper.log_critical(f"Caught exception when sending event to Splunk :/ Stopping input, exception: {ex}")
                            return None

                        num_indexed = num_indexed + 1

                self.helper.log_info(f"Successfully indexed {num_indexed} applications for AID {aid}!")

            # remove AID from checkpoint
            self.helper.log_debug(f"Removing AID {aid} from checkpoint ...")
            try:
                kv_checkpoint.data.delete_by_id(aid)
            except Exception as ex:
                self.helper.log_critical(f"Unable to delete AID {aid} from checkpoint: {ex}")

            self.helper.log_info(f"Successfully removed AID {aid} from checkpoint!")

            return num_indexed

    async def bulk_fetch_and_index(
        self,
        event_writer: smi.EventWriter,
        kv_checkpoint: KVStoreCollection,
        index,
        aids,
        fql_filter_application="",
        index_host_info=False,
        excluded_fields="",
    ):
        tasks = []

        for aid in aids:
            tasks.append(
                self.single_fetch_application_and_index(
                    aid,
                    event_writer,
                    kv_checkpoint,
                    index,
                    fql_filter_application,
                    index_host_info,
                    excluded_fields,
                )
            )

        event_counters = await asyncio.gather(*tasks)
        num_total_indexed = sum(event_counters)

        return num_total_indexed

    def fetch_host_ids(self, fql_filter=""):
        """
        This function fetches all Discover host IDs matching the given FQL filter
        and returns a list of host IDs.
        """
        host_ids = []
        offset = 0
        total = 1
        limit = 100

        while offset < total:
            self.helper.log_info(
                f'Querying Discover hosts: filter="{fql_filter}", offset={offset}, total={total}, '
                f"progress={round(offset / total * 100, 2)}%"
            )
            query_response = self.discover_client.query_hosts(
                offset=offset, limit=limit, filter=fql_filter
            )

            if query_response["status_code"] != 200:
                for error_result in query_response["body"]["errors"]:
                    self.helper.log_critical(
                        f"Received API error when querying Discover hosts: {error_result['message']}"
                    )
                return None

            query_response_data = query_response["body"]
            offset = offset + limit
            total = query_response_data["meta"]["pagination"]["total"]

            resources = query_response_data.get("resources") or []
            if not resources:
                self.helper.log_info("No Discover host IDs returned for this page.")

            host_ids.extend(resources)

        host_ids = list(set(host_ids))
        self.helper.log_info(f"Successfully fetched {len(host_ids)} Discover host ID(s) in total!")
        return host_ids

    def fetch_hosts_and_index_all(
        self,
        event_writer: smi.EventWriter,
        kv_checkpoint: KVStoreCollection,
        index,
        host_ids,
        excluded_fields="",
    ):
        """
        This function fetches full host details for a given list of host IDs from the
        CrowdStrike Discover API and indexes them into Splunk.
        """
        num_total_indexed = 0

        for lower_boundary in range(0, len(host_ids), 100):
            upper_boundary = (
                lower_boundary + 100
                if lower_boundary + 100 < len(host_ids)
                else len(host_ids)
            )
            host_id_batch = host_ids[lower_boundary:upper_boundary]

            self.helper.log_debug(
                f"Requesting host details {lower_boundary}-{upper_boundary} of {len(host_ids)} ..."
            )

            get_hosts_response = self.discover_client.get_hosts(ids=host_id_batch)

            if get_hosts_response["status_code"] != 200:
                for error_result in get_hosts_response["body"]["errors"]:
                    self.helper.log_critical(
                        f"Received API error when fetching Discover host details: {error_result['message']}"
                    )
                return None

            resources = get_hosts_response["body"].get("resources") or []
            self.helper.log_debug(
                f"Sending {len(resources)} host event(s) to index {index} ..."
            )

            for host in resources:
                # remove excluded fields (supports dot notation)
                for field_to_remove in excluded_fields.split(","):
                    normalized_field = field_to_remove.strip()
                    if not normalized_field:
                        continue
                    try:
                        if "." in normalized_field:
                            key_parts = normalized_field.split(".", 1)
                            parent_key = key_parts[0].strip()
                            child_key = key_parts[1].strip()
                            del host[parent_key][child_key]
                        else:
                            del host[normalized_field]
                    except KeyError as ex:
                        self.helper.log_debug(
                            f"Unable to remove excluded field {normalized_field} from host: {ex}"
                        )

                event = smi.Event(
                    data=json.dumps(host, ensure_ascii=False),
                    index=index,
                    sourcetype="crowdstrike:discover:host",
                    source="TA-crowdstrike_falcon_discover",
                    time=time.time(),
                )
                try:
                    event_writer.write_event(event)
                except Exception as ex:
                    self.helper.log_critical(
                        f"Caught exception when sending host event to Splunk: {ex}"
                    )
                    return None

                num_total_indexed += 1

            # remove processed host IDs from checkpoint
            for host_id in host_id_batch:
                try:
                    kv_checkpoint.data.delete_by_id(host_id)
                except Exception as ex:
                    self.helper.log_critical(
                        f"Unable to delete host ID {host_id} from checkpoint: {ex}"
                    )

            self.helper.log_info(
                f"Successfully indexed and checkpointed batch {lower_boundary}-{upper_boundary}."
            )

        return num_total_indexed

    def fetch_applications_and_index_all(
        self,
        event_writer: smi.EventWriter,
        kv_checkpoint: KVStoreCollection,
        index,
        aids,
        fql_filter_application="",
        index_host_info=False,
        excluded_fields="",
    ):
        """
        This function fetches all applications for a given list of AIDs and
        an optional FQL filter and returns a set of application details.
        """
        num_total_indexed = asyncio.run(
            self.bulk_fetch_and_index(
                event_writer,
                kv_checkpoint,
                index,
                aids,
                fql_filter_application,
                index_host_info,
                excluded_fields,
            )
        )

        return num_total_indexed
