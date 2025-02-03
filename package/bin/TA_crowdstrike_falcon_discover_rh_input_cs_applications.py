import import_declare_test  # noqa: F401

from splunktaucclib.rest_handler.endpoint import (
    field,
    validator,
    RestModel,
    DataInputModel,
)
from splunktaucclib.rest_handler import admin_external, util
from splunktaucclib.rest_handler.admin_external import AdminExternalHandler
import logging

util.remove_http_proxy_env_vars()


fields = [
    field.RestField(
        "interval",
        required=True,
        encrypted=False,
        default="86400",
        validator=validator.Pattern(
            regex=r"""^\-[1-9]\d*$|^\d*$""",
        ),
    ),
    field.RestField(
        "cron_schedule",
        required=True,
        encrypted=False,
        default="0 0 * * *",
        validator=validator.String(
            max_len=80,
            min_len=1,
        ),
    ),
    field.RestField(
        "index",
        required=True,
        encrypted=False,
        default="default",
        validator=validator.String(
            max_len=80,
            min_len=1,
        ),
    ),
    field.RestField("cs_account", required=True, encrypted=False, default=None, validator=None),
    field.RestField(
        "fql_filter_devices",
        required=False,
        encrypted=False,
        default=None,
        validator=validator.String(
            max_len=8192,
            min_len=0,
        ),
    ),
    field.RestField(
        "fql_filter_devices_help",
        required=False,
        encrypted=False,
        default=None,
        validator=None,
    ),
    field.RestField(
        "fql_filter_applications",
        required=False,
        encrypted=False,
        default=None,
        validator=validator.String(
            max_len=8192,
            min_len=0,
        ),
    ),
    field.RestField(
        "fql_filter_applications_help",
        required=False,
        encrypted=False,
        default=None,
        validator=None,
    ),
    field.RestField("index_host_info", required=True, encrypted=False, default=False, validator=None),
    field.RestField(
        "excluded_fields",
        required=False,
        encrypted=False,
        default=None,
        validator=validator.String(
            max_len=8192,
            min_len=0,
        ),
    ),
    field.RestField(
        "num_worker_threads",
        required=True,
        encrypted=False,
        default=5,
        validator=validator.Number(
            max_val=10,
            min_val=1,
        ),
    ),
    field.RestField("verify", required=True, encrypted=False, default=True, validator=None),
    field.RestField("disabled", required=False, validator=None),
]
model = RestModel(fields, name=None)


endpoint = DataInputModel(
    "input_cs_applications",
    model,
)


if __name__ == "__main__":
    logging.getLogger().addHandler(logging.NullHandler())
    admin_external.handle(
        endpoint,
        handler=AdminExternalHandler,
    )
