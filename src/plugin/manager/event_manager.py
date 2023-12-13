import logging
import hashlib
import json
from typing import Union
from dateutil import parser
from yaml import dump

from spaceone.core import utils
from spaceone.core.manager import BaseManager
from plugin.error import *

__all__ = ['EventManager']
_LOGGER = logging.getLogger('spaceone')


class EventManager(BaseManager):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        return

    def parse(self, raw_data: dict) -> dict:
        """

        :param raw_data: dict
        :return EventsResponse: {
            "results": EventResponse
        }
        """
        results = []
        _LOGGER.debug(f"[parse] data => {raw_data}")

        event: dict = {
            "event_key": self._generate_event_key(raw_data),
            "event_type": self._get_event_type(raw_data),
            "severity": self._get_severity(raw_data),
            "title": raw_data.get("AlarmName", ""),
            "rule": raw_data.get("AlarmName", ""),
            "image_url": "",
            "resource": self._get_resource(raw_data),
            "description": self._get_description(raw_data),
            "occurred_at": self._convert_to_iso8601(raw_data.get("StateChangeTime")),
            "account": self._get_account_id(raw_data),
            "additional_info": self._get_additional_info(raw_data)
        }
        results.append(event)
        _LOGGER.debug(f"[parse] parse Event => {event}")

        return {
            "results": results
        }

    @staticmethod
    def _generate_event_key(raw_data: dict) -> str:
        alarm_arn: str = raw_data.get("AlarmArn")

        if alarm_arn is None:
            raise ERROR_REQUIRED_FIELDS(field="AlarmArn")
        hash_object = hashlib.md5(alarm_arn.encode())
        hashed_event_key: str = hash_object.hexdigest()

        return hashed_event_key

    @staticmethod
    def _get_event_type(raw_data: dict) -> str:
        sns_event_state: str = raw_data.get("NewStateValue", "INSUFFICIENT_DATA")
        return 'RECOVERY' if sns_event_state == 'OK' else 'ALERT'

    @staticmethod
    def _get_severity(raw_data: dict) -> Union[str, None]:
        """
        Severity:
            - CRITICAL
            - ERROR
            - WARNING
            - INFO
            - NOT_AVAILABLE
        """
        sns_event_state: str = raw_data.get('NewStateValue')

        if sns_event_state == "OK":
            return "INFO"
        elif sns_event_state in ['ALERT', 'ALARM']:
            return "ERROR"
        else:
            return None

    @staticmethod
    def _get_description(raw_data: dict) -> str:
        description: dict = {
            "NewStateReason": raw_data.get("NewStateReason", ""),
            "AlarmDescription": raw_data.get("AlarmDescription", ""),
            "Region": raw_data.get("Region", ""),
            "Trigger": raw_data.get("Trigger", {})
        }
        return dump(description, sort_keys=False)

    @staticmethod
    def _convert_to_iso8601(raw_time: str) -> Union[str, None]:
        return utils.datetime_to_iso8601(parser.parse(raw_time))

    def _get_resource(self, raw_data: dict) -> dict:
        return {
            "resource_id": self._get_resource_id(raw_data),
            "resource_type": self._get_resource_type(raw_data),
            "name": self._get_resource_name(raw_data)
        }

    def _get_resource_id(self, raw_data: dict) -> str:
        values = []
        metric_stat = self._get_value_from_metrics(raw_data, "MetricStat")

        for dimension in metric_stat.get("Metric", {}).get("Dimensions", []):
            values.append(dimension.get("value", ""))

        return ",".join(values)

    def _get_resource_type(self, raw_data: dict) -> str:
        metric_stat = self._get_value_from_metrics(raw_data, "MetricStat")
        return metric_stat.get("Metric", {}).get("Namespace", "")

    def _get_resource_name(self, raw_data: dict) -> str:
        namespace = self._get_resource_type(raw_data)
        metric_stat = self._get_value_from_metrics(raw_data, "MetricStat")

        r_list = []
        for dimension in metric_stat.get("Metric", {}).get("Dimensions", []):
            r_list.append(dimension.get("name", "") + "=" + dimension.get("value", ""))
        resource_names = ",".join(r_list)

        return f"[{namespace}] {resource_names}"

    def _get_value_from_metrics(self, raw_data: dict, key: str) -> Union[str, dict, bool, None]:

        if self._get_metrics_cnt(raw_data) > 0:
            return raw_data.get("Trigger", {}).get("Metrics", [])[0].get(key)
        else:
            return ""

    def _get_account_id(self, raw_data: dict) -> str:
        if self._get_metrics_cnt(raw_data) > 0:
            return raw_data.get("Trigger", {}).get("Metrics", [])[0].get("AccountId")
        else:
            return ""

    @staticmethod
    def _get_metrics_cnt(raw_data: dict) -> int:
        return len(raw_data.get("Trigger", {}).get("Metrics", []))

    def _get_additional_info(self, raw_data: dict) -> dict:

        return {
            "AlarmArn": raw_data.get("AlarmArn", ""),
            "AlarmName": raw_data.get("AlarmName", ""),
            "AWSAccountId": raw_data.get("AWSAccountId", ""),
            "MetricName": self._get_value_from_metrics(raw_data, "MetricStat").get("Metric", {}).get("MetricName", ""),
            "Namespace": self._get_value_from_metrics(raw_data, "MetricStat").get("Metric", {}).get("Namespace", ""),
            "OldStateValue": raw_data.get("OldStateValue", ""),
            "Region": raw_data.get("Region", "")
        }
