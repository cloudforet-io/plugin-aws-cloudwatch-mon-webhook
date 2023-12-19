import logging
import hashlib
from typing import Union
from dateutil import parser
from yaml import dump

from spaceone.core import utils
from plugin.manager.event_manager import ParseManager
from plugin.error import *

__all__ = ['AWSCloudWatchManager']
_LOGGER = logging.getLogger('spaceone')


class AWSCloudWatchManager(ParseManager):
    webhook_type = "AWS_CLOUDWATCH"

    def parse(self, raw_data: dict) -> dict:
        """

        :param raw_data: dict
        :return EventsResponse: {
            "results": EventResponse
        }
        """
        results = []
        alarm_type = self._get_alarm_type(raw_data)
        _LOGGER.debug(f"[AWSCloudWatchManager] data => {raw_data}")

        event: dict = {
            "event_key": self.generate_event_key(raw_data),
            "event_type": self.get_event_type(raw_data),
            "severity": self.get_severity(raw_data),
            "title": raw_data.get("AlarmName", ""),
            "rule": raw_data.get("AlarmName", ""),
            "image_url": "",
            "resource": self._get_resource(alarm_type, raw_data),
            "description": self._get_description(raw_data),
            "occurred_at": self.convert_to_iso8601(raw_data.get("StateChangeTime")),
            "account": raw_data.get("AWSAccountId", ""),
            "additional_info": self.get_additional_info(alarm_type, raw_data)
        }
        results.append(event)
        _LOGGER.debug(f"[AWSCloudWatchManager] parse => {event}")

        return {
            "results": results
        }

    def generate_event_key(self, raw_data: dict) -> str:
        alarm_arn: str = raw_data.get("AlarmArn")

        if alarm_arn is None:
            raise ERROR_REQUIRED_FIELDS(field="AlarmArn")
        hash_object = hashlib.md5(alarm_arn.encode())
        hashed_event_key: str = hash_object.hexdigest()

        return hashed_event_key

    def get_event_type(self, raw_data: dict) -> str:
        sns_event_state: str = raw_data.get("NewStateValue", "INSUFFICIENT_DATA")
        return 'RECOVERY' if sns_event_state == 'OK' else 'ALERT'

    def get_severity(self, raw_data: dict) -> Union[str, None]:
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
        elif sns_event_state in ["ALERT", "ALARM"]:
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

    def _get_resource(self, alarm_type, raw_data: dict) -> dict:
        return {
            "resource_id": self._get_resource_id(alarm_type, raw_data),
            "resource_type": self._get_resource_type(alarm_type, raw_data),
            "name": self._get_resource_name(alarm_type, raw_data)
        }

    def _get_resource_id(self, alarm_type, raw_data: dict) -> str:
        values = []
        metric = self._get_metric(alarm_type, raw_data)

        if metric is None:
            return ""

        for dimension in metric.get("Dimensions", []):
            values.append(dimension.get("value", ""))

        return ",".join(values)

    def _get_resource_type(self, alarm_type, raw_data: dict) -> str:
        metric = self._get_metric(alarm_type, raw_data)
        if metric == {}:
            return ""

        return metric.get("Namespace", "")

    def _get_resource_name(self, alarm_type, raw_data: dict) -> str:
        namespace = self._get_resource_type(alarm_type, raw_data)
        metric = self._get_metric(alarm_type, raw_data)

        if metric == {}:
            return ""

        r_list = []

        for dimension in metric.get("Dimensions", []):
            r_list.append(dimension.get("name", "") + "=" + dimension.get("value", ""))
        resource_names = ",".join(r_list)

        return f"[{namespace}] {resource_names}"

    @staticmethod
    def _get_alarm_type(raw_data: dict) -> str:
        """
        Trigger Type:
         - STATIC_THRESHOLD
         - METRIC_MATH_FUNCTION

        :param raw_data:
        :return:
        """
        if raw_data.get("Trigger", {}).get("Metrics"):
            return "METRIC_MATH_FUNCTION"
        elif raw_data.get("Trigger", {}).get("Dimensions"):
            return "STATIC_THRESHOLD"

    def _get_metric(self, alarm_type: str, raw_data: dict) -> dict:
        if alarm_type == "METRIC_MATH_FUNCTION":
            if self._get_metrics_cnt(alarm_type, raw_data) > 0:
                return raw_data.get("Trigger", {}).get("Metrics", [])[0].get("MetricStat", {})
            else:
                return {}
        elif alarm_type == "STATIC_THRESHOLD":
            return raw_data.get("Trigger", {})

    @staticmethod
    def _get_metrics_cnt(alarm_type, raw_data: dict) -> int:
        if alarm_type == "METRIC_MATH_FUNCTION":
            return len(raw_data.get("Trigger", {}).get("Metrics", []))
        elif alarm_type == "STATIC_THRESHOLD":
            return 1

    def get_additional_info(self, alarm_type, raw_data: dict) -> dict:
        additional_info: dict = {
            "AlarmArn": raw_data.get("AlarmArn", ""),
            "AlarmName": raw_data.get("AlarmName", ""),
            "AWSAccountId": raw_data.get("AWSAccountId", ""),
            "OldStateValue": raw_data.get("OldStateValue", ""),
            "Region": raw_data.get("Region", "")
        }
        metric = self._get_metric(alarm_type, raw_data)
        if metric == {}:
            return additional_info
        else:
            additional_info.update({
                "MetricName": self._get_metric(alarm_type, raw_data).get("MetricName", ""),
                "Namespace": self._get_metric(alarm_type, raw_data).get("Namespace", "")
            })

        return additional_info
