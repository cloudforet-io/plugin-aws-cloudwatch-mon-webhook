import logging
import json

from spaceone.monitoring.plugin.webhook.lib.server import WebhookPluginServer
from plugin.manager.event_manager.base import ParseManager

_LOGGER = logging.getLogger('spaceone')

app = WebhookPluginServer()


@app.route('Webhook.init')
def webhook_init(params: dict) -> dict:
    """ init plugin by options
    {
        'options': 'dict'       # Required
    }

    :return:
    :param params: WebhookRequest :
        WebhookResponse: {
            'metadata': 'dict'  # Required
        }
    """
    return {
        'meatadata': {}
    }


@app.route('Webhook.verify')
def webhook_verify(params: dict) -> None:
    """ verifying plugin

    :param params: WebhookRequest: {
            'options': 'dict'   # Required
        }

    :return:
        None
    """
    pass


@app.route('Event.parse')
def event_parse(params: dict) -> dict:
    """ Parsing Event Webhook

    Args:
        params (EventRequest): {
            'options': {        # Required
                'message_root': 'message.detail.xxx'
            },
            'data': 'dict'      # Required
        }

    Returns:
        List[EventResponse]
        {
            'event_key': 'str'          # Required
            'event_type': 'str'         # Required
            'title': 'str'              # Required
            'description': 'str'
            'severity': 'str'           # Required
            'resource': dict
            'rule': 'str'
            'occurred_at': 'datetime'   # Required
            'additional_info': dict     # Required
            'image_url': ''
        }
    """
    options = params["options"]
    data = params["data"]

    # Check if webhook messages are SNS subscription
    webhook_type = _get_webhook_type(data)
    parse_mgr = ParseManager.get_parse_manager_by_webhook_type(webhook_type)

    if webhook_type == "AWS_SNS":
        return parse_mgr.parse(data)
    else:
        return parse_mgr.parse(json.loads(data.get("Message", "")))


def _get_webhook_type(data: dict) -> str:
    if data.get("Type") == "SubscriptionConfirmation":
        return "AWS_SNS"
    else:
        return "AWS_CLOUDWATCH"
