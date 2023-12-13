import logging
import json
from typing import List

from spaceone.monitoring.plugin.webhook.lib.server import WebhookPluginServer
from plugin.manager.event_manager import EventManager

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
    options = params['options']
    data = params['data']

    event_mgr = EventManager()
    return event_mgr.parse(data["Message"])



