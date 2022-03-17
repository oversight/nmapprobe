from collections import namedtuple


def check_response(name, state_data, error, framework):
    CheckResponse = namedtuple(
        'CheckResponse',
        ['name', 'state_data', 'error', 'framework'])
    return CheckResponse(
        name, state_data, error, framework)
