TOOL_POLICY_VERSION = "1.2"
MAX_RESULT_COUNT = 25
MAX_STRING_CHARS = 400
MAX_JSON_CHARS = 12000


def validate_tool_arguments(arguments: object, schema: dict[str, object]) -> bool:
    """Validate the small JSON subset used by chatbot tools before dispatch."""
    if not isinstance(arguments, dict):
        return False
    parameters = schema.get("parameters")
    if not isinstance(parameters, dict):
        return False
    properties = parameters.get("properties")
    required = parameters.get("required")
    if not isinstance(properties, dict) or not isinstance(required, list):
        return False
    if set(arguments) != set(properties):
        return False
    if not set(required).issubset(arguments):
        return False
    for name, value in arguments.items():
        definition = properties.get(name)
        if not isinstance(definition, dict):
            return False
        types = definition.get("type")
        allowed_types = types if isinstance(types, list) else [types]
        actual = "null" if value is None else "string" if isinstance(value, str) else "other"
        if actual not in allowed_types:
            return False
        if isinstance(value, str) and len(value) > MAX_STRING_CHARS:
            return False
    return True
