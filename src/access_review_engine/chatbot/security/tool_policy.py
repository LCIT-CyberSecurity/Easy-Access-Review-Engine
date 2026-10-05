TOOL_POLICY_VERSION = "1.2"
MAX_RESULT_COUNT = 100
MAX_STRING_CHARS = 400
MAX_JSON_CHARS = 12000


def validate_tool_arguments(arguments: object, schema: dict[str, object]) -> bool:
    """Validate the small JSON subset used by chatbot tools before dispatch."""
    if not isinstance(arguments, dict):
        return False
    parameters = schema.get("parameters")
    if not isinstance(parameters, dict):
        return False
    return _validate(arguments, parameters)


def _json_type(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "other"


def _validate(value: object, definition: dict[str, object]) -> bool:
    declared = definition.get("type")
    allowed = declared if isinstance(declared, list) else [declared]
    actual = _json_type(value)
    if actual not in allowed and not (actual == "integer" and "number" in allowed):
        return False
    enum = definition.get("enum")
    if isinstance(enum, list) and value not in enum:
        return False
    if isinstance(value, str):
        minimum = definition.get("minLength", 0)
        maximum = definition.get("maxLength", MAX_STRING_CHARS)
        return (
            isinstance(minimum, int)
            and isinstance(maximum, int)
            and minimum <= len(value) <= min(maximum, MAX_STRING_CHARS)
        )
    if isinstance(value, bool):
        return True
    if isinstance(value, (int, float)):
        minimum = definition.get("minimum")
        maximum = definition.get("maximum")
        return not (
            (isinstance(minimum, (int, float)) and value < minimum)
            or (isinstance(maximum, (int, float)) and value > maximum)
        )
    if isinstance(value, list):
        minimum = definition.get("minItems", 0)
        maximum = definition.get("maxItems", MAX_RESULT_COUNT)
        items = definition.get("items")
        if not isinstance(minimum, int) or not isinstance(maximum, int):
            return False
        if not minimum <= len(value) <= min(maximum, MAX_RESULT_COUNT):
            return False
        if definition.get("uniqueItems") is True:
            try:
                if len({str(item) for item in value}) != len(value):
                    return False
            except TypeError:
                return False
        return isinstance(items, dict) and all(_validate(item, items) for item in value)
    if isinstance(value, dict):
        properties = definition.get("properties")
        required = definition.get("required", [])
        if not isinstance(properties, dict) or not isinstance(required, list):
            return False
        if not set(required).issubset(value):
            return False
        if definition.get("additionalProperties", True) is False and not set(value) <= set(
            properties
        ):
            return False
        return all(
            isinstance(properties.get(name), dict) and _validate(item, properties[name])
            for name, item in value.items()
        )
    return value is None
