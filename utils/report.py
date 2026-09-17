import json
from pathlib import Path


def save_json(data, output_path):
    """
    Save data as a formatted JSON file.
    """

    path = Path(output_path)

    path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    path.write_text(
        json.dumps(
            data,
            indent=2,
            default=str
        ),
        encoding="utf-8"
    )

    return path