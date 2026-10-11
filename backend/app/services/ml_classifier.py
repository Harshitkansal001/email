from app.schemas.analysis import ClassifierOutput


def classify(_: str) -> ClassifierOutput:
    return ClassifierOutput(
        status="not_configured",
        label=None,
        note="No classifier has been selected and evaluated; no model prediction was made.",
    )
