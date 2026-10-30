from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse

from src.case_store import CaseStore


app = FastAPI(
    title="TRACEE API",
    version="2.1",
    description="Read-only investigation API for TRACEE",
)

store = CaseStore()


@app.get("/")
def dashboard() -> FileResponse:
    dashboard_file = (
        Path(__file__).resolve().parent.parent
        / "web"
        / "index.html"
    )

    if not dashboard_file.exists():
        raise HTTPException(
            status_code=404,
            detail="Dashboard not found",
        )

    return FileResponse(dashboard_file)


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "tracee-api",
        "version": "2.1",
    }


@app.get("/investigations")
def list_investigations() -> dict[str, Any]:
    investigations = store.list_investigations()

    return {
        "count": len(investigations),
        "investigations": investigations,
    }


@app.get("/investigations/{run_id}")
def get_investigation(
    run_id: str,
) -> dict[str, Any]:

    try:
        return store.get_investigation(run_id)

    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid investigation run ID",
        )

    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail="Investigation not found",
        )


@app.get("/investigations/{run_id}/evidence")
def get_evidence(
    run_id: str,
) -> dict[str, Any]:

    try:
        evidence = store.list_evidence(run_id)

    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid investigation run ID",
        )

    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail="Investigation not found",
        )

    return {
        "run_id": run_id,
        "count": len(evidence),
        "evidence": evidence,
    }


@app.get(
    "/investigations/{run_id}/evidence/{evidence_id}"
)
def get_evidence_detail(
    run_id: str,
    evidence_id: str,
) -> dict[str, Any]:

    try:
        return store.get_evidence_detail(
            run_id,
            evidence_id,
        )

    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid investigation or evidence ID",
        )

    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail="Evidence not found",
        )


@app.get("/investigations/{run_id}/events")
def get_events(
    run_id: str,
    event_type: str | None = Query(
        default=None
    ),
    entity: str | None = Query(
        default=None
    ),
    evidence_id: str | None = Query(
        default=None
    ),
) -> dict[str, Any]:

    try:
        events = store.get_events(run_id)

    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid investigation run ID",
        )

    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail="Investigation not found",
        )

    if event_type:
        events = [
            event
            for event in events
            if str(
                event.get("event_type", "")
            ).lower()
            == event_type.lower()
        ]

    if entity:
        entity_query = entity.lower()

        filtered_events = []

        for event in events:

            entities = event.get(
                "entities",
                [],
            )

            attributes = event.get(
                "attributes",
                {},
            )

            entity_text = " ".join(
                str(item)
                for item in entities
            ).lower()

            attribute_text = str(
                attributes
            ).lower()

            if (
                entity_query in entity_text
                or entity_query in attribute_text
            ):
                filtered_events.append(
                    event
                )

        events = filtered_events

    if evidence_id:
        events = [
            event
            for event in events
            if event.get("evidence_id")
            == evidence_id
        ]

    return {
        "run_id": run_id,
        "count": len(events),
        "events": events,
    }


@app.get(
    "/investigations/{run_id}/correlations"
)
def get_correlations(
    run_id: str,
) -> dict[str, Any]:

    try:
        correlations = store.get_correlations(
            run_id
        )

    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid investigation run ID",
        )

    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail="Investigation not found",
        )

    return {
        "run_id": run_id,
        "count": len(correlations),
        "correlations": correlations,
    }


@app.get(
    "/investigations/{run_id}/timeline"
)
def get_timeline(
    run_id: str,
) -> dict[str, Any]:

    try:
        timeline = store.get_timeline(
            run_id
        )

    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid investigation run ID",
        )

    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail="Investigation timeline not found",
        )

    return {
        "run_id": run_id,
        "count": (
            len(timeline)
            if hasattr(timeline, "__len__")
            else 0
        ),
        "timeline": timeline,
    }


@app.get(
    "/investigations/{run_id}/graph"
)
def get_graph(
    run_id: str,
) -> Any:

    try:
        return store.get_graph(run_id)

    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid investigation run ID",
        )

    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail="Investigation graph not found",
        )
