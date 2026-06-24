"""Analysis history endpoints."""

from fastapi import APIRouter, HTTPException, Query

from app.services.database import get_analysis, get_analyses

router = APIRouter()


@router.get("/analyses")
async def list_analyses(page: int = Query(1, ge=1), pageSize: int = Query(20, ge=1, le=100)):
    """Get paginated analysis history."""
    results, total = get_analyses(page, pageSize)

    analyses = []
    for r in results:
        analyses.append({
            "analysis_id": r.get("analysis_id", ""),
            "timestamp": r.get("timestamp", ""),
            "input_preview": r.get("input_text", "")[:100],
            "risk_score": r.get("risk_score", 0),
            "risk_level": r.get("risk_level", "low"),
        })

    return {
        "analyses": analyses,
        "total": total,
        "page": page,
        "page_size": pageSize,
    }


@router.get("/analyses/{analysis_id}")
async def get_analysis_detail(analysis_id: str):
    """Get a specific analysis by ID."""
    result = get_analysis(analysis_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Analysis {analysis_id} not found")
    return result
