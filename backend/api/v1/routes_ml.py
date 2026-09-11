from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException, BackgroundTasks
from backend.ml.train import PhishingModelTrainer
from backend.ml.predictor import predictor

router = APIRouter(prefix="/ml", tags=["ml"])

class PredictRequest(BaseModel):
    text: str = Field(..., description="Subject or email body text to evaluate with ML")

class TrainRequest(BaseModel):
    dataset: Optional[str] = Field(default="all", description="Specific dataset filename (e.g. 'phishing_email.csv') or 'all'")
    max_per_ds: Optional[int] = Field(default=8000, description="Max samples per dataset to ingest")

@router.get("/status")
def get_model_status():
    """Returns the current trained model metadata, accuracy, F1, confusion matrix, and feature stats."""
    status = PhishingModelTrainer.get_status()
    return status

@router.get("/datasets")
def list_available_datasets():
    """Lists all CSV datasets stored in backend/data/datasets with metadata."""
    datasets = PhishingModelTrainer.list_datasets()
    return {
        "datasets": datasets,
        "total_count": len(datasets),
        "primary_recommendation": "all"
    }

@router.post("/predict")
def predict_text(req: PredictRequest):
    """Executes live NLP inference on raw text content."""
    if not req.text or not req.text.strip():
        raise HTTPException(status_code=400, detail="Empty text input provided")
    
    result = predictor.predict(req.text)
    return result

@router.post("/train")
def train_model(req: TrainRequest):
    """
    Triggers model training across all uploaded datasets or a specific dataset.
    Reloads in-memory predictor upon completion.
    """
    try:
        metrics = PhishingModelTrainer.train(
            dataset_name=req.dataset,
            max_samples_per_dataset=req.max_per_ds or 8000
        )
        # Reload live predictor
        predictor.reload()
        return {
            "success": True,
            "message": f"Model successfully retrained on {metrics.get('trained_source', 'datasets')}",
            "metrics": metrics
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Training failed: {str(e)}")
