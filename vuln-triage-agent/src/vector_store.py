"""
CVE Vector Store
Embeds CVE descriptions into a local Chroma vector database, enabling
retrieval-augmented generation (RAG): when triaging a new vulnerability,
the agent can retrieve similar historical CVEs for context (e.g.,
"has a CVE like this been exploited in the wild before?").

By default, Chroma downloads the all-MiniLM-L6-v2 sentence-transformer
model on first use for embeddings (recommended for production - much
higher retrieval quality). If you're in an offline/restricted environment
or want zero external downloads, this module falls back to a TF-IDF based
embedding function (USE_LOCAL_EMBEDDINGS=True below).
"""

import json
import pickle
import chromadb
from chromadb import EmbeddingFunction, Documents, Embeddings
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np

DATA_DIR = Path(__file__).parent.parent / "data"
CHROMA_DIR = DATA_DIR / "chroma_db"
VECTORIZER_PATH = DATA_DIR / "tfidf_vectorizer.pkl"
COLLECTION_NAME = "cve_knowledge_base"

# Set to False to use Chroma's default sentence-transformer embeddings
# (requires internet access on first run to download the model).
USE_LOCAL_EMBEDDINGS = True


class TfidfEmbeddingFunction(EmbeddingFunction):
    """
    Lightweight offline embedding function using TF-IDF + SVD for
    dimensionality reduction. Good enough for small CVE collections
    and demo purposes. For production, swap to sentence-transformers
    or an API-based embedding model (e.g., OpenAI/Voyage embeddings).
    """

    def __init__(self, max_features: int = 512):
        self.vectorizer = TfidfVectorizer(max_features=max_features, stop_words="english")
        self._fitted = False

    def __call__(self, input: Documents) -> Embeddings:
        if not self._fitted:
            matrix = self.vectorizer.fit_transform(input)
            self._fitted = True
            self._save()
        else:
            matrix = self.vectorizer.transform(input)
        dense = matrix.toarray().astype(np.float32)
        width = len(self.vectorizer.get_feature_names_out()) or 1
        if dense.shape[1] < width:
            pad = np.zeros((dense.shape[0], width - dense.shape[1]), dtype=np.float32)
            dense = np.hstack([dense, pad])
        return dense.tolist()

    def _save(self):
        with open(VECTORIZER_PATH, "wb") as f:
            pickle.dump(self.vectorizer, f)

    def load_if_exists(self):
        if VECTORIZER_PATH.exists():
            with open(VECTORIZER_PATH, "rb") as f:
                self.vectorizer = pickle.load(f)
                self._fitted = True
        return self


def load_cves(filename: str = "cves_raw.json") -> list[dict]:
    path = DATA_DIR / filename
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found. Run ingest_cves.py first to fetch CVE data."
        )
    with open(path) as f:
        return json.load(f)


def get_embedding_function():
    if USE_LOCAL_EMBEDDINGS:
        return TfidfEmbeddingFunction()
    return None  # Chroma will use its default (sentence-transformers)


def build_vector_store(cves: list[dict]):
    """
    Build (or rebuild) the Chroma collection from a list of CVE dicts.
    Each CVE's description is embedded; metadata (id, severity, score)
    is stored alongside for filtering and display.
    """
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))

    # Drop existing collection for a clean rebuild
    try:
        client.delete_collection(COLLECTION_NAME)
    except Exception:
        pass

    embed_fn = get_embedding_function()
    if embed_fn:
        collection = client.create_collection(name=COLLECTION_NAME, embedding_function=embed_fn)
    else:
        collection = client.create_collection(name=COLLECTION_NAME)

    ids, documents, metadatas = [], [], []
    for cve in cves:
        if not cve.get("description"):
            continue
        ids.append(cve["cve_id"])
        documents.append(cve["description"])
        metadatas.append({
            "cve_id": cve["cve_id"],
            "severity": cve.get("severity") or "UNKNOWN",
            "cvss_score": cve.get("cvss_score") or 0.0,
            "published": cve.get("published") or "",
        })

    if not documents:
        print("No CVE descriptions found to embed.")
        return collection

    collection.add(ids=ids, documents=documents, metadatas=metadatas)
    print(f"Embedded {len(documents)} CVEs into vector store at {CHROMA_DIR}")
    return collection


def query_similar_cves(query_text: str, top_k: int = 3) -> list[dict]:
    """
    Retrieve the top_k most similar CVEs to a given query/description.
    Used by the triage agent to pull relevant historical context.
    """
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    embed_fn = get_embedding_function()
    if embed_fn and hasattr(embed_fn, "load_if_exists"):
        embed_fn.load_if_exists()
    if embed_fn:
        collection = client.get_collection(COLLECTION_NAME, embedding_function=embed_fn)
    else:
        collection = client.get_collection(COLLECTION_NAME)

    results = collection.query(query_texts=[query_text], n_results=top_k)

    similar = []
    for i in range(len(results["ids"][0])):
        similar.append({
            "cve_id": results["ids"][0][i],
            "description": results["documents"][0][i],
            "metadata": results["metadatas"][0][i],
            "distance": results["distances"][0][i],
        })
    return similar


if __name__ == "__main__":
    cves = load_cves()
    build_vector_store(cves)

    # Quick smoke test: query with a sample description
    if cves:
        sample_query = cves[0]["description"]
        print(f"\nTest query (using first CVE's description):")
        print(f"  {sample_query[:100]}...")
        results = query_similar_cves(sample_query, top_k=3)
        print("\nTop similar CVEs:")
        for r in results:
            print(f"  {r['cve_id']} (severity={r['metadata']['severity']}, "
                  f"distance={r['distance']:.4f})")
