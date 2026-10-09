"""Bounded retrieval math. No weights, downloads, hidden indexes or shared state."""
import math
from collections import Counter


def bm25(documents, query_terms, *, k1=1.2, b=0.75):
    """BM25 over caller-authorized token lists, returning aligned scores."""
    if not documents:
        return []
    counts = [Counter(tokens) for tokens in documents]
    lengths = [sum(row.values()) for row in counts]
    average = sum(lengths) / len(lengths) or 1
    scores = [0.0] * len(counts)
    for term in set(query_terms):
        frequency = sum(term in row for row in counts)
        weight = math.log(1 + (len(counts) - frequency + 0.5) / (frequency + 0.5))
        for index, row in enumerate(counts):
            tf = row[term]
            if tf:
                scores[index] += weight * tf * (k1 + 1) / (tf + k1 * (1 - b + b * lengths[index] / average))
    return scores


def normalized(vector):
    if (not isinstance(vector, list) or not 1 <= len(vector) <= 4096
            or any(type(v) not in (int, float) or not math.isfinite(v) for v in vector)):
        raise ValueError("Invalid finite dense vector")
    norm = math.hypot(*vector)
    if not math.isfinite(norm) or norm == 0:
        raise ValueError("Invalid dense vector norm")
    return [v / norm for v in vector]


def dense_rank(query, documents, *, coarse_dimension=None, reviewed_dimensions=(), candidates=100):
    """Exact coarse MRL shortlist followed by full-native-width cosine reranking.

    A bounded index needs no ANN dependency. Truncation is permitted only for a
    dimension explicitly reviewed as trained into the selected embedding model.
    """
    query = normalized(query)
    if not isinstance(documents, list) or len(documents) > 384 or type(candidates) is not int or not 1 <= candidates <= 384:
        raise ValueError("Dense candidate limits exceeded")
    rows = [normalized(row) for row in documents]
    if any(len(row) != len(query) for row in rows):
        raise ValueError("Dense model dimensions differ")
    indices = list(range(len(rows)))
    if coarse_dimension is not None:
        if (type(coarse_dimension) is not int or coarse_dimension not in reviewed_dimensions
                or not 1 <= coarse_dimension <= len(query)):
            raise ValueError("Coarse dimensions require a reviewed MRL-trained model")
        coarse_query = normalized(query[:coarse_dimension])
        coarse_rows = [normalized(row[:coarse_dimension]) for row in rows]
        indices.sort(key=lambda i: (-sum(a * b for a, b in zip(coarse_query, coarse_rows[i])), i))
        indices = indices[:candidates]
    scored = [(i, sum(a * b for a, b in zip(query, rows[i]))) for i in indices]
    return sorted(scored, key=lambda item: (-item[1], item[0]))


def late_interaction(query_tokens, document_tokens):
    """Actual normalized MaxSim for already-produced ColBERT token embeddings.

    The caller must supply embeddings from the same pinned model. This function
    never claims lexical counts are ColBERT and never loads an encoder.
    """
    if not 1 <= len(query_tokens) <= 128 or not 1 <= len(document_tokens) <= 512:
        raise ValueError("Late interaction token limits exceeded")
    query = [normalized(row) for row in query_tokens]
    document = [normalized(row) for row in document_tokens]
    width = len(query[0])
    if any(len(row) != width for row in query + document):
        raise ValueError("Late interaction model dimensions differ")
    return sum(max(sum(a * b for a, b in zip(q, d)) for d in document) for q in query)
