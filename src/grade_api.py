"""Grade-system API client.

Wraps fdjwgl's grade endpoints behind one object that is transport-
agnostic: pass it a :class:`src.webvpn.WebVPNSession` for off-campus runs
or a :class:`src.direct_session.DirectSession` on the campus network —
both expose the same ``get``/``post`` surface.

Endpoints (all under fdjwgl.fudan.edu.cn):

* ``info/{id}``              — every semester's grades, credits included
* ``grade-statistic/{id}``   — GPA + credit + course counts (total + per-term)
* ``get-not-retake-grade/{id}`` — grade IDs that are not retakes
* ``my-gpa/search``          — ranking (department needs no extra config;
  major needs ``MAJOR_ASSOC``)
"""

import re

from src import config


class GradeClient:
    """Read-only client over fdjwgl's grade APIs."""

    def __init__(self, session):
        # session is a WebVPNSession or DirectSession (duck-typed: get/post).
        self.session = session
        self.base = config.GRADE_BASE

    # ── discovery ─────────────────────────────────────────────────────────

    def discover_grade_sheet_id(self) -> str:
        """Hit the grade-sheet landing URL and read the per-student id.

        fdjwgl redirects ``/grade/sheet/`` to ``/grade/sheet/semester-index/{id}``;
        the id is the same one the info/statistic endpoints key on.
        """
        resp = self.session.get(config.GRADE_HOME_URL, timeout=30)
        for source in (resp.url, resp.text or ""):
            match = re.search(r"semester-index/(\d+)", source)
            if match:
                return match.group(1)
        # Fall back to the alternate path shape some deployments use.
        match = re.search(r"grade/sheet/info/(\d+)", resp.text or "")
        if match:
            return match.group(1)
        raise RuntimeError(
            f"Could not detect grade sheet id (final URL: {resp.url[:120]})"
        )

    # ── grade data ────────────────────────────────────────────────────────

    def get_all_grades(self, grade_sheet_id: str) -> dict:
        """Return every semester's grades with credits and GP already set.

        Shape::

            {
              "semesterId2studentGrades": {"<semId>": [ {courseCode, courseName,
                gaGrade, gp, credits, ...}, ... ]},
              "semesters": [...],
              "id2semesters": {...},
            }
        """
        resp = self.session.get(
            f"{self.base}/student/for-std/grade/sheet/info/{grade_sheet_id}",
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    def get_grade_statistic(self, grade_sheet_id: str) -> dict:
        """Return official GPA / credit / course counts.

        Shape::

            {
              "totalStatistic": {"gpa": "3.89", "credits": "83.5", "count": 33},
              "id2Statistic":   {"<semId>": {"gpa": ..., "credits": ..., "count": ...}},
            }

        No more manual GPA arithmetic — the server already excludes P/NP
        and retakes the way the registrar does.
        """
        resp = self.session.get(
            f"{self.base}/student/for-std/grade/sheet/grade-statistic/{grade_sheet_id}",
            params={"semester": ""},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    def get_not_retake_ids(self, grade_sheet_id: str) -> list[int]:
        """Return the set of grade-row ids that are not retakes.

        Useful for filtering retake duplicates out of ``info`` if you ever
        need to compute something the statistic endpoint doesn't cover.
        """
        resp = self.session.get(
            f"{self.base}/student/for-std/grade/sheet/get-not-retake-grade/{grade_sheet_id}",
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json().get("notRetakeGradeIds", [])

    def get_ranking(
        self, grade_sheet_id: str, scope: str = "department",
        student_code: str = None,
    ) -> dict:
        """Return department or major ranking — zero config either way.

        Both scopes are derived from the single ``my-gpa/search`` call the
        server answers with just ``studentAssoc``: the response is the full
        department cohort (every peer's row, masked except your own), and
        each row carries a ``major`` field.  Major ranking is just the
        department cohort filtered to your major and re-ranked by GPA — so
        no internal ``majorAssoc`` id is ever needed.

        ``scope='department'`` returns the full cohort; ``scope='major'``
        returns the same shape narrowed to your major.

        Returns::

            {
              "scope": "department"|"major",
              "total": <int>,        # students in scope
              "my_rank": <int>|None, # this student's rank (ties share a rank)
              "my_gpa": <float>|None,
              "my_credits": <float>|None,
              "rows": [ {code, name, major, department, gpa, credit, ranking}, ... ],
            }
        """
        if scope not in ("department", "major"):
            raise ValueError(f"unknown scope: {scope!r}")

        resp = self.session.get(
            f"{self.base}/student/for-std/grade/my-gpa/search",
            params={"studentAssoc": grade_sheet_id},
            timeout=60,
        )
        resp.raise_for_status()
        data = resp.json()

        rows = data.get("data", []) or []
        student_code = student_code or config.STUDENT_ID
        mine = next((r for r in rows if r.get("code") == student_code), None)

        if scope == "major":
            if mine is None:
                raise RuntimeError(
                    "Can't derive major ranking: own row not found in cohort."
                )
            my_major = mine.get("major")
            rows = [r for r in rows if r.get("major") == my_major]
            # Re-rank within the major cohort (server's `ranking` field was
            # computed department-wide; recompute so ties share a rank).
            _rerank_by_gpa(rows)

        total = len(rows)
        mine = next((r for r in rows if r.get("code") == student_code), mine)
        return {
            "scope": scope,
            "total": total,
            "my_rank": (mine or {}).get("ranking"),
            "my_gpa": (mine or {}).get("gpa"),
            "my_credits": (mine or {}).get("credit"),
            "rows": rows,
        }


def _rerank_by_gpa(rows: list[dict]) -> None:
    """Assign ``ranking`` in-place by descending GPA, ties sharing a rank.

    Mirrors the registrar's "dense share" convention: students with equal
    GPA get the same rank, and the next distinct GPA jumps by the cohort
    size in between (1,1,1,4,...) — matching what the official major-scoped
    endpoint returns.
    """
    ordered = sorted(rows, key=lambda r: r.get("gpa") or 0, reverse=True)
    rank = 0
    prev_gpa = None
    seen = 0
    for row in ordered:
        seen += 1
        gpa = row.get("gpa")
        if gpa != prev_gpa:
            rank = seen
            prev_gpa = gpa
        row["ranking"] = rank
