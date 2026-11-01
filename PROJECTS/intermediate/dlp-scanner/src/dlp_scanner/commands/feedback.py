"""
©AngelaMos | 2026
commands/feedback.py

    dlp-scan feedback <finding_id> --report results.json --false-positive
    dlp-scan feedback <finding_id> --report results.json --true-positive
    dlp-scan feedback --stats
    dlp-scan feedback --retrain

The finding is looked up in a JSON scan report (finding_ids are stable
there), its features are extracted and stored, and the model is updated.
"""


from pathlib import Path
from typing import Annotated

import orjson
import typer


def feedback(
    finding_id: Annotated[
        str | None,
        typer.Argument(help = "Finding ID (or unique prefix) from a JSON report"),
    ] = None,
    true_positive: Annotated[
        bool,
        typer.Option("--true-positive", "-t", help = "Mark as a real finding"),
    ] = False,
    false_positive: Annotated[
        bool,
        typer.Option("--false-positive", "-F", help = "Mark as a false positive"),
    ] = False,
    report: Annotated[
        str,
        typer.Option("--report", "-r", help = "JSON scan report containing the finding"),
    ] = "",
    db: Annotated[
        str,
        typer.Option("--db", "-d", help = "Feedback database path"),
    ] = "",
    stats: Annotated[
        bool,
        typer.Option("--stats", help = "Show feedback and model statistics"),
    ] = False,
    retrain: Annotated[
        bool,
        typer.Option("--retrain", help = "Force a full model retrain"),
    ] = False,
) -> None:
    """
    Record analyst feedback to train the false-positive classifier.
    """
    from dlp_scanner.commands.report import _rebuild_result
    from dlp_scanner.constants import FP_SUPPRESS_THRESHOLD
    from dlp_scanner.ml.features import cooccurrence_counts
    from dlp_scanner.ml.feedback import (
        FeedbackManager,
        default_feedback_db_path,
    )
    from dlp_scanner.ml.store import FeedbackStore

    db_path = Path(db) if db else default_feedback_db_path()

    if stats or retrain:
        with FeedbackStore(db_path) as store:
            manager = FeedbackManager(store)
            if retrain:
                ok, detail = manager.retrain()
                typer.echo(("Retrained: " if ok else "Not retrained: ") + detail)
                raise typer.Exit(code = 0 if ok else 1)

            counts = store.counts()
            model = manager.load_model()
            typer.echo(f"Database        : {db_path}")
            typer.echo(f"True positives  : {counts['true_positive']}")
            typer.echo(f"False positives : {counts['false_positive']}")
            typer.echo(
                "Model           : "
                + (f"trained ({model.n_seen} examples)" if model else "not trained yet")
            )
            rep = manager.evaluate(FP_SUPPRESS_THRESHOLD)
            if rep.note:
                typer.echo(f"Holdout         : {rep.note}")
            else:
                typer.echo(
                    f"Holdout (n={rep.test_size}): "
                    f"{rep.fp_reduction:.0%} of false positives demoted, "
                    f"{rep.tp_recall:.0%} of true positives kept"
                )
        return

    if not finding_id or not report:
        typer.echo("Provide FINDING_ID and --report (or use --stats).", err = True)
        raise typer.Exit(code = 1)
    if true_positive == false_positive:
        typer.echo("Choose exactly one of --true-positive / --false-positive.", err = True)
        raise typer.Exit(code = 1)

    report_path = Path(report)
    if not report_path.exists():
        typer.echo(f"File not found: {report}", err = True)
        raise typer.Exit(code = 1)

    result = _rebuild_result(orjson.loads(report_path.read_bytes()))
    matches = [f for f in result.findings if f.finding_id.startswith(finding_id)]
    if len(matches) != 1:
        typer.echo(
            f"{'No' if not matches else 'Ambiguous'} finding matches '{finding_id}'",
            err = True,
        )
        raise typer.Exit(code = 1)

    finding = matches[0]
    cooc = cooccurrence_counts(result.findings)[finding.finding_id]

    with FeedbackStore(db_path) as store:
        outcome = FeedbackManager(store).submit(
            finding,
            is_false_positive = false_positive,
            cooccurrence = cooc,
        )

    label = "false positive" if false_positive else "true positive"
    typer.echo(
        f"Recorded {finding.finding_id} ({finding.rule_id}) as {label}. "
        f"Labels: {outcome.total} "
        f"(TP {outcome.true_positives} / FP {outcome.false_positives}). "
        f"{outcome.action}{': ' + outcome.detail if outcome.detail else ''}"
    )