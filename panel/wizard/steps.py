"""Wizard state-machine labels + transitions.

Phase 3 implements steps 1 (countries) and 2 (ports); the labels below include
the future steps (apply, xui_detect, xui_creds, template, clone, done) so that
the persistence schema and the state-transition table are stable across the
Phase 4 / Phase 5 work. Unknown future step labels should be appended BEFORE
``done`` and ``STEPS`` should remain ordered.

The wizard row lives at ``Wizard(id=1)`` — a singleton. ``current_step`` is the
label of the next step the user must still complete; reaching ``done`` flips
``Settings.wizard_completed`` to true and re-runs of the panel present the
management dashboard instead of the wizard.
"""

from __future__ import annotations

from enum import Enum


class WizardStep(str, Enum):
    """Ordered wizard step labels.

    Values are stored in :class:`panel.models.Wizard.current_step`.
    """

    COUNTRIES = "countries"
    PORTS = "ports"
    APPLY = "apply"
    XUI_DETECT = "xui_detect"
    XUI_CREDS = "xui_creds"
    TEMPLATE = "template"
    CLONE = "clone"
    DONE = "done"


# Ordered tuple mirrors ROADMAP §8 mermaid: countries → ports → apply →
# xui_detect → xui_creds → template → clone → done.
STEPS: tuple[WizardStep, ...] = (
    WizardStep.COUNTRIES,
    WizardStep.PORTS,
    WizardStep.APPLY,
    WizardStep.XUI_DETECT,
    WizardStep.XUI_CREDS,
    WizardStep.TEMPLATE,
    WizardStep.CLONE,
    WizardStep.DONE,
)


def normalize_step(value: str | WizardStep) -> WizardStep:
    """Coerce a raw string or :class:`WizardStep` to the enum variant.

    Raises ``ValueError`` if the value does not match a known step label.
    """
    if isinstance(value, WizardStep):
        return value
    try:
        return WizardStep(value)
    except ValueError as exc:
        raise ValueError(f"unknown wizard step: {value!r}") from exc


def step_index(step: WizardStep) -> int:
    """Position of *step* in :data:`STEPS` (0-based)."""
    return STEPS.index(step)


def is_terminal(step: WizardStep) -> bool:
    return step == WizardStep.DONE


def next_step(step: WizardStep) -> WizardStep:
    """Return the step that follows *step* in the ordered list.

    Raises ``ValueError`` if *step* is already terminal (``DONE``).
    """
    if is_terminal(step):
        raise ValueError("no next step — terminal state reached")
    return STEPS[step_index(step) + 1]


def can_advance_from(current: WizardStep, target: WizardStep) -> bool:
    """True iff *target* is reachable from *current* in one forward jump.

    The wizard only allows forward progression (a step may be skipped by
    jumping over it, but we reject backward jumps to keep step_data coherent —
    the dashboard's "re-apply" endpoints live outside the wizard and reset
    progress explicitly when needed).
    """
    return step_index(target) > step_index(current)


def reachable_from(current: WizardStep) -> tuple[WizardStep, ...]:
    """Return every step in :data:`STEPS` strictly after *current*."""
    return STEPS[step_index(current) + 1 :]
