from typing import Callable, List, Tuple

from .constants import CONFIG_KEYS
from .i18n import translate_text
from .models import CanonicalConfig, Paths
from .runtime_binding import describe_binding_status
from .system import SystemAdapter
from .system_features import (
    collect_conntrack_status,
    collect_rp_filter_status,
    describe_conntrack_runtime,
    describe_rp_filter_runtime,
    describe_rp_filter_source,
)

def build_runtime_integration_lines(
    paths: Paths,
    config: CanonicalConfig,
    adapter: SystemAdapter,
    *,
    translate=None,
    template: Callable[[str, str], str] = None,
) -> List[str]:
    external = describe_binding_status("external", config["EXTERNAL_IFS"])
    listen = describe_binding_status("listen", config["LISTEN_IPS"])
    runtime_lines = [
        translate_text(
            translate,
            "config.show.runtime.external_status",
            "External interface binding status: {status}",
            status=translate_text(template, external.message_key, external.message_default),
        ),
        translate_text(
            translate,
            "config.show.runtime.listen_status",
            "Exposure address binding status: {status}",
            status=translate_text(template, listen.message_key, listen.message_default),
        ),
    ]
    if external.note_key:
        runtime_lines.append(
            translate_text(
                translate,
                "config.show.runtime.external_note",
                "External interface binding note: {note}",
                note=translate_text(template, external.note_key, external.note_default),
            )
        )
    if listen.note_key:
        runtime_lines.append(
            translate_text(
                translate,
                "config.show.runtime.listen_note",
                "Exposure address binding note: {note}",
                note=translate_text(template, listen.note_key, listen.note_default),
            )
        )

    rpfilter_report = collect_rp_filter_status(paths, config, adapter)
    runtime_lines.extend(
        [
            translate_text(
                translate,
                "config.show.runtime.rpfilter_source",
                "rp_filter source: {source}",
                source=describe_rp_filter_source(rpfilter_report, translate=template),
            ),
            translate_text(
                translate,
                "config.show.runtime.rpfilter_status",
                "rp_filter runtime status: {status}",
                status=describe_rp_filter_runtime(rpfilter_report, translate=template),
            ),
        ]
    )

    conntrack_report = collect_conntrack_status(paths, config, adapter)
    runtime_lines.append(
        translate_text(
            translate,
            "config.show.runtime.conntrack_status",
            "Conntrack runtime status: {status}",
            status=describe_conntrack_runtime(conntrack_report, translate=template),
        )
    )
    return runtime_lines


def build_config_show_sections(
    paths: Paths,
    config: CanonicalConfig,
    adapter: SystemAdapter,
    *,
    translate=None,
    template: Callable[[str, str], str] = None,
) -> List[Tuple[str, List[str]]]:
    value_lines = [f"{key}: {config.get(key, '')}" for key in CONFIG_KEYS]
    runtime_lines = build_runtime_integration_lines(
        paths,
        config,
        adapter,
        translate=translate,
        template=template,
    )

    return [
        (
            translate_text(translate, "config.show.sections.values", "Canonical Values"),
            value_lines,
        ),
        (
            translate_text(translate, "config.show.sections.runtime", "Runtime and Integration"),
            runtime_lines,
        ),
    ]
