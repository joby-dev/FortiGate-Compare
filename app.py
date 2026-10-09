"""Streamlit dashboard for comparing two FortiGate configuration files."""

from __future__ import annotations

import difflib
import hashlib
import html
import uuid

import pandas as pd
import streamlit as st

from comparer import ComparisonResult, compare_policies
from parser import (
    ConfigParseError,
    ParseResult,
    POLICY_FIELDS,
    parse_firewall_config_safe,
)
from report import display_value
from ha_consistency import (
    HAChange,
    HAComparison,
    POLICY_MATCH_MODES,
    compare_ha_configurations,
    render_ha_object_html,
)
from raw_diff import (
    DiffHunk,
    ObjectSpan,
    RawDiffResult,
    SECTION_FILTERS,
    build_raw_html_report,
    build_unified_diff,
    compare_raw_configurations,
    render_side_by_side_document,
)
from session_analyzer import (
    SessionAnalysis,
    analyze_sessions,
    build_session_excel_report,
    format_traffic,
)


st.set_page_config(
    page_title="Firewall Configuration Compare",
    page_icon="↔",
    layout="wide",
    initial_sidebar_state="collapsed",
)


def _render_compare_theme() -> None:
    st.markdown(
        """
        <style>
        :root {
            color-scheme: light;
            --compare-bg: #EAF6FF;
            --compare-panel: #FFFFFF;
            --compare-header: #D6EEFF;
            --compare-border: #B8DFF5;
            --compare-text: #20252a;
            --compare-muted: #5f6972;
            --compare-accent: #1769aa;
        }
        html, body, [data-testid="stAppViewContainer"], .stApp {
            background: var(--compare-bg);
            color: var(--compare-text);
            font-family: "Segoe UI", sans-serif;
        }
        [data-testid="stAppViewContainer"] {
            background: var(--compare-bg);
        }
        [data-testid="stHeader"] { background: var(--compare-bg); }
        [data-testid="stMain"] .block-container {
            max-width: none;
            min-width: 0;
            padding: 4rem 1.25rem 1.5rem;
        }
        [data-testid="stSidebar"] {
            background: var(--compare-panel);
            border-right: 1px solid var(--compare-border);
            flex-shrink: 0;
        }
        [data-testid="stMain"] { flex: 1 1 0; min-width: 0; }
        [data-testid="stSidebar"] > div:first-child { background: transparent; }
        h1, h2, h3, p, label, [data-testid="stMarkdownContainer"] { color: var(--compare-text); }
        [data-testid="stCaptionContainer"], small { color: var(--compare-muted); }
        [data-testid="stMetric"] { background: var(--compare-panel); border: 1px solid var(--compare-border); border-radius: 4px; padding: 12px 16px; }
        [data-testid="stMetricLabel"] { color: var(--compare-muted); font-size: .75rem; }
        [data-testid="stMetricValue"] { color: var(--compare-text); font-family: Consolas, monospace; }
        [data-testid="stTextInput"] input, [data-testid="stSelectbox"] [role="combobox"],
        [data-testid="stFileUploader"] section {
            background: var(--compare-panel);
            color: var(--compare-text);
            border-color: var(--compare-border);
        }
        [data-testid="stFileUploader"] section { border-radius: 4px; }
        [data-testid="stButton"] button { color: var(--compare-text); background: var(--compare-panel); border: 1px solid var(--compare-border); border-radius: 4px; }
        [data-testid="stButton"] button:hover { border-color: var(--compare-accent); color: var(--compare-accent); }
        [data-testid="stRadio"] [role="radiogroup"] { gap: .55rem; }
        [data-testid="stRadio"] [role="radiogroup"] label {
            background: var(--compare-panel);
            border: 1px solid var(--compare-border);
            border-radius: 4px;
            padding: .35rem .75rem;
        }
        [data-testid="stRadio"] [role="radiogroup"] label:has(input:checked) {
            border-color: var(--compare-accent);
            box-shadow: 0 0 0 1px rgba(23,105,170,.14);
        }
        [data-testid="stDataFrame"] { border: 1px solid var(--compare-border); border-radius: 4px; }
        .compare-title { margin: 0 0 1rem; padding: .8rem 1rem; background: var(--compare-header); border: 1px solid var(--compare-border); font: 600 22px/1.3 "Segoe UI", sans-serif; }
        .object-heading { margin: .4rem 0 .8rem; padding: .7rem 1rem; background: var(--compare-panel); border: 1px solid var(--compare-border); color: var(--compare-text); }
        @media (max-width: 900px) {
            [data-testid="stMain"] .block-container { padding: 4rem 1rem 2rem; }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _render_compare_header() -> None:
    st.markdown(
        """
        <div class="compare-title">Firewall Configuration Compare</div>
        """,
        unsafe_allow_html=True,
    )


def _parse_upload(
    file_bytes: bytes, filename: str
) -> ParseResult:
    try:
        config_text = file_bytes.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ConfigParseError(
            f"{filename} could not be decoded as a UTF-8 text configuration."
        ) from error
    return parse_firewall_config_safe(config_text)


def _object_navigation_target(
    raw_result: RawDiffResult,
    category: str,
    before_id: str,
    after_id: str,
    label: str,
    status: str,
) -> dict[str, object]:
    def find_span(spans: list[ObjectSpan], object_id: str) -> ObjectSpan | None:
        if not object_id:
            return None
        return next(
            (
                span
                for span in spans
                if span.category == category and span.object_id == object_id
            ),
            None,
        )

    before_span = find_span(raw_result.before_spans, before_id)
    after_span = find_span(raw_result.after_spans, after_id)

    def serialize(span: ObjectSpan | None) -> dict[str, object] | None:
        if span is None:
            return None
        return {
            "start": span.start,
            "end": span.end,
            "object_id": span.object_id,
            "name": span.name,
            "start_line": span.start + 1,
            "end_line": span.end + 1,
        }

    return {
        "token": uuid.uuid4().hex,
        "category": category,
        "label": label,
        "status": status,
        "before_id": before_id,
        "after_id": after_id,
        "before_line": before_span.start + 1 if before_span else None,
        "after_line": after_span.start + 1 if after_span else None,
        "before": serialize(before_span),
        "after": serialize(after_span),
    }


def _render_navigation_context(target: dict[str, object] | None) -> None:
    if not target:
        return
    before_span = target.get("before")
    after_span = target.get("after")
    before_line = before_span.get("start_line") if isinstance(before_span, dict) else "Policy Missing"
    after_line = after_span.get("start_line") if isinstance(after_span, dict) else "Policy Missing"
    heading = (
        "Selected Policy"
        if target.get("category") in {"Firewall Policies", "Proxy Policies", "Local-In Policies"}
        else "Selected Object"
    )
    st.markdown(
        f"<div class='object-heading'><strong>{heading}:</strong> "
        f"{html.escape(str(target.get('before_id') or target.get('after_id') or ''))} - "
        f"{html.escape(str(target.get('label') or ''))}<br>"
        f"<strong>Firewall A:</strong> Line {html.escape(str(before_line))}<br>"
        f"<strong>Firewall B:</strong> Line {html.escape(str(after_line))}<br>"
        f"<strong>Status:</strong> {html.escape(str(target.get('status') or ''))}</div>",
        unsafe_allow_html=True,
    )


def _render_fullscreen_comparison(
    before_bytes: bytes,
    after_bytes: bytes,
    before_name: str,
    after_name: str,
    comparison_mode: str,
    policy_match_mode: str,
    ignore_categories: set[str],
    fingerprint: str,
) -> None:
    is_ha = comparison_mode == "HA Firewall A vs Firewall B Comparison"
    ha_result: HAComparison | None = None
    if is_ha:
        ha_result_key = f"fullscreen_ha_result_{fingerprint}_{policy_match_mode}"
        if ha_result_key not in st.session_state:
            try:
                before_text = before_bytes.decode("utf-8-sig")
                after_text = after_bytes.decode("utf-8-sig")
            except UnicodeDecodeError as error:
                st.error(f"A configuration could not be decoded as UTF-8 text: {error}")
                return
            with st.spinner("Validating HA policy consistency..."):
                st.session_state[ha_result_key] = compare_ha_configurations(
                    before_text,
                    after_text,
                    before_name,
                    after_name,
                    policy_match_mode=policy_match_mode,
                )
        ha_result = st.session_state[ha_result_key]

    result_key = f"fullscreen_raw_result_{fingerprint}"
    if result_key not in st.session_state:
        try:
            before_text = before_bytes.decode("utf-8-sig")
            after_text = after_bytes.decode("utf-8-sig")
        except UnicodeDecodeError as error:
            st.error(f"A configuration could not be decoded as UTF-8 text: {error}")
            return
        with st.spinner("Comparing complete configurations..."):
            st.session_state[result_key] = compare_raw_configurations(
                before_text,
                after_text,
                before_name,
                after_name,
                ignore_categories=ignore_categories,
            )
        del before_text, after_text

    result: RawDiffResult = st.session_state[result_key]
    if ha_result is not None:
        _render_ha_dashboard(ha_result, result, fingerprint)
    jump_key = f"fullscreen_object_jump_{fingerprint}"
    navigation_target = st.session_state.get(jump_key)
    all_rows = result.full_rows
    difference_rows = [
        (row_index, row)
        for row_index, row in enumerate(all_rows)
        if row.kind in {"Added", "Removed", "Modified"}
    ]
    difference_blocks = [
        opcode
        for opcode in difflib.SequenceMatcher(
            None, result.before_lines, result.after_lines, autojunk=True
        ).get_opcodes()
        if opcode[0] != "equal"
    ]
    counts = {
        kind: sum(row.kind == kind for _, row in difference_rows)
        for kind in ("Added", "Removed", "Modified")
    }

    summary = st.columns(4)
    for column, label, value in zip(
        summary,
        ("Difference Blocks", "Added Lines", "Removed Lines", "Modified Lines"),
        (
            len(difference_blocks),
            counts["Added"],
            counts["Removed"],
            counts["Modified"],
        ),
    ):
        column.metric(label, f"{value:,}")

    if not difference_blocks and not navigation_target:
        st.info("The configurations are identical.")
        return

    combined_hunk = DiffHunk(
        "Full Configuration",
        {category for hunk in result.hunks for category in hunk.categories},
        {object_key for hunk in result.hunks for object_key in hunk.objects},
        all_rows,
    )
    before_label, after_label = (
        ("Firewall A", "Firewall B")
        if is_ha
        else ("Pre-Change", "Post-Change")
    )
    _render_navigation_context(navigation_target)
    st.components.v1.html(
        render_side_by_side_document(
            combined_hunk,
            before_name,
            after_name,
            max_rows=len(all_rows),
            before_label=before_label,
            after_label=after_label,
            source_before_lines=result.before_lines,
            source_after_lines=result.after_lines,
            storage_key=f"fortigate-diff-{fingerprint}",
            navigation_target=navigation_target,
            navigation_before_line=(
                navigation_target.get("before_line") if navigation_target else None
            ),
            navigation_after_line=(
                navigation_target.get("after_line") if navigation_target else None
            ),
        ),
        height=780,
        scrolling=False,
    )

    export_columns = st.columns(2)
    html_key = f"fullscreen_html_export_{fingerprint}"
    txt_key = f"fullscreen_txt_export_{fingerprint}"
    if export_columns[0].button("Export HTML", key=f"fullscreen_export_html_{fingerprint}"):
        with st.spinner("Building HTML export..."):
            st.session_state[html_key] = build_raw_html_report(result)
    if export_columns[1].button("Export TXT", key=f"fullscreen_export_txt_{fingerprint}"):
        with st.spinner("Building text export..."):
            st.session_state[txt_key] = build_unified_diff(result).encode("utf-8")
    downloads = st.columns(2)
    if html_key in st.session_state:
        downloads[0].download_button(
            "Download HTML", st.session_state[html_key],
            file_name="firewall_configuration_diff.html", mime="text/html",
            key=f"fullscreen_download_html_{fingerprint}",
        )
    if txt_key in st.session_state:
        downloads[1].download_button(
            "Download TXT", st.session_state[txt_key],
            file_name="firewall_configuration_diff.txt", mime="text/plain",
            key=f"fullscreen_download_txt_{fingerprint}",
        )


def _render_dashboard(result: ComparisonResult, fingerprint: str) -> None:
    matching_count = len(result.unchanged)
    modified_count = len(result.modified_policy_keys)
    missing_count = len(result.added) + len(result.removed)
    st.subheader("Summary Statistics")
    summary_columns = st.columns(3)
    for column, label, value in zip(
        summary_columns,
        ("Matching Objects", "Modified Objects", "Missing Objects"),
        (matching_count, modified_count, missing_count),
    ):
        column.metric(label, f"{value:,}")

    comparisons: list[tuple[str, str, str, dict[str, object] | None, dict[str, object] | None]] = []
    for key, policy in result.added.items():
        comparisons.append(
            (
                result.policy_type(key, policy),
                result.policy_id(key, policy),
                "Missing in Pre-Change",
                None,
                policy,
            )
        )
    for key, policy in result.removed.items():
        comparisons.append(
            (
                result.policy_type(key, policy),
                result.policy_id(key, policy),
                "Missing in Post-Change",
                policy,
                None,
            )
        )
    for key, policy in result.unchanged.items():
        comparisons.append(
            (
                result.policy_type(key, policy),
                result.policy_id(key, policy),
                "Matching",
                policy,
                policy,
            )
        )
    for policy_type, policy_id in sorted(result.modified_policy_keys):
        comparisons.append(
            (
                policy_type,
                policy_id,
                "Modified",
                result.before[(policy_type, policy_id)],
                result.after[(policy_type, policy_id)],
            )
        )
    comparisons.sort(key=lambda item: (item[0].casefold(), item[1].casefold()))

    filters = st.columns([2, 1, 1])
    search_text = filters[0].text_input(
        "Search objects", key=f"policy_search_{fingerprint}"
    )
    object_types = sorted({item[0] for item in comparisons})
    selected_types = filters[1].multiselect(
        "Object Type", object_types, default=object_types, key=f"policy_types_{fingerprint}"
    )
    statuses = sorted({item[2] for item in comparisons})
    selected_statuses = filters[2].multiselect(
        "Status", statuses, default=statuses, key=f"policy_statuses_{fingerprint}"
    )
    visible_comparisons = [
        item
        for item in comparisons
        if item[0] in selected_types
        and item[2] in selected_statuses
        and search_text.casefold() in f"{item[0]} {item[1]} {display_value((item[4] or item[3] or {}).get('name'))}".casefold()
    ]
    object_rows = pd.DataFrame(
        [
            {
                "Object Type": policy_type,
                "Object Name": display_value((after or before or {}).get("name")) or policy_id,
                "Status": status,
            }
            for policy_type, policy_id, status, before, after in visible_comparisons
        ],
        columns=["Object Type", "Object Name", "Status"],
    )
    st.subheader("Object List")
    selected_comparison = None
    if object_rows.empty:
        st.info("No objects match the current search and filters.")
    else:
        selection = st.dataframe(
            object_rows,
            use_container_width=True,
            hide_index=True,
            on_select="rerun",
            selection_mode="single-row",
            key=f"policy_object_list_{fingerprint}",
        )
        selected_rows = selection.selection.rows
        selected_comparison = (
            visible_comparisons[selected_rows[0]] if selected_rows else None
        )

    st.subheader("Side-by-Side Comparison")
    if selected_comparison is None:
        st.caption("Select an object from the list to compare its configuration.")
    else:
        policy_type, policy_id, status, before, after = selected_comparison
        st.caption(f"{policy_type} · {policy_id} · {status}")
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "Setting": field_name.replace("_", " ").title(),
                        "Pre-Change": display_value((before or {}).get(field_name)),
                        "Post-Change": display_value((after or {}).get(field_name)),
                    }
                    for field_name in POLICY_FIELDS
                ]
            ),
            use_container_width=True,
            hide_index=True,
        )


def _render_raw_dashboard(result: RawDiffResult, fingerprint: str) -> None:
    st.subheader("Summary Statistics")
    summary_columns = st.columns(3)
    for column, label in zip(
        summary_columns,
        ("Matching Objects", "Modified Objects", "Missing Objects"),
    ):
        column.metric(label, f"{result.object_summary[label]:,}")

    view_mode = st.radio(
        "View Mode",
        [
            "Raw Config Diff",
            "Firewall Policy Diff",
            "Proxy Policy Diff",
            "Object Diff",
            "Routes",
        ],
        horizontal=True,
        key=f"raw_view_mode_{fingerprint}",
    )
    view_categories = {
        "Raw Config Diff": set(SECTION_FILTERS),
        "Firewall Policy Diff": {"Firewall Policies"},
        "Proxy Policy Diff": {"Proxy Policies"},
        "Object Diff": {
            "Address Objects",
            "Service Objects",
            "VIP Objects",
            "SSL Profiles",
            "Web Filter Profiles",
        },
        "Routes": {"Static Routes", "SD-WAN"},
    }[view_mode]

    st.subheader("Search and Filters")
    filter_columns = st.columns(5)
    selected_categories = set()
    for index, section in enumerate(SECTION_FILTERS):
        if filter_columns[index % len(filter_columns)].checkbox(
            section, value=True, key=f"raw_filter_{fingerprint}_{index}"
        ):
            selected_categories.add(section)
    selected_categories.intersection_update(view_categories)

    kind_columns = st.columns(4)
    selected_kinds = {
        kind
        for column, kind in zip(
            kind_columns, ("Added", "Removed", "Modified", "Unchanged")
        )
        if column.checkbox(kind, value=True, key=f"raw_kind_{kind}_{fingerprint}")
    }
    hide_unchanged = st.checkbox(
        "Hide unchanged lines", key=f"raw_hide_unchanged_{fingerprint}"
    )
    if hide_unchanged:
        selected_kinds.discard("Unchanged")

    search_columns = st.columns(3)
    search_text = search_columns[0].text_input("Search text", key=f"raw_text_{fingerprint}")
    search_policy_id = search_columns[1].text_input(
        "Search policy ID", key=f"raw_policy_{fingerprint}"
    )
    search_object_name = search_columns[2].text_input(
        "Search object name", key=f"raw_object_{fingerprint}"
    )

    object_key = f"raw_changed_object_{fingerprint}"
    visible_objects = []
    for item in result.changed_objects:
        if item["Category"] not in selected_categories or item["Category"] not in view_categories:
            continue
        if search_object_name and search_object_name.casefold() not in item["Object"].casefold():
            continue
        if search_policy_id and search_policy_id.casefold() not in item["Object ID"].casefold():
            continue
        object_key_tuple = (item["Section"], item["Object ID"])
        matching_hunks = [hunk for hunk in result.hunks if object_key_tuple in hunk.objects]
        if search_text and not any(
            search_text.casefold()
            in (row.before_text + row.after_text).casefold()
            for hunk in matching_hunks
            for row in hunk.rows
        ):
            continue
        status = result.object_statuses[object_key_tuple]
        visible_objects.append((item, status))

    st.subheader("Object List")
    selected_object_key = None
    if visible_objects:
        object_rows = pd.DataFrame(
            [
                {
                    "Object Type": item["Category"],
                    "Object Name": item["Object Name"],
                    "Status": status,
                }
                for item, status in visible_objects
            ],
            columns=["Object Type", "Object Name", "Status"],
        )
        selection = st.dataframe(
            object_rows,
            use_container_width=True,
            hide_index=True,
            on_select="rerun",
            selection_mode="single-row",
            key=object_key,
        )
        selected_rows = selection.selection.rows
        if selected_rows:
            selected_item = visible_objects[selected_rows[0]][0]
            selected_object_key = (selected_item["Section"], selected_item["Object ID"])
            selection_state_key = f"raw_object_selection_{fingerprint}"
            if st.session_state.get(selection_state_key) != selected_object_key:
                st.session_state[selection_state_key] = selected_object_key
                selected_status = result.object_statuses[selected_object_key]
                st.session_state[f"raw_object_jump_{fingerprint}"] = _object_navigation_target(
                    result,
                    selected_item["Category"],
                    "" if selected_status == "Missing in Pre-Change" else selected_item["Object ID"],
                    "" if selected_status == "Missing in Post-Change" else selected_item["Object ID"],
                    selected_item["Object Name"],
                    selected_status,
                )
    else:
        st.session_state[f"raw_object_selection_{fingerprint}"] = None
        st.info("No objects match the current search and filters.")

    jump_state_key = f"raw_object_jump_{fingerprint}"
    for index, (item, status) in enumerate(visible_objects):
        before_id = "" if status == "Missing in Pre-Change" else item["Object ID"]
        after_id = "" if status == "Missing in Post-Change" else item["Object ID"]
        if st.button(
            f"Open {item['Object ID']} · {item['Object Name']} in raw comparison",
            key=f"raw_object_jump_button_{fingerprint}_{index}",
            use_container_width=True,
        ):
            st.session_state[jump_state_key] = _object_navigation_target(
                result,
                item["Category"],
                before_id,
                after_id,
                item["Object Name"],
                status,
            )
            st.rerun()

    st.subheader("Side-by-Side Comparison")
    visible_hunks = []
    for hunk in result.hunks:
        if hunk.categories and not hunk.categories.intersection(selected_categories):
            continue
        if hunk.categories and not hunk.categories.intersection(view_categories):
            continue
        object_names = [
            result_object["Object"]
            for key in hunk.objects
            for result_object in result.changed_objects
            if (
                result_object["Section"],
                result_object["Object ID"],
            )
            == key
        ]
        if selected_object_key and selected_object_key not in hunk.objects:
            continue
        if search_object_name and not any(
            search_object_name.casefold() in name.casefold() for name in object_names
        ):
            continue
        if search_policy_id and not any(
            search_policy_id.casefold() in key[1].casefold() for key in hunk.objects
        ):
            continue
        if search_text and not any(
            search_text.casefold() in (row.before_text + row.after_text).casefold()
            for row in hunk.rows
        ):
            continue
        visible_hunks.append(hunk)

    visible_differences = [
        (hunk, row_index)
        for hunk in visible_hunks
        for row_index, row in enumerate(hunk.rows)
        if row.kind != "Unchanged" and row.kind in selected_kinds
    ]
    active_jump = st.session_state.get(jump_state_key)
    if visible_differences or active_jump:
        cursor_key = f"raw_difference_cursor_{fingerprint}"
        navigation_token_key = f"raw_difference_navigation_{fingerprint}"
        cursor = min(st.session_state.get(cursor_key, 0), len(visible_differences) - 1)
        navigation_columns = st.columns([1, 1, 3, 1])
        if navigation_columns[0].button("Previous Difference", key=f"previous_{fingerprint}"):
            st.session_state[cursor_key] = (cursor - 1) % len(visible_differences)
            st.session_state[navigation_token_key] = uuid.uuid4().hex
            st.rerun()
        navigation_columns[1].markdown(
            f"**Difference {cursor + 1:,} of {len(visible_differences):,}**"
        )
        if navigation_columns[3].button("Next Difference", key=f"next_{fingerprint}"):
            st.session_state[cursor_key] = (cursor + 1) % len(visible_differences)
            st.session_state[navigation_token_key] = uuid.uuid4().hex
            st.rerun()

        selected_hunk, selected_row = visible_differences[cursor] if visible_differences else (None, None)
        navigation_token = st.session_state.get(navigation_token_key)
        focus_row = selected_row if navigation_token else None
        if active_jump:
            _render_navigation_context(active_jump)
            selected_hunk = DiffHunk(
                "Full Configuration",
                {category for hunk in result.hunks for category in hunk.categories},
                {object_key for hunk in result.hunks for object_key in hunk.objects},
                result.full_rows,
            )
            focus_row = None
        else:
            st.caption(f"{selected_hunk.title} · Pre-Change left · Post-Change right")
        st.components.v1.html(
            render_side_by_side_document(
                selected_hunk,
                result.before_name,
                result.after_name,
                selected_kinds,
                focus_row,
                source_before_lines=result.before_lines if active_jump else None,
                source_after_lines=result.after_lines if active_jump else None,
                storage_key=f"fortigate-diff-{fingerprint}",
                navigation_target=active_jump,
                navigation_token=navigation_token,
            ),
            height=680,
            scrolling=False,
        )
        if len(visible_hunks) > 200:
            st.caption(
                f"Showing the selected change from {len(visible_hunks):,} matching hunks. "
                "The viewer renders one aligned hunk at a time."
            )
    else:
        st.info("No differences match the current filters and search.")

    unified_key = f"show_unified_{fingerprint}"
    if st.checkbox("Show unified diff", value=False, key=unified_key):
        st.code(
            build_unified_diff(result, max_lines=20000),
            language="diff",
            line_numbers=True,
        )


_HA_NAVIGATOR_GROUPS = (
    "Firewall Policies",
    "Address Objects",
    "Address Groups",
    "Service Objects",
    "Proxy Policies",
)


def _ha_navigator_group(change: HAChange) -> str | None:
    if change.category in {"Firewall Policies", "Proxy Policies"}:
        return change.category
    if change.category in {"Address Objects", "Address Groups"}:
        return change.category
    if change.category in {"Service Objects", "Service Groups"}:
        return "Service Objects"
    return None


def _render_ha_navigator(
    changes: list[HAChange], raw_result: RawDiffResult, fingerprint: str
) -> HAChange | None:
    differences = [
        change
        for change in changes
        if change.status != "Matching" and _ha_navigator_group(change) is not None
    ]
    group_order = {group: index for index, group in enumerate(_HA_NAVIGATOR_GROUPS)}
    differences.sort(
        key=lambda change: (
            group_order[_ha_navigator_group(change)],
            change.label.casefold(),
            change.object_id.casefold(),
        )
    )
    selected_state_key = f"ha_selected_change_{fingerprint}"

    def change_key(change: HAChange) -> tuple[str, str, str, str]:
        return (change.category, change.object_id, change.label, change.status)

    available_keys = {change_key(change) for change in differences}
    if st.session_state.get(selected_state_key) not in available_keys:
        st.session_state[selected_state_key] = (
            change_key(differences[0]) if differences else None
        )

    with st.sidebar:
        st.subheader("Changes")
        for group in _HA_NAVIGATOR_GROUPS:
            group_changes = [
                change for change in differences if _ha_navigator_group(change) == group
            ]
            with st.expander(group, expanded=any(
                change_key(change) == st.session_state[selected_state_key]
                for change in group_changes
            )):
                if not group_changes:
                    st.caption("No changes")
                for index, change in enumerate(group_changes):
                    selected = change_key(change) == st.session_state[selected_state_key]
                    if st.button(
                        f"{change.label} · {change.status}",
                        key=f"ha_nav_{fingerprint}_{group}_{index}",
                        type="primary" if selected else "secondary",
                        use_container_width=True,
                    ):
                        st.session_state[selected_state_key] = change_key(change)
                        if change.status == "Missing in A":
                            before_id, after_id = "", change.object_id
                        elif change.status == "Missing in B":
                            before_id, after_id = change.object_id, ""
                        else:
                            before_id = change.before_object_id or change.object_id
                            after_id = change.after_object_id or change.object_id
                        st.session_state[f"fullscreen_object_jump_{fingerprint}"] = _object_navigation_target(
                            raw_result,
                            change.category,
                            before_id,
                            after_id,
                            change.label,
                            change.status,
                        )
                        st.rerun()

    return next(
        (
            change
            for change in differences
            if change_key(change) == st.session_state[selected_state_key]
        ),
        None,
    )


def _render_ha_dashboard(
    result: HAComparison, raw_result: RawDiffResult, fingerprint: str
) -> None:
    selected_change = _render_ha_navigator(result.changes, raw_result, fingerprint)

    st.subheader("Policy Matching Summary")
    summary_columns = st.columns(4)
    summary_metrics = (
        ("Exact Matches", result.exact_policy_count),
        ("Equivalent Matches", result.equivalent_policy_count),
        ("Modified Matches", result.modified_policy_count),
        ("Missing Policies", result.missing_policy_count),
    )
    expanded_key = f"missing_policy_details_{fingerprint}"
    for column, (label, value) in zip(summary_columns, summary_metrics):
        if label == "Missing Policies":
            if column.button(
                f"{label} · {value:,}",
                key=f"missing_policy_tile_{fingerprint}",
                use_container_width=True,
            ):
                st.session_state[expanded_key] = not st.session_state.get(expanded_key, False)
        else:
            column.metric(label, f"{value:,}")

    policy_changes = [
        change
        for change in result.changes
        if change.category in {"Firewall Policies", "Proxy Policies", "Local-In Policies"}
    ]
    missing_changes = [change for change in policy_changes if change.status.startswith("Missing in")]

    policy_table_key = f"ha_policy_table_{fingerprint}"

    def navigate_to_change(change: HAChange) -> None:
        if change.status == "Missing in A":
            before_id, after_id = "", change.object_id
        elif change.status == "Missing in B":
            before_id, after_id = change.object_id, ""
        else:
            before_id = change.before_object_id or change.object_id
            after_id = change.after_object_id or change.object_id
        st.session_state[f"fullscreen_object_jump_{fingerprint}"] = _object_navigation_target(
            raw_result,
            change.category,
            before_id,
            after_id,
            change.label,
            change.status,
        )

    def handle_policy_selection() -> None:
        selection = st.session_state.get(policy_table_key)
        selected_rows = selection.selection.rows if selection is not None else []
        last_selected_key = f"{policy_table_key}_last_selected"
        selected_index = selected_rows[0] if selected_rows else st.session_state.get(last_selected_key)
        if isinstance(selected_index, int) and 0 <= selected_index < len(policy_changes):
            st.session_state[last_selected_key] = selected_index
            navigate_to_change(policy_changes[selected_index])

    def navigate_sequence(changes: list[HAChange], direction: int) -> None:
        if not changes:
            return
        selected = st.session_state.get(f"fullscreen_object_jump_{fingerprint}") or {}
        current = next(
            (
                index
                for index, change in enumerate(changes)
                if change.category == selected.get("category")
                and change.before_object_id == selected.get("before_id")
                and change.after_object_id == selected.get("after_id")
            ),
            -1,
        )
        index = (current + direction) % len(changes)
        navigate_to_change(changes[index])

    policy_nav = st.columns(2)
    if policy_nav[0].button("Previous Policy Difference", key=f"previous_policy_{fingerprint}"):
        navigate_sequence([change for change in policy_changes if change.status != "Matching"], -1)
        st.rerun()
    if policy_nav[1].button("Next Policy Difference", key=f"next_policy_{fingerprint}"):
        navigate_sequence([change for change in policy_changes if change.status != "Matching"], 1)
        st.rerun()
    missing_nav = st.columns(2)
    if missing_nav[0].button("Previous Missing Policy", key=f"previous_missing_{fingerprint}"):
        navigate_sequence(missing_changes, -1)
        st.rerun()
    if missing_nav[1].button("Next Missing Policy", key=f"next_missing_{fingerprint}"):
        navigate_sequence(missing_changes, 1)
        st.rerun()

    if st.session_state.get(expanded_key):
        st.subheader("Missing Policies")
        a_only, b_only = st.columns(2)
        for column, heading, status, id_field in (
            (a_only, "Firewall A Only", "Missing in B", "before_object_id"),
            (b_only, "Firewall B Only", "Missing in A", "after_object_id"),
        ):
            column.markdown(f"**{heading}**")
            side_changes = [change for change in missing_changes if change.status == status]
            if not side_changes:
                column.caption("None")
            for index, change in enumerate(side_changes):
                policy_id = getattr(change, id_field)
                if column.button(
                    f"{policy_id} · {change.label}",
                    key=f"missing_policy_{fingerprint}_{heading}_{index}",
                    use_container_width=True,
                ):
                    navigate_to_change(change)
                    st.rerun()

    if policy_changes:
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "Firewall A Policy ID": change.before_object_id or "Not present",
                        "Firewall B Policy ID": change.after_object_id or "Not present",
                        "Policy Name": change.label,
                        "Match Result": change.status,
                    }
                    for change in policy_changes
                ]
            ),
            use_container_width=True,
            hide_index=True,
            on_select=handle_policy_selection,
            selection_mode="single-row",
            key=policy_table_key,
        )
        for index, change in enumerate(policy_changes):
            before_id = change.before_object_id or "Missing"
            after_id = change.after_object_id or "Missing"
            if st.button(
                f"{before_id} ↔ {after_id} · {change.label} · {change.status}",
                key=f"ha_policy_jump_{fingerprint}_{index}",
                use_container_width=True,
            ):
                navigate_to_change(change)
                st.rerun()

    if selected_change is None:
        st.info("No modified, equivalent, or missing objects in the selected categories.")
        return

    type_labels = {
        "Firewall Policies": "Firewall Policy",
        "Address Objects": "Address Object",
        "Address Groups": "Address Group",
        "Service Objects": "Service Object",
        "Service Groups": "Service Group",
        "Proxy Policies": "Proxy Policy",
    }
    if selected_change.category in {"Firewall Policies", "Proxy Policies", "Local-In Policies"}:
        heading = (
            f'<strong>Firewall A Policy ID:</strong> {html.escape(selected_change.before_object_id or "Not present")}<br>'
            f'<strong>Firewall B Policy ID:</strong> {html.escape(selected_change.after_object_id or "Not present")}<br>'
            f'<strong>Policy Name:</strong> {html.escape(selected_change.label)}<br>'
            f'<strong>Match Result:</strong> {html.escape(selected_change.status)}'
        )
    else:
        heading = (
            f'<strong>{type_labels.get(selected_change.category, selected_change.category)}:</strong> '
            f'{html.escape(selected_change.label)}<br><strong>Status:</strong> '
            f'{html.escape(selected_change.status)}'
        )
    st.markdown(f'<div class="object-heading">{heading}</div>', unsafe_allow_html=True)
    st.components.v1.html(
        render_ha_object_html(selected_change),
        height=720,
        scrolling=False,
    )


def _close_fullscreen_comparison() -> None:
    for key in list(st.session_state):
        if key == "fullscreen_raw_payload" or key.startswith(
            ("fullscreen_raw_result_", "fullscreen_ha_result_", "fullscreen_html_export_", "fullscreen_txt_export_")
        ):
            del st.session_state[key]
    st.session_state["fullscreen_comparison_open"] = False
    st.rerun()


def _render_session_analyzer() -> None:
    _render_compare_header()
    st.subheader("Session Analyzer")
    session_text = st.text_area(
        "Paste FortiGate Session Output",
        height=360,
        placeholder="Paste output from diagnose sys session list",
        key="session_analyzer_input",
    )
    input_fingerprint = hashlib.sha256(session_text.encode("utf-8")).hexdigest()
    if st.button("Analyze Sessions", type="primary", key="analyze_sessions"):
        if not session_text.strip():
            st.warning("Paste FortiGate session output before analyzing.")
        else:
            with st.spinner("Parsing session output..."):
                st.session_state["session_analysis"] = analyze_sessions(session_text)
                st.session_state["session_analysis_fingerprint"] = input_fingerprint
                st.session_state.pop("session_analysis_excel", None)

    if st.session_state.get("session_analysis_fingerprint") != input_fingerprint:
        return
    analysis: SessionAnalysis = st.session_state["session_analysis"]
    if analysis.sessions.empty:
        st.warning("No session blocks beginning with 'session info:' were found.")
        return

    summary = analysis.summary
    metric_rows = (
        (
            ("Total Sessions", f"{summary['Total Sessions']:,}"),
            ("Unique Sources", f"{summary['Unique Sources']:,}"),
            ("Unique Destinations", f"{summary['Unique Destinations']:,}"),
            ("Total Traffic", format_traffic(float(summary["Total Traffic GB"]) * 1024)),
            ("Average Throughput", f"{summary['Average Throughput Mbps']:.3f} Mbps"),
        ),
        (
            ("Highest Throughput Session", str(summary["Highest Throughput Session"])),
            ("Longest Session", str(summary["Longest Session"])),
            ("Sessions Without NPU Offload", f"{summary['Sessions Without NPU Offload']:,}"),
            ("HTTP Sessions", f"{summary['HTTP Sessions']:,}"),
            ("HTTPS Sessions", f"{summary['HTTPS Sessions']:,}"),
        ),
    )
    st.subheader("Session Summary")
    for row in metric_rows:
        columns = st.columns(5)
        for column, (label, value) in zip(columns, row):
            column.metric(label, value)

    st.subheader("Incident Summary")
    st.code(analysis.incident_summary, language="text")

    sessions = analysis.sessions
    st.subheader("Search and Filters")
    filter_columns = st.columns(6)
    search_text = filter_columns[0].text_input("Search sessions", key="session_search")
    source_options = sorted(sessions["Source IP"].dropna().unique())
    destination_options = sorted(sessions["Destination IP"].dropna().unique())
    application_options = sorted(sessions["Application"].dropna().unique())
    port_options = sorted(int(port) for port in sessions["Port"].dropna().unique())
    policy_options = sorted(sessions["Policy ID"].dropna().astype(str).unique())
    state_options = sorted(sessions["Session State"].dropna().astype(str).unique())
    source_filter = filter_columns[1].multiselect("Source IP", source_options, key="session_source_filter")
    destination_filter = filter_columns[2].multiselect("Destination IP", destination_options, key="session_destination_filter")
    application_filter = filter_columns[3].multiselect("Application", application_options, key="session_application_filter")
    port_filter = filter_columns[4].multiselect("Port", port_options, key="session_port_filter")
    policy_filter = filter_columns[5].multiselect("Policy ID", policy_options, key="session_policy_filter")
    state_filter = st.multiselect("State", state_options, key="session_state_filter")

    visible = sessions
    filters = (
        ("Source IP", source_filter),
        ("Destination IP", destination_filter),
        ("Application", application_filter),
        ("Port", port_filter),
        ("Policy ID", policy_filter),
        ("Session State", state_filter),
    )
    for column_name, selected in filters:
        if selected:
            visible = visible[visible[column_name].isin(selected)]
    if search_text:
        search_mask = visible.astype(str).apply(
            lambda column: column.str.contains(search_text, case=False, regex=False)
        ).any(axis=1)
        visible = visible[search_mask]
    st.caption(f"Showing {len(visible):,} of {len(sessions):,} sessions")

    traffic_gb_format = lambda value: format_traffic(float(value) * 1024)
    st.subheader("All Sessions")
    st.dataframe(
        visible.style.format({"Total Traffic GB": traffic_gb_format, "Total Traffic MB": "{:,.2f} MB", "Current Throughput Mbps": "{:,.3f}"}),
        width="stretch",
        hide_index=True,
    )

    top_talkers = visible.sort_values("Total Bytes", ascending=False).head(20).loc[
        :, ["Source IP", "Destination IP", "Port", "Application", "Duration Human Format", "Total Traffic GB", "Current Throughput Mbps"]
    ].rename(columns={"Duration Human Format": "Duration", "Total Traffic GB": "Traffic GB"}).reset_index(drop=True)
    longest_sessions = visible.sort_values("Duration", ascending=False).head(20).loc[
        :, ["Source IP", "Destination IP", "Port", "Application", "Duration Human Format", "Duration", "Total Traffic GB", "Current Throughput Mbps"]
    ].rename(columns={"Duration Human Format": "Duration Format"}).reset_index(drop=True)
    source_analysis = (
        visible.groupby("Source IP", dropna=False)
        .agg(**{
            "Session Count": ("Source IP", "size"),
            "Total Traffic GB": ("Total Traffic GB", "sum"),
            "Average Throughput Mbps": ("Current Throughput Mbps", "mean"),
        })
        .sort_values("Total Traffic GB", ascending=False)
        .reset_index()
    )
    destination_analysis = (
        visible.groupby("Destination IP", dropna=False)
        .agg(**{
            "Session Count": ("Destination IP", "size"),
            "Total Traffic GB": ("Total Traffic GB", "sum"),
        })
        .sort_values("Total Traffic GB", ascending=False)
        .reset_index()
    )
    health_findings = analysis.health_findings
    for column_name, selected in filters:
        if selected and column_name in health_findings.columns:
            health_findings = health_findings[health_findings[column_name].isin(selected)]
    if search_text:
        for table_name, table in (
            ("top_talkers", top_talkers),
            ("longest_sessions", longest_sessions),
            ("health_findings", health_findings),
        ):
            search_mask = table.astype(str).apply(
                lambda column: column.str.contains(search_text, case=False, regex=False)
            ).any(axis=1)
            if table_name == "top_talkers":
                top_talkers = table[search_mask]
            elif table_name == "longest_sessions":
                longest_sessions = table[search_mask]
            else:
                health_findings = table[search_mask]

    st.subheader("Top 20 Sessions By Traffic")
    st.dataframe(
        top_talkers.style.format({"Traffic GB": traffic_gb_format, "Current Throughput Mbps": "{:,.3f}"}),
        width="stretch",
        hide_index=True,
    )
    st.subheader("Top 20 Longest Duration Sessions")
    st.dataframe(
        longest_sessions.style.format({"Total Traffic GB": traffic_gb_format, "Current Throughput Mbps": "{:,.3f}"}),
        width="stretch",
        hide_index=True,
    )
    st.subheader("Top Source IPs")
    st.dataframe(
        source_analysis.style.format({"Total Traffic GB": traffic_gb_format, "Average Throughput Mbps": "{:,.3f}"}),
        width="stretch",
        hide_index=True,
    )
    st.subheader("Top Destination IPs")
    st.dataframe(
        destination_analysis.style.format({"Total Traffic GB": traffic_gb_format}),
        width="stretch",
        hide_index=True,
    )
    st.subheader("Session Health Findings")
    if health_findings.empty:
        st.info("No health findings match the current filters.")
    else:
        st.dataframe(health_findings, width="stretch", hide_index=True)

    excel_key = "session_analysis_excel"
    if excel_key not in st.session_state:
        st.session_state[excel_key] = build_session_excel_report(analysis).getvalue()
    st.download_button(
        "Export Excel",
        data=st.session_state[excel_key],
        file_name="fortigate_session_analysis.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        key="export_session_analysis",
    )


def _render_setup_screen(is_ha: bool = False) -> None:
    st.markdown(
        """
        <style>
        [data-testid="stSidebar"] { display: none !important; }
        [data-testid="stMain"] .block-container { max-width: 1100px; margin: 0 auto; }
        .setup-panel { padding: 1.25rem; background: #FFFFFF; border: 1px solid #B8DFF5; }
        </style>
        """,
        unsafe_allow_html=True,
    )
    _render_compare_header()
    comparison_mode = (
        "HA Firewall A vs Firewall B Comparison" if is_ha else "Pre/Post Comparison"
    )
    policy_match_mode = (
        st.segmented_control(
            "Policy Comparison Mode",
            POLICY_MATCH_MODES,
            default="Functional Match",
            key="policy_match_mode",
            width="stretch",
        )
        if is_ha
        else "Policy ID Match"
    )
    before_label = "Firewall A Configuration" if is_ha else "Pre-Change Configuration"
    after_label = "Firewall B Configuration" if is_ha else "Post-Change Configuration"

    upload_columns = st.columns(2)
    before_file = upload_columns[0].file_uploader(
        before_label, type=["conf", "cfg", "txt"], key="before_config"
    )
    after_file = upload_columns[1].file_uploader(
        after_label, type=["conf", "cfg", "txt"], key="after_config"
    )

    st.subheader("Optional Ignore Filters")
    ignore_options = (
        "Hostname",
        "Interface IP",
        "UUID",
        "Comments",
        "Config Revisions",
        "HA Settings",
    )
    ignore_columns = st.columns(3)
    ignored_categories = {
        option
        for index, option in enumerate(ignore_options)
        if ignore_columns[index % len(ignore_columns)].checkbox(
            option, key=f"ignore_{option.casefold().replace(' ', '_')}"
        )
    }

    can_compare = before_file is not None and after_file is not None
    if st.button(
        "Open Raw Comparison Window",
        type="primary",
        use_container_width=True,
        disabled=not can_compare,
        key="open_raw_comparison",
    ):
        before_bytes = before_file.getvalue()
        after_bytes = after_file.getvalue()
        upload_identity = (
            f"{before_file.file_id}:{before_file.name}:{before_file.size}:"
            f"{after_file.file_id}:{after_file.name}:{after_file.size}:"
            f"{comparison_mode}:{','.join(sorted(ignored_categories))}"
        )
        fingerprint = hashlib.sha256(upload_identity.encode("utf-8")).hexdigest()[:16]
        st.session_state["fullscreen_raw_payload"] = {
            "before_bytes": before_bytes,
            "after_bytes": after_bytes,
            "before_name": before_file.name,
            "after_name": after_file.name,
            "comparison_mode": comparison_mode,
            "policy_match_mode": policy_match_mode,
            "ignore_categories": ignored_categories,
            "fingerprint": fingerprint,
        }
        st.session_state["fullscreen_comparison_open"] = True
        st.rerun()


def _render_fullscreen_page() -> None:
    _render_compare_theme()
    st.markdown(
        """
        <style>
        [data-testid="stSidebar"] { display: none !important; }
        [data-testid="stMain"] .block-container { max-width: none; padding: 4rem .65rem .75rem; }
        .fullscreen-title { color: #20252a; font: 600 19px/1.3 "Segoe UI", sans-serif; }
        [data-testid="stMetric"] { background: #FFFFFF; border: 1px solid #B8DFF5; border-radius: 3px; padding: .4rem .65rem; }
        </style>
        """,
        unsafe_allow_html=True,
    )
    payload = st.session_state.get("fullscreen_raw_payload")
    if payload is None:
        st.session_state["fullscreen_comparison_open"] = False
        st.rerun()
        return

    heading_columns = st.columns([6, 1])
    heading_columns[0].markdown(
        '<div class="fullscreen-title">Full Configuration Comparison</div>',
        unsafe_allow_html=True,
    )
    if heading_columns[1].button("Close Comparison", use_container_width=True):
        _close_fullscreen_comparison()

    _render_fullscreen_comparison(
        payload["before_bytes"],
        payload["after_bytes"],
        payload["before_name"],
        payload["after_name"],
        payload["comparison_mode"],
        payload["policy_match_mode"],
        payload["ignore_categories"],
        payload["fingerprint"],
    )


if st.session_state.get("fullscreen_comparison_open", False):
    _render_fullscreen_page()
else:
    _render_compare_theme()
    page = st.segmented_control(
        "Page",
        ["HA Comparison", "Configuration Comparison", "Session Analyzer"],
        default="Configuration Comparison",
        key="main_page",
        width="stretch",
    )
    if page == "Session Analyzer":
        _render_session_analyzer()
    else:
        _render_setup_screen(is_ha=page == "HA Comparison")