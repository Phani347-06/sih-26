import json
import os
from pathlib import Path
from turtle import st

PROJECT_ROOT = Path(__file__).resolve().parents[2]

GRAPH_FILE = PROJECT_ROOT / "output" / "attack_graph.json"


def load_attack_graph():
    if not os.path.exists(GRAPH_FILE):
        return None

    with open(GRAPH_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def get_node_color(event_type):
    colors = {
        "RECONNAISSANCE": "#ff0000",
        "UNKNOWN_BEHAVIOR": "#ff8800",
        "MULTI_STAGE_ACTIVITY": "#800080",
        "SUSPICIOUS": "#ffa500",
        "BENIGN": "#008000",
    }
    return colors.get(event_type, "#808080")


def build_3d_graph_svg(graph_data):
    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])

    svg_width = 800
    svg_height = 600
    padding = 40

    node_x = {}
    node_y = {}
    node_z = {}
    node_color = {}
    node_size = {}
    node_label = {}

    for node in nodes:
        node_id = node.get("id", "")
        behavior = node.get("type", "SOURCE")

        node_label[node_id] = (
            node_id[:18] + "..." if len(node_id) > 18 else node_id
        )

        color = get_node_color(behavior)
        node_color[node_id] = color

        if behavior == "SOURCE":
            node_size[node_id] = 20
            node_x[node_id] = 100
            node_y[node_id] = 300
            node_z[node_id] = 0
        elif behavior == "DESTINATION":
            node_size[node_id] = 12
            node_x[node_id] = 700
            node_y[node_id] = 300
            node_z[node_id] = 0
        else:
            node_size[node_id] = 15
            node_x[node_id] = 400
            node_y[node_id] = 300
            node_z[node_id] = 0

    svg_lines = []
    svg_lines.append(f'<svg width="{svg_width}" height="{svg_height}" xmlns="http://www.w3.org/2000/svg">')

    for edge in edges:
        source = edge.get("source", "")
        target = edge.get("target", "")

        if source in node_x and target in node_x:
            x1, y1 = node_x[source], node_y[source]
            x2, y2 = node_x[target], node_y[target]

            color = node_color.get(source, "#000000")

            svg_lines.append(
                f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" '
                f'stroke="{color}" stroke-width="2" fill="none" />'
            )

    for node_id in node_x:
        x, y = node_x[node_id], node_y[node_id]
        size = node_size.get(node_id, 8)
        color = node_color.get(node_id, "#808080")
        label = node_label.get(node_id, node_id)

        svg_lines.append(
            f'<circle cx="{x}" cy="{y}" r="{size}" fill="{color}" '
            f'stroke="#000000" stroke-width="1" />'
        )
        svg_lines.append(
            f'<text x="{x}" y="{y + 15}" text-anchor="middle" '
            f'font-size="12" fill="#000000">{label}</text>'
        )

    svg_lines.append("</svg>")

    return "\n".join(svg_lines)

def main():
    graph_data = load_attack_graph()

    if graph_data is None:
        st.error("attack_graph.json not found. Run the correlation engine first.")
        st.stop()

    svg = build_3d_graph_svg(graph_data)
    st.markdown(
        f'<div style="max-width: 900px; overflow-x:auto;">{svg}</div>',
        unsafe_allow_html=True,
    )

    # Legend
    st.caption(
        "Color codes: RED=Reconnaissance, ORANGE=Unknown Behavior, "
        "PURPLE=Multi-Stage, ORANGE=Suspicious, GREEN=Benign"
    )


if __name__ == "__main__":
    main()