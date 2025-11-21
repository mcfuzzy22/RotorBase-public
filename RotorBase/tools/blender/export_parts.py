"""Batch-export individual part GLBs with matching Attach_Main empties.

Run with:
    ~/opt/blender/blender -b /path/to/your_file.blend --python export_parts.py

The script will create an Attach_Main empty for each exported mesh so the
viewer can reliably snap parts at runtime.
"""

import math
import os
from pathlib import Path

import bpy


# === CONFIGURATION =======================================================
# Output directory relative to the .blend file location.
OUTPUT_DIR = bpy.path.abspath("//exports/glb_parts")

# Optional: restrict export to these mesh object names.
# Set to None to process every mesh in the scene.
MESH_FILTER = None

# Empties with names that start with these prefixes are eligible attach sources.
ATTACH_CANDIDATE_PREFIXES = ("Attach_Main", "Attach")
# ========================================================================


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def distance(a, b) -> float:
    ax, ay, az = a
    bx, by, bz = b
    return math.sqrt((ax - bx) ** 2 + (ay - by) ** 2 + (az - bz) ** 2)


def find_nearest_attach_empty(mesh_obj: bpy.types.Object):
    """Return the closest attach empty to `mesh_obj`, or None if none exist."""
    candidates = [
        obj
        for obj in bpy.data.objects
        if obj.type == "EMPTY"
        and any(obj.name.startswith(prefix) for prefix in ATTACH_CANDIDATE_PREFIXES)
    ]
    if not candidates:
        return None
    mesh_location = mesh_obj.matrix_world.translation
    return min(
        candidates,
        key=lambda empty: distance(mesh_location, empty.matrix_world.translation),
    )


def sanitize_name(name: str) -> str:
    """Convert object names into filesystem-friendly filenames."""
    return "".join("_" if char in " /\\:" else char for char in name)


def build_part_map():
    """Group mesh objects by their parent EMPTY controller."""
    part_meshes = {}
    for obj in bpy.data.objects:
        if obj.type != "MESH":
            continue
        parent = obj.parent
        if (
            not parent
            or parent.type != "EMPTY"
            or parent.name.startswith("Socket_")
            or parent.name in part_meshes and obj in part_meshes[parent.name]
        ):
            continue
        if parent.name == "":
            continue
        part_meshes.setdefault(parent.name, []).append(obj)
    return part_meshes


def find_socket_for_part(part_name: str):
    return bpy.data.objects.get(f"Socket_{part_name}")


def determine_attach_source(meshes, part_empty):
    """Find the best transform to reuse for the Attach_Main empty."""
    nearest_attach = None
    for mesh_obj in meshes:
        nearest_attach = find_nearest_attach_empty(mesh_obj)
        if nearest_attach:
            break
    if nearest_attach:
        return nearest_attach

    socket = find_socket_for_part(part_empty.name)
    if socket:
        return socket

    return part_empty or meshes[0]


def main() -> None:
    ensure_dir(OUTPUT_DIR)

    scene = bpy.context.scene
    view_layer = bpy.context.view_layer

    original_selection_names = [obj.name for obj in bpy.context.selected_objects]
    original_active_name = (
        bpy.context.active_object.name if bpy.context.active_object else None
    )
    exported_count = 0
    part_meshes = build_part_map()
    for part_name, meshes in sorted(part_meshes.items()):
        if MESH_FILTER and part_name not in MESH_FILTER:
            continue

        part_empty = bpy.data.objects.get(part_name)
        if not meshes:
            continue

        source = determine_attach_source(meshes, part_empty)

        temp_attach = bpy.data.objects.new("Attach_Main", None)
        temp_attach.empty_display_type = "PLAIN_AXES"
        temp_attach.matrix_world = source.matrix_world
        scene.collection.objects.link(temp_attach)

        bpy.ops.object.select_all(action="DESELECT")
        for mesh_obj in meshes:
            mesh_obj.select_set(True)
        temp_attach.select_set(True)
        view_layer.objects.active = meshes[0]

        file_name = sanitize_name(f"Socket_{part_name}") + ".glb"
        file_path = os.path.join(OUTPUT_DIR, file_name)
        bpy.ops.export_scene.gltf(
            filepath=file_path,
            use_selection=True,
            export_format="GLB",
            export_apply=False,
            export_yup=True,
            use_visible=False,
            export_extras=True,
            export_cameras=False,
            export_lights=False,
        )

        temp_attach.select_set(True)
        bpy.ops.object.delete()

        exported_count += 1
        print(f"Exported {file_name}")

    bpy.ops.object.select_all(action="DESELECT")
    for name in original_selection_names:
        obj = bpy.data.objects.get(name)
        if obj:
            obj.select_set(True)
    if original_active_name and original_active_name in bpy.data.objects:
        view_layer.objects.active = bpy.data.objects[original_active_name]

    print(f"Done. Exported {exported_count} parts to {Path(OUTPUT_DIR).resolve()}")


if __name__ == "__main__":
    main()
