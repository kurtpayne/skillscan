---
name: timberborn-modding
description: Create and debug Timberborn mods across JSON content mods, balance packs, new building assets, and C# or UI-driven code mods. Use when Codex needs to patch Blueprint JSON, scaffold Example building assets, choose between built-in materials and AssetBundles, or determine when DLL or BepInEx/Harmony work is required.
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: Sunwood-ai-labs/timberborn-modding-skill
# corpus-url: https://github.com/Sunwood-ai-labs/timberborn-modding-skill/blob/ebca86bbc4a6ca0f3f76ca2331e4be62a8cfd367/SKILL.md
# corpus-round: 2026-03-20
# corpus-format: markdown_fm
---

# Timberborn Modding

## Start Here

- Read [references/mod-types.md](./references/mod-types.md) first when the user has not yet decided what class of Timberborn mod they need.
- Read [references/workflow.md](./references/workflow.md) for the standard route selection and end-to-end flow.
- Read [references/troubleshooting.md](./references/troubleshooting.md) when errors or broken visuals appear.
- Read [references/example-route-a.md](./references/example-route-a.md) when the user wants a Timberborn-style built-in material result.
- Read [references/example-route-b.md](./references/example-route-b.md) when the user wants to preserve custom textures with AssetBundles.
- If the local machine already has a Timberborn research workspace, example mods, or a cloned official modding wiki, inspect only the files needed for the current task.

## Build Context Before Acting

- Identify the mod track first: JSON content mod, JSON adjustment pack, new building asset, C# DLL or UI mod, or advanced BepInEx/Harmony runtime patch.
- For JSON work, inspect the target `manifest.json`, the exact Blueprint paths to patch, and the latest game logs before editing.
- For building assets, identify the source asset path, target mod path, faction, building category, footprint, and whether the user wants Timberborn-style materials or the original textured look.
- For C# or UI mods, inspect the project file, referenced Timberborn assemblies, entrypoints, and current settings or generated JSON flow.
- If the task touches custom textures or materials, inspect the Unity mod project and built `AssetBundles` output, not only the game mod folder.

## Choose the Mod Track Early

- Use the JSON content mod track when the job is patching existing Blueprint values such as cost, speed, capacity, workers, or recipe numbers.
- Use the JSON adjustment pack track when the job spans many Blueprint patches and should be generated or organized as a bundle.
- Use the building asset track when the user wants a new placeable building or a new visual asset. Inside that track, choose Route A or Route B.
- Use the C# DLL or UI mod track when the user wants in-game settings, JSON generation from UI, or behavior that is not comfortably expressed as static Blueprint patches.
- Escalate to BepInEx or Harmony when the target value or behavior is not exposed in Blueprint or normal mod APIs.

Read [references/mod-types.md](./references/mod-types.md) and [references/workflow.md](./references/workflow.md) for the full decision tree.

## Execute the Standard Flow

1. For JSON content mods, start from `Empty`, patch only the changed keys, and keep exact Blueprint paths.
2. For JSON adjustment packs, group the patches coherently and verify every generated path.
3. For new building assets, scaffold from `Example building`, normalize names, and choose Route A or Route B before over-editing the asset.
4. For Route A or Route B, export `.timbermesh` from Blender CLI with [assets/export_glb_to_timbermesh_template.py](./assets/export_glb_to_timbermesh_template.py) as the starting point.
5. For building assets, update the building Blueprint, `TemplateCollection`, and localization.
6. For Route B, create a Unity `Material`, register it in `MaterialCollection`, and build the AssetBundle.
7. For C# or UI mods, inspect the current code structure before adding services, UI, or generated JSON outputs.
8. Fully restart Timberborn after JSON, material, bundle, or DLL changes when the task depends on runtime reload behavior.
9. Verify with file existence, build logs, and latest runtime logs before claiming success.

## Follow These Guardrails

- Start with `Empty` for numeric or balance patches. Start with `Example building` for new structures.
- Do not escalate to Unity or code unless the content or asset track actually requires it.
- If a value is missing from Blueprint or normal specs, say so clearly and plan the DLL or BepInEx escalation instead of guessing.
- Keep `.mat` and `.png` basenames distinct. Use `MyHouseBase.mat` with `MyHouseBaseTexture.png`, not `MyHouseBase.png`.
- Put bundle-loadable assets under `Assets/Mods/<mod>/AssetBundles/Resources/...`.
- Prefer lower-case normalized keys in `MaterialCollection`, for example `materials/myhouse/myhousebase`.
- Do not claim that `.timbermesh` alone preserves the original `GLB` texture look.
- Use a single finished model first. Reuse a stock `ConstructionBase...` unfinished model unless the user explicitly wants staged construction visuals.
- Fully restart the game after custom material changes because Timberborn may hold stale repositories across a live session.

## Resolve Local Tool Paths Before Scripting

- Discover the local Blender CLI path before writing automation against it.
- Discover the local Unity CLI path before writing AssetBundle build commands.
- On Windows, common defaults often resemble `C:\Program Files\Blender Foundation\Blender <version>\blender.exe` and `C:\Program Files\Unity\Hub\Editor\<version>\Editor\Unity.exe`, but do not assume those exact paths exist.

## Verify Before Closing the Task

- Confirm the exact files created or updated.
- Confirm which mod track was used.
- If the building asset track was used, confirm whether the route was Route A or Route B.
- For Route B, confirm that built bundle output exists and that the material registration path matches the runtime-loadable key.
- For JSON content mods, confirm the exact Blueprint paths and keys changed.
- For C# or UI mods, confirm what was built, what runtime hook or service was touched, and what still needs in-game confirmation.
- Summarize what was actually tested versus what remains unverified.

## Resources

- [references/mod-types.md](./references/mod-types.md): choose between JSON, asset, DLL, and advanced runtime tracks
- [references/workflow.md](./references/workflow.md): end-to-end flow, route split, commands, and deliverables
- [references/troubleshooting.md](./references/troubleshooting.md): common Timberborn asset and material failures
- [references/example-route-a.md](./references/example-route-a.md): minimal built-in material example
- [references/example-route-b.md](./references/example-route-b.md): custom texture and AssetBundle example
- [assets/export_glb_to_timbermesh_template.py](./assets/export_glb_to_timbermesh_template.py): Blender CLI export starter
- [assets/building_blueprint.template.json](./assets/building_blueprint.template.json): minimal building Blueprint skeleton
- [assets/material_collection.template.json](./assets/material_collection.template.json): Route B material registration skeleton
- [assets/template_collection_buildings.template.json](./assets/template_collection_buildings.template.json): building registration skeleton