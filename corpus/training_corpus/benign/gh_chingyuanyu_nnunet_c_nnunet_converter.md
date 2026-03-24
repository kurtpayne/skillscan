---
name: nnunet-converter
description: >
  Convert medical imaging datasets (NIfTI .nii/.nii.gz, .mha) into nnUNet v2 format.
  Use this skill whenever the user mentions nnUNet, nnU-Net, dataset conversion for
  segmentation training, preparing data for nnUNet, organizing imagesTr/labelsTr folders,
  generating dataset.json, or structuring medical images for nnUNet preprocessing.
  Trigger even if the user just says "convert my dataset to nnUNet" or "prepare my
  segmentation data for nnUNet training". Covers single-modality MRI, multi-modal MRI,
  and CT datasets. Also handles classification labels (cls_data.csv) and
  classification_labels in dataset.json.
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: ChingYuanYu/nnunet-converter-skill
# corpus-url: https://github.com/ChingYuanYu/nnunet-converter-skill/blob/46c4fe47db93e6c33fc0423a71f57f526ade2fb9/SKILL.md
# corpus-round: 2026-03-20
# corpus-format: markdown_fm
---

# nnUNet v2 Dataset Converter Skill

Convert NIfTI (.nii, .nii.gz) and MetaImage (.mha) datasets into nnUNet v2 format,
including folder structure creation, file renaming, automatic dataset.json generation,
and classification label support (cls_data.csv + classification_labels in dataset.json).

## nnUNet v2 Format at a Glance

```
nnUNet_raw/
└── Dataset{ID}_{Name}/        # e.g. Dataset042_LiverSeg
    ├── dataset.json
    ├── imagesTr/
    │   ├── case_0001_0000.nii.gz   # channel 0 of case 0001
    │   ├── case_0001_0001.nii.gz   # channel 1 (multi-modal only)
    │   └── ...
    ├── labelsTr/
    │   ├── case_0001.nii.gz        # segmentation mask (NO channel suffix)
    │   └── ...
    └── imagesTs/               # optional test images (no labels needed)
        └── ...
```

**File naming rule:** `{CASE_ID}_{CHANNEL:04d}.{ext}` for images, `{CASE_ID}.{ext}` for labels.
- CASE_ID: any string, e.g. `liver_001`, `BRATS_042`
- CHANNEL: 4-digit zero-padded integer (`_0000`, `_0001`, ...)
- Single modality: only `_0000` exists
- Labels: **no** channel suffix

## Workflow

### Step 1 — Understand the Input Dataset

Ask the user (or infer from context) these things before writing any code:

1. **Source layout**: How is the input organized? Common patterns:
   - Flat: all images in one folder, labels in another
   - Per-subject: one folder per patient/case containing image(s) + mask
   - Mixed: images and labels interleaved with a naming convention

2. **Modalities / channels**: How many input channels?
   - Single (CT, T1 MRI, etc.) → one file per case, suffix `_0000`
   - Multi-modal (T1+T2+FLAIR+T1Gd) → one file per channel per case

3. **File extension**: `.nii`, `.nii.gz`, or `.mha`? Must be **consistent** across the dataset (nnUNet requires one `file_ending` for the whole dataset). If mixing .nii and .nii.gz, convert all to .nii.gz.

4. **Label values**: What integer values appear in the masks? Must be **consecutive** starting from 0. 0 = background always. Ask the user what each label value represents (e.g. 1=liver, 2=tumor).

5. **Train/test split**: Does the user have a pre-defined split, or should the script put everything in `imagesTr`?

6. **Dataset ID and name**: nnUNet needs a 3-digit ID (e.g. 042) and a CamelCase name (e.g. LiverSeg). Ask if not obvious. IDs 001–010 are reserved for Medical Segmentation Decathlon.

7. **Channel names**: What is each modality called? This affects nnUNet normalization:
   - Use `"CT"` exactly for CT scans → triggers CT-specific global normalization
   - Use `"MRI"`, `"T1"`, `"T2"`, `"FLAIR"`, `"ADC"`, etc. for MRI → triggers per-channel z-score normalization
   - The exact string matters for normalization scheme selection!

8. **Classification labels**: Does the dataset have case-level classification labels?
   - If yes, determine the label source (CSV, metadata, folder names, etc.)
   - Determine label semantics: binary (0/1), multi-class (0,1,2,...), or multi-label ([0,1], [1,0], ...)
   - Classification labels go in BOTH `cls_data.csv` AND `classification_labels` in `dataset.json`

9. **Spatial alignment**: For multi-modal data, check if all modalities share the same geometry (size, spacing, origin, direction). If not, resample non-reference modalities to the reference image space.

### Step 2 — Write the Conversion Script

Write a Python script using **only standard library + SimpleITK** (for .mha support) and **nibabel** (for NIfTI).
See `scripts/convert_template.py` for a reusable template.

Key rules to enforce in the script:
- Output file extension must match `file_ending` in dataset.json
- All images **must** be the same extension (.nii.gz preferred for outputs)
- Labels must not have a channel suffix
- Case identifiers must be consistent between imagesTr and labelsTr
- Validate that label values are consecutive integers starting at 0

### Step 3 — Generate dataset.json

Generate dataset.json automatically by scanning the output `imagesTr` folder.
Read the reference: `references/dataset_json_spec.md`

Minimal required fields:
```json
{
  "channel_names": {"0": "CT"},
  "labels": {"background": 0, "liver": 1},
  "numTraining": 51,
  "file_ending": ".nii.gz"
}
```

Optional but recommended:
```json
{
  "name": "Dataset042_LiverSeg",
  "description": "Liver segmentation from CT",
  "reference": "",
  "licence": "",
  "overwrite_image_reader_writer": "SimpleITKIO"
}
```

> **Note on `overwrite_image_reader_writer`**: Add `"SimpleITKIO"` when using `.mha` files, since SimpleITK handles .mha natively. For `.nii.gz` it's optional.

### Step 4 — Validate

After running the conversion script, verify:
```bash
# Count files match
ls imagesTr/ | wc -l   # should be numTraining * num_channels
ls labelsTr/ | wc -l   # should be numTraining

# Spot-check naming
ls imagesTr/ | head -5
ls labelsTr/ | head -5

# If nnUNet is installed, run integrity check:
nnUNetv2_plan_and_preprocess -d {ID} --verify_dataset_integrity
```

---

## Classification Labels (cls_data.csv + dataset.json)

Many datasets have case-level classification labels in addition to segmentation masks. These are stored in two places:

### cls_data.csv
A CSV file at the dataset root with format:
```csv
identifier,label
case_001,0
case_002,1
case_003,2
```

- `identifier`: matches the case ID used in imagesTr/labelsTr filenames (WITHOUT channel suffix or file extension)
- `label`: integer class label. Can also be a list for multi-label tasks: `"[1, 0]"`

### classification_labels in dataset.json
Add a `classification_labels` field to dataset.json that maps label names to their integer values:
```json
{
  "classification_labels": {
    "ISUP_grade": {
      "0": "Benign/Indolent (ISUP 0-1)",
      "1": "ISUP 1",
      "2": "ISUP 2",
      "3": "ISUP 3"
    }
  }
}
```

For multi-label classification (e.g., primary tumor origin with multiple classes):
```json
{
  "classification_labels": {
    "primary_tumor_origin": {
      "0": "NSCLC",
      "1": "Breast carcinoma",
      "2": "SCLC"
    }
  }
}
```

### Classification Label Sources
Classification labels can come from:
- Clinical metadata CSV/spreadsheet (e.g., ISUP grade, IDH mutation status, tumor type)
- Derived from segmentation masks (e.g., presence/absence of tumor = binary classification)
- Folder structure or filename patterns

**Important**: Classification labels and segmentation labels serve different purposes:
- Segmentation = voxel-level (WHERE is the lesion)
- Classification = case-level (WHAT type/grade is it)
- They should ideally capture different information — if classification can be trivially derived from the segmentation mask (e.g., "has any tumor voxel"), consider using a richer classification target instead (e.g., tumor grade, molecular subtype)

### Existing Examples in /mnt/pool/datasets/CY/nnUNet_raw/:
- `Dataset219_BrainMets`: `primary_tumor_origin` (NSCLC/Breast/SCLC) — multi-class
- `Dataset227_MU_Glioma_Post`: `primary_diagnosis` (GBM/Astrocytoma/Others) — multi-class
- `Dataset306_JSC_UCSD_PTGB`: `idh_mutation_status` (IDH Wild-Type/IDH Mutant) — binary with -1 for unknown
- `Dataset211_BMLMPS_FLAIR`: multi-label format `"[1, 0]"`
- `Dataset320_PICAI`: `ISUP_grade` (0-5) — ordinal grading scale

---

## Spatial Resampling for Multi-Modal Data

When combining modalities with **different spatial resolutions** (common in MRI), all channels must be resampled to a common reference space before nnUNet can use them.

### When to resample
- Check size, spacing, origin, and direction of each modality
- If any differ, resample the non-reference modalities to match the reference

### How to resample
```python
import SimpleITK as sitk

def resample_to_reference(moving_img, reference_img, interpolator=sitk.sitkLinear):
    """Resample moving image to match reference image geometry."""
    resampler = sitk.ResampleImageFilter()
    resampler.SetReferenceImage(reference_img)
    resampler.SetInterpolator(interpolator)
    resampler.SetDefaultPixelValue(0)
    return resampler.Execute(moving_img)
```

### Interpolation choice
- **Images**: `sitk.sitkLinear` (smooth, preserves intensity gradients)
- **Labels/masks**: `sitk.sitkNearestNeighbor` (preserves integer label values)

### Example: PICAI dataset
- T2W: 384×384×19 @ 0.5mm spacing (high-res reference)
- ADC: 84×128×19 @ 2.0mm spacing → resample to T2W space
- HBV: 84×128×19 @ 2.0mm spacing → resample to T2W space
- Labels: already at T2W resolution

---

## Handling Common Input Layouts

### Layout A: Two flat folders (images/ and labels/)
```
input/
├── images/
│   ├── patient001.nii.gz
│   └── patient002.nii.gz
└── labels/
    ├── patient001.nii.gz
    └── patient002.nii.gz
```
→ Sort both folders, pair by sorted index or matching filename stem.

### Layout B: Per-subject folders
```
input/
├── patient001/
│   ├── T1.nii.gz
│   ├── T2.nii.gz
│   └── seg.nii.gz
└── patient002/
    ├── T1.nii.gz
    ├── T2.nii.gz
    └── seg.nii.gz
```
→ Walk subdirectories; use folder name as case ID; detect channels by known filenames.

### Layout C: Single folder, mixed files
```
input/
├── patient001_image.nii.gz
├── patient001_label.nii.gz
├── patient002_image.nii.gz
└── patient002_label.nii.gz
```
→ Use regex/glob patterns to separate images from labels by suffix.

---

## Multi-Modal Handling

For multi-modal MRI (e.g. T1, T2, FLAIR):
- Each modality becomes a separate file with incrementing channel index
- Channel order must be **identical** for all cases
- `channel_names` in dataset.json maps `"0"` → `"T1"`, `"1"` → `"T2"`, etc.

Example output for 4-channel BraTS-style data:
```
imagesTr/
├── BraTS_001_0000.nii.gz   # T1
├── BraTS_001_0001.nii.gz   # T1Gd
├── BraTS_001_0002.nii.gz   # T2
├── BraTS_001_0003.nii.gz   # FLAIR
└── ...
```

---

## .mha → .nii.gz Conversion

If input is `.mha` but user prefers `.nii.gz` output (recommended for compatibility):
```python
import SimpleITK as sitk
img = sitk.ReadImage("input.mha")
sitk.WriteImage(img, "output.nii.gz")
```
SimpleITK preserves spacing, origin, and direction cosines across formats.

If keeping `.mha` as output format, set `"file_ending": ".mha"` and optionally add `"overwrite_image_reader_writer": "SimpleITKIO"`.

---

## Label Validation

nnUNet requires:
- Label 0 = background (always)
- Consecutive integers: 0, 1, 2, 3, ...
- No gaps (e.g. 0, 1, 4 is INVALID)

Check and remap if needed:
```python
import numpy as np
import nibabel as nib

img = nib.load("label.nii.gz")
data = img.get_fdata().astype(int)
unique_vals = sorted(np.unique(data))
# Remap to consecutive if needed
mapping = {old: new for new, old in enumerate(unique_vals)}
```

---

## Reference Files

- `references/dataset_json_spec.md` — Full dataset.json field reference
- `scripts/convert_template.py` — Reusable Python conversion script template