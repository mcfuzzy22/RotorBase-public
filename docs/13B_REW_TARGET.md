# 13B-REW Target Slice

The first focused target is the 13B-REW street-turbo build path. Preset builds can be added later, but the product value should come from validating an individual build one slot at a time.

## Product Shape

- Keep presets as starting points, not final answers.
- Let users replace every category/slot piece by piece.
- Treat unknown compatibility as a first-class state instead of pretending the catalog is complete.
- Show missing catalog coverage in the builder so research work is visible.

## Initial Scope

The seed in `db/seeds/13b_rew_street_turbo_target.sql` extends the existing default 13B-REW tree with planning groups:

- Air & Exhaust
- Fuel System
- Engine Management
- Cooling
- Drivetrain

It adds slots for major systems such as turbocharger, exhaust manifold, intercooler, injectors, fuel pump, ECU, MAP sensor, ignition, radiator, oil cooler, clutch, and flywheel.

## Compatibility Model

The first rule layer uses existing `SlotEdge` relationships:

- `REQUIRES`: selecting one slot implies another support slot should be filled.
- `MATCH_ATTR`: future part attributes can enforce paired compatibility such as flange, injector feed style, or clutch spline.
- `EXCLUDES`: future rules can block mutually incompatible choices.

Part-level compatibility should be encoded with:

- `PartFitment` for engine-family fitment.
- `PartSlot` for which slot/category a part can satisfy.
- `PartAttribute` for flange, feed style, pressure range, electrical style, spline, and similar structured facts.

## 3D Model Strategy

Exact GLB coverage is not required for the first target. The builder should work with:

- engine-level GLB when available,
- slot/socket placeholders,
- category cards and part photos,
- `needs catalog` states for categories with no verified part candidates,
- optional exact part GLBs only for high-value or vendor-supplied parts.

This keeps the compatibility brain moving while the visual catalog matures.

## Data Rule

Do not treat seeded categories as recommendations. They are planning slots. A part becomes recommendable only after it has fitment, category/slot mapping, source/vendor metadata, and enough attributes to validate the relevant constraints.
