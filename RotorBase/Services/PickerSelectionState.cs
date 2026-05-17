namespace RotorBase.Services;

public sealed class PickerSelectionState
{
    public long EngineFamilyId { get; private set; }
    public string EngineCode { get; private set; } = string.Empty;
    public Dictionary<long, PickerPartSelection> Selections { get; } = new();
    public Dictionary<long, int> Quantities { get; } = new();
    public HashSet<string> ExpandedGroups { get; } = new(StringComparer.OrdinalIgnoreCase);

    public void SetEngine(long engineFamilyId, string engineCode, bool clearSelections)
    {
        if (clearSelections && EngineFamilyId != engineFamilyId)
        {
            Selections.Clear();
            Quantities.Clear();
            ExpandedGroups.Clear();
        }

        EngineFamilyId = engineFamilyId;
        EngineCode = engineCode;
    }

    public void SelectPart(long slotId, PickerPartSelection part, int quantity)
    {
        Selections[slotId] = part;
        Quantities[slotId] = Math.Max(1, quantity);
    }

    public void ClearSlot(long slotId)
    {
        Selections.Remove(slotId);
    }
}

public sealed class PickerPartSelection
{
    public long part_id { get; set; }
    public string sku { get; set; } = string.Empty;
    public string name { get; set; } = string.Empty;
    public string brand { get; set; } = string.Empty;
    public string? image_url { get; set; }
    public decimal? best_price { get; set; }
    public bool is_kit { get; set; }
    public string? category_name { get; set; }
    public string? category_slug { get; set; }
}
