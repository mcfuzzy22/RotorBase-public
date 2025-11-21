namespace RotorBase;

public sealed record UpsertEngine(long? Id, string Key, string Name, string? GltfUri, string? Revision);
public sealed record UpsertSubsystem(long? Id, long EngineId, string Key, string Name, string? GltfNodePath, int SortOrder);
public sealed record UpsertSlot(long? Id, long EngineId, long SubsystemId, string Key, string Name, string GltfNodePath, int MinRequired, int Capacity, string? Notes);
public sealed record UpsertEdge(long? Id, long EngineId, long FromSlotId, long ToSlotId, string Edge, int MinRequired, string? RuleJson);
public sealed record UpsertPartSlot(long? Id, long SlotId, long? CategoryId, long? PartId, bool Allow);
public sealed record UpsertAttribute(long? Id, string Key, string Name, string Type);
public sealed record UpsertPartAttribute(long PartId, long AttributeId, decimal? ValueNum, string? ValueText, bool? ValueBool);

public sealed class SlotMatrixSlot
{
    public long SlotId { get; set; }
    public string SlotKey { get; set; } = "";
    public string SlotName { get; set; } = "";
    public string? GltfNodePath { get; set; }
    public int MinRequired { get; set; }
    public int Capacity { get; set; }
    public string SubsystemName { get; set; } = "";
}

public sealed class SlotMatrixCategory
{
    public long SlotId { get; set; }
    public long CategoryId { get; set; }
    public string CategoryKey { get; set; } = "";
    public string CategoryName { get; set; } = "";
}

public sealed class SlotMatrixPart
{
    public long SlotId { get; set; }
    public long PartId { get; set; }
    public string PartName { get; set; } = "";
}

public sealed class SlotMappingRow
{
    public long SlotId { get; set; }
    public string SlotKey { get; set; } = "";
    public string SlotName { get; set; } = "";
    public string? GltfNodePath { get; set; }
    public string SubsystemName { get; set; } = "";
    public bool IsMapped { get; set; }
}

public sealed record SlotCategoryMap(long SlotId, long CategoryId);
public sealed record SlotPartMap(long SlotId, long PartId);
