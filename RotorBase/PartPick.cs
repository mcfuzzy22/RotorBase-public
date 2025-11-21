using System.Collections.Generic;

namespace RotorBase;

public record ClearPick(long BuildId, string? SocketKey, long? SlotId, long? CategoryId);

public record SelectPart(long BuildId, long? SlotId, long? CategoryId, long PartId);

internal sealed class SlotBadgeRow
{
    public long SlotId { get; set; }
    public string SlotKey { get; set; } = string.Empty;
    public string SlotName { get; set; } = string.Empty;
    public string? GltfNodePath { get; set; }
    public long? SubsystemId { get; set; }
    public string? SubsystemKey { get; set; }
    public string? SubsystemName { get; set; }
    public int SelectedCount { get; set; }
    public int MinRequired { get; set; }
    public int Capacity { get; set; }
    public long? PartId { get; set; }
    public string? PartName { get; set; }
    public string? PartGltfUri { get; set; }
    public string? PartGltfAttachNode { get; set; }
    public bool LocalOk { get; set; }
}

internal sealed class SocketMatchRow
{
    public long SlotId { get; set; }
    public string SlotKey { get; set; } = string.Empty;
    public string? GltfNodePath { get; set; }
    public string? SubsystemName { get; set; }
    public int Priority { get; set; }
    public string Reason { get; set; } = string.Empty;
}

internal sealed record RuleHintResult(
    List<string> Requires,
    List<string> MatchAttr,
    List<string> Excludes);
