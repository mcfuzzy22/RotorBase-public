using Microsoft.AspNetCore.Http;

namespace RotorBase;

internal readonly record struct SubtreeEdge(long ParentCategoryId, long ChildCategoryId, int Position, string ParentSlug, string ChildSlug);

internal sealed class SubtreeLoadResult
{
    public bool Success { get; init; }
    public IResult? Error { get; init; }
    public long TreeId { get; init; }
    public long RootCategoryId { get; init; }
    public SubtreeEdge[]? Edges { get; init; }
}
