using System.Text.Json.Serialization;

namespace RotorBase;

public sealed record CancelSubscriptionRequestDto(
    [property: JsonPropertyName("at_period_end")] bool? AtPeriodEnd
);
