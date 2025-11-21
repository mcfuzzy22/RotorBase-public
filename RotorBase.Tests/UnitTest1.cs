using RotorBase;

namespace RotorBase.Tests;

public class SocketRouteMessagesTests
{
    [Theory]
    [InlineData("authorized", "Opening your build...")]
    [InlineData("forked_copy", "You don't have edit access - opening a copy you can edit.")]
    [InlineData("new_on_same_engine", "You don't have access - opening a fresh build on the same engine.")]
    [InlineData("new_build", "Creating a new build...")]
    [InlineData("UNKNOWN", "Opening socket builder...")]
    [InlineData(null, "Opening socket builder...")]
    public void Maps_reason_to_expected_message(string? reason, string expected)
    {
        var actual = SocketRouteMessages.GetToastMessage(reason);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Uses_reason_from_result()
    {
        var result = new RouteToSocketsResult
        {
            Reason = "forked_copy"
        };

        var message = SocketRouteMessages.GetToastMessage(result);

        Assert.Equal("You don't have edit access - opening a copy you can edit.", message);
    }
}
