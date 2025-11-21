using System.Threading.Tasks;
using Microsoft.JSInterop;

namespace RotorBase.Services;

public sealed class ThemeService
{
    private readonly IJSRuntime _js;

    public ThemeService(IJSRuntime js)
    {
        _js = js;
    }

    public ValueTask<string> GetAsync()
        => _js.InvokeAsync<string>("theme.current");

    public ValueTask SetAsync(string mode)
        => _js.InvokeVoidAsync("theme.set", mode);

    public async ValueTask<string> ToggleAsync()
    {
        var current = await GetAsync();
        var next = current == "dark" ? "light" : "dark";
        await SetAsync(next);
        return next;
    }

    public ValueTask ApplyAsync()
        => _js.InvokeVoidAsync("theme.applyCurrent");

    public ValueTask SetBrandAsync(string? brand)
        => _js.InvokeVoidAsync("theme.setBrand", brand);
}
