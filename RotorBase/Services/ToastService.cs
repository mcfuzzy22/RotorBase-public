using System;
using System.Collections.Generic;

namespace RotorBase.Services;

public enum ToastKind
{
    Info,
    Success,
    Warning,
    Error
}

public sealed record ToastMessage(string Text, ToastKind Kind, TimeSpan Duration);

public sealed class ToastService
{
    public event Action<ToastMessage>? OnShow;

    public void Show(string text, ToastKind kind = ToastKind.Success, int durationMs = 2500)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return;
        }

        var message = new ToastMessage(text, kind, TimeSpan.FromMilliseconds(Math.Clamp(durationMs, 500, 10000)));
        OnShow?.Invoke(message);
    }
}
