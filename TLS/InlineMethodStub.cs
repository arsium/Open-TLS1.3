// Stub for InlineMethod.Fody attribute — satisfies [InlineMethod.Inline] references
// in ZstdSharp source without requiring the Fody NuGet package.
// The actual inlining is a build-time optimization; the attribute is a no-op here.
namespace InlineMethod
{
    [System.AttributeUsage(System.AttributeTargets.Method)]
    internal sealed class InlineAttribute : System.Attribute { }
}
