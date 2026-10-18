using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Web.Models;

namespace SafeVault.Web.Controllers;

/// <summary>Public landing page and error pages.</summary>
public sealed class HomeController : Controller
{
    [HttpGet]
    public IActionResult Index() => View();

    /// <summary>Generic error page for unhandled exceptions. Shows a trace id, never exception details.</summary>
    [HttpGet, HttpPost]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error() =>
        View(new ErrorViewModel(Activity.Current?.Id ?? HttpContext.TraceIdentifier, 500));

    /// <summary>Friendly page for status codes such as 404 (wired up with UseStatusCodePagesWithReExecute).</summary>
    [HttpGet, HttpPost]
    public IActionResult HttpStatus(int id)
    {
        // Only echo a sane range of codes back to the view.
        var code = id is >= 400 and <= 599 ? id : 500;
        Response.StatusCode = code;
        return View(new ErrorViewModel(HttpContext.TraceIdentifier, code));
    }
}
