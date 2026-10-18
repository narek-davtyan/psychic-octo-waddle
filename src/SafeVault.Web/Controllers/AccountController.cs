using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SafeVault.Web.Data;
using SafeVault.Web.Models;
using SafeVault.Web.Services;

namespace SafeVault.Web.Controllers;

/// <summary>Registration, login, logout and the signed-in user's own profile.</summary>
/// <remarks>
/// CSRF: a global AutoValidateAntiforgeryToken filter (see Program.cs) protects every POST action here.
/// </remarks>
public sealed class AccountController(
    AuthService auth, IUserRepository users, IAuditLogger audit) : Controller
{
    // One deliberately vague message for ALL login failures (unknown user, bad password, locked account).
    private const string GenericLoginError = "Invalid username or password, or the account is temporarily locked.";

    private string? ClientIp => HttpContext.Connection.RemoteIpAddress?.ToString();

    // ---------------------------------------------------------------- Register

    [AllowAnonymous, HttpGet]
    public IActionResult Register() => View(new RegisterViewModel());

    [AllowAnonymous, HttpPost]
    [EnableRateLimiting("auth")] // brute-force / mass-signup throttle per client IP
    public async Task<IActionResult> Register(RegisterViewModel model, CancellationToken ct)
    {
        // Annotations ([Required], whitelist regex, [SafeText] ...) run before this line.
        if (!ModelState.IsValid) return View(model);

        var result = await auth.RegisterAsync(model.Username, model.Email, model.Password, ClientIp, ct);

        if (result.Status != RegisterStatus.Success)
        {
            foreach (var error in result.Errors) ModelState.AddModelError(string.Empty, error);

            // Never send the password back to the browser.
            model.Password = model.ConfirmPassword = string.Empty;
            return View(model);
        }

        TempData["Success"] = "Account created. You can now sign in.";
        return RedirectToAction(nameof(Login));
    }

    // ------------------------------------------------------------------- Login

    [AllowAnonymous, HttpGet]
    public IActionResult Login(string? returnUrl = null) =>
        View(new LoginViewModel { ReturnUrl = returnUrl });

    [AllowAnonymous, HttpPost]
    [EnableRateLimiting("auth")]
    public async Task<IActionResult> Login(LoginViewModel model, CancellationToken ct)
    {
        if (!ModelState.IsValid) return View(model);

        var result = await auth.LoginAsync(model.Username, model.Password, ClientIp, ct);

        if (result.Status != LoginStatus.Success || result.User is null)
        {
            ModelState.AddModelError(string.Empty, GenericLoginError);
            model.Password = string.Empty;
            return View(model);
        }

        // Build the identity from DB-sourced values; the cookie is encrypted and signed by ASP.NET Core.
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, result.User.Id.ToString()),
            new(ClaimTypes.Name, result.User.Username),
            new(ClaimTypes.Email, result.User.Email),
            new(ClaimTypes.Role, result.User.Role)
        };
        var principal = new ClaimsPrincipal(
            new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme));

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            principal,
            new AuthenticationProperties { IsPersistent = false }); // session cookie: gone when the browser closes

        // Open-redirect defence: only follow returnUrl if it points back to THIS site.
        if (!string.IsNullOrEmpty(model.ReturnUrl) && Url.IsLocalUrl(model.ReturnUrl))
        {
            return LocalRedirect(model.ReturnUrl);
        }

        return RedirectToAction(nameof(Me));
    }

    // ------------------------------------------------------------------ Logout

    /// <summary>POST-only (and CSRF-protected) so a malicious page cannot sign users out via an image tag.</summary>
    [Authorize, HttpPost]
    public async Task<IActionResult> Logout()
    {
        audit.Log("LOGOUT", User.Identity?.Name, ClientIp);
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction("Index", "Home");
    }

    // ----------------------------------------------------------------- Profile

    /// <summary>Shows the signed-in user's own data. Identity comes from the cookie, never from a URL parameter.</summary>
    [Authorize, HttpGet]
    public async Task<IActionResult> Me(CancellationToken ct)
    {
        if (!Guid.TryParse(User.FindFirstValue(ClaimTypes.NameIdentifier), out var id)) return Forbid();

        var user = await users.GetByIdAsync(id, ct);
        if (user is null) return Forbid();

        return View(new ProfileViewModel(user.Username, user.Email, user.Role, user.CreatedUtc, user.LastLoginUtc));
    }

    // ------------------------------------------------------------ Access denied

    [AllowAnonymous, HttpGet]
    public IActionResult AccessDenied()
    {
        audit.Log("ACCESS_DENIED", User.Identity?.Name, ClientIp, Request.Query["ReturnUrl"].ToString());
        Response.StatusCode = StatusCodes.Status403Forbidden;
        return View();
    }
}
