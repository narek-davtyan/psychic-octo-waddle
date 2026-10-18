using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Web.Data;
using SafeVault.Web.Models;
using SafeVault.Web.Services;

namespace SafeVault.Web.Controllers;

/// <summary>Administrator-only user management. The class-level [Authorize] covers every action.</summary>
[Authorize(Roles = Roles.Admin)]
public sealed class AdminController(IUserRepository users, IAuditLogger audit) : Controller
{
    private Guid CurrentUserId =>
        Guid.TryParse(User.FindFirstValue(ClaimTypes.NameIdentifier), out var id) ? id : Guid.Empty;

    private string? ClientIp => HttpContext.Connection.RemoteIpAddress?.ToString();

    [HttpGet]
    public async Task<IActionResult> Index(CancellationToken ct) =>
        View(new AdminIndexViewModel(await users.ListAsync(ct), CurrentUserId, audit.ReadRecent(20)));

    /// <summary>Changes a user's role. Refuses to remove the last remaining administrator.</summary>
    [HttpPost]
    public async Task<IActionResult> SetRole(Guid id, string role, CancellationToken ct)
    {
        // Whitelist the role value: anything else is rejected outright.
        if (!Roles.IsValid(role)) return BadRequest("Unknown role.");

        var target = await users.GetByIdAsync(id, ct);
        if (target is null) return NotFound();

        if (target.Role == Roles.Admin && role != Roles.Admin && await IsLastAdminAsync(ct))
        {
            TempData["Error"] = "You cannot demote the last administrator.";
            return RedirectToAction(nameof(Index));
        }

        await users.UpdateAsync(target with { Role = role }, ct);
        audit.Log("ROLE_CHANGED", User.Identity?.Name, ClientIp, $"target={target.Username} {target.Role}->{role}");

        TempData["Success"] = $"Role for '{target.Username}' set to {role}.";
        return RedirectToAction(nameof(Index));
    }

    /// <summary>Deletes a user. Admins cannot delete themselves or the last administrator.</summary>
    [HttpPost]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        if (id == CurrentUserId)
        {
            TempData["Error"] = "You cannot delete your own account.";
            return RedirectToAction(nameof(Index));
        }

        var target = await users.GetByIdAsync(id, ct);
        if (target is null) return NotFound();

        if (target.Role == Roles.Admin && await IsLastAdminAsync(ct))
        {
            TempData["Error"] = "You cannot delete the last administrator.";
            return RedirectToAction(nameof(Index));
        }

        await users.DeleteAsync(id, ct);
        audit.Log("USER_DELETED", User.Identity?.Name, ClientIp, $"target={target.Username}");

        TempData["Success"] = $"User '{target.Username}' deleted.";
        return RedirectToAction(nameof(Index));
    }

    private async Task<bool> IsLastAdminAsync(CancellationToken ct) =>
        (await users.ListAsync(ct)).Count(u => u.Role == Roles.Admin) <= 1;
}
