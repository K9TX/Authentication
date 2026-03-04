import { useEffect, useRef, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { useAuthStore } from "../stores/authStore";
import { authAPI, getErrorMessage } from "../services/api";
import toast from "react-hot-toast";

// Namespaced localStorage keys (avoids collision with other apps on same origin)
const STORAGE_KEY_DISMISSED = "secureauth_onetap_dismissed";
const STORAGE_KEY_DISMISS_COUNT = "secureauth_onetap_dismiss_count";

// Exponential backoff cooldown: 2h, 4h, 8h, 24h max
const BASE_COOLDOWN_MS = 2 * 60 * 60 * 1000;
const MAX_COOLDOWN_MS = 24 * 60 * 60 * 1000;

function getDismissalCooldown() {
  const count = parseInt(
    localStorage.getItem(STORAGE_KEY_DISMISS_COUNT) || "0",
    10,
  );
  return Math.min(BASE_COOLDOWN_MS * 2 ** count, MAX_COOLDOWN_MS);
}

/**
 * Google One Tap Hook — Enterprise Implementation
 *
 * - Uses the GIS script already loaded by GoogleOAuthProvider (no duplicate loading)
 * - Handles MFA enforcement (Google login + TOTP if user has MFA enabled)
 * - Exponential backoff on dismissal (2h → 4h → 8h → 24h cap)
 * - Namespaced localStorage keys
 *
 * @param {Object} options
 * @param {boolean} options.disabled - Disable One Tap prompt
 * @param {string} options.context - "signin" | "signup" | "use"
 * @param {function} options.onMfaRequired - Callback when MFA step is needed after Google auth
 */
export function useGoogleOneTap({
  disabled = false,
  context = "signin",
  onMfaRequired,
} = {}) {
  const navigate = useNavigate();
  const { setUser, setIsAuthenticated, isAuthenticated } = useAuthStore();
  const isInitialized = useRef(false);

  const handleCredentialResponse = useCallback(
    async (response) => {
      try {
        const result = await authAPI.googleLogin(response.credential);

        // MFA required — delegate to the caller (Login page)
        if (result.data.mfa_required) {
          if (typeof onMfaRequired === "function") {
            onMfaRequired(result.data.email);
          } else {
            toast("MFA verification required. Please sign in manually.", {
              icon: "🔐",
            });
          }
          return;
        }

        setUser(result.data.user);
        setIsAuthenticated(true);
        toast.success("Welcome");
        navigate("/dashboard");
      } catch (error) {
        toast.error(getErrorMessage(error));
      }
    },
    [navigate, setUser, setIsAuthenticated, onMfaRequired],
  );

  useEffect(() => {
    if (disabled || isAuthenticated || isInitialized.current) return;

    const GOOGLE_CLIENT_ID = import.meta.env.VITE_GOOGLE_CLIENT_ID;
    if (!GOOGLE_CLIENT_ID || GOOGLE_CLIENT_ID === "your-google-client-id")
      return;

    // Exponential backoff dismissal cooldown
    const dismissedTime = localStorage.getItem(STORAGE_KEY_DISMISSED);
    if (dismissedTime) {
      const cooldown = getDismissalCooldown();
      if (Date.now() - parseInt(dismissedTime, 10) < cooldown) return;
    }

    // Wait for GIS to be loaded by GoogleOAuthProvider (no duplicate script)
    const initializeOneTap = () => {
      if (!window.google?.accounts?.id) return;

      window.google.accounts.id.initialize({
        client_id: GOOGLE_CLIENT_ID,
        callback: handleCredentialResponse,
        auto_select: false,
        cancel_on_tap_outside: true,
        context,
        itp_support: true,
      });

      window.google.accounts.id.prompt((notification) => {
        if (notification.isDismissedMoment()) {
          // Ignore cancel_called — triggered by our own cleanup (React StrictMode)
          if (notification.getDismissedReason?.() === "cancel_called") return;

          localStorage.setItem(STORAGE_KEY_DISMISSED, Date.now().toString());
          const count = parseInt(
            localStorage.getItem(STORAGE_KEY_DISMISS_COUNT) || "0",
            10,
          );
          localStorage.setItem(STORAGE_KEY_DISMISS_COUNT, String(count + 1));
        }
      });

      isInitialized.current = true;
    };

    // GoogleOAuthProvider loads GIS; poll briefly in case it's still loading
    if (window.google?.accounts?.id) {
      initializeOneTap();
    } else {
      const interval = setInterval(() => {
        if (window.google?.accounts?.id) {
          clearInterval(interval);
          initializeOneTap();
        }
      }, 200);

      // Give up after 5 seconds (GIS script failed or blocked by ad-blocker)
      const timeout = setTimeout(() => clearInterval(interval), 5000);

      return () => {
        clearInterval(interval);
        clearTimeout(timeout);
        window.google?.accounts?.id?.cancel();
        isInitialized.current = false;
      };
    }

    return () => {
      window.google?.accounts?.id?.cancel();
      isInitialized.current = false;
    };
  }, [disabled, isAuthenticated, context, handleCredentialResponse]);
}

/** Reset the dismissal backoff (call on successful manual login/logout) */
export function resetOneTapDismissal() {
  localStorage.removeItem(STORAGE_KEY_DISMISSED);
  localStorage.removeItem(STORAGE_KEY_DISMISS_COUNT);
  localStorage.removeItem("google_onetap_dismissed"); // legacy key cleanup
}
