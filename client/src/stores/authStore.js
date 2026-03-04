import { create } from "zustand";
import {
  authAPI,
  getErrorMessage,
  cancelPendingRequests,
} from "../services/api";

// Allowed user fields (prevents prototype pollution from unexpected server data)
const ALLOWED_USER_FIELDS = [
  "id",
  "username",
  "email",
  "first_name",
  "last_name",
  "is_verified",
  "mfa_enabled",
  "created_at",
];

/** Sanitize user data to only include expected fields */
const sanitizeUser = (user) => {
  if (!user || typeof user !== "object") return null;
  const clean = {};
  for (const field of ALLOWED_USER_FIELDS) {
    if (Object.hasOwn(user, field)) clean[field] = user[field];
  }
  return Object.keys(clean).length > 0 ? clean : null;
};

export const useAuthStore = create((set, get) => ({
  user: null,
  isAuthenticated: false,
  isLoading: true,
  lastActivity: Date.now(),

  /** Check auth status on app mount */
  initialize: async () => {
    try {
      const { data } = await authAPI.getCurrentUser();
      const user = sanitizeUser(data);
      if (!user) throw new Error("Invalid user data");

      set({
        user,
        isAuthenticated: true,
        isLoading: false,
        lastActivity: Date.now(),
      });
      return { success: true, data: user };
    } catch (error) {
      set({ user: null, isAuthenticated: false, isLoading: false });
      return { success: false, error };
    }
  },

  /** Login — backend rate limits, no client-side duplication needed */
  login: async (credentials) => {
    if (!credentials?.email || !credentials?.password) {
      return { success: false, error: "Email and password are required" };
    }

    try {
      const { data } = await authAPI.login(credentials);
      if (!data)
        return { success: false, error: "Invalid response from server" };

      // MFA required — don't set auth state yet
      if (data.mfa_required) {
        return {
          success: false,
          mfa_required: true,
          email: data.email,
          message: data.message,
        };
      }

      const user = sanitizeUser(data.user);
      if (!user) return { success: false, error: "Invalid user data received" };

      set({ user, isAuthenticated: true, lastActivity: Date.now() });
      return { success: true };
    } catch (error) {
      return { success: false, error: getErrorMessage(error) };
    }
  },

  /** Register */
  register: async (userData) => {
    try {
      const { data } = await authAPI.register(userData);
      const user = sanitizeUser(data.user);
      if (!user) return { success: false, error: "Invalid user data received" };

      set({ user, isAuthenticated: true, lastActivity: Date.now() });
      return { success: true, data: { message: data.message } };
    } catch (error) {
      return {
        success: false,
        error: error.response?.data || getErrorMessage(error),
      };
    }
  },

  /** Logout — clear all state + cancel pending requests */
  logout: async () => {
    try {
      await authAPI.logout();
    } catch {
      // Server-side logout failed, but still clear client state
    } finally {
      cancelPendingRequests();

      // Reset One Tap dismissal so it shows again on login page
      localStorage.removeItem("secureauth_onetap_dismissed");
      localStorage.removeItem("secureauth_onetap_dismiss_count");
      localStorage.removeItem("google_onetap_dismissed");

      set({ user: null, isAuthenticated: false, lastActivity: Date.now() });
    }
  },

  /** Merge partial user update (e.g., after MFA enable/disable) */
  updateUser: (userData) => {
    if (!get().user) return;
    const patch = sanitizeUser(userData);
    if (!patch) return;
    set((state) => ({
      user: { ...state.user, ...patch },
      lastActivity: Date.now(),
    }));
  },

  /** Replace user entirely (e.g., after MFA login) */
  setUser: (user) => {
    const clean = sanitizeUser(user);
    if (clean) set({ user: clean, lastActivity: Date.now() });
  },

  /** Only allow setting authenticated to true if user data exists */
  setIsAuthenticated: (isAuthenticated) => {
    if (isAuthenticated && !get().user) return;
    set({ isAuthenticated, lastActivity: Date.now() });
  },

  /** Activity tracking for session timeout detection */
  updateActivity: () => set({ lastActivity: Date.now() }),

  /** Check if session is stale (30 min default) */
  isSessionStale: (maxInactiveMs = 30 * 60 * 1000) => {
    return Date.now() - get().lastActivity > maxInactiveMs;
  },
}));
